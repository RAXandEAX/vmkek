#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

#include "bootstrap.h"
#include "r12_test_pin.h"

typedef struct Invocation {
    const VmkWindowsRuntime *runtime;
    VmkRuntime handle;
    HANDLE start;
    VmkRequestId id;
    int64_t input;
    VmkStatus status;
    VmkInvokeResultV1 result;
} Invocation;

static int local_mitigations(void) {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg = {0};
    acg.ProhibitDynamicCode = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &acg, sizeof(acg)) ||
        !GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &acg, sizeof(acg)) ||
        !acg.ProhibitDynamicCode) {
        return 0;
    }
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {0};
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet = {0};
    int cfg_ok = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
    int cet_ok = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &cet, sizeof(cet));
    printf("r12 mitigations: ACG=1 CFG=%d CET-shadow-stack=%d\n",
           cfg_ok ? (int)cfg.EnableControlFlowGuard : -1,
           cet_ok ? (int)cet.EnableUserShadowStack : -1);
    return 1;
}

static int unwind_entries(const VmkWindowsRuntime *runtime) {
    DWORD64 base = 0;
    DWORD64 initialize = (DWORD64)(uintptr_t)runtime->initialize;
    if (!RtlLookupFunctionEntry(initialize, &base, NULL) || base != (DWORD64)(uintptr_t)runtime->image) {
        return 0;
    }
    DWORD64 invoke = (DWORD64)(uintptr_t)runtime->invoke;
    return RtlLookupFunctionEntry(invoke, &base, NULL) && base == (DWORD64)(uintptr_t)runtime->image;
}

static int sharing_denied(const wchar_t *file, DWORD access) {
    HANDLE probe = CreateFileW(file, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (probe != INVALID_HANDLE_VALUE) {
        CloseHandle(probe);
        return 0;
    }
    return GetLastError() == ERROR_SHARING_VIOLATION;
}

static int file_is_pinned(const VmkWindowsRuntime *runtime) {
    wchar_t image[MAX_PATH];
    DWORD count = GetModuleFileNameW(runtime->image, image, MAX_PATH);
    return count > 0 && count < MAX_PATH && sharing_denied(image, GENERIC_WRITE) &&
           sharing_denied(image, DELETE);
}

static int fresh_id(VmkRequestId *id) {
    return BCryptGenRandom(NULL, id->bytes, sizeof(id->bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static VmkInvokeV1 request(const Invocation *job, const VmkScalar *scalar) {
    VmkInvokeV1 call = {0};
    call.size = sizeof(call);
    call.abi_version = VMK_ABI_VERSION;
    call.request_id = job->id;
    call.scalars = scalar;
    call.scalar_count = 1;
    return call;
}

static VmkInvokeResultV1 sentinel(void) {
    return (VmkInvokeResultV1){sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {VMK_SCALAR_U64, 0, 0xfeed}, UINT64_MAX};
}

static DWORD WINAPI invoke_worker(LPVOID value) {
    Invocation *job = value;
    VmkScalar scalar = {VMK_SCALAR_I64, 0, (uint64_t)job->input};
    VmkInvokeV1 call = request(job, &scalar);
    job->result = sentinel();
    if (job->start && WaitForSingleObject(job->start, INFINITE) != WAIT_OBJECT_0) {
        return 1;
    }
    job->status = job->runtime->invoke(job->handle, &call, &job->result);
    return 0;
}

static int unchanged(const Invocation *job) {
    return job->result.scalar.kind == VMK_SCALAR_U64 && job->result.scalar.bits == 0xfeed &&
           job->result.output_len == UINT64_MAX;
}

static int valid_result(const Invocation *job) {
    return job->status == VMK_OK && job->result.scalar.kind == VMK_SCALAR_I64 &&
           job->result.scalar.bits == (uint64_t)job->input && job->result.output_len == 0;
}

static int invalid_buffer(Invocation *job) {
    VmkScalar scalar = {VMK_SCALAR_I64, 0, 42};
    VmkInvokeV1 call = request(job, &scalar);
    call.output.capacity = 1;
    job->result = sentinel();
    return job->runtime->invoke(job->handle, &call, &job->result) == VMK_INVALID_ARGUMENT && unchanged(job);
}

static int wait_worker(HANDLE thread) {
    DWORD exit_code = 1;
    if (WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) {
        /* Avoid returning while a worker still borrows its argument. */
        ExitProcess(1);
    }
    int ok = GetExitCodeThread(thread, &exit_code) && exit_code == 0;
    CloseHandle(thread);
    return ok;
}

static int run_identity_pair(const VmkWindowsRuntime *runtime, VmkRuntime handle) {
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start) {
        return 0;
    }
    Invocation jobs[2] = {{.runtime = runtime, .handle = handle, .start = start, .input = -17},
                          {.runtime = runtime, .handle = handle, .start = start, .input = 42}};
    HANDLE workers[2] = {0};
    for (size_t index = 0; index < 2; ++index) {
        if (fresh_id(&jobs[index].id)) {
            workers[index] = CreateThread(NULL, 0, invoke_worker, &jobs[index], 0, NULL);
        }
    }
    if (!SetEvent(start)) {
        ExitProcess(1);
    }
    int accepted = 0;
    int valid = 1;
    for (size_t index = 0; index < 2; ++index) {
        int finished = workers[index] && wait_worker(workers[index]);
        if (finished && valid_result(&jobs[index])) {
            ++accepted;
        } else if (!finished || jobs[index].status != VMK_RESOURCE_LIMIT || !unchanged(&jobs[index])) {
            printf("r12 worker %zu unexpected status=%lu\n", index, (unsigned long)jobs[index].status);
            valid = 0;
        }
    }
    CloseHandle(start);
    return valid ? accepted : -1;
}

static int concurrent_identity(const VmkWindowsRuntime *runtime, VmkRuntime handle, int limit) {
    // A scheduler may run a pair serially. Retry a bounded number of times
    // to require an observed overlap for the single-context negative control.
    for (int attempt = 0; attempt < (limit == 1 ? 8 : 1); ++attempt) {
        int accepted = run_identity_pair(runtime, handle);
        if (accepted == limit) {
            printf("r12 concurrent pair accepted=%d resource-limit=%d\n", accepted, 2 - accepted);
            return 1;
        }
        if (limit != 1 || accepted != 2) {
            return 0;
        }
    }
    return 0;
}

static int cancellation(const VmkWindowsRuntime *runtime, VmkRuntime handle) {
    Invocation job = {.runtime = runtime, .handle = handle, .input = 0};
    if (!fresh_id(&job.id)) {
        return 0;
    }
    HANDLE thread = CreateThread(NULL, 0, invoke_worker, &job, 0, NULL);
    if (!thread) {
        return 0;
    }
    VmkStatus status;
    ULONGLONG started = GetTickCount64();
    do {
        status = runtime->cancel(handle, job.id);
        if (status != VMK_NOT_FOUND || WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) {
            break;
        }
        Sleep(1);
    } while (GetTickCount64() - started < 4000);
    int ok = wait_worker(thread) && status == VMK_OK && job.status == VMK_CANCELLED && unchanged(&job);
    printf("r12 cancel status=%lu invoke status=%lu\n", (unsigned long)status, (unsigned long)job.status);
    return ok;
}

static VmkStatus initialize_online(const VmkWindowsRuntime *runtime, const wchar_t *path, VmkRuntime *handle) {
    char utf8[MAX_PATH * 4];
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, utf8, sizeof(utf8), NULL, NULL);
    if (size <= 1) {
        return VMK_INVALID_ARGUMENT;
    }
    VmkInitializeV2 args = {
        .size = sizeof(args),
        .abi_version = VMK_ONLINE_ABI_VERSION,
        .profile = VMK_PROFILE_ONLINE,
        .config_path = { (const uint8_t *)utf8, (uint64_t)size - 1 }
    };
    return runtime->initialize((const VmkInitializeV1 *)(const void *)&args, handle);
}

static int online_case(const VmkWindowsRuntime *runtime, const wchar_t *path,
                       VmkStatus expected_init, VmkStatus expected_call, int cancel_case, int contexts) {
    VmkRuntime handle = 0;
    VmkStatus status = initialize_online(runtime, path, &handle);
    printf("r12 initialize status=%lu\n", (unsigned long)status);
    if (status != VMK_OK) {
        return status == expected_init && handle == 0;
    }
    int ok = expected_init == VMK_OK;
    if (ok && expected_call == VMK_OK) {
        Invocation bad = {.runtime = runtime, .handle = handle};
        ok = fresh_id(&bad.id) && invalid_buffer(&bad) && concurrent_identity(runtime, handle, contexts);
        if (ok && cancel_case) {
            ok = cancellation(runtime, handle);
        }
    } else if (ok) {
        Invocation job = {.runtime = runtime, .handle = handle, .input = 42};
        ok = fresh_id(&job.id) && invoke_worker(&job) == 0 && job.status == expected_call && unchanged(&job);
        printf("r12 invoke status=%lu\n", (unsigned long)job.status);
    }
    return runtime->shutdown(handle) == VMK_OK && ok;
}

static VmkStatus parse_status(const wchar_t *text) {
    wchar_t *end = NULL;
    unsigned long value = wcstoul(text, &end, 10);
    return end == text || *end || value > VMK_NOT_FOUND ? UINT32_MAX : (VmkStatus)value;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 4 || !local_mitigations()) {
        return 2;
    }
    int is_load = wcscmp(argv[1], L"load") == 0;
    int is_preload = wcscmp(argv[1], L"preloaded") == 0 && argc == 5;
    int is_online = wcscmp(argv[1], L"online") == 0 && argc == 6;
    int is_cancel = wcscmp(argv[1], L"cancel") == 0 && argc == 4;
    int is_quota_one = wcscmp(argv[1], L"quota-one") == 0 && argc == 4;
    if (!is_load && !is_preload && !is_online && !is_cancel && !is_quota_one) {
        return 2;
    }
    HMODULE preloaded = is_preload ? LoadLibraryExW(argv[4], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32) : NULL;
    if (is_preload && !preloaded) {
        return 2;
    }
    VmkWindowsRuntime runtime = {0};
    VmkStatus status = vmk_windows_open(argv[2], r12_vendor_pin, VMK_ONLINE_ABI_VERSION, &runtime);
    printf("r12 bootstrap status=%lu\n", (unsigned long)status);
    int ok = 0;
    if (is_load || is_preload) {
        ok = status == parse_status(argv[3]);
        if (status == VMK_OK) {
            ok = ok && unwind_entries(&runtime) && file_is_pinned(&runtime);
            if (ok) {
                puts("r12 x64 unwind entries and DLL sharing pin verified");
            }
        } else {
            ok = ok && runtime.image == NULL;
        }
    } else if (status == VMK_OK && unwind_entries(&runtime) && file_is_pinned(&runtime)) {
        ok = online_case(&runtime, argv[3], is_online ? parse_status(argv[4]) : VMK_OK,
                         is_online ? parse_status(argv[5]) : VMK_OK, is_cancel, is_quota_one ? 1 : 2);
        if (ok) {
            puts("r12 online ABI result matched");
        }
    }
    vmk_windows_close(&runtime);
    if (preloaded) {
        FreeLibrary(preloaded);
    }
    return ok ? 0 : 1;
}
