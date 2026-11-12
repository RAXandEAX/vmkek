#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef enum {
    EARLY_DEBUG, GATED_CLEAN, GATED_ATTACH, GATED_DETACH, GATED_SOFTWARE, GATED_HARDWARE
} Mode;

typedef struct {
    HANDLE ready, release, resample_ready, resample_release;
} Gates;

typedef struct {
    const PROCESS_INFORMATION *child;
    void *image_base;
    uintptr_t target;
    CONTEXT original;
} HardwareProbe;

static BOOL lab_mode;

static void oracle(const char *event) {
    if (!lab_mode) return;
    printf("oracle=%s tick_ms=%llu\n", event, GetTickCount64());
    fflush(stdout);
}

static void report_mitigation(HANDLE child, PROCESS_MITIGATION_POLICY policy, const char *name) {
    DWORD flags = 0;
    if (GetProcessMitigationPolicy(child, policy, &flags, sizeof(flags))) {
        printf("mitigation=%s flags=0x%08lx\n", name, flags);
    } else {
        printf("mitigation=%s unavailable=%lu\n", name, GetLastError());
    }
}

static HANDLE create_lab_job(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job == NULL) return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

static uintptr_t fixture_breakpoint_address(void) {
    wchar_t path[32768];
    DWORD length = GetEnvironmentVariableW(L"VMKEK_A02_RECORD", path, ARRAYSIZE(path));
    if (!length || length >= ARRAYSIZE(path)) return 0;
    HANDLE record = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (record == INVALID_HANDLE_VALUE) return 0;
    char text[4096];
    DWORD bytes = 0;
    BOOL read = ReadFile(record, text, sizeof(text) - 1, &bytes, NULL);
    CloseHandle(record);
    if (!read) return 0;
    text[bytes] = 0;
    const char *line = strstr(text, "\nhardware_target=");
    unsigned long long address = 0;
    if (line && sscanf_s(line + 1, "hardware_target=0x%llx", &address) == 1) return (uintptr_t)address;
    return 0;
}

/* The debug event suspends the job-owned fixture. Only its designated function
 * and main thread participate in the breakpoint experiment. */
static BOOL arm_hardware_probe(HardwareProbe *probe) {
    MEMORY_BASIC_INFORMATION region = {0};
    probe->target = fixture_breakpoint_address();
    if (!probe->target || !probe->image_base) {
        fprintf(stderr, "Hardware fixture address unavailable: target=%d image=%d\n",
                probe->target != 0, probe->image_base != NULL);
        return FALSE;
    }
    if (VirtualQueryEx(probe->child->hProcess, (const void *)probe->target,
                      &region, sizeof(region)) != sizeof(region)) {
        fprintf(stderr, "Hardware fixture mapping query failed: %lu\n", GetLastError());
        return FALSE;
    }
    if (region.AllocationBase != probe->image_base ||
        region.State != MEM_COMMIT || region.Type != MEM_IMAGE ||
        region.Protect != PAGE_EXECUTE_READ) {
        fprintf(stderr, "Hardware fixture mapping outside scope: base=%d state=%lu type=%lu protection=%lu\n",
                region.AllocationBase == probe->image_base, region.State, region.Type, region.Protect);
        return FALSE;
    }
    probe->original.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(probe->child->hThread, &probe->original)) {
        fprintf(stderr, "Hardware context read failed: %lu\n", GetLastError());
        return FALSE;
    }
    if ((probe->original.Dr7 & 0xff) != 0) {
        fputs("Hardware fixture registers already in use\n", stderr);
        return FALSE;
    }
    CONTEXT armed = probe->original;
    armed.Dr0 = probe->target;
    armed.Dr6 &= ~1ull;
    armed.Dr7 = (armed.Dr7 & ~0xf0000ull) | 1ull;
    if (SetThreadContext(probe->child->hThread, &armed)) return TRUE;
    fprintf(stderr, "Hardware context write failed: %lu\n", GetLastError());
    return FALSE;
}

static BOOL restore_hardware_probe(const HardwareProbe *probe, const DEBUG_EVENT *event) {
    CONTEXT state = {0};
    state.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return event->dwThreadId == probe->child->dwThreadId &&
        (uintptr_t)event->u.Exception.ExceptionRecord.ExceptionAddress == probe->target &&
        GetThreadContext(probe->child->hThread, &state) &&
        (state.Dr6 & 1) != 0 && state.Dr0 == probe->target &&
        SetThreadContext(probe->child->hThread, &probe->original);
}

static DWORD wait_for_child(const PROCESS_INFORMATION *child) {
    DWORD status = 2;
    if (WaitForSingleObject(child->hProcess, 10000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(child->hProcess, &status)) return 2;
    return status;
}

static DWORD detach_child(const PROCESS_INFORMATION *child, HANDLE release) {
    if (!DebugActiveProcessStop(child->dwProcessId)) {
        fprintf(stderr, "DebugActiveProcessStop failed: %lu\n", GetLastError());
        return 2;
    }
    oracle("detach_succeeded");
    if (!SetEvent(release)) return 2;
    return wait_for_child(child);
}

static DWORD observe_debug(const PROCESS_INFORMATION *child, Mode mode, const Gates *gates) {
    BOOL initial_breakpoint_seen = FALSE;
    BOOL expected_breakpoint_seen = FALSE;
    HardwareProbe probe = {0};
    probe.child = child;
    const ULONGLONG deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline) {
        if (mode == GATED_DETACH && initial_breakpoint_seen &&
            WaitForSingleObject(gates->resample_ready, 0) == WAIT_OBJECT_0) {
            oracle("detach_ready");
            return detach_child(child, gates->resample_release);
        }
        DEBUG_EVENT event;
        if (!WaitForDebugEvent(&event, mode == GATED_DETACH ? 25 : 250)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            return 2;
        }
        if (event.dwProcessId != child->dwProcessId) return 2;
        DWORD reply = DBG_CONTINUE;
        DWORD exit_code = 0;
        BOOL event_ok = TRUE;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            probe.image_base = event.u.CreateProcessInfo.lpBaseOfImage;
            oracle("debug_process_event");
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_DEBUG_INFO *exc = &event.u.Exception;
            DWORD code = exc->ExceptionRecord.ExceptionCode;
            printf("exception=0x%08lx first=%lu\n", code, exc->dwFirstChance);
            if (code == EXCEPTION_BREAKPOINT && exc->dwFirstChance && !initial_breakpoint_seen) {
                initial_breakpoint_seen = TRUE;
                oracle("initial_breakpoint");
                if (mode == GATED_HARDWARE) {
                    event_ok = arm_hardware_probe(&probe);
                    if (event_ok) oracle("hardware_armed");
                }
                if (event_ok && gates->release != NULL) event_ok = SetEvent(gates->release);
            } else if (mode == GATED_SOFTWARE && !expected_breakpoint_seen &&
                       code == EXCEPTION_BREAKPOINT && exc->dwFirstChance &&
                       event.dwThreadId == child->dwThreadId) {
                expected_breakpoint_seen = TRUE;
                oracle("software_breakpoint");
            } else if (mode == GATED_HARDWARE && !expected_breakpoint_seen &&
                       code == EXCEPTION_SINGLE_STEP && exc->dwFirstChance) {
                event_ok = restore_hardware_probe(&probe, &event);
                expected_breakpoint_seen = event_ok;
                if (event_ok) oracle("hardware_breakpoint_restored");
            } else {
                reply = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            exit_code = event.u.ExitProcess.dwExitCode;
            break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, reply) || !event_ok) return 2;
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            if ((gates->release != NULL && !initial_breakpoint_seen) ||
                ((mode == GATED_SOFTWARE || mode == GATED_HARDWARE) && !expected_breakpoint_seen) ||
                mode == GATED_DETACH) return 2;
            return exit_code;
        }
    }
    return 2;
}

static HANDLE make_gate(const wchar_t *label, const wchar_t *key) {
    wchar_t name[64];
    if (swprintf_s(name, ARRAYSIZE(name), L"Local\\vmkek-t6-%lu-%ls", GetCurrentProcessId(), label) < 0) {
        return NULL;
    }
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, name);
    if (event == NULL) return NULL;
    if (GetLastError() == ERROR_ALREADY_EXISTS || !SetEnvironmentVariableW(key, name)) {
        CloseHandle(event);
        return NULL;
    }
    return event;
}

static DWORD observe_gated(const PROCESS_INFORMATION *child, Mode mode, const Gates *gates) {
    HANDLE wait_for[] = { gates->ready, child->hProcess };
    if (WaitForMultipleObjects(ARRAYSIZE(wait_for), wait_for, FALSE, 10000) != WAIT_OBJECT_0) {
        fputs("Fixture did not reach its readiness gate\n", stderr);
        return 2;
    }
    puts("fixture initialized and waiting before protected call");
    oracle("ready");
    if (lab_mode && mode == GATED_CLEAN && GetEnvironmentVariableW(L"VMKEK_A08_ACTIVITY_DLL", NULL, 0) != 0) {
        FILETIME created, exited, kernel, user;
        if (!GetProcessTimes(child->hProcess, &created, &exited, &kernel, &user)) return 2;
        printf("compatibility_pid=%lu creation=%08lx%08lx\n",
               child->dwProcessId, created.dwHighDateTime, created.dwLowDateTime);
        report_mitigation(child->hProcess, ProcessDynamicCodePolicy, "compat_ready_acg");
        fflush(stdout);
    }
    if (mode != GATED_CLEAN) {
        if (!DebugActiveProcess(child->dwProcessId)) {
            fprintf(stderr, "DebugActiveProcess failed: %lu\n", GetLastError());
            return 2;
        }
        oracle("attach_succeeded");
        return observe_debug(child, mode, gates);
    }
    return SetEvent(gates->release) ? wait_for_child(child) : 2;
}

static BOOL start_child(const wchar_t *path, wchar_t *command, DWORD flags, HANDLE job,
                        PROCESS_INFORMATION *child) {
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup.StartupInfo);
    if (job == NULL) {
        return CreateProcessW(path, command, NULL, NULL, FALSE, flags, NULL, NULL, &startup.StartupInfo, child);
    }

    SIZE_T bytes = 0;
    if (InitializeProcThreadAttributeList(NULL, 1, 0, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;
    startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (startup.lpAttributeList == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    BOOL initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes);
    BOOL started = FALSE;
    if (initialized && UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), NULL, NULL)) {
        startup.StartupInfo.cb = sizeof(startup);
        started = CreateProcessW(path, command, NULL, NULL, FALSE,
            flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL, NULL, &startup.StartupInfo, child);
    }
    DWORD error = GetLastError();
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    if (!started) SetLastError(error);
    return started;
}

static DWORD run_child(const wchar_t *path, wchar_t *command, Mode mode, const Gates *gates) {
    PROCESS_INFORMATION child = {0};
    HANDLE job = lab_mode ? create_lab_job() : NULL;
    if (lab_mode && job == NULL) return 2;
    DWORD flags = CREATE_NO_WINDOW;
    if (mode == EARLY_DEBUG) flags |= DEBUG_ONLY_THIS_PROCESS;
    if (!start_child(path, command, flags, job, &child)) {
        fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
        if (job != NULL) CloseHandle(job);
        return 2;
    }
    DWORD status = 2;
    if (lab_mode) {
        report_mitigation(child.hProcess, ProcessDynamicCodePolicy, "dynamic_code");
        report_mitigation(child.hProcess, ProcessControlFlowGuardPolicy, "cfg");
        report_mitigation(child.hProcess, ProcessUserShadowStackPolicy, "shadow_stack");
        oracle(mode == EARLY_DEBUG ? "created_debug" : "created_clean");
    }
    if (lab_mode && ResumeThread(child.hThread) == (DWORD)-1) {
        fprintf(stderr, "ResumeThread failed: %lu\n", GetLastError());
    } else {
        status = mode == EARLY_DEBUG ? observe_debug(&child, mode, gates) :
                                      observe_gated(&child, mode, gates);
    }
    if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess, 2);
        WaitForSingleObject(child.hProcess, 1000);
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    if (job != NULL) CloseHandle(job);
    oracle("exited");
    return status;
}

int wmain(int argc, wchar_t **argv) {
    if (argc >= 3 && wcscmp(argv[1], L"--lab") == 0) {
        lab_mode = TRUE;
        --argc;
        ++argv;
    }
    wchar_t response_command[32767];
    wchar_t *command = NULL;
    Mode mode = EARLY_DEBUG;
    if (argc == 3 && wcscmp(argv[2], L"--gated") == 0) mode = GATED_CLEAN;
    else if (argc == 3 && wcscmp(argv[2], L"--attach-after-ready") == 0) mode = GATED_ATTACH;
    else if (lab_mode && argc == 3 && wcscmp(argv[2], L"--attach-detach") == 0) mode = GATED_DETACH;
    else if (lab_mode && argc == 3 && wcscmp(argv[2], L"--software-breakpoint") == 0) mode = GATED_SOFTWARE;
    else if (lab_mode && argc == 3 && wcscmp(argv[2], L"--hardware-breakpoint") == 0) mode = GATED_HARDWARE;
    else if (lab_mode && argc == 3 && wcsncmp(argv[2], L"--response-", 11) == 0) {
        const wchar_t *test = NULL;
        if (wcscmp(argv[2], L"--response-active") == 0)
            test = L"online::tests::lifecycle::response::native_response_active_reentry_and_parallel --ignored";
        else if (wcscmp(argv[2], L"--response-loss") == 0)
            test = L"online::tests::lifecycle::response::native_response_loss_keeps_local_denial_and_allows_fresh_session --ignored";
        else if (wcscmp(argv[2], L"--response-offline-active") == 0)
            test = L"observations::tests::response::response_offline_stop_discards_admitted_work_and_latches_for_the_activation";
        if (test == NULL || _snwprintf_s(response_command, _countof(response_command), _TRUNCATE,
                                        L"\"%ls\" --exact %ls --nocapture", argv[1], test) < 0) return 2;
        command = response_command;
        mode = wcscmp(argv[2], L"--response-offline-active") == 0 ? GATED_DETACH : GATED_ATTACH;
    }
    else if (argc != 2) return 2;
    Gates gates = {0};
    if (mode != EARLY_DEBUG) {
        gates.ready = make_gate(L"ready", L"VMKEK_T6_READY");
        gates.release = make_gate(L"release", L"VMKEK_T6_RELEASE");
    }
    if (mode == GATED_DETACH) {
        gates.resample_ready = make_gate(L"resample-ready", L"VMKEK_A03_RESAMPLE_READY");
        gates.resample_release = make_gate(L"resample-release", L"VMKEK_A03_RESAMPLE_RELEASE");
    }
    DWORD status = 2;
    if (mode == EARLY_DEBUG ||
        (gates.ready != NULL && gates.release != NULL &&
         (mode != GATED_DETACH || (gates.resample_ready != NULL && gates.resample_release != NULL)) &&
         SetEnvironmentVariableW(L"VMKEK_T6_DEBUG_EXPECTED", mode != GATED_CLEAN ? L"1" : L"0"))) {
        status = run_child(argv[1], command, mode, &gates);
    }
    if (gates.ready != NULL) CloseHandle(gates.ready);
    if (gates.release != NULL) CloseHandle(gates.release);
    if (gates.resample_ready != NULL) CloseHandle(gates.resample_ready);
    if (gates.resample_release != NULL) CloseHandle(gates.resample_release);
    printf("child exit=0x%08lx\n", status);
    fflush(stdout);
    ExitProcess(status);
}
