#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmkek_runtime.h"

typedef struct Worker {
    HANDLE start;
    VmkRuntime runtime;
    uint64_t ordinal;
} Worker;

static int read_bytes(const char *path, VmkBytes *bytes) {
    FILE *file = NULL;
    if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
        return 0;
    }
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (size <= 0 || size > 4 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    uint8_t *data = malloc((size_t)size);
    int ok = data != NULL && fread(data, 1, (size_t)size, file) == (size_t)size;
    fclose(file);
    if (!ok) {
        free(data);
        return 0;
    }
    bytes->data = data;
    bytes->len = (uint64_t)size;
    return 1;
}

static int check_call(VmkRuntime runtime, uint64_t value, uint64_t count, uint64_t selector) {
    const uint8_t input[] = {3, 1, 4, 1};
    uint8_t output[sizeof(input)] = {0};
    VmkScalar scalars[] = {
        {VMK_SCALAR_U64, 0, value},
        {VMK_SCALAR_U64, 0, count},
        {VMK_SCALAR_U64, 0, selector}
    };
    VmkInvokeV1 call = {
        sizeof(VmkInvokeV1), VMK_ABI_VERSION, {{0}}, scalars, 3,
        {input, sizeof(input)}, {output, sizeof(output)}
    };
    VmkInvokeResultV1 result = {
        sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {0, 0, 0}, 0
    };
    if (BCryptGenRandom(NULL, call.request_id.bytes, (ULONG)sizeof(call.request_id.bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 ||
        vmk_invoke(runtime, &call, &result) != VMK_OK) {
        return 0;
    }
    uint64_t expected = value + (selector == 0 ? 8 : 3) + 17;
    return result.scalar.kind == VMK_SCALAR_U64 && result.scalar.bits == expected &&
           result.output_len == sizeof(input) && memcmp(input, output, sizeof(input)) == 0;
}

static DWORD WINAPI run_worker(LPVOID state) {
    const Worker *worker = state;
    if (WaitForSingleObject(worker->start, INFINITE) != WAIT_OBJECT_0) {
        return 1;
    }
    for (uint64_t i = 0; i < 64; ++i) {
        if (!check_call(worker->runtime, UINT64_MAX - i + worker->ordinal, i % 8, i % 2)) {
            return 1;
        }
    }
    return 0;
}

static int concurrent_calls(VmkRuntime runtime) {
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (start == NULL) {
        return 0;
    }
    Worker workers[2] = {{start, runtime, 1}, {start, runtime, 2}};
    HANDLE threads[2] = {
        CreateThread(NULL, 0, run_worker, &workers[0], 0, NULL),
        CreateThread(NULL, 0, run_worker, &workers[1], 0, NULL)
    };
    if (!SetEvent(start)) {
        /* The executable exits so neither worker can retain its stack argument. */
        ExitProcess(1);
    }
    int ok = 1;
    for (size_t i = 0; i < 2; ++i) {
        DWORD result = 1;
        if (threads[i] == NULL) {
            ok = 0;
            continue;
        }
        if (WaitForSingleObject(threads[i], INFINITE) != WAIT_OBJECT_0) {
            ExitProcess(1);
        }
        ok = GetExitCodeThread(threads[i], &result) && result == 0 && ok;
        CloseHandle(threads[i]);
    }
    CloseHandle(start);
    return ok;
}

static int check_form(VmkBytes module, const char *descriptor_path, const char *form) {
    VmkInitializeV1 init = {
        sizeof(VmkInitializeV1), VMK_ABI_VERSION, VMK_PROFILE_LAB, 0, {NULL, 0}, module
    };
    if (!read_bytes(descriptor_path, &init.descriptor)) {
        return 0;
    }
    VmkRuntime runtime = 0;
    VmkStatus status = vmk_initialize(&init, &runtime);
    free((void *)init.descriptor.data);
    if (status != VMK_OK) {
        return 0;
    }
    int ok = concurrent_calls(runtime);
    if (vmk_shutdown(runtime) != VMK_OK || !ok) {
        return 0;
    }
    printf("r07 %s: two Windows threads, 128 calls, matched scalar and buffer oracle\n", form);
    return 1;
}

int main(int argc, char **argv) {
    VmkBytes module = {NULL, 0};
    if (argc != 5 || !read_bytes(argv[1], &module)) {
        fputs("usage: r07_abi.exe module.bin stack.bin register.bin mixed.bin\n", stderr);
        return 1;
    }
    int ok = check_form(module, argv[2], "stack") &&
             check_form(module, argv[3], "register") &&
             check_form(module, argv[4], "mixed");
    free((void *)module.data);
    return ok ? 0 : 2;
}
