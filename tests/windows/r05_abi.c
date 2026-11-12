#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmkek_runtime.h"

#ifdef __cplusplus
#define STATIC_ASSERT static_assert
#else
#define STATIC_ASSERT _Static_assert
#endif

STATIC_ASSERT(sizeof(VmkRequestId) == 16, "request ID");
STATIC_ASSERT(sizeof(VmkScalar) == 16, "scalar");
STATIC_ASSERT(sizeof(VmkInitializeV1) == 48, "initialize");
STATIC_ASSERT(sizeof(VmkInvokeV1) == 72, "invoke");
STATIC_ASSERT(offsetof(VmkInvokeV1, output) == 56, "invoke output");
STATIC_ASSERT(sizeof(VmkInvokeResultV1) == 32, "result");

static int load_bytes(const char *path, VmkBytes *bytes) {
    FILE *file = NULL;
    if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    long size = ftell(file);
    if (size <= 0 || size > 4 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    uint8_t *data = (uint8_t *)malloc((size_t)size);
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

static int fresh_request(VmkRequestId *id) {
    return BCryptGenRandom(NULL, id->bytes, (ULONG)sizeof(id->bytes),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static int call_sample(VmkRuntime runtime) {
    const uint8_t input[] = {0, 1, 127, 255};
    uint8_t output[sizeof(input)] = {0};
    VmkScalar args[] = {
        {VMK_SCALAR_U64, 0, UINT64_C(0x9000000000000000)},
        {VMK_SCALAR_I64, 0, UINT64_MAX - 9}
    };
    VmkInvokeV1 call = {
        sizeof(VmkInvokeV1), VMK_ABI_VERSION, {{0}}, args, 2,
        {input, sizeof(input)}, {output, sizeof(output)}
    };
    VmkInvokeResultV1 result = {
        sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {0, 0, 0}, 0
    };
    if (!fresh_request(&call.request_id) ||
        vmk_invoke(runtime, &call, &result) != VMK_OK ||
        result.scalar.kind != VMK_SCALAR_I64 ||
        result.scalar.bits != UINT64_MAX - 16 ||
        result.output_len != sizeof(input) ||
        memcmp(input, output, sizeof(input)) != 0) {
        return 0;
    }
    return vmk_cancel(runtime, call.request_id) == VMK_NOT_FOUND;
}

static int call_without_buffers(VmkRuntime runtime) {
    VmkScalar args[] = {
        {VMK_SCALAR_U64, 0, 0},
        {VMK_SCALAR_I64, 0, 0}
    };
    VmkInvokeV1 call = {
        sizeof(VmkInvokeV1), VMK_ABI_VERSION, {{0}}, args, 2,
        {NULL, 0}, {NULL, 0}
    };
    VmkInvokeResultV1 result = {
        sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {0, 0, 0}, UINT64_MAX
    };
    return fresh_request(&call.request_id) &&
           vmk_invoke(runtime, &call, &result) == VMK_OK &&
           result.scalar.kind == VMK_SCALAR_I64 &&
           result.scalar.bits == 42 &&
           result.output_len == 0;
}

static int rejects_short_output(VmkRuntime runtime) {
    const uint8_t input[] = {1, 2};
    uint8_t output = 0xA5;
    VmkScalar args[] = {
        {VMK_SCALAR_U64, 0, 1},
        {VMK_SCALAR_I64, 0, 0}
    };
    VmkInvokeV1 call = {
        sizeof(VmkInvokeV1), VMK_ABI_VERSION, {{0}}, args, 2,
        {input, sizeof(input)}, {&output, sizeof(output)}
    };
    VmkInvokeResultV1 result = {
        sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {VMK_SCALAR_U64, 0, 71}, 83
    };
    return fresh_request(&call.request_id) &&
           vmk_invoke(runtime, &call, &result) == VMK_OUTPUT_TOO_SMALL &&
           result.scalar.kind == VMK_SCALAR_U64 && result.scalar.bits == 71 &&
           result.output_len == 83 && output == 0xA5;
}

int main(int argc, char **argv) {
    VmkInitializeV1 init = {
        sizeof(VmkInitializeV1), VMK_ABI_VERSION, VMK_PROFILE_LAB, 0,
        {NULL, 0}, {NULL, 0}
    };
    VmkRuntime runtime = 0;
    if (argc != 3 || !load_bytes(argv[1], &init.descriptor) ||
        !load_bytes(argv[2], &init.program)) {
        fputs("usage: r05_abi.exe r05_descriptor.bin r05_program.bin\n", stderr);
        free((void *)init.descriptor.data);
        return 1;
    }
    VmkStatus initialized = vmk_initialize(&init, &runtime);
    free((void *)init.descriptor.data);
    free((void *)init.program.data);
    if (initialized != VMK_OK) {
        fprintf(stderr, "vmk_initialize returned %lu\n", (unsigned long)initialized);
        return 2;
    }
    int ok = call_sample(runtime) && call_without_buffers(runtime) && rejects_short_output(runtime);
    if (vmk_shutdown(runtime) != VMK_OK || vmk_shutdown(runtime) != VMK_NOT_FOUND || !ok) {
        fputs("R05 C ABI sample failed\n", stderr);
        return 3;
    }
    puts("r05 ABI result: i64=-17 bytes=00017fff; i64=42 bytes=0");
    return 0;
}
