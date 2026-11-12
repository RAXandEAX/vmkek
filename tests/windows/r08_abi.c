#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "vmkek_runtime.h"

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

static int check_call(VmkRuntime runtime, uint64_t left, uint64_t right) {
    VmkScalar scalars[] = {
        {VMK_SCALAR_U64, 0, left},
        {VMK_SCALAR_U64, 0, right}
    };
    VmkInvokeV1 call = {
        sizeof(VmkInvokeV1), VMK_ABI_VERSION, {{0}}, scalars, 2, {NULL, 0}, {NULL, 0}
    };
    VmkInvokeResultV1 result = {
        sizeof(VmkInvokeResultV1), VMK_ABI_VERSION, {0, 0, 0}, UINT64_MAX
    };
    if (BCryptGenRandom(NULL, call.request_id.bytes, (ULONG)sizeof(call.request_id.bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 ||
        vmk_invoke(runtime, &call, &result) != VMK_OK) {
        return 0;
    }
    return result.scalar.kind == VMK_SCALAR_U64 && result.scalar.bits == left + right &&
           result.output_len == 0;
}

static int check_depth(VmkBytes module, const char *descriptor_path, unsigned depth) {
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
    int ok = check_call(runtime, UINT64_MAX, 1) && check_call(runtime, UINT32_MAX, 1);
    for (uint64_t index = 0; ok && index < 1024; ++index) {
        ok = check_call(runtime, index * UINT64_C(0x9e3779b9), UINT64_MAX - index);
    }
    if (vmk_shutdown(runtime) != VMK_OK || !ok) {
        return 0;
    }
    printf("r08 depth %u: 1026 calls, fuel cap 64, matched wrapping arithmetic\n", depth);
    return 1;
}

int main(int argc, char **argv) {
    VmkBytes module = {NULL, 0};
    if (argc != 5 || !read_bytes(argv[1], &module)) {
        fputs("usage: r08_abi.exe module.bin depth2.bin depth3.bin depth4.bin\n", stderr);
        return 1;
    }
    int ok = check_depth(module, argv[2], 2) && check_depth(module, argv[3], 3) &&
             check_depth(module, argv[4], 4);
    free((void *)module.data);
    return ok ? 0 : 2;
}
