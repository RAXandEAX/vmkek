#ifndef VMKEK_RUNTIME_H
#define VMKEK_RUNTIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMK_ABI_VERSION UINT32_C(1)
#define VMK_ONLINE_ABI_VERSION UINT32_C(2)

typedef uint32_t VmkStatus;
#define VMK_OK UINT32_C(0)
#define VMK_UNAVAILABLE UINT32_C(1)
#define VMK_EXPIRED UINT32_C(2)
#define VMK_DENIED UINT32_C(3)
#define VMK_REVOKED UINT32_C(4)
#define VMK_INCOMPATIBLE UINT32_C(5)
#define VMK_INVALID_PACKAGE UINT32_C(6)
#define VMK_RESOURCE_LIMIT UINT32_C(7)
#define VMK_CANCELLED UINT32_C(8)
#define VMK_INTERNAL UINT32_C(9)
#define VMK_INVALID_ARGUMENT UINT32_C(10)
#define VMK_OUTPUT_TOO_SMALL UINT32_C(11)
#define VMK_NOT_FOUND UINT32_C(12)

#define VMK_PROFILE_LAB UINT32_C(1)
#define VMK_PROFILE_ONLINE UINT32_C(2)

#define VMK_SCALAR_NONE UINT32_C(0)
#define VMK_SCALAR_U64 UINT32_C(1)
#define VMK_SCALAR_I64 UINT32_C(2)

typedef uint64_t VmkRuntime;
typedef struct VmkRequestId {
    uint8_t bytes[16];
} VmkRequestId;

typedef struct VmkBytes {
    const uint8_t *data;
    uint64_t len;
} VmkBytes;

typedef struct VmkOutput {
    uint8_t *data;
    uint64_t capacity;
} VmkOutput;

typedef struct VmkScalar {
    uint32_t kind;
    uint32_t reserved;
    uint64_t bits;
} VmkScalar;

typedef struct VmkInitializeV1 {
    uint32_t size;
    uint32_t abi_version;
    uint32_t profile;
    uint32_t reserved;
    VmkBytes descriptor;
    VmkBytes program;
} VmkInitializeV1;

typedef struct VmkInitializeV2 {
    uint32_t size;
    uint32_t abi_version;
    uint32_t profile;
    uint32_t reserved;
    VmkBytes config_path;
    uint64_t reserved_tail[2];
} VmkInitializeV2;

typedef struct VmkInvokeV1 {
    uint32_t size;
    uint32_t abi_version;
    VmkRequestId request_id;
    const VmkScalar *scalars;
    uint64_t scalar_count;
    VmkBytes input;
    VmkOutput output;
} VmkInvokeV1;

typedef struct VmkInvokeResultV1 {
    uint32_t size;
    uint32_t abi_version;
    VmkScalar scalar;
    uint64_t output_len;
} VmkInvokeResultV1;

/*
 * x86-64 C ABI. Set size to sizeof(struct), abi_version to VMK_ABI_VERSION,
 * and all reserved fields to zero. I64 bits are the two's-complement bit
 * pattern of the signed value. Zero-length spans may have NULL data.
 *
 * Each pointer must designate valid, aligned storage for its declared extent
 * throughout the call. Inputs must be readable and stable. Writable extents
 * require exclusive access and must be disjoint from inputs and other output
 * extents. A failed call leaves its caller-owned outputs unchanged.
 *
 * R05 Lab accepts local unsigned descriptor/program pairs and verifies the
 * descriptor's program digest. V1 Online returns VMK_UNAVAILABLE.
 * V2 Online uses a trusted installation configuration on Windows and Linux x64.
 * Linux requires the VMKR21 format with an owner-only sibling device.key.
 * A Linux child forked after runtime use must exec before opening a new session.
 * Runtime calls in that inherited child fail before reading caller storage.
 * config_path is an absolute UTF-8 path without a trailing NUL. Call it
 * outside DllMain or loader lock. Invoke/result structures retain v1.
 * The inline adapter below calls the same exported initializer.
 */
VmkStatus vmk_initialize(const VmkInitializeV1 *args, VmkRuntime *out_runtime);

static inline VmkStatus vmk_initialize_online(const VmkInitializeV2 *args,
                                               VmkRuntime *out_runtime) {
    return vmk_initialize((const VmkInitializeV1 *)(const void *)args, out_runtime);
}

/*
 * Generate a fresh, nonzero request ID with a CSPRNG for each invocation.
 * Set size and abi_version in out_result before calling. VMK_SCALAR_NONE means
 * there is no scalar result. Buffers and scalar values are copied by the runtime.
 */
VmkStatus vmk_invoke(VmkRuntime runtime, const VmkInvokeV1 *args,
                     VmkInvokeResultV1 *out_result);

/*
 * Cancellation is ordered against result publication. VMK_NOT_FOUND means no
 * active invocation has that ID. Shutdown retires the handle and requests
 * cancellation of its active calls. Keep invocation buffers valid until those
 * calls return, including calls that overlap shutdown.
 */
VmkStatus vmk_cancel(VmkRuntime runtime, VmkRequestId request_id);
VmkStatus vmk_shutdown(VmkRuntime runtime);

#ifdef __cplusplus
}
#endif

#endif
