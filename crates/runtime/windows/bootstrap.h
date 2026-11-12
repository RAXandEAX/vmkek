#ifndef VMKEK_WINDOWS_BOOTSTRAP_H
#define VMKEK_WINDOWS_BOOTSTRAP_H

#include <windows.h>
#include "vmkek_runtime.h"

typedef struct VmkWindowsRuntime {
    HMODULE image;
    HANDLE image_pin;
    VmkStatus (*initialize)(const VmkInitializeV1 *, VmkRuntime *);
    VmkStatus (*invoke)(VmkRuntime, const VmkInvokeV1 *, VmkInvokeResultV1 *);
    VmkStatus (*cancel)(VmkRuntime, VmkRequestId);
    VmkStatus (*shutdown)(VmkRuntime);
} VmkWindowsRuntime;

/*
 * Call from ordinary program code after loader lock. The application supplies
 * a local absolute installation directory whose entire path and ACLs it trusts,
 * and a manufacturer P-256 public key in uncompressed SEC1 form.
 * The caller also trusts its unpackaged executable, activation context,
 * existing process modules, and Windows System32. The launcher directory
 * ACL must prevent untrusted child creation. The file pins do not verify ACLs.
 * An executable .local
 * redirection marker is rejected before loading. Installation may use a
 * separate trusted directory.
 * The bootstrap supports one loaded runtime DLL per process. Installation
 * ancestors and files must be ordinary local paths. The DLL remains pinned
 * until close, which requires all handles and invocations to have shut down.
 */
VmkStatus vmk_windows_open(const wchar_t *directory, const uint8_t manufacturer[65],
                           uint32_t initialize_abi, VmkWindowsRuntime *out);
void vmk_windows_close(VmkWindowsRuntime *runtime);

#endif
