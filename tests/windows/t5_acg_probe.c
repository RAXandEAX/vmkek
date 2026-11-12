/* Tests only fixed-base, locally compiled lab fixtures. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

typedef enum { ACG, CET, CFG } Policy;

static uintptr_t image_limit(HANDLE process, uintptr_t base) {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (!ReadProcessMemory(process, (void *)base, &dos, sizeof(dos), NULL) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) {
        return 0;
    }
    if (!ReadProcessMemory(process, (void *)(base + dos.e_lfanew), &nt, sizeof(nt), NULL) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage == 0 || nt.OptionalHeader.SizeOfImage > 0x4000000) {
        return 0;
    }
    return base + nt.OptionalHeader.SizeOfImage;
}

static int check_pages(HANDLE process) {
    const uintptr_t image_base = 0x140000000ull;
    const uintptr_t limit = image_limit(process, image_base);
    if (limit == 0) {
        fputs("Could not read the fixed-base image headers\n", stderr);
        return 0;
    }
    unsigned executable = 0, writable = 0;
    for (uintptr_t cursor = image_base; cursor < limit;) {
        MEMORY_BASIC_INFORMATION region;
        if (!VirtualQueryEx(process, (void *)cursor, &region, sizeof(region)) ||
            region.Type != MEM_IMAGE || (uintptr_t)region.AllocationBase != image_base) {
            fputs("Unexpected mapping inside the image span\n", stderr);
            return 0;
        }
        DWORD mode = region.Protect & 0xffu;
        if (mode == PAGE_EXECUTE_READWRITE || mode == PAGE_EXECUTE_WRITECOPY) {
            fputs("Writable executable image mapping\n", stderr);
            return 0;
        }
        executable += mode == PAGE_EXECUTE || mode == PAGE_EXECUTE_READ;
        writable += mode == PAGE_READWRITE || mode == PAGE_WRITECOPY;
        cursor = (uintptr_t)region.BaseAddress + region.RegionSize;
    }
    printf("Executable image regions: %u, writable image regions: %u\n", executable, writable);
    return executable != 0 && writable != 0;
}

static int check_policy(HANDLE process, Policy policy) {
    if (policy == ACG) {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic = {0};
        if (!GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &dynamic, sizeof(dynamic))) {
            fprintf(stderr, "ACG query failed: %lu\n", GetLastError());
            return 0;
        }
        printf("ProhibitDynamicCode=%u AllowThreadOptOut=%u\n",
               dynamic.ProhibitDynamicCode, dynamic.AllowThreadOptOut);
        return dynamic.ProhibitDynamicCode != 0 && dynamic.AllowThreadOptOut == 0;
    }
    if (policy == CET) {
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY shadow = {0};
        if (!GetProcessMitigationPolicy(process, ProcessUserShadowStackPolicy, &shadow, sizeof(shadow))) {
            fprintf(stderr, "CET shadow-stack query failed: %lu\n", GetLastError());
            return 0;
        }
        printf("EnableUserShadowStack=%u\n", shadow.EnableUserShadowStack);
        return shadow.EnableUserShadowStack != 0;
    }
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {0};
    if (!GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg))) {
        fprintf(stderr, "CFG query failed: %lu\n", GetLastError());
        return 0;
    }
    printf("EnableControlFlowGuard=%u\n", cfg.EnableControlFlowGuard);
    return cfg.EnableControlFlowGuard != 0;
}

static int run_fixture(const PROCESS_INFORMATION *child) {
    DWORD count = ResumeThread(child->hThread);
    if (count != 1) {
        if (count == (DWORD)-1) fprintf(stderr, "ResumeThread failed: %lu\n", GetLastError());
        else fprintf(stderr, "Unexpected suspension count: %lu\n", count);
        return 0;
    }
    if (WaitForSingleObject(child->hProcess, 10000) != WAIT_OBJECT_0) {
        fputs("Fixture timed out or wait failed\n", stderr);
        return 0;
    }
    DWORD status;
    if (!GetExitCodeProcess(child->hProcess, &status)) return 0;
    printf("Fixture exit=0x%08lx\n", status);
    return status == 17;
}

static int start_fixture(STARTUPINFOEXW *startup, const wchar_t *path, Policy policy, int run) {
    PROCESS_INFORMATION child = {0};
    if (!CreateProcessW(path, NULL, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &startup->StartupInfo, &child)) {
        fprintf(stderr, "Mitigated process creation failed: %lu\n", GetLastError());
        return 1;
    }
    int status = 1;
    if (!check_policy(child.hProcess, policy)) {
        status = 3;
    } else if (check_pages(child.hProcess) && (!run || run_fixture(&child))) {
        status = 0;
    }
    if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0 &&
        (!TerminateProcess(child.hProcess, 1) ||
         WaitForSingleObject(child.hProcess, 5000) != WAIT_OBJECT_0)) {
        status = 1;
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return status;
}

int wmain(int argc, wchar_t **argv) {
    STARTUPINFOEXW startup = {0};
    SIZE_T bytes = 0;
    Policy policy = ACG;
    int run = 0;
    if (argc < 2 || argc > 4) return 2;
    for (int i = 2; i < argc; ++i) {
        if (wcscmp(argv[i], L"--cet") == 0) policy = CET;
        else if (wcscmp(argv[i], L"--cfg") == 0) policy = CFG;
        else if (wcscmp(argv[i], L"--run") == 0) run = 1;
        else return 2;
    }
    DWORD64 flags[2] = {0, 0};
    if (policy == CET) flags[1] = PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON;
    else if (policy == CFG) flags[0] = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
    else flags[0] = PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;

    startup.StartupInfo.cb = sizeof(startup);
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (startup.lpAttributeList == NULL) return 2;
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) {
        HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
        return 2;
    }
    int status = 1;
    if (UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                  PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                  flags, sizeof(flags), NULL, NULL)) {
        status = start_fixture(&startup, argv[1], policy, run);
    } else {
        fprintf(stderr, "Mitigation startup attribute failed: %lu\n", GetLastError());
    }
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    return status;
}
