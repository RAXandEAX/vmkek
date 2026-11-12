#include <windows.h>
#include <stdint.h>

typedef unsigned long long (*Operation)(unsigned long long);

__declspec(dllexport) __declspec(noinline)
unsigned long long fixture_cfg_target(unsigned long long value) {
    return value * 7 + 10;
}

/* Keep the negative control native in both images. */
__declspec(noinline)
static unsigned long long fixture_cfg_control(unsigned long long value) {
    return value * 7 + 10;
}

static Operation volatile selected = fixture_cfg_target;

void fixture_entry(void) {
#ifdef VMKEK_REQUIRE_ASLR
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {0};
    if ((uintptr_t)GetModuleHandleW(NULL) == 0x140000000ull) ExitProcess(18);
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy,
                                    &policy, sizeof(policy)) ||
        !policy.EnableControlFlowGuard) ExitProcess(19);
#endif
    wchar_t flag[2];
    if (GetEnvironmentVariableW(L"VMKEK_T5_CFG_NEGATIVE", flag, ARRAYSIZE(flag)) != 0) {
        selected = (Operation)((uintptr_t)fixture_cfg_control + 1u);
    }
    ExitProcess((UINT)selected(1));
}
