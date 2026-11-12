#include <windows.h>

#ifndef VMKEK_GLOBAL_FLAGS
#define VMKEK_GLOBAL_FLAGS 0
#endif

/* The Windows loader applies this to the fixture process at startup. */
const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64),
    .GlobalFlagsSet = VMKEK_GLOBAL_FLAGS,
};

__declspec(dllexport) __declspec(noinline)
unsigned long long fixture_global_leaf(unsigned long long value) {
    return value * 7 + 10;
}

void fixture_entry(void) {
    if (IsDebuggerPresent()) ExitProcess(24);
    ExitProcess((DWORD)fixture_global_leaf(1));
}
