#include <windows.h>

__declspec(dllexport) __declspec(noinline)
unsigned long long fixture_attach_leaf(unsigned long long value) {
    return value * 7 + 10;
}

static HANDLE open_gate(const wchar_t *key, DWORD access) {
    wchar_t name[64];
    DWORD size = GetEnvironmentVariableW(key, name, ARRAYSIZE(name));
    if (size == 0 || size >= ARRAYSIZE(name)) return NULL;
    return OpenEventW(access, FALSE, name);
}

static DWORD fixture_main(void) {
    wchar_t expected[2];
    if (GetEnvironmentVariableW(L"VMKEK_T6_DEBUG_EXPECTED", expected, ARRAYSIZE(expected)) != 1 ||
        (expected[0] != L'0' && expected[0] != L'1') || IsDebuggerPresent()) return 24;
    HANDLE ready = open_gate(L"VMKEK_T6_READY", EVENT_MODIFY_STATE);
    HANDLE release = open_gate(L"VMKEK_T6_RELEASE", SYNCHRONIZE);
    if (ready == NULL || release == NULL) ExitProcess(21);
    if (!SetEvent(ready)) ExitProcess(22);
    CloseHandle(ready);
    DWORD wait = WaitForSingleObject(release, 10000);
    CloseHandle(release);
    if (wait != WAIT_OBJECT_0) return 23;
    if ((IsDebuggerPresent() != FALSE) != (expected[0] == L'1')) return 25;
    return (DWORD)fixture_attach_leaf(1);
}

void fixture_entry(void) {
    ExitProcess(fixture_main());
}
