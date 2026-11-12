#include <windows.h>
#define FIXTURE_EXCEPTION ((DWORD)0xe1234567)

__declspec(noinline) void fixture_raise(void) {
    RaiseException(FIXTURE_EXCEPTION, 0, 0, NULL);
}

__declspec(dllexport) __declspec(noinline) unsigned long long fixture_target(unsigned long long fail) {
    if (fail) fixture_raise();
    return 17;
}

__declspec(dllexport) __declspec(noinline) unsigned long long fixture_unrelated_leaf(unsigned long long value) {
    return value * 7 + 3;
}

__declspec(noinline) static int catches_fixture_exception(void) {
    __try {
        fixture_target(1);
        return 0;
    } __except (GetExceptionCode() == FIXTURE_EXCEPTION ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return 1;
    }
}

static int fixture_main(void) {
    if (fixture_unrelated_leaf(5) != 38) return 24;
    if (fixture_target(0) != 17) return 22;
    for (unsigned round = 0; round < 64; ++round) {
        if (!catches_fixture_exception()) return 23;
        if (fixture_target(0) != 17) return 25;
    }
    return 17;
}

void fixture_entry(void) {
    ExitProcess((UINT)fixture_main());
}
