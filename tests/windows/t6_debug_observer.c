#include <windows.h>
#include <stdio.h>
#include <wchar.h>

typedef enum { EARLY_DEBUG, GATED_CLEAN, GATED_ATTACH } Mode;

static DWORD observe_debug(HANDLE release) {
    BOOL initial_breakpoint_seen = FALSE;
    const ULONGLONG deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline) {
        DEBUG_EVENT event;
        if (!WaitForDebugEvent(&event, 250)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            return 2;
        }
        DWORD reply = DBG_CONTINUE;
        DWORD exit_code = 0;
        BOOL gate_released = TRUE;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_DEBUG_INFO *exc = &event.u.Exception;
            DWORD code = exc->ExceptionRecord.ExceptionCode;
            printf("exception=0x%08lx first=%lu\n", code, exc->dwFirstChance);
            if (code == EXCEPTION_BREAKPOINT && !initial_breakpoint_seen) {
                initial_breakpoint_seen = TRUE;
                if (release != NULL) gate_released = SetEvent(release);
            } else {
                reply = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            exit_code = event.u.ExitProcess.dwExitCode;
            break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, reply) || !gate_released) return 2;
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            if (release != NULL && !initial_breakpoint_seen) return 2;
            return exit_code;
        }
    }
    return 2;
}

static HANDLE make_gate(const wchar_t *label, const wchar_t *key) {
    wchar_t name[64];
    if (swprintf_s(name, ARRAYSIZE(name), L"Local\\vmkek-t6-%lu-%ls", GetCurrentProcessId(), label) < 0) {
        return NULL;
    }
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, name);
    if (event == NULL) return NULL;
    if (GetLastError() == ERROR_ALREADY_EXISTS || !SetEnvironmentVariableW(key, name)) {
        CloseHandle(event);
        return NULL;
    }
    return event;
}

static DWORD observe_gated(const PROCESS_INFORMATION *child, Mode mode, HANDLE ready, HANDLE release) {
    HANDLE wait_for[] = { ready, child->hProcess };
    if (WaitForMultipleObjects(ARRAYSIZE(wait_for), wait_for, FALSE, 10000) != WAIT_OBJECT_0) {
        fputs("Fixture did not reach its readiness gate\n", stderr);
        return 2;
    }
    puts("fixture initialized and waiting before protected call");
    if (mode == GATED_ATTACH) {
        if (!DebugActiveProcess(child->dwProcessId)) {
            fprintf(stderr, "DebugActiveProcess failed: %lu\n", GetLastError());
            return 2;
        }
        return observe_debug(release);
    }
    DWORD status = 2;
    if (!SetEvent(release) ||
        WaitForSingleObject(child->hProcess, 10000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(child->hProcess, &status)) return 2;
    return status;
}

static DWORD run_child(const wchar_t *path, Mode mode, HANDLE ready, HANDLE release) {
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION child = {0};
    DWORD flags = CREATE_NO_WINDOW;
    if (mode == EARLY_DEBUG) flags |= DEBUG_ONLY_THIS_PROCESS;
    if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, flags, NULL, NULL, &startup, &child)) {
        fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
        return 2;
    }
    DWORD status = mode == EARLY_DEBUG ? observe_debug(NULL) :
                                        observe_gated(&child, mode, ready, release);
    if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess, 2);
        WaitForSingleObject(child.hProcess, 1000);
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return status;
}

int wmain(int argc, wchar_t **argv) {
    Mode mode = EARLY_DEBUG;
    if (argc == 3 && wcscmp(argv[2], L"--gated") == 0) mode = GATED_CLEAN;
    else if (argc == 3 && wcscmp(argv[2], L"--attach-after-ready") == 0) mode = GATED_ATTACH;
    else if (argc != 2) return 2;
    HANDLE ready = NULL, release = NULL;
    if (mode != EARLY_DEBUG) {
        ready = make_gate(L"ready", L"VMKEK_T6_READY");
        release = make_gate(L"release", L"VMKEK_T6_RELEASE");
    }
    DWORD status = 2;
    if (mode == EARLY_DEBUG ||
        (ready != NULL && release != NULL &&
         SetEnvironmentVariableW(L"VMKEK_T6_DEBUG_EXPECTED", mode == GATED_ATTACH ? L"1" : L"0"))) {
        status = run_child(argv[1], mode, ready, release);
    }
    if (ready != NULL) CloseHandle(ready);
    if (release != NULL) CloseHandle(release);
    printf("child exit=0x%08lx\n", status);
    fflush(stdout);
    ExitProcess(status);
}
