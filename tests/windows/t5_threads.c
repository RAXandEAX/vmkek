#include <windows.h>

enum { WORKERS = 4, ROUNDS = 64, FIXTURE_OK = 17 };

typedef struct {
    HANDLE gate;
    unsigned index;
} Worker;

static volatile LONG completed_workers;

__declspec(dllexport) __declspec(noinline)
unsigned long long fixture_thread_leaf(unsigned long long value) {
    return value * 7 + 11;
}

#ifndef VMKEK_LEAF_ONLY
static unsigned long long fixture_native_callback(unsigned long long value);

__declspec(dllexport) __declspec(noinline)
unsigned long long fixture_thread_target(unsigned long long value, unsigned long long reenter) {
    if (reenter != 0) {
        return fixture_native_callback(value + 5) + value;
    }
    return value * 7 + 11;
}

__declspec(noinline) static unsigned long long fixture_native_callback(unsigned long long value) {
    /* The native callback enters the same protected function through its PE entry. */
    return fixture_thread_target(value, 0);
}
#endif

static DWORD WINAPI check_worker(void *argument) {
    const Worker *worker = argument;
    if (WaitForSingleObject(worker->gate, 5000) != WAIT_OBJECT_0) return 21;
    for (unsigned round = 0; round < ROUNDS; ++round) {
        unsigned long long value = worker->index * ROUNDS + round;
        if (fixture_thread_leaf(value) != value * 7 + 11) return 22;
#ifndef VMKEK_LEAF_ONLY
        unsigned long long nested = fixture_thread_target(value, 1);
        if (nested != (value + 5) * 7 + 11 + value) return 22;
#endif
    }
    InterlockedIncrement(&completed_workers);
    return FIXTURE_OK;
}

static DWORD fixture_main(void) {
    HANDLE threads[WORKERS] = {0};
    Worker workers[WORKERS];
    HANDLE gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (gate == NULL) return 23;
    for (unsigned index = 0; index < WORKERS; ++index) {
        workers[index].gate = gate;
        workers[index].index = index;
        threads[index] = CreateThread(NULL, 0, check_worker, &workers[index], 0, NULL);
        if (threads[index] == NULL) ExitProcess(24);
    }
    if (!SetEvent(gate)) ExitProcess(25);
    if (WaitForMultipleObjects(WORKERS, threads, TRUE, 8000) != WAIT_OBJECT_0) {
        ExitProcess(26);
    }
    DWORD result = FIXTURE_OK;
    for (unsigned index = 0; index < WORKERS; ++index) {
        DWORD status = 0;
        if (!GetExitCodeThread(threads[index], &status) || status != FIXTURE_OK) {
            result = status != 0 ? status : 27;
        }
        CloseHandle(threads[index]);
    }
    CloseHandle(gate);
    if (result == FIXTURE_OK && completed_workers != WORKERS) return 28;
    return result;
}

void fixture_entry(void) {
    ExitProcess(fixture_main());
}
