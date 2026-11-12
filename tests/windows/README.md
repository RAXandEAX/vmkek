# Windows x64 T4–T6 lab

Run `t4_t6.ps1` from an x64 Native Tools PowerShell with MSVC on PATH. Keep the script and its C sources together. When the checkout lives on a WSL share, copy the files to a local Windows directory if PowerShell rejects scripts on network paths.

Use a built Windows CLI or a WSL CLI with access to the Windows temporary directory.

```powershell
.\t4_t6.ps1 -Protector C:\path\to\vmkek.exe
.\t4_t6.ps1 -WslProtector /path/to/vmkek/target/debug/vmkek
.\t4_t6.ps1 -WslProtector /path/to/vmkek/target/debug/vmkek -Stage T5,T6
```

The runner creates and prints a fresh temporary directory. It builds with `protect --windows-native` and runs each requested stage independently. Omit `-Stage` to run the full matrix.

| Stage | Live check |
| --- | --- |
| T4 | A native MSVC function calls `RaiseException` through a virtualized nonleaf function. The original SEH handler must catch it in both builds. The test repeats 64 exception and clean-call pairs, then returns `0x11`. A control protects a separate leaf while keeping the exception path native. |
| T5 | Four threads released by one gate each run 64 checks of a selected leaf function. Clean, ACG and process CFG runs must return `0x11`. The CET run uses a separately linked `/CETCOMPAT` fixture and verifies that user shadow stacks are active. |
| T5-Reentry | A virtualized nonleaf function calls a native callback that enters the same protected function before the first invocation returns. Four threads each check 64 reentries. |
| T5-CFG | MSVC `/guard:cf` relocatable control must return `0x11` on the valid indirect call and `0xC0000409` on an invalid target inside the fixture. The same assertions apply after protection. Both runs require an actual load at a nonpreferred base and active process CFG. The fixed control records metadata and live behavior separately. |
| T6 | The leaf fixture runs normally and under the standard debugger event loop. The original must return `0x11` in both runs. The protected fixture must return `0x11` when clean and `0xDEB6` under the debugger at startup. A separate gated fixture must return `0x11` when released without a debugger and `0xBAD1` if the debugger attaches after startup. A separate pair varies the PE load-config global flag and checks startup without a debugger. |

The debugger observer handles documented Win32 events without changing the child's memory or registers. The late-attach fixture opens two named events, signals readiness after loader initialization, and waits before invoking the selected leaf. The observer calls `DebugActiveProcess` on its own child and releases the leaf after receiving the initial breakpoint. The fixture requires `IsDebuggerPresent` to report 0 before signaling readiness. Immediately before the leaf call it requires 0 for the gated clean case and 1 for the attached case. These checks cover startup refusal and a live VM call after attachment. The per-signal T6 matrix runs in M-EMU. [Win32 debugging events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events), [DebugActiveProcess](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess), [IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent).

The NtGlobalFlag fixture uses `IMAGE_LOAD_CONFIG_DIRECTORY64.GlobalFlagsSet` to apply a flag at load time to the fixture process. Both original builds check `IsDebuggerPresent` and must return `0x11` without a debugger. The protected build with the flag clear must return `0x11`. The protected build with bit `0x10` set must return `0xDEB6`. [PE load configuration](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-load-configuration-structure-image-only).

The SEH, thread and debugger fixtures use fixed-base PE files and `/guard:no`. The process CFG run in T5 verifies the policy bit and executes the leaf fixture. T5-CFG tests instrumented indirect calls separately. The fixed CFG control allowed the invalid target on the lab host, including under a forced process CFG policy. Both relocatable builds denied it. The tested native unwind subset covers canonical Win64 frames and a handler in the original caller. The tested CFG profile selects functions without guest calls.

## Standalone policy probe

Compile the probe in the same x64 tools shell. Pass the absolute path to a synthetic lab fixture with image base `0x140000000`.

```powershell
cl /nologo /W4 /WX t5_acg_probe.c /Fe:t5_acg_probe.exe
.\t5_acg_probe.exe C:\path\to\threads-protected.exe
.\t5_acg_probe.exe C:\path\to\threads-protected.exe --cfg --run
.\t5_acg_probe.exe C:\path\to\threads-cet-protected.exe --cet --run
```

The probe starts the process suspended, verifies the requested policy and checks its image mappings for writable-executable pages. By default it terminates the child while still suspended. With `--run` it resumes the fixture and requires exit `0x11`. Run this mode only for the original fixture or the `--windows-native` build. Exit code `3` means that the requested policy could not be verified. ACG is the default. [Process creation mitigation options](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute), [policy queries](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy).
