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

The T6 observer handles documented Win32 events and leaves the child's memory and registers intact. The late-attach fixture opens two named events, signals readiness after loader initialization, and waits before invoking the selected leaf. The observer calls `DebugActiveProcess` on its own child and releases the leaf after receiving the initial breakpoint. The fixture requires `IsDebuggerPresent` to report 0 before signaling readiness. Immediately before the leaf call it requires 0 for the gated clean case and 1 for the attached case. These checks cover startup refusal and a live VM call after attachment. The per-signal T6 matrix runs in M-EMU. [Win32 debugging events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events), [DebugActiveProcess](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess), [IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent).

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

## A02 Windows x64 observation lab

Open an x64 Developer PowerShell with PowerShell 7 or newer, Rust 1.95.0
with the `x86_64-pc-windows-msvc` target, and the Visual Studio 2022 C++ build
tools with Windows SDK 10.0.26100.0 or newer. Use a local Windows checkout for
the runner and the evidence directory. The lab was verified on Windows 11
26H2 build 26300.9974.

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case All -Profile observe -Repeat 3 -OutputDir docs/plans/anti-analysis/evidence/A02
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case All -Profile enforce -Repeat 3 -OutputDir docs/plans/anti-analysis/evidence/A02
```

`-Case` also accepts `Clean`, `StartupDebugger`, `LateDebugger`, `WinDbg`,
`X64dbg`, `IDA`, `Ghidra`, `BinaryNinja`, and `Frida`. The first three
build and exercise a fixed owned fixture. The other cases record tool
discovery on PATH and whether a native launch or attach was exercised.
The current runner has an adapter for the built-in Win32 debugger harness.
External tool cases are optional and emit `not-run` with a reason. A path
match, including a Windows app execution alias, is evidence of discovery.

Each required iteration starts a new observer and fixture. The observer
records creation, readiness, successful debugger attachment where
applicable, the initial breakpoint, and child exit from Win32 events.
The fixture separately records phases, signed policy identity, debugger
observation, admission decision, and the result of its protected ABI call.
In observe mode a confirmed debugger records a report-only decision and the
call completes. In enforce mode it receives a local denial and the output
buffers stay unchanged. Clean controls complete in both modes.

`-Repeat` accepts 1 to 30. The runner creates a new `a02-*` evidence folder
per invocation, with one `manifest.json`, separate bounded stdout/stderr,
and a fixture record per required iteration. Each build command has a
180-second limit and each observer a 25-second limit. Each launch runs in its own
kill-on-close job. The observer also assigns its fixture to a nested job at
creation. An iteration failure or required skip yields
exit 1. The runner uses a private temporary build directory and cleans it up.

## A03 native debugger matrix

Use the same x64 Developer PowerShell. The qualified host for this matrix
is Windows 11 x64 build 26300.9974.

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Debugger -Profile observe -Repeat 30 -OutputDir docs/plans/anti-analysis/evidence/A03
```

The matrix includes startup, late attach, and late detach followed by a
second sample of the same process. It covers the documented debugger
attachment state in the signed Lab profile. The two Windows APIs form one
dependency group. The software breakpoint is requested by the fixture.
The hardware breakpoint uses only the fixture's designated code address
and main thread, checks the first-chance event, and restores the captured
debug registers before a second call to the function. The observer never
writes the fixture's image. [Win32 debugger loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop) · [DebugBreak](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak) · [Detach](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop)

Clean controls cover ordinary execution, a `0xCC` input byte, CPU work,
repeated calls on a recursive host stack, concurrent calls, the unarmed
breakpoint target, and a Visual
Studio Code instance editing a synthetic source file without attachment.
The IDE uses a separate settings and extensions directory in an owned job.
Use `-IdeExecutable` to select another installed `Code.exe`. If the fixture
IDE is unavailable, the required control records `not-run` and the matrix
returns exit 1. [Visual Studio Code CLI](https://code.visualstudio.com/docs/configure/command-line)

The manifest records a capability for this build and the unsupported
legacy-layout and kernel scopes. Preexisting standalone paths retain
their separate T6 evidence. Each required case supports 1 to 30 repeats.
The optional `-CargoTargetDir` reuses a caller-owned Cargo build cache that should be exclusive to the current run.

## A04 Windows x64 integrity lab

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Integrity -Profile observe -Repeat 30 -OutputDir docs/plans/anti-analysis/evidence/A04
```

The runner builds two revisions of an owned DLL and runs one isolated process
per repetition. The fixture checks a signed eight-byte inert marker in a
file-backed RX section after a nonpreferred load. It records relocation
exclusion, an altered signed marker, an alteration outside the signed range,
an unavailable page, module reference lifetime, and a signed epoch update.
The exported call verifies execution independently of the marker bytes.
The manifest contains per-pass bytes, elapsed time and actual process
mitigation flags. Integrity is an observe-only measurement case.

The prepared API holds the verified loader-path file with read-only sharing
and a reference to the loaded module. A new signed revision requires
preparation again. The launcher coordinates file replacement with unloading
and loading the new module. Mapped headers are checked before and after a
code pass. Only the PE ImageBase field may differ, and its loaded value must
equal the preferred or actual base. The signed file digest remains exact.
Code ranges must be immutable, file-backed RX and exclude recognized
relocation targets and loader-written slots. The measured scope does not
include imports, dynamic relocation formats, delay imports, writable
loader tables, or VM transitions outside the signed immutable ranges.

File preparation is capped at 128 MiB of file hash input and 4 MiB plus
192 KiB of layout/header reads. Each incremental pass reads two mapped header
snapshots of at most 64 KiB each and two snapshots of at most 64 KiB per rule
for up to 16 rules. Deadlines of 500 ms for preparation and 100 ms for
incremental sampling are checked between synchronous reads. The runner adds
its own process timeout. Repeated sampling has no disk reads for a prepared
revision. It does not certify intervening memory states.

## A05 native instrumentation matrix

Use x64 Developer PowerShell on the qualified Windows 11 build 26300.9974.
The runner expects the official Windows AMD64 Frida 16.6.6 Python wheel.
Set `VMKEK_A05_PYTHON` to the interpreter in a dedicated environment with
that wheel installed. Set `VMKEK_A05_GADGET` to the DLL extracted from the
matching official Windows x86_64 Gadget release. The runner verifies the
wheel's package members and the Gadget DLL by SHA-256 before use.
[Frida 16.6.6 release](https://github.com/frida/frida/releases/tag/16.6.6) · [Frida wheel](https://pypi.org/project/frida/16.6.6/)

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Instrumentation -Profile observe -Repeat 30 -OutputDir docs/plans/anti-analysis/evidence/A05
```

Each iteration launches the bundled synthetic fixture in a dedicated
kill-on-close job. The fixed tool script targets two designated exports
of its own DLL. Spawn, late attach, local-script Gadget, Interceptor, and
Stalker have separate activity witnesses. The stock tool release stays the
same when the fixture executable and DLL are renamed. The Gadget uses
local script mode. [Frida modes](https://frida.re/docs/modes/) · [Gadget script mode](https://frida.re/docs/gadget/#script) · [Stalker](https://frida.re/docs/stalker/)

The detector samples only a signed file-backed RX range. The laboratory
records tool activity, page protection, typed observation, policy
revision, and protected-call output independently. The profiler control
instruments a separate unsigned export and performs measured calls.
The controlled mismatch comes from an inert byte change made by the
fixture. The stock Stalker row and its clean control use a separately
hashed compiler-default research fixture. Other modes use the CFG/CET
fixture. Results describe the observed effect in this scope. Supported
tool activity can be missed or yield an inconclusive sample. The matrix
runs in observe mode and records each invocation result. After the
fixture has shut down its runtime and published the result, the controller
closes its dedicated job and verifies the child exit through its retained
process handle.

## A06 Windows x64 scheduling lab

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Scheduling -Profile observe -Repeat 30 -OutputDir docs/plans/anti-analysis/evidence/A06
```

The Scheduling fixture compares the same protected ABI with observations
disabled and enabled. Each repeat exercises concurrent calls under CPU
load, stale and unavailable mandatory observations, resumed sampling,
denial on a sustained synthetic event, report-only observe, and shutdown.
It records whole-call admission time, added startup, signature verification,
and synthetic detection and reaction latency separately.

For a separate 600-second comparison, build `scheduling_lab` with Rust 1.95.0
and run the same Windows binary once with `--steady disabled` and once with
`--steady enabled`. The enabled process uses real debugger sampling and the
prepared own-code path. The two modes emit wall time, process CPU, private
memory and sampling counts. The `--prepare` mode measures a separate
warm-cache file preparation and incremental pass.

Profiled Windows policies sample debugger state every 250 ms and own code
on a 500 ms cadence without catch-up. The legacy version-one observer keeps
its initial and recurring 500 ms wait. Admission uses the cached observation
and a Windows elapsed clock that includes system sleep. A mandatory stale or
failed check yields Unavailable. The terminal notice is a separate capacity
one queue, and its enqueue result cannot change a local stop. The observer's
shutdown wait is bounded at 100 ms. An unfinished OS call retains a worker
slot and a loader reference until its callback completes.


## A07 Windows x64 response lab

Start the isolated loopback TLS fixture from `crates/server/examples/r13_online.rs`
with a fresh private PostgreSQL database named `vmkek_r17_response_*`.
Point `VMKEK_A07_ONLINE_CONFIG` at the fixture's base configuration copied
to a private local Windows path. The runner treats missing live configuration
as required `not-run` rows and returns exit 1. Keep the fixture available
until the run finishes. Configuration files contain synthetic device
credentials and belong outside the evidence directory.

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Response -Profile enforce -Repeat 30 -OutputDir docs/plans/anti-analysis/evidence/A07
```

Offline and Online each use the owned Windows debugger observer. The
startup case starts with the debugger attached. The late case releases
the target after the operating system confirms attachment. The Offline
detach case confirms a clean sample while the same handle still returns
Denied. The active cases hold two ABI calls at deterministic checkpoints
and complete a nested ABI call on the same thread before attachment.
They verify denial without publishing the active calls' results. Online
also checks that both calls' owned key and plaintext buffers are cleared
and that the server acknowledges the bounded own-stop report.

A separate isolated fixture can interrupt its loopback listener during
the native response-loss test. The old handle stays denied, the report
records an unavailable transport, and a fresh session with the same
license succeeds once the listener is available. The live R17 server
test separately covers idempotent reports, administrative revocation,
authorization races and administrative recovery.
