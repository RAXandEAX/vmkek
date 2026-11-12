# Architecture

[Русский](architecture.ru.md) · [README](../README.md) · [Roadmap](../ROADMAP.md)

## From machine code to a protected binary

vmkek lifts selected x86-64 functions to an intermediate representation (IR). Rewrite passes operate on that representation. Native mutation emits machine code again, while virtualization encodes the rewritten function as bytecode and places its runtime in the output image. The passes include mixed Boolean-arithmetic (MBA) identities, constant blinding, opaque predicates, and control-flow flattening. The JSON report records the choices made for the build. Instruction coverage and the calling convention matter when choosing functions to protect.

| Path | Scope |
| --- | --- |
| Native Windows PE and Linux ELF | Selected functions on supported x86-64 images. The outer VM executes function bytecode. The inner VM interprets the bytecode that selects native handlers. |
| Lab VM | Stack, register, and mixed machine forms. Experimental depths 3 and 4 execute selected handler operations as microprograms. The lab also exercises bounded buffers and versioned module descriptors. |
| Online runtime | The client validates signed session and module metadata before accepting encrypted bytecode for a compatible VM. Selected operations execute on the server. |
| Windows driver research | Synthetic Native-subsystem PE images exercise rewriting. Live loading, IOCTL and unload belong to the driver milestone in the [roadmap](../ROADMAP.md). |

## Integrity and keys

The authenticated PE and ELF lab profiles verify an ECDSA P-256 signature at startup and authenticate the encrypted payload with ChaCha20-Poly1305. HKDF-SHA256 separates keys by purpose and build context. This path takes a separately managed signing key and uses the build seed for reproducible diversity. The default CLI path also supports deterministic builds and derives keys from the seed in that mode. Treat those keys as reproducible build material. The authenticated path requires an independently trusted public key and a trusted launch environment.

The online path uses TLS 1.3 and signed application-level metadata. A session grant binds module delivery to a session and VM generation. The runtime tracks active frames when changing generations, and the server can withdraw access. Operations that must keep their implementation and secrets off the client can execute on the server. An operator controlling the client can inspect the bytecode and data made available to that process at runtime.

<a id="observation-profiles"></a>

## Observation profiles

The labels describe opt-in signed Lab and Online policy configurations. Qualification is tied to the tested applications and hosts. Windows x64 was tested on Windows 11 build `10.0.26300.9974`. The Windows policy binds numeric build `26300`. Linux x64 was tested under WSL2 with Ubuntu 24.04.2, glibc 2.39, and kernel `6.18.58.1-microsoft-standard-WSL2`. The Linux policy binds the numeric kernel version and digest of the full release string.

| Profile | Windows x64 | WSL2 x64 |
| --- | --- | --- |
| `observe` | Reports current-process debugger attachment and observations from explicitly signed immutable file-backed RX ranges of the owned PE image. The debugger APIs form one dependent signal group. | Reports the thread-group leader's `TracerPid` as visible in current procfs and observations from explicitly signed immutable file-backed RX ranges of the owned main ELF image. |
| `supported-enforce` | Signed Lab and Online debugger policies exercised startup, late attachment and active calls. The legacy Online owned-code stop has its own focused test. | Signed Lab debugger and main-ELF integrity policies exercised owned GDB/LLDB startup and stable signed-range mismatch. Online own-session stop was tested with owned GDB startup. |
| `experimental` | Broader Windows compatibility, general instrumentation coverage, and profiled Online code-integrity enforcement beyond the focused lab scope await qualification. | Bare-metal Linux, external PID namespaces, DSOs, external profilers, and Online code-integrity enforcement await qualification. |

`observe` allows calls while recording typed outcomes, including unavailable samples. In `enforce`, a missing, expired or inconclusive required observation can return `Unavailable` (1). A fresh qualifying stop returns `Denied` (3) and preserves uncommitted output storage. An Offline stop stays latched for the activation. Online closes local admission first, then attempts one bounded own-session report. Acknowledgement is independent of the local decision. Permanent access revocation requires a separate administrative decision.

Windows compatibility covered 1,008 distinct processes, 504 per mode and 42 per scenario in each mode. The 24-hour soak was waived after a partial run with 13 verified launches. WSL2 covered 390 matrix rows per mode. Its Frida 16.6.6 read-only check verified 60 runs of the owned fixture. The Windows matrix recorded 120 missed stock-tool activity rows, 60 inconclusive stock-tool rows, and 30 detections of a separate change to the owned signed marker. These results qualify their exact lab scenarios. Production EDR, other OS builds, and general Frida detection remain open.

External memory reads can inspect data available to a client. A suspended process cannot sample until it resumes. Freshness checks apply on resumed admission. An operator controlling the kernel or hypervisor controls the execution environment. Short events can fall between samples. Independent first-attempt effort and transfer across builds remain unqualified.

<a id="policy-rollout"></a>

## Signed policy rollout and recovery

1. Provision the detection-policy verification key independently. Use the signing APIs for the intended Offline or Online profile and bind application, build, platform, expiry, epoch and supported rules. Online configurations add signed local-stop consent. Windows uses the observed `VMKR17` configuration, and Linux uses `VMKRA10` with an owner-only configuration and separate device credential.
2. Keep the accepted epoch, revision digest and configured epoch floor in trusted launcher or deployment storage. Offline verification accepts the prior revision explicitly. The Online initializer applies the configured floor. The deployment process checks for same-epoch substitutions before updating that configuration.
3. Install the candidate for a small cohort of test devices first. Open fresh runtime handles and check clean ABI results, observation freshness and Online report acknowledgement before widening the rollout.
4. For a defective rule, sign the corrected or previous recommended settings at an epoch above the affected revision. Verify the new package, advance the trusted floor with the rollout and initialize fresh handles. A same-epoch byte-for-byte retry is admissible. A different revision at the same epoch or an older epoch is rejected when the prior revision is supplied.
5. After transport returns, establish a fresh permitted session. Administrative revocation requires a separate signed restore before access resumes. Retain the policy and decision records for audit.

From a clean source tree with Rust 1.95.0, verify the package contract and the native Offline canary/rollback fixture. The latter uses separate owned runtime activations.

```sh
cargo +1.95.0 test --locked -p vmkek-protocol --test anti_analysis_contract
cargo +1.95.0 test --locked -p vmkek-runtime --lib staged_policy_rollout_recovers_with_a_higher_epoch -- --ignored --nocapture
```

The verified PE fixture workflow builds the protector CLI in WSL and builds the Windows runtime and fixtures with x64 MSVC. The standalone Windows CLI build is unqualified. Use the Windows runner in x64 Developer PowerShell. The Linux matrix uses a WSL2 or Linux x64 shell. Set `VMKEK_A10_GDB` and `VMKEK_A10_LLDB` for tools outside PATH. Windows Response requires `VMKEK_A07_ONLINE_CONFIG` for its Online rows. Linux Online rows use `VMKEK_A10_ONLINE_CONFIG`. Both use the private loopback TLS fixture. Supply a local output directory for each run. [Windows lab prerequisites](../tests/windows/README.md) · [Linux runner](../tests/linux/anti_analysis.py)

```powershell
pwsh -NoProfile -File tests/windows/anti_analysis.ps1 -Case Response -Profile enforce -Repeat 30 -OutputDir out/windows-response
```

```sh
python3 tests/linux/anti_analysis.py --case all --profile enforce --repeat 30 --output out/linux-response
```

## Evidence

- **Equivalence.** The experimental Lab build asks Z3 for counterexamples to selected 64-bit rewrites. One example is `(x + a) + b = x + (a + b) mod 2^64`. The obligation is about the value of a straight-line sequence. The runtime checks the shape of the candidate sequence before using a rule. The separate [Kani harnesses](c5-kani.md) cover selected IR integer identities and their stated flag conditions.
- **Compatibility.** Differential tests compare reference and protected execution. Live results have a platform, fixture, and profile. See the [Windows lab](../tests/windows/README.md) and the [evaluation harness](../evaluation/README.md).
- **Cryptography.** Signatures and authenticated encryption give integrity and authenticity under the stated key and verification assumptions. Resistance to reverse engineering is a separate empirical result.
- **Resistance to analysis.** Record time to recover behavior and the effort to reach an accepted result. Repeating the measurement across builds shows how much of the analysis transfers. Publish the corpus, timeouts, and resource limits alongside the results.

## Further reading

- [Online sample](../samples/online/README.md)
- [Service recovery runbook](../runbooks/r20-recovery.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Security reporting](../SECURITY.md)
