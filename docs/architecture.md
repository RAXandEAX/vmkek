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
