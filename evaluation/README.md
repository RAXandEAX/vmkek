# R04 owned-fixture evaluation

The corpus contains 24 synthetic functions in eight families. The first two IDs in
each [catalogue](catalog.json) entry are training fixtures. The third is a holdout.
The evaluator retains eight unsigned byte parameters and one unsigned 64-bit vector
seed in a private JSON object with the keys `parameters` and `vector_seed`.
Keep that pack and all holdout artifacts outside the source checkout. Build one
selected function per target. The holdout build test verifies that the other
23 corpus functions are absent from its symbol table.

Each case supplies two unsigned operands, an initial state and a bounded input
buffer. The independent Python oracle compares the status, return value, whole
buffer, canaries, final state, effect count and ordered effects. Training controls
use six public cases. Holdout checks add 68 generated cases, three private
threshold boundary cases and two directed TLV length cases. The original fixture
and protected fixture each execute directly. The report must bind the exact
protected bytes, Lab profile and selected function before the run can pass.

## Reproduce

Run from the repository root on x86-64 Linux with Python 3.12, GCC and GNU
binutils. Build the repository protector and the trusted ELF Lab verifier.

```sh
cargo +1.95.0 build --locked --release --bin vmkek
tools/elf-auth-helper/build.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s evaluation -v
python3 evaluation/evaluate.py doctor
```

The driver creates the named evidence directories. Set `run` to a directory
outside the checkout. Supply disposable manufacturer credentials as separate
raw files, a 32-byte scalar and a 65-byte SEC1 public point. The build manifest
records the public pin digest. The evaluator passes the selected private parameter
through an owner-only temporary include file. Recorded commands use a placeholder
for that file and private compiler failures retain only the exit status.

```sh
python3 evaluation/evaluate.py controls --output "$run/source-controls"
python3 evaluation/evaluate.py build --fixture affine_xor --fixture xor_copy --fixture counter --fixture two_helpers --output "$run/training" --signer "$signer" --pin "$pin"
python3 evaluation/evaluate.py build --fixture lane_sum --holdout "$private_pack" --output "$run/holdout" --signer "$signer" --pin "$pin"
python3 evaluation/evaluate.py plan --fixture affine_xor --baseline "$run/training/baseline.json" > "$run/fresh-transfer-plan.jsonl"
python3 evaluation/evaluate.py grade --fixture lane_sum --holdout "$private_pack" --candidate "$candidate"
```

The fixture linker script reserves ELF program headers for the existing
authenticated Lab protector. Compilation flags are the same for the original and
its protected derivatives. Each `baseline.json` binds the corpus, tool and
configuration hashes and the original and protected artifact digests. Keep the
files and raw source-control output together. Lab generation uses OS randomness,
so the same layout seed on a new build produces a new artifact digest.

Build comparisons use one worker by default. Pass `--oracle-workers 2` to run
two independent fixture processes at a time. The evaluator preserves vector
order and records the worker count. The affine probe uses the serial mode.
When comparing timings, record the worker count alongside the existing scope
limits.

`baseline-progress.json` is an incomplete record. The build atomically
updates it after each completed original control and terminal seed result.
Missing seeds have no recorded outcome. Once all rows finish, the evaluator
publishes `baseline.json` and removes the progress file. Use `baseline.json`
with `plan`. The loader rejects the incomplete file.

## Controls and coverage

| Control | Scope and observed result |
| --- | --- |
| Z3 4.8.12.0 | Passed the owned 64-bit equivalence and changed-formula controls. |
| LLVM 18.1.3 | Passed source bitcode normalization and ADCE projection. The return and state write remain after removal of an unused SSA computation. |
| Clang DFSan 18.1.3 | Observed the expected value 17 and label 3. Some WSL launches received SIGSEGV, including in non-PIE mode. The driver records eight fixed attempts and classifies any failed attempt as an error. |
| KLEE | Executable unavailable. The source harness is present, and the KLEE/LLVM version pair remains unverified. |
| Frama-C Slicing | Executable unavailable. The source harness is present, and the installed version and slicing command remain unverified. |
| Native ELF Authenticated Lab | `affine_xor`, `counter` and the isolated `lane_sum` holdout matched the oracle at all ten seeds. `xor_copy` exceeded the payload layout limit. The historical `two_helpers` run exited with SIGSEGV at all ten seeds. The corrected run matched the oracle at all ten seeds, with six public cases each. |
| Native PE | Separate platform gate remains open. |

The symbolic control models only the named arithmetic fixture. LLVM ADCE is a
narrow source-level liveness control. DFSan tracks the instrumented source
execution. General protected-image recovery and empirical resistance remain open. [Z3 bit-vectors](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/),
[LLVM ADCE](https://llvm.org/docs/Passes.html#adce-aggressive-dead-code-elimination),
[LLVM DFSan](https://clang.llvm.org/docs/DataFlowSanitizer.html)

KLEE's source calibration would compile the same fixture with
`-DR04_KLEE -emit-llvm -c` using the LLVM compiler version supported by the
installed KLEE, then run `klee fixtures.bc`. Frama-C's source calibration would
preprocess with `-DR04_SLICE` and retain the value returned by `main`. Both are
outside the observed results above. [KLEE testing tutorial](https://klee-se.org/releases/docs/v2.2/tutorials/testing-function/),
[Frama-C Slicing](https://frama-c.com/slicing.html)

## Bounded affine hypothesis

The optional probe applies only to the repository's `affine_xor` fixture. It fits
the parameters of a declared modular-affine XOR model from six public return
observations. Target-free scoring in the same Python process compares the model's
full predictions with 73 private cases, including state, buffer, canaries and
effects. The scoring function receives the fitted parameters and cases without
opening or running either target. The probe fits independently
on each of ten protected seeds. Transfer uses the fixed donor's fitted parameters
with zero target queries. The original fixture provides a separate control.

Run the batch inside a transient user scope. The driver verifies the scope's
one-minute lifetime and 8 GiB memory limit before building or probing.

```sh
systemd-run --user --scope --quiet --property=MemoryMax=8589934592 --property=RuntimeMaxSec=60 -- /usr/bin/python3 "$PWD/evaluation/evaluate.py" build --fixture affine_xor --affine-probe --holdout "$private_pack" --output "$run/affine-probe" --signer "$signer" --pin "$pin"
```

The result uses `hypothesis_match` and records one batch memory peak, elapsed time
per attempt, exact artifact and donor hashes, and the hidden oracle digest. This
measurement covers the declared function family and the one-minute budget. The
ten- and sixty-minute cells and broader protected recovery remain `not_run`.

## Result protocol

The version 1 JSONL plan has one row per fixture, platform, adapter, mode, target
seed and budget. Fresh uses seeds `0x0401` through `0x040a` independently.
Transfer uses the previous seed in the fixed cycle as donor, including the
last-to-first edge. A failed donor remains in the plan. Planned budgets are 60,
600 and 3600 seconds and 8 GiB aggregate memory. The Linux doctor verified that
a child in a transient user scope reads `8589934592` from `memory.max`.
General protected-image jobs remain `not_run`. The affine control uses the
separate measured scope above. [Linux cgroup v2](https://www.kernel.org/doc/html/v6.8/admin-guide/cgroup-v2.html)

Retain exact artifact and donor hashes, tool version, command, exit status,
elapsed time, memory peak, candidate and oracle digests with each independently
reviewed run. Its outcome distinguishes `unsupported`, `error`, `timeout`,
`not_recovered` and `recovered`. Use `not_run` for missing execution. The
grading input maps `case-000`, `case-001` and subsequent case IDs to exact
observation objects. Only the independent evaluator should see the hidden
inputs. Execute an independently produced candidate in a separate context
without either target executable, then record and bind the results. The
`grade` command compares those submitted observations and reports
`matched_observations` or `mismatch`. Recovery requires separate verified
execution and provenance. Result and control files stay outside client reports.


## A09 matched Windows Lab evidence

```sh
python3 evaluation/anti_analysis.py --manifest docs/plans/anti-analysis/evidence/A09/manifest.json --output docs/plans/anti-analysis/evidence/A09/results
```

The manifest references SHA-256-pinned evidence files under its directory.
It records ten distinct Lab artifacts, each paired across the unprofiled
baseline, observe, enforce, debugger-only enforce, and integrity-only
enforce. The native fixture is the Windows x64 `scheduling_lab` example in
`--assessment <profile> <seed>` mode. Every run uses the same native
executable and a seed-specific signed policy where applicable.

The evaluator checks the recorded stdin digest, canonical descriptor and
program bytes, selected clean observations, and actual ABI outputs against
a private arithmetic corpus. It never executes recorded commands. A new
output directory receives `summary.json` with row outcomes, coverage and
timing. Activation uses same-seed baseline deltas. Invocation statistics
compare each process's 128-call p95. The ten-run p95 uses nearest rank.

This campaign verifies clean behavior and the configured signal selection
on one Windows build. First-attempt effort, transfer, accepted external
outcomes and client-data assessment need independent evidence and are
recorded as `not-run`.
