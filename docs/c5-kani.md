# Integer IR checks with Kani

[Architecture](architecture.md#evidence)

The `s1_` harnesses in [src/check.rs](../src/check.rs) compare selected integer rewrite sequences with their direct ALU operations. They run through the integer-block interpreter. They quantify over both 64-bit input values, allow either operand to use register 0 or 1, and vary the incoming CF, PF, ZF, SF, and OF flags. The split-add harness varies its signed 32-bit immediate. The move harnesses vary their 64-bit mask.

The preserved-flag rules check equality of the resulting value and flags. The dead-flag rules check value equality under their precondition. The property covers the selected register slots and integer rules. Native lowering, VM dispatch, x87, AVX and other vector instructions, and resistance to analysis are outside this property.

With Kani 0.68.0 installed and configured, run from the repository root:

```sh
cargo kani --package vmkek --lib --harness s1_ --output-format terse
```

The project records this historical result as `Канал Math: зелёный`. A previous run with Kani 0.68.0 and CBMC 6.11.0 reported `VERIFICATION:- SUCCESSFUL` for all 13 harnesses. Reproduction on this publication preview is pending. The ordinary workspace tests sample concrete inputs.
