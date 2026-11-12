# Authenticated ELF lab verifier

Build on x86-64 Linux with Rust 1.95.0, the `x86_64-unknown-linux-gnu` target and GNU binutils. From the repository root, run

```sh
tools/elf-auth-helper/build.sh
```

The script prints the ELF layout and SHA-256. The artifact is
`tools/elf-auth-helper/target/x86_64-unknown-linux-gnu/release/vmkek-elf-auth-helper`.
Use the artifact from a trusted build. The protector checks the helper's ELF layout,
fixed address, size and absence of runtime relocations or imports. Provenance depends
on the build and the operator's selection of that file.

```sh
vmkek protect sample.elf -o protected.elf --virtualize mix --authenticated-lab \
  --elf-auth-helper tools/elf-auth-helper/target/x86_64-unknown-linux-gnu/release/vmkek-elf-auth-helper \
  --manufacturer-signing-key signer.bin --manufacturer-public-key public.bin \
  --application-id 0102030405060708090a0b0c0d0e0f10
chmod +x protected.elf
./protected.elf
```

The input must be a fixed ELF64 x86-64 executable using the standard glibc interpreter,
with libc as its sole dependency and no visible executable exports, pre-existing
initializers, IFUNC relocations, text relocations, GNU property segment, or executable
stack. The lab reserves a fixed
verifier address, requires room for two load headers, and keeps the original entry
native. Authentication runs unconditionally at the new entry point before execution
can reach the original entry or selected functions. The dynamic table is preserved. Select functions explicitly.
The lab assumes a trusted system interpreter,
dependencies, and launch environment. The artifact contains an extractable per-build
bootstrap key.

The direct-execution test covers the repository ELF sample, W^X, repeated execution,
same-seed builds, and rejection of altered metadata, ciphertext, a re-signed invalid
tag and a signature. It also checks unsupported startup tags and rejection of damaged
ciphertext despite a nonzero byte in writable padding. Run it with the freshly built verifier.

```sh
VMKEK_R02_ELF_HELPER="$PWD/tools/elf-auth-helper/target/x86_64-unknown-linux-gnu/release/vmkek-elf-auth-helper" \
  cargo +1.95.0 --config profile.test.package.vmkek.opt-level=2 test --locked --offline --test r02_elf -- --ignored --nocapture
```
