#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
target=x86_64-unknown-linux-gnu
export CARGO_TARGET_DIR="$PWD/target"
export RUSTFLAGS="--cfg chacha20_force_soft --cfg poly1305_force_soft"
cargo +1.95.0 rustc --locked --release --target "$target" -- \
    -C relocation-model=pic -C linker=ld -C "link-arg=-T$PWD/helper.ld" \
    -C link-arg=-static -C link-arg=-no-pie
artifact="$CARGO_TARGET_DIR/$target/release/vmkek-elf-auth-helper"
if [[ -n $(nm -u "$artifact") ]]; then
    printf '%s\n' "ELF verifier contains undefined symbols" >&2
    exit 1
fi
readelf -lWdWr "$artifact"
sha256sum "$artifact"
