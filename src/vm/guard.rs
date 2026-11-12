//! Fail-closed guest accesses and the T1 proof rows.
//!
//! A length that wraps the address, or an address outside the caller's guest
//! window, is refused before any byte is stored. The System row is the emulator
//! test. The Crypto row is the process-lifetime nonce ledger. Math is not claimed.

use crate::error::{msg, Result};
use crate::ir::{MapMem, MemIo};

/// One T1 proof row. `machine` is empty for a known-answer Crypto test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainProof {
    /// `System` or `Crypto`.
    pub channel: &'static str,
    /// `M-EMU`, or empty when the row has no machine.
    pub machine: &'static str,
    /// Test that locks the row.
    pub anchor: &'static str,
}

/// System on M-EMU, and the Crypto nonce invariant. No Math row.
#[must_use]
pub fn proofs() -> [ContainProof; 2] {
    [
        ContainProof {
            channel: "System",
            machine: "M-EMU",
            anchor: "curved_operands_fail_closed_on_m_emu",
        },
        ContainProof {
            channel: "Crypto",
            machine: "",
            anchor: "block_nonce_does_not_repeat_for_the_process",
        },
    ]
}

/// Refuse a zero length or a span that wraps the address space.
pub fn admit_guest(addr: u64, len: usize) -> Result<()> {
    let len = u64::try_from(len).map_err(|_| msg("guest length out of range"))?;
    if len == 0 {
        return Err(msg("guest length out of range"));
    }
    addr.checked_add(len - 1)
        .ok_or_else(|| msg("guest address out of range"))?;
    Ok(())
}

/// Refuse a span that is outside `[base, base + len)`.
pub fn admit_window(base: u64, len: u64, addr: u64, width: usize) -> Result<()> {
    admit_guest(addr, width)?;
    let width = width as u64;
    let end = base
        .checked_add(len)
        .ok_or_else(|| msg("guest address out of range"))?;
    let last = addr + width - 1;
    if addr < base || last >= end {
        return Err(msg("guest address out of range"));
    }
    Ok(())
}

/// Guest memory that rejects stores outside its window before they land.
pub struct GuestMem {
    base: u64,
    len: u64,
    inner: MapMem,
}

impl GuestMem {
    /// Empty window covering `[base, base + len)`.
    #[must_use]
    pub fn new(base: u64, len: u64) -> Self {
        Self {
            base,
            len,
            inner: MapMem::default(),
        }
    }

    /// Byte stored at `addr`, if any write reached it.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<u8> {
        self.inner.bytes.get(&addr).copied()
    }
}

impl MemIo for GuestMem {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        admit_window(self.base, self.len, addr, len)?;
        self.inner.read(addr, len)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        admit_window(self.base, self.len, addr, data.len())?;
        self.inner.write(addr, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emu::{bare, Machine, Policy, Region};
    use crate::flags::Flags;
    use crate::ir::{Block, Exit, FuncIr, MemIo, Op};
    use crate::stub::{assemble_vm, place_runtime};
    use crate::vm::{
        exec_image, lower_image, open_high_water, plain_insn, probe_store64, reset_open_window,
        weave_next, xor_keystream,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn containment_proofs_name_system_and_crypto_only() {
        let rows = proofs();
        assert!(rows.iter().any(|row| {
            row.channel == "System"
                && row.machine == "M-EMU"
                && row.anchor == "curved_operands_fail_closed_on_m_emu"
        }));
        assert!(rows.iter().any(|row| {
            row.channel == "Crypto"
                && row.machine.is_empty()
                && row.anchor == "block_nonce_does_not_repeat_for_the_process"
        }));
        assert!(rows.iter().all(|row| row.channel != "Math"));
    }

    #[test]
    fn curved_operands_fail_closed_on_m_emu() {
        assert_wrapping_store_does_not_land();
        assert_window_store_does_not_land();
        assert_stub_rejects_wild_address_and_bad_index();
    }

    #[test]
    fn inverted_crc_decision_refuses_the_synthetic_guest() {
        let mut guest = wild_store();
        guest.blocks[0].ops = vec![Op::MovRi(0, 7)];
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let image = lower_image(&[guest], &mut rng).unwrap();
        let origin = 0x400000;
        let vm = assemble_vm(origin).unwrap();
        let decision = crc_decision(&vm, origin);

        let crc = crc_of(&image);
        let mut damaged = image.clone();
        let func = &mut damaged.funcs[0];
        let check = &mut func.insns[func.entry as usize].bytes;
        check[1] ^= 1;

        for (fixture, matches, invert, expected) in [
            (&image, true, false, 7),
            (&image, true, true, 0xbad1),
            (&damaged, false, false, 0xbad1),
            (&damaged, false, true, 0xbad1),
        ] {
            let mut machine = mount(&vm.bytes);
            place_one(&mut machine, fixture, &vm, crc, 0x500000);
            assert!(machine.drive(|guest| guest.rip == decision).unwrap());
            assert_eq!(machine.flags.zf, matches, "unexpected CRC compare result");
            if invert {
                // Inject the opposite compare result at this branch in M-EMU only.
                machine.flags.zf = !machine.flags.zf;
            }
            machine.run().unwrap();
            assert_eq!(
                machine.exit_code,
                Some(expected),
                "match={matches}, invert={invert}"
            );
        }
    }

    fn crc_decision(vm: &crate::stub::NativeVm, origin: u64) -> u64 {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};

        let instructions: Vec<_> = Decoder::with_ip(
            64,
            vm.handler_window(),
            origin + vm.handlers as u64,
            DecoderOptions::NONE,
        )
        .into_iter()
        .collect();
        let mut decisions = instructions.windows(2).filter(|pair| {
            let [compare, branch] = [pair[0], pair[1]];
            compare.mnemonic() == Mnemonic::Cmp
                && compare.op0_register() == Register::EAX
                && compare.memory_base() == Register::R13
                && compare.memory_displacement64() == 0x30
                && branch.mnemonic() == Mnemonic::Jne
        });
        let at = decisions.next().expect("CRC decision")[1].ip();
        assert!(decisions.next().is_none(), "ambiguous CRC decision");
        at
    }

    fn assert_wrapping_store_does_not_land() {
        let mut regs = [0u64; 16];
        regs[1] = u64::MAX - 3;
        regs[0] = 0x1122_3344_5566_7788;
        let mut mem = MapMem::default();
        let err = probe_store64(&mut regs, &mut mem, 1, 0).expect_err("wrap");
        assert_eq!(err.to_string(), "guest address out of range");
        assert!(mem.bytes.is_empty(), "wrapped store landed");
    }

    fn assert_window_store_does_not_land() {
        let mut regs = [0u64; 16];
        regs[1] = 0x10;
        regs[0] = 0x99;
        let mut mem = GuestMem::new(0x1000, 0x1000);
        let err = probe_store64(&mut regs, &mut mem, 1, 0).expect_err("outside");
        assert_eq!(err.to_string(), "guest address out of range");
        assert!(mem.get(0x10).is_none());
        regs[1] = 0x1000;
        probe_store64(&mut regs, &mut mem, 1, 0).expect("inside");
        assert_eq!(mem.get(0x1000), Some(0x99));
    }

    fn assert_stub_rejects_wild_address_and_bad_index() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let image = lower_image(std::slice::from_ref(&wild_store()), &mut rng).unwrap();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = mount(&vm.bytes);
        let canary = machine.read(CANARY, 16).unwrap();
        place_one(&mut machine, &image, &vm, crc_of(&image), 0x500000);
        let err = machine.run().expect_err("wild store");
        assert!(err.to_string().contains("unmapped"), "{err}");
        assert_eq!(machine.read(CANARY, 16).unwrap(), canary);

        let slot = bad_slot_snapshot(&vm);
        let mut patched = image;
        let crc = crc_of(&patched);
        patch_store_index(&mut patched, 240);
        let mut machine = mount(&vm.bytes);
        place_one(&mut machine, &patched, &vm, crc, 0x500000);
        let frame = origin + vm.frame as u64;
        machine.rip = origin + vm.dispatch as u64;
        let _ = machine.run();
        let after = machine.read(frame + 240 * 8, 8).unwrap();
        assert_eq!(after, slot, "bad index wrote past the register file");
        assert_eq!(machine.read(CANARY, 16).unwrap(), canary);
    }

    fn bad_slot_snapshot(vm: &crate::stub::NativeVm) -> Vec<u8> {
        let frame = vm.frame + 240 * 8;
        vm.bytes[frame..frame + 8].to_vec()
    }

    fn wild_store() -> FuncIr {
        FuncIr {
            name: "wild".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(1, 0x10), Op::Store64(1, 0)],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    const CANARY: u64 = 0x900000;

    fn mount(code: &[u8]) -> Machine {
        let mut machine = bare(Policy {
            max_steps: 2_000_000,
            ..Policy::default()
        })
        .unwrap();
        machine.regions.push(Region {
            base: 0x400000,
            data: code.to_vec(),
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        machine.regions.push(Region {
            base: CANARY,
            data: vec![0x5a; 16],
        });
        machine
    }

    fn place_one(
        machine: &mut Machine,
        image: &crate::vm::BcImage,
        vm: &crate::stub::NativeVm,
        crc: u32,
        runtime: u64,
    ) {
        place_runtime(
            &image.funcs[0],
            &image.inv,
            crc,
            &image.slots,
            image.handler_mix,
            machine,
            runtime,
            runtime + 0x18000,
        )
        .unwrap();
        let frame = 0x400000 + vm.frame as u64;
        let stack = machine.regs[4];
        let slot = u64::from(image.slots.arch(4));
        machine
            .write(frame + slot * 8, &stack.to_le_bytes())
            .unwrap();
        machine.regs[3] = frame;
        machine.regs[13] = runtime;
        machine.regs[14] = u64::from(image.funcs[0].entry);
        machine.rip = 0x400000 + vm.dispatch as u64;
    }

    fn crc_of(image: &crate::vm::BcImage) -> u32 {
        let mut crc = 0u32;
        for index in 0..image.funcs[0].insns.len() {
            let plain = plain_insn(&image.funcs[0], index, &image.inv).unwrap();
            if plain.first() == Some(&0x60) && plain.len() >= 5 {
                crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
            }
        }
        crc
    }

    fn patch_store_index(image: &mut crate::vm::BcImage, index_byte: u8) {
        let func = &mut image.funcs[0];
        for index in 0..func.insns.len() {
            let mut key = key_at(func, index);
            let mut raw = func.insns[index].bytes.clone();
            let nonce = crate::vm::block_nonce(index as u32, &func.salt, func.rva);
            let opened = xor_keystream(&key, &nonce, 0, &mut raw);
            let store = opened.is_ok() && image.inv[raw[0] as usize] == 0x07;
            if !store {
                crate::secret::wipe(&mut key);
                crate::secret::wipe(&mut raw);
                continue;
            }
            raw[1] = index_byte;
            assert!(xor_keystream(&key, &nonce, 0, &mut raw).is_err());
            func.insns[index].bytes[1] ^= index_byte;
            crate::secret::wipe(&mut key);
            crate::secret::wipe(&mut raw);
            return;
        }
        panic!("store block missing");
    }

    fn key_at(func: &crate::vm::BcFunc, index: usize) -> [u8; 32] {
        let mut key = func.key.bytes();
        for at in 0..index {
            let next = weave_next(&key, at as u32, &func.insns[at].bytes);
            crate::secret::wipe(&mut key);
            key = next;
        }
        key
    }

    #[test]
    fn startup_does_not_decrypt_the_whole_image() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let image = lower_image(std::slice::from_ref(&wild_store()), &mut rng).unwrap();
        assert!(
            image.funcs[0].insns.len() > 1,
            "expected more than one block"
        );
        for (index, insn) in image.funcs[0].insns.iter().enumerate() {
            let plain = plain_insn(&image.funcs[0], index, &image.inv).unwrap();
            assert_ne!(insn.bytes, plain, "block {index} is plaintext at rest");
        }
        reset_open_window();
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = GuestMem::new(0, 0);
        let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        let _ = exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host);
        assert!(
            open_high_water() <= 1,
            "resident plaintext blocks {}",
            open_high_water()
        );
    }

    #[test]
    fn call_and_nested_keep_one_plaintext_block() {
        let mut rng = ChaCha20Rng::seed_from_u64(19);
        let image = lower_image(&call_pair(), &mut rng).unwrap();
        reset_open_window();
        let caller = run_arch(&image, false);
        assert!(open_high_water() <= 1, "call {}", open_high_water());
        assert_eq!(caller, 7);
        reset_open_window();
        let nested = run_arch(&image, true);
        assert_eq!(nested, caller);
        assert!(open_high_water() <= 1, "nested {}", open_high_water());
    }

    fn run_arch(image: &crate::vm::BcImage, nested: bool) -> u64 {
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = GuestMem::new(0, 0);
        let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        if nested {
            crate::vm::exec_image_nested(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host)
                .unwrap();
        } else {
            exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        }
        arch[0]
    }

    fn call_pair() -> Vec<FuncIr> {
        vec![
            FuncIr {
                name: "caller".into(),
                rva: 0x1800,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![Op::MovRi(0, 1)],
                        exit: Exit::CallRva {
                            rva: 0x2800,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![Op::AddRi(0, 2)],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            FuncIr {
                name: "callee".into(),
                rva: 0x2800,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(0, 5)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
        ]
    }

    #[test]
    fn register_index_still_fails_before_a_guest_write() {
        let mut regs = [0u64; 4];
        let mut mem = MapMem::default();
        let err = probe_store64(&mut regs, &mut mem, 240, 0).expect_err("index");
        assert!(err.to_string().contains("register index"));
        assert!(mem.bytes.is_empty());
    }
}
