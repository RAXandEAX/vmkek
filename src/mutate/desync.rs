//! Static desynchronization of a linear disassembler.
//!
//! The prefix is an unconditional short jump, which the architecture always
//! takes, followed by one byte the linear decoder accepts as an instruction
//! start. Execution jumps over that byte. Nothing here is self-modifying.
//! Junk is only multi-byte `nop` (`90`, `66 90`, `0F 1F /0`).

#[cfg(test)]
use iced_x86::{Decoder, DecoderOptions, Instruction};

/// `JMP rel8 +1`. Skips exactly one byte.
pub const TAKEN: [u8; 2] = [0xeb, 0x01];

/// `CALL rel32` opcode. A linear decoder starts an instruction here.
pub const TRAP: u8 = 0xe8;

const NOPS: [&[u8]; 4] = [
    &[0x90],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
];

/// Jump, trap byte, then seed-selected nop junk.
#[must_use]
pub fn prefix(seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAKEN.len() + 1);
    out.extend_from_slice(&TAKEN);
    out.push(TRAP);
    out.extend(junk(seed));
    out
}

/// One to three copies of one nop encoding. The encoding and the count follow `seed`.
#[must_use]
pub fn junk(seed: u64) -> Vec<u8> {
    let kind = (seed % NOPS.len() as u64) as usize;
    let copies = 1 + ((seed / NOPS.len() as u64) % 3) as usize;
    repeat(NOPS[kind], copies)
}

/// Instruction starts a linear sweep would report. Branches are not followed.
#[cfg(test)]
#[must_use]
pub fn linear(code: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let end = ip.saturating_add(code.len() as u64);
    let mut out = Vec::new();
    while let Some(insn) = next_linear(&mut decoder, end) {
        out.push(insn);
    }
    out
}

fn repeat(bytes: &[u8], copies: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * copies);
    for _ in 0..copies {
        out.extend_from_slice(bytes);
    }
    out
}

#[cfg(test)]
fn next_linear(decoder: &mut Decoder<'_>, end: u64) -> Option<Instruction> {
    if !decoder.can_decode() || decoder.ip() >= end {
        return None;
    }
    let insn = decoder.decode();
    if insn.is_invalid() || insn.len() == 0 || insn.next_ip() > end {
        return None;
    }
    Some(insn)
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};

    use super::{junk, linear, prefix, TAKEN, TRAP};
    use crate::emu::{self, Region};
    use crate::flags::Flags;

    const IP: u64 = 0x0000_0001_4000_1000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Snap {
        regs: [u64; 16],
        flags: Flags,
        af: bool,
    }

    #[test]
    fn linear_decoder_diverges_from_the_trace() {
        let body = [0xb8, 0x42, 0x00, 0x00, 0x00, 0xc3];
        let mut code = prefix(7);
        code.extend_from_slice(&body);
        let swept = linear(&code, IP);
        let (ran, snap) = trace(&code);
        assert_eq!(swept[0].mnemonic(), Mnemonic::Jmp);
        assert_eq!(swept[0].near_branch_target(), IP + TAKEN.len() as u64 + 1);
        assert_eq!(swept[1].ip(), IP + TAKEN.len() as u64);
        assert_eq!(code[TAKEN.len()], TRAP);
        assert_eq!(swept[1].mnemonic(), Mnemonic::Call);
        assert!(swept.iter().any(|insn| !ran.contains(&insn.ip())));
        assert!(!ran.contains(&(IP + TAKEN.len() as u64)));
        assert!(ran
            .iter()
            .all(|ip| mnemonic_at(&code, *ip) != Mnemonic::Call));
        assert_eq!(snap.regs[0], 0x42);
        assert_eq!(snap, execute(&body));
    }

    #[test]
    fn nop_junk_is_neutral_on_the_emulator() {
        for seed in 0..(super::NOPS.len() as u64) * 3 {
            let bytes = junk(seed);
            let swept = linear(&bytes, IP);
            assert!(!swept.is_empty());
            assert!(swept
                .iter()
                .all(|insn| { matches!(insn.mnemonic(), Mnemonic::Nop | Mnemonic::Reservednop) }));
            assert_eq!(
                swept.iter().map(|insn| insn.len()).sum::<usize>(),
                bytes.len()
            );
            let mut ran = bytes.clone();
            ran.push(0xc3);
            assert_eq!(execute(&ran), execute(&[0xc3]));
        }
    }

    fn mnemonic_at(code: &[u8], ip: u64) -> Mnemonic {
        let off = (ip - IP) as usize;
        let mut decoder = Decoder::with_ip(64, &code[off..], ip, DecoderOptions::NONE);
        decoder.decode().mnemonic()
    }

    fn trace(code: &[u8]) -> (Vec<u64>, Snap) {
        let mut machine = machine(code);
        let mut ips = Vec::new();
        while machine.exit_code.is_none() {
            ips.push(machine.rip);
            machine.step().expect("step");
            assert!(ips.len() < 32, "runaway");
        }
        (ips, snap(&machine))
    }

    fn execute(code: &[u8]) -> Snap {
        let mut machine = machine(code);
        machine.run().expect("run");
        snap(&machine)
    }

    fn machine(code: &[u8]) -> emu::Machine {
        let mut machine = emu::bare(emu::Policy::default()).expect("machine");
        let rsp = machine.regs[4];
        machine.regions.push(Region {
            base: IP,
            data: code.to_vec(),
        });
        machine.rip = IP;
        machine.regs = [0x1111_2222_3333_4444; 16];
        machine.regs[4] = rsp;
        machine.flags = Flags {
            cf: true,
            pf: true,
            zf: true,
            sf: true,
            of: true,
        };
        machine.af = true;
        machine
    }

    fn snap(machine: &emu::Machine) -> Snap {
        Snap {
            regs: machine.regs,
            flags: machine.flags,
            af: machine.af,
        }
    }
}
