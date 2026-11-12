//! One plaintext bytecode block in the process.
//!
//! A gate in the shared image admits one chain at a time. The legacy window
//! reseals cached bytes. Authenticated lab builds wipe the plaintext cache and
//! open the original immutable encoding on subsequent reads. Returning to
//! native code closes the open block and drops the gate. The same chain re-enters without waiting, so a
//! nested call cannot deadlock on its own gate. The blob ciphertext is not rewritten.
//! The placed gate is an aligned qword, so `lock cmpxchg` is not a split lock and
//! the release `mov` does not tear.

use iced_x86::code_asm::*;

use crate::error::Result;
use crate::vm::{
    CACHE_OPEN, CACHE_SEALED, CTX_INDEX, CTX_OPEN_CACHE, CTX_OPEN_INDEX, CTX_OPEN_KEYS,
    CTX_OPEN_RUNTIME, CTX_SALT, RESEAL_MARK, RT_INDEX, RT_SALT,
};

use super::{chain, ice, CHACHA_RSP, CHACHA_STACK};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Legacy,
    Immutable,
    External,
}

/// Seal the recorded block, then reopen `r14` when its cache slot is sealed.
pub(super) fn emit_before_open(
    a: &mut CodeAssembler,
    chacha: &CodeLabel,
    fresh: &mut CodeLabel,
    mode: Mode,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    emit_close_open(a, chacha, mode)?;
    if mode != Mode::Legacy {
        return Ok(());
    }
    chain::emit_cache_r10(a)?;
    go(a.cmp(byte_ptr(r10 + r14), u32::from(CACHE_SEALED)))?;
    go(a.jne(*fresh))?;
    emit_reopen_sealed(a, chacha)?;
    go(a.ret())?;
    go(a.set_label(fresh))?;
    Ok(())
}

fn emit_close_open(a: &mut CodeAssembler, chacha: &CodeLabel, mode: Mode) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut skip = a.create_label();
    chain::emit_load_r15(a)?;
    go(a.mov(rax, qword_ptr(r15 + CTX_OPEN_CACHE)))?;
    go(a.test(rax, rax))?;
    go(a.jz(skip))?;
    match mode {
        Mode::Legacy => emit_seal_body(a, chacha)?,
        Mode::Immutable | Mode::External => emit_clear_body(a)?,
    }
    go(a.set_label(&mut skip))?;
    Ok(())
}

fn emit_clear_body(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    let mut closed = a.create_label();
    go(a.mov(r10, qword_ptr(r15 + CTX_OPEN_CACHE)))?;
    go(a.mov(r8, qword_ptr(r15 + CTX_OPEN_RUNTIME)))?;
    go(a.mov(r11d, dword_ptr(r15 + CTX_OPEN_INDEX)))?;
    go(a.mov(rax, qword_ptr(r8 + 16i32)))?;
    go(a.mov(eax, dword_ptr(rax + r11 * 4)))?;
    go(a.lea(rdx, qword_ptr(r10 + rax)))?;
    go(a.add(rdx, qword_ptr(r8)))?;
    go(a.mov(rax, qword_ptr(r8 + 32i32)))?;
    go(a.mov(ecx, dword_ptr(rax + r11 * 4)))?;
    go(a.xor(eax, eax))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(closed))?;
    go(a.set_label(&mut next))?;
    go(a.mov(byte_ptr(rdx), al))?;
    go(a.inc(rdx))?;
    go(a.dec(ecx))?;
    go(a.jnz(next))?;
    go(a.set_label(&mut closed))?;
    go(a.mov(byte_ptr(r10 + r11), al))?;
    go(a.mov(qword_ptr(r15 + CTX_OPEN_CACHE), rax))
}

fn emit_seal_body(a: &mut CodeAssembler, chacha: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(r10, qword_ptr(r15 + CTX_OPEN_CACHE)))?;
    go(a.mov(r9, qword_ptr(r15 + CTX_OPEN_KEYS)))?;
    go(a.mov(r8, qword_ptr(r15 + CTX_OPEN_RUNTIME)))?;
    go(a.mov(r11d, dword_ptr(r15 + CTX_OPEN_INDEX)))?;
    emit_slide_xor(a, chacha)?;
    chain::emit_load_r15(a)?;
    go(a.mov(rax, qword_ptr(r15 + CTX_OPEN_CACHE)))?;
    go(a.mov(r11d, dword_ptr(r15 + CTX_OPEN_INDEX)))?;
    go(a.mov(byte_ptr(rax + r11), u32::from(CACHE_SEALED)))?;
    go(a.xor(ecx, ecx))?;
    go(a.mov(qword_ptr(r15 + CTX_OPEN_CACHE), rcx))?;
    Ok(())
}

fn emit_reopen_sealed(a: &mut CodeAssembler, chacha: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    chain::emit_cache_r10(a)?;
    chain::emit_load_r11(a)?;
    chain::emit_keys_r8(a)?;
    go(a.mov(r9, r8))?;
    go(a.mov(r8, r13))?;
    go(a.mov(r11d, r14d))?;
    emit_slide_xor(a, chacha)?;
    chain::emit_cache_r10(a)?;
    go(a.mov(byte_ptr(r10 + r14), u32::from(CACHE_OPEN)))?;
    emit_note_open(a)?;
    Ok(())
}

/// Remember the block `r14` just opened. `r13` is its runtime.
pub(super) fn emit_note_open(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    chain::emit_load_r15(a)?;
    chain::emit_cache_r10(a)?;
    go(a.mov(qword_ptr(r15 + CTX_OPEN_CACHE), r10))?;
    go(a.mov(dword_ptr(r15 + CTX_OPEN_INDEX), r14d))?;
    go(a.mov(qword_ptr(r15 + CTX_OPEN_RUNTIME), r13))?;
    chain::emit_load_r11(a)?;
    chain::emit_keys_r8(a)?;
    go(a.mov(qword_ptr(r15 + CTX_OPEN_KEYS), r8))?;
    Ok(())
}

/// Take the process gate for this chain. The owner re-enters without spinning.
pub(super) fn emit_acquire(a: &mut CodeAssembler, gate: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut retry = a.create_label();
    let mut claim = a.create_label();
    let mut mine = a.create_label();
    go(a.push(rbx))?;
    go(a.push(r13))?;
    go(a.push(r14))?;
    chain::emit_load_r15(a)?;
    go(a.set_label(&mut retry))?;
    go(a.mov(rax, qword_ptr(*gate)))?;
    go(a.test(rax, rax))?;
    go(a.jz(claim))?;
    go(a.cmp(rax, r15))?;
    go(a.je(mine))?;
    go(a.pause())?;
    go(a.jmp(retry))?;
    go(a.set_label(&mut claim))?;
    go(a.xor(eax, eax))?;
    go(a.lock().cmpxchg(qword_ptr(*gate), r15))?;
    go(a.jnz(retry))?;
    go(a.set_label(&mut mine))?;
    go(a.pop(r14))?;
    go(a.pop(r13))?;
    go(a.pop(rbx))?;
    Ok(())
}

fn emit_release(a: &mut CodeAssembler, gate: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut skip = a.create_label();
    chain::emit_load_r15(a)?;
    go(a.mov(rax, qword_ptr(*gate)))?;
    go(a.cmp(rax, r15))?;
    go(a.jne(skip))?;
    go(a.xor(eax, eax))?;
    go(a.mov(qword_ptr(*gate), rax))?;
    go(a.set_label(&mut skip))?;
    Ok(())
}

/// Seal `CTX_OPEN` and return. `r13`, `r14`, and `rbx` stay put.
pub(super) fn emit_seal_slot(
    a: &mut CodeAssembler,
    slot: &mut CodeLabel,
    chacha: &CodeLabel,
    mode: Mode,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(slot))?;
    emit_close_open(a, chacha, mode)?;
    go(a.ret())?;
    Ok(())
}

/// Reopen `r14` after [`emit_seal_slot`] and remember it as the open block.
pub(super) fn emit_reopen_slot(
    a: &mut CodeAssembler,
    slot: &mut CodeLabel,
    chacha: &CodeLabel,
    replay: &CodeLabel,
    external_fetch: &CodeLabel,
    mode: Mode,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(slot))?;
    match mode {
        Mode::Immutable => return go(a.jmp(*replay)),
        Mode::External => return go(a.jmp(*external_fetch)),
        Mode::Legacy => emit_reopen_sealed(a, chacha)?,
    }
    go(a.ret())?;
    Ok(())
}

/// Seal the open block, then drop the gate when this chain owns it.
///
/// The guest frame sits below the VM `rsp` (handlers adjust only the
/// architectural slot). Pushing on that `rsp` would overwrite it, so the
/// seal runs on the work stack. Four pushes and the 64-byte slide fit in
/// the reserve under that stack. The return address is parked in `r11`.
pub(super) fn emit_drop(
    a: &mut CodeAssembler,
    drop_window: &mut CodeLabel,
    gate: &CodeLabel,
    chacha: &CodeLabel,
    mode: Mode,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(drop_window))?;
    go(a.pop(r11))?;
    go(a.mov(qword_ptr(rbx + super::SAVED_RSP), rsp))?;
    go(a.lea(rsp, qword_ptr(rbx + super::WORK_STACK)))?;
    go(a.push(rbx))?;
    go(a.push(r13))?;
    go(a.push(r14))?;
    go(a.push(r11))?;
    emit_close_open(a, chacha, mode)?;
    emit_release(a, gate)?;
    go(a.pop(r11))?;
    go(a.pop(r14))?;
    go(a.pop(r13))?;
    go(a.pop(rbx))?;
    go(a.mov(rsp, qword_ptr(rbx + super::SAVED_RSP)))?;
    go(a.jmp(r11))?;
    Ok(())
}

fn emit_slide_xor(a: &mut CodeAssembler, chacha: &CodeLabel) -> Result<()> {
    emit_slide_save(a)?;
    emit_slide_key(a)?;
    emit_slide_buf(a, chacha)?;
    emit_slide_restore(a)
}

fn emit_slide_save(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    chain::emit_load_r15(a)?;
    // Forty-four saved bytes stay below the `open_one` return address.
    go(a.sub(rsp, 64i32))?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r15 + (word * 8))))?;
        go(a.mov(qword_ptr(rsp + (word * 8)), rax))?;
    }
    for word in 0..3i32 {
        go(a.mov(eax, dword_ptr(r15 + (CTX_INDEX + word * 4))))?;
        go(a.mov(dword_ptr(rsp + (32 + word * 4)), eax))?;
    }
    Ok(())
}

fn emit_slide_key(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(eax, r11d))?;
    go(a.shl(rax, 5u32))?;
    go(a.add(r9, rax))?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r9 + (word * 8))))?;
        go(a.mov(qword_ptr(r15 + (word * 8)), rax))?;
    }
    go(a.mov(ecx, RESEAL_MARK))?;
    go(a.mov(eax, r11d))?;
    go(a.or(eax, ecx))?;
    go(a.mov(dword_ptr(r15 + CTX_INDEX), eax))?;
    go(a.mov(eax, dword_ptr(r8 + RT_SALT)))?;
    go(a.mov(dword_ptr(r15 + CTX_SALT), eax))?;
    go(a.mov(eax, dword_ptr(r8 + (RT_SALT + 4))))?;
    go(a.mov(dword_ptr(r15 + (CTX_SALT + 4)), eax))?;
    go(a.mov(eax, dword_ptr(r8 + RT_INDEX)))?;
    go(a.xor(dword_ptr(r15 + CTX_SALT), eax))?;
    Ok(())
}

fn emit_slide_buf(a: &mut CodeAssembler, chacha: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rax, qword_ptr(r8)))?;
    go(a.add(r10, rax))?;
    go(a.mov(rax, qword_ptr(r8 + 16i32)))?;
    go(a.mov(eax, dword_ptr(rax + r11 * 4)))?;
    go(a.add(r10, rax))?;
    go(a.mov(rsi, r10))?;
    go(a.mov(rdi, r10))?;
    go(a.mov(rax, qword_ptr(r8 + 32i32)))?;
    go(a.mov(ecx, dword_ptr(rax + r11 * 4)))?;
    go(a.xor(r10d, r10d))?;
    go(a.mov(qword_ptr(rbx + CHACHA_RSP), rsp))?;
    go(a.lea(rsp, qword_ptr(rbx + CHACHA_STACK)))?;
    go(a.call(*chacha))?;
    go(a.mov(rsp, qword_ptr(rbx + CHACHA_RSP)))?;
    Ok(())
}

fn emit_slide_restore(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    chain::emit_load_r15(a)?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(rsp + (word * 8))))?;
        go(a.mov(qword_ptr(r15 + (word * 8)), rax))?;
    }
    for word in 0..3i32 {
        go(a.mov(eax, dword_ptr(rsp + (32 + word * 4))))?;
        go(a.mov(dword_ptr(r15 + (CTX_INDEX + word * 4)), eax))?;
    }
    go(a.add(rsp, 64i32))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::Mode;
    use crate::crypto::authenticated::{BlockPurpose, BlockScope, MasterSecret};
    use crate::emu::{bare, Machine, Policy, Region, GS_BASE, SENTINEL};
    use crate::flags::Flags;
    use crate::ir::{Block, Exit, FuncIr, MapMem, MemIo, Op};
    use crate::stub::{assemble_vm, assemble_vm_for_authenticated_lab, place_runtime, NativeVm};
    use crate::vm::{
        exec_image, lower_image, lower_image_scoped, plain_insn, reseal_block, runtime_fits,
        weave_next, BcFunc, BcImage, CACHE_OPEN, CACHE_SEALED, CHAIN_BYTES, CTX_BOUND, CTX_CACHE,
        CTX_MAP, CTX_MAP_SLOTS, CTX_MAP_STRIDE, FILE_STACK_BYTES, FRAME_BYTES, GS_CHAIN_AT,
        GS_CHAIN_PTR, INNER_PLAIN, RUNTIME_WINDOW,
    };

    const OTHER_FRAME: u64 = 0x900000;
    const OTHER_STACK: u64 = 0x910000;

    struct Mount {
        machine: Machine,
        vm: NativeVm,
        image: BcImage,
        origin: u64,
        base: u64,
        mode: Mode,
    }

    struct Cpu {
        regs: [u64; 16],
        flags: Flags,
        af: bool,
        df: bool,
        rip: u64,
        chain: u64,
        exit: Option<u32>,
    }

    struct Plain {
        func: usize,
        index: usize,
        off: u64,
        bytes: Vec<u8>,
    }

    #[test]
    fn one_open_block_at_each_boundary() {
        let mut mount = mount_image(&[loop_ir(), helper_ir()]);
        let plains = plains_of(&mount.image);
        let needles = proof_needles(&plains);
        let before = blob_bytes(&mount);
        assert_eq!(live_count(&mount, &plains), 0);
        assert_eq!(wide_hits(&mount.machine, &needles), 0);
        let expect = oracle(&mount.image);
        arm(&mut mount);
        assert_eq!(walk(&mut mount, &plains, &needles, true), expect);
        assert_eq!(live_count(&mount, &plains), 0, "plaintext after ret");
        assert_eq!(wide_hits(&mount.machine, &needles), 0, "copy after ret");
        assert_eq!(blob_bytes(&mount), before);
        assert_eq!(chain_key(&mount), mount.image.funcs[0].terminal.to_vec());
        resume_same(&mut mount, &plains, &needles, expect);
    }

    #[test]
    fn scoped_window_reopens_immutable_blocks_and_clears_plaintext() {
        let funcs = [loop_ir(), helper_ir()];
        let mut mount = mount_with_mode(&funcs, Mode::Immutable);
        let plains = plains_of(&mount.image);
        let needles = proof_needles(&plains);
        let original = blob_bytes(&mount);
        let expected = oracle(&mount.image);
        arm(&mut mount);
        assert_eq!(walk(&mut mount, &plains, &needles, true), expected);
        assert_empty_caches(&mount);
        resume_same(&mut mount, &plains, &needles, expected);
        assert_empty_caches(&mount);
        assert_eq!(blob_bytes(&mount), original);
    }

    fn assert_empty_caches(mount: &Mount) {
        for (cache, runtime) in caches(&mount.machine, &mount.image, mount.base) {
            let index = func_index(&mount.image, mount.base, runtime).unwrap();
            let func = &mount.image.funcs[index];
            let length = func.insns.len()
                + func
                    .insns
                    .iter()
                    .map(|insn| insn.bytes.len())
                    .sum::<usize>();
            let bytes = mount.machine.read(cache, length).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn scoped_vm_masks_do_not_follow_the_layout_seed() {
        let funcs = [loop_ir(), helper_ir()];
        let scope = BlockScope::for_new_build([3; 16], [0; 16], 1, BlockPurpose::Payload).unwrap();
        let lower = |master: &MasterSecret| {
            let mut rng = ChaCha20Rng::seed_from_u64(5);
            lower_image_scoped(&funcs, &mut rng, master, scope).unwrap()
        };
        let first = lower(&MasterSecret::generate().unwrap());
        let second = lower(&MasterSecret::generate().unwrap());
        assert_eq!(first.perm, second.perm);
        assert_eq!(first.handler_mix, second.handler_mix);
        assert!(first.funcs[0].key.bytes() != first.funcs[1].key.bytes());
        assert!(first.funcs[0].key.bytes() != second.funcs[0].key.bytes());
        let dispatcher = first.funcs[0].dispatcher().unwrap();
        assert!(dispatcher.key != first.funcs[0].key.bytes());
        assert!(dispatcher.key != first.funcs[1].dispatcher().unwrap().key);
        assert!(dispatcher.key != second.funcs[0].dispatcher().unwrap().key);
        for _ in 0..3 {
            assert_eq!(
                first.funcs[0].open_dispatcher().unwrap(),
                crate::vm::inner::product_program()
            );
            assert_eq!(first.funcs[0].dispatcher().unwrap(), dispatcher);
        }
        assert_ne!(
            first.funcs[0].insns[0].bytes,
            second.funcs[0].insns[0].bytes
        );
    }

    fn loop_ir() -> FuncIr {
        FuncIr {
            name: "loop".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(0, 0xC2C2_C2C2_C2C2_C2C2), Op::MovRi(1, 2)],
                    exit: Exit::Jmp(1),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::AddRi(0, 1), Op::Dec(1)],
                    exit: Exit::Jcc(5, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![],
                    exit: Exit::CallRva {
                        rva: 0x2000,
                        next: 3,
                    },
                    opaque: false,
                },
                Block {
                    ops: vec![],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    fn helper_ir() -> FuncIr {
        FuncIr {
            name: "helper".into(),
            rva: 0x2000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::AddRi(0, 10)],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn mount_image(funcs: &[FuncIr]) -> Mount {
        mount_with_mode(funcs, Mode::Legacy)
    }

    fn mount_with_mode(funcs: &[FuncIr], mode: Mode) -> Mount {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let origin = 0x400000u64;
        let (image, vm) = match mode {
            Mode::Legacy => (
                lower_image(funcs, &mut rng).unwrap(),
                assemble_vm(origin).unwrap(),
            ),
            Mode::Immutable => {
                let scope =
                    BlockScope::for_new_build([1; 16], [0; 16], 1, BlockPurpose::Payload).unwrap();
                let master = MasterSecret::generate().unwrap();
                (
                    lower_image_scoped(funcs, &mut rng, &master, scope).unwrap(),
                    assemble_vm_for_authenticated_lab(origin).unwrap(),
                )
            }
            Mode::External => unreachable!("external-key is exercised by native socket tests"),
        };
        let base = 0x500000u64;
        let mut machine = bare(Policy {
            interpret_cipher: true,
            ..Policy::default()
        })
        .unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        let span = image.funcs.len() * RUNTIME_WINDOW as usize + 0x8000;
        machine.regions.push(Region {
            base,
            data: vec![0; span],
        });
        machine.regions.push(Region {
            base: OTHER_FRAME,
            data: vec![0xA5; FRAME_BYTES + FILE_STACK_BYTES],
        });
        machine.regions.push(Region {
            base: OTHER_STACK,
            data: vec![0; 0x1000],
        });
        place_all(&mut machine, &image, &vm, origin, base);
        Mount {
            machine,
            vm,
            image,
            origin,
            base,
            mode,
        }
    }

    fn place_all(machine: &mut Machine, image: &BcImage, vm: &NativeVm, origin: u64, base: u64) {
        let mut cursor = base + image.funcs.len() as u64 * RUNTIME_WINDOW;
        let mut table = Vec::new();
        table.extend((image.funcs.len() as u32).to_le_bytes());
        for (index, func) in image.funcs.iter().enumerate() {
            let runtime = base + index as u64 * RUNTIME_WINDOW;
            place_one(machine, image, func, runtime, cursor);
            cursor += func.insns.len() as u64 * 32;
            table.extend(func.rva.to_le_bytes());
            table.extend(func.entry.to_le_bytes());
            table.extend(runtime.to_le_bytes());
        }
        machine.write(cursor, &table).unwrap();
        machine
            .write(origin + vm.calls as u64, &cursor.to_le_bytes())
            .unwrap();
    }

    fn place_one(machine: &mut Machine, image: &BcImage, func: &BcFunc, runtime: u64, keys: u64) {
        place_runtime(
            func,
            &image.inv,
            crc_of(func, &image.inv),
            &image.slots,
            image.handler_mix,
            machine,
            runtime,
            keys,
        )
        .unwrap();
    }

    fn crc_of(func: &BcFunc, inv: &[u8; 256]) -> u32 {
        let mut crc = 0u32;
        for index in 0..func.insns.len() {
            let plain = plain_insn(func, index, inv).unwrap();
            if plain.first() == Some(&0x60) && plain.len() >= 5 {
                crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
            }
        }
        crc
    }

    fn arm(mount: &mut Mount) {
        let frame = mount.origin + mount.vm.frame as u64;
        let slot = u64::from(mount.image.slots.arch(4));
        let stack = mount.machine.regs[4];
        mount
            .machine
            .write(frame + slot * 8, &stack.to_le_bytes())
            .unwrap();
        mount.machine.regs[3] = frame;
        mount.machine.regs[13] = mount.base;
        mount.machine.regs[14] = u64::from(mount.image.funcs[0].entry);
        mount.machine.rip = mount.origin + mount.vm.dispatch as u64;
    }

    fn walk(mount: &mut Mount, plains: &[Plain], needles: &[Vec<u8>], contend: bool) -> u64 {
        let resume = mount.origin + mount.vm.resume as u64;
        let mut saw = false;
        let mut parked = None;
        while mount.machine.exit_code.is_none() {
            if contend && parked.is_none() && at_open_block(mount, plains, resume) {
                parked = Some(park_other(mount, plains, needles));
            }
            saw |= note_step(mount, plains, needles, resume);
            step_one(mount);
        }
        assert_eq!(
            saw,
            mount.mode == Mode::Legacy,
            "unexpected cache reseal behavior"
        );
        assert!(
            parked.is_some() || !contend,
            "never parked a second context"
        );
        let result = mount.machine.regs[0];
        if let Some(other) = parked {
            release_other(mount, &other, plains, needles, result);
        }
        result
    }

    fn at_open_block(mount: &Mount, plains: &[Plain], resume: u64) -> bool {
        mount.machine.rip == resume && live_count(mount, plains) >= 1
    }

    fn park_other(mount: &mut Mount, plains: &[Plain], needles: &[Vec<u8>]) -> Cpu {
        let saved = cpu_of(mount);
        arm_other(mount);
        let mut pauses = 0u32;
        for _ in 0..250_000 {
            let live = live_count(mount, plains);
            assert!(live <= 1, "second context holds plaintext ({live})");
            if paused(&mount.machine) {
                pauses += 1;
            }
            if pauses > 8 {
                break;
            }
            step_one(mount);
            if mount.machine.exit_code.is_some() {
                break;
            }
        }
        assert!(pauses > 8, "second context did not wait");
        assert!(wide_hits(&mount.machine, needles) <= 1, "parked snapshot");
        let other = cpu_of(mount);
        restore(mount, &saved);
        other
    }

    fn release_other(
        mount: &mut Mount,
        other: &Cpu,
        plains: &[Plain],
        needles: &[Vec<u8>],
        result: u64,
    ) {
        let back = cpu_of(mount);
        restore(mount, other);
        mount.machine.exit_code = None;
        run_until_return(mount, plains, needles);
        assert_eq!(mount.machine.regs[0], oracle(&mount.image));
        restore(mount, &back);
        mount.machine.regs[0] = result;
    }

    fn run_until_return(mount: &mut Mount, plains: &[Plain], needles: &[Vec<u8>]) {
        let resume = mount.origin + mount.vm.resume as u64;
        while mount.machine.exit_code.is_none() {
            assert!(live_count(mount, plains) <= 1);
            if mount.machine.rip == resume {
                assert!(wide_hits(&mount.machine, needles) <= 1);
            }
            step_one(mount);
        }
        assert_eq!(live_count(mount, plains), 0, "plaintext after second ret");
        assert_eq!(wide_hits(&mount.machine, needles), 0);
    }

    fn resume_same(mount: &mut Mount, plains: &[Plain], needles: &[Vec<u8>], expect: u64) {
        let frame = mount.origin + mount.vm.frame as u64;
        let stack = guest_stack(mount, frame);
        mount.machine.write(stack, &SENTINEL.to_le_bytes()).unwrap();
        mount.machine.exit_code = None;
        mount.machine.regs[3] = frame;
        mount.machine.regs[4] = stack;
        mount.machine.regs[13] = mount.base;
        mount.machine.regs[14] = u64::from(mount.image.funcs[0].entry);
        mount.machine.rip = mount.origin + mount.vm.resume as u64;
        assert_eq!(walk(mount, plains, needles, false), expect);
        assert_eq!(live_count(mount, plains), 0, "plaintext after resume");
        assert_eq!(chain_key(mount), mount.image.funcs[0].terminal.to_vec());
    }

    fn guest_stack(mount: &Mount, frame: u64) -> u64 {
        let slot = u64::from(mount.image.slots.arch(4));
        qword(&mount.machine, frame + slot * 8)
    }

    fn arm_other(mount: &mut Mount) {
        let stack = OTHER_STACK + 0x800;
        mount.machine.write(stack, &SENTINEL.to_le_bytes()).unwrap();
        let slot = u64::from(mount.image.slots.arch(4));
        mount
            .machine
            .write(OTHER_FRAME + slot * 8, &stack.to_le_bytes())
            .unwrap();
        mount.machine.exit_code = None;
        mount.machine.regs[3] = OTHER_FRAME;
        mount.machine.regs[4] = stack;
        mount.machine.regs[13] = mount.base;
        mount.machine.regs[14] = u64::from(mount.image.funcs[0].entry);
        mount.machine.rip = mount.origin + mount.vm.dispatch as u64;
        let chain = GS_BASE + GS_CHAIN_AT as u64 + CHAIN_BYTES as u64;
        mount
            .machine
            .write(mount.machine.gs + GS_CHAIN_PTR as u64, &chain.to_le_bytes())
            .unwrap();
    }

    fn paused(machine: &Machine) -> bool {
        machine.read(machine.rip, 2).ok().as_deref() == Some(&[0xF3, 0x90])
    }

    fn cpu_of(mount: &Mount) -> Cpu {
        Cpu {
            regs: mount.machine.regs,
            flags: mount.machine.flags,
            af: mount.machine.af,
            df: mount.machine.df,
            rip: mount.machine.rip,
            chain: qword(&mount.machine, mount.machine.gs + GS_CHAIN_PTR as u64),
            exit: mount.machine.exit_code,
        }
    }

    fn restore(mount: &mut Mount, cpu: &Cpu) {
        mount.machine.regs = cpu.regs;
        mount.machine.flags = cpu.flags;
        mount.machine.af = cpu.af;
        mount.machine.df = cpu.df;
        mount.machine.rip = cpu.rip;
        mount.machine.exit_code = cpu.exit;
        mount
            .machine
            .write(
                mount.machine.gs + GS_CHAIN_PTR as u64,
                &cpu.chain.to_le_bytes(),
            )
            .unwrap();
    }

    fn step_one(mount: &mut Mount) {
        mount.machine.steps += 1;
        assert!(
            mount.machine.steps <= mount.machine.policy.max_steps,
            "step limit at {:#x}",
            mount.machine.rip
        );
        mount.machine.step().unwrap();
    }

    fn note_step(mount: &Mount, plains: &[Plain], needles: &[Vec<u8>], resume: u64) -> bool {
        let step = mount.machine.steps;
        let live = live_count(mount, plains);
        assert!(live <= 1, "open blocks {live} at step {step}");
        if mount.machine.rip != resume {
            return false;
        }
        let copies = wide_hits(&mount.machine, needles);
        assert!(copies <= 1, "memory copies {copies} at step {step}");
        note_reseal(&mount.machine, &mount.image, mount.base, plains)
    }

    fn plains_of(image: &BcImage) -> Vec<Plain> {
        let mut out = Vec::new();
        for (func, body) in image.funcs.iter().enumerate() {
            let mut off = 0u64;
            for index in 0..body.insns.len() {
                let bytes = plain_insn(body, index, &image.inv).unwrap();
                out.push(Plain {
                    func,
                    index,
                    off,
                    bytes,
                });
                off += body.insns[index].bytes.len() as u64;
            }
        }
        out
    }

    fn long_needles(plains: &[Plain]) -> Vec<Vec<u8>> {
        plains
            .iter()
            .filter(|plain| plain.bytes.len() >= 8)
            .map(|plain| plain.bytes.clone())
            .collect()
    }

    fn proof_needles(plains: &[Plain]) -> Vec<Vec<u8>> {
        let mut needles = long_needles(plains);
        needles.push(crate::vm::inner::product_program());
        needles
    }

    fn live_count(mount: &Mount, plains: &[Plain]) -> usize {
        open_slots(&mount.machine, &mount.image, mount.base, plains)
            + inner_buffers(&mount.machine, &mount.image, mount.base)
    }

    fn inner_buffers(machine: &Machine, image: &BcImage, base: u64) -> usize {
        let program = crate::vm::inner::product_program();
        (0..image.funcs.len())
            .filter(|index| inner_at(machine, base, *index, &program))
            .count()
    }

    fn inner_at(machine: &Machine, base: u64, index: usize, program: &[u8]) -> bool {
        let at = base + index as u64 * RUNTIME_WINDOW + INNER_PLAIN as u64;
        machine.read(at, program.len()).ok().as_deref() == Some(program)
    }

    fn open_slots(machine: &Machine, image: &BcImage, base: u64, plains: &[Plain]) -> usize {
        caches(machine, image, base)
            .into_iter()
            .map(|(cache, runtime)| slots_at(machine, image, base, cache, runtime, plains))
            .sum()
    }

    fn slots_at(
        machine: &Machine,
        image: &BcImage,
        base: u64,
        cache: u64,
        runtime: u64,
        plains: &[Plain],
    ) -> usize {
        let Some(func) = func_index(image, base, runtime) else {
            return 0;
        };
        let count = image.funcs[func].insns.len();
        let flags = machine.read(cache, count).unwrap();
        plains
            .iter()
            .filter(|plain| plain.func == func && slot_open(machine, cache, count, plain, &flags))
            .count()
    }

    fn slot_open(machine: &Machine, cache: u64, count: usize, plain: &Plain, flags: &[u8]) -> bool {
        if flags[plain.index] == CACHE_OPEN {
            return true;
        }
        if plain.bytes.len() < 4 {
            return false;
        }
        let got = machine
            .read(cache + count as u64 + plain.off, plain.bytes.len())
            .unwrap();
        got == plain.bytes
    }

    fn note_reseal(machine: &Machine, image: &BcImage, base: u64, plains: &[Plain]) -> bool {
        caches(machine, image, base)
            .into_iter()
            .any(|(cache, runtime)| reseal_cache(machine, image, cache, runtime, base, plains))
    }

    fn reseal_cache(
        machine: &Machine,
        image: &BcImage,
        cache: u64,
        runtime: u64,
        base: u64,
        plains: &[Plain],
    ) -> bool {
        let Some(func_index) = func_index(image, base, runtime) else {
            return false;
        };
        let func = &image.funcs[func_index];
        let count = func.insns.len() as u64;
        let mut saw = false;
        for plain in plains.iter().filter(|item| item.func == func_index) {
            saw |= sealed_slot(machine, func, cache, count, plain);
        }
        saw
    }

    fn sealed_slot(
        machine: &Machine,
        func: &BcFunc,
        cache: u64,
        count: u64,
        plain: &Plain,
    ) -> bool {
        let flag = machine.read(cache + plain.index as u64, 1).unwrap()[0];
        if flag != CACHE_SEALED {
            return false;
        }
        let got = machine
            .read(cache + count + plain.off, plain.bytes.len())
            .unwrap();
        let expect = reseal_block(
            &key_before(func, plain.index),
            plain.index as u32,
            func.rva,
            &func.salt,
            &plain.bytes,
        )
        .unwrap();
        assert_eq!(got, expect, "block {} reseal", plain.index);
        true
    }

    fn key_before(func: &BcFunc, index: usize) -> [u8; 32] {
        let mut key = func.key.bytes();
        for at in 0..index {
            let next = weave_next(&key, at as u32, &func.insns[at].bytes);
            crate::secret::wipe(&mut key);
            key = next;
        }
        key
    }

    fn caches(machine: &Machine, image: &BcImage, base: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for index in 0..image.funcs.len() {
            let runtime = base + index as u64 * RUNTIME_WINDOW;
            let func = &image.funcs[index];
            let len = func.insns.iter().map(|insn| insn.bytes.len()).sum();
            let cache = runtime_fits(runtime, func.insns.len(), len).unwrap().cache;
            push_cache(&mut out, cache, runtime);
        }
        for chain in chain_blocks(machine) {
            push_cache(
                &mut out,
                qword(machine, chain + CTX_CACHE as u64),
                qword(machine, chain + CTX_BOUND as u64),
            );
            push_map(&mut out, machine, chain);
        }
        out
    }

    fn chain_blocks(machine: &Machine) -> Vec<u64> {
        let mut out = Vec::new();
        let current = qword(machine, machine.gs + GS_CHAIN_PTR as u64);
        if current != 0 {
            out.push(current);
        }
        for index in 0..2 {
            let at = GS_BASE + GS_CHAIN_AT as u64 + index as u64 * CHAIN_BYTES as u64;
            if !out.contains(&at) {
                out.push(at);
            }
        }
        out
    }

    fn push_map(out: &mut Vec<(u64, u64)>, machine: &Machine, chain: u64) {
        for slot in 0..CTX_MAP_SLOTS {
            let at = chain + CTX_MAP as u64 + slot as u64 * CTX_MAP_STRIDE as u64;
            let runtime = qword(machine, at);
            if runtime == 0 {
                break;
            }
            push_cache(out, qword(machine, at + 8), runtime);
        }
    }

    fn push_cache(out: &mut Vec<(u64, u64)>, cache: u64, runtime: u64) {
        if cache != 0 && out.iter().all(|item| item.0 != cache) {
            out.push((cache, runtime));
        }
    }

    fn func_index(image: &BcImage, base: u64, runtime: u64) -> Option<usize> {
        let span = runtime.checked_sub(base)?;
        if !span.is_multiple_of(RUNTIME_WINDOW) {
            return None;
        }
        let index = usize::try_from(span / RUNTIME_WINDOW).ok()?;
        image.funcs.get(index).map(|_| index)
    }

    fn wide_hits(machine: &Machine, needles: &[Vec<u8>]) -> usize {
        let mut hits = 0usize;
        for region in &machine.regions {
            for needle in needles {
                hits += count_needle(&region.data, needle);
            }
        }
        hits
    }

    fn count_needle(hay: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || hay.len() < needle.len() || !hay.contains(&needle[0]) {
            return 0;
        }
        let last = needle.len() - 1;
        let mut hits = 0usize;
        for index in 0..=hay.len() - needle.len() {
            if hay[index] == needle[0]
                && hay[index + last] == needle[last]
                && &hay[index..index + needle.len()] == needle
            {
                hits += 1;
            }
        }
        hits
    }

    fn blob_bytes(mount: &Mount) -> Vec<Vec<u8>> {
        mount
            .image
            .funcs
            .iter()
            .enumerate()
            .map(|(index, func)| read_blob(&mount.machine, mount.base, index, func))
            .collect()
    }

    fn read_blob(machine: &Machine, base: u64, index: usize, func: &BcFunc) -> Vec<u8> {
        let len = func.insns.iter().map(|insn| insn.bytes.len()).sum();
        let runtime = base + index as u64 * RUNTIME_WINDOW;
        let blob = runtime_fits(runtime, func.insns.len(), len).unwrap().blob;
        machine.read(blob, len).unwrap()
    }

    fn chain_key(mount: &Mount) -> Vec<u8> {
        let chain = qword(&mount.machine, mount.machine.gs + GS_CHAIN_PTR as u64);
        mount.machine.read(chain, 32).unwrap()
    }

    fn qword(machine: &Machine, at: u64) -> u64 {
        let bytes = machine.read(at, 8).unwrap();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn oracle(image: &BcImage) -> u64 {
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        arch[0]
    }
}
