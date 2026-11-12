//! Fixed-base ELF64 carrier for the Linux protect proof.
//!
//! The process prints [`crate::sample::line`] through libc `write` and `exit`.
//! Addresses are absolute, matching the VM's image base. A spare `PT_NULL`
//! leaves room for the protected segment.

use iced_x86::code_asm::*;
use iced_x86::BlockEncoderOptions;

use crate::error::{msg, Result};
use crate::sample::STRING;

/// Lowest mapped address. The VM bakes this base into trampolines.
pub const IMAGE_BASE: u64 = 0x400000;
const CODE_VA: u64 = 0x401000;
const DATA_VA: u64 = 0x402000;
const STRING_OFF: u64 = 0xF00;
/// Virtual address of the plaintext `vmkek-ok:` bytes.
pub const STRING_VA: u64 = DATA_VA + STRING_OFF;
const GOT_WRITE: u64 = DATA_VA;
const GOT_EXIT: u64 = DATA_VA + 8;
const PAGE: usize = 0x1000;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const GLOB_DAT: u32 = 6;

/// Build the unprotected carrier.
///
/// # Errors
///
/// Returns an error when assembly or the fixed layout does not fit.
pub fn build() -> Result<Vec<u8>> {
    let code = assemble_text()?;
    if code.len() > PAGE {
        return Err(msg("elf sample text does not fit in one page"));
    }
    let mut file = vec![0u8; PAGE * 3];
    file[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    file[0x2000 + STRING_OFF as usize..0x2000 + STRING_OFF as usize + STRING.len()]
        .copy_from_slice(STRING);
    let dynamic = data_image(&file)?;
    file[0x2000..0x2000 + dynamic.len()].copy_from_slice(&dynamic);
    write_header(&mut file)?;
    Ok(file)
}

fn assemble_text() -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut mix_l = a.create_label();
    let mut compute_l = a.create_label();
    let mut start_l = a.create_label();
    let mut loop_l = a.create_label();
    let mut done_l = a.create_label();
    let mut copy_l = a.create_label();
    let mut digits_l = a.create_label();
    let mut pop_l = a.create_label();
    let mut zero_l = a.create_label();
    emit_mix(&mut a, &mut mix_l)?;
    emit_compute(&mut a, &mut compute_l, &mut loop_l, &mut done_l, &mix_l)?;
    emit_start(
        &mut a,
        &mut start_l,
        &compute_l,
        &mut copy_l,
        &mut digits_l,
        &mut pop_l,
        &mut zero_l,
    )?;
    let encoded = a
        .assemble_options(CODE_VA, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .map_err(|err| msg(err.to_string()))?;
    let mut code = encoded.inner.code_buffer;
    patch_rip(&mut code, CODE_VA, &[STRING_VA], &[0x48, 0x8d, 0x35])?;
    patch_rip(
        &mut code,
        CODE_VA,
        &[GOT_WRITE, GOT_EXIT],
        &[0x48, 0x8b, 0x05],
    )?;
    Ok(code)
}

fn emit_mix(a: &mut CodeAssembler, mix_l: &mut CodeLabel) -> Result<()> {
    step(a.set_label(mix_l))?;
    step(a.mov(rax, rdi))?;
    step(a.imul_3(rax, rax, 7i32))?;
    step(a.add(rax, 3i32))?;
    step(a.xor(rax, 0x5ai32))?;
    step(a.ret())
}

fn emit_compute(
    a: &mut CodeAssembler,
    compute_l: &mut CodeLabel,
    loop_l: &mut CodeLabel,
    done_l: &mut CodeLabel,
    mix_l: &CodeLabel,
) -> Result<()> {
    step(a.set_label(compute_l))?;
    step(a.push(rbx))?;
    step(a.push(r12))?;
    step(a.mov(rbx, rdi))?;
    step(a.xor(r12, r12))?;
    step(a.mov(rdi, 1u64))?;
    step(a.set_label(loop_l))?;
    step(a.cmp(rdi, rbx))?;
    step(a.ja(*done_l))?;
    step(a.push(rdi))?;
    step(a.push(rbx))?;
    step(a.call(*mix_l))?;
    step(a.add(r12, rax))?;
    step(a.pop(rbx))?;
    step(a.pop(rdi))?;
    step(a.inc(rdi))?;
    step(a.jmp(*loop_l))?;
    step(a.set_label(done_l))?;
    step(a.mov(rax, r12))?;
    step(a.pop(r12))?;
    step(a.pop(rbx))?;
    step(a.ret())
}

fn emit_start(
    a: &mut CodeAssembler,
    start_l: &mut CodeLabel,
    compute_l: &CodeLabel,
    copy_l: &mut CodeLabel,
    digits_l: &mut CodeLabel,
    pop_l: &mut CodeLabel,
    zero_l: &mut CodeLabel,
) -> Result<()> {
    step(a.set_label(start_l))?;
    step(a.push(rbx))?;
    step(a.push(rbp))?;
    step(a.push(r12))?;
    step(a.mov(rbp, rsp))?;
    step(a.and(rsp, -16i32))?;
    step(a.sub(rsp, 0x40i32))?;
    step(a.mov(rdi, 10u64))?;
    step(a.call(*compute_l))?;
    step(a.mov(rbx, rax))?;
    step(a.db(&[0x48, 0x8d, 0x35, 0, 0, 0, 0]))?;
    step(a.lea(rdi, qword_ptr(rsp + 0x10i32)))?;
    step(a.mov(r12, rdi))?;
    step(a.mov(rcx, 9u64))?;
    step(a.set_label(copy_l))?;
    step(a.movzx(rax, byte_ptr(rsi)))?;
    step(a.mov(byte_ptr(rdi), al))?;
    step(a.inc(rsi))?;
    step(a.inc(rdi))?;
    step(a.dec(rcx))?;
    step(a.jnz(*copy_l))?;
    emit_digits(a, digits_l, pop_l, zero_l)?;
    step(a.mov(byte_ptr(rdi), 0x0ai32))?;
    step(a.inc(rdi))?;
    step(a.mov(rdx, rdi))?;
    step(a.sub(rdx, r12))?;
    step(a.mov(rsi, r12))?;
    step(a.mov(rdi, 1u64))?;
    step(a.db(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]))?;
    step(a.call(rax))?;
    step(a.xor(rdi, rdi))?;
    step(a.db(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]))?;
    step(a.call(rax))?;
    step(a.mov(rsp, rbp))?;
    step(a.pop(r12))?;
    step(a.pop(rbp))?;
    step(a.pop(rbx))?;
    step(a.ret())
}

fn emit_digits(
    a: &mut CodeAssembler,
    digits_l: &mut CodeLabel,
    pop_l: &mut CodeLabel,
    zero_l: &mut CodeLabel,
) -> Result<()> {
    step(a.test(rbx, rbx))?;
    step(a.jz(*zero_l))?;
    step(a.mov(rax, rbx))?;
    step(a.xor(rcx, rcx))?;
    step(a.set_label(digits_l))?;
    step(a.xor(rdx, rdx))?;
    step(a.mov(r8, 10u64))?;
    step(a.div(r8))?;
    step(a.add(rdx, 0x30i32))?;
    step(a.push(rdx))?;
    step(a.inc(rcx))?;
    step(a.test(rax, rax))?;
    step(a.jnz(*digits_l))?;
    step(a.jmp(*pop_l))?;
    step(a.set_label(zero_l))?;
    step(a.mov(rdx, 0x30u64))?;
    step(a.push(rdx))?;
    step(a.mov(rcx, 1u64))?;
    step(a.set_label(pop_l))?;
    step(a.pop(rax))?;
    step(a.mov(byte_ptr(rdi), al))?;
    step(a.inc(rdi))?;
    step(a.dec(rcx))?;
    step(a.jnz(*pop_l))
}

fn data_image(file: &[u8]) -> Result<Vec<u8>> {
    let names = dyn_names();
    let code = &file[0x1000..0x2000];
    let (mix_va, compute_va, start_va, mix_size, compute_size, start_size) = symbol_spans(code)?;
    let mut data = vec![0u8; 0xE00];
    let mut cursor = 16usize;
    let dyn_at = cursor;
    cursor += 11 * 16;
    let sym_at = cursor;
    cursor += 6 * 24;
    let str_at = cursor;
    data[str_at..str_at + names.bytes.len()].copy_from_slice(&names.bytes);
    cursor += names.bytes.len();
    let rela_at = cursor;
    cursor += 2 * 24;
    let hash_at = cursor;
    cursor += 8 + 4 * (1 + 6);
    if cursor > data.len() {
        return Err(msg("elf sample dynamic image does not fit"));
    }
    write_symbols(
        &mut data,
        sym_at,
        &names,
        [mix_va, compute_va, start_va],
        [mix_size, compute_size, start_size],
    );
    write_relocs(&mut data, rela_at);
    write_hash(&mut data, hash_at);
    write_dynamic(
        &mut data,
        dyn_at,
        &names,
        [
            DATA_VA + str_at as u64,
            DATA_VA + sym_at as u64,
            DATA_VA + hash_at as u64,
            DATA_VA + rela_at as u64,
        ],
    );
    Ok(data)
}

struct Names {
    bytes: Vec<u8>,
    libc: u32,
    write: u32,
    exit: u32,
    mix: u32,
    compute: u32,
    start: u32,
}

fn dyn_names() -> Names {
    let mut bytes = vec![0u8];
    let libc = push_name(&mut bytes, b"libc.so.6");
    let write = push_name(&mut bytes, b"write");
    let exit = push_name(&mut bytes, b"exit");
    let mix = push_name(&mut bytes, b"mix");
    let compute = push_name(&mut bytes, b"compute");
    let start = push_name(&mut bytes, b"start");
    Names {
        bytes,
        libc,
        write,
        exit,
        mix,
        compute,
        start,
    }
}

fn push_name(bytes: &mut Vec<u8>, name: &[u8]) -> u32 {
    let at = bytes.len() as u32;
    bytes.extend(name);
    bytes.push(0);
    at
}

fn symbol_spans(code: &[u8]) -> Result<(u64, u64, u64, u64, u64, u64)> {
    let mut decoder = iced_x86::Decoder::with_ip(64, code, CODE_VA, iced_x86::DecoderOptions::NONE);
    let mut rets = Vec::new();
    while decoder.can_decode() && decoder.ip() < CODE_VA + code.len() as u64 {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        if insn.mnemonic() == iced_x86::Mnemonic::Ret {
            rets.push(insn.next_ip());
        }
        if rets.len() == 3 {
            break;
        }
    }
    if rets.len() != 3 {
        return Err(msg("elf sample did not assemble three functions"));
    }
    let mix_va = CODE_VA;
    let compute_va = rets[0];
    let start_va = rets[1];
    let end = rets[2];
    Ok((
        mix_va,
        compute_va,
        start_va,
        compute_va - mix_va,
        start_va - compute_va,
        end - start_va,
    ))
}

fn write_symbols(data: &mut [u8], at: usize, names: &Names, vas: [u64; 3], sizes: [u64; 3]) {
    let entries = [
        sym(0, 0, 0, 0, 0),
        sym(names.write, 0x12, 0, 0, 0),
        sym(names.exit, 0x12, 0, 0, 0),
        sym(names.mix, 0x12, 1, vas[0], sizes[0]),
        sym(names.compute, 0x12, 1, vas[1], sizes[1]),
        sym(names.start, 0x12, 1, vas[2], sizes[2]),
    ];
    for (index, entry) in entries.iter().enumerate() {
        let off = at + index * 24;
        data[off..off + 24].copy_from_slice(entry);
    }
}

fn sym(name: u32, info: u8, shndx: u16, value: u64, size: u64) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&name.to_le_bytes());
    out[4] = info;
    out[6..8].copy_from_slice(&shndx.to_le_bytes());
    out[8..16].copy_from_slice(&value.to_le_bytes());
    out[16..24].copy_from_slice(&size.to_le_bytes());
    out
}

fn write_relocs(data: &mut [u8], at: usize) {
    let write = rela(GOT_WRITE, 1, GLOB_DAT);
    let exit = rela(GOT_EXIT, 2, GLOB_DAT);
    data[at..at + 24].copy_from_slice(&write);
    data[at + 24..at + 48].copy_from_slice(&exit);
}

fn rela(offset: u64, symbol: u32, kind: u32) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&offset.to_le_bytes());
    let info = (u64::from(symbol) << 32) | u64::from(kind);
    out[8..16].copy_from_slice(&info.to_le_bytes());
    out
}

fn write_hash(data: &mut [u8], at: usize) {
    data[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    data[at + 4..at + 8].copy_from_slice(&6u32.to_le_bytes());
}

fn write_dynamic(data: &mut [u8], at: usize, names: &Names, vas: [u64; 4]) {
    let [strtab, symtab, hash, rela] = vas;
    let entries = [
        (1i64, u64::from(names.libc)),
        (5, strtab),
        (6, symtab),
        (10, names.bytes.len() as u64),
        (11, 24),
        (4, hash),
        (7, rela),
        (8, 48),
        (9, 24),
        (21, 0),
        (0, 0),
    ];
    for (index, (tag, value)) in entries.iter().enumerate() {
        let off = at + index * 16;
        data[off..off + 8].copy_from_slice(&tag.to_le_bytes());
        data[off + 8..off + 16].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_header(file: &mut [u8]) -> Result<()> {
    let start = entry_va(&file[0x1000..0x2000])?;
    write_ehdr(file, start);
    let interp_len = write_interp(file);
    write_phdrs(file, interp_len);
    Ok(())
}

fn write_ehdr(file: &mut [u8], start: u64) {
    file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&2u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[24..32].copy_from_slice(&start.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&7u16.to_le_bytes());
}

fn write_interp(file: &mut [u8]) -> u64 {
    let interp = b"/lib64/ld-linux-x86-64.so.2\0";
    let interp_off = 0x200u64;
    file[interp_off as usize..interp_off as usize + interp.len()].copy_from_slice(interp);
    interp.len() as u64
}

fn write_phdrs(file: &mut [u8], interp_len: u64) {
    for (index, header) in program_headers(interp_len).iter().enumerate() {
        let off = 64 + index * 56;
        file[off..off + 56].copy_from_slice(header);
    }
}

fn program_headers(interp_len: u64) -> [[u8; 56]; 7] {
    [
        phdr(PT_PHDR, PF_R, 64, IMAGE_BASE + 64, 7 * 56, 7 * 56, 8),
        phdr(
            PT_INTERP,
            PF_R,
            0x200,
            IMAGE_BASE + 0x200,
            interp_len,
            interp_len,
            1,
        ),
        phdr(PT_LOAD, PF_R | PF_X, 0, IMAGE_BASE, 0x2000, 0x2000, 0x1000),
        phdr(
            PT_LOAD,
            PF_R | PF_W,
            0x2000,
            DATA_VA,
            0x1000,
            0x1000,
            0x1000,
        ),
        phdr(
            PT_DYNAMIC,
            PF_R | PF_W,
            0x2010,
            DATA_VA + 16,
            11 * 16,
            11 * 16,
            8,
        ),
        phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0x10),
        phdr(PT_NULL, 0, 0, 0, 0, 0, 0),
    ]
}

fn entry_va(code: &[u8]) -> Result<u64> {
    let spans = symbol_spans(code)?;
    Ok(spans.2)
}

fn phdr(
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) -> [u8; 56] {
    let mut out = [0u8; 56];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..24].copy_from_slice(&vaddr.to_le_bytes());
    out[24..32].copy_from_slice(&vaddr.to_le_bytes());
    out[32..40].copy_from_slice(&filesz.to_le_bytes());
    out[40..48].copy_from_slice(&memsz.to_le_bytes());
    out[48..56].copy_from_slice(&align.to_le_bytes());
    out
}

fn patch_rip(code: &mut [u8], origin: u64, targets: &[u64], opcode: &[u8]) -> Result<()> {
    let mut cursor = 0usize;
    for target in targets {
        let found = code[cursor..]
            .windows(opcode.len() + 4)
            .position(|window| {
                window[..opcode.len()] == *opcode && window[opcode.len()..] == [0; 4]
            })
            .ok_or_else(|| msg("elf sample rip placeholder is missing"))?;
        let at = cursor + found;
        let next = origin + at as u64 + (opcode.len() + 4) as u64;
        let disp = i32::try_from(
            i64::try_from(*target).map_err(|_| msg("elf sample rip target does not fit"))?
                - i64::try_from(next).map_err(|_| msg("elf sample rip site does not fit"))?,
        )
        .map_err(|_| msg("elf sample rip displacement does not fit"))?;
        code[at + opcode.len()..at + opcode.len() + 4].copy_from_slice(&disp.to_le_bytes());
        cursor = at + opcode.len() + 4;
    }
    Ok(())
}

fn step(result: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn carrier_parses_and_names_libc_imports() {
        let bytes = build().unwrap();
        let image = crate::elf::parse(&bytes).unwrap();
        assert_eq!(image.kind, crate::elf::ElfKind::Executable);
        assert_eq!(image.image_base, IMAGE_BASE);
        assert!(image.imports.iter().any(|item| item.name == "write"));
        assert!(image.imports.iter().any(|item| item.name == "exit"));
        assert!(image.exports.iter().any(|item| item.name == "start"));
        assert_eq!(image.entry, entry_va(&bytes[0x1000..0x2000]).unwrap());
    }

    #[test]
    fn carrier_prints_the_sample_line() {
        let bytes = build().unwrap();
        let (code, stdout) = run(&bytes);
        assert_eq!(code, Some(0), "{}", String::from_utf8_lossy(&stdout));
        assert_eq!(stdout, crate::sample::line().into_bytes());
    }

    fn run(bytes: &[u8]) -> (Option<i32>, Vec<u8>) {
        let path =
            std::env::temp_dir().join(format!("vmkek-elf-{}-{}", std::process::id(), bytes.len()));
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        (output.status.code(), output.stdout)
    }
}
