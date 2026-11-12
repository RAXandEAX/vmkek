use iced_x86::code_asm::*;
use iced_x86::BlockEncoderOptions;

use crate::error::{msg, Result};
use crate::pe::{emit, PeImage, Section, CH_RDATA, CH_TEXT, IMAGE_BASE};

pub const STRING: &[u8] = b"vmkek-ok:";
pub const STRING_RVA: u32 = 0x2000;
/// Byte the sample stores between `GetStdHandle` and `WriteFile`, then after the write.
pub const PHASE_RVA: u32 = 0x2700;
const IAT_RVA: u32 = 0x2100;
const NAMES: &[&str] = &[
    "GetStdHandle",
    "WriteFile",
    "ExitProcess",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "GetTickCount64",
];

pub fn mix(value: u64) -> u64 {
    value.wrapping_mul(7).wrapping_add(3) ^ 0x5a
}

pub fn compute(n: u64) -> u64 {
    (1..=n).fold(0u64, |sum, index| sum.wrapping_add(mix(index)))
}

pub fn line() -> String {
    format!("vmkek-ok:{}\n", compute(10))
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub symbols: Vec<Symbol>,
}

pub fn build() -> Result<Built> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut mix_l = a.create_label();
    let mut compute_l = a.create_label();
    let mut start_l = a.create_label();
    let mut loop_l = a.create_label();
    let mut done_l = a.create_label();
    let mut end_l = a.create_label();

    emit_mix(&mut a, &mut mix_l)?;
    emit_compute(&mut a, &mut compute_l, &mut loop_l, &mut done_l, &mix_l)?;
    emit_start(&mut a, &mut start_l, &compute_l, &mut end_l)?;

    pack_sample(a, &mix_l, &compute_l, &start_l, &end_l)
}

fn asm_ok(result: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

fn emit_mix(a: &mut CodeAssembler, mix_l: &mut CodeLabel) -> Result<()> {
    asm_ok(a.set_label(mix_l))?;
    asm_ok(a.mov(rax, rcx))?;
    asm_ok(a.imul_3(rax, rax, 7i32))?;
    asm_ok(a.add(rax, 3i32))?;
    asm_ok(a.xor(rax, 0x5ai32))?;
    asm_ok(a.ret())
}

fn emit_compute(
    a: &mut CodeAssembler,
    compute_l: &mut CodeLabel,
    loop_l: &mut CodeLabel,
    done_l: &mut CodeLabel,
    mix_l: &CodeLabel,
) -> Result<()> {
    asm_ok(a.set_label(compute_l))?;
    asm_ok(a.push(rbx))?;
    asm_ok(a.push(rdi))?;
    asm_ok(a.mov(rbx, rcx))?;
    asm_ok(a.xor(rdi, rdi))?;
    asm_ok(a.mov(rcx, 1u64))?;
    asm_ok(a.set_label(loop_l))?;
    asm_ok(a.cmp(rcx, rbx))?;
    asm_ok(a.ja(*done_l))?;
    asm_ok(a.push(rcx))?;
    asm_ok(a.push(rbx))?;
    asm_ok(a.call(*mix_l))?;
    asm_ok(a.add(rdi, rax))?;
    asm_ok(a.pop(rbx))?;
    asm_ok(a.pop(rcx))?;
    asm_ok(a.inc(rcx))?;
    asm_ok(a.jmp(*loop_l))?;
    asm_ok(a.set_label(done_l))?;
    asm_ok(a.mov(rax, rdi))?;
    asm_ok(a.pop(rdi))?;
    asm_ok(a.pop(rbx))?;
    asm_ok(a.ret())
}

fn emit_start(
    a: &mut CodeAssembler,
    start_l: &mut CodeLabel,
    compute_l: &CodeLabel,
    end_l: &mut CodeLabel,
) -> Result<()> {
    asm_ok(a.set_label(start_l))?;
    asm_ok(a.sub(rsp, 0x28i32))?;
    asm_ok(a.mov(rcx, 10u64))?;
    asm_ok(a.call(*compute_l))?;
    asm_ok(a.mov(rbx, rax))?;
    emit_handle_call(a)?;
    emit_line_call(a)?;
    asm_ok(a.xor(rax, rax))?;
    asm_ok(a.add(rsp, 0x28i32))?;
    asm_ok(a.ret())?;
    asm_ok(a.set_label(end_l))?;
    asm_ok(a.nop())?;
    Ok(())
}

fn emit_handle_call(a: &mut CodeAssembler) -> Result<()> {
    asm_ok(a.mov(rcx, 0xffff_fff5u64))?;
    asm_ok(a.db(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]))?;
    asm_ok(a.call(rax))?;
    asm_ok(a.db(&[0xc6, 0x05, 0, 0, 0, 0, 1]))?;
    Ok(())
}

fn emit_line_call(a: &mut CodeAssembler) -> Result<()> {
    asm_ok(a.mov(rcx, rax))?;
    asm_ok(a.mov(rdx, rbx))?;
    asm_ok(a.mov(r8d, crate::trace::LINE_NUMBER as i32))?;
    asm_ok(a.xor(r9, r9))?;
    asm_ok(a.db(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]))?;
    asm_ok(a.call(rax))?;
    asm_ok(a.db(&[0xc6, 0x05, 0, 0, 0, 0, 2]))?;
    Ok(())
}

fn pack_sample(
    mut a: CodeAssembler,
    mix_l: &CodeLabel,
    compute_l: &CodeLabel,
    start_l: &CodeLabel,
    end_l: &CodeLabel,
) -> Result<Built> {
    let origin = IMAGE_BASE + 0x1000;
    let encoded = a
        .assemble_options(origin, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .map_err(|err| msg(err.to_string()))?;
    let rva = |label: &CodeLabel| -> Result<u32> {
        Ok((encoded
            .label_ip(label)
            .map_err(|err| msg(err.to_string()))?
            - IMAGE_BASE) as u32)
    };
    let mix_rva = rva(mix_l)?;
    let compute_rva = rva(compute_l)?;
    let start_rva = rva(start_l)?;
    let end_rva = rva(end_l)?;
    let mut code = encoded.inner.code_buffer;
    patch_rip(
        &mut code,
        origin,
        &[
            IMAGE_BASE + u64::from(IAT_RVA),
            IMAGE_BASE + u64::from(IAT_RVA + 8),
        ],
    )?;
    patch_phase(&mut code, origin)?;
    let symbols = sample_symbols(mix_rva, compute_rva, start_rva, end_rva);
    Ok(Built {
        bytes: emit(&sample_image(code, start_rva, &symbols))?,
        symbols,
    })
}

fn sample_symbols(mix_rva: u32, compute_rva: u32, start_rva: u32, end_rva: u32) -> Vec<Symbol> {
    vec![
        Symbol {
            name: "mix".into(),
            rva: mix_rva,
            size: compute_rva - mix_rva,
        },
        Symbol {
            name: "compute".into(),
            rva: compute_rva,
            size: start_rva - compute_rva,
        },
        Symbol {
            name: "start".into(),
            rva: start_rva,
            size: end_rva - start_rva,
        },
    ]
}

fn sample_image(code: Vec<u8>, start_rva: u32, symbols: &[Symbol]) -> PeImage {
    let data = rdata(symbols);
    PeImage {
        image_base: IMAGE_BASE,
        entry_rva: start_rva,
        sections: vec![
            Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: code,
                characteristics: CH_TEXT,
            },
            Section {
                name: ".rdata".into(),
                rva: 0x2000,
                bytes: data.bytes,
                characteristics: CH_RDATA,
            },
        ],
        exports: symbols
            .iter()
            .map(|sym| crate::pe::Export {
                name: sym.name.clone(),
                rva: sym.rva,
            })
            .collect(),
        imports: sample_imports(),
        export_rva: data.export_rva,
        export_size: data.export_size,
        import_rva: data.import_rva,
        import_size: data.import_size,
        iat_rva: IAT_RVA,
        iat_size: NAMES.len() as u32 * 8,
        exception_rva: 0,
        exception_size: 0,
        tls_rva: 0,
        tls_size: 0,
    }
}

fn sample_imports() -> Vec<crate::pe::Import> {
    NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| crate::pe::Import {
            dll: "kernel32.dll".into(),
            name: (*name).into(),
            iat_rva: IAT_RVA + index as u32 * 8,
            name_rva: 0,
            dll_rva: 0,
        })
        .collect()
}

struct Rdata {
    bytes: Vec<u8>,
    export_rva: u32,
    export_size: u32,
    import_rva: u32,
    import_size: u32,
}

fn rdata(symbols: &[Symbol]) -> Rdata {
    let mut bytes = vec![0u8; 0x800];
    bytes[..STRING.len()].copy_from_slice(STRING);
    let base = 0x2000u32;
    let export_off = 0x20usize;
    let func_off = 0x80usize;
    let name_off = 0xa0usize;
    let ord_off = 0xc0usize;
    let str_off = 0xe0usize;
    let n = symbols.len() as u32;
    put32(&mut bytes, export_off + 16, 1);
    put32(&mut bytes, export_off + 20, n);
    put32(&mut bytes, export_off + 24, n);
    put32(&mut bytes, export_off + 28, base + func_off as u32);
    put32(&mut bytes, export_off + 32, base + name_off as u32);
    put32(&mut bytes, export_off + 36, base + ord_off as u32);
    let mut cursor = str_off;
    for (index, symbol) in symbols.iter().enumerate() {
        put32(&mut bytes, func_off + index * 4, symbol.rva);
        put32(&mut bytes, name_off + index * 4, base + cursor as u32);
        bytes[ord_off + index * 2..ord_off + index * 2 + 2]
            .copy_from_slice(&(index as u16).to_le_bytes());
        bytes[cursor..cursor + symbol.name.len()].copy_from_slice(symbol.name.as_bytes());
        cursor += symbol.name.len() + 1;
    }
    let desc = 0x300usize;
    let ilt_off = 0x140usize;
    let dll_off = 0x500usize;
    bytes[dll_off..dll_off + 13].copy_from_slice(b"kernel32.dll\0");
    put32(&mut bytes, desc, base + ilt_off as u32);
    put32(&mut bytes, desc + 12, base + dll_off as u32);
    put32(&mut bytes, desc + 16, IAT_RVA);
    let mut hint = 0x540usize;
    for (index, name) in NAMES.iter().enumerate() {
        put32(&mut bytes, ilt_off + index * 8, base + hint as u32);
        bytes[hint + 2..hint + 2 + name.len()].copy_from_slice(name.as_bytes());
        hint += 2 + name.len() + 1;
    }
    Rdata {
        bytes,
        export_rva: base + export_off as u32,
        export_size: 40,
        import_rva: base + desc as u32,
        import_size: 40,
    }
}

fn patch_rip(code: &mut [u8], origin: u64, targets: &[u64]) -> Result<()> {
    let pattern = [0x48, 0x8b, 0x05, 0, 0, 0, 0];
    let mut cursor = 0usize;
    for target in targets {
        let found = code[cursor..]
            .windows(pattern.len())
            .position(|window| window == pattern)
            .ok_or_else(|| msg("rip load placeholder"))?;
        let at = cursor + found;
        let next = origin
            .checked_add(at as u64)
            .and_then(|ip| ip.checked_add(7))
            .ok_or_else(|| msg("rip load placeholder"))?;
        let disp = i32::try_from(
            i64::try_from(*target).map_err(|_| msg("rip load placeholder"))?
                - i64::try_from(next).map_err(|_| msg("rip load placeholder"))?,
        )
        .map_err(|_| msg("rip load placeholder"))?;
        code[at + 3..at + 7].copy_from_slice(&disp.to_le_bytes());
        cursor = at + 7;
    }
    Ok(())
}

fn patch_phase(code: &mut [u8], origin: u64) -> Result<()> {
    let pattern = [0xc6, 0x05, 0, 0, 0, 0];
    let target = IMAGE_BASE + u64::from(PHASE_RVA);
    let mut cursor = 0usize;
    let mut found_count = 0u32;
    while let Some(found) = code[cursor..]
        .windows(pattern.len())
        .position(|window| window == pattern)
    {
        let at = cursor + found;
        let next = origin
            .checked_add(at as u64 + 7)
            .ok_or_else(|| msg("phase disp"))?;
        let disp = i32::try_from(target as i64 - next as i64).map_err(|_| msg("phase disp"))?;
        code[at + 2..at + 6].copy_from_slice(&disp.to_le_bytes());
        cursor = at + 7;
        found_count += 1;
    }
    if found_count != 2 {
        return Err(msg("phase sites"));
    }
    Ok(())
}

fn put32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_rip_placeholder_is_an_error() {
        let mut code = [0u8; 8];
        let err = patch_rip(&mut code, IMAGE_BASE, &[IMAGE_BASE]).unwrap_err();
        assert_eq!(err.to_string(), "rip load placeholder");
    }
}
