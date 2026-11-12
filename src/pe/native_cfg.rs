//! Validation for the native PE subset with compiler-instrumented CFG.

use super::native::{containing_data_section, overlaps};
use super::native_reloc::Relocations;
use super::native_unwind::check_code_range;
use super::*;

const GUARD_FLAGS: usize = 0x90;
const CF_INSTRUMENTED_AND_FIDS: u32 = 0x0500;
const CFG_FLAGS: u32 = 0x0001_7d00;
const MAX_GFIDS: u32 = MAX_SECTION_BYTES as u32 / 4;
const GFID_SECTION: &str = ".vmgfids";

pub(super) struct GuardConfig {
    targets: Vec<u32>,
    table: (u32, u32),
    config_rva: u32,
    stride: usize,
    pub(super) data: Vec<(u32, u32)>,
}

impl GuardConfig {
    pub(super) fn read(
        image: &PeImage,
        config_rva: u32,
        config: &[u8],
        relocations: &Relocations,
    ) -> Result<Self> {
        let flags = rd_u32(config, GUARD_FLAGS)?;
        let extra = flags >> 28;
        if flags & CF_INSTRUMENTED_AND_FIDS != CF_INSTRUMENTED_AND_FIDS
            || flags & !(CFG_FLAGS | 0xf000_0000) != 0
            || extra > 1
        {
            return Err(msg("unsupported native PE CFG guard flags"));
        }
        require_zero(cfg_tail(config, 0x94, 0x100)?)?;
        require_zero(cfg_tail(config, 0x108, 0x118)?)?;
        require_zero(config.get(0x140..).unwrap_or(&[]))?;
        let count = rd_u64(config, 0x88)?;
        if count == 0 || count > u64::from(MAX_GFIDS) {
            return Err(msg("invalid PE Guard CF function table count"));
        }
        let table_size = count as u32 * (4 + extra);
        let table = address_field(image, config_rva, config, 0x80, relocations)?
            .ok_or_else(|| msg("missing PE Guard CF function table"))?;
        let mut data = vec![(table, table_size)];
        let targets = guard_targets(image, table, table_size, (4 + extra) as usize)?;
        for offset in [0x70, 0x78, 0x118, 0x120, 0x128, 0x130, 0x138] {
            let slot = address_field(image, config_rva, config, offset, relocations)?;
            let required = matches!(offset, 0x70 | 0x78);
            if let Some(slot) = slot {
                verify_pointer_slot(image, slot, relocations, required)?;
                data.push((slot, 8));
            } else if required {
                return Err(msg("missing PE Guard CF check or dispatch slot"));
            }
        }
        if let Some(volatile) = address_field(image, config_rva, config, 0x100, relocations)? {
            let size = rd_u32(read_rva(image, volatile, 4)?, 0)?;
            if size < 24 {
                return Err(msg("invalid PE volatile metadata size"));
            }
            containing_data_section(image, volatile, size)?;
            data.push((volatile, size));
        }
        Ok(Self {
            targets,
            table: (table, table_size),
            config_rva,
            stride: (4 + extra) as usize,
            data,
        })
    }

    pub(super) fn publish(&self, image: &mut PeImage) -> Result<()> {
        if image.sections.len() >= MAX_SECTIONS
            || image
                .sections
                .iter()
                .any(|section| section.name == GFID_SECTION)
        {
            return Err(msg("cannot append a PE Guard CF function table section"));
        }
        let callback = generated_callback(image)?;
        let mut generated = [image.entry_rva, callback];
        generated.sort_unstable();
        if generated[0] == generated[1] {
            return Err(msg("overlapping generated PE Guard CF targets"));
        }
        for target in generated {
            if !target.is_multiple_of(16) || self.targets.binary_search(&target).is_ok() {
                return Err(msg(
                    "generated PE Guard CF target must be new and 16-byte aligned",
                ));
            }
            let end = target
                .checked_add(1)
                .ok_or_else(|| msg("PE Guard CF target overflows"))?;
            check_code_range(image, target, end)?;
        }
        let bytes = self.merge_generated_targets(image, generated)?;
        let rva = image_span(image)?;
        let count = self.targets.len() as u64 + 2;
        let table_va = image
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| msg("generated PE Guard CF table VA overflows"))?;
        write_rva(image, self.config_rva + 0x80, &table_va.to_le_bytes())?;
        write_rva(image, self.config_rva + 0x88, &count.to_le_bytes())?;
        image.sections.push(Section {
            name: GFID_SECTION.into(),
            rva,
            bytes,
            characteristics: CH_RDATA,
        });
        Ok(())
    }

    fn merge_generated_targets(&self, image: &PeImage, generated: [u32; 2]) -> Result<Vec<u8>> {
        let original = read_rva(image, self.table.0, self.table.1 as usize)?;
        let mut bytes = Vec::with_capacity(original.len() + 2 * self.stride);
        let mut new = generated.into_iter().peekable();
        for (&rva, record) in self.targets.iter().zip(original.chunks_exact(self.stride)) {
            while let Some(target) = new.next_if(|&target| target < rva) {
                push_generated(&mut bytes, self.stride, target);
            }
            bytes.extend_from_slice(record);
        }
        for rva in new {
            push_generated(&mut bytes, self.stride, rva);
        }
        Ok(bytes)
    }

    pub(super) fn validate_rewrite(&self, (rva, len): (u32, u32)) -> Result<()> {
        let index = self.targets.partition_point(|&target| target <= rva);
        if self
            .targets
            .get(index)
            .is_some_and(|&target| overlaps((rva, len), (target, 1)))
        {
            return Err(msg(
                "PE Guard CF target lies inside a function being rewritten",
            ));
        }
        Ok(())
    }
}

fn generated_callback(image: &PeImage) -> Result<u32> {
    if image.tls_rva == 0 || image.tls_size != 40 {
        return Err(msg("generated PE TLS directory is missing"));
    }
    let directory = read_rva(image, image.tls_rva, 40)?;
    let table = va_to_rva(image, rd_u64(directory, 24)?)?;
    let callback = read_rva(image, table, 16)?;
    if rd_u64(callback, 8)? != 0 {
        return Err(msg("generated PE Guard CF expects one TLS callback"));
    }
    va_to_rva(image, rd_u64(callback, 0)?)
}

fn push_generated(bytes: &mut Vec<u8>, stride: usize, rva: u32) {
    bytes.extend_from_slice(&rva.to_le_bytes());
    bytes.resize(bytes.len() + stride - 4, 0);
}

fn require_zero(bytes: &[u8]) -> Result<()> {
    if bytes.iter().any(|&byte| byte != 0) {
        return Err(msg("unsupported PE Guard CF load configuration extensions"));
    }
    Ok(())
}

fn cfg_tail(config: &[u8], start: usize, end: usize) -> Result<&[u8]> {
    if config.len() <= start {
        return Ok(&[]);
    }
    rd(config, start, end.min(config.len()) - start)
}

fn address_field(
    image: &PeImage,
    config_rva: u32,
    config: &[u8],
    offset: usize,
    relocations: &Relocations,
) -> Result<Option<u32>> {
    if config.len() <= offset {
        return Ok(None);
    }
    let va = rd_u64(config, offset)?;
    if va == 0 {
        return Ok(None);
    }
    if !relocations.contains(config_rva + offset as u32) {
        return Err(msg("PE Guard CF absolute field lacks a DIR64 relocation"));
    }
    Ok(Some(va_to_rva(image, va)?))
}

fn va_to_rva(image: &PeImage, va: u64) -> Result<u32> {
    va.checked_sub(image.image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| msg("PE Guard CF VA is outside the image"))
}

fn verify_pointer_slot(
    image: &PeImage,
    slot: u32,
    relocations: &Relocations,
    required: bool,
) -> Result<()> {
    let section = containing_data_section(image, slot, 8)?;
    if !slot.is_multiple_of(8) || section.characteristics & SCN_WRITE != 0 {
        return Err(msg(
            "PE Guard CF pointer slot must be aligned and read-only",
        ));
    }
    let value = rd_u64(read_rva(image, slot, 8)?, 0)?;
    if required && value == 0 {
        return Err(msg("missing PE Guard CF default function pointer"));
    }
    if value != 0 {
        if !relocations.contains(slot) {
            return Err(msg("PE Guard CF function slot lacks a DIR64 relocation"));
        }
        let target = va_to_rva(image, value)?;
        let end = target
            .checked_add(1)
            .ok_or_else(|| msg("PE Guard CF target overflows"))?;
        check_code_range(image, target, end)?;
    }
    Ok(())
}

fn guard_targets(image: &PeImage, table: u32, size: u32, stride: usize) -> Result<Vec<u32>> {
    let section = containing_data_section(image, table, size)?;
    if section.characteristics & SCN_WRITE != 0 {
        return Err(msg("PE Guard CF function table must be read-only"));
    }
    let mut targets = Vec::new();
    for record in read_rva(image, table, size as usize)?.chunks_exact(stride) {
        let target = rd_u32(record, 0)?;
        if targets.last().is_some_and(|&last| target <= last)
            || record.get(4).is_some_and(|flags| flags & !3 != 0)
        {
            return Err(msg(
                "invalid or unsupported PE Guard CF function table entry",
            ));
        }
        let end = target
            .checked_add(1)
            .ok_or_else(|| msg("PE Guard CF target overflows"))?;
        check_code_range(image, target, end)?;
        targets.push(target);
    }
    Ok(targets)
}
