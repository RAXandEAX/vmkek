//! Base relocations for a native PE whose generated code is position-independent.

use super::native::containing_data_section;
use super::*;

const NAME: &str = ".vmreloc";
const PAGE_BYTES: u32 = 0x1000;
const DIR64: u16 = 10;
const DISCARDABLE: u32 = 0x0200_0000;

pub(super) struct Relocations {
    sites: Vec<u32>,
    input_range: (u32, u32),
}

impl Relocations {
    pub(super) fn parse(image: &PeImage, range: (u32, u32)) -> Result<Self> {
        let (rva, size) = range;
        if rva == 0 || size == 0 || !rva.is_multiple_of(4) {
            return Err(msg("missing or unaligned PE base relocation directory"));
        }
        containing_data_section(image, rva, size)?;
        let data = read_rva(image, rva, size as usize)?;
        let mut cursor = 0;
        let mut sites = Vec::new();
        let mut previous = None;
        while cursor < data.len() {
            let page = rd_u32(data, cursor)?;
            let length = rd_u32(data, cursor + 4)? as usize;
            if !page.is_multiple_of(PAGE_BYTES)
                || previous.is_some_and(|last| page <= last)
                || length < 8
                || !length.is_multiple_of(4)
            {
                return Err(msg("invalid PE base relocation block"));
            }
            let entries = rd(data, cursor + 8, length - 8)?;
            read_block(image, page, entries, &mut sites)?;
            previous = Some(page);
            cursor += length;
        }
        sites.sort_unstable();
        if sites.is_empty() || sites.windows(2).any(|pair| pair[0] + 8 > pair[1]) {
            return Err(msg("empty or overlapping PE base relocations"));
        }
        Ok(Self {
            sites,
            input_range: range,
        })
    }

    pub(super) fn input_range(&self) -> (u32, u32) {
        self.input_range
    }

    pub(super) fn contains(&self, rva: u32) -> bool {
        self.sites.binary_search(&rva).is_ok()
    }

    pub(super) fn reject_rewrite(&self, (rva, len): (u32, u32)) -> Result<()> {
        let index = self.sites.partition_point(|&site| site + 8 <= rva);
        if self
            .sites
            .get(index)
            .is_some_and(|&site| u64::from(site) < u64::from(rva) + u64::from(len))
        {
            return Err(msg(
                "cannot rewrite a function containing a PE base relocation",
            ));
        }
        Ok(())
    }

    pub(super) fn publish(&self, image: &mut PeImage) -> Result<()> {
        if image.sections.iter().any(|section| section.name == NAME)
            || image.sections.len() >= MAX_SECTIONS
        {
            return Err(msg("cannot append a PE base relocation section"));
        }
        let mut sites = self.sites.clone();
        sites.extend(tls_fixups(image)?);
        sites.sort_unstable();
        if sites.windows(2).any(|pair| pair[0] + 8 > pair[1]) {
            return Err(msg("overlapping generated PE base relocations"));
        }
        let bytes = emit_blocks(&sites);
        image.sections.push(Section {
            name: NAME.into(),
            rva: image_span(image)?,
            bytes,
            characteristics: CH_RDATA | DISCARDABLE,
        });
        Ok(())
    }

    pub(super) fn restore_directory(bytes: &mut [u8]) -> Result<()> {
        let (_, count, table) = pe_table(bytes)?;
        let section = (0..count)
            .map(|index| table + index * 40)
            .find(|&at| bytes.get(at..at + 8) == Some(b".vmreloc"))
            .ok_or_else(|| msg("PE base relocation section is missing"))?;
        let size = rd_u32(bytes, section + 8)?;
        let rva = rd_u32(bytes, section + 12)?;
        put_dir(bytes, 5, rva, size);
        Ok(())
    }
}

fn read_block(image: &PeImage, page: u32, bytes: &[u8], sites: &mut Vec<u32>) -> Result<()> {
    let end = image
        .image_base
        .checked_add(u64::from(image_span(image)?))
        .ok_or_else(|| msg("PE preferred image address overflows"))?;
    for entry in bytes.chunks_exact(2) {
        let raw = u16::from_le_bytes([entry[0], entry[1]]);
        if raw >> 12 == 0 {
            continue;
        }
        if raw >> 12 != DIR64 {
            return Err(msg("unsupported PE base relocation type"));
        }
        let target = page
            .checked_add(u32::from(raw & 0x0fff))
            .ok_or_else(|| msg("PE base relocation target overflows"))?;
        let value = rd_u64(read_rva(image, target, 8)?, 0)?;
        if !(image.image_base..=end).contains(&value) {
            return Err(msg("PE DIR64 value is outside the preferred image"));
        }
        sites.push(target);
    }
    Ok(())
}

fn tls_fixups(image: &PeImage) -> Result<[u32; 5]> {
    if image.tls_rva == 0 || image.tls_size != 40 {
        return Err(msg("generated PE TLS directory is missing"));
    }
    let directory = read_rva(image, image.tls_rva, 40)?;
    let callbacks = rd_u64(directory, 24)?
        .checked_sub(image.image_base)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| msg("generated PE callback VA is invalid"))?;
    let pointers = read_rva(image, callbacks, 16)?;
    if rd_u64(pointers, 0)? == 0 || rd_u64(pointers, 8)? != 0 {
        return Err(msg("invalid generated PE callback table"));
    }
    let rva = image.tls_rva;
    Ok([rva, rva + 8, rva + 16, rva + 24, callbacks])
}

fn emit_blocks(sites: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for block in sites.chunk_by(|a, b| a / PAGE_BYTES == b / PAGE_BYTES) {
        let page = block[0] & !(PAGE_BYTES - 1);
        let padded_count = block.len().next_multiple_of(2);
        bytes.extend_from_slice(&page.to_le_bytes());
        bytes.extend_from_slice(&(8 + 2 * padded_count as u32).to_le_bytes());
        for &rva in block {
            let entry = (DIR64 << 12) | (rva - page) as u16;
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        if padded_count != block.len() {
            bytes.extend_from_slice(&[0; 2]);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_relocation_blocks_require_unique_mapped_dir64_sites() {
        let mut image = parse(&crate::sample::build().unwrap().bytes).unwrap();
        let value = (image.image_base + 0x1000).to_le_bytes();
        write_rva(&mut image, 0x2700, &value).unwrap();
        write_rva(&mut image, 0x2708, &value).unwrap();
        let valid = emit_blocks(&[0x2700, 0x2708]);
        write_rva(&mut image, 0x2780, &valid).unwrap();
        let parsed = Relocations::parse(&image, (0x2780, valid.len() as u32)).unwrap();
        assert!(parsed.contains(0x2708));
        assert!(parsed.reject_rewrite((0x2707, 1)).is_err());
        assert!(parsed.reject_rewrite((0x2710, 1)).is_ok());

        let duplicate = emit_blocks(&[0x2700, 0x2700]);
        write_rva(&mut image, 0x2780, &duplicate).unwrap();
        assert!(Relocations::parse(&image, (0x2780, duplicate.len() as u32)).is_err());
        write_rva(&mut image, 0x2780, &valid).unwrap();
        write_rva(&mut image, 0x2789, &[0x47]).unwrap();
        assert!(Relocations::parse(&image, (0x2780, valid.len() as u32)).is_err());
    }
}
