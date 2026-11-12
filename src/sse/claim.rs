//! Which L4, L5, and L6 mnemonics this host can replay.
//!
//! An L4 mnemonic is replayed only when a long-mode legacy or 128-bit VEX
//! encoding can run here. An L5 mnemonic is replayed when a VEX.128 or VEX.256
//! encoding can run here. An L6 mnemonic is replayed when an EVEX or VEX opmask
//! encoding can run here: AVX-512F must be set and XCR0[7:5] must be 111.
//! The host mask save uses `kmovq` only when AVX512BW is present and `kmovw`
//! otherwise, so the group gate stays AVX-512F. A missing CPUID bit or a
//! disabled XCR0 state leaves the census bit `proven: false`. RDRAND, RDSEED,
//! and FS/GS base are not replayed, but their CPUID bits are present, so the
//! L8 inventory records them `proven: true`. XOP is not replayed.

use std::sync::OnceLock;

use iced_x86::{Code, CpuidFeature, EncodingKind, Mnemonic, OpCodeOperandKind};

use crate::isa::encoding_outside_user_x64;

/// `true` when the System differential can run `mnemonic` on this CPU.
#[must_use]
pub(crate) fn is_proven(mnemonic: Mnemonic) -> bool {
    skip_reason(mnemonic).is_none()
}

/// Why `mnemonic` stays unproven. `None` means this host can prove it.
#[must_use]
pub(crate) fn skip_reason(mnemonic: Mnemonic) -> Option<String> {
    if let Some(reason) = fixed_skip(mnemonic) {
        return Some(reason.to_string());
    }
    let mut missing = Vec::new();
    for code in mnemonic_codes(mnemonic) {
        if let Some(text) = absent(code) {
            missing.push(text);
            continue;
        }
        if replay_shape(code) {
            return None;
        }
    }
    Some(unproven_text(mnemonic, &missing))
}

/// `true` when host replay must not run this mnemonic.
#[must_use]
pub(crate) fn blocked(mnemonic: Mnemonic) -> bool {
    fixed_skip(mnemonic).is_some()
}

/// `true` when a VEX.128 or VEX.256 form of `mnemonic` can run on this CPU.
#[must_use]
pub(crate) fn is_l5_proven(mnemonic: Mnemonic) -> bool {
    l5_skip_reason(mnemonic).is_none()
}

/// Why an L5 mnemonic stays unproven. `None` means a VEX form can run here.
#[must_use]
pub(crate) fn l5_skip_reason(mnemonic: Mnemonic) -> Option<String> {
    if let Some(reason) = avx2_block() {
        return Some(reason);
    }
    let mut missing = Vec::new();
    let mut saw = false;
    for code in mnemonic_codes(mnemonic) {
        if !l5_code(code) {
            continue;
        }
        saw = true;
        if let Some(text) = absent(code) {
            missing.push(text);
            continue;
        }
        return None;
    }
    if saw {
        Some(unproven_text(mnemonic, &missing))
    } else {
        Some(format!(
            "{mnemonic:?} has no VEX.128 or VEX.256 encoding in long mode"
        ))
    }
}

/// `true` when an EVEX or VEX opmask form of `mnemonic` can run on this CPU.
#[must_use]
pub(crate) fn is_l6_proven(mnemonic: Mnemonic) -> bool {
    l6_skip_reason(mnemonic).is_none()
}

/// Why an L6 mnemonic stays unproven. `None` means an AVX-512 form can run here.
#[must_use]
pub(crate) fn l6_skip_reason(mnemonic: Mnemonic) -> Option<String> {
    if let Some(reason) = avx512_block() {
        return Some(reason);
    }
    let mut missing = Vec::new();
    let mut saw = false;
    for code in mnemonic_codes(mnemonic) {
        if !l6_code(code) {
            continue;
        }
        saw = true;
        if let Some(text) = absent(code) {
            missing.push(text);
            continue;
        }
        return None;
    }
    if saw {
        Some(unproven_text(mnemonic, &missing))
    } else {
        Some(format!(
            "{mnemonic:?} has no EVEX or opmask encoding in long mode; CPUID features do not match"
        ))
    }
}

fn avx512_block() -> Option<String> {
    if !host_has(CpuidFeature::AVX512F) {
        return Some("missing CPUID.07H:EBX[16] AVX512F absent".to_string());
    }
    if cache().xcr0 & 0xE0 != 0xE0 {
        return Some("CPUID.07H:EBX[16] AVX512F is present but XCR0[7:5] is not 111".to_string());
    }
    None
}

fn l6_code(code: Code) -> bool {
    let encoding = code.op_code().encoding();
    matches!(encoding, EncodingKind::EVEX | EncodingKind::VEX) && !code_uses_tmm(code)
}

fn code_uses_tmm(code: Code) -> bool {
    let info = code.op_code();
    (0..info.op_count()).any(|index| {
        let name = format!("{:?}", info.op_kind(index));
        name.split('_').next().unwrap_or("") == "tmm"
    })
}

fn avx2_block() -> Option<String> {
    if !host_has(CpuidFeature::AVX) {
        return Some("missing CPUID.01H:ECX[28] AVX absent".to_string());
    }
    if !host_has(CpuidFeature::AVX2) {
        return Some("missing CPUID.07H:EBX[5] AVX2 absent".to_string());
    }
    if cache().xcr0 & 6 != 6 {
        return Some("CPUID.07H:EBX[5] AVX2 is present but XCR0[2:1] is not 11".to_string());
    }
    None
}

fn l5_code(code: Code) -> bool {
    code.op_code().encoding() == EncodingKind::VEX && !code_forbidden(code)
}

fn code_forbidden(code: Code) -> bool {
    let info = code.op_code();
    (0..info.op_count()).any(|index| {
        let name = format!("{:?}", info.op_kind(index));
        let head = name.split('_').next().unwrap_or("");
        matches!(head, "zmm" | "tmm" | "k")
    })
}

/// `true` when `code` writes a YMM, ZMM, or opmask operand.
#[must_use]
pub(crate) fn code_is_wide(code: Code) -> bool {
    let info = code.op_code();
    (0..info.op_count()).any(|index| wide_kind(info.op_kind(index)))
}

fn fixed_skip(mnemonic: Mnemonic) -> Option<&'static str> {
    match mnemonic {
        Mnemonic::Rdrand | Mnemonic::Rdseed => Some(
            "RDRAND/RDSEED is nondeterministic; CPUID.01H:ECX[30] and CPUID.07H:EBX[18] are present, but a System differential has no stable oracle",
        ),
        Mnemonic::Rdfsbase | Mnemonic::Rdgsbase | Mnemonic::Wrfsbase | Mnemonic::Wrgsbase => Some(
            "FS/GS base is not guest state; CPUID.07H:EBX[0] FSGSBASE is present, but host replay would read the host thread",
        ),
        _ => None,
    }
}

fn unproven_text(mnemonic: Mnemonic, missing: &[String]) -> String {
    if missing.is_empty() {
        return format!("{mnemonic:?} has no legacy or 128-bit VEX encoding in long mode");
    }
    let mut uniq = missing.to_vec();
    uniq.sort();
    uniq.dedup();
    format!("missing {}", uniq.join("; "))
}

fn mnemonic_codes(mnemonic: Mnemonic) -> impl Iterator<Item = Code> {
    Code::values().filter(move |code| code_of(mnemonic, *code))
}

fn code_of(mnemonic: Mnemonic, code: Code) -> bool {
    code != Code::INVALID
        && code.mnemonic() == mnemonic
        && !code.is_privileged()
        && code.op_code().is_available_in_mode(64)
        && !encoding_outside_user_x64(code)
}

fn replay_shape(code: Code) -> bool {
    let encoding = code.op_code().encoding();
    matches!(encoding, EncodingKind::Legacy | EncodingKind::VEX) && !code_is_wide(code)
}

fn absent(code: Code) -> Option<String> {
    let mut parts = Vec::new();
    for feature in code.cpuid_features() {
        if !host_has(*feature) {
            parts.push(format!("{} absent", feature_label(*feature)));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn wide_kind(kind: OpCodeOperandKind) -> bool {
    let name = format!("{kind:?}");
    let head = name.split('_').next().unwrap_or("");
    matches!(head, "ymm" | "zmm" | "tmm" | "k")
}

#[derive(Clone, Copy)]
enum Leaf {
    OneEcx,
    SevenEbx,
    SevenEcx,
    SevenEdx,
    Seven1Eax,
    ExtEcx,
}

struct Feat {
    feature: CpuidFeature,
    leaf: Leaf,
    bit: u32,
    label: &'static str,
}

const FEATS: &[Feat] = &[
    Feat {
        feature: CpuidFeature::SSE3,
        leaf: Leaf::OneEcx,
        bit: 0,
        label: "CPUID.01H:ECX[0] SSE3",
    },
    Feat {
        feature: CpuidFeature::PCLMULQDQ,
        leaf: Leaf::OneEcx,
        bit: 1,
        label: "CPUID.01H:ECX[1] PCLMULQDQ",
    },
    Feat {
        feature: CpuidFeature::SSSE3,
        leaf: Leaf::OneEcx,
        bit: 9,
        label: "CPUID.01H:ECX[9] SSSE3",
    },
    Feat {
        feature: CpuidFeature::FMA,
        leaf: Leaf::OneEcx,
        bit: 12,
        label: "CPUID.01H:ECX[12] FMA",
    },
    Feat {
        feature: CpuidFeature::SSE4_1,
        leaf: Leaf::OneEcx,
        bit: 19,
        label: "CPUID.01H:ECX[19] SSE4_1",
    },
    Feat {
        feature: CpuidFeature::SSE4_2,
        leaf: Leaf::OneEcx,
        bit: 20,
        label: "CPUID.01H:ECX[20] SSE4_2",
    },
    Feat {
        feature: CpuidFeature::MOVBE,
        leaf: Leaf::OneEcx,
        bit: 22,
        label: "CPUID.01H:ECX[22] MOVBE",
    },
    Feat {
        feature: CpuidFeature::POPCNT,
        leaf: Leaf::OneEcx,
        bit: 23,
        label: "CPUID.01H:ECX[23] POPCNT",
    },
    Feat {
        feature: CpuidFeature::AES,
        leaf: Leaf::OneEcx,
        bit: 25,
        label: "CPUID.01H:ECX[25] AES",
    },
    Feat {
        feature: CpuidFeature::AVX,
        leaf: Leaf::OneEcx,
        bit: 28,
        label: "CPUID.01H:ECX[28] AVX",
    },
    Feat {
        feature: CpuidFeature::F16C,
        leaf: Leaf::OneEcx,
        bit: 29,
        label: "CPUID.01H:ECX[29] F16C",
    },
    Feat {
        feature: CpuidFeature::RDRAND,
        leaf: Leaf::OneEcx,
        bit: 30,
        label: "CPUID.01H:ECX[30] RDRAND",
    },
    Feat {
        feature: CpuidFeature::FSGSBASE,
        leaf: Leaf::SevenEbx,
        bit: 0,
        label: "CPUID.07H:EBX[0] FSGSBASE",
    },
    Feat {
        feature: CpuidFeature::BMI1,
        leaf: Leaf::SevenEbx,
        bit: 3,
        label: "CPUID.07H:EBX[3] BMI1",
    },
    Feat {
        feature: CpuidFeature::AVX2,
        leaf: Leaf::SevenEbx,
        bit: 5,
        label: "CPUID.07H:EBX[5] AVX2",
    },
    Feat {
        feature: CpuidFeature::BMI2,
        leaf: Leaf::SevenEbx,
        bit: 8,
        label: "CPUID.07H:EBX[8] BMI2",
    },
    Feat {
        feature: CpuidFeature::RDSEED,
        leaf: Leaf::SevenEbx,
        bit: 18,
        label: "CPUID.07H:EBX[18] RDSEED",
    },
    Feat {
        feature: CpuidFeature::ADX,
        leaf: Leaf::SevenEbx,
        bit: 19,
        label: "CPUID.07H:EBX[19] ADX",
    },
    Feat {
        feature: CpuidFeature::SHA,
        leaf: Leaf::SevenEbx,
        bit: 29,
        label: "CPUID.07H:EBX[29] SHA",
    },
    Feat {
        feature: CpuidFeature::LZCNT,
        leaf: Leaf::ExtEcx,
        bit: 5,
        label: "CPUID.80000001H:ECX[5] LZCNT",
    },
    Feat {
        feature: CpuidFeature::SSE4A,
        leaf: Leaf::ExtEcx,
        bit: 6,
        label: "CPUID.80000001H:ECX[6] SSE4A",
    },
    Feat {
        feature: CpuidFeature::FMA4,
        leaf: Leaf::ExtEcx,
        bit: 16,
        label: "CPUID.80000001H:ECX[16] FMA4",
    },
    Feat {
        feature: CpuidFeature::TBM,
        leaf: Leaf::ExtEcx,
        bit: 21,
        label: "CPUID.80000001H:ECX[21] TBM",
    },
];

const FEATS_512: &[Feat] = &[
    Feat {
        feature: CpuidFeature::AVX512F,
        leaf: Leaf::SevenEbx,
        bit: 16,
        label: "CPUID.07H:EBX[16] AVX512F",
    },
    Feat {
        feature: CpuidFeature::AVX512DQ,
        leaf: Leaf::SevenEbx,
        bit: 17,
        label: "CPUID.07H:EBX[17] AVX512DQ",
    },
    Feat {
        feature: CpuidFeature::AVX512_IFMA,
        leaf: Leaf::SevenEbx,
        bit: 21,
        label: "CPUID.07H:EBX[21] AVX512_IFMA",
    },
    Feat {
        feature: CpuidFeature::AVX512PF,
        leaf: Leaf::SevenEbx,
        bit: 26,
        label: "CPUID.07H:EBX[26] AVX512PF",
    },
    Feat {
        feature: CpuidFeature::AVX512ER,
        leaf: Leaf::SevenEbx,
        bit: 27,
        label: "CPUID.07H:EBX[27] AVX512ER",
    },
    Feat {
        feature: CpuidFeature::AVX512CD,
        leaf: Leaf::SevenEbx,
        bit: 28,
        label: "CPUID.07H:EBX[28] AVX512CD",
    },
    Feat {
        feature: CpuidFeature::AVX512BW,
        leaf: Leaf::SevenEbx,
        bit: 30,
        label: "CPUID.07H:EBX[30] AVX512BW",
    },
    Feat {
        feature: CpuidFeature::AVX512VL,
        leaf: Leaf::SevenEbx,
        bit: 31,
        label: "CPUID.07H:EBX[31] AVX512VL",
    },
    Feat {
        feature: CpuidFeature::AVX512_VBMI,
        leaf: Leaf::SevenEcx,
        bit: 1,
        label: "CPUID.07H:ECX[1] AVX512_VBMI",
    },
    Feat {
        feature: CpuidFeature::AVX512_VBMI2,
        leaf: Leaf::SevenEcx,
        bit: 6,
        label: "CPUID.07H:ECX[6] AVX512_VBMI2",
    },
    Feat {
        feature: CpuidFeature::GFNI,
        leaf: Leaf::SevenEcx,
        bit: 8,
        label: "CPUID.07H:ECX[8] GFNI",
    },
    Feat {
        feature: CpuidFeature::VAES,
        leaf: Leaf::SevenEcx,
        bit: 9,
        label: "CPUID.07H:ECX[9] VAES",
    },
    Feat {
        feature: CpuidFeature::VPCLMULQDQ,
        leaf: Leaf::SevenEcx,
        bit: 10,
        label: "CPUID.07H:ECX[10] VPCLMULQDQ",
    },
    Feat {
        feature: CpuidFeature::AVX512_VNNI,
        leaf: Leaf::SevenEcx,
        bit: 11,
        label: "CPUID.07H:ECX[11] AVX512_VNNI",
    },
    Feat {
        feature: CpuidFeature::AVX512_BITALG,
        leaf: Leaf::SevenEcx,
        bit: 12,
        label: "CPUID.07H:ECX[12] AVX512_BITALG",
    },
    Feat {
        feature: CpuidFeature::AVX512_VPOPCNTDQ,
        leaf: Leaf::SevenEcx,
        bit: 14,
        label: "CPUID.07H:ECX[14] AVX512_VPOPCNTDQ",
    },
    Feat {
        feature: CpuidFeature::PREFETCHWT1,
        leaf: Leaf::SevenEcx,
        bit: 0,
        label: "CPUID.07H:ECX[0] PREFETCHWT1",
    },
    Feat {
        feature: CpuidFeature::AVX512_4VNNIW,
        leaf: Leaf::SevenEdx,
        bit: 2,
        label: "CPUID.07H:EDX[2] AVX512_4VNNIW",
    },
    Feat {
        feature: CpuidFeature::AVX512_4FMAPS,
        leaf: Leaf::SevenEdx,
        bit: 3,
        label: "CPUID.07H:EDX[3] AVX512_4FMAPS",
    },
    Feat {
        feature: CpuidFeature::AVX512_VP2INTERSECT,
        leaf: Leaf::SevenEdx,
        bit: 8,
        label: "CPUID.07H:EDX[8] AVX512_VP2INTERSECT",
    },
    Feat {
        feature: CpuidFeature::AVX512_FP16,
        leaf: Leaf::SevenEdx,
        bit: 23,
        label: "CPUID.07H:EDX[23] AVX512_FP16",
    },
    Feat {
        feature: CpuidFeature::AVX512_BF16,
        leaf: Leaf::Seven1Eax,
        bit: 5,
        label: "CPUID.(EAX=07H, ECX=1H):EAX[5] AVX512_BF16",
    },
];

fn feature_label(feature: CpuidFeature) -> String {
    feat_of(feature)
        .map(|item| item.label.to_string())
        .unwrap_or_else(|| format!("CPUID feature {feature:?} is not in the SSE/AVX map"))
}

/// `true` when this CPU advertises AVX512BW. `kmovq` needs that bit; `kmovw` does not.
#[must_use]
pub(crate) fn avx512bw() -> bool {
    host_has(CpuidFeature::AVX512BW)
}

/// `true` when `code` names a CPUID feature this host does not have.
#[cfg(test)]
#[must_use]
pub(crate) fn feature_missing(code: Code) -> bool {
    absent(code).is_some()
}

fn host_has(feature: CpuidFeature) -> bool {
    let Some(feat) = feat_of(feature) else {
        return false;
    };
    let word = match feat.leaf {
        Leaf::OneEcx => cache().one_ecx,
        Leaf::SevenEbx => cache().seven_ebx,
        Leaf::SevenEcx => cache().seven_ecx,
        Leaf::SevenEdx => cache().seven_edx,
        Leaf::Seven1Eax => cache().seven1_eax,
        Leaf::ExtEcx => cache().ext_ecx,
    };
    word & (1 << feat.bit) != 0
}

fn feat_of(feature: CpuidFeature) -> Option<&'static Feat> {
    FEATS
        .iter()
        .chain(FEATS_512)
        .find(|item| item.feature == feature)
}

struct Cache {
    one_ecx: u32,
    seven_ebx: u32,
    seven_ecx: u32,
    seven_edx: u32,
    seven1_eax: u32,
    ext_ecx: u32,
    xcr0: u64,
}

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(read_cache)
}

fn read_cache() -> Cache {
    let max = cpuid(0, 0).eax;
    let ext = cpuid(0x8000_0000, 0).eax;
    let one_ecx = leaf_ecx(max, 1);
    let seven = leaf7(max, 0);
    let seven1 = leaf7(max, 1);
    Cache {
        one_ecx,
        seven_ebx: seven.ebx,
        seven_ecx: seven.ecx,
        seven_edx: seven.edx,
        seven1_eax: seven1.eax,
        ext_ecx: leaf_ecx(ext, 0x8000_0001),
        xcr0: read_xcr0(one_ecx),
    }
}

fn leaf7(max: u32, sub: u32) -> std::arch::x86_64::CpuidResult {
    if max >= 7 {
        cpuid(7, sub)
    } else {
        std::arch::x86_64::CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }
}

fn read_xcr0(one_ecx: u32) -> u64 {
    if one_ecx & (1 << 27) == 0 {
        return 0;
    }
    let eax: u32;
    let edx: u32;
    // SAFETY: CPUID.01H:ECX[27] OSXSAVE is set, so `xgetbv` with ecx 0 reads
    // XCR0 and does not fault. It only writes eax and edx.
    unsafe {
        std::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            lateout("eax") eax,
            lateout("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    u64::from(eax) | (u64::from(edx) << 32)
}

fn leaf_ecx(max: u32, leaf: u32) -> u32 {
    if max >= leaf {
        cpuid(leaf, 0).ecx
    } else {
        0
    }
}

fn cpuid(leaf: u32, sub: u32) -> std::arch::x86_64::CpuidResult {
    // Leaves 0, 1, 7, and 0x8000_0001 only identify the CPU.
    std::arch::x86_64::__cpuid_count(leaf, sub)
}
