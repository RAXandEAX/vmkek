//! CPUID bits iced-x86 hangs on an encoding, read from this process.
//!
//! M-LINUX is the only registered machine with a CPU. A feature this process
//! does not advertise is absent on every registered machine.

use std::sync::OnceLock;

use iced_x86::CpuidFeature;

#[derive(Clone, Copy)]
enum Reg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

struct Leaves {
    max_basic: u32,
    one_eax: u32,
    one_ecx: u32,
    one_edx: u32,
    seven_max: u32,
    seven_ebx: u32,
    seven_ecx: u32,
    seven_edx: u32,
    seven1_eax: u32,
    seven1_ebx: u32,
    seven1_edx: u32,
    ext_max: u32,
    ext_ecx: u32,
    ext_edx: u32,
    ext8_ebx: u32,
    d1_eax: u32,
    leaf12_eax: u32,
    leaf14_ebx: u32,
    leaf19_ebx: u32,
    centaur_max: u32,
    centaur_edx: u32,
    vendor: [u8; 12],
}

pub(crate) fn host_has(feature: CpuidFeature) -> bool {
    match probe(feature) {
        Probe::Always => true,
        Probe::Never => false,
        Probe::Bit {
            leaf,
            sub,
            reg,
            bit,
        } => bit_set(leaf, sub, reg, bit),
        Probe::Either {
            leaf,
            sub,
            reg,
            a,
            b,
        } => bit_set(leaf, sub, reg, a) || bit_set(leaf, sub, reg, b),
        Probe::Padlock(shift) => padlock(shift),
        Probe::Vendor(name) => vendor_is(name),
        Probe::Family(family) => display_family() == family,
        Probe::MultibyteNop => {
            let nibble = (leaves().one_eax >> 8) & 0xf;
            nibble == 0b0110 || nibble == 0b1111
        }
        Probe::Fpu => bit_set(1, 0, Reg::Edx, 0),
        Probe::CyrixEmmi => vendor_is("CyrixInstead") && bit_set(0x8000_0001, 0, Reg::Edx, 24),
    }
}

enum Probe {
    Always,
    Never,
    Bit {
        leaf: u32,
        sub: u32,
        reg: Reg,
        bit: u32,
    },
    Either {
        leaf: u32,
        sub: u32,
        reg: Reg,
        a: u32,
        b: u32,
    },
    Padlock(u32),
    Vendor(&'static str),
    Family(u32),
    MultibyteNop,
    Fpu,
    CyrixEmmi,
}

fn probe(feature: CpuidFeature) -> Probe {
    // iced-x86 marks the enum non-exhaustive. An unknown feature is not
    // advertised here, so a mnemonic that needs it stays unproven.
    probe_baseline(feature)
        .or_else(|| probe_leaf1(feature))
        .or_else(|| probe_leaf7_0(feature))
        .or_else(|| probe_leaf7_1(feature))
        .or_else(|| probe_extended(feature))
        .or_else(|| probe_xsave_sgx_pt_kl(feature))
        .or_else(|| probe_padlock_cyrix(feature))
        .unwrap_or(Probe::Never)
}

fn bit_probe(leaf: u32, sub: u32, reg: Reg, bit: u32) -> Probe {
    Probe::Bit {
        leaf,
        sub,
        reg,
        bit,
    }
}

fn probe_baseline(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    Some(match feature {
        INTEL8086 | INTEL186 | INTEL286 | INTEL386 | INTEL486 | CPUID | RDPMC | PAUSE | SMM => {
            Probe::Always
        }
        INTEL8086_ONLY | INTEL286_ONLY | INTEL386_ONLY | INTEL386_A0_ONLY | INTEL486_A_ONLY
        | UMOV | FPU287XL_ONLY | FPU387SL_ONLY | IA64 | CL1INVMB | INVEPT | INVVPID | MOV_TR
        | TDX | UDBG | PADLOCK_UNDOC => Probe::Never,
        FPU | FPU287 | FPU387 => Probe::Fpu,
        MULTIBYTENOP => Probe::MultibyteNop,
        KNC => Probe::Family(0x0b),
        _ => return None,
    })
}

fn probe_leaf1(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    let (reg, bit) = match feature {
        AES => (Reg::Ecx, 25),
        AVX => (Reg::Ecx, 28),
        CLFSH => (Reg::Edx, 19),
        CMOV => (Reg::Edx, 15),
        CMPXCHG16B => (Reg::Ecx, 13),
        CX8 => (Reg::Edx, 8),
        F16C => (Reg::Ecx, 29),
        FMA => (Reg::Ecx, 12),
        FXSR => (Reg::Edx, 24),
        MMX => (Reg::Edx, 23),
        MONITOR => (Reg::Ecx, 3),
        MOVBE => (Reg::Ecx, 22),
        MSR => (Reg::Edx, 5),
        PCLMULQDQ => (Reg::Ecx, 1),
        POPCNT => (Reg::Ecx, 23),
        RDRAND => (Reg::Ecx, 30),
        SEP => (Reg::Edx, 11),
        SMX => (Reg::Ecx, 6),
        SSE => (Reg::Edx, 25),
        SSE2 => (Reg::Edx, 26),
        SSE3 => (Reg::Ecx, 0),
        SSE4_1 => (Reg::Ecx, 19),
        SSE4_2 => (Reg::Ecx, 20),
        SSSE3 => (Reg::Ecx, 9),
        TSC => (Reg::Edx, 4),
        VMX => (Reg::Ecx, 5),
        XSAVE => (Reg::Ecx, 26),
        _ => return None,
    };
    Some(bit_probe(1, 0, reg, bit))
}

fn probe_leaf7_0(feature: CpuidFeature) -> Option<Probe> {
    probe_leaf7_ebx(feature)
        .or_else(|| probe_leaf7_ecx(feature))
        .or_else(|| probe_leaf7_edx(feature))
}

fn probe_leaf7_ebx(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    if feature == HLE_or_RTM {
        return Some(Probe::Either {
            leaf: 7,
            sub: 0,
            reg: Reg::Ebx,
            a: 4,
            b: 11,
        });
    }
    let bit = match feature {
        ADX => 19,
        AVX2 => 5,
        AVX512_IFMA => 21,
        AVX512BW => 30,
        AVX512CD => 28,
        AVX512DQ => 17,
        AVX512ER => 27,
        AVX512F => 16,
        AVX512PF => 26,
        AVX512VL => 31,
        BMI1 => 3,
        BMI2 => 8,
        CLFLUSHOPT => 23,
        CLWB => 24,
        FSGSBASE => 0,
        HLE => 4,
        INVPCID => 10,
        MPX => 14,
        PCOMMIT => 22,
        RDSEED => 18,
        RTM => 11,
        SHA => 29,
        SMAP => 20,
        _ => return None,
    };
    Some(bit_probe(7, 0, Reg::Ebx, bit))
}

fn probe_leaf7_ecx(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    let bit = match feature {
        AVX512_BITALG => 12,
        AVX512_VBMI => 1,
        AVX512_VBMI2 => 6,
        AVX512_VNNI => 11,
        AVX512_VPOPCNTDQ => 14,
        CET_SS => 7,
        CLDEMOTE => 25,
        ENQCMD => 29,
        GFNI => 8,
        MOVDIR64B => 28,
        MOVDIRI => 27,
        PKU => 3,
        PREFETCHWT1 => 0,
        RDPID => 22,
        VAES => 9,
        VPCLMULQDQ => 10,
        WAITPKG => 5,
        KL => 23,
        _ => return None,
    };
    Some(bit_probe(7, 0, Reg::Ecx, bit))
}

fn probe_leaf7_edx(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    let bit = match feature {
        AVX512_4FMAPS => 3,
        AVX512_4VNNIW => 2,
        AVX512_VP2INTERSECT => 8,
        CET_IBT => 20,
        PCONFIG => 18,
        SERIALIZE => 14,
        TSXLDTRK => 16,
        AMX_BF16 => 22,
        AMX_TILE => 24,
        AMX_INT8 => 25,
        UINTR => 5,
        AVX512_FP16 => 23,
        _ => return None,
    };
    Some(bit_probe(7, 0, Reg::Edx, bit))
}

fn probe_leaf7_1(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    let (reg, bit) = match feature {
        AVX512_BF16 => (Reg::Eax, 5),
        HRESET => (Reg::Eax, 22),
        AVX_VNNI => (Reg::Eax, 4),
        FRED => (Reg::Eax, 17),
        LKGS => (Reg::Eax, 18),
        RAO_INT => (Reg::Eax, 3),
        PREFETCHITI => (Reg::Edx, 14),
        AMX_FP16 => (Reg::Eax, 21),
        CMPCCXADD => (Reg::Eax, 7),
        AVX_IFMA => (Reg::Eax, 23),
        AVX_NE_CONVERT => (Reg::Edx, 5),
        AVX_VNNI_INT8 => (Reg::Edx, 4),
        MSRLIST => (Reg::Eax, 27),
        WRMSRNS => (Reg::Eax, 19),
        AMX_COMPLEX => (Reg::Edx, 8),
        SHA512 => (Reg::Eax, 0),
        SM3 => (Reg::Eax, 1),
        SM4 => (Reg::Eax, 2),
        TSE => (Reg::Ebx, 1),
        AVX_VNNI_INT16 => (Reg::Edx, 10),
        _ => return None,
    };
    Some(bit_probe(7, 1, reg, bit))
}

fn probe_extended(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    if feature == SKINIT_or_SVM {
        return Some(Probe::Either {
            leaf: 0x8000_0001,
            sub: 0,
            reg: Reg::Ecx,
            a: 2,
            b: 12,
        });
    }
    let (leaf, reg, bit) = match feature {
        X64 => (0x8000_0001, Reg::Edx, 29),
        CLZERO => (0x8000_0008, Reg::Ebx, 0),
        D3NOW => (0x8000_0001, Reg::Edx, 31),
        D3NOWEXT => (0x8000_0001, Reg::Edx, 30),
        FMA4 => (0x8000_0001, Reg::Ecx, 16),
        LWP => (0x8000_0001, Reg::Ecx, 15),
        LZCNT => (0x8000_0001, Reg::Ecx, 5),
        MCOMMIT => (0x8000_0008, Reg::Ebx, 8),
        MONITORX => (0x8000_0001, Reg::Ecx, 29),
        PREFETCHW => (0x8000_0001, Reg::Ecx, 8),
        RDPRU => (0x8000_0008, Reg::Ebx, 4),
        RDTSCP => (0x8000_0001, Reg::Edx, 27),
        SKINIT => (0x8000_0001, Reg::Ecx, 12),
        SSE4A => (0x8000_0001, Reg::Ecx, 6),
        SVM => (0x8000_0001, Reg::Ecx, 2),
        SEV_ES => (0x8000_001f, Reg::Eax, 3),
        SYSCALL => (0x8000_0001, Reg::Edx, 11),
        TBM => (0x8000_0001, Reg::Ecx, 21),
        WBNOINVD => (0x8000_0008, Reg::Ebx, 9),
        XOP => (0x8000_0001, Reg::Ecx, 11),
        SEV_SNP => (0x8000_001f, Reg::Eax, 4),
        INVLPGB => (0x8000_0008, Reg::Ebx, 3),
        RMPQUERY => (0x8000_001f, Reg::Eax, 6),
        _ => return None,
    };
    Some(bit_probe(leaf, 0, reg, bit))
}

fn probe_xsave_sgx_pt_kl(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    let (leaf, sub, reg, bit) = match feature {
        OSS => (0x12, 0, Reg::Eax, 5),
        PTWRITE => (0x14, 0, Reg::Ebx, 4),
        SGX1 => (0x12, 0, Reg::Eax, 0),
        XSAVEC => (0x0d, 1, Reg::Eax, 1),
        XSAVEOPT => (0x0d, 1, Reg::Eax, 0),
        XSAVES => (0x0d, 1, Reg::Eax, 3),
        AESKLE => (0x19, 0, Reg::Ebx, 0),
        WIDE_KL => (0x19, 0, Reg::Ebx, 2),
        _ => return None,
    };
    Some(bit_probe(leaf, sub, reg, bit))
}

fn probe_padlock_cyrix(feature: CpuidFeature) -> Option<Probe> {
    use CpuidFeature::*;
    Some(match feature {
        CYRIX_D3NOW | CYRIX_FPU | CYRIX_SMM | CYRIX_SMINT | CYRIX_SMINT_0F7E | CYRIX_SHR
        | CYRIX_DDI | CYRIX_DMI => Probe::Vendor("CyrixInstead"),
        CYRIX_EMMI => Probe::CyrixEmmi,
        PADLOCK_RNG => Probe::Padlock(2),
        PADLOCK_GMI => Probe::Padlock(4),
        PADLOCK_ACE => Probe::Padlock(6),
        PADLOCK_PHE => Probe::Padlock(10),
        PADLOCK_PMM => Probe::Padlock(12),
        CENTAUR_AIS => Probe::Padlock(0),
        _ => return None,
    })
}

fn bit_set(leaf: u32, sub: u32, reg: Reg, bit: u32) -> bool {
    word(leaf, sub, reg) & (1 << bit) != 0
}

fn word(leaf: u32, sub: u32, reg: Reg) -> u32 {
    let leaves = leaves();
    if !leaf_ok(leaves, leaf, sub) {
        return 0;
    }
    let cached = match (leaf, sub, reg) {
        (1, 0, Reg::Eax) => Some(leaves.one_eax),
        (1, 0, Reg::Ecx) => Some(leaves.one_ecx),
        (1, 0, Reg::Edx) => Some(leaves.one_edx),
        (7, 0, Reg::Ebx) => Some(leaves.seven_ebx),
        (7, 0, Reg::Ecx) => Some(leaves.seven_ecx),
        (7, 0, Reg::Edx) => Some(leaves.seven_edx),
        (7, 1, Reg::Eax) => Some(leaves.seven1_eax),
        (7, 1, Reg::Ebx) => Some(leaves.seven1_ebx),
        (7, 1, Reg::Edx) => Some(leaves.seven1_edx),
        (0x8000_0001, 0, Reg::Ecx) => Some(leaves.ext_ecx),
        (0x8000_0001, 0, Reg::Edx) => Some(leaves.ext_edx),
        (0x8000_0008, 0, Reg::Ebx) => Some(leaves.ext8_ebx),
        (0x0d, 1, Reg::Eax) => Some(leaves.d1_eax),
        (0x12, 0, Reg::Eax) => Some(leaves.leaf12_eax),
        (0x14, 0, Reg::Ebx) => Some(leaves.leaf14_ebx),
        (0x19, 0, Reg::Ebx) => Some(leaves.leaf19_ebx),
        _ => None,
    };
    if let Some(word) = cached {
        return word;
    }
    reg_of(cpuid(leaf, sub), reg)
}

fn leaf_ok(leaves: &Leaves, leaf: u32, sub: u32) -> bool {
    if leaf >= 0x8000_0000 {
        return leaves.ext_max >= leaf;
    }
    if leaves.max_basic < leaf {
        return false;
    }
    if leaf == 7 {
        return sub <= leaves.seven_max;
    }
    true
}

fn padlock(shift: u32) -> bool {
    let leaves = leaves();
    if leaves.centaur_max < 0xC000_0001 {
        return false;
    }
    (leaves.centaur_edx >> shift) & 0b11 == 0b11
}

fn vendor_is(expect: &str) -> bool {
    let vendor = leaves().vendor;
    expect.as_bytes() == vendor
}

fn display_family() -> u32 {
    let eax = leaves().one_eax;
    let base = (eax >> 8) & 0xf;
    if base == 0xf {
        base + ((eax >> 20) & 0xff)
    } else {
        base
    }
}

fn leaves() -> &'static Leaves {
    static LEAVES: OnceLock<Leaves> = OnceLock::new();
    LEAVES.get_or_init(read_leaves)
}

fn read_leaf(max: u32, need: u32, leaf: u32, sub: u32) -> std::arch::x86_64::CpuidResult {
    if max >= need {
        cpuid(leaf, sub)
    } else {
        zero()
    }
}

fn read_leaves() -> Leaves {
    let basic = cpuid(0, 0);
    let one = cpuid(1, 0);
    let ext = cpuid(0x8000_0000, 0);
    let seven = read_leaf(basic.eax, 7, 7, 0);
    // `seven.eax` is the max subleaf. A missing leaf 7 leaves it at zero.
    let seven1 = read_leaf(seven.eax, 1, 7, 1);
    let ext1 = read_leaf(ext.eax, 0x8000_0001, 0x8000_0001, 0);
    let ext8 = read_leaf(ext.eax, 0x8000_0008, 0x8000_0008, 0);
    let d1 = read_leaf(basic.eax, 0x0d, 0x0d, 1);
    let leaf12 = read_leaf(basic.eax, 0x12, 0x12, 0);
    let leaf14 = read_leaf(basic.eax, 0x14, 0x14, 0);
    let leaf19 = read_leaf(basic.eax, 0x19, 0x19, 0);
    let centaur = cpuid(0xC000_0000, 0);
    let centaur1 = read_leaf(centaur.eax, 0xC000_0001, 0xC000_0001, 0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&basic.ecx.to_le_bytes());
    Leaves {
        max_basic: basic.eax,
        one_eax: one.eax,
        one_ecx: one.ecx,
        one_edx: one.edx,
        seven_max: seven.eax,
        seven_ebx: seven.ebx,
        seven_ecx: seven.ecx,
        seven_edx: seven.edx,
        seven1_eax: seven1.eax,
        seven1_ebx: seven1.ebx,
        seven1_edx: seven1.edx,
        ext_max: ext.eax,
        ext_ecx: ext1.ecx,
        ext_edx: ext1.edx,
        ext8_ebx: ext8.ebx,
        d1_eax: d1.eax,
        leaf12_eax: leaf12.eax,
        leaf14_ebx: leaf14.ebx,
        leaf19_ebx: leaf19.ebx,
        centaur_max: centaur.eax,
        centaur_edx: centaur1.edx,
        vendor,
    }
}

fn reg_of(result: std::arch::x86_64::CpuidResult, reg: Reg) -> u32 {
    match reg {
        Reg::Eax => result.eax,
        Reg::Ebx => result.ebx,
        Reg::Ecx => result.ecx,
        Reg::Edx => result.edx,
    }
}

fn zero() -> std::arch::x86_64::CpuidResult {
    std::arch::x86_64::CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    }
}

fn cpuid(leaf: u32, sub: u32) -> std::arch::x86_64::CpuidResult {
    std::arch::x86_64::__cpuid_count(leaf, sub)
}
