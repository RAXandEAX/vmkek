//! Group and refusal class for one iced-x86 mnemonic, derived from its encodings.

use iced_x86::{Code, CpuidFeature, FlowControl, Mnemonic};

use super::census::{Group, InstructionClass};

#[derive(Clone, Copy, Default)]
pub(super) struct Signals {
    codes: u32,
    /// Every non-privileged encoding, including ones outside user x86-64.
    user_codes: u32,
    /// Non-privileged encodings that belong to the user x86-64 sets L1–L7 prove.
    /// Knights Corner, IA-64, Cyrix, Centaur AIS, and undocumented PadLock do not vote:
    /// a later `proven` flag covers the whole group.
    x64_codes: u32,
    privileged_codes: u32,
    control_codes: u32,
    exception_codes: u32,
    fpu: bool,
    late: bool,
    sse: bool,
    avx: bool,
    avx512: bool,
    outside_avx_family: bool,
    outside_integer: bool,
    vmx: bool,
    svm: bool,
}

impl Signals {
    pub(super) fn observe(&mut self, code: Code) {
        self.codes += 1;
        let privileged = code.is_privileged();
        if privileged {
            self.privileged_codes += 1;
        } else {
            self.user_codes += 1;
        }
        let votes = !privileged && !encoding_outside_user_x64(code);
        if votes {
            self.record_x64_encoding(code);
        }
        let vector = encoding_has_vector(code);
        for feature in code.cpuid_features() {
            // AES/PCLMUL beside AVX or AVX-512 is that form's CPUID bit, not an L4 mnemonic.
            let companion = votes && vector && is_late(*feature);
            self.note_feature(*feature, votes && !companion);
            if companion {
                self.outside_integer = true;
                self.outside_avx_family = true;
            }
        }
    }

    fn record_x64_encoding(&mut self, code: Code) {
        self.x64_codes += 1;
        self.note_flow(code.flow_control());
        if code.cpuid_features().is_empty() {
            self.outside_integer = true;
            self.outside_avx_family = true;
        }
    }

    pub(super) fn codes(&self) -> u32 {
        self.codes
    }

    pub(super) fn privileged_encodings(&self) -> bool {
        self.privileged_codes > 0
    }

    pub(super) fn only_non_user(&self) -> bool {
        self.codes > 0 && self.user_codes == 0
    }

    fn note_flow(&mut self, flow: FlowControl) {
        match flow {
            FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Return
            | FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Interrupt => self.control_codes += 1,
            FlowControl::Exception => self.exception_codes += 1,
            FlowControl::Next | FlowControl::XbeginXabortXend => {}
        }
    }

    fn note_feature(&mut self, feature: CpuidFeature, user: bool) {
        let mark = feature_mark(feature);
        match mark {
            Mark::Vmx => self.vmx = true,
            Mark::Svm => self.svm = true,
            Mark::Fpu if user => self.fpu = true,
            Mark::Late if user => self.late = true,
            Mark::Sse if user => self.sse = true,
            Mark::Avx if user => self.avx = true,
            Mark::Avx512 if user => self.avx512 = true,
            _ => {}
        }
        if user && mark != Mark::Integer {
            self.outside_integer = true;
        }
        if user && !mark.in_avx_family() {
            self.outside_avx_family = true;
        }
    }
}

pub(super) fn group_from_user(signals: &Signals) -> Group {
    let users = signals.x64_codes;
    if users > 0 && (signals.control_codes == users || signals.exception_codes == users) {
        return Group::L7Control;
    }
    if signals.fpu {
        return Group::L2X87;
    }
    if signals.late {
        return Group::L4LateSse;
    }
    if signals.sse {
        return Group::L3Sse;
    }
    if signals.avx && !signals.outside_avx_family {
        return Group::L5Avx;
    }
    if signals.avx512 {
        return Group::L6Avx512;
    }
    if users > 0 && !signals.outside_integer {
        return Group::L1Integer;
    }
    Group::L8Rest
}

pub(super) fn refuse_class(mnemonic: Mnemonic, signals: &Signals) -> InstructionClass {
    if is_io(mnemonic) {
        InstructionClass::Io
    } else if signals.svm {
        InstructionClass::Svm
    } else if signals.vmx {
        InstructionClass::Vmx
    } else {
        InstructionClass::Privileged
    }
}

pub(super) fn explicit_lift_group(mnemonic: Mnemonic) -> Option<Group> {
    if mnemonic == Mnemonic::Wait {
        return Some(Group::L2X87);
    }
    if matches!(mnemonic, Mnemonic::Endbr32 | Mnemonic::Endbr64) {
        return Some(Group::L7Control);
    }
    if is_system_user(mnemonic) {
        return Some(Group::L8Rest);
    }
    None
}

/// Assembler directives iced-x86 exposes as mnemonics. Not CPU instructions.
pub(super) fn is_declare(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Db | Mnemonic::Dw | Mnemonic::Dd | Mnemonic::Dq
    )
}

/// Exits and CPL 0 instructions iced-x86 does not flag. `VMFUNC` is not a VM-exit.
pub(super) fn forced_refuse(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Vmcall
            | Mnemonic::Vmmcall
            | Mnemonic::Vmgexit
            | Mnemonic::Getsec
            | Mnemonic::Getsecq
    )
}

pub(super) fn is_io(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::In
            | Mnemonic::Insb
            | Mnemonic::Insw
            | Mnemonic::Insd
            | Mnemonic::Out
            | Mnemonic::Outsb
            | Mnemonic::Outsw
            | Mnemonic::Outsd
    )
}

fn is_system_user(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Sgdt
            | Mnemonic::Sidt
            | Mnemonic::Sldt
            | Mnemonic::Str
            | Mnemonic::Smsw
            | Mnemonic::Lar
            | Mnemonic::Lsl
            | Mnemonic::Verr
            | Mnemonic::Verw
            | Mnemonic::Arpl
            | Mnemonic::Lds
            | Mnemonic::Les
            | Mnemonic::Lfs
            | Mnemonic::Lgs
            | Mnemonic::Lss
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Fpu,
    Late,
    Sse,
    Avx,
    Avx512,
    AvxFamilyExtra,
    Integer,
    Vmx,
    Svm,
    Other,
}

impl Mark {
    fn in_avx_family(self) -> bool {
        matches!(self, Mark::Avx | Mark::Avx512 | Mark::AvxFamilyExtra)
    }
}

fn feature_mark(feature: CpuidFeature) -> Mark {
    if is_late(feature) {
        Mark::Late
    } else if is_avx512(feature) {
        Mark::Avx512
    } else if is_integer_feature(feature) {
        Mark::Integer
    } else {
        match feature {
            CpuidFeature::FPU
            | CpuidFeature::FPU287
            | CpuidFeature::FPU287XL_ONLY
            | CpuidFeature::FPU387
            | CpuidFeature::FPU387SL_ONLY => Mark::Fpu,
            CpuidFeature::SSE | CpuidFeature::SSE2 | CpuidFeature::CLFSH => Mark::Sse,
            CpuidFeature::AVX | CpuidFeature::AVX2 => Mark::Avx,
            CpuidFeature::KNC => Mark::AvxFamilyExtra,
            CpuidFeature::VMX
            | CpuidFeature::INVEPT
            | CpuidFeature::INVVPID
            | CpuidFeature::TDX => Mark::Vmx,
            CpuidFeature::SVM
            | CpuidFeature::SKINIT
            | CpuidFeature::SKINIT_or_SVM
            | CpuidFeature::SEV_ES
            | CpuidFeature::SEV_SNP => Mark::Svm,
            _ => Mark::Other,
        }
    }
}

/// iced-x86 still decodes these, but they are not user-mode x86-64.
/// A single such encoding must not place the mnemonic in L1–L7.
fn feature_outside_user_x64(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::IA64
            | CpuidFeature::KNC
            | CpuidFeature::CENTAUR_AIS
            | CpuidFeature::CYRIX_FPU
            | CpuidFeature::CYRIX_D3NOW
            | CpuidFeature::CYRIX_SMM
            | CpuidFeature::CYRIX_SMINT
            | CpuidFeature::CYRIX_SMINT_0F7E
            | CpuidFeature::CYRIX_SHR
            | CpuidFeature::CYRIX_DDI
            | CpuidFeature::CYRIX_EMMI
            | CpuidFeature::CYRIX_DMI
            | CpuidFeature::PADLOCK_UNDOC
    )
}

pub(crate) fn encoding_outside_user_x64(code: Code) -> bool {
    code.cpuid_features()
        .iter()
        .any(|feature| feature_outside_user_x64(*feature))
}

fn encoding_has_vector(code: Code) -> bool {
    code.cpuid_features().iter().any(|feature| {
        matches!(feature, CpuidFeature::AVX | CpuidFeature::AVX2) || is_avx512(*feature)
    })
}

/// SSE3–FMA from the L4 stage, plus same-era features the census already groups here.
/// `VAES` and `VPCLMULQDQ` are vector forms, so they stay out of this predicate.
fn is_late(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::SSE3
            | CpuidFeature::SSSE3
            | CpuidFeature::SSE4_1
            | CpuidFeature::SSE4_2
            | CpuidFeature::SSE4A
            | CpuidFeature::POPCNT
            | CpuidFeature::PCLMULQDQ
            | CpuidFeature::AES
            | CpuidFeature::SHA
            | CpuidFeature::BMI1
            | CpuidFeature::BMI2
            | CpuidFeature::ADX
            | CpuidFeature::FMA
            | CpuidFeature::FMA4
            | CpuidFeature::F16C
            | CpuidFeature::LZCNT
            | CpuidFeature::MOVBE
            | CpuidFeature::RDRAND
            | CpuidFeature::RDSEED
            | CpuidFeature::FSGSBASE
            | CpuidFeature::TBM
    )
}

fn is_avx512(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::AVX512_4FMAPS
            | CpuidFeature::AVX512_4VNNIW
            | CpuidFeature::AVX512_BF16
            | CpuidFeature::AVX512_BITALG
            | CpuidFeature::AVX512_IFMA
            | CpuidFeature::AVX512_VBMI
            | CpuidFeature::AVX512_VBMI2
            | CpuidFeature::AVX512_VNNI
            | CpuidFeature::AVX512_VP2INTERSECT
            | CpuidFeature::AVX512_VPOPCNTDQ
            | CpuidFeature::AVX512BW
            | CpuidFeature::AVX512CD
            | CpuidFeature::AVX512DQ
            | CpuidFeature::AVX512ER
            | CpuidFeature::AVX512F
            | CpuidFeature::AVX512PF
            | CpuidFeature::AVX512VL
            | CpuidFeature::AVX512_FP16
    )
}

fn is_integer_feature(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::INTEL8086
            | CpuidFeature::INTEL8086_ONLY
            | CpuidFeature::INTEL186
            | CpuidFeature::INTEL286
            | CpuidFeature::INTEL286_ONLY
            | CpuidFeature::INTEL386
            | CpuidFeature::INTEL386_ONLY
            | CpuidFeature::INTEL386_A0_ONLY
            | CpuidFeature::INTEL486
            | CpuidFeature::INTEL486_A_ONLY
            | CpuidFeature::UMOV
            | CpuidFeature::X64
            | CpuidFeature::CMOV
            | CpuidFeature::CX8
            | CpuidFeature::CMPXCHG16B
            | CpuidFeature::PAUSE
            | CpuidFeature::MULTIBYTENOP
    )
}
