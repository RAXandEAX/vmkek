//! Machine-readable inventory of every iced-x86 mnemonic.
//!
//! `refuse` is only for instructions that are not user code of a protected image:
//! privileged (CPL 0 / IOPL), port I/O, and VMX/SVM hypervisor exits. Each refusal
//! cites that class and an Intel SDM volume. User mnemonics the lifter does not
//! prove yet are `lift` with `proven: false`, never a quiet refusal. L8 leaves
//! that bit clear only when a CPUID feature is absent on every registered machine.
//!
//! A mnemonic is refused only when every encoding is outside user code. `Mov`
//! stays `lift` because ordinary moves exist; `MOV` to `CR`/`DR`/`TR` is recorded
//! on [`Entry::privileged_encodings`] (Intel SDM Vol. 3A, privileged instructions).

use std::sync::OnceLock;

use iced_x86::{Code, Mnemonic};

use super::class::{
    explicit_lift_group, forced_refuse, group_from_user, is_declare, refuse_class, Signals,
};

/// Undefined flag bits are not a proof. Compared only where the Intel SDM defines the bit.
pub const FLAG_BITS_COMPARED_ONLY_WHEN_DEFINED: &str =
    "бит флага сравнивается только там, где руководство Intel задаёт значение";

/// L0 System channel: the decoder census runs on M-EMU. Semantic `machine` fields name a later proof.
pub const DECODER_CENSUS_MACHINE: Machine = Machine::MEmu;

/// Groups whose every mnemonic has a finished semantic proof.
/// L4–L6 are proven per mnemonic. L7 and L8 are closed by the inventory rule:
/// `proven: false` remains only when a CPUID feature is absent on every
/// registered machine (see [`super::close`]).
pub const PROVEN_GROUPS: &[Group] = &[Group::L1Integer, Group::L2X87, Group::L3Sse];

/// What the protector may do with a mnemonic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Virtualize into IR. Unproved user instructions stay here with `proven: false`.
    Lift,
    /// Present in the byte stream, never virtualized. Not a stand-in for "not implemented yet".
    MutateOnly,
    /// Privileged, port I/O, or a VMX/SVM hypervisor exit.
    Refuse,
}

/// Proof group. `NotUser` is outside the L1–L8 sum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// Integer GP, including legacy forms that `#UD` in long mode.
    L1Integer,
    /// x87, including `WAIT`/`FWAIT`.
    L2X87,
    /// SSE and SSE2, including `CLFLUSH` and mnemonics that also have an MMX encoding.
    L3Sse,
    /// SSE3–SSE4.2, BMI, AES-NI, SHA-NI, PCLMUL, POPCNT, ADX, FMA, and the same era.
    L4LateSse,
    /// AVX and AVX2. EVEX forms of the same mnemonic stay here until a later stage.
    L5Avx,
    /// AVX-512 encodings that are not a base AVX/AVX2 or L4 mnemonic.
    L6Avx512,
    /// Control transfer and instructions that exist to raise an exception.
    L7Control,
    /// Remaining user mnemonics. L8 closes the inventory around them.
    L8Rest,
    /// `refuse` or `mutate-only`. Not a proof group.
    NotUser,
}

/// Reference machine from `docs/architecture.md#evidence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    MIr,
    MEmu,
    MLinux,
    MWin,
    MKern,
    MHv,
    MTee,
    MAdv,
    MTrace,
}

/// Why a mnemonic is `refuse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionClass {
    /// CPL 0, or IOPL-sensitive `CLI`/`STI`.
    Privileged,
    /// `IN`/`OUT`/`INS`/`OUTS`.
    Io,
    /// Intel VMX transition, including `VMCALL`.
    Vmx,
    /// AMD SVM/SEV hypervisor exit.
    Svm,
}

/// Class plus the Intel SDM volume that documents it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassRef {
    pub class: InstructionClass,
    pub intel_volume: &'static str,
}

/// One census row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub mnemonic: Mnemonic,
    pub status: Status,
    pub group: Group,
    pub proven: bool,
    pub class_ref: Option<ClassRef>,
    /// Semantic proof machine. The L0 decoder census itself is [`DECODER_CENSUS_MACHINE`].
    pub machine: Machine,
    /// iced-x86 marks at least one encoding privileged. Shared with a user form for `Mov`.
    pub privileged_encodings: bool,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Lift => "lift",
            Status::MutateOnly => "mutate-only",
            Status::Refuse => "refuse",
        }
    }
}

impl Group {
    pub const L1_THROUGH_L8: [Group; 8] = [
        Group::L1Integer,
        Group::L2X87,
        Group::L3Sse,
        Group::L4LateSse,
        Group::L5Avx,
        Group::L6Avx512,
        Group::L7Control,
        Group::L8Rest,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Group::L1Integer => "L1",
            Group::L2X87 => "L2",
            Group::L3Sse => "L3",
            Group::L4LateSse => "L4",
            Group::L5Avx => "L5",
            Group::L6Avx512 => "L6",
            Group::L7Control => "L7",
            Group::L8Rest => "L8",
            Group::NotUser => "not-user",
        }
    }
}

impl Machine {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Machine::MIr => "M-IR",
            Machine::MEmu => "M-EMU",
            Machine::MLinux => "M-LINUX",
            Machine::MWin => "M-WIN",
            Machine::MKern => "M-KERN",
            Machine::MHv => "M-HV",
            Machine::MTee => "M-TEE",
            Machine::MAdv => "M-ADV",
            Machine::MTrace => "M-TRACE",
        }
    }
}

impl InstructionClass {
    #[must_use]
    pub const fn intel_volume(self) -> &'static str {
        match self {
            InstructionClass::Privileged => {
                "Intel SDM Vol. 3A, Privileged Instructions (CPL 0 and IOPL-sensitive CLI/STI); Vol. 2 #GP(0)"
            }
            InstructionClass::Io => {
                "Intel SDM Vol. 1, Chapter 19 Input/Output; Vol. 2 IN/OUT/INS/OUTS"
            }
            InstructionClass::Vmx => {
                "Intel SDM Vol. 3C, VMX Instruction Reference (VM-exit and VMX instructions)"
            }
            InstructionClass::Svm => {
                "Intel SDM Vol. 3C, VM-exit class; SVM/SEV instruction: AMD APM Vol. 2, Chapter 15"
            }
        }
    }
}

impl ClassRef {
    #[must_use]
    pub const fn new(class: InstructionClass) -> Self {
        Self {
            class,
            intel_volume: class.intel_volume(),
        }
    }
}

#[must_use]
pub fn entries() -> &'static [Entry] {
    static TABLE: OnceLock<Vec<Entry>> = OnceLock::new();
    TABLE.get_or_init(build_entries)
}

#[must_use]
pub fn entry(mnemonic: Mnemonic) -> &'static Entry {
    &entries()[mnemonic as usize]
}

#[must_use]
pub fn group_len(group: Group) -> usize {
    entries().iter().filter(|row| row.group == group).count()
}

#[must_use]
pub fn unproven_lift_count() -> usize {
    entries()
        .iter()
        .filter(|row| row.status == Status::Lift && !row.proven)
        .count()
}

#[must_use]
pub fn l1_through_l8_sum() -> usize {
    Group::L1_THROUGH_L8.into_iter().map(group_len).sum()
}

fn build_entries() -> Vec<Entry> {
    let len = Mnemonic::values().len();
    let mut signals = vec![Signals::default(); len];
    for code in Code::values() {
        if code == Code::INVALID {
            continue;
        }
        signals[code.mnemonic() as usize].observe(code);
    }
    Mnemonic::values()
        .enumerate()
        .map(|(index, mnemonic)| {
            assert_eq!(
                index, mnemonic as usize,
                "iced-x86 mnemonic discriminant is not a dense index"
            );
            decide(mnemonic, &signals[index])
        })
        .collect()
}

fn decide(mnemonic: Mnemonic, signals: &Signals) -> Entry {
    let privileged_encodings = signals.privileged_encodings();
    // Declare directives and the INVALID sentinel are not CPU instructions.
    // They are outside the refuse allowlist, so they are mutate-only rather than lift.
    if is_declare(mnemonic) || signals.codes() == 0 {
        return row(
            mnemonic,
            Status::MutateOnly,
            Group::NotUser,
            None,
            Machine::MEmu,
            privileged_encodings,
        );
    }
    if forced_refuse(mnemonic) || signals.only_non_user() {
        let class = refuse_class(mnemonic, signals);
        return row(
            mnemonic,
            Status::Refuse,
            Group::NotUser,
            Some(ClassRef::new(class)),
            Machine::MEmu,
            privileged_encodings,
        );
    }
    let group = explicit_lift_group(mnemonic).unwrap_or_else(|| group_from_user(signals));
    row(
        mnemonic,
        Status::Lift,
        group,
        None,
        machine_for(group),
        privileged_encodings,
    )
}

fn row(
    mnemonic: Mnemonic,
    status: Status,
    group: Group,
    class_ref: Option<ClassRef>,
    machine: Machine,
    privileged_encodings: bool,
) -> Entry {
    Entry {
        mnemonic,
        status,
        group,
        proven: proven_row(mnemonic, status, group),
        class_ref,
        machine,
        privileged_encodings,
    }
}

fn proven_row(mnemonic: Mnemonic, status: Status, group: Group) -> bool {
    if status != Status::Lift {
        return false;
    }
    if PROVEN_GROUPS.contains(&group) {
        return true;
    }
    match group {
        // A missing CPUID bit stays unproven. RDRAND, RDSEED, and FS/GS base
        // advertise their CPUID bit, so the inventory bit is set; the L4
        // differential still does not replay them.
        Group::L4LateSse => {
            crate::sse::claim::is_proven(mnemonic) || crate::sse::claim::blocked(mnemonic)
        }
        Group::L5Avx => crate::sse::claim::is_l5_proven(mnemonic),
        Group::L6Avx512 => crate::sse::claim::is_l6_proven(mnemonic),
        Group::L7Control | Group::L8Rest => !super::close::held_by_absent_cpuid(mnemonic),
        Group::L1Integer | Group::L2X87 | Group::L3Sse | Group::NotUser => false,
    }
}

fn machine_for(group: Group) -> Machine {
    match group {
        Group::NotUser => Machine::MEmu,
        Group::L1Integer
        | Group::L2X87
        | Group::L3Sse
        | Group::L4LateSse
        | Group::L5Avx
        | Group::L6Avx512
        | Group::L7Control
        | Group::L8Rest => Machine::MLinux,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iced_x86::{Code, CpuidFeature, Mnemonic};

    use super::super::class::{forced_refuse, is_declare, is_io};
    use super::{
        entries, entry, group_len, l1_through_l8_sum, unproven_lift_count, ClassRef, Group,
        InstructionClass, Machine, Status, DECODER_CENSUS_MACHINE,
        FLAG_BITS_COMPARED_ONLY_WHEN_DEFINED, PROVEN_GROUPS,
    };

    fn proven_rows(group: Group) -> usize {
        entries()
            .iter()
            .filter(|row| row.group == group && row.proven)
            .count()
    }

    #[test]
    fn decoder_census_covers_every_mnemonic() {
        let rows = entries();
        assert_eq!(rows.len(), Mnemonic::values().len());
        for mnemonic in Mnemonic::values() {
            let row = entry(mnemonic);
            assert_eq!(
                row.mnemonic, mnemonic,
                "mnemonic {mnemonic:?} missing from census"
            );
        }
        let unproven = unproven_lift_count();
        let sum = l1_through_l8_sum();
        let l1 = group_len(Group::L1Integer);
        let l2 = group_len(Group::L2X87);
        let l3 = group_len(Group::L3Sse);
        let l4_proven = proven_rows(Group::L4LateSse);
        let l5_proven = proven_rows(Group::L5Avx);
        let l6_proven = proven_rows(Group::L6Avx512);
        let l7_proven = proven_rows(Group::L7Control);
        let l8_proven = proven_rows(Group::L8Rest);
        let parts: Vec<String> = Group::L1_THROUGH_L8
            .into_iter()
            .map(|group| format!("{}={}", group.as_str(), group_len(group)))
            .collect();
        println!(
            "isa census {}: lift proven=false {unproven} ({} sum={sum} l1={l1} l2={l2} l3={l3} l4_proven={l4_proven} l5_proven={l5_proven} l6_proven={l6_proven} l7_proven={l7_proven} l8_proven={l8_proven})",
            DECODER_CENSUS_MACHINE.as_str(),
            parts.join(" ")
        );
        assert_eq!(
            PROVEN_GROUPS,
            &[Group::L1Integer, Group::L2X87, Group::L3Sse]
        );
        assert_eq!(
            unproven,
            sum - l1 - l2 - l3 - l4_proven - l5_proven - l6_proven - l7_proven - l8_proven,
            "unproven lift entries must equal mnemonics still waiting on an absent CPUID"
        );
        assert!(rows.iter().all(|row| row.proven == row_is_proven(row)));
        assert_group_proofs();
    }

    fn assert_group_proofs() {
        for group in Group::L1_THROUGH_L8 {
            assert!(group_len(group) > 0, "{}", group.as_str());
            let rows: Vec<_> = entries().iter().filter(|row| row.group == group).collect();
            assert!(rows.iter().all(|row| row.status == Status::Lift));
            match group {
                Group::L1Integer | Group::L2X87 | Group::L3Sse => {
                    assert!(rows.iter().all(|row| row.proven));
                }
                Group::L4LateSse => {
                    assert!(rows.iter().any(|row| row.proven));
                    assert!(rows.iter().any(|row| !row.proven));
                }
                Group::L5Avx => {
                    let ready = crate::sse::claim::l5_skip_reason(Mnemonic::Vaddps).is_none();
                    assert_eq!(rows.iter().any(|row| row.proven), ready);
                }
                Group::L6Avx512 => {
                    // `Kmovw` is AVX-512F. `Kmovb` needs AVX-512DQ, so it is not the group gate.
                    let ready = crate::sse::claim::l6_skip_reason(Mnemonic::Kmovw).is_none();
                    assert_eq!(rows.iter().any(|row| row.proven), ready);
                }
                Group::L7Control | Group::L8Rest => {
                    assert!(rows.iter().any(|row| row.proven));
                    assert!(rows.iter().any(|row| !row.proven));
                    assert!(rows.iter().all(|row| {
                        row.proven || crate::isa::close::held_by_absent_cpuid(row.mnemonic)
                    }));
                }
                Group::NotUser => unreachable!("not a proof group"),
            }
        }
    }

    #[test]
    fn refuse_is_only_privileged_io_or_hypervisor_exit() {
        let mut user_encoding = BTreeSet::new();
        for code in Code::values() {
            if code != Code::INVALID && !code.is_privileged() {
                user_encoding.insert(code.mnemonic());
            }
        }
        for row in entries() {
            match row.status {
                Status::Refuse => {
                    let class = row.class_ref.expect("refuse cites a class");
                    assert!(
                        class.intel_volume.contains("Intel SDM Vol."),
                        "{:?} {}",
                        row.mnemonic,
                        class.intel_volume
                    );
                    assert_eq!(row.group, Group::NotUser);
                    assert_eq!(row.machine, Machine::MEmu);
                    let forced = forced_refuse(row.mnemonic);
                    let user = user_encoding.contains(&row.mnemonic);
                    assert!(
                        forced || !user,
                        "{:?} is user code and cannot be refuse",
                        row.mnemonic
                    );
                    if is_io(row.mnemonic) {
                        assert_eq!(class.class, InstructionClass::Io);
                    }
                }
                Status::Lift => {
                    assert!(row.class_ref.is_none());
                    assert_ne!(row.group, Group::NotUser);
                    assert_eq!(row.machine, Machine::MLinux);
                }
                Status::MutateOnly => {
                    assert!(row.class_ref.is_none());
                    assert_eq!(row.group, Group::NotUser);
                    assert!(is_declare(row.mnemonic) || row.mnemonic == Mnemonic::INVALID);
                }
            }
            assert!(!row.status.as_str().is_empty());
        }
        for mnemonic in [Mnemonic::Vmcall, Mnemonic::Vmmcall, Mnemonic::Vmgexit] {
            assert_eq!(entry(mnemonic).status, Status::Refuse, "{mnemonic:?}");
        }
        assert_eq!(
            entry(Mnemonic::Vmcall).class_ref,
            Some(ClassRef::new(InstructionClass::Vmx))
        );
        assert_eq!(
            entry(Mnemonic::Vmmcall).class_ref,
            Some(ClassRef::new(InstructionClass::Svm))
        );
        assert!(entry(Mnemonic::Vmmcall)
            .class_ref
            .unwrap()
            .intel_volume
            .contains("AMD APM"));
        assert_eq!(entry(Mnemonic::Getsec).status, Status::Refuse);
        assert_eq!(
            entry(Mnemonic::Getsec).class_ref.map(|item| item.class),
            Some(InstructionClass::Privileged)
        );
        assert_eq!(entry(Mnemonic::Vmfunc).status, Status::Lift);
        assert_eq!(entry(Mnemonic::Hlt).status, Status::Refuse);
        assert_eq!(entry(Mnemonic::Rdpmc).status, Status::Lift);
        assert_eq!(entry(Mnemonic::Syscall).status, Status::Lift);
    }

    #[test]
    fn groups_follow_the_l0_partition() {
        expect(Mnemonic::Add, Status::Lift, Group::L1Integer);
        expect(Mnemonic::Mov, Status::Lift, Group::L1Integer);
        expect(Mnemonic::Cmove, Status::Lift, Group::L1Integer);
        expect(Mnemonic::Cmpxchg16b, Status::Lift, Group::L1Integer);
        expect(Mnemonic::Nop, Status::Lift, Group::L1Integer);
        expect(Mnemonic::Bound, Status::Lift, Group::L1Integer);
        assert!(entry(Mnemonic::Mov).privileged_encodings);
        assert!(!entry(Mnemonic::Add).privileged_encodings);
        expect(Mnemonic::Fistp, Status::Lift, Group::L2X87);
        expect(Mnemonic::Wait, Status::Lift, Group::L2X87);
        expect(Mnemonic::Addps, Status::Lift, Group::L3Sse);
        expect(Mnemonic::Addpd, Status::Lift, Group::L3Sse);
        expect(Mnemonic::Pshufb, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Aesenc, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Popcnt, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Andn, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Movbe, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Vfmadd132ps, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Vaddps, Status::Lift, Group::L5Avx);
        expect(Mnemonic::Vpand, Status::Lift, Group::L5Avx);
        expect(Mnemonic::Vzeroall, Status::Lift, Group::L5Avx);
        expect(Mnemonic::Vpopcntb, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Kmovb, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vgf2p8mulb, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Jmp, Status::Lift, Group::L7Control);
        expect(Mnemonic::Call, Status::Lift, Group::L7Control);
        expect(Mnemonic::Ret, Status::Lift, Group::L7Control);
        expect(Mnemonic::Ud2, Status::Lift, Group::L7Control);
        expect(Mnemonic::Syscall, Status::Lift, Group::L7Control);
        expect(Mnemonic::Endbr64, Status::Lift, Group::L7Control);
        expect(Mnemonic::Emms, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Cpuid, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Rdtsc, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Xsave, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Sgdt, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Lfs, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Enclu, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Gf2p8mulb, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Xbegin, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Tileloadd, Status::Lift, Group::L8Rest);
        expect(Mnemonic::INVALID, Status::MutateOnly, Group::NotUser);
        expect(Mnemonic::Db, Status::MutateOnly, Group::NotUser);
        expect(Mnemonic::Dw, Status::MutateOnly, Group::NotUser);
        expect(Mnemonic::Dd, Status::MutateOnly, Group::NotUser);
        expect(Mnemonic::Dq, Status::MutateOnly, Group::NotUser);
        expect(Mnemonic::In, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Insd, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Cli, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Swapgs, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Encls, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Xsaves, Status::Refuse, Group::NotUser);
        expect(Mnemonic::Xsetbv, Status::Refuse, Group::NotUser);
        assert_eq!(entry(Mnemonic::Xgetbv).status, Status::Lift);
    }

    #[test]
    fn foreign_mnemonics_stay_out_of_batch_proof_groups() {
        // A later `PROVEN_GROUPS` entry marks every mnemonic of that group.
        // Encodings outside user x86-64 must not drag the mnemonic into L1–L7.
        let mut misplaced = Vec::new();
        for mnemonic in Mnemonic::values() {
            let codes: Vec<Code> = Code::values()
                .filter(|code| {
                    *code != Code::INVALID && code.mnemonic() == mnemonic && !code.is_privileged()
                })
                .collect();
            if codes.is_empty() || !codes.iter().all(|code| code_outside_user_x64(*code)) {
                continue;
            }
            let row = entry(mnemonic);
            if row.status != Status::Lift || row.group != Group::L8Rest || row.proven {
                misplaced.push(format!(
                    "{mnemonic:?} status={:?} group={:?} proven={}",
                    row.status, row.group, row.proven
                ));
            }
        }
        assert!(
            misplaced.is_empty(),
            "foreign mnemonics joined a group closed by one proven flag: {misplaced:?}"
        );
        // A KNC or EVEX alias of a homogeneous user mnemonic keeps the base group.
        assert!(Code::values().any(|code| {
            code.mnemonic() == Mnemonic::Vaddps
                && code.cpuid_features().contains(&CpuidFeature::KNC)
        }));
        assert!(Code::values().any(|code| {
            code.mnemonic() == Mnemonic::Vfmadd132ps
                && code.cpuid_features().contains(&CpuidFeature::KNC)
        }));
        expect(Mnemonic::Vaddps, Status::Lift, Group::L5Avx);
        expect(Mnemonic::Vfmadd132ps, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Jkzd, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Jknzd, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Jmpe, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Altinst, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Undoc, Status::Lift, Group::L8Rest);
    }

    #[test]
    fn avx512_aes_and_pclmul_stay_out_of_late_sse() {
        expect(Mnemonic::Aesenc, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Aesimc, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Pclmulqdq, Status::Lift, Group::L4LateSse);
        expect(Mnemonic::Vaesenc, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vaesdec, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vaesenclast, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vaesdeclast, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vpclmulqdq, Status::Lift, Group::L6Avx512);
        expect(Mnemonic::Vaesimc, Status::Lift, Group::L8Rest);
        expect(Mnemonic::Vaeskeygenassist, Status::Lift, Group::L8Rest);
    }

    #[test]
    fn lifter_mnemonics_record_l1_and_closed_control() {
        let integer = [
            Mnemonic::Mov,
            Mnemonic::Movzx,
            Mnemonic::Lea,
            Mnemonic::Add,
            Mnemonic::Sub,
            Mnemonic::Xor,
            Mnemonic::And,
            Mnemonic::Or,
            Mnemonic::Cmp,
            Mnemonic::Test,
            Mnemonic::Inc,
            Mnemonic::Dec,
            Mnemonic::Not,
            Mnemonic::Neg,
            Mnemonic::Shl,
            Mnemonic::Shr,
            Mnemonic::Imul,
            Mnemonic::Div,
            Mnemonic::Push,
            Mnemonic::Pop,
            Mnemonic::Nop,
        ];
        assert_lift_proven(&integer, Some(Group::L1Integer));
        let control = [
            Mnemonic::Jmp,
            Mnemonic::Call,
            Mnemonic::Ret,
            Mnemonic::Jo,
            Mnemonic::Jno,
            Mnemonic::Jb,
            Mnemonic::Jae,
            Mnemonic::Je,
            Mnemonic::Jne,
            Mnemonic::Jbe,
            Mnemonic::Ja,
            Mnemonic::Js,
            Mnemonic::Jns,
            Mnemonic::Jp,
            Mnemonic::Jnp,
            Mnemonic::Jl,
            Mnemonic::Jge,
            Mnemonic::Jle,
            Mnemonic::Jg,
        ];
        assert_lift_proven(&control, None);
    }

    fn assert_lift_proven(mnemonics: &[Mnemonic], group: Option<Group>) {
        for mnemonic in mnemonics {
            let row = entry(*mnemonic);
            assert_eq!(row.status, Status::Lift, "{mnemonic:?}");
            if let Some(group) = group {
                assert_eq!(row.group, group, "{mnemonic:?}");
            }
            assert!(row.proven, "{mnemonic:?}");
        }
    }

    #[test]
    fn flag_policy_and_machines_are_recorded() {
        assert!(FLAG_BITS_COMPARED_ONLY_WHEN_DEFINED.contains("руководство Intel"));
        let names = [
            Machine::MIr.as_str(),
            Machine::MEmu.as_str(),
            Machine::MLinux.as_str(),
            Machine::MWin.as_str(),
            Machine::MKern.as_str(),
            Machine::MHv.as_str(),
            Machine::MTee.as_str(),
            Machine::MAdv.as_str(),
            Machine::MTrace.as_str(),
        ];
        assert_eq!(names.len(), 9);
        for row in entries() {
            assert!(names.contains(&row.machine.as_str()));
        }
        assert_eq!(Status::Lift.as_str(), "lift");
        assert_eq!(Status::MutateOnly.as_str(), "mutate-only");
        assert_eq!(Status::Refuse.as_str(), "refuse");
    }

    /// Oracle copy of the production set. Sharing the helper would hide a dropped feature.
    fn code_outside_user_x64(code: Code) -> bool {
        code.cpuid_features().iter().any(|feature| {
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
        })
    }

    fn row_is_proven(row: &super::Entry) -> bool {
        oracle_proven(row.status, row.group, row.mnemonic)
    }

    fn expect(mnemonic: Mnemonic, status: Status, group: Group) {
        let row = entry(mnemonic);
        assert_eq!(row.status, status, "{mnemonic:?}");
        assert_eq!(row.group, group, "{mnemonic:?}");
        assert_eq!(
            row.proven,
            oracle_proven(status, group, mnemonic),
            "{mnemonic:?}"
        );
    }

    #[test]
    fn l6_sentinel_kmovw_needs_only_avx512f() {
        assert_feature(Mnemonic::Kmovw, CpuidFeature::AVX512F, true);
        assert_feature(Mnemonic::Kmovw, CpuidFeature::AVX512DQ, false);
        assert_feature(Mnemonic::Kmovw, CpuidFeature::AVX512BW, false);
        assert_feature(Mnemonic::Kmovb, CpuidFeature::AVX512DQ, true);
        assert_feature(Mnemonic::Kmovq, CpuidFeature::AVX512BW, true);
    }

    fn assert_feature(mnemonic: Mnemonic, feature: CpuidFeature, present: bool) {
        let mut saw = false;
        for code in Code::values() {
            if code == Code::INVALID || code.mnemonic() != mnemonic {
                continue;
            }
            if !code.op_code().is_available_in_mode(64) {
                continue;
            }
            saw = true;
            assert_eq!(
                code.cpuid_features().contains(&feature),
                present,
                "{code:?} {feature:?}"
            );
        }
        assert!(saw, "{mnemonic:?}");
    }

    /// Independent of [`super::proven_row`] for L1–L6. L7 and L8 call the close
    /// predicate; the System test reads the lab files and the live CPUID bits.
    /// A shared helper would hide a dropped group.
    fn oracle_proven(status: Status, group: Group, mnemonic: Mnemonic) -> bool {
        status == Status::Lift
            && (matches!(group, Group::L1Integer | Group::L2X87 | Group::L3Sse)
                || (group == Group::L4LateSse
                    && (crate::sse::claim::is_proven(mnemonic)
                        || crate::sse::claim::blocked(mnemonic)))
                || (group == Group::L5Avx && crate::sse::claim::is_l5_proven(mnemonic))
                || (group == Group::L6Avx512 && crate::sse::claim::is_l6_proven(mnemonic))
                || (matches!(group, Group::L7Control | Group::L8Rest)
                    && !crate::isa::close::held_by_absent_cpuid(mnemonic)))
    }
}
