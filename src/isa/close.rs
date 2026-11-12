//! L8 inventory close. A user mnemonic stays `proven: false` only when every
//! encoding that could still be a user instruction needs a CPUID feature this
//! process does not advertise. M-LINUX is the only registered CPU, so that
//! feature is absent on every registered machine.

use std::collections::BTreeSet;

use iced_x86::{Code, CpuidFeature, Mnemonic};

use super::class::encoding_outside_user_x64;
use super::cpuid_host::host_has;

/// `true` when this process's CPUID advertises `feature`.
#[must_use]
pub fn cpu_has(feature: CpuidFeature) -> bool {
    host_has(feature)
}

/// Encodings that decide the inventory bit.
///
/// Long-mode user encodings that belong to x86-64 come first. A mnemonic whose
/// only leftovers are outside that set (Knights Corner, IA-64, Cyrix, Centaur,
/// undocumented PadLock) is judged on those leftovers. No encoding means the
/// mnemonic is not in long mode.
#[must_use]
pub fn proving_codes(mnemonic: Mnemonic) -> Vec<Code> {
    let mut primary = Vec::new();
    let mut foreign = Vec::new();
    for code in Code::values() {
        if code == Code::INVALID || code.mnemonic() != mnemonic || code.is_privileged() {
            continue;
        }
        if encoding_outside_user_x64(code) {
            foreign.push(code);
            continue;
        }
        if code.op_code().is_available_in_mode(64) {
            primary.push(code);
        }
    }
    if primary.is_empty() {
        foreign
    } else {
        primary
    }
}

/// `true` when every [`proving_codes`] encoding requires a CPUID feature that
/// is absent here. An empty encoding list is not such a hold.
#[must_use]
pub fn held_by_absent_cpuid(mnemonic: Mnemonic) -> bool {
    let codes = proving_codes(mnemonic);
    !codes.is_empty() && codes.iter().copied().all(encoding_needs_absent_cpuid)
}

/// CPUID features that keep `mnemonic` unproven, when [`held_by_absent_cpuid`].
#[must_use]
pub fn missing_features(mnemonic: Mnemonic) -> Vec<CpuidFeature> {
    if !held_by_absent_cpuid(mnemonic) {
        return Vec::new();
    }
    let mut missing = BTreeSet::new();
    for code in proving_codes(mnemonic) {
        for feature in code.cpuid_features() {
            if !host_has(*feature) {
                missing.insert(*feature);
            }
        }
    }
    missing.into_iter().collect()
}

fn encoding_needs_absent_cpuid(code: Code) -> bool {
    let features = code.cpuid_features();
    !features.is_empty() && features.iter().any(|feature| !host_has(*feature))
}
