//! S8 quality contract for the integer PE core on M-EMU.
//!
//! The detector bar is the code that is actually linked: five S6 detectors and
//! eight S6b detectors. Each one is armed alone and must fail closed. This
//! test does not add protection and does not lower a threshold.

use vmkek::emu::{self, Detector, Policy};
use vmkek::proof::Claim;
use vmkek::protect::{self, Options, Protected};
use vmkek::report::{claims_are_anchored, report_hides_seed, section_difference_percent};
use vmkek::{crypto, pe, proof, sample};

const SEED_A: u64 = 0x5a5a_11ce;
const SEED_B: u64 = 0x11ce_5a5a;
/// Five S6 detectors plus eight S6b detectors. The older roadmap row of five is only S6.
const DETECTOR_COUNT: usize = 13;
const SECTION_GAP_PERCENT: u32 = 25;
const FAIL_CLOSED: u32 = 0xdeb6;

const DETECTORS: &[Detector] = &[
    Detector::BeingDebugged,
    Detector::NtGlobalFlag,
    Detector::IsDebuggerPresent,
    Detector::RemoteDebugger,
    Detector::TickDelta,
    Detector::HardwareDr,
    Detector::DebugPort,
    Detector::DebugObject,
    Detector::ProcessDebugFlags,
    Detector::HeapFlags,
    Detector::Int2d,
    Detector::ProtectedHandle,
    Detector::ParentDebugger,
];

const DETECTOR_PASSES: &[&str] = &[
    "peb-being-debugged",
    "nt-global-flag",
    "is-debugger-present",
    "remote-debugger",
    "tick-delta",
    "hardware-dr",
    "debug-port",
    "debug-object",
    "process-debug-flags",
    "heap-flags",
    "int-2d",
    "protected-handle",
    "parent-debugger",
];

#[test]
fn integer_pe_core_meets_the_quality_contract() {
    let built = sample::build().expect("sample");
    let plain = emu::run_pe(&built.bytes, Policy::default()).expect("unprotected sample");
    let first = protect(&built.bytes, SEED_A);
    let again = protect(&built.bytes, SEED_A);
    let second = protect(&built.bytes, SEED_B);

    assert_eq!(first.bytes, again.bytes, "deterministic protect diverged");
    assert_same_stdout(&first.bytes, &plain.stdout);
    assert_disk_hides(&first.bytes);
    assert_section_gap(&first.bytes, &second.bytes);
    assert_each_detector_fails_closed(&first.bytes, &plain.stdout);
    assert_signature(&first, &second);
    assert!(
        report_hides_seed(&first.report, SEED_A),
        "report stored seed {SEED_A}"
    );
    assert!(claims_are_anchored(&first.report.claims));
    assert_detector_claims(&first.report);
    assert_crypto_claims(&first.report);
    assert_virtual_black_box_is_not_a_pass();
}

fn protect(input: &[u8], seed: u64) -> Protected {
    protect::protect(input, &options(seed)).expect("protect")
}

fn options(seed: u64) -> Options {
    Options {
        virtualize: std::collections::BTreeSet::new(),
        mutate: std::collections::BTreeSet::new(),
        virtualize_all: true,
        mutate_all: false,
        seed,
        random_key: false,
        debug_seed: false,
    }
}

fn assert_same_stdout(protected: &[u8], plain: &[u8]) {
    let ran = emu::run_pe(protected, Policy::default()).expect("protected sample");
    assert_eq!(ran.exit_code, 0, "{}", String::from_utf8_lossy(&ran.stdout));
    assert_eq!(ran.stdout, plain);
}

fn assert_disk_hides(bytes: &[u8]) {
    assert!(bytes
        .windows(b"vmkek-ok:".len())
        .all(|window| window != b"vmkek-ok:"));
    assert!(bytes
        .windows(b"WriteFile".len())
        .all(|window| window != b"WriteFile"));
}

fn assert_section_gap(left: &[u8], right: &[u8]) {
    let percent = section_difference_percent(&vmkek_section(left), &vmkek_section(right));
    assert!(
        percent >= SECTION_GAP_PERCENT,
        "payload section differs by {percent}%, below {SECTION_GAP_PERCENT}%"
    );
}

fn vmkek_section(bytes: &[u8]) -> Vec<u8> {
    pe::parse(bytes)
        .expect("pe")
        .sections
        .into_iter()
        .find(|section| section.bytes.starts_with(crypto::MAGIC))
        .expect("payload section")
        .bytes
}

fn assert_each_detector_fails_closed(bytes: &[u8], plain: &[u8]) {
    assert_eq!(DETECTORS.len(), DETECTOR_COUNT);
    assert_eq!(DETECTOR_PASSES.len(), DETECTOR_COUNT);
    for detector in DETECTORS {
        let name = detector_name(*detector);
        let ran = emu::run_pe(bytes, Policy::arm(*detector)).expect(name);
        assert_ne!(ran.stdout, plain, "{name} printed the sample line");
        assert_eq!(
            ran.exit_code,
            FAIL_CLOSED,
            "{name} exit {:#x}, stdout {}",
            ran.exit_code,
            String::from_utf8_lossy(&ran.stdout)
        );
    }
}

fn assert_signature(first: &Protected, second: &Protected) {
    let pinned = decode_public(&first.report.public_key);
    let header = protect::inspect(&first.bytes, &pinned).expect("signature");
    let at = crypto::find_header(&first.bytes).expect("header");
    let mut tampered = first.bytes.clone();
    let flip = at + header.payload_off as usize + 8;
    tampered[flip] ^= 0xff;
    assert!(protect::inspect(&tampered, &pinned).is_err());
    let foreign = decode_public(&second.report.public_key);
    assert_ne!(foreign, pinned);
    assert!(protect::inspect(&first.bytes, &foreign).is_err());
}

fn assert_detector_claims(report: &vmkek::report::Report) {
    for pass in DETECTOR_PASSES {
        let claim = report
            .claims
            .iter()
            .find(|item| item.pass == *pass)
            .unwrap_or_else(|| panic!("missing claim {pass}"));
        assert_eq!(claim.claim, Claim::Proven, "{pass}");
        assert_eq!(claim.channel, "System", "{pass}");
        assert_eq!(claim.machine, "M-EMU", "{pass}");
        assert!(claim.proof_anchor.is_some_and(|anchor| !anchor.is_empty()));
    }
}

fn assert_crypto_claims(report: &vmkek::report::Report) {
    for pass in ["bytecode-encrypt", "aead-inspect", "ecdsa-p256"] {
        let claim = report
            .claims
            .iter()
            .find(|item| item.pass == pass)
            .unwrap_or_else(|| panic!("missing claim {pass}"));
        assert_eq!(claim.claim, Claim::Proven, "{pass}");
        assert_eq!(claim.channel, "Crypto", "{pass}");
        assert!(claim.proof_anchor.is_some_and(|anchor| !anchor.is_empty()));
    }
}

fn assert_virtual_black_box_is_not_a_pass() {
    let entry = proof::registry()
        .into_iter()
        .find(|item| item.pass == "virtual-black-box")
        .expect("virtual-black-box boundary");
    assert_eq!(entry.claim, Claim::Unreachable);
    assert!(DETECTOR_PASSES.iter().all(|pass| *pass != entry.pass));
}

fn detector_name(detector: Detector) -> &'static str {
    match detector {
        Detector::BeingDebugged => "BeingDebugged",
        Detector::NtGlobalFlag => "NtGlobalFlag",
        Detector::IsDebuggerPresent => "IsDebuggerPresent",
        Detector::RemoteDebugger => "CheckRemoteDebuggerPresent",
        Detector::TickDelta => "tick-delta",
        Detector::HardwareDr => "hardware-dr",
        Detector::DebugPort => "debug-port",
        Detector::DebugObject => "debug-object",
        Detector::ProcessDebugFlags => "process-debug-flags",
        Detector::HeapFlags => "heap-flags",
        Detector::Int2d => "int-2d",
        Detector::ProtectedHandle => "protected-handle",
        Detector::ParentDebugger => "parent-debugger",
        Detector::TrapFlag => "trap-flag",
        Detector::Int3Page => "int3-page",
        Detector::ThreadHide => "thread-hide",
        Detector::KernelDebugger => "kernel-debugger",
        Detector::RemoteBreakin => "remote-breakin",
        Detector::InstrumentationCallback => "instrumentation-callback",
    }
}

fn decode_public(text: &str) -> [u8; 65] {
    assert_eq!(text.len(), 130, "public key hex");
    let mut out = [0u8; 65];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("public key hex");
    }
    out
}
