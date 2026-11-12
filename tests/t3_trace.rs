//! T3 on channel System, machine M-EMU.
//!
//! Between two native calls the guest holds neither the address returned by
//! the previous resolve nor the cleartext sample literal. The name-hash key
//! is not stored in the clear in the file. Volatile registers are scrubbed
//! after the call returns.

use vmkek::crypto::{self, HEADER_LEN};
use vmkek::emu::{self, Policy};
use vmkek::loader;
use vmkek::pe::{self, IMAGE_BASE};
use vmkek::proof::{self, Claim};
use vmkek::protect::{self, Options, Protected};
use vmkek::sample;
use vmkek::trace;

const NTDLL_BASE: u64 = 0x1_7FF0_0000;
const K32_EXPORTS: usize = 11;
const NTDLL_EXPORTS: usize = 4;

#[test]
fn between_calls_snapshot_is_clean() {
    let built = sample::build().expect("sample");
    let protected = protect::protect(&built.bytes, &opts(0x73_0001)).expect("protect");
    assert_api_names_absent(&built.bytes, &protected.bytes);
    let image = pe::parse(&protected.bytes).expect("protected pe");
    let mut machine = emu::load(&image, Policy::default()).expect("load");
    let phase_at = IMAGE_BASE + u64::from(sample::PHASE_RVA);
    let reached = drive_to(&mut machine, phase_at, 1);
    assert!(
        reached,
        "phase 1 exit {:?} rip {:#x} stdout {} phase {}",
        machine.exit_code,
        machine.rip,
        String::from_utf8_lossy(&machine.stdout),
        phase_byte(&machine, phase_at)
    );
    assert_snapshot_clean(&machine);
    assert!(drive_to(&mut machine, phase_at, 2), "phase 2");
    assert_snapshot_clean(&machine);
    machine.run().expect("finish");
    assert_eq!(machine.exit_code, Some(0));
    assert_eq!(machine.stdout, sample::line().into_bytes());
    assert_call_trace(&protected.report);
}

#[test]
fn name_hash_key_is_absent_from_the_file() {
    let seed = 0x73_0002u64;
    let built = sample::build().expect("sample");
    let protected = protect::protect(&built.bytes, &opts(seed)).expect("protect");
    let key = trace::name_key(seed).expect("name key");
    assert!(protected
        .bytes
        .windows(key.len())
        .all(|window| window != key));
    let plain = opened_payload(&protected);
    assert_eq!(&plain[..trace::NAME_KEY_LEN], &key);
    let (aead, _) = loader::read_embedded_aead(loader_bytes(&protected.bytes)).expect("aead");
    assert_ne!(key.as_slice(), &aead[..trace::NAME_KEY_LEN]);
}

#[test]
fn volatile_regs_are_scrubbed_after_the_call() {
    let number = sample::compute(10);
    let call = trace::native_call_volatiles(number).expect("native call");
    for index in [1usize, 2, 8, 9, 10, 11] {
        assert_eq!(call.regs[index], 0, "reg {index}");
    }
    assert_eq!(call.regs[0], 1);
    assert_eq!(call.stdout, sample::line().into_bytes());
    assert!(call.guest.windows(9).all(|window| window != b"vmkek-ok:"));
}

fn opts(seed: u64) -> Options {
    Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed,
        random_key: false,
        debug_seed: false,
    }
}

fn drive_to(machine: &mut emu::Machine, phase_at: u64, want: u8) -> bool {
    machine
        .drive(|guest| phase_byte(guest, phase_at) == want)
        .expect("drive")
}

fn phase_byte(machine: &emu::Machine, at: u64) -> u8 {
    machine
        .read(at, 1)
        .ok()
        .and_then(|bytes| bytes.first().copied())
        .unwrap_or(0)
}

fn assert_snapshot_clean(machine: &emu::Machine) {
    let mut blob = Vec::new();
    for region in &machine.regions {
        blob.extend_from_slice(&region.data);
    }
    assert!(blob.windows(9).all(|window| window != b"vmkek-ok:"));
    for addr in hook_addresses() {
        let bytes = addr.to_le_bytes();
        assert!(
            blob.windows(8).all(|window| window != bytes),
            "hook {addr:#x} is still resident"
        );
        assert!(
            !machine.regs.contains(&addr),
            "hook {addr:#x} is in a register"
        );
    }
}

fn hook_addresses() -> Vec<u64> {
    let mut out = Vec::with_capacity(K32_EXPORTS + NTDLL_EXPORTS);
    for index in 0..K32_EXPORTS {
        out.push(emu::K32_BASE + 0x1000 + index as u64 * 0x10);
    }
    for index in 0..NTDLL_EXPORTS {
        out.push(NTDLL_BASE + 0x1000 + index as u64 * 0x10);
    }
    out
}

fn assert_api_names_absent(plain: &[u8], protected: &[u8]) {
    let image = pe::parse(plain).expect("plain pe");
    for import in &image.imports {
        let name = import.name.as_bytes();
        assert!(
            protected.windows(name.len()).all(|window| window != name),
            "{}",
            import.name
        );
    }
}

fn assert_call_trace(report: &vmkek::report::Report) {
    let claim = report
        .claims
        .iter()
        .find(|item| item.pass == "call-trace")
        .expect("call-trace claim");
    let row = proof::registry()
        .into_iter()
        .find(|item| item.pass == "call-trace")
        .expect("call-trace row");
    assert_eq!(*claim, row);
    assert_eq!(claim.channel, "System");
    assert_eq!(claim.machine, "M-EMU");
    assert_eq!(claim.claim, Claim::Proven);
    assert_eq!(claim.proof_anchor, Some("between_calls_snapshot_is_clean"));
}

fn opened_payload(protected: &Protected) -> Vec<u8> {
    let public = decode_public(&protected.report.public_key);
    let header = protect::inspect(&protected.bytes, &public).expect("inspect");
    let at = crypto::find_header(&protected.bytes).expect("header");
    let payload = payload_slice(&protected.bytes, at, &header);
    let (key, nonce) = loader::read_embedded_aead(loader_bytes(&protected.bytes)).expect("aead");
    let aad = crypto::payload_aad(
        &header.public,
        &header.nonce,
        header.raw_len,
        header.payload_len,
        header.original_entry,
        header.image_base,
    );
    crypto::open_payload(&key, &nonce, &header.tag, payload, &aad).expect("open")
}

fn payload_slice<'a>(bytes: &'a [u8], at: usize, header: &crypto::Header) -> &'a [u8] {
    let start = at + header.payload_off as usize;
    &bytes[start..start + header.payload_len as usize]
}

fn loader_bytes(bytes: &[u8]) -> &[u8] {
    let at = crypto::find_header(bytes).expect("header");
    &bytes[at + HEADER_LEN..]
}

fn decode_public(text: &str) -> [u8; 65] {
    let raw = hex::decode(text).expect("public hex");
    raw.try_into().expect("public length")
}
