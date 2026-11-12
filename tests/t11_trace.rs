//! T11 on channel System, machine M-TRACE.
//!
//! The branch ring lives inside the emulator and stores taken jump targets.
//! It is not an Intel Processor Trace recording. Live PT stays red.

use vmkek::crypto::{self, HEADER_LEN};
use vmkek::emu::{self, ChannelColor, Policy};
use vmkek::loader;
use vmkek::pe;
use vmkek::protect::{self, Options, Protected};
use vmkek::sample;
use vmkek::trace;
use vmkek::vm::{self, KEY_LEN, RUNTIME_WINDOW, TABLES_AT};

const SEED: u64 = 0x7110_0001;

#[test]
fn sample_branch_ring_holds_no_key_bytes() {
    let built = sample::build().expect("sample");
    let protected = protect::protect(&built.bytes, &opts()).expect("protect");
    let plain = open_plain(&protected);
    let keys = secret_keys(&protected, &plain);
    assert_terminal(&plain);
    let image = pe::parse(&protected.bytes).expect("pe");
    let mut machine = emu::load(&image, Policy::default()).expect("load");
    machine.run().expect("run");
    assert_eq!(machine.exit_code, Some(0));
    assert_eq!(machine.stdout, sample::line().into_bytes());
    let targets = machine.branch_targets();
    assert!(!targets.is_empty(), "sample took no branches");
    let bytes = machine.branch_bytes();
    let encoded: Vec<_> = targets.into_iter().flat_map(u64::to_le_bytes).collect();
    assert_eq!(bytes, encoded);
    for key in &keys {
        assert!(
            bytes
                .windows(key.len())
                .all(|window| window != key.as_slice()),
            "branch ring holds a key"
        );
    }
}

#[test]
fn trace_claims_name_m_trace_and_leave_live_pt_red() {
    let rows = emu::trace_claims();
    let green: Vec<_> = rows
        .iter()
        .filter(|row| row.color == ChannelColor::Green)
        .collect();
    assert!(green
        .iter()
        .any(|row| row.anchor == "sample_branch_ring_holds_no_key_bytes"));
    assert!(green
        .iter()
        .any(|row| row.anchor == "opcode_class_memory_accesses_match"));
    assert!(green
        .iter()
        .any(|row| row.anchor == "secret_byte_does_not_select_a_tag_branch"));
    assert!(green
        .iter()
        .all(|row| row.channel == "System" && row.machine == "M-TRACE"));
    assert!(green
        .iter()
        .all(|row| row.statement.contains("M-TRACE") || row.id == "opcode-class-access"));
    let live = rows.iter().find(|row| row.id == "live-intel-pt").unwrap();
    assert_eq!(live.color, ChannelColor::Red);
    assert_eq!(live.channel, "System");
    assert_eq!(live.machine, "");
    assert!(live.statement.contains("не модель M-TRACE"));
    assert!(live.statement.contains("Intel PT"));
}

fn opts() -> Options {
    Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed: SEED,
        random_key: false,
        debug_seed: false,
    }
}

fn secret_keys(protected: &Protected, plain: &[u8]) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    let (aead, _) = loader::read_embedded_aead(loader_bytes(&protected.bytes)).expect("aead");
    keys.push(aead.to_vec());
    keys.push(trace::name_key(SEED).expect("name").to_vec());
    keys.push(
        crypto::deterministic_signing_scalar(SEED)
            .expect("scalar")
            .to_vec(),
    );
    keys.push(plain[..trace::NAME_KEY_LEN].to_vec());
    for key in runtime_keys(plain) {
        keys.push(key.to_vec());
    }
    keys.retain(|key| key.iter().any(|byte| *byte != 0));
    keys
}

fn assert_terminal(plain: &[u8]) {
    let (base, count) = runtime_span(plain);
    for index in 0..count {
        let at = base + index * RUNTIME_WINDOW as usize;
        let term = read_key(plain, at + vm::RT_TERM as usize);
        let walked = walked_terminal(plain, at);
        assert_eq!(walked, term, "function {index}");
    }
}

fn runtime_keys(plain: &[u8]) -> Vec<[u8; KEY_LEN]> {
    let (base, count) = runtime_span(plain);
    let mut keys = Vec::new();
    for index in 0..count {
        let at = base + index * RUNTIME_WINDOW as usize;
        keys.push(read_key(plain, at + vm::RT_KEY as usize));
        keys.push(read_key(plain, at + vm::RT_MASTER as usize));
        keys.push(read_key(plain, at + vm::RT_TERM as usize));
        keys.push(read_key(plain, at + vm::INNER_KEY as usize));
        keys.extend(weave_steps(plain, at));
    }
    keys
}

fn weave_steps(plain: &[u8], at: usize) -> Vec<[u8; KEY_LEN]> {
    let count = insn_count(plain, at);
    let mut running = read_key(plain, at + vm::RT_KEY as usize);
    let mut keys = Vec::with_capacity(count);
    let offs = at + TABLES_AT as usize;
    let lens = offs + count * 4 + 16;
    let blob = lens + count * 4 + 16 + 256;
    for index in 0..count {
        let off = u32_at(plain, offs + index * 4) as usize;
        let len = u32_at(plain, lens + index * 4) as usize;
        let block = &plain[blob + off..blob + off + len];
        running = vm::weave_next(&running, index as u32, block);
        keys.push(running);
    }
    keys
}

fn walked_terminal(plain: &[u8], at: usize) -> [u8; KEY_LEN] {
    weave_steps(plain, at)
        .last()
        .copied()
        .unwrap_or_else(|| read_key(plain, at + vm::RT_KEY as usize))
}

fn runtime_span(plain: &[u8]) -> (usize, usize) {
    let mut body = trace::NAME_KEY_LEN;
    // Both the transient strings and the T4 image-map records precede imports.
    for _ in 0..2 {
        let count = u32_at(plain, body) as usize;
        body += 4 + count * 12;
    }
    let nimports = u32_at(plain, body);
    body += 4 + nimports as usize * 8;
    let table = trace::NAME_KEY_LEN + align16(body - trace::NAME_KEY_LEN);
    let nfuncs = u32_at(plain, table) as usize;
    let after = table + 4 + nfuncs * 16;
    let runtime = trace::NAME_KEY_LEN + align16(after - trace::NAME_KEY_LEN);
    (runtime, nfuncs)
}

fn insn_count(plain: &[u8], at: usize) -> usize {
    u64::from_le_bytes(plain[at..at + 8].try_into().unwrap()) as usize
}

fn read_key(plain: &[u8], at: usize) -> [u8; KEY_LEN] {
    plain[at..at + KEY_LEN].try_into().unwrap()
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn align16(value: usize) -> usize {
    value.div_ceil(16) * 16
}

fn open_plain(protected: &Protected) -> Vec<u8> {
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
