//! M-LINUX System channel for L8. The inventory is closed: every user mnemonic
//! is `proven: true`, or every encoding that still counts needs a CPUID feature
//! named by a lab protocol and absent on this process. Protocols for a
//! feature that is available here are historical observations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use iced_x86::{Code, CpuidFeature, Mnemonic};
use vmkek::isa::census::{self, Status};
use vmkek::isa::close;

#[test]
fn inventory_is_proven_or_has_an_absent_cpuid_protocol() {
    let protocols = load_protocols();
    let named = assert_protocols_match_cpuid(&protocols);
    // Sentinels from this M-LINUX. A table that reports every feature absent
    // would still satisfy the clauses above.
    assert!(close::cpu_has(CpuidFeature::X64));
    assert!(close::cpu_has(CpuidFeature::SYSCALL));
    assert!(close::cpu_has(CpuidFeature::AVX512F));
    assert!(close::cpu_has(CpuidFeature::GFNI));
    let used = features_used_by_unproven_lift();
    let missing: Vec<_> = used.difference(&named).copied().collect();
    assert!(
        missing.is_empty(),
        "missing CPUID lab protocols: {missing:?}"
    );
    let extra: Vec<_> = named.difference(&used).copied().collect();
    assert!(
        extra.is_empty(),
        "lab protocol names a CPUID no unproven mnemonic needs: {extra:?}"
    );
}

fn assert_protocols_match_cpuid(
    protocols: &BTreeMap<CpuidFeature, Protocol>,
) -> BTreeSet<CpuidFeature> {
    let mut named = BTreeSet::new();
    for protocol in protocols.values() {
        assert!(
            protocol.body.contains("M-LINUX"),
            "{:?} does not name M-LINUX",
            protocol.feature
        );
        assert!(
            protocol.body.contains("proven: false"),
            "{:?} does not keep the unproven bit",
            protocol.feature
        );
        let absent = clause_is_absent(&protocol.clause);
        assert_eq!(
            absent,
            !close::cpu_has(protocol.feature),
            "{:?} clause `{}` disagrees with the host capability map",
            protocol.feature,
            protocol.clause
        );
        if absent {
            assert!(
                named.insert(protocol.feature),
                "duplicate {:?}",
                protocol.feature
            );
        }
    }
    named
}

fn features_used_by_unproven_lift() -> BTreeSet<CpuidFeature> {
    let mut used = BTreeSet::new();
    for row in census::entries() {
        if row.status != Status::Lift {
            continue;
        }
        note_lift_features(row, &mut used);
    }
    used
}

fn note_lift_features(row: &census::Entry, used: &mut BTreeSet<CpuidFeature>) {
    let codes = close::proving_codes(row.mnemonic);
    if row.proven {
        assert!(
            codes.is_empty() || codes.iter().any(|code| encoding_can_run(*code)),
            "{:?} is proven but every encoding needs an absent CPUID",
            row.mnemonic
        );
        return;
    }
    assert!(
        !codes.is_empty(),
        "{:?} is lift and not proven, and it has no encoding",
        row.mnemonic
    );
    let missing = close::missing_features(row.mnemonic);
    assert!(
        !missing.is_empty(),
        "{:?} is lift and not proven without an absent CPUID",
        row.mnemonic
    );
    for code in &codes {
        record_blockers(row.mnemonic, *code, used);
    }
    for feature in missing {
        used.insert(feature);
    }
}

fn record_blockers(mnemonic: Mnemonic, code: Code, used: &mut BTreeSet<CpuidFeature>) {
    let blockers: Vec<_> = code
        .cpuid_features()
        .iter()
        .copied()
        .filter(|feature| !close::cpu_has(*feature))
        .collect();
    assert!(
        !blockers.is_empty(),
        "{:?} {:?} can run but the mnemonic is not proven",
        mnemonic,
        code
    );
    used.extend(blockers);
}

struct Protocol {
    feature: CpuidFeature,
    clause: String,
    body: String,
}

fn load_protocols() -> BTreeMap<CpuidFeature, Protocol> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/labs");
    let mut out = BTreeMap::new();
    let entries =
        std::fs::read_dir(&root).unwrap_or_else(|err| panic!("read {}: {err}", root.display()));
    for entry in entries {
        let entry = entry.expect("lab entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("cpuid-") || !name.ends_with(".md") {
            continue;
        }
        let body = std::fs::read_to_string(entry.path())
            .unwrap_or_else(|err| panic!("read {}: {err}", entry.path().display()));
        let feature = field(&body, "feature");
        let clause = field(&body, "cpuid-absent");
        let parsed = feature_named(&feature);
        let stem = name.trim_start_matches("cpuid-").trim_end_matches(".md");
        assert_eq!(
            stem,
            feature.to_ascii_lowercase(),
            "file {name} does not match feature {feature}"
        );
        out.insert(
            parsed,
            Protocol {
                feature: parsed,
                clause,
                body,
            },
        );
    }
    assert!(
        !out.is_empty(),
        "no CPUID protocols under {}",
        root.display()
    );
    out
}

fn field(body: &str, key: &str) -> String {
    let prefix = format!("- {key}:");
    body.lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::trim))
        .unwrap_or_else(|| panic!("protocol is missing {prefix}"))
        .to_string()
}

fn feature_named(name: &str) -> CpuidFeature {
    CpuidFeature::values()
        .find(|feature| format!("{feature:?}") == name)
        .unwrap_or_else(|| panic!("unknown CPUID feature {name}"))
}

fn encoding_can_run(code: Code) -> bool {
    code.cpuid_features()
        .iter()
        .all(|feature| close::cpu_has(*feature))
}

fn clause_is_absent(clause: &str) -> bool {
    let clause = clause.trim();
    if let Some(rest) = clause.strip_prefix("all-clear") {
        let bits: Vec<_> = rest
            .split("bit")
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        assert!(!bits.is_empty(), "all-clear needs bits");
        return bits.iter().all(|part| !bit_is_set(part));
    }
    if let Some(rest) = clause.strip_prefix("bit ") {
        return !bit_is_set(rest);
    }
    if let Some(rest) = clause.strip_prefix("padlock ") {
        return !padlock_enabled(parse_u32(rest.trim()));
    }
    if let Some(rest) = clause.strip_prefix("vendor-not ") {
        return vendor() != rest.trim();
    }
    if let Some(rest) = clause.strip_prefix("family-not ") {
        return display_family() != parse_u32(rest.trim());
    }
    if clause == "arch x86_64" {
        return std::env::consts::ARCH == "x86_64";
    }
    if clause == "centaur-missing" {
        return cpuid(0xC000_0000, 0).eax < 0xC000_0001;
    }
    panic!("unknown cpuid-absent clause: {clause}");
}

fn bit_is_set(spec: &str) -> bool {
    let mut parts = spec.split_whitespace();
    let leaf = parse_u32(parts.next().expect("leaf"));
    let sub = parse_u32(parts.next().expect("subleaf"));
    let reg = parts.next().expect("register");
    let bit = parse_u32(parts.next().expect("bit"));
    assert!(parts.next().is_none(), "extra tokens in `{spec}`");
    assert!(bit < 32, "bit {bit}");
    if !leaf_ok(leaf, sub) {
        return false;
    }
    let result = cpuid(leaf, sub);
    let word = match reg {
        "eax" => result.eax,
        "ebx" => result.ebx,
        "ecx" => result.ecx,
        "edx" => result.edx,
        other => panic!("unknown register {other}"),
    };
    word & (1 << bit) != 0
}

fn leaf_ok(leaf: u32, sub: u32) -> bool {
    if leaf >= 0x8000_0000 {
        return cpuid(0x8000_0000, 0).eax >= leaf;
    }
    if cpuid(0, 0).eax < leaf {
        return false;
    }
    if leaf == 7 {
        return sub <= cpuid(7, 0).eax;
    }
    true
}

fn padlock_enabled(shift: u32) -> bool {
    let max = cpuid(0xC000_0000, 0).eax;
    if max < 0xC000_0001 {
        return false;
    }
    (cpuid(0xC000_0001, 0).edx >> shift) & 0b11 == 0b11
}

fn vendor() -> String {
    let result = cpuid(0, 0);
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&result.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&result.edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&result.ecx.to_le_bytes());
    String::from_utf8_lossy(&bytes).into_owned()
}

fn display_family() -> u32 {
    let eax = cpuid(1, 0).eax;
    let base = (eax >> 8) & 0xf;
    if base == 0xf {
        base + ((eax >> 20) & 0xff)
    } else {
        base
    }
}

fn parse_u32(text: &str) -> u32 {
    if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).unwrap_or_else(|err| panic!("hex {text}: {err}"))
    } else {
        text.parse()
            .unwrap_or_else(|err| panic!("number {text}: {err}"))
    }
}

fn cpuid(leaf: u32, sub: u32) -> std::arch::x86_64::CpuidResult {
    std::arch::x86_64::__cpuid_count(leaf, sub)
}

/// rust-review counts physical lines from the `fn` line through its closing `}`.
/// Fifty is still allowed. Two census tests were already over that cap and sit
/// outside the L8 diff, so they stay out of this guard.
#[test]
fn reviewed_functions_stay_within_fifty_lines() {
    let inherited = [
        "refuse_is_only_privileged_io_or_hypervisor_exit",
        "groups_follow_the_l0_partition",
    ];
    let paths = [
        "src/isa/cpuid_host.rs",
        "src/isa/close.rs",
        "src/isa/census.rs",
        "tests/l8_isa.rs",
    ];
    for path in paths {
        for (name, span) in fn_spans(path) {
            if inherited.contains(&name.as_str()) {
                continue;
            }
            assert!(span <= 50, "{path} {name} is {span} physical lines");
        }
    }
    assert_must_use("src/isa/close.rs", "proving_codes");
    assert_must_use("src/isa/close.rs", "missing_features");
}

/// E2 rust-review uses this same physical-line counter. Fifty is still allowed.
#[test]
fn e2_functions_stay_within_fifty_lines() {
    for path in [
        "src/protect/elf.rs",
        "src/loader_sysv.rs",
        "src/elf/sample.rs",
        "tests/e2_linux.rs",
    ] {
        for (name, span) in fn_spans(path) {
            assert!(span <= 50, "{path} {name} is {span} physical lines");
        }
    }
    assert_rustdoc("src/loader_sysv.rs", "assemble");
    assert_reserves_gs_page();
}

/// E3 rust-review uses the same physical-line counter. Fifty is still allowed.
#[test]
fn e3_functions_stay_within_fifty_lines() {
    for path in [
        "src/antidebug/linux.rs",
        "src/early.rs",
        "tests/e3_linux.rs",
        "tests/c6_early.rs",
        "src/agent/mod.rs",
        "src/agent/wire.rs",
        "src/agent/serve.rs",
        "src/stub/external.rs",
        "tests/c8_linux.rs",
    ] {
        for (name, span) in fn_spans(path) {
            assert!(span <= 50, "{path} {name} is {span} physical lines");
        }
    }
    for (path, name) in [
        ("src/stub/handlers.rs", "emit_probe"),
        ("src/stub/handlers.rs", "emit_handler_control"),
        ("src/stub/mod.rs", "emit_epilogue"),
        ("src/stub/mod.rs", "emit_gate_pad"),
        ("src/stub/mod.rs", "emit_handler_labels"),
        ("src/stub/mod.rs", "create_vm_labels"),
        ("src/stub/mod.rs", "assemble_vm_seeded"),
        ("src/stub/mod.rs", "encode_vm"),
        ("src/stub/mod.rs", "padded_vm"),
        ("src/protect/mod.rs", "code_layout"),
        ("src/protect/payload.rs", "build_section"),
        ("src/protect/payload.rs", "section_image"),
        ("src/protect/elf.rs", "assemble_body"),
        ("src/protect/elf.rs", "measure"),
        ("src/proof/mod.rs", "expected_claim"),
        ("src/proof/mod.rs", "proven_anchor"),
        ("src/driver/mod.rs", "system_channel_on_m_kern_stays_red"),
    ] {
        let span = fn_spans(path)
            .into_iter()
            .find(|(item, _)| item == name)
            .unwrap_or_else(|| panic!("missing {path} {name}"))
            .1;
        assert!(span <= 50, "{path} {name} is {span} physical lines");
    }
}

fn assert_rustdoc(path: &str, name: &str) {
    let text = read_src(path);
    let lines: Vec<_> = text.lines().collect();
    let idx = lines
        .iter()
        .position(|line| fn_name(line).as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing {name}"));
    assert!(
        idx > 0 && lines[idx - 1].trim_start().starts_with("///"),
        "{path} {name} is missing rustdoc"
    );
}

fn assert_reserves_gs_page() {
    let body = read_src("src/protect/elf.rs");
    let start = body
        .lines()
        .position(|line| fn_name(line).as_deref() == Some("assemble_body"))
        .expect("assemble_body");
    let end = start + close_line(&body, start);
    let lines: Vec<_> = body.lines().collect();
    let text = lines[start..=end].join("\n");
    assert!(
        text.contains("Vec::with_capacity"),
        "assemble_body reserves the final gs page"
    );
}

fn assert_must_use(path: &str, name: &str) {
    let text = read_src(path);
    let lines: Vec<_> = text.lines().collect();
    let idx = lines
        .iter()
        .position(|line| fn_name(line).as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing {name}"));
    assert!(
        idx > 0 && lines[idx - 1].trim() == "#[must_use]",
        "{path} {name} is missing #[must_use]"
    );
}

fn fn_spans(path: &str) -> Vec<(String, usize)> {
    let text = read_src(path);
    let mut spans = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let Some(name) = fn_name(line) else {
            continue;
        };
        spans.push((name, close_line(&text, idx) + 1));
    }
    spans
}

fn read_src(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn fn_name(line: &str) -> Option<String> {
    let mut trimmed = line.trim();
    for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            trimmed = rest;
            break;
        }
    }
    for prefix in ["const ", "async ", "unsafe "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            trimmed = rest;
        }
    }
    let rest = trimmed.strip_prefix("fn ")?;
    let end = rest.find(['(', '<']).unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

fn close_line(text: &str, start: usize) -> usize {
    let offset: usize = text.lines().take(start).map(|line| line.len() + 1).sum();
    scan_close(&text[offset..])
}

fn scan_close(rest: &str) -> usize {
    let mut line = 0usize;
    let mut depth = 0i32;
    let mut started = false;
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            '/' => line += skip_slash(&mut chars),
            '"' => line += skip_string(&mut chars),
            '\'' => skip_tick(&mut chars),
            '{' => {
                depth += 1;
                started = true;
            }
            '}' => {
                depth -= 1;
                if started && depth == 0 {
                    return line;
                }
            }
            _ => {}
        }
    }
    panic!("unclosed function");
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn skip_slash(chars: &mut Chars<'_>) -> usize {
    match chars.peek().copied() {
        Some('/') => skip_line_comment(chars),
        Some('*') => skip_block_comment(chars),
        _ => 0,
    }
}

fn skip_line_comment(chars: &mut Chars<'_>) -> usize {
    chars.next();
    for c in chars.by_ref() {
        if c == '\n' {
            return 1;
        }
    }
    0
}

fn skip_block_comment(chars: &mut Chars<'_>) -> usize {
    chars.next();
    let mut lines = 0;
    while let Some(c) = chars.next() {
        if c == '\n' {
            lines += 1;
        }
        if c == '*' && chars.peek() == Some(&'/') {
            chars.next();
            break;
        }
    }
    lines
}

fn skip_string(chars: &mut Chars<'_>) -> usize {
    let mut lines = 0;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => return lines,
            '\n' => lines += 1,
            _ => {}
        }
    }
    lines
}

fn skip_tick(chars: &mut Chars<'_>) {
    let Some(first) = chars.peek().copied() else {
        return;
    };
    if first.is_ascii_alphabetic() || first == '_' {
        while chars
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
        {
            chars.next();
        }
        if chars.peek() == Some(&'\'') {
            chars.next();
        }
        return;
    }
    if first == '\\' {
        chars.next();
        if chars.peek() == Some(&'u') {
            for c in chars.by_ref() {
                if c == '\'' {
                    break;
                }
            }
            return;
        }
        chars.next();
    } else {
        chars.next();
    }
    if chars.peek() == Some(&'\'') {
        chars.next();
    }
}
