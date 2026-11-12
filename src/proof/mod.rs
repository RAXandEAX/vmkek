//! Honest claim levels for protection passes. This module does not add protection.

use serde::Serialize;

use crate::error::{msg, Result};

/// User-mode analyst assumed by every claim in [`registry`].
pub const ATTACKER_MODEL: &str = "user-mode аналитик со статическим дизассемблером и user-mode отладчиком. Вне модели: ядро, гипервизор, полный эмулятор ОС.";

/// Claim strength: a cited proof, an engineering assumption, or a boundary the model does not promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Claim {
    Proven,
    ReducedToAssumption,
    Unreachable,
}

/// One catalog row: pass name, claim level, attacker model, and optional proof anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PassClaim {
    pub pass: &'static str,
    pub claim: Claim,
    pub attacker_model: &'static str,
    pub proof_anchor: Option<&'static str>,
    /// Proof channel. Bytecode encryption and payload AEAD use the Crypto channel.
    #[serde(skip_serializing_if = "channel_empty")]
    pub channel: &'static str,
    /// Proof machine from `docs/architecture.md#evidence`. Empty when the claim names no machine.
    #[serde(skip_serializing_if = "channel_empty")]
    pub machine: &'static str,
}

fn channel_empty(channel: &&str) -> bool {
    channel.is_empty()
}

const fn claim(pass: &'static str, claim: Claim, proof_anchor: Option<&'static str>) -> PassClaim {
    PassClaim {
        pass,
        claim,
        attacker_model: ATTACKER_MODEL,
        proof_anchor,
        channel: "",
        machine: "",
    }
}

const fn crypto(pass: &'static str, level: Claim, proof_anchor: Option<&'static str>) -> PassClaim {
    PassClaim {
        channel: "Crypto",
        ..claim(pass, level, proof_anchor)
    }
}

const fn crypto_linux(pass: &'static str, proof_anchor: &'static str) -> PassClaim {
    PassClaim {
        machine: "M-LINUX",
        ..crypto(pass, Claim::Proven, Some(proof_anchor))
    }
}

const fn system_linux(pass: &'static str, proof_anchor: &'static str) -> PassClaim {
    PassClaim {
        channel: "System",
        machine: "M-LINUX",
        claim: Claim::Proven,
        proof_anchor: Some(proof_anchor),
        ..claim(pass, Claim::Proven, Some(proof_anchor))
    }
}

const fn system_emu(pass: &'static str, proof_anchor: &'static str) -> PassClaim {
    PassClaim {
        channel: "System",
        machine: "M-EMU",
        claim: Claim::Proven,
        proof_anchor: Some(proof_anchor),
        ..claim(pass, Claim::Proven, Some(proof_anchor))
    }
}

const EXTERNAL_KEY_ANCHOR: &str = "guest_snapshot_misses_the_key_and_finds_the_sample: программное измерение, хэш образа в агенте на M-LINUX, не аппаратная аттестация. Успех программного хэша не является успехом H1 и не является аппаратной аттестацией SEV-SNP или TDX";

const REGISTRY: &[PassClaim] = &[
    claim(
        "mba",
        Claim::Proven,
        Some("catalog_rewrite_matches_the_oracle"),
    ),
    claim(
        "constant-blind",
        Claim::Proven,
        Some("obfuscation_preserves_straight_line"),
    ),
    claim(
        "data-mix",
        Claim::Proven,
        Some("data_mix_pairs_restore_input_rax_and_flags"),
    ),
    claim(
        "template-diversity",
        Claim::ReducedToAssumption,
        Some("разнообразие шаблонов измеряется на наборе seed; это не стойкость к нормализатору"),
    ),
    claim(
        "opaque-predicate",
        Claim::Proven,
        Some("obfuscation_preserves_carry_branch"),
    ),
    claim(
        "bogus-control-flow",
        Claim::Proven,
        Some("obfuscation_preserves_straight_line"),
    ),
    claim(
        "control-flow-flatten",
        Claim::Proven,
        Some("obfuscation_preserves_carry_branch"),
    ),
    claim(
        "block-split",
        Claim::Proven,
        Some("obfuscation_preserves_straight_line"),
    ),
    claim(
        "block-shuffle",
        Claim::Proven,
        Some("obfuscation_preserves_straight_line"),
    ),
    claim(
        "opcode-polymorph",
        Claim::Proven,
        Some("vm_matches_ir_and_changes_with_seed"),
    ),
    crypto(
        "bytecode-encrypt",
        Claim::Proven,
        Some("vm_matches_ir_and_changes_with_seed"),
    ),
    crypto(
        "per-instruction-stream",
        Claim::Proven,
        Some("vm_matches_ir_and_changes_with_seed"),
    ),
    claim(
        "vm-equivalence",
        Claim::Proven,
        Some("both_interpreters_match_ir"),
    ),
    claim(
        "layout-stealth",
        Claim::ReducedToAssumption,
        Some(
            "перестановка слотов, junk и вычисляемый диспетчер меняются от seed; это не доказанная скрытность от нормализатора",
        ),
    ),
    claim("integrity-cookies", Claim::ReducedToAssumption, None),
    claim("fail-closed-handlers", Claim::ReducedToAssumption, None),
    claim("anti-debug", Claim::ReducedToAssumption, None),
    system_emu(
        "peb-being-debugged",
        "being_debugged_alone_fails_closed",
    ),
    system_emu("nt-global-flag", "nt_global_flag_alone_fails_closed"),
    system_emu(
        "is-debugger-present",
        "is_debugger_present_alone_fails_closed",
    ),
    system_emu("remote-debugger", "remote_debugger_alone_fails_closed"),
    system_emu("tick-delta", "tick_jump_alone_fails_closed"),
    system_emu("hardware-dr", "hardware_dr_alone_fails_closed"),
    system_emu("debug-port", "debug_port_alone_fails_closed"),
    system_emu("debug-object", "debug_object_alone_fails_closed"),
    system_emu(
        "process-debug-flags",
        "process_debug_flags_alone_fails_closed",
    ),
    system_emu("heap-flags", "heap_flags_alone_fails_closed"),
    system_emu("int-2d", "int2d_alone_fails_closed"),
    system_emu("protected-handle", "protected_handle_alone_fails_closed"),
    system_emu("parent-debugger", "parent_debugger_alone_fails_closed"),
    system_emu("trap-flag", "trap_flag_alone_fails_closed"),
    system_emu("int3-page", "int3_page_alone_fails_closed"),
    system_emu("thread-hide", "thread_hide_alone_fails_closed"),
    system_emu("kernel-debugger", "kernel_debugger_alone_fails_closed"),
    system_emu("remote-breakin", "remote_breakin_alone_fails_closed"),
    system_emu(
        "instrumentation-callback",
        "instrumentation_callback_alone_fails_closed",
    ),
    system_emu(
        "substituted-api-and-peb",
        "substituted_api_and_peb_still_fail_closed",
    ),
    system_linux("linux-tracer-pid", "tracer_pid_alone_fails_closed"),
    system_linux("linux-ptrace", "ptrace_alone_fails_closed"),
    system_linux("linux-clock", "clock_delta_alone_fails_closed"),
    system_emu(
        "early-tls",
        "early_tls_runs_before_the_original_entry",
    ),
    system_linux(
        "early-init",
        "early_init_runs_before_the_original_entry",
    ),
    system_emu("direct-syscall", "direct_syscall_matches_the_import"),
    system_linux(
        "direct-syscall-linux",
        "linux_direct_syscall_matches_the_import",
    ),
    claim("trampoline", Claim::ReducedToAssumption, None),
    claim("import-hash", Claim::ReducedToAssumption, None),
    claim("string-encrypt", Claim::ReducedToAssumption, None),
    system_emu("call-trace", "between_calls_snapshot_is_clean"),
    system_emu(
        "image-hygiene",
        "synthetic_and_sample_drop_fixed_metadata",
    ),
    system_emu(
        "sealed-maps",
        "virtualized_pools_and_rtti_are_sealed",
    ),
    claim(
        "instruction-substitution",
        Claim::Proven,
        Some("mutation_rules_match_the_emulator"),
    ),
    claim(
        "mutation-diversity",
        Claim::ReducedToAssumption,
        Some(
            "чётность seed включает словарь замен, а nop-префикс cave зависит от seed; разнообразие байтов между seed не доказано против нормализатора",
        ),
    ),
    claim(
        "code-cave",
        Claim::Proven,
        Some("cave_move_matches_the_emulator"),
    ),
    claim(
        "linear-desync",
        Claim::Proven,
        Some("linear_decoder_diverges_from_the_trace"),
    ),
    crypto(
        "authenticated-bootstrap",
        Claim::ReducedToAssumption,
        Some("crypto::authenticated::bootstrap tests; the lab runtime requires separate execution evidence"),
    ),
    crypto(
        "aead-runtime",
        Claim::ReducedToAssumption,
        Some(
            "asm-loader расшифровывает ChaCha20 и не проверяет тег Poly1305; рантайм-целостность ReducedToAssumption",
        ),
    ),
    crypto(
        "aead-inspect",
        Claim::Proven,
        Some("aead_inspect_rejects_tamper_and_forged_key"),
    ),
    claim(
        "crc32",
        Claim::ReducedToAssumption,
        Some(
            "быстрый чек CRC32, не криптографическая целостность; crc32_known_answer проверяет только алгоритм; это не криптостойкость",
        ),
    ),
    claim(
        "sha256",
        Claim::ReducedToAssumption,
        Some("отпечаток SHA-256, не криптографическая целостность"),
    ),
    crypto(
        "ecdsa-p256",
        Claim::Proven,
        Some("aead_inspect_rejects_tamper_and_forged_key"),
    ),
    crypto(
        "offline-key",
        Claim::ReducedToAssumption,
        Some(
            "режим offline сохраняет S3b: сырой ключ ChaCha20 остаётся в процессе и слабее external-key",
        ),
    ),
    crypto_linux("external-key", EXTERNAL_KEY_ANCHOR),
    system_linux(
        "external-sample",
        "offline_and_external_print_one_sample_line",
    ),
    claim(
        "virtual-black-box",
        Claim::Unreachable,
        Some("универсальная virtual black-box обфускация произвольной программы не обещается"),
    ),
    claim(
        "kernel-hypervisor",
        Claim::Unreachable,
        Some("стойкость против ядра и гипервизора лежит вне модели"),
    ),
];

/// Claims for emitted protection passes, standalone test evidence, and model boundaries.
#[must_use]
pub fn registry() -> Vec<PassClaim> {
    REGISTRY.to_vec()
}

pub(crate) fn claims_for(passes: &[String]) -> Result<Vec<PassClaim>> {
    let known = registry();
    passes
        .iter()
        .map(|pass| {
            known
                .iter()
                .copied()
                .find(|item| item.pass == pass)
                .ok_or_else(|| msg(format!("pass {pass} has no proof claim")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;
    use crate::protect::{self, Options};
    use crate::sample;

    const PASSES: &[&str] = &[
        "mba",
        "constant-blind",
        "data-mix",
        "template-diversity",
        "opaque-predicate",
        "bogus-control-flow",
        "control-flow-flatten",
        "block-split",
        "block-shuffle",
        "opcode-polymorph",
        "bytecode-encrypt",
        "per-instruction-stream",
        "vm-equivalence",
        "layout-stealth",
        "integrity-cookies",
        "fail-closed-handlers",
        "anti-debug",
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
        "trap-flag",
        "int3-page",
        "thread-hide",
        "kernel-debugger",
        "remote-breakin",
        "instrumentation-callback",
        "linux-tracer-pid",
        "linux-ptrace",
        "linux-clock",
        "early-tls",
        "early-init",
        "direct-syscall",
        "direct-syscall-linux",
        "trampoline",
        "import-hash",
        "string-encrypt",
        "call-trace",
        "image-hygiene",
        "sealed-maps",
        "instruction-substitution",
        "mutation-diversity",
        "code-cave",
        "linear-desync",
        "authenticated-bootstrap",
        "aead-runtime",
        "aead-inspect",
        "crc32",
        "sha256",
        "ecdsa-p256",
        "offline-key",
        "external-key",
        "external-sample",
    ];

    fn entry(pass: &str) -> PassClaim {
        registry()
            .into_iter()
            .find(|item| item.pass == pass)
            .unwrap_or_else(|| panic!("missing registry entry {pass}"))
    }

    fn expected_claim(pass: &str) -> Claim {
        if PROVEN.contains(&pass) {
            Claim::Proven
        } else if ASSUMED.contains(&pass) {
            Claim::ReducedToAssumption
        } else {
            panic!("unexpected pass {pass}");
        }
    }

    fn proven_anchor(pass: &str) -> &'static str {
        match pass {
            "mba" => "catalog_rewrite_matches_the_oracle",
            "data-mix" => "data_mix_pairs_restore_input_rax_and_flags",
            "constant-blind" | "block-split" | "block-shuffle" | "bogus-control-flow" => {
                "obfuscation_preserves_straight_line"
            }
            "opaque-predicate" | "control-flow-flatten" => "obfuscation_preserves_carry_branch",
            "opcode-polymorph" | "bytecode-encrypt" | "per-instruction-stream" => {
                "vm_matches_ir_and_changes_with_seed"
            }
            "vm-equivalence" => "both_interpreters_match_ir",
            "instruction-substitution" => "mutation_rules_match_the_emulator",
            "code-cave" => "cave_move_matches_the_emulator",
            "linear-desync" => "linear_decoder_diverges_from_the_trace",
            "aead-inspect" | "ecdsa-p256" => "aead_inspect_rejects_tamper_and_forged_key",
            "peb-being-debugged" => "being_debugged_alone_fails_closed",
            "nt-global-flag" => "nt_global_flag_alone_fails_closed",
            "is-debugger-present" => "is_debugger_present_alone_fails_closed",
            "remote-debugger" => "remote_debugger_alone_fails_closed",
            "tick-delta" => "tick_jump_alone_fails_closed",
            "hardware-dr" => "hardware_dr_alone_fails_closed",
            "debug-port" => "debug_port_alone_fails_closed",
            "debug-object" => "debug_object_alone_fails_closed",
            "process-debug-flags" => "process_debug_flags_alone_fails_closed",
            "heap-flags" => "heap_flags_alone_fails_closed",
            "int-2d" => "int2d_alone_fails_closed",
            "protected-handle" => "protected_handle_alone_fails_closed",
            "parent-debugger" => "parent_debugger_alone_fails_closed",
            "trap-flag" => "trap_flag_alone_fails_closed",
            "int3-page" => "int3_page_alone_fails_closed",
            "thread-hide" => "thread_hide_alone_fails_closed",
            "kernel-debugger" => "kernel_debugger_alone_fails_closed",
            "remote-breakin" => "remote_breakin_alone_fails_closed",
            "instrumentation-callback" => "instrumentation_callback_alone_fails_closed",
            "linux-tracer-pid" => "tracer_pid_alone_fails_closed",
            "linux-ptrace" => "ptrace_alone_fails_closed",
            "linux-clock" => "clock_delta_alone_fails_closed",
            "early-tls" => "early_tls_runs_before_the_original_entry",
            "early-init" => "early_init_runs_before_the_original_entry",
            "direct-syscall" => "direct_syscall_matches_the_import",
            "direct-syscall-linux" => "linux_direct_syscall_matches_the_import",
            "call-trace" => "between_calls_snapshot_is_clean",
            "image-hygiene" => "synthetic_and_sample_drop_fixed_metadata",
            "sealed-maps" => "virtualized_pools_and_rtti_are_sealed",
            "external-key" => EXTERNAL_KEY_ANCHOR,
            "external-sample" => "offline_and_external_print_one_sample_line",
            other => panic!("{other} is not Proven"),
        }
    }

    const PROVEN: &[&str] = &[
        "mba",
        "constant-blind",
        "data-mix",
        "opaque-predicate",
        "bogus-control-flow",
        "control-flow-flatten",
        "block-split",
        "block-shuffle",
        "opcode-polymorph",
        "bytecode-encrypt",
        "per-instruction-stream",
        "vm-equivalence",
        "instruction-substitution",
        "code-cave",
        "linear-desync",
        "aead-inspect",
        "ecdsa-p256",
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
        "trap-flag",
        "int3-page",
        "thread-hide",
        "kernel-debugger",
        "remote-breakin",
        "instrumentation-callback",
        "linux-tracer-pid",
        "linux-ptrace",
        "linux-clock",
        "early-tls",
        "early-init",
        "direct-syscall",
        "direct-syscall-linux",
        "call-trace",
        "image-hygiene",
        "sealed-maps",
        "external-key",
        "external-sample",
    ];

    const ASSUMED: &[&str] = &[
        "template-diversity",
        "layout-stealth",
        "integrity-cookies",
        "fail-closed-handlers",
        "anti-debug",
        "trampoline",
        "import-hash",
        "string-encrypt",
        "mutation-diversity",
        "authenticated-bootstrap",
        "aead-runtime",
        "crc32",
        "sha256",
        "offline-key",
    ];

    fn protect_sample() -> crate::report::Report {
        let built = sample::build().expect("sample");
        let options = Options {
            virtualize: BTreeSet::new(),
            mutate: BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed: 1,
            random_key: false,
            debug_seed: false,
        };
        protect::protect(&built.bytes, &options)
            .expect("protect")
            .report
    }

    #[test]
    fn unknown_pass_has_no_proof_claim() {
        let err = claims_for(&["not-a-pass".into()]).expect_err("unknown pass");
        assert_eq!(err.to_string(), "pass not-a-pass has no proof claim");
    }

    #[test]
    fn empty_pass_list_yields_no_claims() {
        let claims = claims_for(&[]).expect("empty");
        assert!(claims.is_empty());
    }

    #[test]
    fn attacker_model_names_the_user_mode_boundary() {
        assert_eq!(
            ATTACKER_MODEL,
            "user-mode аналитик со статическим дизассемблером и user-mode отладчиком. Вне модели: ядро, гипервизор, полный эмулятор ОС."
        );
    }

    #[test]
    fn registry_covers_every_pass_protect_can_emit() {
        let names: BTreeSet<_> = registry().iter().map(|item| item.pass).collect();
        for pass in PASSES {
            assert!(names.contains(pass), "missing {pass}");
        }
        assert_eq!(names.len(), registry().len());
        let emitted: BTreeSet<_> = PASSES.iter().copied().collect();
        let registry_only: Vec<_> = names.difference(&emitted).copied().collect();
        assert_eq!(
            registry_only,
            [
                "kernel-hypervisor",
                "substituted-api-and-peb",
                "virtual-black-box"
            ]
        );
    }

    #[test]
    fn claim_levels_match_existing_anchors() {
        for pass in PASSES {
            let item = entry(pass);
            assert_eq!(item.claim, expected_claim(pass), "{pass}");
            assert_eq!(item.attacker_model, ATTACKER_MODEL);
            if item.claim == Claim::Proven {
                assert_eq!(item.proof_anchor, Some(proven_anchor(pass)), "{pass}");
                assert!(!item.proof_anchor.unwrap().is_empty());
            }
        }
        assert!(entry("crc32")
            .proof_anchor
            .unwrap()
            .contains("не криптостойкость"));
        assert!(entry("crc32")
            .proof_anchor
            .unwrap()
            .contains("не криптографическая целостность"));
        assert!(entry("sha256")
            .proof_anchor
            .unwrap()
            .contains("не криптографическая целостность"));
        assert_eq!(entry("aead-runtime").claim, Claim::ReducedToAssumption);
        assert!(entry("aead-runtime")
            .proof_anchor
            .unwrap()
            .contains("Poly1305"));
        assert_eq!(entry("aead-runtime").channel, "Crypto");
        assert_eq!(entry("aead-inspect").claim, Claim::Proven);
        assert_eq!(entry("aead-inspect").channel, "Crypto");
        assert_eq!(entry("ecdsa-p256").channel, "Crypto");
        assert_eq!(entry("bytecode-encrypt").channel, crate::vm::CHANNEL);
        assert_eq!(entry("per-instruction-stream").channel, "Crypto");
        assert_eq!(entry("crc32").channel, "");
        assert_eq!(entry("sha256").channel, "");
        for pass in [
            "integrity-cookies",
            "fail-closed-handlers",
            "anti-debug",
            "trampoline",
            "import-hash",
            "string-encrypt",
        ] {
            assert_eq!(entry(pass).proof_anchor, None, "{pass}");
        }
        assert!(entry("mutation-diversity")
            .proof_anchor
            .unwrap()
            .contains("не доказано"));
    }

    #[test]
    fn user_mode_detectors_are_system_on_m_emu() {
        for pass in [
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
            "trap-flag",
            "int3-page",
            "thread-hide",
            "kernel-debugger",
            "remote-breakin",
            "instrumentation-callback",
            "early-tls",
        ] {
            let item = entry(pass);
            assert_eq!(item.channel, "System", "{pass}");
            assert_eq!(item.machine, "M-EMU", "{pass}");
            assert_eq!(item.claim, Claim::Proven, "{pass}");
        }
    }

    #[test]
    fn api_and_peb_fixture_has_a_system_anchor_on_m_emu() {
        let item = entry("substituted-api-and-peb");
        assert_eq!(item.channel, "System");
        assert_eq!(item.machine, "M-EMU");
        assert_eq!(item.claim, Claim::Proven);
        assert_eq!(
            item.proof_anchor,
            Some("substituted_api_and_peb_still_fail_closed")
        );
        let report = protect_sample();
        assert!(report.passes.iter().all(|pass| pass != item.pass));
    }

    #[test]
    fn external_key_names_a_software_measurement() {
        let offline = entry("offline-key");
        assert_eq!(offline.claim, Claim::ReducedToAssumption);
        assert_eq!(offline.channel, "Crypto");
        assert!(offline.proof_anchor.unwrap().contains("слабее"));
        let external = entry("external-key");
        assert_eq!(external.claim, Claim::Proven);
        assert_eq!(external.channel, "Crypto");
        assert_eq!(external.machine, "M-LINUX");
        let anchor = external.proof_anchor.unwrap();
        assert!(anchor.contains("программное измерение"));
        assert!(anchor.contains("не аппаратная аттестация"));
        assert!(anchor.contains("H1"));
        assert!(anchor.contains("SEV-SNP"));
        assert!(anchor.contains("TDX"));
        let sample = entry("external-sample");
        assert_eq!(sample.channel, "System");
        assert_eq!(sample.machine, "M-LINUX");
        assert_eq!(
            sample.proof_anchor,
            Some("offline_and_external_print_one_sample_line")
        );
    }

    #[test]
    fn linux_detectors_are_system_on_m_linux() {
        for pass in [
            "linux-tracer-pid",
            "linux-ptrace",
            "linux-clock",
            "early-init",
        ] {
            let item = entry(pass);
            assert_eq!(item.channel, "System", "{pass}");
            assert_eq!(item.machine, "M-LINUX", "{pass}");
            assert_eq!(item.claim, Claim::Proven, "{pass}");
        }
    }

    #[test]
    fn unreachable_boundaries_are_not_protection_passes() {
        let vbb = entry("virtual-black-box");
        let kernel = entry("kernel-hypervisor");
        assert_eq!(vbb.claim, Claim::Unreachable);
        assert_eq!(kernel.claim, Claim::Unreachable);
        assert_eq!(vbb.attacker_model, ATTACKER_MODEL);
        assert_eq!(kernel.attacker_model, ATTACKER_MODEL);
        assert!(PASSES
            .iter()
            .all(|pass| *pass != vbb.pass && *pass != kernel.pass));
        let report = protect_sample();
        assert!(report.passes.iter().all(|pass| pass != vbb.pass));
        assert!(report
            .claims
            .iter()
            .all(|item| item.claim != Claim::Unreachable));
    }

    #[test]
    fn sample_report_projects_registry_claims() {
        let report = protect_sample();
        let names: BTreeSet<_> = registry().iter().map(|item| item.pass).collect();
        for pass in &report.passes {
            assert!(names.contains(pass.as_str()), "{pass}");
        }
        assert_eq!(report.claims.len(), report.passes.len());
        for (pass, claim) in report.passes.iter().zip(&report.claims) {
            assert_eq!(claim.pass, pass);
            assert_eq!(*claim, entry(pass));
        }
        let json = serde_json::to_value(&report).expect("json");
        assert!(json.get("claims").is_some());
        assert!(matches!(json["claims"], Value::Array(_)));
        let rendered = serde_json::to_string(&report).expect("json");
        assert!(rendered.contains("\"claims\""));
    }
}
