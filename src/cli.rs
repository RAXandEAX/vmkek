use std::env;
use std::fs;

use clap::{Parser, Subcommand};

use crate::config::FileConfig;
use crate::emu::{self, Policy};
use crate::i18n::{self, Lang};
use crate::protect::{self, Options};

mod authenticated;
use authenticated::NativeAuthArgs;

#[cfg(target_os = "linux")]
mod native;

#[derive(Parser)]
#[command(
    name = "vmkek",
    disable_help_subcommand = true,
    subcommand_required = false,
    args_conflicts_with_subcommands = false
)]
struct Args {
    #[arg(long, global = true, value_name = "en|ru")]
    lang: Option<String>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    #[cfg(target_os = "linux")]
    RunNative {
        file: std::path::PathBuf,
        /// SHA-256 of the final ELF from the trusted deployment policy.
        #[arg(long)]
        sha256: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Protect {
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long = "virtualize")]
        virtualize: Vec<String>,
        #[arg(long = "mutate")]
        mutate: Vec<String>,
        #[arg(long)]
        seed: Option<u64>,
        /// Draw the payload AEAD key and the P-256 signing key from the OS RNG.
        #[arg(long = "random-key", conflicts_with = "deterministic")]
        random_key: bool,
        /// HKDF-SHA256 keys from `--seed`. This is the default.
        #[arg(long, conflicts_with = "random_key")]
        deterministic: bool,
        /// Write the seed into the JSON report. Off by default.
        #[arg(long = "debug-seed")]
        debug_seed: bool,
        #[arg(long)]
        config: Option<String>,
        #[arg(long = "virtualize-all")]
        virtualize_all: bool,
        #[arg(long = "mutate-all")]
        mutate_all: bool,
        /// Target native Windows with OS-managed imports.
        #[arg(long)]
        windows_native: bool,
        #[command(flatten)]
        authentication: NativeAuthArgs,
    },
    /// Display a versioned protection report.
    Report { file: String },
    Inspect {
        file: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        config: Option<String>,
    },
    Run {
        file: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        config: Option<String>,
    },
}

pub fn execute_from_env() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    match execute_with_process_policy(&args, true) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

pub fn execute(args: &[String]) -> crate::Result<i32> {
    execute_with_process_policy(args, false)
}

fn execute_with_process_policy(args: &[String], standalone: bool) -> crate::Result<i32> {
    let mut argv = vec!["vmkek".to_string()];
    argv.extend_from_slice(args);
    let parsed = match Args::try_parse_from(&argv) {
        Ok(parsed) => parsed,
        Err(err) if err.kind() == clap::error::ErrorKind::DisplayHelp => {
            print!("{}", i18n::help(language(args)));
            return Ok(0);
        }
        Err(err) => return Err(crate::error::msg(err.to_string())),
    };
    let lang = parsed
        .lang
        .as_deref()
        .map(Lang::parse)
        .unwrap_or_else(|| language(args));
    if standalone && matches!(&parsed.command, Some(Cmd::Protect { .. })) {
        crate::secret::disable_process_dumps()?;
    }
    match parsed.command {
        Some(command) => dispatch(command, lang),
        None => {
            print!("{}", i18n::help(lang));
            Ok(0)
        }
    }
}

fn dispatch(command: Cmd, lang: Lang) -> crate::Result<i32> {
    match command {
        #[cfg(target_os = "linux")]
        Cmd::RunNative { file, sha256, args } => native::run(&file, &sha256, &args),
        Cmd::Protect {
            input,
            output,
            virtualize,
            mutate,
            seed,
            random_key,
            deterministic,
            debug_seed,
            config,
            virtualize_all,
            mutate_all,
            windows_native,
            authentication,
        } => protect_cmd(
            ProtectArgs {
                input: &input,
                output: &output,
                virtualize,
                mutate,
                seed,
                random_key,
                deterministic,
                debug_seed,
                config_path: config.as_deref(),
                virtualize_all,
                mutate_all,
                windows_native,
                lang,
            },
            authentication,
        ),
        Cmd::Report { file } => {
            println!("{}", crate::report::view_json(&fs::read_to_string(file)?)?);
            Ok(0)
        }
        Cmd::Inspect { file, key, config } => {
            inspect_cmd(&file, key.as_deref(), config.as_deref(), lang)
        }
        Cmd::Run { file, key, config } => run_cmd(&file, key.as_deref(), config.as_deref(), lang),
    }
}

fn language(args: &[String]) -> Lang {
    if let Some(index) = args.iter().position(|arg| arg == "--lang") {
        if let Some(value) = args.get(index + 1) {
            return Lang::parse(value);
        }
    }
    Lang::parse(&env::var("VMKEK_LANG").unwrap_or_else(|_| "en".into()))
}

struct ProtectArgs<'a> {
    input: &'a str,
    output: &'a str,
    virtualize: Vec<String>,
    mutate: Vec<String>,
    seed: Option<u64>,
    random_key: bool,
    deterministic: bool,
    debug_seed: bool,
    config_path: Option<&'a str>,
    virtualize_all: bool,
    mutate_all: bool,
    windows_native: bool,
    lang: Lang,
}

fn protect_cmd(args: ProtectArgs<'_>, authentication: NativeAuthArgs) -> crate::Result<i32> {
    let input = args.input;
    let output = args.output;
    let lang = args.lang;
    let windows_native = args.windows_native;
    let options = protect_options(args)?;
    let bytes = protect::read_input(input)?;
    let protected = if authentication.authenticated_lab {
        authentication.protect(&bytes, &options, windows_native)?
    } else if windows_native {
        protect::protect_windows_native(&bytes, &options)?
    } else {
        protect::protect(&bytes, &options)?
    };
    fs::write(output, &protected.bytes)?;
    let report_path = format!("{output}.report.json");
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&protected.report)?,
    )?;
    println!("{}: {output}", i18n::t(lang, "protected"));
    println!("{report_path}");
    Ok(0)
}

fn protect_options(args: ProtectArgs<'_>) -> crate::Result<Options> {
    let mut config = FileConfig::default();
    if let Some(path) = args.config_path {
        config = crate::config::load(&fs::read_to_string(path)?)?;
    }
    let random_key = if args.deterministic {
        false
    } else {
        args.random_key || config.random_key
    };
    Ok(Options {
        virtualize: chosen(args.virtualize, config.virtualize),
        mutate: chosen(args.mutate, config.mutate),
        virtualize_all: args.virtualize_all || config.virtualize_all,
        mutate_all: args.mutate_all || config.mutate_all,
        seed: args.seed.or(config.seed).unwrap_or_else(random_seed),
        random_key,
        debug_seed: args.debug_seed || config.debug_seed,
    })
}

fn chosen(flag: Vec<String>, config: Vec<String>) -> std::collections::BTreeSet<String> {
    if flag.is_empty() {
        config.into_iter().collect()
    } else {
        flag.into_iter().collect()
    }
}

fn inspect_cmd(
    input: &str,
    key: Option<&str>,
    config: Option<&str>,
    lang: Lang,
) -> crate::Result<i32> {
    let expected = match resolve_public(key, config) {
        Err(error) if !fs::metadata(input).is_ok_and(|metadata| metadata.is_file()) => {
            return Err(error);
        }
        expected => expected,
    };
    let bytes = match protect::read_input(input) {
        Ok(bytes) => bytes,
        Err(error) => return Err(expected.err().unwrap_or(error)),
    };
    authenticated::reject_for_legacy_reader(&bytes)?;
    match protect::inspect(&bytes, &expected?) {
        Ok(header) => {
            println!("{}", i18n::t(lang, "inspected"));
            println!("entry rva: {:#x}", header.original_entry);
            println!("payload: {} bytes", header.payload_len);
            Ok(0)
        }
        Err(err) => {
            eprintln!("{}: {err}", i18n::t(lang, "bad-sig"));
            Ok(1)
        }
    }
}

fn run_cmd(input: &str, key: Option<&str>, config: Option<&str>, lang: Lang) -> crate::Result<i32> {
    let bytes = fs::read(input)?;
    verify_before_run(&bytes, key, config)?;
    println!("{}", i18n::t(lang, "running"));
    let outcome = emu::run_pe(&bytes, Policy::default())?;
    print!("{}", String::from_utf8_lossy(&outcome.stdout));
    Ok(outcome.exit_code as i32)
}

fn verify_before_run(bytes: &[u8], key: Option<&str>, config: Option<&str>) -> crate::Result<()> {
    use crate::crypto::VmkekHeader;
    authenticated::reject_for_legacy_reader(bytes)?;
    match crate::crypto::locate_header(bytes)? {
        VmkekHeader::At(_) => {
            let expected = resolve_public(key, config)?;
            protect::inspect(bytes, &expected)?;
            Ok(())
        }
        VmkekHeader::Absent if entry_is_loader_prologue(bytes) => Err(crate::error::msg(
            "entry point is a vmkek loader prologue but the header is not recognizable",
        )),
        VmkekHeader::Absent if key.is_some() || config.is_some() => {
            resolve_public(key, config)?;
            Err(crate::error::msg("protected image has no vmkek header"))
        }
        VmkekHeader::Absent => Ok(()),
    }
}

fn entry_is_loader_prologue(file: &[u8]) -> bool {
    let Ok(image) = crate::pe::parse(file) else {
        return false;
    };
    let Some(code) = code_at_entry(&image) else {
        return false;
    };
    crate::loader::is_loader_prologue(code)
}

fn code_at_entry(image: &crate::pe::PeImage) -> Option<&[u8]> {
    let section = image.sections.iter().find(|section| {
        let start = section.rva as usize;
        let end = start + section.bytes.len();
        (image.entry_rva as usize) >= start && (image.entry_rva as usize) < end
    })?;
    Some(&section.bytes[(image.entry_rva - section.rva) as usize..])
}

fn resolve_public(key: Option<&str>, config_path: Option<&str>) -> crate::Result<[u8; 65]> {
    if let Some(key) = key {
        return parse_public(key);
    }
    if let Some(path) = config_path {
        let config = crate::config::load(&fs::read_to_string(path)?)?;
        if let Some(key) = config.public_key {
            return parse_public(&key);
        }
    }
    Err(crate::error::msg(
        "public key must be passed with --key or public_key in --config",
    ))
}

fn parse_public(text: &str) -> crate::Result<[u8; 65]> {
    let bytes = hex::decode(text.trim()).map_err(|err| crate::error::msg(err.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| crate::error::msg("public key must be 65 bytes"))
}

fn random_seed() -> u64 {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_is_available_in_both_languages() {
        assert_eq!(execute(&[]).unwrap(), 0);
        assert_eq!(
            execute(&["--lang".into(), "ru".into(), "--help".into()]).unwrap(),
            0
        );
        assert!(i18n::help(Lang::Ru).contains("защита"));
        assert!(i18n::help(Lang::En).contains("protect"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standalone_protect_disables_core_dumps_before_opening_input() {
        const CHILD: &str = "VMKEK_T10_DUMPABILITY_CHILD";
        if env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::tests::standalone_protect_disables_core_dumps_before_opening_input",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let missing = TempPath::new("dumpability", b"");
        fs::remove_file(&missing.0).unwrap();
        let args = ["protect".into(), missing.arg(), "-o".into(), missing.arg()];
        let get_dumpable = || {
            const PR_GET_DUMPABLE: i32 = 3;
            extern "C" {
                fn prctl(option: i32, ...) -> i32;
            }
            // SAFETY: PR_GET_DUMPABLE requires no pointers or extra arguments.
            unsafe { prctl(PR_GET_DUMPABLE, 0usize, 0usize, 0usize, 0usize) }
        };

        assert_eq!(get_dumpable(), 1);
        assert!(execute_with_process_policy(&args, false).is_err());
        assert_eq!(get_dumpable(), 1);
        assert!(execute_with_process_policy(&args, true).is_err());
        assert_eq!(get_dumpable(), 0);
    }

    #[test]
    fn bad_seed_and_unknown_flags_are_errors() {
        let err = execute(&[
            "protect".into(),
            "in".into(),
            "-o".into(),
            "out".into(),
            "--seed".into(),
            "nope".into(),
        ])
        .unwrap_err();
        assert!(!err.to_string().is_empty());
        assert!(execute(&[
            "protect".into(),
            "in".into(),
            "-o".into(),
            "out".into(),
            "--not-a-flag".into()
        ])
        .is_err());
        assert!(execute(&[
            "protect".into(),
            "in".into(),
            "-o".into(),
            "out".into(),
            "--random-key".into(),
            "--deterministic".into(),
        ])
        .is_err());
        let missing = execute(&["inspect".into(), "image.bin".into()]).unwrap_err();
        assert!(missing.to_string().contains("public key"));
    }

    fn protect_options() -> crate::protect::Options {
        crate::protect::Options {
            virtualize: std::collections::BTreeSet::new(),
            mutate: std::collections::BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed: 1,
            random_key: false,
            debug_seed: false,
        }
    }

    fn protected_image() -> &'static (Vec<u8>, String) {
        use std::sync::OnceLock;
        static IMAGE: OnceLock<(Vec<u8>, String)> = OnceLock::new();
        IMAGE.get_or_init(|| {
            let built = crate::sample::build().expect("sample");
            let protected =
                crate::protect::protect(&built.bytes, &protect_options()).expect("protect");
            (protected.bytes, protected.report.public_key)
        })
    }

    struct TempPath(std::path::PathBuf);

    impl TempPath {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vmkek-s5a-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::write(&path, bytes).expect("temp");
            Self(path)
        }

        fn arg(&self) -> String {
            self.0.display().to_string()
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn rename_vmkek(bytes: &mut [u8]) {
        let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(bytes[lfanew + 6..lfanew + 8].try_into().unwrap()) as usize;
        let optional =
            u16::from_le_bytes(bytes[lfanew + 20..lfanew + 22].try_into().unwrap()) as usize;
        let table = lfanew + 24 + optional;
        for index in 0..count {
            let off = table + index * 40;
            let name = crate::protect::section_name(1);
            if bytes[off..off + name.len()] == name.as_bytes()[..name.len()] {
                bytes[off] = b'X';
            }
        }
    }

    #[test]
    fn run_rejects_corrupt_vmkek_magic_before_emulation() {
        let (bytes, _) = protected_image();
        let at = crate::crypto::find_header(bytes).unwrap();
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0xff;
        assert!(crate::pe::parse(&corrupt)
            .unwrap()
            .sections
            .iter()
            .any(|section| section.name == crate::protect::section_name(1)));
        let path = TempPath::new("magic", &corrupt);
        let err = execute(&["run".into(), path.arg()]).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn run_does_not_ignore_a_key_on_an_unrecognized_image() {
        let (bytes, key) = protected_image();
        let at = crate::crypto::find_header(bytes).unwrap();
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0xff;
        let path = TempPath::new("magic-key", &corrupt);
        let err = execute(&["run".into(), path.arg(), "--key".into(), key.clone()]).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
        assert_ne!(
            err.to_string(),
            "run needs --key or public_key in --config for a protected image"
        );
    }

    #[test]
    fn run_rejects_a_renamed_section_whose_entry_is_the_loader() {
        let (bytes, key) = protected_image();
        let image = crate::pe::parse(bytes).unwrap();
        assert!(image
            .sections
            .iter()
            .any(|section| section.name == crate::protect::section_name(1)));
        assert!(image
            .sections
            .iter()
            .all(|section| section.name != ".vmkek"));
        let mut renamed = bytes.clone();
        rename_vmkek(&mut renamed);
        assert!(crate::crypto::find_header(&renamed).is_ok());
        let at = crate::crypto::find_header(&renamed).unwrap();
        renamed[at..at + 8].fill(0);
        assert!(crate::crypto::find_header(&renamed).is_err());
        let image = crate::pe::parse(&renamed).unwrap();
        let section = image
            .sections
            .iter()
            .find(|section| {
                image.entry_rva >= section.rva
                    && (image.entry_rva as usize) < section.rva as usize + section.bytes.len()
            })
            .unwrap();
        let off = (image.entry_rva - section.rva) as usize;
        assert_eq!(&section.bytes[off..off + 2], &[0xeb, 0x2c]);
        let path = TempPath::new("renamed", &renamed);
        let err = execute(&["run".into(), path.arg(), "--key".into(), key.clone()]).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn run_accepts_a_protected_image_when_the_key_matches() {
        let (bytes, key) = protected_image();
        let path = TempPath::new("good", bytes);
        assert_eq!(
            execute(&["run".into(), path.arg(), "--key".into(), key.clone()]).unwrap(),
            0
        );
    }

    #[test]
    fn run_allows_an_unprotected_sample_without_a_key() {
        let built = crate::sample::build().unwrap();
        let path = TempPath::new("plain", &built.bytes);
        assert_eq!(execute(&["run".into(), path.arg()]).unwrap(), 0);
    }

    #[test]
    fn run_keeps_resolve_public_error_text() {
        let (bytes, key) = protected_image();
        let path = TempPath::new("resolve", bytes);
        let short = execute(&["run".into(), path.arg(), "--key".into(), "aa".into()]).unwrap_err();
        assert!(short.to_string().contains("65 bytes"), "{short}");
        assert!(!short.to_string().contains("run needs --key"), "{short}");
        let missing = execute(&[
            "run".into(),
            path.arg(),
            "--config".into(),
            "/no/such/vmkek-s5a.toml".into(),
        ])
        .unwrap_err();
        assert!(
            !missing.to_string().contains("run needs --key"),
            "{missing}"
        );
        assert!(missing.to_string().contains("io:"), "{missing}");
        let empty = TempPath::new("empty-cfg", b"seed = 1\n");
        let bare =
            execute(&["run".into(), path.arg(), "--config".into(), empty.arg()]).unwrap_err();
        assert!(
            bare.to_string().contains("public key must be passed"),
            "{bare}"
        );
        assert!(!bare.to_string().contains("run needs --key"), "{bare}");
        let built = crate::sample::build().unwrap();
        let plain = TempPath::new("plain-key", &built.bytes);
        let err = execute(&["run".into(), plain.arg(), "--key".into(), key.clone()]).unwrap_err();
        assert!(err.to_string().contains("no vmkek header"), "{err}");
        assert!(!err.to_string().contains("run needs --key"), "{err}");
    }
}
