use std::collections::BTreeSet;
use std::fs;

use vmkek::crypto::VmkekHeader;
use vmkek::emu::{self, Policy};
use vmkek::error::{msg, Result};
use vmkek::i18n::Lang;
use vmkek::protect::{self, Options};

/// Form state for the shell. Actions write files and the on-screen report.
#[derive(Clone, Debug)]
pub struct App {
    pub input: String,
    pub output: String,
    pub seed: String,
    pub virtualize: String,
    pub mutate: String,
    pub virtualize_all: bool,
    pub mutate_all: bool,
    pub public_key: String,
    pub lang: Lang,
    pub status: String,
    pub report: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input: String::new(),
            output: String::new(),
            seed: String::new(),
            virtualize: String::new(),
            mutate: String::new(),
            virtualize_all: false,
            mutate_all: false,
            public_key: String::new(),
            lang: Lang::En,
            status: String::new(),
            report: String::new(),
        }
    }
}

impl App {
    /// Read `input`, call [`protect::protect`], write `output` and the JSON report.
    pub fn protect(&mut self) {
        match self.protect_inner() {
            Ok(()) => self.status = vmkek::i18n::t(self.lang, "protected").to_string(),
            Err(err) => {
                self.report.clear();
                self.status = err.to_string();
            }
        }
    }

    /// Read a report from the input path and display its unverified evidence statuses.
    pub fn open_report(&mut self) {
        match self.read_report() {
            Ok(report) => {
                self.report = report;
                self.status.clear();
            }
            Err(err) => {
                self.report.clear();
                self.status = err.to_string();
            }
        }
    }

    fn read_report(&self) -> Result<String> {
        let path = required(self.input.trim(), "report input path is required")?;
        vmkek::report::view_json(&fs::read_to_string(path)?)
    }

    /// Inspect the protected image with [`protect::inspect`].
    pub fn inspect(&mut self) {
        let bytes = match self.read_subject() {
            Ok(bytes) => bytes,
            Err(err) => {
                self.status = err.to_string();
                return;
            }
        };
        let key = match self.require_key() {
            Ok(key) => key,
            Err(err) => {
                self.status = err.to_string();
                return;
            }
        };
        match protect::inspect(&bytes, &key) {
            Ok(header) => {
                self.report = format!(
                    "entry rva: {:#x}\npayload: {} bytes",
                    header.original_entry, header.payload_len
                );
                self.status = vmkek::i18n::t(self.lang, "inspected").to_string();
            }
            Err(err) => {
                self.status = format!("{}: {err}", vmkek::i18n::t(self.lang, "bad-sig"));
            }
        }
    }

    /// Verify a protected image, then call [`emu::run_pe`].
    pub fn run(&mut self) {
        match self.run_inner() {
            Ok(outcome) => {
                self.report = String::from_utf8_lossy(&outcome.stdout).into_owned();
                self.status = format!(
                    "{}: {}",
                    vmkek::i18n::t(self.lang, "running"),
                    outcome.exit_code
                );
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn protect_inner(&mut self) -> Result<()> {
        let input = required(self.input.trim(), "input and output paths are required")?.to_string();
        let output =
            required(self.output.trim(), "input and output paths are required")?.to_string();
        let options = protect_options(self)?;
        let bytes = protect::read_input(input)?;
        let protected = protect::protect(&bytes, &options)?;
        fs::write(&output, &protected.bytes)?;
        let pretty = serde_json::to_string_pretty(&protected.report)?;
        fs::write(format!("{output}.report.json"), &pretty)?;
        self.public_key = protected.report.public_key.clone();
        self.report = pretty;
        Ok(())
    }

    fn run_inner(&mut self) -> Result<emu::Outcome> {
        let bytes = self.read_subject()?;
        let key = self.key()?;
        verify_before_run(&bytes, key)?;
        emu::run_pe(&bytes, Policy::default())
    }

    fn read_subject(&self) -> Result<Vec<u8>> {
        Ok(fs::read(self.subject()?)?)
    }

    /// Inspect and run read the output path when it is set, otherwise the input.
    fn subject(&self) -> Result<&str> {
        let output = self.output.trim();
        let path = if output.is_empty() {
            self.input.trim()
        } else {
            output
        };
        required(path, "input and output paths are required")
    }

    fn require_key(&self) -> Result<[u8; 65]> {
        self.key()?
            .ok_or_else(|| msg("public key must be passed with --key or public_key in --config"))
    }

    fn key(&self) -> Result<Option<[u8; 65]>> {
        let text = self.public_key.trim();
        if text.is_empty() {
            return Ok(None);
        }
        Ok(Some(parse_public(text)?))
    }
}

fn protect_options(app: &App) -> Result<Options> {
    let seed = app
        .seed
        .trim()
        .parse::<u64>()
        .map_err(|_| msg("seed must be an integer"))?;
    Ok(Options {
        virtualize: split_list(&app.virtualize),
        mutate: split_list(&app.mutate),
        virtualize_all: app.virtualize_all,
        mutate_all: app.mutate_all,
        seed,
        random_key: false,
        debug_seed: false,
    })
}

fn split_list(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn required<'a>(text: &'a str, error: &str) -> Result<&'a str> {
    if text.is_empty() {
        Err(msg(error))
    } else {
        Ok(text)
    }
}

fn parse_public(text: &str) -> Result<[u8; 65]> {
    let bytes = hex::decode(text.trim()).map_err(|err| msg(err.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| msg("public key must be 65 bytes"))
}

/// Same recognition gate the CLI uses before [`emu::run_pe`].
fn verify_before_run(bytes: &[u8], key: Option<[u8; 65]>) -> Result<()> {
    match vmkek::crypto::locate_header(bytes)? {
        VmkekHeader::At(_) => {
            let expected = key.ok_or_else(|| {
                msg("public key must be passed with --key or public_key in --config")
            })?;
            protect::inspect(bytes, &expected)?;
            Ok(())
        }
        VmkekHeader::Absent if entry_is_loader_prologue(bytes) => Err(msg(
            "entry point is a vmkek loader prologue but the header is not recognizable",
        )),
        VmkekHeader::Absent if key.is_some() => Err(msg("protected image has no vmkek header")),
        VmkekHeader::Absent => Ok(()),
    }
}

fn entry_is_loader_prologue(file: &[u8]) -> bool {
    let Ok(image) = vmkek::pe::parse(file) else {
        return false;
    };
    let Some(code) = code_at_entry(&image) else {
        return false;
    };
    vmkek::loader::is_loader_prologue(code)
}

fn code_at_entry(image: &vmkek::pe::PeImage) -> Option<&[u8]> {
    let section = image.sections.iter().find(|section| {
        let start = section.rva as usize;
        let end = start + section.bytes.len();
        (image.entry_rva as usize) >= start && (image.entry_rva as usize) < end
    })?;
    Some(&section.bytes[(image.entry_rva - section.rva) as usize..])
}
