//! Opt-in startup integrity in the emulator. The verifier supplies the
//! expected lists from a trusted output image and loader configuration.

use crate::{crypto, pe, Result};

use super::Machine;

/// Startup policy captured before an image is handed to the process model.
#[derive(Clone, Debug)]
pub struct StartupManifest {
    tls_digest: [u8; 32],
    veh_digest: [u8; 32],
    allowed_modules: Vec<String>,
}

impl StartupManifest {
    /// Record the trusted callback order and allowed canonical module paths.
    pub fn capture(image: &pe::PeImage, veh: &[u64], allowed_modules: Vec<String>) -> Result<Self> {
        Ok(Self {
            tls_digest: digest(&pe::tls_callbacks(image)?),
            veh_digest: digest(veh),
            allowed_modules,
        })
    }
}

/// Inputs supplied by the modeled loader before callbacks execute.
#[derive(Clone, Debug)]
pub struct StartupObservation {
    pub manifest: StartupManifest,
    pub veh: Vec<u64>,
    /// Canonical full paths as reported by the modeled loader.
    pub modules: Vec<String>,
}

fn digest(entries: &[u64]) -> [u8; 32] {
    let bytes: Vec<u8> = entries
        .iter()
        .flat_map(|address| address.to_le_bytes())
        .collect();
    crypto::sha256(&bytes)
}

pub(super) fn validate(machine: &mut Machine) {
    let Some(startup) = &machine.policy.startup else {
        return;
    };
    let allowed = |module: &String| {
        startup
            .manifest
            .allowed_modules
            .iter()
            .any(|item| item.eq_ignore_ascii_case(module))
    };
    if digest(&machine.tls) != startup.manifest.tls_digest
        || digest(&startup.veh) != startup.manifest.veh_digest
        || !startup.modules.iter().all(allowed)
    {
        machine.exit_code = Some(0xDEB6);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emu::{self, Policy};

    fn with_tls(count: usize) -> pe::PeImage {
        let mut image = pe::parse(&crate::sample::build().unwrap().bytes).unwrap();
        let text = &mut image.sections[0];
        let callback = image.image_base + u64::from(text.rva) + text.bytes.len() as u64;
        text.bytes.extend(std::iter::repeat_n(0xc3, count));
        let mut tls = vec![0; 40];
        let rva = 0x3000;
        let table = image.image_base + u64::from(rva) + 40;
        tls[24..32].copy_from_slice(&table.to_le_bytes());
        for index in 0..count {
            tls.extend_from_slice(&(callback + index as u64).to_le_bytes());
        }
        tls.extend_from_slice(&0u64.to_le_bytes());
        image.sections.push(pe::Section {
            name: ".t7tls".into(),
            rva,
            bytes: tls,
            characteristics: pe::CH_RDATA,
        });
        image.tls_rva = rva;
        image.tls_size = 40;
        image
    }

    #[test]
    fn startup_manifest_is_opt_in_and_accepts_the_expected_loader() {
        let image = with_tls(2);
        let sample = pe::emit(&image).unwrap();
        let image = pe::parse(&sample).unwrap();
        let manifest = StartupManifest::capture(
            &image,
            &[0x1000, 0x1010],
            vec![r"C:\app\trusted.dll".into()],
        )
        .unwrap();
        let policy = Policy {
            startup: Some(StartupObservation {
                manifest,
                veh: vec![0x1000, 0x1010],
                modules: vec![r"C:\APP\TRUSTED.DLL".into()],
            }),
            ..Policy::default()
        };
        for policy in [Policy::default(), policy] {
            let outcome = emu::run_pe(&sample, policy).unwrap();
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(outcome.stdout, crate::sample::line().as_bytes());
        }
    }

    #[test]
    fn startup_manifest_refuses_changed_lists_before_guest_execution() {
        let image = with_tls(2);
        let veh = [0x1000, 0x1010];
        let manifest =
            StartupManifest::capture(&image, &veh, vec![r"C:\app\trusted.dll".into()]).unwrap();
        let mut reordered = image.clone();
        let callbacks = pe::tls_callbacks(&image).unwrap();
        let table = image.tls_rva + 40;
        pe::write_rva(&mut reordered, table, &callbacks[1].to_le_bytes()).unwrap();
        pe::write_rva(&mut reordered, table + 8, &callbacks[0].to_le_bytes()).unwrap();
        let default_outcome =
            emu::run_pe(&pe::emit(&reordered).unwrap(), Policy::default()).unwrap();
        assert_eq!(default_outcome.exit_code, 0);
        assert_eq!(default_outcome.stdout, crate::sample::line().as_bytes());
        for (candidate, veh, modules) in [
            (&image, vec![0x1010, 0x1000], vec![]),
            (&image, veh.to_vec(), vec![r"C:\other\trusted.dll".into()]),
            (&reordered, veh.to_vec(), vec![]),
        ] {
            let policy = Policy {
                startup: Some(StartupObservation {
                    manifest: manifest.clone(),
                    veh,
                    modules,
                }),
                ..Policy::default()
            };
            let file = pe::emit(candidate).unwrap();
            let parsed = pe::parse(&file).unwrap();
            let mut machine = emu::load(&parsed, policy).unwrap();
            machine.run().unwrap();
            assert_eq!(machine.exit_code, Some(0xDEB6));
            assert_eq!(machine.steps, 0);
            assert!(machine.stdout.is_empty());
        }
    }

    #[test]
    fn startup_manifest_accepts_a_terminated_nine_callback_table() {
        let file = pe::emit(&with_tls(9)).unwrap();
        let image = pe::parse(&file).unwrap();
        assert_eq!(pe::tls_callbacks(&image).unwrap().len(), 9);
        let manifest = StartupManifest::capture(&image, &[], vec![]).unwrap();
        let enforced = Policy {
            startup: Some(StartupObservation {
                manifest,
                veh: vec![],
                modules: vec![],
            }),
            ..Policy::default()
        };
        for policy in [Policy::default(), enforced] {
            let outcome = emu::run_pe(&file, policy).unwrap();
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(outcome.stdout, crate::sample::line().as_bytes());
        }
    }

    #[test]
    fn startup_manifest_refuses_malformed_callback_directories() {
        let capture = |image: &pe::PeImage| StartupManifest::capture(image, &[], vec![]);
        let valid = with_tls(8);
        let manifest = capture(&valid).unwrap();
        assert!(capture(&with_tls(0)).is_ok());
        let sample = crate::sample::build().unwrap();
        assert!(capture(&pe::parse(&sample.bytes).unwrap()).is_ok());

        let mut missing_terminator = valid.clone();
        let table = &mut missing_terminator.sections.last_mut().unwrap().bytes;
        table.truncate(table.len() - std::mem::size_of::<u64>());
        let mut split_table = missing_terminator.clone();
        let section = split_table.sections.last_mut().unwrap();
        let callbacks = section.bytes[40..].to_vec();
        section.bytes.resize(0x1000, 0);
        let offset = section.bytes.len() - callbacks.len();
        section.bytes[offset..].copy_from_slice(&callbacks);
        let table_va = split_table.image_base + u64::from(section.rva) + offset as u64;
        section.bytes[24..32].copy_from_slice(&table_va.to_le_bytes());
        split_table.sections.push(pe::Section {
            name: ".next".into(),
            rva: 0x4000,
            bytes: vec![0; 8],
            characteristics: pe::CH_RDATA,
        });
        let mut truncated = with_tls(0);
        truncated.tls_size = 39;
        let mut incomplete = with_tls(0);
        incomplete.tls_rva = 0;
        let mut oversized = with_tls(0);
        oversized.tls_size = u32::MAX;
        for (name, malformed) in [
            ("missing terminator", missing_terminator),
            ("terminator in another section", split_table),
            ("truncated directory", truncated),
            ("missing directory RVA", incomplete),
            ("oversized directory", oversized),
        ] {
            assert!(capture(&malformed).is_err(), "{name}");
            let policy = Policy {
                startup: Some(StartupObservation {
                    manifest: manifest.clone(),
                    veh: vec![],
                    modules: vec![],
                }),
                ..Policy::default()
            };
            let file = pe::emit(&malformed).unwrap();
            assert!(emu::run_pe(&file, policy).is_err(), "{name}");
        }
    }
}
