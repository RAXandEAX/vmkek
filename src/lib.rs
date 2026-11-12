//! vmkek protects PE32+ images, including native-subsystem drivers, and fixed
//! ELF64 x86-64 executables, with obfuscation, virtualization, and mutation.

#[cfg(not(kani))]
pub mod adversary;
#[cfg(not(kani))]
pub mod agent;
#[cfg(not(kani))]
pub mod antidebug;
pub mod check;
#[cfg(not(kani))]
pub mod cli;
#[cfg(not(kani))]
pub mod config;
#[cfg(not(kani))]
pub mod crypto;
#[cfg(not(kani))]
pub mod driver;
#[cfg(not(kani))]
pub mod early;
#[cfg(not(kani))]
pub mod elf;
#[cfg(not(kani))]
pub mod emu;
pub mod error;
pub mod flags;
#[cfg(not(kani))]
pub mod gp;
#[cfg(not(kani))]
pub mod i18n;
/// S1 catalog alone, so `cargo kani` does not compile the rest of `obf`.
#[cfg(kani)]
#[path = "obf/identities.rs"]
pub(crate) mod identities;
pub mod ir;
#[cfg(not(kani))]
pub mod isa;
#[cfg(not(kani))]
pub mod lift;
#[cfg(not(kani))]
pub mod loader;
#[cfg(not(kani))]
pub mod mutate;
#[cfg(not(kani))]
pub mod obf;
#[cfg(not(kani))]
pub mod pe;
#[cfg(not(kani))]
pub mod proof;
#[cfg(not(kani))]
pub mod protect;
#[cfg(not(kani))]
pub mod report;
#[cfg(not(kani))]
pub mod sample;
#[cfg(not(kani))]
pub mod secret;
#[cfg(not(kani))]
pub mod sse;
#[cfg(not(kani))]
pub mod stub;
#[cfg(not(kani))]
pub mod syscall;
#[cfg(not(kani))]
pub mod trace;
#[cfg(not(kani))]
pub mod unwind;
#[cfg(not(kani))]
pub mod vm;
#[cfg(not(kani))]
pub mod watermark;
#[cfg(not(kani))]
pub mod x87;

pub use error::{Error, Result};
