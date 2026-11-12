//! x86-64 instruction-set census. L0 records status; it does not extend the lifter.

pub mod census;
mod class;
pub mod close;
mod cpuid_host;

pub(crate) use class::encoding_outside_user_x64;
