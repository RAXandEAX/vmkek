//! R09 online license and device enrollment.
pub mod access;
pub mod generation;
mod http;
pub mod operations;
pub mod packages;
pub mod recovery;
pub mod session;
mod store;

pub use http::router;
pub use store::{ActivationToken, DeviceIdentity, IdentityError, IdentityStore, RevokeReason};

pub const DEFAULT_DEVICE_LIMIT: i32 = 1;
pub const ENROLLMENTS_PER_HOUR: i64 = 5;
pub const CHALLENGE_TTL_MS: i64 = 30_000;
