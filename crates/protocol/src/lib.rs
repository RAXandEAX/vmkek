//! Canonical R05 protocol objects and the bounded local Lab program contract.

pub mod access_command;
mod canonical;
mod descriptor;
pub mod detection;
mod generation;
mod identity;
pub mod lab;
mod module_open;
mod operation;
mod package;
mod recovery;
mod session;
pub mod session_observation;
mod signed;
mod trust;

pub use descriptor::{
    Budgets, Capability, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    R06_FUSION_CAPABILITY, R07_MIXED_REGIONS_CAPABILITY,
};
pub use generation::{
    GenerationChoice, GenerationOffer, SignedGenerationChoice, GENERATION_CHOICE_BYTES,
    GENERATION_COPY_INPUT, GENERATION_OFFER_BYTES, GENERATION_REGISTER, GENERATION_STACK,
};
#[cfg(windows)]
pub use identity::windows_cng::{CngSoftwareError, CngSoftwareKey};
pub use identity::{DeviceTrust, EnrollmentChallenge};
pub use lab::{Execution, ExecutionControl, Scalar, VerifiedProgram, VmError, MAX_SCALAR_ARGS};
pub use module_open::{
    decode_module_key, encode_module_key, ModuleOpen, MODULE_KEY_RECEIPT_BYTES, MODULE_OPEN_BYTES,
};
pub use operation::{
    OperationReceipt, SampleJob, SampleOperationRequest, SignedOperationReceipt,
    SAMPLE_JOB_RECEIPT_OPERATION, SAMPLE_OPERATION_RECEIPT_BYTES, SAMPLE_OPERATION_REQUEST_BYTES,
};
pub use package::{ModuleFetch, PackageFrame, MODULE_FETCH_BYTES};
pub use recovery::{
    RecoveryCheckpoint, RecoveryScope, SignedRecoveryCheckpoint, RECOVERY_SNAPSHOT_VERSION,
};
pub use session::{
    SessionChallenge, SessionIntent, SessionOperation, SESSION_CHALLENGE_BYTES,
    SESSION_CHALLENGE_EXTENSION, SESSION_HEARTBEAT_MS, SESSION_INTENT_BYTES, SESSION_PROOF_BYTES,
};
pub use signed::{
    public_key_id, GrantBinding, GrantExpectation, GrantPayload, ModuleExpectation, ModuleManifest,
    ModulePurpose, Permission, PermissionKind, SessionGrant, SessionGrantExpectation,
    SignedModuleManifest,
};

pub use trust::{SignedTrustBundle, TrustBundle};

pub const SCHEMA_VERSION: u16 = 1;
pub const ABI_VERSION: u16 = 1;
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_VM_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ACTIVE_CONTEXTS: usize = 32;
pub const MAX_CALL_DEPTH: u8 = 32;
pub const MAX_FUEL: u64 = 10_000_000;
pub const MAX_DEADLINE_MS: u32 = 5_000;
pub const MAX_GRANT_LIFETIME_MS: u32 = 30_000;

pub type Id = [u8; 16];
pub type Digest = [u8; 32];

/// A canonical v1 extension. No required extension IDs are defined in v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub id: u16,
    pub required: bool,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported schema version")]
    Version,
    #[error("unexpected envelope type")]
    Type,
    #[error("invalid field or encoding")]
    Invalid,
    #[error("size or resource limit exceeded")]
    Limit,
    #[error("unknown mandatory field or capability")]
    UnknownMandatory,
    #[error("signature or pinned key identifier mismatch")]
    Signature,
    #[error("verified object does not match the expected binding")]
    Binding,
    #[error("validity window does not admit this time")]
    Expired,
}
