use serde::Deserialize;

use crate::error::{msg, Result};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub virtualize: Vec<String>,
    #[serde(default)]
    pub mutate: Vec<String>,
    #[serde(default)]
    pub virtualize_all: bool,
    #[serde(default)]
    pub mutate_all: bool,
    pub seed: Option<u64>,
    /// AEAD and signing keys from the OS RNG. Default is HKDF-SHA256 of `seed`.
    #[serde(default)]
    pub random_key: bool,
    /// Write the seed into the protect report. Off unless set.
    #[serde(default)]
    pub debug_seed: bool,
    /// P-256 public key for `inspect` and `run`, hex, 65 bytes uncompressed.
    #[serde(default)]
    pub public_key: Option<String>,
}

pub fn load(text: &str) -> Result<FileConfig> {
    toml::from_str(text).map_err(|err| msg(err.to_string()))
}
