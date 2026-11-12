use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported instruction at rva {rva:#x}: {text}")]
    Unsupported { rva: u64, text: String },
    #[error("signature verification failed")]
    BadSignature,
    #[error("integrity check failed")]
    Integrity,
    #[error("debugger detected")]
    Debugger,
}

pub fn msg(text: impl Into<String>) -> Error {
    Error::Msg(text.into())
}

pub fn exact_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| msg("short read"))
}
