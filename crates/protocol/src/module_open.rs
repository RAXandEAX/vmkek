use p256::ecdsa::VerifyingKey;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES},
    session::{prehash, verify},
    Digest, ModuleFetch, ProtocolError as Error, MODULE_FETCH_BYTES, SESSION_PROOF_BYTES,
};

const OPEN: u16 = 11;
const RECEIPT: u16 = 12;
pub const MODULE_OPEN_BYTES: usize = HEADER_BYTES + 4 + MODULE_FETCH_BYTES + 4 + 32;
pub const MODULE_KEY_RECEIPT_BYTES: usize = HEADER_BYTES + 3 * (4 + 32);
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleOpen {
    pub fetch: ModuleFetch,
    pub manifest_sha256: Digest,
}

impl ModuleOpen {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(MODULE_OPEN_BYTES - HEADER_BYTES);
        push_field(&mut body, &self.fetch.encode()?);
        push_field(&mut body, &self.manifest_sha256);
        envelope(OPEN, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, OPEN, 0)?;
        let mut reader = Reader::new(&encoded[HEADER_BYTES..]);
        let fetch = ModuleFetch::decode(reader.field(MODULE_FETCH_BYTES)?)?;
        let manifest_sha256 = reader.fixed()?;
        reader.finish()?;
        Ok(Self {
            fetch,
            manifest_sha256,
        })
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(b"vmkek.protocol.v1.module-open\0", &self.encode()?))
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SESSION_PROOF_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }
}

/// Secret response storage is zeroized when dropped.
pub fn encode_module_key(
    request_sha256: &Digest,
    manifest_sha256: &Digest,
    key: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MODULE_KEY_RECEIPT_BYTES));
    bytes.extend(crate::SCHEMA_VERSION.to_le_bytes());
    bytes.extend(RECEIPT.to_le_bytes());
    bytes.extend(((MODULE_KEY_RECEIPT_BYTES - HEADER_BYTES) as u32).to_le_bytes());
    push_field(&mut bytes, request_sha256);
    push_field(&mut bytes, manifest_sha256);
    push_field(&mut bytes, key);
    bytes
}

pub fn decode_module_key(
    bytes: &[u8],
    expected_request: &Digest,
    expected_manifest: &Digest,
) -> Result<Zeroizing<[u8; 32]>> {
    let (encoded, _) = split_envelope(bytes, RECEIPT, 0)?;
    let mut reader = Reader::new(&encoded[HEADER_BYTES..]);
    if &reader.fixed::<32>()? != expected_request || &reader.fixed::<32>()? != expected_manifest {
        return Err(Error::Binding);
    }
    let key = reader.field(32)?;
    reader.finish()?;
    if key.len() != 32 {
        return Err(Error::Invalid);
    }
    let mut owned = Zeroizing::new([0; 32]);
    owned.copy_from_slice(key);
    Ok(owned)
}
