//! Shared cryptographic types for authenticated modules.

use p256::elliptic_curve::zeroize::Zeroizing;
use rand::{rngs::OsRng, RngCore};

use crate::error::{msg, Result};

use super::{hkdf_sha256, AEAD_KEY_LEN};

const SCOPE_DOMAIN: &[u8] = b"vmkek.module.block-scope.v2";
const BLOCK_DOMAIN: &[u8] = b"vmkek.module.block-key.v2";

/// Secret material for a build. It has no layout seed or public serialization.
pub struct MasterSecret(Zeroizing<[u8; AEAD_KEY_LEN]>);

impl MasterSecret {
    /// Create a fresh, independent 256-bit secret using the OS RNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(os_random()?))
    }

    /// Restrict key material to the stated app, build, function, generation, level, and purpose.
    pub fn scope(&self, binding: BlockScope) -> Result<ScopeSecret> {
        if !(1..=4).contains(&binding.level) {
            return Err(msg("unsupported authenticated block level"));
        }
        let mut key = Zeroizing::new([0; AEAD_KEY_LEN]);
        hkdf_sha256(
            self.0.as_ref(),
            SCOPE_DOMAIN,
            &binding.bytes(),
            key.as_mut(),
        )?;
        Ok(ScopeSecret { key, binding })
    }
}

fn os_random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| msg("OS entropy unavailable"))?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockPurpose {
    Payload = 1,
    Bytecode = 2,
    Dispatcher = 3,
}

/// Identifiers are fixed-width opaque bytes. Their order is part of key separation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockScope {
    pub app: [u8; 16],
    pub build: [u8; 16],
    pub function: [u8; 16],
    pub generation: [u8; 16],
    pub level: u8,
    pub purpose: BlockPurpose,
}

impl BlockScope {
    /// Choose fresh CSPRNG IDs for a new artifact and generation.
    pub fn for_new_build(
        app: [u8; 16],
        function: [u8; 16],
        level: u8,
        purpose: BlockPurpose,
    ) -> Result<Self> {
        Ok(Self {
            app,
            build: *os_random()?,
            function,
            generation: *os_random()?,
            level,
            purpose,
        })
    }

    fn bytes(self) -> [u8; 66] {
        let mut bytes = [0; 66];
        bytes[..16].copy_from_slice(&self.app);
        bytes[16..32].copy_from_slice(&self.build);
        bytes[32..48].copy_from_slice(&self.function);
        bytes[48..64].copy_from_slice(&self.generation);
        bytes[64] = self.level;
        bytes[65] = self.purpose as u8;
        bytes
    }
}

/// Scoped key material. Keep it within the authorized build or runtime.
pub struct ScopeSecret {
    key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    binding: BlockScope,
}

impl ScopeSecret {
    /// The scope attached to this key.
    #[must_use]
    pub fn binding(&self) -> BlockScope {
        self.binding
    }

    /// Material for the legacy VM representation inside an authenticated bootstrap.
    /// The stream remains an encoding, and this namespace is separate from the AEAD key.
    pub(crate) fn vm_encoding_material<const N: usize>(
        &self,
    ) -> Result<(Zeroizing<[u8; AEAD_KEY_LEN]>, [u8; N])> {
        const DOMAIN: &[u8] = b"vmkek.module.vm-encoding.v2";
        let mut key = Zeroizing::new([0; AEAD_KEY_LEN]);
        let mut nonce = [0; N];
        hkdf_sha256(self.key.as_ref(), DOMAIN, b"key", key.as_mut())?;
        hkdf_sha256(self.key.as_ref(), DOMAIN, b"nonce", &mut nonce)?;
        Ok((key, nonce))
    }

    fn block_key(&self, salt: &[u8; 32], sequence: u64) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
        let mut info = [0; BLOCK_DOMAIN.len() + size_of::<u64>()];
        info[..BLOCK_DOMAIN.len()].copy_from_slice(BLOCK_DOMAIN);
        info[BLOCK_DOMAIN.len()..].copy_from_slice(&sequence.to_le_bytes());
        let mut key = Zeroizing::new([0; AEAD_KEY_LEN]);
        hkdf_sha256(self.key.as_ref(), salt, &info, key.as_mut())?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests;

mod bootstrap;
pub use bootstrap::*;
