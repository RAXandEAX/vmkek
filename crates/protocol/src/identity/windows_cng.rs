//! Ephemeral software proof of possession using the Windows CNG primitive provider.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptExportKey, BCryptFinalizeKeyPair,
    BCryptGenerateKeyPair, BCryptOpenAlgorithmProvider, BCryptSignHash, BCRYPT_ALG_HANDLE,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    BCRYPT_KEY_HANDLE, MS_PRIMITIVE_PROVIDER,
};

use super::{DeviceTrust, EnrollmentChallenge};

/// A non-persistent P-256 signing key in the Microsoft software provider.
pub struct CngSoftwareKey {
    key: KeyHandle,
    _algorithm: AlgorithmHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CngSoftwareError {
    #[error("Windows CNG operation failed with NTSTATUS {0:#010x}")]
    Native(i32),
    #[error("Windows CNG returned an unexpected P-256 key or signature layout")]
    Layout,
    #[error("challenge does not admit this software key")]
    Binding,
}

struct KeyHandle(BCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SAFETY: This guard owns the key returned by BCryptGenerateKeyPair.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

struct AlgorithmHandle(BCRYPT_ALG_HANDLE);

impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        // SAFETY: This guard owns the provider opened by BCryptOpenAlgorithmProvider.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

impl CngSoftwareKey {
    pub fn generate() -> Result<Self, CngSoftwareError> {
        let mut algorithm = null_mut();
        // SAFETY: The output pointer is writable and both identifiers are static wide strings.
        check(unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algorithm,
                BCRYPT_ECDSA_P256_ALGORITHM,
                MS_PRIMITIVE_PROVIDER,
                0,
            )
        })?;
        let algorithm = AlgorithmHandle(algorithm);
        let mut key = null_mut();
        // SAFETY: The provider is live and the output pointer is writable.
        check(unsafe { BCryptGenerateKeyPair(algorithm.0, &mut key, 256, 0) })?;
        let key = KeyHandle(key);
        // SAFETY: The owned key is live and has not yet been finalized.
        check(unsafe { BCryptFinalizeKeyPair(key.0, 0) })?;
        Ok(Self {
            key,
            _algorithm: algorithm,
        })
    }

    pub fn public_key(&self) -> Result<[u8; 65], CngSoftwareError> {
        let mut blob = [0; 72];
        let mut written = 0;
        // SAFETY: The key is live and the output buffer and length pointer are writable.
        check(unsafe {
            BCryptExportKey(
                self.key.0,
                null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut written,
                0,
            )
        })?;
        if written as usize != blob.len()
            || blob[..4] != BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes()
            || blob[4..8] != 32u32.to_le_bytes()
        {
            return Err(CngSoftwareError::Layout);
        }
        let mut sec1 = [4; 65];
        sec1[1..].copy_from_slice(&blob[8..]);
        Ok(sec1)
    }

    pub fn sign_challenge(
        &self,
        challenge: &EnrollmentChallenge,
    ) -> Result<[u8; 64], CngSoftwareError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.public_key()?)
            .map_err(|_| CngSoftwareError::Layout)?;
        if challenge.trust != DeviceTrust::Software
            || challenge.key_id != crate::public_key_id(&key)
        {
            return Err(CngSoftwareError::Binding);
        }
        let digest = challenge
            .signature_digest()
            .map_err(|_| CngSoftwareError::Binding)?;
        let mut signature = [0; 64];
        let mut written = 0;
        // SAFETY: The key is live. ECDSA uses no padding. The input and output lengths
        // correspond to the supplied SHA-256 digest and fixed-width signature buffers.
        check(unsafe {
            BCryptSignHash(
                self.key.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut written,
                0,
            )
        })?;
        if written as usize != signature.len() {
            return Err(CngSoftwareError::Layout);
        }
        Ok(signature)
    }
}

fn check(status: i32) -> Result<(), CngSoftwareError> {
    if status < 0 {
        Err(CngSoftwareError::Native(status))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{public_key_id, ProtocolError};
    use p256::ecdsa::VerifyingKey;

    #[test]
    fn windows_software_proof_interoperates_with_canonical_enrollment() {
        let signer = CngSoftwareKey::generate().unwrap();
        let public_key = signer.public_key().unwrap();
        let key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        let challenge = EnrollmentChallenge {
            app_id: [1; 16],
            license_id: [2; 16],
            challenge_id: [3; 16],
            nonce: [4; 32],
            key_id: public_key_id(&key),
            trust: DeviceTrust::Software,
            expires_unix_ms: 987_654,
        };
        let canonical = challenge.encode().unwrap();
        let mut challenge = EnrollmentChallenge::decode(&canonical).unwrap();
        let proof = signer.sign_challenge(&challenge).unwrap();
        assert_eq!(challenge.verify_proof(&public_key, &proof), Ok(()));
        challenge.nonce[0] ^= 1;
        assert_eq!(
            challenge.verify_proof(&public_key, &proof),
            Err(ProtocolError::Signature)
        );
        challenge.trust = DeviceTrust::TpmAttested;
        assert_eq!(
            signer.sign_challenge(&challenge),
            Err(CngSoftwareError::Binding)
        );
        challenge.trust = DeviceTrust::Software;
        challenge.key_id[0] ^= 1;
        assert_eq!(
            signer.sign_challenge(&challenge),
            Err(CngSoftwareError::Binding)
        );
    }
}
