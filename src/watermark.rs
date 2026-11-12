//! Signed customer identifiers for build artifacts. Add the watermark before
//! Authenticode signing. The manufacturer public key comes from the verifier.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::crypto::sha256;
use crate::error::{exact_bytes, msg, Result};

const MAGIC: &[u8; 8] = b"VMKWMK01";
const CUSTOMER_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const TRAILER_LEN: usize = MAGIC.len() + CUSTOMER_LEN + SIGNATURE_LEN;
const DOMAIN: &[u8] = b"vmkek.watermark.v1.sig";

/// Append a signed, opaque customer identifier to an unsigned artifact.
/// The signing key is never serialized into the artifact.
pub fn append(file: &mut Vec<u8>, customer_id: [u8; CUSTOMER_LEN], key: &SigningKey) -> Result<()> {
    if trailer(file).is_some() {
        return Err(msg("artifact already contains a vmkek watermark"));
    }
    let signature: Signature = key.sign(&message(file, &customer_id));
    file.try_reserve(TRAILER_LEN)
        .map_err(|_| msg("could not reserve watermark trailer"))?;
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&customer_id);
    file.extend_from_slice(&signature.to_bytes());
    Ok(())
}

/// Verify the watermark against an independently trusted manufacturer key.
pub fn verify(file: &[u8], key: &VerifyingKey) -> Result<[u8; CUSTOMER_LEN]> {
    let (artifact, fields) = trailer(file).ok_or_else(|| msg("missing vmkek watermark"))?;
    let (customer, signature) = fields.split_at(CUSTOMER_LEN);
    let customer_id = exact_bytes(customer)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| msg("invalid watermark signature"))?;
    key.verify(&message(artifact, &customer_id), &signature)
        .map_err(|_| msg("watermark does not match this artifact and manufacturer"))?;
    Ok(customer_id)
}

fn trailer(file: &[u8]) -> Option<(&[u8], &[u8])> {
    let split = file.len().checked_sub(TRAILER_LEN)?;
    let (artifact, trailer) = file.split_at(split);
    Some((artifact, trailer.strip_prefix(MAGIC)?))
}

fn message(file: &[u8], customer: &[u8; CUSTOMER_LEN]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + 64);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(customer);
    message.extend_from_slice(&sha256(file));
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_watermark_is_bound_to_build_and_customer() {
        let key = SigningKey::from_slice(&[3; 32]).unwrap();
        let other = SigningKey::from_slice(&[4; 32]).unwrap();
        let original = crate::sample::build().unwrap().bytes;
        let mut artifact = original.clone();
        append(&mut artifact, [5; 32], &key).unwrap();
        assert_eq!(verify(&artifact, key.verifying_key()).unwrap(), [5; 32]);
        assert!(verify(&artifact, other.verifying_key()).is_err());
        assert!(append(&mut artifact, [6; 32], &key).is_err());

        let at = original.len() + MAGIC.len();
        artifact[at] ^= 1;
        assert!(verify(&artifact, key.verifying_key()).is_err());
        artifact[at] ^= 1;
        artifact[0] ^= 1;
        assert!(verify(&artifact, key.verifying_key()).is_err());
        assert!(verify(&artifact[..artifact.len() - 1], key.verifying_key()).is_err());
    }
}
