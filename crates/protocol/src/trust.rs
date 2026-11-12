use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::{
    canonical::{decode_extensions, encode_extensions, push_field, Reader},
    public_key_id,
    signed::{Payload, Signed},
    Digest, Extension, Id, ProtocolError as Error,
};

const TRUST_BUNDLE: u16 = 8;
const MAX_REVOKED_KEYS: usize = 256;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustBundle {
    pub app_id: Id,
    pub epoch: u64,
    pub active: [u8; 65],
    pub next: Option<[u8; 65]>,
    pub revoked: Vec<Digest>,
    pub root_key_id: Digest,
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug)]
pub struct SignedTrustBundle(Signed<TrustBundle>);

impl SignedTrustBundle {
    pub fn sign(bundle: TrustBundle, root: &SigningKey) -> Result<Self> {
        Signed::sign(bundle, root).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn verify_for(
        &self,
        root: &VerifyingKey,
        app: Id,
        minimum_epoch: u64,
    ) -> Result<&TrustBundle> {
        let bundle = self.0.verify(root)?;
        if bundle.app_id != app || bundle.epoch < minimum_epoch {
            return Err(Error::Binding);
        }
        Ok(bundle)
    }
}

impl TrustBundle {
    pub fn active_key(&self) -> Result<VerifyingKey> {
        decode_key(&self.active)
    }

    /// Validate a staged-key transition against a prior authenticated bundle.
    pub fn check_successor(&self, previous: &Self) -> Result<()> {
        self.validate()?;
        if self.app_id != previous.app_id
            || self.root_key_id != previous.root_key_id
            || self.epoch <= previous.epoch
            || (self.active != previous.active && previous.next != Some(self.active))
            || previous
                .revoked
                .iter()
                .any(|key| self.revoked.binary_search(key).is_err())
        {
            return Err(Error::Binding);
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.epoch == 0 || self.epoch > i64::MAX as u64 {
            return Err(Error::Invalid);
        }
        if self.revoked.len() > MAX_REVOKED_KEYS {
            return Err(Error::Limit);
        }
        if self.revoked.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid);
        }
        let active = public_key_id(&self.active_key()?);
        let next = self
            .next
            .as_ref()
            .map(decode_key)
            .transpose()?
            .as_ref()
            .map(public_key_id);
        if active == self.root_key_id
            || self.revoked.binary_search(&active).is_ok()
            || next.is_some_and(|id| {
                id == active || id == self.root_key_id || self.revoked.binary_search(&id).is_ok()
            })
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

fn decode_key(bytes: &[u8; 65]) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Invalid)
}

impl Payload for TrustBundle {
    const KIND: u16 = TRUST_BUNDLE;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.package-trust\0";

    fn key_id(&self) -> &Digest {
        &self.root_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_field(&mut bytes, &self.app_id);
        push_field(&mut bytes, &self.epoch.to_le_bytes());
        push_field(&mut bytes, &self.active);
        push_field(
            &mut bytes,
            self.next.as_ref().map_or(&[], |key| key.as_slice()),
        );
        let mut revoked = Vec::with_capacity(2 + self.revoked.len() * 36);
        revoked.extend((self.revoked.len() as u16).to_le_bytes());
        for key in &self.revoked {
            push_field(&mut revoked, key);
        }
        push_field(&mut bytes, &revoked);
        push_field(&mut bytes, &self.root_key_id);
        encode_extensions(&mut bytes, &self.extensions)?;
        Ok(bytes)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut bytes = Reader::new(body);
        let app_id = bytes.fixed()?;
        let epoch = bytes.field_u64()?;
        let active = bytes.fixed()?;
        let next = match bytes.field(65)? {
            [] => None,
            key => Some(key.try_into().map_err(|_| Error::Invalid)?),
        };
        let mut revoked = Reader::new(bytes.field(2 + MAX_REVOKED_KEYS * 36)?);
        let count = revoked.u16()? as usize;
        if count > MAX_REVOKED_KEYS {
            return Err(Error::Limit);
        }
        let keys = (0..count)
            .map(|_| revoked.fixed())
            .collect::<Result<Vec<_>>>()?;
        revoked.finish()?;
        let bundle = Self {
            app_id,
            epoch,
            active,
            next,
            revoked: keys,
            root_key_id: bytes.fixed()?,
            extensions: decode_extensions(&mut bytes)?,
        };
        bytes.finish()?;
        bundle.validate()?;
        Ok(bundle)
    }
}
