use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES},
    session::{prehash, verify},
    signed::{Payload, Signed},
    Digest, GrantBinding, Id, ProtocolError as Error, VmForm, SESSION_PROOF_BYTES,
};

const OFFER: u16 = 13;
const CHOICE: u16 = 14;
pub const GENERATION_STACK: u8 = 1;
pub const GENERATION_REGISTER: u8 = 2;
pub const GENERATION_COPY_INPUT: u16 = 1;
pub const GENERATION_OFFER_BYTES: usize = 131;
pub const GENERATION_CHOICE_BYTES: usize = 461;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationOffer {
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub function_id: Id,
    pub request_id: Id,
    pub descriptor_schema: u16,
    pub descriptor_abi: u16,
    pub forms: u8,
    pub capabilities: u16,
}

impl GenerationOffer {
    fn validate(&self) -> Result<()> {
        if self.forms == 0
            || self.forms & !(GENERATION_STACK | GENERATION_REGISTER) != 0
            || self.capabilities & !GENERATION_COPY_INPUT != 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::with_capacity(GENERATION_OFFER_BYTES - HEADER_BYTES);
        for id in [
            self.app_id,
            self.build_id,
            self.device_id,
            self.function_id,
            self.request_id,
        ] {
            push_field(&mut body, &id);
        }
        push_field(&mut body, &self.descriptor_schema.to_le_bytes());
        push_field(&mut body, &self.descriptor_abi.to_le_bytes());
        push_field(&mut body, &[self.forms]);
        push_field(&mut body, &self.capabilities.to_le_bytes());
        envelope(OFFER, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, OFFER, 0)?;
        let mut input = Reader::new(&encoded[HEADER_BYTES..]);
        let offer = Self {
            app_id: input.fixed()?,
            build_id: input.fixed()?,
            device_id: input.fixed()?,
            function_id: input.fixed()?,
            request_id: input.fixed()?,
            descriptor_schema: input.field_u16()?,
            descriptor_abi: input.field_u16()?,
            forms: input.field_u8()?,
            capabilities: input.field_u16()?,
        };
        input.finish()?;
        offer.validate()?;
        Ok(offer)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.generation-offer\0",
            &self.encode()?,
        ))
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SESSION_PROOF_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationChoice {
    pub offer_digest: Digest,
    pub binding: GrantBinding,
    pub function_id: Id,
    pub descriptor_sha256: Digest,
    pub manifest_sha256: Digest,
    pub module_id: Id,
    pub module_version: u64,
    pub form: VmForm,
    pub policy_epoch: u64,
    pub challenge_id: Id,
    pub nonce: Digest,
    pub signing_key_id: Digest,
}

#[derive(Clone, Debug)]
pub struct SignedGenerationChoice(Signed<GenerationChoice>);

impl SignedGenerationChoice {
    pub fn sign(choice: GenerationChoice, signer: &SigningKey) -> Result<Self> {
        Signed::sign(choice, signer).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn digest(&self) -> Digest {
        Sha256::digest(self.as_bytes()).into()
    }

    pub fn completion_digest(&self) -> Digest {
        prehash(b"vmkek.protocol.v1.generation-complete\0", self.as_bytes())
    }

    pub fn verify_for(&self, pin: &VerifyingKey) -> Result<&GenerationChoice> {
        self.0.verify(pin)
    }

    pub fn verify_completion(
        &self,
        key: &VerifyingKey,
        proof: &[u8; SESSION_PROOF_BYTES],
    ) -> Result<()> {
        verify(key, &self.completion_digest(), proof)
    }
}

impl Payload for GenerationChoice {
    const KIND: u16 = CHOICE;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.generation-choice\0";
    fn key_id(&self) -> &Digest {
        &self.signing_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body =
            Vec::with_capacity(GENERATION_CHOICE_BYTES - HEADER_BYTES - SESSION_PROOF_BYTES);
        push_field(&mut body, &self.offer_digest);
        self.binding.encode(&mut body);
        push_field(&mut body, &self.function_id);
        push_field(&mut body, &self.descriptor_sha256);
        push_field(&mut body, &self.manifest_sha256);
        push_field(&mut body, &self.module_id);
        push_field(&mut body, &self.module_version.to_le_bytes());
        push_field(&mut body, &[self.form as u8]);
        push_field(&mut body, &self.policy_epoch.to_le_bytes());
        push_field(&mut body, &self.challenge_id);
        push_field(&mut body, &self.nonce);
        push_field(&mut body, &self.signing_key_id);
        Ok(body)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut input = Reader::new(body);
        let choice = Self {
            offer_digest: input.fixed()?,
            binding: GrantBinding::decode(&mut input)?,
            function_id: input.fixed()?,
            descriptor_sha256: input.fixed()?,
            manifest_sha256: input.fixed()?,
            module_id: input.fixed()?,
            module_version: input.field_u64()?,
            form: input.field_u8()?.try_into()?,
            policy_epoch: input.field_u64()?,
            challenge_id: input.fixed()?,
            nonce: input.fixed()?,
            signing_key_id: input.fixed()?,
        };
        input.finish()?;
        choice.validate()?;
        Ok(choice)
    }
}

impl GenerationChoice {
    fn validate(&self) -> Result<()> {
        if self.binding.session_id == [0; 16]
            || self.binding.generation_id == [0; 16]
            || !(1..=i64::MAX as u64).contains(&self.module_version)
            || !(1..=i64::MAX as u64).contains(&self.policy_epoch)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
