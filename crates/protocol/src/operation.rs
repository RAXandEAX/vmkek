use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES},
    session::{prehash, verify},
    signed::{Payload, Signed},
    Digest, GrantBinding, Id, ProtocolError as Error, SESSION_PROOF_BYTES,
};

const REQUEST: u16 = 18;
const RECEIPT: u16 = 19;
const SAMPLE_PURPOSE: u8 = 1;
pub const SAMPLE_JOB_RECEIPT_OPERATION: Id = *b"sample-job-v1\0\0\0";
pub const SAMPLE_OPERATION_REQUEST_BYTES: usize = 206;
pub const SAMPLE_OPERATION_RECEIPT_BYTES: usize = 391;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleJob {
    pub job_id: Id,
    pub units: u16,
}

impl SampleJob {
    fn validate(&self) -> Result<()> {
        if self.job_id == [0; 16] || !(1..=128).contains(&self.units) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// The fixed calculation authorized by this operation.
    pub fn receipt_value(&self) -> u64 {
        u64::from(self.units) * 7
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleOperationRequest {
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub session_id: Id,
    pub generation_id: Id,
    pub function_id: Id,
    pub operation_id: Id,
    pub request_id: Id,
    pub sequence: u64,
    pub job: SampleJob,
}

impl SampleOperationRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::with_capacity(SAMPLE_OPERATION_REQUEST_BYTES - HEADER_BYTES);
        for id in [
            self.app_id,
            self.build_id,
            self.device_id,
            self.session_id,
            self.generation_id,
            self.function_id,
            self.operation_id,
            self.request_id,
        ] {
            push_field(&mut body, &id);
        }
        push_field(&mut body, &self.sequence.to_le_bytes());
        push_field(&mut body, &self.job.job_id);
        push_field(&mut body, &self.job.units.to_le_bytes());
        envelope(REQUEST, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (bytes, _) = split_envelope(bytes, REQUEST, 0)?;
        let mut input = Reader::new(&bytes[HEADER_BYTES..]);
        let request = Self {
            app_id: input.fixed()?,
            build_id: input.fixed()?,
            device_id: input.fixed()?,
            session_id: input.fixed()?,
            generation_id: input.fixed()?,
            function_id: input.fixed()?,
            operation_id: input.fixed()?,
            request_id: input.fixed()?,
            sequence: input.field_u64()?,
            job: SampleJob {
                job_id: input.fixed()?,
                units: input.field_u16()?,
            },
        };
        input.finish()?;
        request.validate()?;
        Ok(request)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }
    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.sample-operation-request\0",
            &self.encode()?,
        ))
    }
    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SESSION_PROOF_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }

    fn validate(&self) -> Result<()> {
        if self.session_id == [0; 16]
            || self.request_id == [0; 16]
            || !(1..=i64::MAX as u64).contains(&self.sequence)
        {
            return Err(Error::Invalid);
        }
        self.job.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationReceipt {
    pub binding: GrantBinding,
    pub function_id: Id,
    pub operation_id: Id,
    pub request_id: Id,
    pub request_digest: Digest,
    pub sequence: u64,
    pub policy_epoch: u64,
    pub job: SampleJob,
    pub value: u64,
    pub signing_key_id: Digest,
}

#[derive(Clone, Debug)]
pub struct SignedOperationReceipt(Signed<OperationReceipt>);

impl SignedOperationReceipt {
    pub fn sign(receipt: OperationReceipt, key: &SigningKey) -> Result<Self> {
        Signed::sign(receipt, key).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn verify_for(
        &self,
        pin: &VerifyingKey,
        request: &SampleOperationRequest,
        binding: GrantBinding,
        policy_epoch: u64,
    ) -> Result<&OperationReceipt> {
        let result = self.0.verify(pin)?;
        if result.binding != binding
            || result.policy_epoch != policy_epoch
            || (
                binding.app_id,
                binding.build_id,
                binding.device_id,
                binding.session_id,
                binding.generation_id,
            ) != (
                request.app_id,
                request.build_id,
                request.device_id,
                request.session_id,
                request.generation_id,
            )
            || (
                result.function_id,
                result.operation_id,
                result.request_id,
                result.sequence,
                result.job,
            ) != (
                request.function_id,
                request.operation_id,
                request.request_id,
                request.sequence,
                request.job,
            )
            || result.request_digest != request.digest()?
        {
            return Err(Error::Binding);
        }
        Ok(result)
    }
}

impl Payload for OperationReceipt {
    const KIND: u16 = RECEIPT;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.sample-operation-receipt\0";
    fn key_id(&self) -> &Digest {
        &self.signing_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body =
            Vec::with_capacity(SAMPLE_OPERATION_RECEIPT_BYTES - HEADER_BYTES - SESSION_PROOF_BYTES);
        self.binding.encode(&mut body);
        for id in [
            self.function_id,
            self.operation_id,
            self.request_id,
            self.job.job_id,
        ] {
            push_field(&mut body, &id);
        }
        push_field(&mut body, &self.request_digest);
        push_field(&mut body, &self.sequence.to_le_bytes());
        push_field(&mut body, &self.policy_epoch.to_le_bytes());
        push_field(&mut body, &self.job.units.to_le_bytes());
        push_field(&mut body, &self.value.to_le_bytes());
        push_field(&mut body, &[SAMPLE_PURPOSE]);
        push_field(&mut body, &self.signing_key_id);
        Ok(body)
    }

    fn decode_body(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader::new(bytes);
        let binding = GrantBinding::decode(&mut input)?;
        let function_id = input.fixed()?;
        let operation_id = input.fixed()?;
        let request_id = input.fixed()?;
        let job_id = input.fixed()?;
        let request_digest = input.fixed()?;
        let sequence = input.field_u64()?;
        let policy_epoch = input.field_u64()?;
        let job = SampleJob {
            job_id,
            units: input.field_u16()?,
        };
        let value = input.field_u64()?;
        if input.field_u8()? != SAMPLE_PURPOSE {
            return Err(Error::Invalid);
        }
        let receipt = Self {
            binding,
            function_id,
            operation_id,
            request_id,
            request_digest,
            sequence,
            policy_epoch,
            job,
            value,
            signing_key_id: input.fixed()?,
        };
        input.finish()?;
        receipt.validate()?;
        Ok(receipt)
    }
}

impl OperationReceipt {
    fn validate(&self) -> Result<()> {
        if self.operation_id != SAMPLE_JOB_RECEIPT_OPERATION
            || self.value != self.job.receipt_value()
            || !(1..=i64::MAX as u64).contains(&self.sequence)
            || self.policy_epoch == 0
        {
            return Err(Error::Invalid);
        }
        self.job.validate()
    }
}
