use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{envelope, split_envelope, Reader, HEADER_BYTES},
    session::{prehash, sign, verify},
    Digest, Id, ProtocolError as Error, SESSION_PROOF_BYTES,
};

#[path = "observation.rs"]
mod observation;
pub use observation::*;

const KIND: u16 = 16;
pub const MAX_OBSERVATIONS: usize = 8;
const RECORD_BYTES: usize = 4;
const BODY_HEADER_BYTES: usize = 7 * 16 + 2 * 8 + 2;
pub const MAX_SESSION_OBSERVATION_BYTES: usize =
    HEADER_BYTES + BODY_HEADER_BYTES + MAX_OBSERVATIONS * RECORD_BYTES;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationAction {
    ReportOnly = 1,
    RequestOwnStop = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ObservationKind {
    DebuggerAttachment = 1,
    CodeIntegrity = 2,
    RegisteredProvider = 3,
    ApplicationFile = 4,
    RunningApplication = 5,
    DriverPackage = 6,
}

impl TryFrom<u8> for ObservationKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::DebuggerAttachment),
            2 => Ok(Self::CodeIntegrity),
            3 => Ok(Self::RegisteredProvider),
            4 => Ok(Self::ApplicationFile),
            5 => Ok(Self::RunningApplication),
            6 => Ok(Self::DriverPackage),
            _ => Err(Error::UnknownMandatory),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationFinding {
    Observed = 1,
    NotObservedWithinScope = 2,
    Inconclusive = 3,
    Unsupported = 4,
    SignedMismatch = 5,
    BenignException = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationRecord {
    pub kind: ObservationKind,
    pub rule_id: u16,
    pub finding: ObservationFinding,
}

impl ObservationRecord {
    /// Eligibility for a trusted local policy to stop its own session.
    /// A reported record gives the server no proof that the observation happened.
    pub fn can_request_own_stop(self) -> bool {
        matches!(
            (self.kind, self.rule_id, self.finding),
            (
                ObservationKind::DebuggerAttachment,
                0,
                ObservationFinding::Observed
            ) | (
                ObservationKind::CodeIntegrity,
                1..,
                ObservationFinding::SignedMismatch
            )
        )
    }

    pub(crate) fn valid(self) -> bool {
        if !self.signal_id().valid() {
            return false;
        }
        match self.finding {
            ObservationFinding::SignedMismatch => self.kind == ObservationKind::CodeIntegrity,
            ObservationFinding::BenignException => matches!(
                self.kind,
                ObservationKind::ApplicationFile
                    | ObservationKind::RunningApplication
                    | ObservationKind::DriverPackage
            ),
            _ => true,
        }
    }

    pub fn signal_id(self) -> SignalId {
        SignalId {
            kind: self.kind,
            rule_id: self.rule_id,
        }
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let kind = ObservationKind::try_from(input.u8()?)?;
        let rule_id = input.u16()?;
        let finding = match input.u8()? {
            1 => ObservationFinding::Observed,
            2 => ObservationFinding::NotObservedWithinScope,
            3 => ObservationFinding::Inconclusive,
            4 => ObservationFinding::Unsupported,
            5 => ObservationFinding::SignedMismatch,
            6 => ObservationFinding::BenignException,
            _ => return Err(Error::UnknownMandatory),
        };
        Ok(Self {
            kind,
            rule_id,
            finding,
        })
    }

    fn write(self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend(self.rule_id.to_le_bytes());
        out.push(self.finding as u8);
    }
}

/// An authenticated request for the device's own session. The records remain
/// untrusted even after device proof and session binding are verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionObservation {
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub session_id: Id,
    pub generation_id: Id,
    pub function_id: Id,
    pub request_id: Id,
    pub sequence: u64,
    pub detection_policy_epoch: u64,
    pub action: ObservationAction,
    pub records: Vec<ObservationRecord>,
}

impl SessionObservation {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::with_capacity(BODY_HEADER_BYTES + self.records.len() * RECORD_BYTES);
        for id in self.ids() {
            body.extend(id);
        }
        body.extend(self.sequence.to_le_bytes());
        body.extend(self.detection_policy_epoch.to_le_bytes());
        body.extend([self.action as u8, self.records.len() as u8]);
        for record in &self.records {
            record.write(&mut body);
        }
        envelope(KIND, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SESSION_OBSERVATION_BYTES {
            return Err(Error::Limit);
        }
        let (bytes, _) = split_envelope(bytes, KIND, 0)?;
        let mut reader = Reader::new(&bytes[HEADER_BYTES..]);
        let mut request = Self::read_header(&mut reader)?;
        let count = usize::from(reader.u8()?);
        if count > MAX_OBSERVATIONS {
            return Err(Error::Limit);
        }
        request.records = (0..count)
            .map(|_| ObservationRecord::read(&mut reader))
            .collect::<Result<_>>()?;
        reader.finish()?;
        request.validate()?;
        Ok(request)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.session-observation\0",
            &self.encode()?,
        ))
    }

    pub fn sign(&self, key: &SigningKey) -> Result<[u8; SESSION_PROOF_BYTES]> {
        sign(key, &self.signature_digest()?)
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SESSION_PROOF_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }

    fn ids(&self) -> [Id; 7] {
        [
            self.app_id,
            self.build_id,
            self.device_id,
            self.session_id,
            self.generation_id,
            self.function_id,
            self.request_id,
        ]
    }

    fn read_header(input: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            app_id: input.array()?,
            build_id: input.array()?,
            device_id: input.array()?,
            session_id: input.array()?,
            generation_id: input.array()?,
            function_id: input.array()?,
            request_id: input.array()?,
            sequence: input.u64()?,
            detection_policy_epoch: input.u64()?,
            action: match input.u8()? {
                1 => ObservationAction::ReportOnly,
                2 => ObservationAction::RequestOwnStop,
                _ => return Err(Error::UnknownMandatory),
            },
            records: Vec::new(),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.records.len() > MAX_OBSERVATIONS {
            return Err(Error::Limit);
        }
        if self.ids().contains(&[0; 16])
            || !(1..=i64::MAX as u64).contains(&self.sequence)
            || !(1..=i64::MAX as u64).contains(&self.detection_policy_epoch)
            || self.records.is_empty()
            || self.records.iter().any(|record| !record.valid())
            || self
                .records
                .windows(2)
                .any(|pair| pair[0].signal_id() >= pair[1].signal_id())
            || (self.action == ObservationAction::RequestOwnStop
                && !self
                    .records
                    .iter()
                    .any(|record| record.can_request_own_stop()))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
