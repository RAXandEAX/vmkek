use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::{
    canonical::Reader,
    signed::{Payload, Signed},
    Digest, Id, ProtocolError as Error,
};

const POLICY: u16 = 15;
const AMD64: u16 = 0x8664;
const MAX_RULES: usize = 128;
const MAX_IMAGE_RULES: usize = 16;
pub const MAX_CODE_BYTES: u32 = 64 * 1024;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildRange {
    pub first: u32,
    pub last: u32,
}

impl BuildRange {
    pub fn contains(self, build: u32) -> bool {
        (self.first..=self.last).contains(&build)
    }

    fn valid(self) -> bool {
        self.first != 0 && self.first <= self.last
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.first.to_le_bytes());
        out.extend(self.last.to_le_bytes());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            first: reader.u32()?,
            last: reader.u32()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ArtifactKind {
    ApplicationFile = 1,
    RunningApplication = 2,
    DriverPackage = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Severity {
    Informational = 1,
    Warning = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Advice {
    Record = 1,
    Review = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactRule {
    pub id: u16,
    pub kind: ArtifactKind,
    pub digest: Digest,
    pub severity: Severity,
    pub advice: Advice,
    pub benign_builds: Option<BuildRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ImagePurpose {
    CodeIntegrity = 1,
    RegisteredInstrumentation = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRule {
    pub id: u16,
    pub purpose: ImagePurpose,
    pub file_digest: Digest,
    pub code_rva: u32,
    pub code_len: u32,
    pub code_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionPolicy {
    pub app_id: Id,
    pub build_id: Id,
    pub key_id: Digest,
    pub epoch: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub windows_builds: BuildRange,
    pub artifacts: Vec<ArtifactRule>,
    pub images: Vec<ImageRule>,
}

#[derive(Clone, Copy)]
pub struct PolicyContext {
    pub app_id: Id,
    pub build_id: Id,
    pub epoch_floor: u64,
    pub windows_build: u32,
    pub now_ms: u64,
}

pub struct VerifiedPolicy<'a> {
    payload: &'a DetectionPolicy,
    windows_build: u32,
}

impl VerifiedPolicy<'_> {
    pub fn check_time(&self, now_ms: u64) -> Result<()> {
        if (self.payload.issued_ms..self.payload.expires_ms).contains(&now_ms) {
            Ok(())
        } else {
            Err(Error::Expired)
        }
    }

    pub fn epoch(&self) -> u64 {
        self.payload.epoch
    }

    pub fn windows_build(&self) -> u32 {
        self.windows_build
    }

    pub fn artifact_rules(&self) -> &[ArtifactRule] {
        &self.payload.artifacts
    }

    pub fn image_rules(&self) -> &[ImageRule] {
        &self.payload.images
    }
}

pub struct SignedDetectionPolicy(Signed<DetectionPolicy>);

impl SignedDetectionPolicy {
    pub fn sign(policy: DetectionPolicy, key: &SigningKey) -> Result<Self> {
        Signed::sign(policy, key).map(Self)
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
        context: PolicyContext,
    ) -> Result<VerifiedPolicy<'_>> {
        let policy = self.0.verify(pin)?;
        if policy.app_id != context.app_id
            || policy.build_id != context.build_id
            || policy.epoch < context.epoch_floor
            || !policy.windows_builds.contains(context.windows_build)
        {
            return Err(Error::Binding);
        }
        if !(policy.issued_ms..policy.expires_ms).contains(&context.now_ms) {
            return Err(Error::Expired);
        }
        Ok(VerifiedPolicy {
            payload: policy,
            windows_build: context.windows_build,
        })
    }
}

impl DetectionPolicy {
    fn validate(&self) -> Result<()> {
        if self.epoch == 0 || self.issued_ms >= self.expires_ms || !self.windows_builds.valid() {
            return Err(Error::Invalid);
        }
        if self.artifacts.len() > MAX_RULES || self.images.len() > MAX_IMAGE_RULES {
            return Err(Error::Limit);
        }
        if self
            .artifacts
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self.images.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self.artifacts.iter().any(|rule| !self.valid_artifact(rule))
            || self.images.iter().any(|rule| !self.valid_image(rule))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn valid_artifact(&self, rule: &ArtifactRule) -> bool {
        rule.id != 0
            && rule.benign_builds.is_none_or(|range| {
                range.valid()
                    && self.windows_builds.contains(range.first)
                    && self.windows_builds.contains(range.last)
            })
            && self
                .artifacts
                .iter()
                .filter(|other| (other.kind, other.digest) == (rule.kind, rule.digest))
                .count()
                == 1
    }

    fn valid_image(&self, rule: &ImageRule) -> bool {
        rule.id != 0
            && self
                .artifacts
                .binary_search_by_key(&rule.id, |entry| entry.id)
                .is_err()
            && rule.code_rva != 0
            && (1..=MAX_CODE_BYTES).contains(&rule.code_len)
            && rule.code_rva.checked_add(rule.code_len).is_some()
    }
}

impl Payload for DetectionPolicy {
    const KIND: u16 = POLICY;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.windows-observation-policy\0";

    fn key_id(&self) -> &Digest {
        &self.key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend(self.app_id);
        out.extend(self.build_id);
        out.extend(self.key_id);
        out.extend(self.epoch.to_le_bytes());
        out.extend(self.issued_ms.to_le_bytes());
        out.extend(self.expires_ms.to_le_bytes());
        out.extend(AMD64.to_le_bytes());
        self.windows_builds.encode(&mut out);
        out.extend((self.artifacts.len() as u16).to_le_bytes());
        for rule in &self.artifacts {
            rule.encode(&mut out);
        }
        out.extend((self.images.len() as u16).to_le_bytes());
        for rule in &self.images {
            rule.encode(&mut out);
        }
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(body);
        let app_id = reader.array()?;
        let build_id = reader.array()?;
        let key_id = reader.array()?;
        let epoch = reader.u64()?;
        let issued_ms = reader.u64()?;
        let expires_ms = reader.u64()?;
        if reader.u16()? != AMD64 {
            return Err(Error::Invalid);
        }
        let policy = Self {
            app_id,
            build_id,
            key_id,
            epoch,
            issued_ms,
            expires_ms,
            windows_builds: BuildRange::decode(&mut reader)?,
            artifacts: decode_rules(&mut reader, MAX_RULES, ArtifactRule::decode)?,
            images: decode_rules(&mut reader, MAX_IMAGE_RULES, ImageRule::decode)?,
        };
        reader.finish()?;
        policy.validate()?;
        Ok(policy)
    }
}

fn decode_rules<T>(
    reader: &mut Reader<'_>,
    limit: usize,
    decode: impl Fn(&mut Reader<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let count = usize::from(reader.u16()?);
    if count > limit {
        return Err(Error::Limit);
    }
    (0..count).map(|_| decode(reader)).collect()
}

impl ArtifactRule {
    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.id.to_le_bytes());
        out.extend([self.kind as u8, self.severity as u8, self.advice as u8]);
        out.extend(self.digest);
        out.push(u8::from(self.benign_builds.is_some()));
        if let Some(builds) = self.benign_builds {
            builds.encode(out);
        }
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let id = reader.u16()?;
        let kind = match reader.u8()? {
            1 => ArtifactKind::ApplicationFile,
            2 => ArtifactKind::RunningApplication,
            3 => ArtifactKind::DriverPackage,
            _ => return Err(Error::UnknownMandatory),
        };
        let severity = match reader.u8()? {
            1 => Severity::Informational,
            2 => Severity::Warning,
            _ => return Err(Error::UnknownMandatory),
        };
        let advice = match reader.u8()? {
            1 => Advice::Record,
            2 => Advice::Review,
            _ => return Err(Error::UnknownMandatory),
        };
        let digest = reader.array()?;
        let benign_builds = match reader.u8()? {
            0 => None,
            1 => Some(BuildRange::decode(reader)?),
            _ => return Err(Error::Invalid),
        };
        Ok(Self {
            id,
            kind,
            digest,
            severity,
            advice,
            benign_builds,
        })
    }
}

impl ImageRule {
    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.id.to_le_bytes());
        out.push(self.purpose as u8);
        out.extend(self.file_digest);
        out.extend(self.code_rva.to_le_bytes());
        out.extend(self.code_len.to_le_bytes());
        out.extend(self.code_digest);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: reader.u16()?,
            purpose: match reader.u8()? {
                1 => ImagePurpose::CodeIntegrity,
                2 => ImagePurpose::RegisteredInstrumentation,
                _ => return Err(Error::UnknownMandatory),
            },
            file_digest: reader.array()?,
            code_rva: reader.u32()?,
            code_len: reader.u32()?,
            code_digest: reader.array()?,
        })
    }
}
