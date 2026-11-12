use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

#[path = "observation_policy.rs"]
mod observation_policy;
pub use observation_policy::*;

use crate::session_observation::{ObservationKind, ObservationPlatform};

use crate::{
    canonical::Reader,
    signed::{Payload, Signed},
    Digest, Id, ProtocolError as Error,
};

const POLICY: u16 = 15;
const AMD64: u16 = 0x8664;
const ELF_AMD64: u16 = 62;
const INTERNAL_LINUX_RANGE: BuildRange = BuildRange { first: 1, last: 1 };
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
    payload: &'a PolicyPayload,
    revision: PolicyRevision,
    supported: u8,
    verified_at_ms: u64,
    platform: ObservationPlatform,
}

impl VerifiedPolicy<'_> {
    pub fn check_time(&self, now_ms: u64) -> Result<()> {
        if (self.payload.policy.issued_ms..self.payload.policy.expires_ms).contains(&now_ms) {
            Ok(())
        } else {
            Err(Error::Expired)
        }
    }

    pub fn expires_ms(&self) -> u64 {
        self.payload.policy.expires_ms
    }

    pub fn epoch(&self) -> u64 {
        self.payload.policy.epoch
    }

    pub fn windows_build(&self) -> u32 {
        match self.platform {
            ObservationPlatform::Windows { build } => build,
            ObservationPlatform::Linux { .. } => 0,
        }
    }

    pub fn platform(&self) -> ObservationPlatform {
        self.platform
    }

    pub fn revision(&self) -> PolicyRevision {
        self.revision
    }

    pub fn observation_policy(&self) -> Option<ObservationPolicy> {
        self.payload
            .settings
            .clone()
            .map(|settings| ObservationPolicy {
                settings,
                app_id: self.payload.policy.app_id,
                build_id: self.payload.policy.build_id,
                supported: self.supported,
                platform: self.platform,
                linux_release: self.payload.linux_release,
                revision: self.revision(),
                issued_ms: self.payload.policy.issued_ms,
                expires_ms: self.payload.policy.expires_ms,
                verified_at_ms: self.verified_at_ms,
            })
    }

    pub fn artifact_rules(&self) -> &[ArtifactRule] {
        &self.payload.policy.artifacts
    }

    pub fn image_rules(&self) -> &[ImageRule] {
        &self.payload.policy.images
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyPayload {
    policy: DetectionPolicy,
    settings: Option<ObservationSettings>,
    linux_release: Option<LinuxRelease>,
}

#[derive(Clone, Debug)]
pub struct SignedDetectionPolicy(Signed<PolicyPayload>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRevision {
    pub epoch: u64,
    pub digest: Digest,
}

pub struct ProfileContext<'a> {
    pub policy: PolicyContext,
    pub profile: ObservationProfile,
    pub supported: &'a [ObservationKind],
    /// An installed revision for this app, build and profile from trusted local
    /// storage, when available. Epoch floors also apply on first activation.
    pub previous: Option<PolicyRevision>,
}

/// Exact Linux kernel release identity, including distribution suffixes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxRelease {
    version: [u32; 3],
    digest: Digest,
}

impl LinuxRelease {
    pub fn from_uname(release: &[u8]) -> Result<Self> {
        if release.is_empty()
            || release.len() > 64
            || !release
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(b))
        {
            return Err(Error::Invalid);
        }
        let numeric = |value: &[u8]| {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(Error::Invalid);
            }
            std::str::from_utf8(value)
                .map_err(|_| Error::Invalid)?
                .parse::<u32>()
                .map_err(|_| Error::Invalid)
        };
        let mut fields = release.splitn(3, |&b| b == b'.');
        let major = numeric(fields.next().ok_or(Error::Invalid)?)?;
        let minor = numeric(fields.next().ok_or(Error::Invalid)?)?;
        let rest = fields.next().ok_or(Error::Invalid)?;
        let digits = rest
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(rest.len());
        let patch = numeric(&rest[..digits])?;
        if major == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            version: [major, minor, patch],
            digest: Sha256::digest(release).into(),
        })
    }

    pub fn platform(self) -> ObservationPlatform {
        let [major, minor, patch] = self.version;
        ObservationPlatform::Linux {
            major,
            minor,
            patch,
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        for field in self.version {
            out.extend(field.to_le_bytes());
        }
        out.extend(self.digest);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let version = [reader.u32()?, reader.u32()?, reader.u32()?];
        let digest = reader.array()?;
        if version[0] == 0 || digest == [0; 32] {
            return Err(Error::Invalid);
        }
        Ok(Self { version, digest })
    }
}

pub struct LinuxProfileContext<'a> {
    pub app_id: Id,
    pub build_id: Id,
    pub epoch_floor: u64,
    pub now_ms: u64,
    pub release: LinuxRelease,
    pub profile: ObservationProfile,
    pub supported: &'a [ObservationKind],
    pub previous: Option<PolicyRevision>,
}

impl SignedDetectionPolicy {
    pub fn sign(policy: DetectionPolicy, key: &SigningKey) -> Result<Self> {
        Signed::sign(
            PolicyPayload {
                policy,
                settings: None,
                linux_release: None,
            },
            key,
        )
        .map(Self)
    }

    pub fn sign_for_profile(
        policy: DetectionPolicy,
        settings: ObservationSettings,
        key: &SigningKey,
    ) -> Result<Self> {
        Signed::sign(
            PolicyPayload {
                policy,
                settings: Some(settings),
                linux_release: None,
            },
            key,
        )
        .map(Self)
    }

    /// Signs Linux-only observation settings. Image ranges use ELF virtual
    /// addresses rather than PE RVAs. Windows build range is unused here.
    pub fn sign_for_linux_profile(
        mut policy: DetectionPolicy,
        settings: ObservationSettings,
        release: LinuxRelease,
        key: &SigningKey,
    ) -> Result<Self> {
        policy.windows_builds = INTERNAL_LINUX_RANGE;
        Signed::sign(
            PolicyPayload {
                policy,
                settings: Some(settings),
                linux_release: Some(release),
            },
            key,
        )
        .map(Self)
    }

    pub fn is_linux(&self) -> bool {
        self.0.payload().linux_release.is_some()
    }

    pub fn verify_for_linux_profile(
        &self,
        pin: &VerifyingKey,
        context: LinuxProfileContext<'_>,
    ) -> Result<VerifiedPolicy<'_>> {
        let payload = self.0.verify(pin)?;
        if payload.linux_release != Some(context.release) {
            return Err(Error::Binding);
        }
        let verified = self.verify_common(
            payload,
            context.app_id,
            context.build_id,
            context.epoch_floor,
            context.now_ms,
            context.release.platform(),
        )?;
        Self::verify_settings(
            verified,
            context.profile,
            context.supported,
            context.previous,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Indicates which validation entry point is required. The version is
    /// authenticated only after successful verification.
    pub fn has_profile(&self) -> bool {
        self.0.payload().settings.is_some()
    }

    pub fn verify_for(
        &self,
        pin: &VerifyingKey,
        context: PolicyContext,
    ) -> Result<VerifiedPolicy<'_>> {
        let verified = self.verify_binding(pin, context)?;
        if verified.payload.settings.is_some() {
            return Err(Error::UnknownMandatory);
        }
        Ok(verified)
    }

    pub fn verify_for_profile(
        &self,
        pin: &VerifyingKey,
        context: ProfileContext<'_>,
    ) -> Result<VerifiedPolicy<'_>> {
        let verified = self.verify_binding(pin, context.policy)?;
        Self::verify_settings(
            verified,
            context.profile,
            context.supported,
            context.previous,
        )
    }

    fn verify_settings<'a>(
        mut verified: VerifiedPolicy<'a>,
        profile: ObservationProfile,
        supported: &[ObservationKind],
        previous: Option<PolicyRevision>,
    ) -> Result<VerifiedPolicy<'a>> {
        let settings = verified.payload.settings.as_ref().ok_or(Error::Version)?;
        if settings.profile != profile {
            return Err(Error::Binding);
        }
        if let Some(previous) = previous {
            if verified.epoch() < previous.epoch
                || (verified.epoch() == previous.epoch
                    && verified.revision().digest != previous.digest)
            {
                return Err(Error::Binding);
            }
        }
        if settings
            .rules
            .iter()
            .any(|rule| rule.required && !supported.contains(&rule.signal_id.kind))
        {
            return Err(Error::UnknownMandatory);
        }
        verified.supported = supported
            .iter()
            .fold(0, |mask, kind| mask | capability_bit(*kind));
        Ok(verified)
    }

    fn verify_binding(
        &self,
        pin: &VerifyingKey,
        context: PolicyContext,
    ) -> Result<VerifiedPolicy<'_>> {
        let payload = self.0.verify(pin)?;
        if payload.linux_release.is_some()
            || !payload
                .policy
                .windows_builds
                .contains(context.windows_build)
        {
            return Err(Error::Binding);
        }
        self.verify_common(
            payload,
            context.app_id,
            context.build_id,
            context.epoch_floor,
            context.now_ms,
            ObservationPlatform::Windows {
                build: context.windows_build,
            },
        )
    }

    fn verify_common<'a>(
        &self,
        payload: &'a PolicyPayload,
        app_id: Id,
        build_id: Id,
        epoch_floor: u64,
        now_ms: u64,
        platform: ObservationPlatform,
    ) -> Result<VerifiedPolicy<'a>> {
        let policy = &payload.policy;
        if policy.app_id != app_id || policy.build_id != build_id || policy.epoch < epoch_floor {
            return Err(Error::Binding);
        }
        let verified = VerifiedPolicy {
            payload,
            revision: PolicyRevision {
                epoch: policy.epoch,
                digest: Sha256::digest(self.as_bytes()).into(),
            },
            supported: 0,
            verified_at_ms: now_ms,
            platform,
        };
        verified.check_time(now_ms)?;
        Ok(verified)
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

impl Payload for PolicyPayload {
    const KIND: u16 = POLICY;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.windows-observation-policy\0";

    fn key_id(&self) -> &Digest {
        &self.policy.key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        let policy = &self.policy;
        policy.validate()?;
        if let Some(settings) = &self.settings {
            settings.validate(policy)?;
        }
        let mut out = Vec::new();
        out.extend(policy.app_id);
        out.extend(policy.build_id);
        out.extend(policy.key_id);
        out.extend(policy.epoch.to_le_bytes());
        out.extend(policy.issued_ms.to_le_bytes());
        out.extend(policy.expires_ms.to_le_bytes());
        if let Some(release) = self.linux_release {
            if self.settings.is_none()
                || !policy.artifacts.is_empty()
                || policy
                    .images
                    .iter()
                    .any(|rule| rule.purpose != ImagePurpose::CodeIntegrity)
            {
                return Err(Error::Invalid);
            }
            out.extend(ELF_AMD64.to_le_bytes());
            release.encode(&mut out);
        } else {
            out.extend(AMD64.to_le_bytes());
            policy.windows_builds.encode(&mut out);
        }
        out.extend((policy.artifacts.len() as u16).to_le_bytes());
        for rule in &policy.artifacts {
            rule.encode(&mut out);
        }
        out.extend((policy.images.len() as u16).to_le_bytes());
        for rule in &policy.images {
            rule.encode(&mut out);
        }
        if let Some(settings) = &self.settings {
            settings.encode(&mut out);
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
        let (windows_builds, linux_release) = match reader.u16()? {
            AMD64 => (BuildRange::decode(&mut reader)?, None),
            ELF_AMD64 => (
                INTERNAL_LINUX_RANGE,
                Some(LinuxRelease::decode(&mut reader)?),
            ),
            _ => return Err(Error::Invalid),
        };
        let policy = DetectionPolicy {
            app_id,
            build_id,
            key_id,
            epoch,
            issued_ms,
            expires_ms,
            windows_builds,
            artifacts: decode_rules(&mut reader, MAX_RULES, ArtifactRule::decode)?,
            images: decode_rules(&mut reader, MAX_IMAGE_RULES, ImageRule::decode)?,
        };
        let settings = if reader.is_empty() {
            None
        } else {
            Some(ObservationSettings::decode(&mut reader, &policy)?)
        };
        reader.finish()?;
        policy.validate()?;
        if linux_release.is_some()
            && (settings.is_none()
                || !policy.artifacts.is_empty()
                || policy
                    .images
                    .iter()
                    .any(|rule| rule.purpose != ImagePurpose::CodeIntegrity))
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            policy,
            settings,
            linux_release,
        })
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
