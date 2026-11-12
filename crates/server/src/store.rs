use p256::ecdsa::VerifyingKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use vmkek_protocol::{public_key_id, DeviceTrust, Digest, EnrollmentChallenge, Id};
use zeroize::Zeroizing;

use crate::{CHALLENGE_TTL_MS, DEFAULT_DEVICE_LIMIT, ENROLLMENTS_PER_HOUR};

pub(crate) static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub struct ActivationToken(Zeroizing<[u8; 32]>);

impl ActivationToken {
    pub fn from_hex(text: &str) -> Result<Self, IdentityError> {
        let mut raw = Zeroizing::new([0; 32]);
        hex::decode_to_slice(text, &mut raw[..]).map_err(|_| IdentityError::Invalid)?;
        Ok(Self(raw))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn digest(&self) -> Digest {
        let mut hash = Sha256::new();
        hash.update(b"vmkek.identity.v1.activation-token\0");
        hash.update(&self.0[..]);
        hash.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: Id,
    pub trust: DeviceTrust,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid identity request")]
    Invalid,
    #[error("identity request denied")]
    Denied,
    #[error("enrollment challenge expired")]
    Expired,
    #[error("enrollment challenge already used")]
    Replay,
    #[error("license device limit reached")]
    DeviceLimit,
    #[error("enrollment rate limit reached")]
    RateLimit,
    #[error("requested device trust is unavailable")]
    TrustUnavailable,
    #[error("identity store unavailable")]
    Unavailable,
}

impl From<sqlx::Error> for IdentityError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum RevokeReason {
    Administrator = 1,
    Compromised = 2,
}

#[derive(Clone)]
pub struct IdentityStore {
    pool: PgPool,
}

impl IdentityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), IdentityError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|_| IdentityError::Unavailable)
    }

    /// Call only from the trusted administrative boundary.
    pub async fn provision_license(
        &self,
        app_id: Id,
        device_limit: Option<i32>,
    ) -> Result<(Id, ActivationToken), IdentityError> {
        let limit = device_limit.unwrap_or(DEFAULT_DEVICE_LIMIT);
        if limit <= 0 {
            return Err(IdentityError::Invalid);
        }
        let id: Id = random()?;
        let token = ActivationToken(Zeroizing::new(random()?));
        sqlx::query("INSERT INTO licenses (id, app_id, activation_digest, device_limit) VALUES ($1,$2,$3,$4)")
            .bind(id.as_slice()).bind(app_id.as_slice()).bind(token.digest().as_slice()).bind(limit)
            .execute(&self.pool).await?;
        Ok((id, token))
    }

    pub async fn challenge(
        &self,
        app_id: Id,
        token: &ActivationToken,
        public_key: [u8; 65],
        trust: DeviceTrust,
    ) -> Result<EnrollmentChallenge, IdentityError> {
        let key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| IdentityError::Invalid)?;
        let key_id = public_key_id(&key);
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT id, state FROM licenses WHERE activation_digest=$1 AND app_id=$2 FOR UPDATE",
        )
        .bind(token.digest().as_slice())
        .bind(app_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(IdentityError::Denied)?;
        let license_id = array(&row, "id")?;
        let state: String = row.try_get("state")?;
        let denial = if state != "active" {
            Some(("state_denied", IdentityError::Denied))
        } else if trust != DeviceTrust::Software {
            Some(("trust_denied", IdentityError::TrustUnavailable))
        } else {
            let issued: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollments WHERE license_id=$1 AND issued_at > clock_timestamp() - interval '1 hour'")
                .bind(license_id.as_slice()).fetch_one(&mut *tx).await?;
            (issued >= ENROLLMENTS_PER_HOUR).then_some(("rate_limit", IdentityError::RateLimit))
        };
        if let Some((event, error)) = denial {
            audit(&mut tx, license_id, None, None, event).await?;
            tx.commit().await?;
            return Err(error);
        }

        let challenge_id: Id = random()?;
        let nonce: Digest = random()?;
        let expires: i64 = sqlx::query_scalar(
            "WITH issued AS (SELECT clock_timestamp() AS ts)
             INSERT INTO enrollments (id, license_id, key_id, public_key, nonce, trust, issued_at, expires_unix_ms)
             SELECT $1,$2,$3,$4,$5,$6,ts,floor(extract(epoch FROM ts)*1000)::bigint+$7 FROM issued
             RETURNING expires_unix_ms",
        )
        .bind(challenge_id.as_slice()).bind(license_id.as_slice()).bind(key_id.as_slice())
        .bind(public_key.as_slice()).bind(nonce.as_slice()).bind(trust as i16).bind(CHALLENGE_TTL_MS)
        .fetch_one(&mut *tx).await?;
        audit(&mut tx, license_id, Some(challenge_id), None, "challenge").await?;
        tx.commit().await?;
        Ok(EnrollmentChallenge {
            app_id,
            license_id,
            challenge_id,
            nonce,
            key_id,
            trust,
            expires_unix_ms: expires.try_into().map_err(|_| IdentityError::Unavailable)?,
        })
    }

    pub async fn enroll(
        &self,
        challenge_id: Id,
        proof: [u8; 64],
    ) -> Result<DeviceIdentity, IdentityError> {
        let mut tx = self.pool.begin().await?;
        let license = sqlx::query(
            "SELECT l.id,l.app_id,l.state,l.device_limit FROM licenses l
             JOIN enrollments e ON e.license_id=l.id WHERE e.id=$1 FOR UPDATE OF l",
        )
        .bind(challenge_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(IdentityError::Denied)?;
        let license_id = array(&license, "id")?;
        let result = redeem(&mut tx, &license, license_id, challenge_id, proof).await?;
        let (event, device_id) = match &result {
            Ok((device, event)) => (*event, Some(device.id)),
            Err((_, event)) => (*event, None),
        };
        audit(&mut tx, license_id, Some(challenge_id), device_id, event).await?;
        tx.commit().await?;
        result.map(|(device, _)| device).map_err(|(error, _)| error)
    }

    /// Revoke a license or one of its devices through the trusted administrative boundary.
    pub async fn revoke(
        &self,
        license_id: Id,
        device_id: Option<Id>,
        actor_id: Id,
        reason: RevokeReason,
    ) -> Result<(), IdentityError> {
        crate::access::revoke_legacy(&self.pool, license_id, device_id, actor_id, reason).await
    }
}

type Redemption = Result<(DeviceIdentity, &'static str), (IdentityError, &'static str)>;

async fn redeem(
    tx: &mut Transaction<'_, Postgres>,
    license: &PgRow,
    license_id: Id,
    challenge_id: Id,
    proof: [u8; 64],
) -> Result<Redemption, IdentityError> {
    let consumed = sqlx::query(
        "UPDATE enrollments SET consumed_at=clock_timestamp() WHERE id=$1 AND license_id=$2
         AND consumed_at IS NULL RETURNING key_id, public_key, nonce, trust, expires_unix_ms,
         expires_unix_ms <= floor(extract(epoch FROM consumed_at)*1000)::bigint AS expired",
    )
    .bind(challenge_id.as_slice())
    .bind(license_id.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = consumed else {
        return Ok(Err((IdentityError::Replay, "replay")));
    };
    let state: String = license.try_get("state")?;
    if state != "active" {
        return Ok(Err((IdentityError::Denied, "state_denied")));
    }
    if row.try_get("expired")? {
        return Ok(Err((IdentityError::Expired, "expired")));
    }
    let trust = read_trust(&row)?;
    if trust != DeviceTrust::Software {
        return Ok(Err((IdentityError::TrustUnavailable, "trust_denied")));
    }
    let public_key = array(&row, "public_key")?;
    let key_id = array(&row, "key_id")?;
    let expires: i64 = row.try_get("expires_unix_ms")?;
    let challenge = EnrollmentChallenge {
        app_id: array(license, "app_id")?,
        license_id,
        challenge_id,
        nonce: array(&row, "nonce")?,
        key_id,
        trust,
        expires_unix_ms: expires.try_into().map_err(|_| IdentityError::Unavailable)?,
    };
    if challenge.verify_proof(&public_key, &proof).is_err() {
        return Ok(Err((IdentityError::Denied, "proof_denied")));
    }

    if let Some(device) =
        sqlx::query("SELECT id,state,trust FROM devices WHERE license_id=$1 AND key_id=$2")
            .bind(license_id.as_slice())
            .bind(key_id.as_slice())
            .fetch_optional(&mut **tx)
            .await?
    {
        let state: String = device.try_get("state")?;
        if state != "active" || read_trust(&device)? != trust {
            return Ok(Err((IdentityError::Denied, "state_denied")));
        }
        return Ok(Ok((
            DeviceIdentity {
                id: array(&device, "id")?,
                trust,
            },
            "reused",
        )));
    }

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE license_id=$1")
        .bind(license_id.as_slice())
        .fetch_one(&mut **tx)
        .await?;
    let limit: i32 = license.try_get("device_limit")?;
    if count >= i64::from(limit) {
        return Ok(Err((IdentityError::DeviceLimit, "device_limit")));
    }

    let id: Id = random()?;
    sqlx::query(
        "INSERT INTO devices (id,license_id,key_id,public_key,trust) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(id.as_slice())
    .bind(license_id.as_slice())
    .bind(key_id.as_slice())
    .bind(public_key.as_slice())
    .bind(trust as i16)
    .execute(&mut **tx)
    .await?;
    Ok(Ok((DeviceIdentity { id, trust }, "enrolled")))
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    license_id: Id,
    challenge_id: Option<Id>,
    device_id: Option<Id>,
    event: &'static str,
) -> Result<(), IdentityError> {
    sqlx::query("INSERT INTO audit (license_id,challenge_id,device_id,event) VALUES ($1,$2,$3,$4)")
        .bind(license_id.as_slice())
        .bind(challenge_id.as_ref().map(|id| id.as_slice()))
        .bind(device_id.as_ref().map(|id| id.as_slice()))
        .bind(event)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn read_trust(row: &PgRow) -> Result<DeviceTrust, IdentityError> {
    let tag: i16 = row.try_get("trust")?;
    u8::try_from(tag)
        .ok()
        .and_then(|tag| tag.try_into().ok())
        .ok_or(IdentityError::Unavailable)
}

fn array<const N: usize>(row: &PgRow, column: &str) -> Result<[u8; N], IdentityError> {
    let bytes: Vec<u8> = row.try_get(column)?;
    bytes.try_into().map_err(|_| IdentityError::Unavailable)
}

fn random<const N: usize>() -> Result<[u8; N], IdentityError> {
    let mut value = [0; N];
    OsRng
        .try_fill_bytes(&mut value)
        .map_err(|_| IdentityError::Unavailable)?;
    Ok(value)
}
