mod observations;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use vmkek_protocol::{
    public_key_id, Digest, Extension, GenerationChoice, GrantBinding, GrantPayload, Id,
    ModuleFetch, Permission, PermissionKind, SampleOperationRequest, SessionChallenge,
    SessionGrant, SessionIntent, SessionOperation, SignedGenerationChoice, MAX_ACTIVE_CONTEXTS,
    MAX_DEADLINE_MS, MAX_GRANT_LIFETIME_MS, SESSION_CHALLENGE_EXTENSION,
};

use crate::packages::{PackageError, PackageStore, ReleaseScope};

const BURST_CREDIT: i64 = 120_000;
const REQUEST_CREDIT: i64 = 1_000;
const REFILL_PER_MS: i64 = 60;

type Tx<'a> = Transaction<'a, Postgres>;
type Result<T> = std::result::Result<T, SessionError>;

#[derive(Clone, Copy)]
pub struct SessionPolicy {
    pub app_id: Id,
    pub build_id: Id,
    pub generation_id: Id,
    pub policy_epoch: u64,
    pub permission: Permission,
}

#[derive(Clone, Copy)]
pub struct NegotiatedSessionPolicy {
    pub app_id: Id,
    pub build_id: Id,
    pub policy_epoch: u64,
    pub function_id: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("invalid session request")]
    Invalid,
    #[error("session request denied")]
    Denied,
    #[error("session request already used or out of order")]
    Replay,
    #[error("session or challenge expired")]
    Expired,
    #[error("session request limit reached")]
    Limit,
    #[error("session service unavailable")]
    Unavailable,
}

impl From<sqlx::Error> for SessionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone)]
pub struct SessionStore(Arc<Service>);

struct Service {
    pool: PgPool,
    policy: SessionPolicy,
    negotiated: bool,
    key: SigningKey,
    epoch: i64,
    wall_start_ms: i64,
    started: Instant,
    in_flight: Mutex<HashMap<Id, usize>>,
}

/// Existing fixed and negotiated policy modes supported by checked recovery.
pub enum RecoverySessionPolicy {
    Fixed(SessionPolicy),
    Negotiated(NegotiatedSessionPolicy),
}

impl RecoverySessionPolicy {
    fn parts(self) -> (SessionPolicy, bool) {
        match self {
            Self::Fixed(policy) => (policy, false),
            Self::Negotiated(policy) => (
                SessionPolicy {
                    app_id: policy.app_id,
                    build_id: policy.build_id,
                    generation_id: [0; 16],
                    policy_epoch: policy.policy_epoch,
                    permission: Permission {
                        kind: PermissionKind::Function,
                        id: policy.function_id,
                    },
                },
                true,
            ),
        }
    }
}

impl SessionStore {
    /// Start the local Lab service. This is not a recovery or physical fencing check.
    pub async fn start(pool: PgPool, policy: SessionPolicy, key: SigningKey) -> Result<Self> {
        Self::start_mode(pool, RecoverySessionPolicy::Fixed(policy), key, None)
            .await
            .map_err(crate::recovery::RecoveryBootError::into_session)
    }

    /// Start the local negotiated Lab service on an unmarked database.
    pub async fn start_negotiated(
        pool: PgPool,
        policy: NegotiatedSessionPolicy,
        key: SigningKey,
    ) -> Result<Self> {
        Self::start_mode(pool, RecoverySessionPolicy::Negotiated(policy), key, None)
            .await
            .map_err(crate::recovery::RecoveryBootError::into_session)
    }

    /// Boot a restored database only after independent fencing and checkpoint verification.
    pub async fn start_checked_recovery(
        pool: PgPool,
        policy: RecoverySessionPolicy,
        key: SigningKey,
        proof: crate::recovery::RecoveryProof<'_>,
    ) -> std::result::Result<Self, crate::recovery::RecoveryBootError> {
        Self::start_mode(pool, policy, key, Some(proof)).await
    }

    async fn start_mode(
        pool: PgPool,
        policy: RecoverySessionPolicy,
        key: SigningKey,
        proof: Option<crate::recovery::RecoveryProof<'_>>,
    ) -> std::result::Result<Self, crate::recovery::RecoveryBootError> {
        let (policy, negotiated) = policy.parts();
        let checkpoint = proof
            .as_ref()
            .map(|proof| {
                proof.verify(
                    policy.app_id,
                    policy.build_id,
                    policy.policy_epoch,
                    public_key_id(key.verifying_key()),
                )
            })
            .transpose()?;
        let policy_epoch = i64::try_from(policy.policy_epoch).map_err(|_| SessionError::Invalid)?;
        if policy_epoch == 0 {
            return Err(SessionError::Invalid.into());
        }
        if checkpoint.is_none() {
            let mut tx = pool.begin().await?;
            crate::recovery::configure_transaction(&mut tx).await?;
            if crate::recovery::is_lab_marked(&mut tx).await? {
                return Err(SessionError::Denied.into());
            }
            tx.rollback().await?;
            crate::IdentityStore::new(pool.clone())
                .migrate()
                .await
                .map_err(|_| SessionError::Unavailable)?;
        }
        let mut tx = pool.begin().await?;
        crate::recovery::configure_transaction(&mut tx).await?;
        if let Some(checkpoint) = &checkpoint {
            crate::recovery::verify_restored(&mut tx, checkpoint).await?;
        } else if crate::recovery::is_lab_marked(&mut tx).await? {
            return Err(SessionError::Denied.into());
        }
        let epoch: i64 = sqlx::query_scalar(
            "INSERT INTO session_service (singleton,epoch,policy_epoch) VALUES (true,1,$1)
             ON CONFLICT (singleton) DO UPDATE SET epoch=session_service.epoch+1,
             policy_epoch=EXCLUDED.policy_epoch WHERE session_service.policy_epoch <= EXCLUDED.policy_epoch
             RETURNING epoch",
        ).bind(policy_epoch).fetch_optional(&mut *tx).await?.ok_or(SessionError::Denied)?;
        let wall_start_ms: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut *tx)
                .await?;
        let started = Instant::now();
        tx.commit().await?;
        if let Some(checkpoint) = &checkpoint {
            crate::recovery::check_fresh(checkpoint)?;
        }
        Ok(Self(Arc::new(Service {
            pool,
            policy,
            negotiated,
            key,
            epoch,
            wall_start_ms,
            started,
            in_flight: Mutex::new(HashMap::new()),
        })))
    }

    pub async fn issue(&self, intent: SessionIntent, proof: [u8; 64]) -> Result<SessionChallenge> {
        let intent_bytes = intent.encode().map_err(|_| SessionError::Invalid)?;
        self.0.check_policy(&intent)?;
        let _permit = self.0.admit(intent.device_id)?;
        let mut tx = self.0.begin().await?;
        let (license_id, key) = lock_identity(&mut tx, intent.device_id, intent.app_id).await?;
        intent
            .verify(&key, &proof)
            .map_err(|_| SessionError::Denied)?;
        let tick = self.0.tick()?;
        if !charge(&mut tx, intent.device_id, self.0.epoch, tick).await? {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM package_fetch_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM generation_offers WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM operation_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM session_observation_reports WHERE device_id=$1 AND request_id=$2)",
        ).bind(intent.device_id.as_slice()).bind(intent.request_id.as_slice())
         .fetch_one(&mut *tx).await?;
        if duplicate {
            tx.commit().await?;
            return Err(SessionError::Replay);
        }
        let current = current_session(&mut tx, license_id).await?;
        let session_id = match self.0.check_transition(current.as_ref(), &intent, tick) {
            Ok(id) => id,
            Err(error) => {
                tx.commit().await?;
                return Err(error);
            }
        };
        let challenge = SessionChallenge {
            intent_digest: intent.digest().map_err(|_| SessionError::Invalid)?,
            session_id,
            challenge_id: random()?,
            nonce: random()?,
        };
        let expires = tick
            .checked_add(i64::from(MAX_DEADLINE_MS))
            .ok_or(SessionError::Unavailable)?;
        let changed = sqlx::query(
            "INSERT INTO session_requests (device_id,request_id,challenge_id,intent,challenge,
             service_epoch,expires_tick_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (device_id,request_id) DO NOTHING",
        )
        .bind(intent.device_id.as_slice())
        .bind(intent.request_id.as_slice())
        .bind(challenge.challenge_id.as_slice())
        .bind(intent_bytes)
        .bind(challenge.encode().map_err(|_| SessionError::Invalid)?)
        .bind(self.0.epoch)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if changed.rows_affected() == 0 {
            return Err(SessionError::Replay);
        }
        Ok(challenge)
    }

    pub async fn complete(
        &self,
        operation: SessionOperation,
        challenge: SessionChallenge,
        proof: [u8; 64],
    ) -> Result<SessionGrant> {
        self.complete_with_packages(operation, challenge, proof, None)
            .await
    }

    pub(super) async fn complete_with_packages(
        &self,
        operation: SessionOperation,
        challenge: SessionChallenge,
        proof: [u8; 64],
        packages: Option<&PackageStore>,
    ) -> Result<SessionGrant> {
        if self.0.negotiated && (operation != SessionOperation::Renew || packages.is_none()) {
            return Err(SessionError::Denied);
        }
        // The lookup only identifies the device. Replay and authorization are checked under locks.
        let device: Vec<u8> =
            sqlx::query_scalar("SELECT device_id FROM session_requests WHERE challenge_id=$1")
                .bind(challenge.challenge_id.as_slice())
                .fetch_optional(&self.0.pool)
                .await?
                .ok_or(SessionError::Denied)?;
        let device_id: Id = device.try_into().map_err(|_| SessionError::Unavailable)?;
        let _permit = self.0.admit(device_id)?;
        let mut tx = self.0.begin().await?;
        let (license_id, key) = lock_identity(&mut tx, device_id, self.0.policy.app_id).await?;
        let row = sqlx::query(
            "SELECT intent,challenge,service_epoch,expires_tick_ms,consumed
             FROM session_requests WHERE challenge_id=$1 AND device_id=$2",
        )
        .bind(challenge.challenge_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let intent = SessionIntent::decode(row.try_get::<&[u8], _>("intent")?)
            .map_err(|_| SessionError::Unavailable)?;
        if operation != intent.operation
            || device_id != intent.device_id
            || challenge
                != SessionChallenge::decode(row.try_get::<&[u8], _>("challenge")?)
                    .map_err(|_| SessionError::Unavailable)?
            || challenge.intent_digest != intent.digest().map_err(|_| SessionError::Unavailable)?
        {
            return Err(SessionError::Denied);
        }
        self.0.check_policy(&intent)?;
        if row.try_get::<i64, _>("service_epoch")? != self.0.epoch {
            return Err(SessionError::Expired);
        }
        if row.try_get::<bool, _>("consumed")? {
            return Err(SessionError::Replay);
        }
        sqlx::query("UPDATE session_requests SET consumed=true WHERE challenge_id=$1")
            .bind(challenge.challenge_id.as_slice())
            .execute(&mut *tx)
            .await?;
        let result = self
            .0
            .grant(
                &mut tx,
                Redemption {
                    license_id,
                    key: &key,
                    intent,
                    challenge,
                    proof,
                    deadline: row.try_get("expires_tick_ms")?,
                    packages,
                },
            )
            .await;
        // Storage failures roll back rather than leaving an incomplete state transition.
        if matches!(result, Err(SessionError::Unavailable)) {
            return result.map(|(grant, _)| grant);
        }
        tx.commit().await?;
        let (grant, release_expiry) = result?;
        if let Some(expiry) = release_expiry {
            if self.package_time()? >= expiry {
                return Err(SessionError::Expired);
            }
        }
        Ok(grant)
    }
}

impl Service {
    fn check_policy(&self, intent: &SessionIntent) -> Result<()> {
        if (intent.app_id, intent.build_id) != (self.policy.app_id, self.policy.build_id)
            || if self.negotiated {
                intent.operation != SessionOperation::Renew
            } else {
                intent.generation_id != self.policy.generation_id
            }
        {
            return Err(SessionError::Denied);
        }
        Ok(())
    }

    fn tick(&self) -> Result<i64> {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| SessionError::Unavailable)
    }

    async fn begin(&self) -> Result<Tx<'_>> {
        let mut tx = self.pool.begin().await?;
        let epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM session_service WHERE singleton FOR SHARE")
                .fetch_one(&mut *tx)
                .await?;
        if epoch != self.epoch {
            return Err(SessionError::Unavailable);
        }
        Ok(tx)
    }

    fn admit(&self, device: Id) -> Result<Permit<'_>> {
        let mut counts = self
            .in_flight
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let count = counts.entry(device).or_default();
        if *count >= MAX_ACTIVE_CONTEXTS {
            return Err(SessionError::Limit);
        }
        *count += 1;
        Ok(Permit {
            counts: &self.in_flight,
            device,
        })
    }

    fn check_transition(
        &self,
        current: Option<&Current>,
        intent: &SessionIntent,
        tick: i64,
    ) -> Result<Id> {
        let active = current.filter(|row| row.epoch == self.epoch && tick < row.expires);
        match intent.operation {
            SessionOperation::Open => {
                if active.is_some_and(|row| row.device != intent.device_id) {
                    return Err(SessionError::Limit);
                }
                random()
            }
            SessionOperation::Renew => {
                let row = active.ok_or(SessionError::Expired)?;
                if (row.id, row.device, row.build, row.generation)
                    != (
                        intent.session_id,
                        intent.device_id,
                        intent.build_id,
                        intent.generation_id,
                    )
                {
                    return Err(SessionError::Denied);
                }
                if row.sequence.checked_add(1) != i64::try_from(intent.sequence).ok() {
                    return Err(SessionError::Replay);
                }
                Ok(row.id)
            }
        }
    }
}

struct Permit<'a> {
    counts: &'a Mutex<HashMap<Id, usize>>,
    device: Id,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let std::collections::hash_map::Entry::Occupied(mut entry) = counts.entry(self.device) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }
}

impl Service {
    async fn grant(
        &self,
        tx: &mut Tx<'_>,
        attempt: Redemption<'_>,
    ) -> Result<(SessionGrant, Option<u64>)> {
        let Redemption {
            license_id,
            key,
            intent,
            challenge,
            proof,
            deadline,
            packages,
        } = attempt;
        let tick = self.tick()?;
        if tick >= deadline {
            return Err(SessionError::Expired);
        }
        challenge
            .verify(key, &proof)
            .map_err(|_| SessionError::Denied)?;
        if !charge(tx, intent.device_id, self.epoch, self.tick()?).await? {
            return Err(SessionError::Limit);
        }
        let current = current_session(tx, license_id).await?;
        let tick = self.tick()?;
        if tick >= deadline {
            return Err(SessionError::Expired);
        }
        let active = current
            .as_ref()
            .filter(|row| row.epoch == self.epoch && tick < row.expires);
        match intent.operation {
            SessionOperation::Open => {
                if active.is_some_and(|row| row.device != intent.device_id) {
                    return Err(SessionError::Limit);
                }
            }
            SessionOperation::Renew => {
                let expected = self.check_transition(current.as_ref(), &intent, tick)?;
                if expected != challenge.session_id {
                    return Err(SessionError::Denied);
                }
            }
        }

        let binding = GrantBinding {
            session_id: challenge.session_id,
            device_id: intent.device_id,
            license_id,
            app_id: intent.app_id,
            build_id: intent.build_id,
            generation_id: intent.generation_id,
        };
        let release_expiry = if self.negotiated {
            let packages = packages.ok_or(SessionError::Denied)?;
            Some(verify_selected_release(tx, packages, binding, self.policy.permission.id).await?)
        } else {
            None
        };
        let signed_tick = self.tick()?;
        if signed_tick >= deadline
            || (intent.operation == SessionOperation::Renew
                && active.is_none_or(|row| signed_tick >= row.expires))
        {
            return Err(SessionError::Expired);
        }
        let (grant, expires) = self.sign_grant(
            binding,
            intent.sequence,
            challenge.digest().map_err(|_| SessionError::Unavailable)?,
            signed_tick,
        )?;
        match intent.operation {
            SessionOperation::Open => self.insert_session(tx, binding, expires).await?,
            SessionOperation::Renew => {
                let sequence =
                    i64::try_from(intent.sequence).map_err(|_| SessionError::Unavailable)?;
                sqlx::query("UPDATE sessions SET sequence=$2,expires_tick_ms=$3 WHERE id=$1")
                    .bind(challenge.session_id.as_slice())
                    .bind(sequence)
                    .bind(expires)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Ok((grant, release_expiry))
    }
}

impl Service {
    fn sign_grant(
        &self,
        binding: GrantBinding,
        sequence: u64,
        digest: Digest,
        tick: i64,
    ) -> Result<(SessionGrant, i64)> {
        let issued_at_ms = self
            .wall_start_ms
            .checked_add(tick)
            .and_then(|ms| ms.try_into().ok())
            .ok_or(SessionError::Unavailable)?;
        let expires = tick
            .checked_add(i64::from(MAX_GRANT_LIFETIME_MS))
            .ok_or(SessionError::Unavailable)?;
        let grant = SessionGrant::sign(
            GrantPayload {
                binding,
                policy_epoch: self.policy.policy_epoch,
                sequence,
                issued_at_ms,
                lifetime_ms: MAX_GRANT_LIFETIME_MS,
                permissions: vec![self.policy.permission],
                signing_key_id: public_key_id(self.key.verifying_key()),
                extensions: vec![Extension {
                    id: SESSION_CHALLENGE_EXTENSION,
                    required: false,
                    bytes: digest.to_vec(),
                }],
            },
            &self.key,
        )
        .map_err(|_| SessionError::Unavailable)?;
        Ok((grant, expires))
    }

    async fn insert_session(
        &self,
        tx: &mut Tx<'_>,
        binding: GrantBinding,
        expires: i64,
    ) -> Result<()> {
        sqlx::query("UPDATE sessions SET stopped=true WHERE license_id=$1 AND NOT stopped")
            .bind(binding.license_id.as_slice())
            .execute(&mut **tx)
            .await?;
        sqlx::query(
            "INSERT INTO sessions (id,license_id,device_id,build_id,generation_id,
             service_epoch,sequence,expires_tick_ms) VALUES ($1,$2,$3,$4,$5,$6,1,$7)",
        )
        .bind(binding.session_id.as_slice())
        .bind(binding.license_id.as_slice())
        .bind(binding.device_id.as_slice())
        .bind(binding.build_id.as_slice())
        .bind(binding.generation_id.as_slice())
        .bind(self.epoch)
        .bind(expires)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

struct Redemption<'a> {
    license_id: Id,
    key: &'a VerifyingKey,
    intent: SessionIntent,
    challenge: SessionChallenge,
    proof: [u8; 64],
    deadline: i64,
    packages: Option<&'a PackageStore>,
}

struct Current {
    id: Id,
    device: Id,
    build: Id,
    generation: Id,
    epoch: i64,
    sequence: i64,
    expires: i64,
}

async fn lock_identity(tx: &mut Tx<'_>, device: Id, app: Id) -> Result<(Id, VerifyingKey)> {
    let license: Vec<u8> = sqlx::query_scalar(
        "SELECT l.id FROM devices d JOIN licenses l ON l.id=d.license_id WHERE d.id=$1
         FOR UPDATE OF l",
    )
    .bind(device.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(SessionError::Denied)?;
    // Read device state with a fresh statement snapshot after acquiring the R09 revocation lock.
    let public_key: Vec<u8> = sqlx::query_scalar(
        "SELECT d.public_key FROM devices d JOIN licenses l ON l.id=d.license_id
         WHERE d.id=$1 AND l.id=$2 AND l.app_id=$3 AND l.state='active' AND d.state='active'",
    )
    .bind(device.as_slice())
    .bind(&license)
    .bind(app.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(SessionError::Denied)?;
    let license = license.try_into().map_err(|_| SessionError::Unavailable)?;
    let key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| SessionError::Unavailable)?;
    Ok((license, key))
}

async fn current_session(tx: &mut Tx<'_>, license: Id) -> Result<Option<Current>> {
    sqlx::query(
        "SELECT id,device_id,build_id,generation_id,service_epoch,sequence,expires_tick_ms
         FROM sessions WHERE license_id=$1 AND NOT stopped",
    )
    .bind(license.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| {
        Ok(Current {
            id: id(&row, "id")?,
            device: id(&row, "device_id")?,
            build: id(&row, "build_id")?,
            generation: id(&row, "generation_id")?,
            epoch: row.try_get("service_epoch")?,
            sequence: row.try_get("sequence")?,
            expires: row.try_get("expires_tick_ms")?,
        })
    })
    .transpose()
}

async fn charge(tx: &mut Tx<'_>, device: Id, epoch: i64, tick: i64) -> Result<bool> {
    let credit: i64 = sqlx::query_scalar(
        "INSERT INTO session_rates (device_id,service_epoch,last_tick_ms,credit)
         VALUES ($1,$2,$3,$4-$5)
         ON CONFLICT (device_id) DO UPDATE SET service_epoch=$2,last_tick_ms=$3,
           credit=CASE WHEN session_rates.service_epoch=$2 THEN
             LEAST($4,session_rates.credit+LEAST(2000,GREATEST(0,$3-session_rates.last_tick_ms))*$6)-$5
             ELSE $4-$5 END
         WHERE session_rates.service_epoch<>$2
            OR session_rates.credit+LEAST(2000,GREATEST(0,$3-session_rates.last_tick_ms))*$6 >= $5
         RETURNING credit",
    ).bind(device.as_slice()).bind(epoch).bind(tick).bind(BURST_CREDIT)
     .bind(REQUEST_CREDIT).bind(REFILL_PER_MS).fetch_optional(&mut **tx).await?.unwrap_or(-1);
    Ok(credit >= 0)
}

fn id<const N: usize>(row: &PgRow, field: &str) -> Result<[u8; N]> {
    row.try_get::<&[u8], _>(field)?
        .try_into()
        .map_err(|_| SessionError::Unavailable)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| SessionError::Unavailable)?;
    Ok(out)
}

impl SessionStore {
    pub(crate) fn package_app(&self) -> Id {
        self.0.policy.app_id
    }

    pub(crate) fn grant_signer_id(&self) -> vmkek_protocol::Digest {
        public_key_id(self.0.key.verifying_key())
    }

    pub(crate) fn generation_clock(&self) -> Result<Option<(i64, i64)>> {
        if self.0.negotiated {
            return Ok(Some((self.0.epoch, self.0.tick()?)));
        }
        Ok(None)
    }

    pub(crate) fn is_negotiated(&self) -> bool {
        self.0.negotiated
    }

    pub(crate) fn package_time(&self) -> Result<u64> {
        self.0
            .wall_start_ms
            .checked_add(self.0.tick()?)
            .and_then(|time| time.try_into().ok())
            .ok_or(SessionError::Unavailable)
    }

    pub(crate) async fn begin_package(&self) -> Result<Transaction<'_, Postgres>> {
        self.0.begin().await
    }

    pub(crate) async fn authorize_package(
        &self,
        fetch: &ModuleFetch,
        verify: impl FnOnce(&VerifyingKey) -> std::result::Result<(), vmkek_protocol::ProtocolError>,
    ) -> Result<PackageAuthorization<'_>> {
        if (fetch.app_id, fetch.build_id) != (self.0.policy.app_id, self.0.policy.build_id)
            || (!self.0.negotiated && fetch.generation_id != self.0.policy.generation_id)
            || self.0.policy.permission
                != (Permission {
                    kind: PermissionKind::Function,
                    id: fetch.function_id,
                })
        {
            return Err(SessionError::Denied);
        }
        let permit = self.0.admit(fetch.device_id)?;
        let mut tx = self.0.begin().await?;
        let (license, key) = lock_identity(&mut tx, fetch.device_id, fetch.app_id).await?;
        verify(&key).map_err(|_| SessionError::Denied)?;
        let tick = self.0.tick()?;
        if !charge(&mut tx, fetch.device_id, self.0.epoch, tick).await? {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        let current = current_session(&mut tx, license).await?;
        let tick = self.0.tick()?;
        let active = current.filter(|row| row.epoch == self.0.epoch && tick < row.expires);
        let Some(active) = active else {
            tx.commit().await?;
            return Err(SessionError::Expired);
        };
        if (active.id, active.device, active.build, active.generation)
            != (
                fetch.session_id,
                fetch.device_id,
                fetch.build_id,
                fetch.generation_id,
            )
            || i64::try_from(fetch.sequence).ok() != Some(active.sequence)
        {
            tx.commit().await?;
            return Err(SessionError::Denied);
        }
        let selected = if self.0.negotiated {
            let row = sqlx::query(
                "SELECT c.manifest_sha256,c.descriptor_sha256 FROM generation_selections s
                 JOIN generation_catalog c ON c.generation_id=s.generation_id
                 WHERE s.session_id=$1 AND s.device_id=$2 AND s.consumed
                   AND c.module_id=$3 AND c.module_version=$4",
            )
            .bind(fetch.session_id.as_slice())
            .bind(fetch.device_id.as_slice())
            .bind(fetch.module_id.as_slice())
            .bind(i64::try_from(fetch.module_version).map_err(|_| SessionError::Invalid)?)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                tx.commit().await?;
                return Err(SessionError::Denied);
            };
            Some((id(&row, "descriptor_sha256")?, id(&row, "manifest_sha256")?))
        } else {
            None
        };
        Ok(PackageAuthorization {
            tx,
            _permit: permit,
            service: &self.0,
            expires: active.expires,
            selected,
        })
    }
}

pub(crate) struct PackageAuthorization<'a> {
    pub(crate) tx: Transaction<'a, Postgres>,
    _permit: Permit<'a>,
    service: &'a Service,
    expires: i64,
    pub(crate) selected: Option<(Digest, Digest)>,
}

impl PackageAuthorization<'_> {
    pub(crate) async fn commit_live(self) -> Result<()> {
        let Self {
            tx,
            service,
            expires,
            _permit,
            selected: _,
        } = self;
        tx.commit().await?;
        if service.tick()? >= expires {
            return Err(SessionError::Expired);
        }
        Ok(())
    }

    pub(crate) fn ensure_live(&self) -> Result<()> {
        if self.service.tick()? >= self.expires {
            return Err(SessionError::Expired);
        }
        Ok(())
    }
}

impl SessionStore {
    pub(crate) fn check_generation_scope(&self, app: Id, build: Id, function: Id) -> Result<()> {
        if !self.0.negotiated
            || (
                self.0.policy.app_id,
                self.0.policy.build_id,
                self.0.policy.permission.id,
            ) != (app, build, function)
        {
            return Err(SessionError::Denied);
        }
        Ok(())
    }

    pub(crate) fn verify_generation_choice<'a>(
        &self,
        signed: &'a SignedGenerationChoice,
    ) -> Result<&'a GenerationChoice> {
        let choice = signed
            .verify_for(self.0.key.verifying_key())
            .map_err(|_| SessionError::Denied)?;
        self.check_generation_scope(
            choice.binding.app_id,
            choice.binding.build_id,
            choice.function_id,
        )?;
        if choice.policy_epoch != self.0.policy.policy_epoch {
            return Err(SessionError::Denied);
        }
        Ok(choice)
    }

    pub(crate) async fn begin_generation(
        &self,
        app: Id,
        build: Id,
        function: Id,
        device: Id,
        verify: impl FnOnce(&VerifyingKey) -> std::result::Result<(), vmkek_protocol::ProtocolError>,
    ) -> Result<GenerationAuthorization<'_>> {
        self.check_generation_scope(app, build, function)?;
        let permit = self.0.admit(device)?;
        let mut tx = self.0.begin().await?;
        let (license_id, key) = lock_identity(&mut tx, device, app).await?;
        verify(&key).map_err(|_| SessionError::Denied)?;
        let tick = self.0.tick()?;
        if !charge(&mut tx, device, self.0.epoch, tick).await? {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        let current = current_session(&mut tx, license_id).await?;
        if current.is_some_and(|row| {
            row.epoch == self.0.epoch && tick < row.expires && row.device != device
        }) {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        Ok(GenerationAuthorization {
            tx,
            license_id,
            _permit: permit,
            service: &self.0,
        })
    }
}

pub(crate) struct GenerationAuthorization<'a> {
    pub(crate) tx: Transaction<'a, Postgres>,
    pub(crate) license_id: Id,
    _permit: Permit<'a>,
    service: &'a Service,
}

impl GenerationAuthorization<'_> {
    pub(crate) async fn commit_before(self, deadline: i64) -> Result<()> {
        let Self {
            tx,
            service,
            _permit,
            ..
        } = self;
        tx.commit().await?;
        if service.tick()? >= deadline {
            return Err(SessionError::Expired);
        }
        Ok(())
    }

    pub(crate) fn tick(&self) -> Result<i64> {
        self.service.tick()
    }
    pub(crate) fn epoch(&self) -> i64 {
        self.service.epoch
    }
    pub(crate) fn policy_epoch(&self) -> u64 {
        self.service.policy.policy_epoch
    }
    pub(crate) fn signer_id(&self) -> Digest {
        public_key_id(self.service.key.verifying_key())
    }

    pub(crate) fn sign_choice(&self, choice: GenerationChoice) -> Result<SignedGenerationChoice> {
        SignedGenerationChoice::sign(choice, &self.service.key)
            .map_err(|_| SessionError::Unavailable)
    }

    pub(crate) async fn activate(
        &mut self,
        choice: &GenerationChoice,
        digest: Digest,
        deadline: i64,
    ) -> Result<SessionGrant> {
        let tick = self.tick()?;
        if tick >= deadline {
            return Err(SessionError::Expired);
        }
        let (grant, expiry) = self.service.sign_grant(choice.binding, 1, digest, tick)?;
        self.service
            .insert_session(&mut self.tx, choice.binding, expiry)
            .await?;
        Ok(grant)
    }
}

async fn verify_selected_release(
    tx: &mut Tx<'_>,
    packages: &PackageStore,
    binding: GrantBinding,
    function_id: Id,
) -> Result<u64> {
    let row = sqlx::query(
        "SELECT c.module_id,c.module_version,c.descriptor_sha256,c.manifest_sha256
         FROM generation_selections s JOIN generation_catalog c ON c.generation_id=s.generation_id
         WHERE s.session_id=$1 AND s.device_id=$2 AND s.consumed
           AND c.generation_id=$3 AND c.app_id=$4 AND c.build_id=$5 AND c.function_id=$6",
    )
    .bind(binding.session_id.as_slice())
    .bind(binding.device_id.as_slice())
    .bind(binding.generation_id.as_slice())
    .bind(binding.app_id.as_slice())
    .bind(binding.build_id.as_slice())
    .bind(function_id.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(SessionError::Denied)?;
    let version = row
        .try_get::<i64, _>("module_version")?
        .try_into()
        .map_err(|_| SessionError::Unavailable)?;
    let scope = ReleaseScope {
        build_id: binding.build_id,
        generation_id: binding.generation_id,
        function_id,
        module_id: id(&row, "module_id")?,
        version,
    };
    packages
        .load_active_release(
            tx,
            binding.app_id,
            scope,
            Some(id(&row, "descriptor_sha256")?),
            Some(id(&row, "manifest_sha256")?),
        )
        .await
        .map(|(_, manifest)| manifest.expires_at_ms)
        .map_err(|error| match error {
            PackageError::Unavailable | PackageError::Session(SessionError::Unavailable) => {
                SessionError::Unavailable
            }
            _ => SessionError::Denied,
        })
}

impl SessionStore {
    pub(crate) fn shares_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn admits_function(&self, app: Id, build: Id, function: Id) -> bool {
        (
            self.0.policy.app_id,
            self.0.policy.build_id,
            self.0.policy.permission,
        ) == (
            app,
            build,
            Permission {
                kind: PermissionKind::Function,
                id: function,
            },
        )
    }

    pub(crate) async fn authorize_operation(
        &self,
        request: &SampleOperationRequest,
        proof: &[u8; 64],
        operation_signer_id: Digest,
        packages: Option<&PackageStore>,
    ) -> Result<OperationAuthorization<'_>> {
        if !self.admits_function(request.app_id, request.build_id, request.function_id)
            || (!self.0.negotiated && self.0.policy.generation_id != request.generation_id)
        {
            return Err(SessionError::Denied);
        }
        let permit = self.0.admit(request.device_id)?;
        let mut tx = self.0.begin().await?;
        let (license_id, key) = lock_identity(&mut tx, request.device_id, request.app_id).await?;
        if public_key_id(&key) == operation_signer_id {
            return Err(SessionError::Denied);
        }
        request
            .verify(&key, proof)
            .map_err(|_| SessionError::Denied)?;
        if !charge(&mut tx, request.device_id, self.0.epoch, self.0.tick()?).await? {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        let current = current_session(&mut tx, license_id).await?;
        let tick = self.0.tick()?;
        let Some(active) = current.filter(|row| row.epoch == self.0.epoch && tick < row.expires)
        else {
            tx.commit().await?;
            return Err(SessionError::Expired);
        };
        if (active.id, active.device, active.build, active.generation)
            != (
                request.session_id,
                request.device_id,
                request.build_id,
                request.generation_id,
            )
            || i64::try_from(request.sequence).ok() != Some(active.sequence)
        {
            tx.commit().await?;
            return Err(SessionError::Denied);
        }
        let binding = GrantBinding {
            license_id,
            session_id: active.id,
            device_id: active.device,
            app_id: request.app_id,
            build_id: active.build,
            generation_id: active.generation,
        };
        let release_expiry = if self.0.negotiated {
            let packages = packages.ok_or(SessionError::Denied)?;
            match verify_selected_release(&mut tx, packages, binding, request.function_id).await {
                Ok(expiry) => Some(expiry),
                Err(SessionError::Unavailable) => return Err(SessionError::Unavailable),
                Err(error) => {
                    tx.commit().await?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(OperationAuthorization {
            tx,
            binding,
            _permit: permit,
            service: &self.0,
            expires: active.expires,
            release_expiry,
        })
    }
}

pub(crate) struct OperationAuthorization<'a> {
    pub(crate) tx: Transaction<'a, Postgres>,
    pub(crate) binding: GrantBinding,
    _permit: Permit<'a>,
    service: &'a Service,
    expires: i64,
    release_expiry: Option<u64>,
}

impl OperationAuthorization<'_> {
    pub(crate) fn policy_epoch(&self) -> u64 {
        self.service.policy.policy_epoch
    }

    pub(crate) fn ensure_live(&self) -> Result<()> {
        ensure_operation_live(self.service, self.expires, self.release_expiry)
    }

    pub(crate) async fn commit_live(self) -> Result<()> {
        let Self {
            tx,
            service,
            expires,
            release_expiry,
            _permit,
            ..
        } = self;
        tx.commit().await?;
        ensure_operation_live(service, expires, release_expiry)
    }
}

fn ensure_operation_live(
    service: &Service,
    expires: i64,
    release_expiry: Option<u64>,
) -> Result<()> {
    let tick = service.tick()?;
    if tick >= expires {
        return Err(SessionError::Expired);
    }
    if let Some(expiry) = release_expiry {
        let wall: u64 = service
            .wall_start_ms
            .checked_add(tick)
            .and_then(|ms| ms.try_into().ok())
            .ok_or(SessionError::Unavailable)?;
        if wall >= expiry {
            return Err(SessionError::Expired);
        }
    }
    Ok(())
}
