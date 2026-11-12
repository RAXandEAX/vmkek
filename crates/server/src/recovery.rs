use p256::ecdsa::VerifyingKey;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use vmkek_protocol::{
    public_key_id, Digest, Id, RecoveryCheckpoint, RecoveryScope, SignedRecoveryCheckpoint,
    RECOVERY_SNAPSHOT_VERSION,
};

type Tx<'a> = Transaction<'a, Postgres>;

const MAX_SNAPSHOT_ROWS: i64 = 100_000;
const MAX_CHECKPOINT_AGE_MS: u64 = 15 * 60 * 1000;
const POSTGRES_MAJOR: i32 = 16;
const TABLES: &[(&str, &str)] = &[
    ("_sqlx_migrations", "version"),
    ("access_decisions", "id"),
    ("audit", "id"),
    ("devices", "id"),
    ("enrollments", "id"),
    ("generation_catalog", "generation_id"),
    ("generation_offers", "device_id, request_id"),
    ("generation_selections", "device_id, request_id"),
    ("licenses", "id"),
    ("operation_requests", "device_id, request_id"),
    ("package_audit", "id"),
    ("package_fetch_requests", "device_id, request_id"),
    ("package_releases", "app_id, module_id, version"),
    ("package_revoked_keys", "app_id, key_id"),
    ("package_trust", "app_id"),
    ("protected_operation_audit", "id"),
    (
        "protected_operations",
        "app_id, build_id, function_id, operation_id",
    ),
    ("recovery_identity", "singleton"),
    ("session_observation_reports", "device_id, request_id"),
    ("session_rates", "device_id"),
    ("session_requests", "device_id, request_id"),
    ("session_service", "singleton"),
    ("sessions", "id"),
];
const SEQUENCES: &[&str] = &[
    "access_decisions_id_seq",
    "audit_id_seq",
    "generation_catalog_ordinal_seq",
    "package_audit_id_seq",
    "protected_operation_audit_id_seq",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryError {
    #[error("checkpoint trust or scope mismatch")]
    Authority,
    #[error("checkpoint is outside its freshness window")]
    Stale,
    #[error("restored state differs from the checkpoint")]
    Snapshot,
    #[error("unsupported or oversized recovery snapshot")]
    Limit,
    #[error("recovery database unavailable")]
    Unavailable,
}

impl From<sqlx::Error> for RecoveryError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryBootError {
    #[error(transparent)]
    Checkpoint(#[from] RecoveryError),
    #[error(transparent)]
    Session(#[from] crate::session::SessionError),
}

impl From<sqlx::Error> for RecoveryBootError {
    fn from(_: sqlx::Error) -> Self {
        Self::Session(crate::session::SessionError::Unavailable)
    }
}

impl RecoveryBootError {
    pub(crate) fn into_session(self) -> crate::session::SessionError {
        use crate::session::SessionError;
        match self {
            Self::Session(error) => error,
            Self::Checkpoint(RecoveryError::Unavailable) => SessionError::Unavailable,
            Self::Checkpoint(RecoveryError::Limit) => SessionError::Limit,
            Self::Checkpoint(_) => SessionError::Denied,
        }
    }
}

#[derive(Clone, Copy)]
pub struct LatestCheckpoint {
    pub scope: RecoveryScope,
    pub fence_id: Id,
    pub sequence: u64,
    pub signed_sha256: Digest,
}

/// Latest identity comes from a trusted source independent of the restored database.
/// The signer must attest the operator's completed old-writer fencing procedure.
pub struct RecoveryProof<'a> {
    pub checkpoint: &'a SignedRecoveryCheckpoint,
    pub independent_pin: &'a VerifyingKey,
    pub latest: LatestCheckpoint,
}

impl RecoveryProof<'_> {
    pub(crate) fn verify(
        &self,
        app_id: Id,
        build_id: Id,
        policy_epoch: u64,
        grant_signer: Digest,
    ) -> Result<RecoveryCheckpoint, RecoveryError> {
        let checkpoint = *self
            .checkpoint
            .verify_for(self.independent_pin)
            .map_err(|_| RecoveryError::Authority)?;
        if checkpoint.scope != self.latest.scope
            || checkpoint.scope.app_id != app_id
            || checkpoint.scope.build_id != build_id
            || checkpoint.fence_id != self.latest.fence_id
            || checkpoint.sequence != self.latest.sequence
            || self.checkpoint.digest() != self.latest.signed_sha256
            || checkpoint.signing_key_id == grant_signer
            || policy_epoch < checkpoint.policy_epoch
        {
            return Err(RecoveryError::Authority);
        }
        check_fresh(&checkpoint)?;
        Ok(checkpoint)
    }
}

/// Capture one recovery checkpoint payload after quiescing the deployment.
/// The operator signs it and publishes its exact digest independently of PostgreSQL.
pub async fn capture_checkpoint(
    pool: &PgPool,
    scope: RecoveryScope,
    fence_id: Id,
    sequence: u64,
    pin: &VerifyingKey,
) -> Result<RecoveryCheckpoint, RecoveryError> {
    if [
        scope.deployment_id,
        scope.app_id,
        scope.build_id,
        scope.history_id,
        fence_id,
    ]
    .contains(&[0; 16])
        || !(1..=i64::MAX as u64).contains(&sequence)
    {
        return Err(RecoveryError::Authority);
    }
    let mut tx = pool.begin().await?;
    configure_transaction(&mut tx).await?;
    lock_checked_identity(&mut tx).await?;
    lock_snapshot(&mut tx).await?;
    verify_migrations(&mut tx).await?;
    sqlx::query(
        "INSERT INTO public.recovery_identity(singleton,deployment_id,app_id,build_id,history_id)
         VALUES(true,$1,$2,$3,$4) ON CONFLICT DO NOTHING",
    )
    .bind(scope.deployment_id.as_slice())
    .bind(scope.app_id.as_slice())
    .bind(scope.build_id.as_slice())
    .bind(scope.history_id.as_slice())
    .execute(&mut *tx)
    .await?;
    verify_scope(&mut tx, scope).await?;
    let (service_epoch, policy_epoch) = epochs(&mut tx).await?;
    let snapshot_sha256 = snapshot(&mut tx).await?;
    let checkpoint = RecoveryCheckpoint {
        scope,
        fence_id,
        sequence,
        issued_at_ms: now_ms()?,
        service_epoch,
        policy_epoch,
        snapshot_version: RECOVERY_SNAPSHOT_VERSION,
        snapshot_sha256,
        signing_key_id: public_key_id(pin),
    };
    tx.commit().await?;
    Ok(checkpoint)
}

pub(crate) async fn configure_transaction(tx: &mut Tx<'_>) -> Result<(), RecoveryError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '15s'")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn lock_checked_identity(tx: &mut Tx<'_>) -> Result<(), RecoveryError> {
    let trusted_path: bool = sqlx::query_scalar(
        "SELECT pg_catalog.current_schemas(false) = ARRAY['public']::pg_catalog.name[]
            AND pg_catalog.pg_my_temp_schema() = 0",
    )
    .fetch_one(&mut **tx)
    .await?;
    if !trusted_path {
        return Err(RecoveryError::Authority);
    }
    sqlx::query("LOCK TABLE public.recovery_identity IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn is_lab_marked(tx: &mut Tx<'_>) -> Result<bool, RecoveryError> {
    // Lock the canonical marker before any distinct, path-local Lab marker.
    let (has_public, has_distinct_local): (bool, bool) = sqlx::query_as(
        "SELECT pg_catalog.to_regclass('public.recovery_identity') IS NOT NULL,
            pg_catalog.to_regclass('recovery_identity') IS NOT NULL AND
            pg_catalog.to_regclass('recovery_identity')
                IS DISTINCT FROM pg_catalog.to_regclass('public.recovery_identity')",
    )
    .fetch_one(&mut **tx)
    .await?;
    if has_public {
        sqlx::query("LOCK TABLE public.recovery_identity IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut **tx)
            .await?;
        let marked: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM public.recovery_identity)")
                .fetch_one(&mut **tx)
                .await?;
        if marked {
            return Ok(true);
        }
    }
    if has_distinct_local {
        sqlx::query("LOCK TABLE recovery_identity IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut **tx)
            .await?;
        return Ok(
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM recovery_identity)")
                .fetch_one(&mut **tx)
                .await?,
        );
    }
    Ok(false)
}

async fn verify_migrations(tx: &mut Tx<'_>) -> Result<(), RecoveryError> {
    let expected = crate::store::MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration());
    let count = expected.clone().count();
    let limit = i64::try_from(count + 1).map_err(|_| RecoveryError::Limit)?;
    let applied: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, success, checksum FROM public._sqlx_migrations ORDER BY version LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    if applied.len() != count
        || expected
            .zip(applied)
            .any(|(migration, (version, success, checksum))| {
                !success || version != migration.version || checksum != migration.checksum.as_ref()
            })
    {
        return Err(RecoveryError::Snapshot);
    }
    Ok(())
}

pub(crate) async fn verify_restored(
    tx: &mut Tx<'_>,
    checkpoint: &RecoveryCheckpoint,
) -> Result<(), RecoveryError> {
    lock_checked_identity(tx).await?;
    lock_snapshot(tx).await?;
    verify_migrations(tx).await?;
    verify_scope(tx, checkpoint.scope).await?;
    if epochs(tx).await? != (checkpoint.service_epoch, checkpoint.policy_epoch)
        || snapshot(tx).await? != checkpoint.snapshot_sha256
    {
        return Err(RecoveryError::Snapshot);
    }
    check_fresh(checkpoint)
}

pub(crate) fn check_fresh(checkpoint: &RecoveryCheckpoint) -> Result<(), RecoveryError> {
    let age = now_ms()?
        .checked_sub(checkpoint.issued_at_ms)
        .ok_or(RecoveryError::Stale)?;
    if age > MAX_CHECKPOINT_AGE_MS {
        return Err(RecoveryError::Stale);
    }
    Ok(())
}

async fn lock_snapshot(tx: &mut Tx<'_>) -> Result<(), RecoveryError> {
    let major: i32 = sqlx::query_scalar(
        "SELECT pg_catalog.current_setting('server_version_num')::integer/10000",
    )
    .fetch_one(&mut **tx)
    .await?;
    if major != POSTGRES_MAJOR {
        return Err(RecoveryError::Limit);
    }
    let tables = TABLES
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| *name != "recovery_identity")
        .map(|name| format!("public.{name}"))
        .collect::<Vec<_>>()
        .join(", ");
    // Every identifier comes from the fixed v1 schema list above.
    sqlx::query(&format!("LOCK TABLE {tables} IN SHARE ROW EXCLUSIVE MODE"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn verify_scope(tx: &mut Tx<'_>, scope: RecoveryScope) -> Result<(), RecoveryError> {
    let matches: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM public.recovery_identity WHERE singleton
         AND deployment_id=$1 AND app_id=$2 AND build_id=$3 AND history_id=$4)",
    )
    .bind(scope.deployment_id.as_slice())
    .bind(scope.app_id.as_slice())
    .bind(scope.build_id.as_slice())
    .bind(scope.history_id.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    if !matches {
        return Err(RecoveryError::Authority);
    }
    Ok(())
}

async fn epochs(tx: &mut Tx<'_>) -> Result<(u64, u64), RecoveryError> {
    let row = sqlx::query("SELECT epoch,policy_epoch FROM public.session_service WHERE singleton")
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(RecoveryError::Snapshot)?;
    Ok((
        row.try_get::<i64, _>("epoch")?
            .try_into()
            .map_err(|_| RecoveryError::Snapshot)?,
        row.try_get::<i64, _>("policy_epoch")?
            .try_into()
            .map_err(|_| RecoveryError::Snapshot)?,
    ))
}

async fn snapshot(tx: &mut Tx<'_>) -> Result<Digest, RecoveryError> {
    let mut hash = Sha256::new();
    hash.update(b"vmkek.postgres.recovery.snapshot\0");
    hash.update(RECOVERY_SNAPSHOT_VERSION.to_le_bytes());
    hash.update(POSTGRES_MAJOR.to_le_bytes());
    let mut remaining = MAX_SNAPSHOT_ROWS;
    for &(name, order) in TABLES {
        // PostgreSQL 16 record_send encodes a field count, built-in field types,
        // and a signed length per field (-1 for NULL, 0 for empty). The driver
        // receives only one 32-byte digest per row, including for large frames.
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(&format!(
            "SELECT pg_catalog.sha256(pg_catalog.record_send(t)) FROM public.{name} t ORDER BY {order} LIMIT $1"
        )).bind(remaining + 1).fetch_all(&mut **tx).await?;
        remaining -= i64::try_from(rows.len()).map_err(|_| RecoveryError::Limit)?;
        if remaining < 0 {
            return Err(RecoveryError::Limit);
        }
        hash_rows(&mut hash, b'T', name, rows)?;
    }
    for &name in SEQUENCES {
        let row = sqlx::query_scalar(&format!(
            "SELECT pg_catalog.sha256(pg_catalog.record_send(ROW(last_value,is_called))) FROM public.{name}"
        )).fetch_one(&mut **tx).await?;
        hash_rows(&mut hash, b'S', name, vec![row])?;
    }
    Ok(hash.finalize().into())
}

fn hash_rows(
    hash: &mut Sha256,
    kind: u8,
    name: &str,
    rows: Vec<Vec<u8>>,
) -> Result<(), RecoveryError> {
    hash.update([kind]);
    hash.update((name.len() as u16).to_le_bytes());
    hash.update(name.as_bytes());
    hash.update((rows.len() as u64).to_le_bytes());
    for row in rows {
        let digest: Digest = row.try_into().map_err(|_| RecoveryError::Snapshot)?;
        hash.update(digest);
    }
    Ok(())
}

fn now_ms() -> Result<u64, RecoveryError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RecoveryError::Stale)?
        .as_millis()
        .try_into()
        .map_err(|_| RecoveryError::Stale)
}
