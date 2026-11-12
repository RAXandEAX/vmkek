use sqlx::{PgPool, Postgres, Row, Transaction};
use vmkek_protocol::{
    access_command::{AccessAction, AccessAuthority, AccessCommand, SignedAccessCommand},
    Digest, Id,
};

use super::{AccessDecision, AccessError};
use crate::{IdentityError, RevokeReason};

type Tx<'a> = Transaction<'a, Postgres>;
type Result<T> = std::result::Result<T, AccessError>;

#[derive(Clone, Copy)]
struct Target {
    license: Id,
    device: Option<Id>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Active,
    Quarantine,
    Revoked,
}

impl State {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "quarantine" => Ok(Self::Quarantine),
            "revoked" => Ok(Self::Revoked),
            _ => Err(AccessError::Unavailable),
        }
    }
}

impl From<&AccessCommand> for Target {
    fn from(command: &AccessCommand) -> Self {
        Self {
            license: command.license_id,
            device: command.device_id,
        }
    }
}

pub(super) async fn apply(
    pool: &PgPool,
    authority: AccessAuthority<'_>,
    policy_version: u64,
    signed: &SignedAccessCommand,
) -> Result<AccessDecision> {
    let mut tx = pool.begin().await?;
    let verified = signed.verify_for(authority, policy_version, database_time(&mut tx).await?)?;
    let command = verified.payload();
    let digest = verified.digest();
    let target = Target::from(command);
    let license_state = lock_license(&mut tx, target, authority.app_id).await?;
    check_expiry(&mut tx, command).await?;
    if let Some(decision) = prior_request(&mut tx, command, digest).await? {
        tx.commit().await?;
        return Ok(decision);
    }
    validate_transition(&mut tx, command, target, license_state).await?;
    let decision = apply_transition(&mut tx, command, target, digest).await?;
    tx.commit().await?;
    Ok(decision)
}

async fn database_time(tx: &mut Tx<'_>) -> Result<u64> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    now.try_into().map_err(|_| AccessError::Unavailable)
}

async fn check_expiry(tx: &mut Tx<'_>, command: &AccessCommand) -> Result<()> {
    let now = database_time(tx).await?;
    if !(command.issued_at_ms..command.expires_at_ms).contains(&now) {
        return Err(AccessError::Expired);
    }
    Ok(())
}

async fn lock_license(tx: &mut Tx<'_>, target: Target, app: Id) -> Result<State> {
    let state: String =
        sqlx::query_scalar("SELECT state FROM licenses WHERE id=$1 AND app_id=$2 FOR UPDATE")
            .bind(target.license.as_slice())
            .bind(app.as_slice())
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AccessError::Denied)?;
    State::parse(&state)
}

async fn target_state(tx: &mut Tx<'_>, target: Target, license_state: State) -> Result<State> {
    let Some(device) = target.device else {
        return Ok(license_state);
    };
    let state: String =
        sqlx::query_scalar("SELECT state FROM devices WHERE license_id=$1 AND id=$2")
            .bind(target.license.as_slice())
            .bind(device.as_slice())
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AccessError::Denied)?;
    State::parse(&state)
}

async fn validate_transition(
    tx: &mut Tx<'_>,
    command: &AccessCommand,
    target: Target,
    license_state: State,
) -> Result<()> {
    let state = target_state(tx, target, license_state).await?;
    match command.action {
        AccessAction::Revoke if state != State::Revoked => Ok(()),
        AccessAction::Restore { prior_decision_id }
            if state == State::Revoked
                && (target.device.is_none() || license_state == State::Active) =>
        {
            require_latest_revoke(tx, target, prior_decision_id).await
        }
        _ => Err(AccessError::Conflict),
    }
}

async fn require_latest_revoke(tx: &mut Tx<'_>, target: Target, prior: u64) -> Result<()> {
    let row = sqlx::query(
        "SELECT id,action FROM access_decisions WHERE license_id=$1 AND device_id IS NOT DISTINCT FROM $2
         ORDER BY id DESC LIMIT 1",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AccessError::Conflict)?;
    if row.try_get::<i64, _>("id")? != prior as i64 || row.try_get::<&str, _>("action")? != "revoke"
    {
        return Err(AccessError::Conflict);
    }
    Ok(())
}

async fn prior_request(
    tx: &mut Tx<'_>,
    command: &AccessCommand,
    digest: Digest,
) -> Result<Option<AccessDecision>> {
    let row = sqlx::query(
        "SELECT id,request_digest FROM access_decisions WHERE actor_id=$1 AND request_id=$2",
    )
    .bind(command.actor_id.as_slice())
    .bind(command.request_id.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        if row.try_get::<&[u8], _>("request_digest")? != digest {
            return Err(AccessError::Conflict);
        }
        Ok(AccessDecision {
            id: checked_id(row.try_get("id")?)?,
            replayed: true,
        })
    })
    .transpose()
}

async fn apply_transition(
    tx: &mut Tx<'_>,
    command: &AccessCommand,
    target: Target,
    digest: Digest,
) -> Result<AccessDecision> {
    let (action, restore_of, state, event) = match command.action {
        AccessAction::Revoke => ("revoke", None, "revoked", "revoked"),
        AccessAction::Restore { prior_decision_id } => (
            "restore",
            Some(prior_decision_id as i64),
            "active",
            "restored",
        ),
    };
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO access_decisions
         (license_id,device_id,actor_id,reason,action,policy_version,request_id,request_digest,restore_of)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (actor_id,request_id) DO NOTHING RETURNING id",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .bind(command.actor_id.as_slice())
    .bind(command.reason as i16)
    .bind(action)
    .bind(command.policy_version as i64)
    .bind(command.request_id.as_slice())
    .bind(digest.as_slice())
    .bind(restore_of)
    .fetch_optional(&mut **tx)
    .await?;
    check_expiry(tx, command).await?;
    let Some(id) = id else {
        return prior_request(tx, command, digest)
            .await?
            .ok_or(AccessError::Conflict);
    };
    change_state(tx, target, state).await?;
    write_audit(tx, target, id, event).await?;
    Ok(AccessDecision {
        id: checked_id(id)?,
        replayed: false,
    })
}

fn checked_id(id: i64) -> Result<u64> {
    u64::try_from(id).map_err(|_| AccessError::Unavailable)
}

async fn change_state(tx: &mut Tx<'_>, target: Target, state: &str) -> Result<()> {
    let count = match target.device {
        Some(device) => {
            sqlx::query("UPDATE devices SET state=$1 WHERE license_id=$2 AND id=$3")
                .bind(state)
                .bind(target.license.as_slice())
                .bind(device.as_slice())
                .execute(&mut **tx)
                .await?
        }
        None => {
            sqlx::query("UPDATE licenses SET state=$1 WHERE id=$2")
                .bind(state)
                .bind(target.license.as_slice())
                .execute(&mut **tx)
                .await?
        }
    };
    if count.rows_affected() != 1 {
        return Err(AccessError::Denied);
    }
    if state == "revoked" {
        stop_sessions(tx, target).await?;
    }
    Ok(())
}

async fn stop_sessions(tx: &mut Tx<'_>, target: Target) -> Result<()> {
    sqlx::query(
        "UPDATE sessions SET stopped=true WHERE license_id=$1 AND NOT stopped
             AND ($2::bytea IS NULL OR device_id=$2)",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE session_requests r SET consumed=true FROM devices d
         WHERE r.device_id=d.id AND d.license_id=$1 AND NOT r.consumed
           AND ($2::bytea IS NULL OR d.id=$2)",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE generation_selections s SET consumed=true FROM devices d
         WHERE s.device_id=d.id AND d.license_id=$1 AND NOT s.consumed
           AND ($2::bytea IS NULL OR d.id=$2)",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn write_audit(tx: &mut Tx<'_>, target: Target, decision: i64, event: &str) -> Result<()> {
    sqlx::query("INSERT INTO audit (license_id,device_id,decision_id,event) VALUES ($1,$2,$3,$4)")
        .bind(target.license.as_slice())
        .bind(target.device.as_ref().map(|id| id.as_slice()))
        .bind(decision)
        .bind(event)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn revoke_legacy(
    pool: &PgPool,
    license: Id,
    device: Option<Id>,
    actor: Id,
    reason: RevokeReason,
) -> std::result::Result<(), IdentityError> {
    legacy_revoke(pool, Target { license, device }, actor, reason)
        .await
        .map_err(|error| match error {
            AccessError::Denied => IdentityError::Denied,
            _ => IdentityError::Unavailable,
        })
}

async fn legacy_revoke(
    pool: &PgPool,
    target: Target,
    actor: Id,
    reason: RevokeReason,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(target.license.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(AccessError::Denied);
    }
    change_state(&mut tx, target, "revoked").await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO access_decisions (license_id,device_id,actor_id,reason,action)
         VALUES ($1,$2,$3,$4,'revoke') RETURNING id",
    )
    .bind(target.license.as_slice())
    .bind(target.device.as_ref().map(|id| id.as_slice()))
    .bind(actor.as_slice())
    .bind(reason as i16)
    .fetch_one(&mut *tx)
    .await?;
    write_audit(&mut tx, target, id, "revoked").await?;
    tx.commit().await?;
    Ok(())
}
