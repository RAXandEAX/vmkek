use vmkek_protocol::{
    session_observation::{ObservationAction, SessionObservation, MAX_OBSERVATIONS},
    Digest, Id, SESSION_PROOF_BYTES,
};

use super::{
    charge, current_session, lock_identity, Current, Result, SessionError, SessionStore, Tx,
};

impl SessionStore {
    pub(crate) async fn observe_session(
        &self,
        report: SessionObservation,
        proof: [u8; SESSION_PROOF_BYTES],
    ) -> Result<()> {
        let digest = report.digest().map_err(|_| SessionError::Invalid)?;
        if !self.admits_function(report.app_id, report.build_id, report.function_id) {
            return Err(SessionError::Denied);
        }
        let service = &self.0;
        let _permit = service.admit(report.device_id)?;
        let mut tx = service.begin().await?;
        let (license, key) = lock_identity(&mut tx, report.device_id, report.app_id).await?;
        report
            .verify(&key, &proof)
            .map_err(|_| SessionError::Denied)?;
        if !charge(&mut tx, report.device_id, service.epoch, service.tick()?).await? {
            tx.commit().await?;
            return Err(SessionError::Limit);
        }
        match self
            .apply_observation(&mut tx, license, &report, digest)
            .await
        {
            Ok(expires) if service.tick()? < expires => tx.commit().await.map_err(Into::into),
            Ok(_) => Err(SessionError::Expired),
            Err(SessionError::Unavailable) => Err(SessionError::Unavailable),
            Err(error) => {
                tx.commit().await?;
                Err(error)
            }
        }
    }

    async fn apply_observation(
        &self,
        tx: &mut Tx<'_>,
        license: Id,
        report: &SessionObservation,
        digest: Digest,
    ) -> Result<i64> {
        if request_used(tx, report).await? {
            return Err(SessionError::Replay);
        }
        let active = current_session(tx, license)
            .await?
            .ok_or(SessionError::Expired)?;
        let service = &self.0;
        check_scope(&active, report)?;
        if active.epoch != service.epoch || service.tick()? >= active.expires {
            return Err(SessionError::Expired);
        }
        if report.action == ObservationAction::ReportOnly
            && report_limit(tx, report.session_id).await?
        {
            return Err(SessionError::Limit);
        }
        insert_report(tx, report, digest).await?;
        if report.action == ObservationAction::RequestOwnStop {
            stop_session(tx, license, report).await?;
        }
        Ok(active.expires)
    }
}

fn check_scope(active: &Current, report: &SessionObservation) -> Result<()> {
    if (
        active.id,
        active.device,
        active.build,
        active.generation,
        active.sequence,
    ) != (
        report.session_id,
        report.device_id,
        report.build_id,
        report.generation_id,
        report.sequence as i64,
    ) {
        return Err(SessionError::Denied);
    }
    Ok(())
}

async fn request_used(tx: &mut Tx<'_>, report: &SessionObservation) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM session_requests WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM package_fetch_requests WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM generation_offers WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM operation_requests WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM session_observation_reports WHERE device_id=$1 AND request_id=$2)",
    )
    .bind(report.device_id.as_slice())
    .bind(report.request_id.as_slice())
    .fetch_one(&mut **tx)
    .await?)
}

async fn report_limit(tx: &mut Tx<'_>, session: Id) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session_observation_reports WHERE session_id=$1 AND action=1",
    )
    .bind(session.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    Ok(count >= MAX_OBSERVATIONS as i64)
}

async fn insert_report(tx: &mut Tx<'_>, report: &SessionObservation, digest: Digest) -> Result<()> {
    let mut records = Vec::with_capacity(4 * report.records.len());
    for record in &report.records {
        records.push(record.kind as u8);
        records.extend(record.rule_id.to_le_bytes());
        records.push(record.finding as u8);
    }
    sqlx::query(
        "INSERT INTO session_observation_reports
         (device_id,request_id,session_id,request_digest,detection_policy_epoch,action,records)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(report.device_id.as_slice())
    .bind(report.request_id.as_slice())
    .bind(report.session_id.as_slice())
    .bind(digest.as_slice())
    .bind(report.detection_policy_epoch as i64)
    .bind(report.action as i16)
    .bind(records)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn stop_session(tx: &mut Tx<'_>, license: Id, report: &SessionObservation) -> Result<()> {
    let changed = sqlx::query(
        "UPDATE sessions SET stopped=true WHERE id=$1 AND license_id=$2 AND device_id=$3 AND NOT stopped",
    ).bind(report.session_id.as_slice()).bind(license.as_slice())
     .bind(report.device_id.as_slice()).execute(&mut **tx).await?;
    if changed.rows_affected() != 1 {
        return Err(SessionError::Unavailable);
    }
    Ok(())
}
