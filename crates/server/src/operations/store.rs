use p256::ecdsa::SigningKey;
use sqlx::{Postgres, Row, Transaction};
use vmkek_protocol::{
    public_key_id, GrantBinding, Id, OperationReceipt, SampleOperationRequest,
    SignedOperationReceipt, SAMPLE_JOB_RECEIPT_OPERATION,
};

use crate::{
    packages::{PackageError, PackageStore},
    session::{SessionError, SessionStore},
};

type Tx<'a> = Transaction<'a, Postgres>;
type Result<T> = std::result::Result<T, PackageError>;

#[derive(Clone, Copy)]
pub struct SampleOperationPolicy {
    pub app_id: Id,
    pub build_id: Id,
    pub function_id: Id,
}

#[derive(Clone)]
pub struct OperationStore {
    pub(crate) session: SessionStore,
    pub(crate) packages: Option<PackageStore>,
    policy: SampleOperationPolicy,
    key: std::sync::Arc<SigningKey>,
}

impl OperationStore {
    pub fn new(
        session: SessionStore,
        packages: Option<PackageStore>,
        policy: SampleOperationPolicy,
        key: SigningKey,
    ) -> Result<Self> {
        if !session.admits_function(policy.app_id, policy.build_id, policy.function_id)
            || (session.is_negotiated() && packages.is_none())
            || packages
                .as_ref()
                .is_some_and(|packages| !session.shares_authority(packages.session()))
            || public_key_id(key.verifying_key()) == session.grant_signer_id()
        {
            return Err(PackageError::Denied);
        }
        Ok(Self {
            session,
            packages,
            policy,
            key: std::sync::Arc::new(key),
        })
    }

    /// Trusted administration. Re-running configuration never re-enables a disabled operation.
    pub async fn configure(&self, actor: Id) -> Result<()> {
        let mut tx = self.session.begin_package().await?;
        let key = public_key_id(self.key.verifying_key());
        if let Some(packages) = &self.packages {
            packages.check_operation_signer(&mut tx, key).await?;
        }
        let p = self.policy;
        let changed = sqlx::query(
            "INSERT INTO protected_operations (app_id,build_id,function_id,operation_id,signing_key_id)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        ).bind(p.app_id.as_slice()).bind(p.build_id.as_slice()).bind(p.function_id.as_slice())
         .bind(SAMPLE_JOB_RECEIPT_OPERATION.as_slice()).bind(key.as_slice()).execute(&mut *tx).await?;
        if changed.rows_affected() == 1 {
            self.audit(&mut tx, actor, "configured").await?;
        } else {
            self.lock_policy(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Stop issuing this operation while retaining its idempotency and audit records.
    pub async fn disable(&self, actor: Id) -> Result<()> {
        let mut tx = self.session.begin_package().await?;
        let p = self.policy;
        let changed = sqlx::query(
            "UPDATE protected_operations SET enabled=false
             WHERE app_id=$1 AND build_id=$2 AND function_id=$3 AND operation_id=$4 AND enabled",
        )
        .bind(p.app_id.as_slice())
        .bind(p.build_id.as_slice())
        .bind(p.function_id.as_slice())
        .bind(SAMPLE_JOB_RECEIPT_OPERATION.as_slice())
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(PackageError::Denied);
        }
        self.audit(&mut tx, actor, "disabled").await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn invoke(
        &self,
        request: SampleOperationRequest,
        proof: [u8; 64],
    ) -> Result<Vec<u8>> {
        let p = self.policy;
        if (
            request.app_id,
            request.build_id,
            request.function_id,
            request.operation_id,
        ) != (
            p.app_id,
            p.build_id,
            p.function_id,
            SAMPLE_JOB_RECEIPT_OPERATION,
        ) {
            return Err(PackageError::Denied);
        }
        let mut auth = self
            .session
            .authorize_operation(
                &request,
                &proof,
                public_key_id(self.key.verifying_key()),
                self.packages.as_ref(),
            )
            .await?;
        let epoch = auth.policy_epoch();
        let result = async {
            if let Some(packages) = &self.packages {
                packages
                    .check_operation_signer(&mut auth.tx, public_key_id(self.key.verifying_key()))
                    .await?;
            }
            self.lock_policy(&mut auth.tx).await?;
            auth.ensure_live()?;
            let binding = auth.binding;
            self.receipt(&mut auth.tx, request, binding, epoch).await
        }
        .await;
        match result {
            Ok(receipt) => {
                auth.commit_live().await?;
                Ok(receipt)
            }
            Err(
                error @ (PackageError::Unavailable
                | PackageError::Session(SessionError::Unavailable)),
            ) => Err(error),
            Err(error) => {
                auth.tx.commit().await?;
                Err(error)
            }
        }
    }

    async fn lock_policy(&self, tx: &mut Tx<'_>) -> Result<()> {
        let p = self.policy;
        let row = sqlx::query(
            "SELECT enabled,signing_key_id FROM protected_operations
             WHERE app_id=$1 AND build_id=$2 AND function_id=$3 AND operation_id=$4 FOR SHARE",
        )
        .bind(p.app_id.as_slice())
        .bind(p.build_id.as_slice())
        .bind(p.function_id.as_slice())
        .bind(SAMPLE_JOB_RECEIPT_OPERATION.as_slice())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(PackageError::Denied)?;
        if !row.try_get::<bool, _>("enabled")?
            || row.try_get::<&[u8], _>("signing_key_id")? != public_key_id(self.key.verifying_key())
        {
            return Err(PackageError::Denied);
        }
        Ok(())
    }

    async fn receipt(
        &self,
        tx: &mut Tx<'_>,
        request: SampleOperationRequest,
        binding: GrantBinding,
        epoch: u64,
    ) -> Result<Vec<u8>> {
        let digest = request.digest()?;
        let existing = sqlx::query(
            "SELECT request_digest,receipt FROM operation_requests WHERE device_id=$1 AND request_id=$2",
        ).bind(binding.device_id.as_slice()).bind(request.request_id.as_slice()).fetch_optional(&mut **tx).await?;
        if let Some(row) = existing {
            if row.try_get::<&[u8], _>("request_digest")? != digest {
                return Err(PackageError::Conflict);
            }
            let receipt: Vec<u8> = row.try_get("receipt")?;
            SignedOperationReceipt::decode(&receipt)?.verify_for(
                self.key.verifying_key(),
                &request,
                binding,
                epoch,
            )?;
            return Ok(receipt);
        }
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM session_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM package_fetch_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM generation_offers WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM session_observation_reports WHERE device_id=$1 AND request_id=$2)",
        )
        .bind(binding.device_id.as_slice())
        .bind(request.request_id.as_slice())
        .fetch_one(&mut **tx)
        .await?;
        if duplicate {
            return Err(PackageError::Conflict);
        }
        let receipt = SignedOperationReceipt::sign(
            OperationReceipt {
                binding,
                function_id: request.function_id,
                operation_id: request.operation_id,
                request_id: request.request_id,
                request_digest: digest,
                sequence: request.sequence,
                policy_epoch: epoch,
                job: request.job,
                value: request.job.receipt_value(),
                signing_key_id: public_key_id(self.key.verifying_key()),
            },
            &self.key,
        )?;
        sqlx::query(
            "INSERT INTO operation_requests (device_id,request_id,session_id,operation_id,request_digest,receipt)
             VALUES ($1,$2,$3,$4,$5,$6)",
        ).bind(binding.device_id.as_slice()).bind(request.request_id.as_slice())
         .bind(binding.session_id.as_slice()).bind(request.operation_id.as_slice())
         .bind(digest.as_slice()).bind(receipt.as_bytes()).execute(&mut **tx).await?;
        Ok(receipt.as_bytes().to_vec())
    }

    async fn audit(&self, tx: &mut Tx<'_>, actor: Id, action: &'static str) -> Result<()> {
        let p = self.policy;
        sqlx::query(
            "INSERT INTO protected_operation_audit (app_id,build_id,function_id,operation_id,actor_id,action)
             VALUES ($1,$2,$3,$4,$5,$6)",
        ).bind(p.app_id.as_slice()).bind(p.build_id.as_slice()).bind(p.function_id.as_slice())
         .bind(SAMPLE_JOB_RECEIPT_OPERATION.as_slice()).bind(actor.as_slice()).bind(action)
         .execute(&mut **tx).await?;
        Ok(())
    }
}
