use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use sqlx::PgPool;
use vmkek_protocol::{
    access_command::{AccessAction, AccessCommand, AccessReason, AccessRole, SignedAccessCommand},
    public_key_id, Id, MAX_DEADLINE_MS,
};
use vmkek_server::access::{AccessAdmin, AdminPin};

pub(super) struct AccessFixture {
    admin: AccessAdmin,
    signer: SigningKey,
    app: Id,
    actor: Id,
    license: Id,
    policy: u64,
}

impl AccessFixture {
    pub(super) fn new(
        pool: PgPool,
        app: Id,
        actor: Id,
        license: Id,
        policy: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let signer = SigningKey::random(&mut OsRng);
        let admin = AccessAdmin::new(
            pool,
            policy,
            [AdminPin {
                app_id: app,
                actor_id: actor,
                role: AccessRole::Administrator,
                key: *signer.verifying_key(),
            }],
        )?;
        Ok(Self {
            admin,
            signer,
            app,
            actor,
            license,
            policy,
        })
    }

    pub(super) async fn apply(
        &self,
        pool: &PgPool,
        previous: Option<u64>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(pool)
        .await?;
        let now = u64::try_from(now)?;
        let (action, reason, request_id) = match previous {
            Some(prior_decision_id) => (
                AccessAction::Restore { prior_decision_id },
                AccessReason::ReviewedRestore,
                [2; 16],
            ),
            None => (AccessAction::Revoke, AccessReason::Administrator, [1; 16]),
        };
        let signed = SignedAccessCommand::sign(
            AccessCommand {
                app_id: self.app,
                actor_id: self.actor,
                license_id: self.license,
                device_id: None,
                request_id,
                policy_version: self.policy,
                issued_at_ms: now,
                expires_at_ms: now + u64::from(MAX_DEADLINE_MS),
                action,
                reason,
                key_id: public_key_id(self.signer.verifying_key()),
            },
            &self.signer,
        )?;
        Ok(self.admin.apply(self.actor, &signed).await?.id)
    }
}

pub(super) async fn own_stop_recorded(pool: &PgPool, license: Id) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM session_observation_reports r
         JOIN sessions s ON s.id=r.session_id AND s.device_id=r.device_id
         WHERE s.license_id=$1 AND s.stopped AND r.action=2)",
    )
    .bind(license.as_slice())
    .fetch_one(pool)
    .await
}
