use std::time::Duration;

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Row,
};
use vmkek_protocol::{
    access_command::{AccessAction, AccessCommand, AccessReason, AccessRole, SignedAccessCommand},
    public_key_id, DeviceTrust, Id, Permission, PermissionKind, SessionChallenge, SessionIntent,
    SessionOperation,
};
use vmkek_server::{
    access::{AccessAdmin, AccessDecision, AccessError, AdminPin},
    session::{SessionError, SessionPolicy, SessionStore},
    ActivationToken, IdentityError, IdentityStore, RevokeReason,
};

const APP: Id = [41; 16];
const BUILD: Id = [42; 16];
const GENERATION: Id = [43; 16];
const ADMIN: Id = [44; 16];
const OBSERVER: Id = [45; 16];
const OTHER_APP: Id = [46; 16];
const POLICY_VERSION: u64 = 7;

struct Fixture {
    pool: PgPool,
    identity: IdentityStore,
    sessions: SessionStore,
    admin: AccessAdmin,
    admin_key: SigningKey,
    observer_key: SigningKey,
}

impl Fixture {
    async fn start() -> Self {
        let socket = std::env::var("VMKEK_R17_PG_SOCKET").expect("isolated R17 PostgreSQL socket");
        let database = std::env::var("VMKEK_R17_PG_DATABASE").expect("dedicated R17 test database");
        assert!(database.starts_with("vmkek_r17_"));
        let options = PgConnectOptions::new()
            .socket(socket)
            .port(55439)
            .username("r09")
            .database(&database);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .unwrap();
        let identity = IdentityStore::new(pool.clone());
        let policy = SessionPolicy {
            app_id: APP,
            build_id: BUILD,
            generation_id: GENERATION,
            policy_epoch: 1,
            permission: Permission {
                kind: PermissionKind::Function,
                id: [47; 16],
            },
        };
        let sessions = SessionStore::start(pool.clone(), policy, key(10))
            .await
            .unwrap();
        let admin_key = key(11);
        let observer_key = key(12);
        let admin = AccessAdmin::new(
            pool.clone(),
            POLICY_VERSION,
            [
                pin(ADMIN, &admin_key, AccessRole::Administrator),
                pin(OBSERVER, &observer_key, AccessRole::Observer),
            ],
        )
        .unwrap();
        assert!(matches!(
            AccessAdmin::new(
                pool.clone(),
                POLICY_VERSION,
                [
                    pin(ADMIN, &admin_key, AccessRole::Administrator),
                    pin(OBSERVER, &admin_key, AccessRole::Observer),
                ]
            ),
            Err(AccessError::Configuration)
        ));
        Self {
            pool,
            identity,
            sessions,
            admin,
            admin_key,
            observer_key,
        }
    }

    async fn enroll(&self, token: &ActivationToken, signer: &SigningKey) -> Id {
        let challenge = self
            .identity
            .challenge(APP, token, public(signer), DeviceTrust::Software)
            .await
            .unwrap();
        let proof: Signature = signer
            .sign_prehash(&challenge.signature_digest().unwrap())
            .unwrap();
        self.identity
            .enroll(challenge.challenge_id, proof.to_bytes().into())
            .await
            .unwrap()
            .id
    }

    async fn access(&self, command: AccessCommand) -> Result<AccessDecision, AccessError> {
        let signed = SignedAccessCommand::sign(command, &self.admin_key).unwrap();
        self.admin.apply(ADMIN, &signed).await
    }

    async fn command(&self, license: Id, device: Option<Id>, request: u8) -> AccessCommand {
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();
        AccessCommand {
            app_id: APP,
            actor_id: ADMIN,
            license_id: license,
            device_id: device,
            request_id: [request; 16],
            policy_version: POLICY_VERSION,
            issued_at_ms: now as u64,
            expires_at_ms: now as u64 + 5_000,
            action: AccessAction::Revoke,
            reason: AccessReason::Administrator,
            key_id: public_key_id(self.admin_key.verifying_key()),
        }
    }

    async fn open_challenge(
        &self,
        device: Id,
        signer: &SigningKey,
        request: u8,
    ) -> SessionChallenge {
        let intent = session_intent(device, [0; 16], request, 1);
        self.sessions
            .issue(intent, intent.sign(signer).unwrap())
            .await
            .unwrap()
    }

    async fn open(&self, device: Id, signer: &SigningKey, request: u8) -> Id {
        let challenge = self.open_challenge(device, signer, request).await;
        self.sessions
            .complete(
                SessionOperation::Open,
                challenge,
                challenge.sign(signer).unwrap(),
            )
            .await
            .unwrap();
        challenge.session_id
    }

    async fn stopped(&self, session: Id) -> bool {
        sqlx::query_scalar("SELECT stopped FROM sessions WHERE id=$1")
            .bind(session.as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn license_state(&self, license: Id) -> String {
        sqlx::query_scalar("SELECT state FROM licenses WHERE id=$1")
            .bind(license.as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn public(signer: &SigningKey) -> [u8; 65] {
    signer
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn pin(actor: Id, signer: &SigningKey, role: AccessRole) -> AdminPin {
    AdminPin {
        app_id: APP,
        actor_id: actor,
        role,
        key: *signer.verifying_key(),
    }
}

fn session_intent(device: Id, session: Id, request: u8, sequence: u64) -> SessionIntent {
    SessionIntent {
        operation: if sequence == 1 {
            SessionOperation::Open
        } else {
            SessionOperation::Renew
        },
        app_id: APP,
        build_id: BUILD,
        device_id: device,
        generation_id: GENERATION,
        session_id: session,
        sequence,
        request_id: [request; 16],
    }
}

fn restore(command: AccessCommand, prior: u64) -> AccessCommand {
    AccessCommand {
        action: AccessAction::Restore {
            prior_decision_id: prior,
        },
        reason: AccessReason::ReviewedRestore,
        ..command
    }
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn signed_admin_scope_transitions_and_sessions() {
    let fixture = Fixture::start().await;
    let (license, token) = fixture
        .identity
        .provision_license(APP, Some(2))
        .await
        .unwrap();
    let first_signer = key(1);
    let other_signer = key(2);
    let first = fixture.enroll(&token, &first_signer).await;
    let other = fixture.enroll(&token, &other_signer).await;
    let session = fixture.open(first, &first_signer, 1).await;

    assert_rbac(&fixture, license).await;
    let command = fixture.command(license, Some(other), 11).await;
    let revoked_device = fixture.access(command).await.unwrap().id;
    assert!(!fixture.stopped(session).await);
    assert_eq!(
        fixture
            .access(AccessCommand {
                reason: AccessReason::Compromised,
                ..command
            })
            .await,
        Err(AccessError::Conflict)
    );

    let pending = session_intent(first, session, 2, 2);
    let pending = fixture
        .sessions
        .issue(pending, pending.sign(&first_signer).unwrap())
        .await
        .unwrap();
    let revoke_license = fixture.command(license, None, 12).await;
    let (one, two) = tokio::join!(
        fixture.access(revoke_license),
        fixture.access(revoke_license)
    );
    let (one, two) = (one.unwrap(), two.unwrap());
    assert_eq!(one.id, two.id);
    assert_ne!(one.replayed, two.replayed);
    assert!(fixture.stopped(session).await);
    assert_eq!(fixture.license_state(license).await, "revoked");
    assert_eq!(
        fixture
            .identity
            .challenge(APP, &token, public(&key(3)), DeviceTrust::Software)
            .await,
        Err(IdentityError::Denied)
    );
    assert_eq!(
        fixture
            .sessions
            .complete(
                SessionOperation::Renew,
                pending,
                pending.sign(&first_signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    let restore_command = fixture.command(license, None, 13).await;
    assert_eq!(
        fixture
            .access(restore(restore_command, revoked_device))
            .await,
        Err(AccessError::Conflict)
    );
    let restored = fixture
        .access(restore(restore_command, one.id))
        .await
        .unwrap();
    assert!(fixture.stopped(session).await);
    assert_eq!(fixture.license_state(license).await, "active");
    assert_eq!(
        fixture
            .sessions
            .complete(
                SessionOperation::Renew,
                pending,
                pending.sign(&first_signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let open = session_intent(other, [0; 16], 3, 1);
    assert_eq!(
        fixture
            .sessions
            .issue(open, open.sign(&other_signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    let fresh = fixture.open(first, &first_signer, 4).await;
    assert_ne!(fresh, session);
    assert!(!fixture.stopped(fresh).await);
    assert!(fixture.stopped(session).await);
    assert_audit(&fixture, license, one.id, restored.id).await;

    fixture
        .identity
        .revoke(license, Some(first), ADMIN, RevokeReason::Compromised)
        .await
        .unwrap();
    assert!(fixture.stopped(fresh).await);
    assert_cross_license_conflict(&fixture).await;
    assert_stale_open_and_lock_expiry(&fixture).await;
}

async fn assert_rbac(fixture: &Fixture, license: Id) {
    let command = fixture.command(license, None, 10).await;
    let untrusted = AccessCommand {
        actor_id: OBSERVER,
        key_id: public_key_id(fixture.observer_key.verifying_key()),
        ..command
    };
    let signed = SignedAccessCommand::sign(untrusted, &fixture.observer_key).unwrap();
    assert_eq!(
        fixture.admin.apply(OBSERVER, &signed).await,
        Err(AccessError::Denied)
    );
    assert_eq!(
        fixture.admin.apply(ADMIN, &signed).await,
        Err(AccessError::Denied)
    );
    assert_eq!(
        fixture.admin.apply([0; 16], &signed).await,
        Err(AccessError::Denied)
    );
    assert_eq!(
        fixture
            .access(AccessCommand {
                policy_version: POLICY_VERSION - 1,
                ..command
            })
            .await,
        Err(AccessError::Denied)
    );
    let (other, _) = fixture
        .identity
        .provision_license(OTHER_APP, None)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .access(AccessCommand {
                license_id: other,
                ..command
            })
            .await,
        Err(AccessError::Denied)
    );
    assert_eq!(fixture.license_state(other).await, "active");
}

async fn assert_audit(fixture: &Fixture, license: Id, revoked: u64, restored: u64) {
    let rows = sqlx::query(
        "SELECT d.id,d.action,d.restore_of,d.policy_version,d.reason,a.event
         FROM access_decisions d JOIN audit a ON a.decision_id=d.id
         WHERE d.license_id=$1 AND d.actor_id=$2 ORDER BY d.id",
    )
    .bind(license.as_slice())
    .bind(ADMIN.as_slice())
    .fetch_all(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].get::<i64, _>("id"), revoked as i64);
    assert_eq!(rows[1].get::<&str, _>("event"), "revoked");
    assert_eq!(rows[2].get::<i64, _>("id"), restored as i64);
    assert_eq!(rows[2].get::<i64, _>("restore_of"), revoked as i64);
    assert_eq!(
        rows[2].get::<i64, _>("policy_version"),
        POLICY_VERSION as i64
    );
    assert_eq!(
        rows[2].get::<i16, _>("reason"),
        AccessReason::ReviewedRestore as i16
    );
    assert_eq!(rows[2].get::<&str, _>("action"), "restore");
    assert_eq!(rows[2].get::<&str, _>("event"), "restored");
}

async fn assert_cross_license_conflict(fixture: &Fixture) {
    let (left, _) = fixture.identity.provision_license(APP, None).await.unwrap();
    let (right, _) = fixture.identity.provision_license(APP, None).await.unwrap();
    let command = fixture.command(left, None, 20).await;
    let (a, b) = tokio::join!(
        fixture.access(command),
        fixture.access(AccessCommand {
            license_id: right,
            ..command
        }),
    );
    let (winner, loser) = match (a, b) {
        (Ok(_), Err(AccessError::Conflict)) => (left, right),
        (Err(AccessError::Conflict), Ok(_)) => (right, left),
        pair => panic!("unexpected administrative replay result {pair:?}"),
    };
    assert_eq!(fixture.license_state(winner).await, "revoked");
    assert_eq!(fixture.license_state(loser).await, "active");
}

async fn assert_stale_open_and_lock_expiry(fixture: &Fixture) {
    let (license, token) = fixture.identity.provision_license(APP, None).await.unwrap();
    let signer = key(4);
    let device = fixture.enroll(&token, &signer).await;
    let pending = fixture.open_challenge(device, &signer, 21).await;
    let mut lock = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(license.as_slice())
        .execute(&mut *lock)
        .await
        .unwrap();
    let short = fixture.command(license, None, 22).await;
    let short = AccessCommand {
        expires_at_ms: short.issued_at_ms + 100,
        ..short
    };
    let waiting = fixture.access(short);
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut waiting)
            .await
            .is_err()
    );
    lock.commit().await.unwrap();
    assert_eq!(waiting.await, Err(AccessError::Expired));
    assert_eq!(fixture.license_state(license).await, "active");

    let revoke = fixture.command(license, None, 23).await;
    let revoked = fixture.access(revoke).await.unwrap();
    let command = fixture.command(license, None, 24).await;
    fixture.access(restore(command, revoked.id)).await.unwrap();
    assert_eq!(
        fixture
            .sessions
            .complete(
                SessionOperation::Open,
                pending,
                pending.sign(&signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    assert_ne!(fixture.open(device, &signer, 25).await, pending.session_id);
}
