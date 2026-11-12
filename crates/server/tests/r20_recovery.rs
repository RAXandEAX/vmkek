use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use vmkek_protocol::{
    access_command::{AccessAction, AccessCommand, AccessReason, AccessRole, SignedAccessCommand},
    public_key_id, DeviceTrust, Id, Permission, PermissionKind, RecoveryScope, SessionIntent,
    SessionOperation, SignedRecoveryCheckpoint,
};
use vmkek_server::{
    access::{AccessAdmin, AdminPin},
    recovery::{
        capture_checkpoint, LatestCheckpoint, RecoveryBootError, RecoveryError, RecoveryProof,
    },
    session::{RecoverySessionPolicy, SessionError, SessionPolicy, SessionStore},
    IdentityStore,
};

const APP: Id = [30; 16];
const BUILD: Id = [31; 16];
const GENERATION: Id = [32; 16];
const ADMIN: Id = [33; 16];
const SCOPE: RecoveryScope = RecoveryScope {
    deployment_id: [34; 16],
    app_id: APP,
    build_id: BUILD,
    history_id: [35; 16],
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn policy(epoch: u64) -> SessionPolicy {
    SessionPolicy {
        app_id: APP,
        build_id: BUILD,
        generation_id: GENERATION,
        policy_epoch: epoch,
        permission: Permission {
            kind: PermissionKind::Function,
            id: [36; 16],
        },
    }
}

struct Lab {
    socket: PathBuf,
    bin: PathBuf,
    directory: PathBuf,
    prefix: String,
}

impl Lab {
    fn new() -> Self {
        let lab = Self {
            socket: std::env::var_os("VMKEK_R20_PG_SOCKET").unwrap().into(),
            bin: std::env::var_os("VMKEK_R20_PG_BIN").unwrap().into(),
            directory: std::env::var_os("VMKEK_R20_DUMP_DIR").unwrap().into(),
            prefix: std::env::var("VMKEK_R20_DB_PREFIX").unwrap(),
        };
        assert!(
            lab.prefix.starts_with("vmkek_r20_")
                && lab.prefix.len() < 44
                && lab
                    .prefix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
        assert!(lab.socket.is_absolute() && lab.bin.is_absolute() && lab.directory.is_absolute());
        assert!(lab.directory.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(lab.directory.metadata().unwrap().mode() & 0o077, 0);
        }
        lab
    }

    fn database(&self, suffix: &str) -> String {
        format!("{}_{}", self.prefix, suffix)
    }

    fn command(&self, binary: &str) -> Command {
        let mut cmd = Command::new(self.bin.join(binary));
        cmd.arg("-h")
            .arg(&self.socket)
            .args(["-p", "55439", "-U", "r09"])
            .env_remove("PGPASSWORD");
        cmd
    }

    fn create(&self, name: &str) {
        assert!(self
            .command("createdb")
            .arg(name)
            .status()
            .unwrap()
            .success());
    }

    fn dump(&self, database: &str, name: &str) -> PathBuf {
        let path = self.directory.join(name);
        assert!(!path.exists());
        assert!(self
            .command("pg_dump")
            .args(["--format=custom", "--file"])
            .arg(&path)
            .arg(database)
            .status()
            .unwrap()
            .success());
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        path
    }

    fn restore(&self, database: &str, archive: &Path) {
        self.create(database);
        assert!(self
            .command("pg_restore")
            .args([
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                "--dbname"
            ])
            .arg(database)
            .arg(archive)
            .status()
            .unwrap()
            .success());
    }

    async fn pool(&self, database: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(8)
            .connect_with(
                PgConnectOptions::new()
                    .socket(&self.socket)
                    .port(55439)
                    .username("r09")
                    .database(database),
            )
            .await
            .unwrap()
    }
}

async fn enroll(identity: &IdentityStore, key: &SigningKey) -> (Id, Id) {
    let (license, token) = identity.provision_license(APP, None).await.unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let challenge = identity
        .challenge(
            APP,
            &token,
            public.as_bytes().try_into().unwrap(),
            DeviceTrust::Software,
        )
        .await
        .unwrap();
    let signature: Signature = key
        .sign_prehash(&challenge.signature_digest().unwrap())
        .unwrap();
    let device = identity
        .enroll(challenge.challenge_id, signature.to_bytes().into())
        .await
        .unwrap()
        .id;
    (license, device)
}

fn intent(device: Id, request: u8) -> SessionIntent {
    SessionIntent {
        operation: SessionOperation::Open,
        app_id: APP,
        build_id: BUILD,
        device_id: device,
        generation_id: GENERATION,
        session_id: [0; 16],
        sequence: 1,
        request_id: [request; 16],
    }
}

async fn epoch(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT epoch FROM session_service WHERE singleton")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn proof<'a>(
    signed: &'a SignedRecoveryCheckpoint,
    pin: &'a p256::ecdsa::VerifyingKey,
    latest: LatestCheckpoint,
) -> RecoveryProof<'a> {
    RecoveryProof {
        checkpoint: signed,
        independent_pin: pin,
        latest,
    }
}

#[tokio::test]
#[ignore = "requires the private disposable PostgreSQL 16 archive fixture"]
async fn recovery_uses_real_archives_and_preserves_revocation_and_replay() {
    let lab = Lab::new();
    let source_db = lab.database("source");
    let stale_db = lab.database("stale");
    let current_db = lab.database("current");
    let tampered_db = lab.database("tampered");
    lab.create(&source_db);
    let source = lab.pool(&source_db).await;
    let grant_key = key(1);
    let checkpoint_key = key(2);
    let admin_key = key(3);
    let revoked_key = key(4);
    let healthy_key = key(5);
    let source_service = SessionStore::start(source.clone(), policy(2), grant_key.clone())
        .await
        .unwrap();
    let identity = IdentityStore::new(source.clone());
    let (revoked_license, revoked_device) = enroll(&identity, &revoked_key).await;
    let (_, healthy_device) = enroll(&identity, &healthy_key).await;
    let used = intent(healthy_device, 40);
    let open = source_service
        .issue(used, used.sign(&healthy_key).unwrap())
        .await
        .unwrap();
    source_service
        .complete(
            SessionOperation::Open,
            open,
            open.sign(&healthy_key).unwrap(),
        )
        .await
        .unwrap();

    let pin = checkpoint_key.verifying_key();
    let before = capture_checkpoint(&source, SCOPE, [41; 16], 1, pin)
        .await
        .unwrap();
    let before = SignedRecoveryCheckpoint::sign(before, &checkpoint_key).unwrap();
    let stale_archive = lab.dump(&source_db, "before-revoke.dump");

    let administrator = AccessAdmin::new(
        source.clone(),
        1,
        [AdminPin {
            app_id: APP,
            actor_id: ADMIN,
            role: AccessRole::Administrator,
            key: *admin_key.verifying_key(),
        }],
    )
    .unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let revoke = SignedAccessCommand::sign(
        AccessCommand {
            app_id: APP,
            actor_id: ADMIN,
            license_id: revoked_license,
            device_id: None,
            request_id: [42; 16],
            policy_version: 1,
            issued_at_ms: now,
            expires_at_ms: now + 5000,
            action: AccessAction::Revoke,
            reason: AccessReason::Administrator,
            key_id: public_key_id(admin_key.verifying_key()),
        },
        &admin_key,
    )
    .unwrap();
    let decision = administrator.apply(ADMIN, &revoke).await.unwrap();
    assert!(!decision.replayed);
    let checkpoint = capture_checkpoint(&source, SCOPE, [43; 16], 2, pin)
        .await
        .unwrap();
    let current = SignedRecoveryCheckpoint::sign(checkpoint, &checkpoint_key).unwrap();
    let latest = LatestCheckpoint {
        scope: SCOPE,
        fence_id: [43; 16],
        sequence: 2,
        signed_sha256: current.digest(),
    };
    let archive = lab.dump(&source_db, "after-revoke.dump");
    drop(administrator);
    drop(source_service);

    lab.restore(&stale_db, &stale_archive);
    lab.restore(&current_db, &archive);
    lab.restore(&tampered_db, &archive);
    let stale = lab.pool(&stale_db).await;
    let restored = lab.pool(&current_db).await;
    let tampered = lab.pool(&tampered_db).await;
    assert!(matches!(
        SessionStore::start_checked_recovery(
            stale.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&before, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Authority))
    ));
    assert!(matches!(
        SessionStore::start_checked_recovery(
            stale.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
    assert_eq!(epoch(&stale).await, 1);
    assert!(matches!(
        SessionStore::start(restored.clone(), policy(2), grant_key.clone()).await,
        Err(SessionError::Denied)
    ));
    let wrong_history = LatestCheckpoint {
        scope: RecoveryScope {
            history_id: [99; 16],
            ..SCOPE
        },
        ..latest
    };
    assert!(matches!(
        SessionStore::start_checked_recovery(
            restored.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, wrong_history)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Authority))
    ));
    let expired = SignedRecoveryCheckpoint::sign(
        vmkek_protocol::RecoveryCheckpoint {
            issued_at_ms: checkpoint.issued_at_ms - 900_001,
            ..checkpoint
        },
        &checkpoint_key,
    )
    .unwrap();
    let expired_pin = LatestCheckpoint {
        signed_sha256: expired.digest(),
        ..latest
    };
    assert!(matches!(
        SessionStore::start_checked_recovery(
            restored.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&expired, pin, expired_pin)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Stale))
    ));

    sqlx::query("UPDATE licenses SET state='active' WHERE id=$1")
        .bind(revoked_license.as_slice())
        .execute(&tampered)
        .await
        .unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            tampered.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
    sqlx::query("UPDATE licenses SET state='revoked' WHERE id=$1")
        .bind(revoked_license.as_slice())
        .execute(&tampered)
        .await
        .unwrap();
    sqlx::query("DELETE FROM session_requests WHERE device_id=$1 AND request_id=$2")
        .bind(healthy_device.as_slice())
        .bind(used.request_id.as_slice())
        .execute(&tampered)
        .await
        .unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            tampered.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
    sqlx::query("UPDATE public._sqlx_migrations SET checksum=pg_catalog.sha256('wrong checksum'::bytea) WHERE version=8")
        .execute(&tampered).await.unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            tampered.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
    assert_eq!(epoch(&tampered).await, 1);

    sqlx::query("DROP TABLE public.recovery_identity")
        .execute(&tampered)
        .await
        .unwrap();
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=8")
        .execute(&tampered)
        .await
        .unwrap();
    assert!(SessionStore::start_checked_recovery(
        tampered.clone(),
        RecoverySessionPolicy::Fixed(policy(2)),
        grant_key.clone(),
        proof(&current, pin, latest)
    )
    .await
    .is_err());
    let wrote_unverified_archive = sqlx::query_scalar::<_, bool>(
        "SELECT pg_catalog.to_regclass('public.recovery_identity') IS NOT NULL
             OR EXISTS(SELECT 1 FROM public._sqlx_migrations WHERE version=8)",
    )
    .fetch_one(&tampered)
    .await
    .unwrap();
    assert_eq!(epoch(&tampered).await, 1);

    sqlx::query("CREATE SCHEMA recovery_lab_shadow")
        .execute(&restored)
        .await
        .unwrap();
    let shadow = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .socket(&lab.socket)
                .port(55439)
                .username("r09")
                .database(&current_db)
                .options([("search_path", "recovery_lab_shadow")]),
        )
        .await
        .unwrap();
    IdentityStore::new(shadow.clone()).migrate().await.unwrap();
    let bypassed_marker = !matches!(
        SessionStore::start(shadow.clone(), policy(2), grant_key.clone()).await,
        Err(SessionError::Denied)
    );
    assert_eq!((wrote_unverified_archive, bypassed_marker), (false, false));
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM recovery_lab_shadow.session_service)"
    )
    .fetch_one(&shadow)
    .await
    .unwrap());
    shadow.close().await;

    let untrusted_path = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .socket(&lab.socket)
                .port(55439)
                .username("r09")
                .database(&current_db)
                .options([("search_path", "public,pg_catalog")]),
        )
        .await
        .unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            untrusted_path,
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Authority))
    ));
    let (last, called): (i64, bool) =
        sqlx::query_as("SELECT last_value,is_called FROM public.audit_id_seq")
            .fetch_one(&restored)
            .await
            .unwrap();
    sqlx::query("SELECT pg_catalog.setval('public.audit_id_seq',$1,true)")
        .bind(last + 1)
        .execute(&restored)
        .await
        .unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            restored.clone(),
            RecoverySessionPolicy::Fixed(policy(2)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
    sqlx::query("SELECT pg_catalog.setval('public.audit_id_seq',$1,$2)")
        .bind(last)
        .bind(called)
        .execute(&restored)
        .await
        .unwrap();

    assert!(matches!(
        SessionStore::start_checked_recovery(
            restored.clone(),
            RecoverySessionPolicy::Fixed(policy(1)),
            grant_key.clone(),
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Authority))
    ));
    assert_eq!(epoch(&restored).await, 1);

    let mut held = restored.begin().await.unwrap();
    sqlx::query("LOCK TABLE licenses IN ROW EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();
    let boot = {
        let restored = restored.clone();
        let pin = *pin;
        let current = current.clone();
        let grant_key = grant_key.clone();
        tokio::spawn(async move {
            SessionStore::start_checked_recovery(
                restored,
                RecoverySessionPolicy::Fixed(policy(3)),
                grant_key,
                proof(&current, &pin, latest),
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2),async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
                   AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE public._sqlx_migrations%')",
            ).fetch_one(&restored).await.unwrap();
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert!(!boot.is_finished());
    assert_eq!(epoch(&restored).await, 1);
    held.commit().await.unwrap();
    let current_service = boot.await.unwrap().unwrap();
    assert_eq!(epoch(&restored).await, 2);
    let rollout_epoch: i64 =
        sqlx::query_scalar("SELECT policy_epoch FROM public.session_service WHERE singleton")
            .fetch_one(&restored)
            .await
            .unwrap();
    assert_eq!(rollout_epoch, 3);
    let forbidden = intent(revoked_device, 44);
    assert_eq!(
        current_service
            .issue(forbidden, forbidden.sign(&revoked_key).unwrap())
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    assert_eq!(
        current_service
            .issue(used, used.sign(&healthy_key).unwrap())
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let fresh = intent(healthy_device, 45);
    let challenge = current_service
        .issue(fresh, fresh.sign(&healthy_key).unwrap())
        .await
        .unwrap();
    assert_ne!(challenge.session_id, open.session_id);
    current_service
        .complete(
            SessionOperation::Open,
            challenge,
            challenge.sign(&healthy_key).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        SessionStore::start_checked_recovery(
            restored.clone(),
            RecoverySessionPolicy::Fixed(policy(3)),
            grant_key,
            proof(&current, pin, latest)
        )
        .await,
        Err(RecoveryBootError::Checkpoint(RecoveryError::Snapshot))
    ));
}
