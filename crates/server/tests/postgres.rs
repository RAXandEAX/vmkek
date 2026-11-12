use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use tower::ServiceExt;
use vmkek_protocol::{DeviceTrust, EnrollmentChallenge, ProtocolError};
use vmkek_server::{router, ActivationToken, IdentityError, IdentityStore, RevokeReason};

const APP: [u8; 16] = [7; 16];
const ACTOR: [u8; 16] = [8; 16];

async fn database() -> (PgPool, IdentityStore) {
    let socket = std::env::var("VMKEK_R09_PG_SOCKET").expect("isolated R09 PostgreSQL socket");
    let database = std::env::var("VMKEK_R09_PG_DATABASE").expect("dedicated R09 test database");
    assert!(database.starts_with("vmkek_r09_"));
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
    let store = IdentityStore::new(pool.clone());
    store.migrate().await.unwrap();
    (pool, store)
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}

fn public(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn proof(key: &SigningKey, challenge: &EnrollmentChallenge) -> [u8; 64] {
    let signature: Signature = key
        .sign_prehash(&challenge.signature_digest().unwrap())
        .unwrap();
    signature.to_bytes().into()
}

async fn issue(
    store: &IdentityStore,
    token: &ActivationToken,
    key: &SigningKey,
) -> EnrollmentChallenge {
    store
        .challenge(APP, token, public(key), DeviceTrust::Software)
        .await
        .unwrap()
}

#[test]
fn canonical_enrollment_is_fixed_and_bound() {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SigningKey::from_slice(&scalar).unwrap();
    let challenge = EnrollmentChallenge {
        app_id: APP,
        license_id: [2; 16],
        challenge_id: [3; 16],
        nonce: [4; 32],
        key_id: vmkek_protocol::public_key_id(key.verifying_key()),
        trust: DeviceTrust::Software,
        expires_unix_ms: 987_654,
    };
    let encoded = challenge.encode().unwrap();
    assert_eq!(encoded.len(), 157);
    assert_eq!(
        hex::encode(&encoded),
        concat!(
            "0100050095000000100000000707070707070707070707070707070710000000",
            "0202020202020202020202020202020210000000030303030303030303030303",
            "0303030320000000040404040404040404040404040404040404040404040404",
            "040404040404040420000000698bea63dc44a344663ff1429aea10842df27b6b",
            "991ef25866b2c6c02cdcc5be01000000010800000006120f0000000000",
        )
    );
    assert_eq!(
        hex::encode(challenge.signature_digest().unwrap()),
        "a80315e7035508254a07f377fe1b843d522fbca4871485caac6c9f2236fa2b48"
    );
    assert_eq!(&encoded[..8], &[1, 0, 5, 0, 149, 0, 0, 0]);
    assert_eq!(EnrollmentChallenge::decode(&encoded).unwrap(), challenge);
    let signature = proof(&key, &challenge);
    assert_eq!(challenge.verify_proof(&public(&key), &signature), Ok(()));
    let mut changed = challenge;
    changed.nonce[0] ^= 1;
    assert_eq!(
        changed.verify_proof(&public(&key), &signature),
        Err(ProtocolError::Signature)
    );
    let mut wrong_version = encoded.clone();
    wrong_version[0] = 2;
    assert_eq!(
        EnrollmentChallenge::decode(&wrong_version),
        Err(ProtocolError::Version)
    );
    assert!(EnrollmentChallenge::decode(&encoded[..156]).is_err());
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn invalid_proof_replay_and_expiry() {
    let (pool, store) = database().await;
    let (license, token) = store.provision_license(APP, None).await.unwrap();
    let signer = key(1);
    let challenge = issue(&store, &token, &signer).await;
    assert_eq!(
        store
            .enroll(challenge.challenge_id, proof(&key(2), &challenge))
            .await,
        Err(IdentityError::Denied)
    );
    assert_eq!(
        store
            .enroll(challenge.challenge_id, proof(&signer, &challenge))
            .await,
        Err(IdentityError::Replay)
    );
    let expired = issue(&store, &token, &signer).await;
    sqlx::query("UPDATE enrollments SET expires_unix_ms=1 WHERE id=$1")
        .bind(expired.challenge_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .enroll(expired.challenge_id, proof(&signer, &expired))
            .await,
        Err(IdentityError::Expired)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE license_id=$1")
        .bind(license.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let events: Vec<String> =
        sqlx::query_scalar("SELECT event FROM audit WHERE license_id=$1 ORDER BY id")
            .bind(license.as_slice())
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        events,
        [
            "challenge",
            "proof_denied",
            "replay",
            "challenge",
            "expired"
        ]
    );
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn parallel_replay_limit_and_reinstall() {
    let (_, store) = database().await;
    let (_, token) = store.provision_license(APP, None).await.unwrap();
    let signer = key(1);
    let challenge = issue(&store, &token, &signer).await;
    let signature = proof(&signer, &challenge);
    let (one, two) = tokio::join!(
        store.enroll(challenge.challenge_id, signature),
        store.enroll(challenge.challenge_id, signature)
    );
    let device = match (one, two) {
        (Ok(device), Err(IdentityError::Replay)) | (Err(IdentityError::Replay), Ok(device)) => {
            device
        }
        pair => panic!("unexpected replay results {pair:?}"),
    };
    let reinstall = issue(&store, &token, &signer).await;
    assert_eq!(
        store
            .enroll(reinstall.challenge_id, proof(&signer, &reinstall))
            .await,
        Ok(device)
    );
    let different = key(2);
    let reinstall = issue(&store, &token, &different).await;
    assert_eq!(
        store
            .enroll(reinstall.challenge_id, proof(&different, &reinstall))
            .await,
        Err(IdentityError::DeviceLimit)
    );

    let (_, token) = store.provision_license(APP, None).await.unwrap();
    let first = issue(&store, &token, &signer).await;
    let second = issue(&store, &token, &different).await;
    let (one, two) = tokio::join!(
        store.enroll(first.challenge_id, proof(&signer, &first)),
        store.enroll(second.challenge_id, proof(&different, &second)),
    );
    assert!(matches!(
        (one, two),
        (Ok(_), Err(IdentityError::DeviceLimit)) | (Err(IdentityError::DeviceLimit), Ok(_))
    ));
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn revocation_survives_migration_and_rejects_inflight_enrollment() {
    let (pool, store) = database().await;
    let (license, token) = store.provision_license(APP, None).await.unwrap();
    let signer = key(1);
    let first = issue(&store, &token, &signer).await;
    let device = store
        .enroll(first.challenge_id, proof(&signer, &first))
        .await
        .unwrap();
    let inflight = issue(&store, &token, &signer).await;
    store
        .revoke(license, Some(device.id), ACTOR, RevokeReason::Compromised)
        .await
        .unwrap();
    assert_eq!(
        store
            .enroll(inflight.challenge_id, proof(&signer, &inflight))
            .await,
        Err(IdentityError::Denied)
    );
    let inflight = issue(&store, &token, &key(2)).await;
    store
        .revoke(license, None, ACTOR, RevokeReason::Administrator)
        .await
        .unwrap();
    let restarted = IdentityStore::new(pool.clone());
    restarted.migrate().await.unwrap();
    assert_eq!(
        restarted
            .enroll(inflight.challenge_id, proof(&key(2), &inflight))
            .await,
        Err(IdentityError::Denied)
    );
    assert_eq!(
        restarted
            .challenge(APP, &token, public(&signer), DeviceTrust::Software)
            .await,
        Err(IdentityError::Denied)
    );
    let joined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_decisions d JOIN audit a ON a.decision_id=d.id WHERE d.license_id=$1 AND d.actor_id=$2",
    ).bind(license.as_slice()).bind(ACTOR.as_slice()).fetch_one(&pool).await.unwrap();
    assert_eq!(joined, 2);
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn issuance_rate_and_trust_are_enforced() {
    let (pool, store) = database().await;
    let (license, token) = store.provision_license(APP, None).await.unwrap();
    let signer = key(1);
    assert_eq!(
        store
            .challenge(APP, &token, public(&signer), DeviceTrust::TpmAttested)
            .await,
        Err(IdentityError::TrustUnavailable)
    );
    for _ in 0..5 {
        issue(&store, &token, &signer).await;
    }
    assert_eq!(
        store
            .challenge(APP, &token, public(&signer), DeviceTrust::Software)
            .await,
        Err(IdentityError::RateLimit)
    );
    sqlx::query("UPDATE enrollments SET issued_at=clock_timestamp()-interval '61 minutes' WHERE license_id=$1")
        .bind(license.as_slice()).execute(&pool).await.unwrap();
    issue(&store, &token, &signer).await;
}

async fn post(app: axum::Router, path: &str, body: Value) -> (StatusCode, String) {
    let response = app
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn http_end_to_end_and_sanitized_errors() {
    let (pool, store) = database().await;
    let (license, token) = store.provision_license(APP, None).await.unwrap();
    let app = router(store);
    let signer = key(1);
    let secret = hex::encode(token.expose());
    let request = json!({
        "app_id": hex::encode(APP), "activation_token": secret,
        "public_key": hex::encode(public(&signer)), "trust": "software"
    });
    let (status, response) = post(app.clone(), "/v1/identity/challenge", request.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!response.contains(&secret));
    let value: Value = serde_json::from_str(&response).unwrap();
    let bytes = hex::decode(value["challenge"].as_str().unwrap()).unwrap();
    let challenge = EnrollmentChallenge::decode(&bytes).unwrap();
    assert_eq!(challenge.license_id, license);
    let request = json!({"challenge_id": hex::encode(challenge.challenge_id), "proof": hex::encode(proof(&signer, &challenge))});
    let (status, response) = post(app.clone(), "/v1/identity/enroll", request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(response.contains("software"));
    let (status, response) = post(
        app,
        "/v1/identity/challenge",
        json!({"activation_token": secret}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response, "invalid_identity_request");
    let stored: Vec<u8> = sqlx::query_scalar("SELECT activation_digest FROM licenses WHERE id=$1")
        .bind(license.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, token.expose());
}
