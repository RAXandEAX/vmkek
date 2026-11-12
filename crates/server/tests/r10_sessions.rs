use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use vmkek_protocol::{
    DeviceTrust, GrantBinding, Id, Permission, PermissionKind, SessionGrant,
    SessionGrantExpectation, SessionIntent, SessionOperation,
};
use vmkek_server::{
    session::{SessionError, SessionPolicy, SessionStore},
    IdentityStore, RevokeReason,
};

const APP: Id = [31; 16];
const BUILD: Id = [32; 16];
const GENERATION: Id = [33; 16];
const ACTOR: Id = [34; 16];
const PERMISSION: Permission = Permission {
    kind: PermissionKind::Function,
    id: [35; 16],
};
const POLICY: SessionPolicy = SessionPolicy {
    app_id: APP,
    build_id: BUILD,
    generation_id: GENERATION,
    policy_epoch: 1,
    permission: PERMISSION,
};

fn key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}

fn intent(device_id: Id, request: u8, session_id: Id, sequence: u64) -> SessionIntent {
    SessionIntent {
        operation: if sequence == 1 {
            SessionOperation::Open
        } else {
            SessionOperation::Renew
        },
        app_id: APP,
        build_id: BUILD,
        device_id,
        generation_id: GENERATION,
        session_id,
        sequence,
        request_id: [request; 16],
    }
}

async fn database(schema: &str) -> PgPool {
    let socket = std::env::var("VMKEK_R10_PG_SOCKET").expect("isolated R10 PostgreSQL socket");
    let database = std::env::var("VMKEK_R10_PG_DATABASE").expect("dedicated R10 test database");
    assert!(database.starts_with("vmkek_r10_"));
    let options = PgConnectOptions::new()
        .socket(socket)
        .port(55439)
        .username("r09")
        .database(&database);
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let create = match schema {
        "r10_ledger" => "CREATE SCHEMA IF NOT EXISTS r10_ledger",
        "r10_tls" => "CREATE SCHEMA IF NOT EXISTS r10_tls",
        "r20_admission" => "CREATE SCHEMA r20_admission",
        "r20_renew_loss" => "CREATE SCHEMA r20_renew_loss",
        _ => panic!("unknown test schema"),
    };
    sqlx::query(create).execute(&control).await.unwrap();
    control.close().await;
    PgPoolOptions::new()
        .max_connections(if schema == "r20_admission" { 38 } else { 12 })
        .connect_with(
            options
                .application_name(schema)
                .options([("search_path", schema)]),
        )
        .await
        .unwrap()
}

async fn provision(identity: &IdentityStore, key: &SigningKey) -> (Id, Id) {
    let (license_id, activation) = identity.provision_license(APP, None).await.unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let challenge = identity
        .challenge(
            APP,
            &activation,
            public.as_bytes().try_into().unwrap(),
            DeviceTrust::Software,
        )
        .await
        .unwrap();
    let proof: Signature = key
        .sign_prehash(&challenge.signature_digest().unwrap())
        .unwrap();
    let device = identity
        .enroll(challenge.challenge_id, proof.to_bytes().into())
        .await
        .unwrap();
    (license_id, device.id)
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn replay_concurrency_restart_and_atomic_revoke() {
    let pool = database("r10_ledger").await;
    let manufacturer = key(3);
    let store = SessionStore::start(pool.clone(), POLICY, manufacturer.clone())
        .await
        .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let signer = key(1);
    let (license, device) = provision(&identity, &signer).await;
    let open = intent(device, 1, [0; 16], 1);

    assert_eq!(
        store
            .issue(open, open.sign(&key(2)).unwrap())
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    let challenge = store
        .issue(open, open.sign(&signer).unwrap())
        .await
        .unwrap();
    assert_eq!(
        store
            .issue(open, open.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let proof = challenge.sign(&signer).unwrap();
    let (one, two) = tokio::join!(
        store.complete(SessionOperation::Open, challenge, proof),
        store.complete(SessionOperation::Open, challenge, proof),
    );
    let grant = match (one, two) {
        (Ok(grant), Err(SessionError::Replay)) | (Err(SessionError::Replay), Ok(grant)) => grant,
        pair => panic!("unexpected parallel completion {pair:?}"),
    };
    let binding = GrantBinding {
        session_id: challenge.session_id,
        device_id: device,
        license_id: license,
        app_id: APP,
        build_id: BUILD,
        generation_id: GENERATION,
    };
    let mut expectation = SessionGrantExpectation {
        binding,
        policy_epoch: 1,
        sequence: 1,
        permission: PERMISSION,
        challenge_digest: challenge.digest().unwrap(),
    };
    assert_eq!(
        SessionGrant::decode(grant.as_bytes())
            .unwrap()
            .verify_session(manufacturer.verifying_key(), &expectation)
            .unwrap()
            .lifetime_ms,
        30_000
    );
    expectation.challenge_digest[0] ^= 1;
    assert!(grant
        .verify_session(manufacturer.verifying_key(), &expectation)
        .is_err());

    let future = intent(device, 2, challenge.session_id, 3);
    assert_eq!(
        store
            .issue(future, future.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let renew = intent(device, 3, challenge.session_id, 2);
    let first = store
        .issue(renew, renew.sign(&signer).unwrap())
        .await
        .unwrap();
    let conflict = SessionIntent {
        request_id: open.request_id,
        ..renew
    };
    assert_eq!(
        store
            .issue(conflict, conflict.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let reordered = SessionIntent {
        request_id: [4; 16],
        ..renew
    };
    let second = store
        .issue(reordered, reordered.sign(&signer).unwrap())
        .await
        .unwrap();
    assert_eq!(
        store
            .complete(SessionOperation::Open, first, first.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    store
        .complete(
            SessionOperation::Renew,
            second,
            second.sign(&signer).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .complete(SessionOperation::Renew, first, first.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Replay
    );

    let other = key(2);
    let (_, other_device) = provision(&identity, &other).await;
    let foreign = intent(other_device, 5, challenge.session_id, 3);
    assert!(matches!(
        store.issue(foreign, foreign.sign(&other).unwrap()).await,
        Err(SessionError::Expired | SessionError::Denied)
    ));

    let renew = intent(device, 6, challenge.session_id, 3);
    let pending = store
        .issue(renew, renew.sign(&signer).unwrap())
        .await
        .unwrap();
    let restarted = SessionStore::start(pool.clone(), POLICY, manufacturer.clone())
        .await
        .unwrap();
    assert_eq!(
        store
            .complete(
                SessionOperation::Renew,
                pending,
                pending.sign(&signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Unavailable
    );
    assert_eq!(
        restarted
            .complete(
                SessionOperation::Renew,
                pending,
                pending.sign(&signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Expired
    );
    assert_eq!(
        restarted
            .issue(renew, renew.sign(&signer).unwrap())
            .await
            .unwrap_err(),
        SessionError::Expired
    );

    let open = intent(device, 7, [0; 16], 1);
    let invalid = restarted
        .issue(open, open.sign(&signer).unwrap())
        .await
        .unwrap();
    assert_eq!(
        restarted
            .complete(
                SessionOperation::Open,
                invalid,
                invalid.sign(&other).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Denied
    );
    assert_eq!(
        restarted
            .complete(
                SessionOperation::Open,
                invalid,
                invalid.sign(&signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Replay
    );
    let open = intent(device, 8, [0; 16], 1);
    let expired = restarted
        .issue(open, open.sign(&signer).unwrap())
        .await
        .unwrap();
    sqlx::query("UPDATE session_requests SET expires_tick_ms=0 WHERE challenge_id=$1")
        .bind(expired.challenge_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .complete(
                SessionOperation::Open,
                expired,
                expired.sign(&signer).unwrap()
            )
            .await
            .unwrap_err(),
        SessionError::Expired
    );

    let open = intent(device, 9, [0; 16], 1);
    let fresh = restarted
        .issue(open, open.sign(&signer).unwrap())
        .await
        .unwrap();
    assert_ne!(fresh.session_id, challenge.session_id);
    restarted
        .complete(SessionOperation::Open, fresh, fresh.sign(&signer).unwrap())
        .await
        .unwrap();
    let renew = intent(device, 10, fresh.session_id, 2);
    let pending = restarted
        .issue(renew, renew.sign(&signer).unwrap())
        .await
        .unwrap();

    // Block completion on the same lock held by R09 while committing a real device revoke.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(license.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let revoker = tokio::spawn(async move {
        identity
            .revoke(license, Some(device), ACTOR, RevokeReason::Compromised)
            .await
            .unwrap();
    });
    // Wait until the trusted revoke has reached the locked license before starting completion.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
                 AND wait_event_type='Lock' AND query LIKE 'SELECT 1 FROM licenses%')",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let contender = {
        let store = restarted.clone();
        let signature = pending.sign(&signer).unwrap();
        tokio::spawn(async move {
            store
                .complete(SessionOperation::Renew, pending, signature)
                .await
        })
    };
    tx.commit().await.unwrap();
    revoker.await.unwrap();
    assert_eq!(contender.await.unwrap().unwrap_err(), SessionError::Denied);
    let sequence: i64 = sqlx::query_scalar("SELECT sequence FROM sessions WHERE id=$1")
        .bind(fresh.session_id.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sequence, 1);
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn real_client_tls_session_and_disconnect() {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::net::TcpListener;
    use vmkek_client::{SessionClient, SessionIdentity, TlsEndpoint};
    use vmkek_server::session::{serve_sessions_tls, session_tls_acceptor};

    let pool = database("r10_tls").await;
    let manufacturer = key(3);
    let store = SessionStore::start(pool.clone(), POLICY, manufacturer.clone())
        .await
        .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let signer = key(1);
    let (license_id, device_id) = provision(&identity, &signer).await;
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = cert.der().clone();
    let tls = session_tls_acceptor(
        vec![cert.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_sessions_tls(listener, tls, store));
    // A plain HTTP request sent to the real listener never reaches the session routes.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut plaintext = tokio::net::TcpStream::connect(address).await.unwrap();
        plaintext
            .write_all(b"POST /v1/session/challenge HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            plaintext.read_to_end(&mut response),
        )
        .await
        .unwrap();
        if let Err(error) = result {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        assert!(!response.starts_with(b"HTTP/"));
    }
    let scope = SessionIdentity {
        app_id: APP,
        build_id: BUILD,
        device_id,
        generation_id: GENERATION,
        license_id,
        policy_epoch: 1,
        permission: PERMISSION,
    };
    let signing_pin = *manufacturer.verifying_key();
    let endpoint = TlsEndpoint::new(address, "localhost", [cert.clone()]).unwrap();
    let wrong_hostname = TlsEndpoint::new(address, "wrong.invalid", [cert]).unwrap();
    let mut denied = SessionClient::new(wrong_hostname, scope, signer.clone(), signing_pin);
    assert!(denied.open().await.is_err());
    let mut client = SessionClient::new(endpoint, scope, signer, signing_pin);
    let open = client.open().await.unwrap().binding.session_id;
    let renewed = client.renew().await.unwrap();
    assert_eq!(renewed.binding.session_id, open);
    assert_eq!(renewed.sequence, 2);
    assert!(client.current_grant().is_some());

    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(client.renew().await.is_err());
    assert!(client.current_grant().is_none());
}

const OPERATIONS_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

struct LoopbackService {
    address: std::net::SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl LoopbackService {
    async fn start(store: SessionStore) -> Self {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use vmkek_server::session::{serve_sessions_tls, session_tls_acceptor};

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = cert.der().clone();
        let tls = session_tls_acceptor(
            vec![cert.clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_sessions_tls(listener, tls, store));
        Self {
            address,
            cert,
            task,
        }
    }

    fn connector(&self) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    }

    fn client(
        &self,
        license_id: Id,
        device_id: Id,
        signer: SigningKey,
        grant_signer: &SigningKey,
    ) -> vmkek_client::SessionClient<SigningKey> {
        let endpoint =
            vmkek_client::TlsEndpoint::new(self.address, "localhost", [self.cert.clone()]).unwrap();
        vmkek_client::SessionClient::new(
            endpoint,
            vmkek_client::SessionIdentity {
                app_id: APP,
                build_id: BUILD,
                device_id,
                generation_id: GENERATION,
                license_id,
                policy_epoch: 1,
                permission: PERMISSION,
            },
            signer,
            *grant_signer.verifying_key(),
        )
    }

    async fn stop(mut self) {
        self.task.abort();
        assert!((&mut self.task).await.unwrap_err().is_cancelled());
    }
}

impl Drop for LoopbackService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn tls_connect(
    address: std::net::SocketAddr,
    connector: &tokio_rustls::TlsConnector,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(address).await?;
    connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
}

async fn challenge_response(
    address: std::net::SocketAddr,
    connector: &tokio_rustls::TlsConnector,
    request: SessionIntent,
    signer: &SigningKey,
) -> (u16, usize) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(OPERATIONS_WAIT, async {
        let mut stream = tls_connect(address, connector).await.unwrap();
        let mut body = request.encode().unwrap();
        body.extend_from_slice(&request.sign(signer).unwrap());
        let headers = format!(
            "POST /v1/session/challenge HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut reply = Vec::new();
        stream.take(4096).read_to_end(&mut reply).await.unwrap();
        let header_end = reply.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&reply[..header_end]).unwrap()
            .split_ascii_whitespace().nth(1).unwrap().parse().unwrap();
        (status, reply.len() - header_end - 4)
    }).await.unwrap()
}

async fn wait_for_sql_lock(pool: &PgPool, application: &str, statement: &str, count: i64) {
    tokio::time::timeout(OPERATIONS_WAIT, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_catalog.pg_stat_activity
                 WHERE datname=pg_catalog.current_database() AND application_name=$1
                   AND wait_event_type='Lock' AND query LIKE $2",
            )
            .bind(application)
            .bind(statement)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting == count {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("owned requests did not reach the expected database lock");
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn live_loopback_connection_and_device_admission_recovers() {
    let pool = database("r20_admission").await;
    let grant_signer = key(3);
    let store = SessionStore::start(pool.clone(), POLICY, grant_signer.clone())
        .await
        .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let signer = key(1);
    let (license, device) = provision(&identity, &signer).await;
    let other_signer = key(2);
    let (other_license, other_device) = provision(&identity, &other_signer).await;
    let service = LoopbackService::start(store).await;
    let connector = service.connector();
    let address = service.address;

    const CONNECTION_LIMIT: usize = 128;
    let connection_start = std::time::Instant::now();
    let mut handshakes = tokio::task::JoinSet::new();
    for _ in 0..CONNECTION_LIMIT {
        let connector = connector.clone();
        handshakes.spawn(async move { tls_connect(address, &connector).await.unwrap() });
    }
    let mut held_connections = Vec::with_capacity(CONNECTION_LIMIT);
    tokio::time::timeout(OPERATIONS_WAIT, async {
        while let Some(result) = handshakes.join_next().await {
            held_connections.push(result.unwrap());
        }
    })
    .await
    .unwrap();
    assert_eq!(held_connections.len(), CONNECTION_LIMIT);
    assert!(
        tokio::time::timeout(OPERATIONS_WAIT, tls_connect(address, &connector))
            .await
            .unwrap()
            .is_err()
    );
    eprintln!(
        "owned loopback TLS: {CONNECTION_LIMIT} concurrent handshakes plus refusal in {:?}",
        connection_start.elapsed()
    );
    drop(held_connections);

    let mut other = service.client(other_license, other_device, other_signer, &grant_signer);
    tokio::time::timeout(OPERATIONS_WAIT, async {
        loop {
            if other.open().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("listener did not recover after draining TLS connections");

    let mut held_license = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(license.as_slice())
        .execute(&mut *held_license)
        .await
        .unwrap();
    let device_start = std::time::Instant::now();
    let mut challenges = tokio::task::JoinSet::new();
    for request_id in 1..=32 {
        let (connector, signer) = (connector.clone(), signer.clone());
        challenges.spawn(async move {
            challenge_response(
                address,
                &connector,
                intent(device, request_id, [0; 16], 1),
                &signer,
            )
            .await
        });
    }
    wait_for_sql_lock(&pool, "r20_admission", "SELECT l.id FROM devices%", 32).await;
    assert_eq!(
        challenge_response(address, &connector, intent(device, 33, [0; 16], 1), &signer).await,
        (429, 0)
    );
    assert_eq!(other.renew().await.unwrap().sequence, 2);
    held_license.commit().await.unwrap();
    let mut admitted = 0;
    while let Some(result) = challenges.join_next().await {
        assert_eq!(result.unwrap().0, 200);
        admitted += 1;
    }
    assert_eq!(admitted, 32);
    let mut client = service.client(license, device, signer, &grant_signer);
    assert_eq!(client.open().await.unwrap().sequence, 1);
    eprintln!("owned device: {admitted} admitted, one empty 429, other device renewed, original device reopened in {:?}", device_start.elapsed());
    service.stop().await;
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn live_listener_loss_during_renew_requires_fresh_authority() {
    let pool = database("r20_renew_loss").await;
    let signer = key(1);
    let grant_signer = key(3);
    let store = SessionStore::start(pool.clone(), POLICY, grant_signer.clone())
        .await
        .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let (license, device) = provision(&identity, &signer).await;
    let service = LoopbackService::start(store).await;
    let mut client = service.client(license, device, signer.clone(), &grant_signer);
    let old_session = client.open().await.unwrap().binding.session_id;
    let mut barrier = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(203420)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION r20_hold_renew() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM pg_catalog.pg_advisory_xact_lock(203420);
             RETURN NEW;
         END $$;
         CREATE TRIGGER r20_hold_renew BEFORE UPDATE OF consumed ON session_requests
             FOR EACH ROW EXECUTE FUNCTION r20_hold_renew()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let renew = tokio::spawn(async move {
        assert!(client.renew().await.is_err());
        assert!(client.current_grant().is_none());
    });
    wait_for_sql_lock(
        &pool,
        "r20_renew_loss",
        "UPDATE session_requests SET consumed=true%",
        1,
    )
    .await;
    service.stop().await;
    tokio::time::timeout(OPERATIONS_WAIT, renew)
        .await
        .unwrap()
        .unwrap();
    barrier.commit().await.unwrap();
    sqlx::raw_sql(
        "DROP TRIGGER r20_hold_renew ON session_requests;
         DROP FUNCTION r20_hold_renew()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let sequence: i64 = sqlx::query_scalar("SELECT sequence FROM sessions WHERE id=$1")
        .bind(old_session.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sequence, 1);
    let store = SessionStore::start(pool.clone(), POLICY, grant_signer.clone())
        .await
        .unwrap();
    let service = LoopbackService::start(store).await;
    assert_eq!(
        challenge_response(
            service.address,
            &service.connector(),
            intent(device, 34, old_session, 2),
            &signer
        )
        .await,
        (410, 0)
    );
    let mut client = service.client(license, device, signer, &grant_signer);
    let fresh = client.open().await.unwrap();
    assert_eq!(fresh.sequence, 1);
    assert_ne!(fresh.binding.session_id, old_session);
    eprintln!(
        "owned listener loss: parked renew denied, sequence unchanged, fresh session admitted"
    );
    service.stop().await;
}
