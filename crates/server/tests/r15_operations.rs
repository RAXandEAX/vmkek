use std::{net::SocketAddr, sync::Arc, time::Duration};

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;
use vmkek_client::{GenerationCapabilities, SessionClient, SessionIdentity, TlsEndpoint};
use vmkek_packager::{seal, Release, VerifiedInput};
use vmkek_protocol::{
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, DeviceTrust, GrantBinding, Id, Permission, PermissionKind, Profile,
    SampleJob, SampleOperationRequest, SignedOperationReceipt, SignedTrustBundle, TrustBundle,
    VmDescriptor, VmForm, ABI_VERSION, SAMPLE_JOB_RECEIPT_OPERATION,
    SAMPLE_OPERATION_RECEIPT_BYTES, SAMPLE_OPERATION_REQUEST_BYTES,
};
use vmkek_server::{
    generation::GenerationStore,
    operations::{serve_hybrid_generations_tls, OperationStore, SampleOperationPolicy},
    packages::{ModuleKeyStore, PackageError, PackageStore, ReleaseScope},
    session::{session_tls_acceptor, NegotiatedSessionPolicy, SessionStore},
    IdentityStore, RevokeReason,
};

const APP: Id = [61; 16];
const BUILD: Id = [62; 16];
const FUNCTION: Id = [63; 16];
const ACTOR: Id = [64; 16];
const POLICY: SampleOperationPolicy = SampleOperationPolicy {
    app_id: APP,
    build_id: BUILD,
    function_id: FUNCTION,
};

fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn sec1(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn signed(key: &SigningKey, request: SampleOperationRequest) -> Vec<u8> {
    let mut bytes = request.encode().unwrap();
    assert_eq!(bytes.len(), SAMPLE_OPERATION_REQUEST_BYTES);
    let signature: Signature = key
        .sign_prehash(&request.signature_digest().unwrap())
        .unwrap();
    bytes.extend(signature.to_bytes());
    bytes
}
fn connector(cert: CertificateDer<'static>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}
async fn start_post(
    address: SocketAddr,
    connector: &TlsConnector,
    body: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let socket = TcpStream::connect(address).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
    let header = format!(
        "POST /v1/operation/sample-job-receipt HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream
}

async fn post(address: SocketAddr, connector: &TlsConnector, body: &[u8]) -> (u16, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let stream = start_post(address, connector, body).await;
        let mut reply = Vec::new();
        stream.take(4096).read_to_end(&mut reply).await.unwrap();
        let split = reply
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let status = std::str::from_utf8(&reply[..split])
            .unwrap()
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, reply.split_off(split + 4))
    })
    .await
    .unwrap()
}

async fn provision_generation(
    packages: &PackageStore,
    generations: &GenerationStore,
    signer: &SigningKey,
    operation_key: &SigningKey,
    number: u8,
) -> ReleaseScope {
    let generation_id = [number; 16];
    let module_id = [number + 10; 16];
    let bytecode = LabProgram {
        arguments: vec![],
        result: None,
        instructions: vec![Instruction::Return],
    }
    .encode()
    .unwrap();
    let descriptor = VmDescriptor {
        abi_version: ABI_VERSION,
        app_id: APP,
        build_id: BUILD,
        function_id: FUNCTION,
        generation_id,
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![],
        program_sha256: Sha256::digest(&bytecode).into(),
        budgets: Budgets {
            fuel: 100,
            memory_bytes: 65536,
            deadline_ms: 5000,
            active_contexts: 1,
            call_depth: 1,
        },
        profile: Profile::Online,
        extensions: vec![],
    };
    let sealed = seal(
        VerifiedInput::verify_negotiated("r15-hybrid", &descriptor, &bytecode).unwrap(),
        Release {
            module_id,
            module_version: 1,
            not_before_ms: 1,
            expires_at_ms: u64::MAX,
        },
        signer,
    )
    .unwrap();
    let operation_scalar = zeroize::Zeroizing::new(operation_key.to_bytes());
    for field in [
        sealed.package.descriptor_bytes(),
        sealed.package.manifest_bytes(),
        sealed.package.ciphertext(),
    ] {
        assert!(!field
            .windows(32)
            .any(|window| window == &operation_scalar[..]));
    }
    let scope = ReleaseScope {
        build_id: BUILD,
        generation_id,
        function_id: FUNCTION,
        module_id,
        version: 1,
    };
    packages
        .publish(ACTOR, scope, &sealed.package)
        .await
        .unwrap();
    generations.prepare(scope, &sealed).await.unwrap();
    scope
}

fn request(binding: GrantBinding, id: u8, sequence: u64) -> SampleOperationRequest {
    SampleOperationRequest {
        app_id: binding.app_id,
        build_id: binding.build_id,
        device_id: binding.device_id,
        session_id: binding.session_id,
        generation_id: binding.generation_id,
        function_id: FUNCTION,
        operation_id: SAMPLE_JOB_RECEIPT_OPERATION,
        request_id: [id; 16],
        sequence,
        job: SampleJob {
            job_id: [74; 16],
            units: 3,
        },
    }
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned fresh vmkek_r15_* PostgreSQL database"]
async fn live_hybrid_receipt_idempotency_and_revocation() {
    let socket = std::env::var("VMKEK_R15_PG_SOCKET").unwrap();
    let database = std::env::var("VMKEK_R15_PG_DATABASE").unwrap();
    assert!(database.starts_with("vmkek_r15_"));
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect_with(
            PgConnectOptions::new()
                .socket(socket)
                .port(55439)
                .username("r09")
                .database(&database),
        )
        .await
        .unwrap();
    let grant = key(1);
    let root = key(2);
    let publisher = key(3);
    let signer = key(4);
    let device = key(5);
    let next = key(6);
    let session = SessionStore::start_negotiated(
        pool.clone(),
        NegotiatedSessionPolicy {
            app_id: APP,
            build_id: BUILD,
            function_id: FUNCTION,
            policy_epoch: 1,
        },
        grant.clone(),
    )
    .await
    .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let (license_id, activation) = identity.provision_license(APP, None).await.unwrap();
    let challenge = identity
        .challenge(APP, &activation, sec1(&device), DeviceTrust::Software)
        .await
        .unwrap();
    let proof: Signature = device
        .sign_prehash(&challenge.signature_digest().unwrap())
        .unwrap();
    let device_id = identity
        .enroll(challenge.challenge_id, proof.to_bytes().into())
        .await
        .unwrap()
        .id;
    let packages = PackageStore::new(session.clone(), *root.verifying_key(), 2).unwrap();
    let trust = SignedTrustBundle::sign(
        TrustBundle {
            app_id: APP,
            epoch: 2,
            active: sec1(&publisher),
            next: Some(sec1(&next)),
            revoked: vec![],
            root_key_id: public_key_id(root.verifying_key()),
            extensions: vec![],
        },
        &root,
    )
    .unwrap();
    packages.install_trust(ACTOR, &trust).await.unwrap();
    let generations = GenerationStore::new(ModuleKeyStore::new(packages.clone()));
    let first = provision_generation(&packages, &generations, &publisher, &signer, 71).await;
    let second = provision_generation(&packages, &generations, &publisher, &signer, 72).await;
    assert!(matches!(
        OperationStore::new(
            session.clone(),
            Some(packages.clone()),
            POLICY,
            grant.clone()
        ),
        Err(PackageError::Denied)
    ));
    let wrong_role =
        OperationStore::new(session.clone(), Some(packages.clone()), POLICY, next).unwrap();
    assert_eq!(wrong_role.configure(ACTOR).await, Err(PackageError::Denied));
    let operations = OperationStore::new(
        session.clone(),
        Some(packages.clone()),
        POLICY,
        signer.clone(),
    )
    .unwrap();
    operations.configure(ACTOR).await.unwrap();

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let tls = session_tls_acceptor(
        vec![cert.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    for mismatch in [
        PackageStore::new(session.clone(), *root.verifying_key(), 1).unwrap(),
        PackageStore::new(session.clone(), *key(8).verifying_key(), 2).unwrap(),
    ] {
        let incompatible =
            OperationStore::new(session.clone(), Some(mismatch), POLICY, signer.clone()).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_millis(250),
            serve_hybrid_generations_tls(listener, tls.clone(), generations.clone(), incompatible),
        )
        .await
        .expect("mismatched package authority must fail before serving")
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let transport = connector(cert.clone());
    let server = tokio::spawn(serve_hybrid_generations_tls(
        listener,
        tls.clone(),
        generations.clone(),
        operations.clone(),
    ));
    let mut client = SessionClient::new(
        TlsEndpoint::new(address, "localhost", [cert]).unwrap(),
        SessionIdentity {
            app_id: APP,
            build_id: BUILD,
            device_id,
            generation_id: [0; 16],
            license_id,
            policy_epoch: 1,
            permission: Permission {
                kind: PermissionKind::Function,
                id: FUNCTION,
            },
        },
        device.clone(),
        *grant.verifying_key(),
    );
    let support = GenerationCapabilities {
        forms: GenerationCapabilities::STACK,
        capabilities: 0,
    };
    let selected = client.negotiate_generation(support).await.unwrap().unwrap();
    assert_eq!(selected.generation_id, first.generation_id);
    let binding = client.current_grant().unwrap().binding;
    let first_request = request(binding, 81, 1);
    assert_eq!(
        post(address, &transport, &signed(&key(7), first_request))
            .await
            .0,
        403
    );
    assert_eq!(
        post(
            address,
            &transport,
            &signed(
                &device,
                SampleOperationRequest {
                    operation_id: [1; 16],
                    ..first_request
                }
            )
        )
        .await
        .0,
        403
    );
    assert_eq!(
        post(
            address,
            &transport,
            &signed(
                &device,
                SampleOperationRequest {
                    session_id: [1; 16],
                    ..first_request
                }
            )
        )
        .await
        .0,
        403
    );
    assert!(SampleOperationRequest {
        job: SampleJob {
            units: 129,
            ..first_request.job
        },
        ..first_request
    }
    .encode()
    .is_err());
    let body = signed(&device, first_request);
    let (one, two) = tokio::join!(
        post(address, &transport, &body),
        post(address, &transport, &body)
    );
    assert_eq!(one, two);
    assert_eq!(one.0, 200);
    assert_eq!(one.1.len(), SAMPLE_OPERATION_RECEIPT_BYTES);
    let receipt = SignedOperationReceipt::decode(&one.1).unwrap();
    assert_eq!(
        receipt
            .verify_for(signer.verifying_key(), &first_request, binding, 1)
            .unwrap()
            .value,
        21
    );
    assert!(receipt
        .verify_for(grant.verifying_key(), &first_request, binding, 1)
        .is_err());
    let conflict = SampleOperationRequest {
        job: SampleJob {
            units: 4,
            ..first_request.job
        },
        ..first_request
    };
    assert_eq!(
        post(address, &transport, &signed(&device, conflict))
            .await
            .0,
        409
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operation_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(client.renew().await.unwrap().sequence, 2);
    assert_eq!(post(address, &transport, &body).await.0, 403);

    let late = request(binding, 82, 2);
    let expiry: i64 = sqlx::query_scalar(
        "UPDATE sessions SET expires_tick_ms=expires_tick_ms-28000 WHERE id=$1 RETURNING expires_tick_ms+28000",
    ).bind(binding.session_id.as_slice()).fetch_one(&pool).await.unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION r15_delay_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.request_id=decode(repeat('52',16),'hex') THEN PERFORM pg_sleep(2.25); END IF;
             RETURN NULL;
         END $$;
         CREATE CONSTRAINT TRIGGER r15_delay_commit AFTER INSERT ON operation_requests
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION r15_delay_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let denied = post(address, &transport, &signed(&device, late)).await;
    assert_eq!(denied, (410, Vec::new()));
    let consumed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operation_requests WHERE request_id=$1)")
            .bind(late.request_id.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(consumed);
    sqlx::query("UPDATE sessions SET expires_tick_ms=$2 WHERE id=$1")
        .bind(binding.session_id.as_slice())
        .bind(expiry)
        .execute(&pool)
        .await
        .unwrap();
    packages
        .revoke_release(ACTOR, first.module_id, first.version)
        .await
        .unwrap();
    assert_eq!(
        post(
            address,
            &transport,
            &signed(&device, request(binding, 83, 2))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        client
            .negotiate_generation(support)
            .await
            .unwrap()
            .unwrap()
            .generation_id,
        second.generation_id
    );
    let binding = client.current_grant().unwrap().binding;
    assert_eq!(
        post(
            address,
            &transport,
            &signed(&device, request(binding, 84, 1))
        )
        .await
        .0,
        200
    );

    let interrupted = request(binding, 86, 1);
    let interrupted_body = signed(&device, interrupted);
    let mut barrier = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(203415)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION r20_hold_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM pg_catalog.pg_advisory_xact_lock(203415);
             RETURN NEW;
         END $$;
         CREATE TRIGGER r20_hold_receipt BEFORE INSERT ON operation_requests
             FOR EACH ROW EXECUTE FUNCTION r20_hold_receipt()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut receipt_stream = tokio::time::timeout(
        Duration::from_secs(2),
        start_post(address, &transport, &interrupted_body),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity
                 WHERE datname=pg_catalog.current_database() AND wait_event_type='Lock'
                   AND wait_event='advisory' AND query LIKE 'INSERT INTO operation_requests%')",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("owned receipt request did not reach the insert barrier");
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let mut byte = [0; 1];
    let response = tokio::time::timeout(Duration::from_secs(2), receipt_stream.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(response, Ok(0))
            || matches!(response, Err(e) if matches!(e.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset))
    );

    barrier.commit().await.unwrap();
    sqlx::raw_sql(
        "DROP TRIGGER r20_hold_receipt ON operation_requests;
         DROP FUNCTION r20_hold_receipt()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let persisted = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT receipt FROM operation_requests WHERE device_id=$1 AND request_id=$2",
    )
    .bind(device_id.as_slice())
    .bind(interrupted.request_id.as_slice())
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(persisted.is_none());

    let listener = TcpListener::bind(address).await.unwrap();
    let server = tokio::spawn(serve_hybrid_generations_tls(
        listener,
        tls,
        generations,
        operations.clone(),
    ));
    let retry = post(address, &transport, &interrupted_body).await;
    assert_eq!(retry.0, 200);
    let receipt = SignedOperationReceipt::decode(&retry.1).unwrap();
    let verified = receipt
        .verify_for(signer.verifying_key(), &interrupted, binding, 1)
        .unwrap();
    assert_eq!(verified.value, 21);
    assert_eq!(post(address, &transport, &interrupted_body).await, retry);
    let durable: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt FROM operation_requests WHERE device_id=$1 AND request_id=$2",
    )
    .bind(device_id.as_slice())
    .bind(interrupted.request_id.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(durable, retry.1);
    eprintln!("owned typed receipt: zero bytes before listener restart, one durable identical receipt after exact retry");

    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(license_id.as_slice())
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let revoker = tokio::spawn(async move {
        identity
            .revoke(license_id, None, ACTOR, RevokeReason::Compromised)
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(2), async {
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
    let revocable = signed(&device, request(binding, 85, 1));
    let request_task = tokio::spawn(async move { post(address, &transport, &revocable).await });
    lock.commit().await.unwrap();
    revoker.await.unwrap();
    assert_eq!(request_task.await.unwrap().0, 403);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operation_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 4);
    operations.disable(ACTOR).await.unwrap();
    assert_eq!(operations.configure(ACTOR).await, Err(PackageError::Denied));
    let events: Vec<String> =
        sqlx::query_scalar("SELECT action FROM protected_operation_audit ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(events, ["configured", "disabled"]);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
