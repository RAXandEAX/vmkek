use std::{net::SocketAddr, sync::Arc, time::Duration};

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use sha2::{Digest as _, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;
use vmkek_client::{SessionClient, SessionIdentity, TlsEndpoint};
use vmkek_packager::{seal, Release, SealedPackage, VerifiedInput};
use vmkek_protocol::{
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, DeviceTrust, Id, ModuleFetch, ModulePurpose, PackageFrame, Permission,
    PermissionKind, Profile, SignedTrustBundle, TrustBundle, VmDescriptor, VmForm, ABI_VERSION,
    MAX_BODY_BYTES,
};
use vmkek_server::{
    packages::{serve_packages_tls, PackageError, PackageStore, ReleaseScope},
    session::{session_tls_acceptor, SessionPolicy, SessionStore},
    IdentityStore, RevokeReason,
};

const APP: Id = [1; 16];
const BUILD: Id = [2; 16];
const FUNCTION: Id = [3; 16];
const GENERATION: Id = [4; 16];
const MODULE: Id = [5; 16];
const ACTOR: Id = [6; 16];
const PERMISSION: Permission = Permission {
    kind: PermissionKind::Function,
    id: FUNCTION,
};
const POLICY: SessionPolicy = SessionPolicy {
    app_id: APP,
    build_id: BUILD,
    generation_id: GENERATION,
    policy_epoch: 1,
    permission: PERMISSION,
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn sec1(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn trust(
    root: &SigningKey,
    epoch: u64,
    active: &SigningKey,
    next: Option<&SigningKey>,
    revoked: Vec<[u8; 32]>,
) -> SignedTrustBundle {
    SignedTrustBundle::sign(
        TrustBundle {
            app_id: APP,
            epoch,
            active: sec1(active),
            next: next.map(sec1),
            revoked,
            root_key_id: public_key_id(root.verifying_key()),
            extensions: vec![],
        },
        root,
    )
    .unwrap()
}

fn scope(version: u64) -> ReleaseScope {
    ReleaseScope {
        build_id: BUILD,
        generation_id: GENERATION,
        function_id: FUNCTION,
        module_id: MODULE,
        version,
    }
}

fn package(signer: &SigningKey, version: u64) -> SealedPackage {
    let code = LabProgram {
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
        generation_id: GENERATION,
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![],
        program_sha256: Sha256::digest(&code).into(),
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
    seal(
        VerifiedInput::verify("r11-fixture", &descriptor, &code).unwrap(),
        Release {
            module_id: MODULE,
            module_version: version,
            not_before_ms: 1,
            expires_at_ms: u64::MAX,
        },
        signer,
    )
    .unwrap()
    .package
}

async fn database() -> PgPool {
    let socket = std::env::var("VMKEK_R11_PG_SOCKET").expect("isolated PostgreSQL socket");
    let database = std::env::var("VMKEK_R11_PG_DATABASE").expect("dedicated R11 test database");
    assert!(database.starts_with("vmkek_r11_"));
    let options = PgConnectOptions::new()
        .socket(socket)
        .port(55439)
        .username("r09")
        .database(&database);
    PgPoolOptions::new()
        .max_connections(12)
        .connect_with(options)
        .await
        .unwrap()
}

async fn enroll(identity: &IdentityStore, device: &SigningKey) -> (Id, Id) {
    let (license, activation) = identity.provision_license(APP, None).await.unwrap();
    let challenge = identity
        .challenge(APP, &activation, sec1(device), DeviceTrust::Software)
        .await
        .unwrap();
    let proof: Signature = device
        .sign_prehash(&challenge.signature_digest().unwrap())
        .unwrap();
    let enrolled = identity
        .enroll(challenge.challenge_id, proof.to_bytes().into())
        .await
        .unwrap();
    (license, enrolled.id)
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
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(config))
}

async fn fetch(
    address: SocketAddr,
    connector: &TlsConnector,
    request: ModuleFetch,
    signer: &SigningKey,
) -> (u16, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let socket = TcpStream::connect(address).await.unwrap();
        let mut stream = connector.connect(ServerName::try_from("localhost").unwrap(), socket).await.unwrap();
        let mut body = request.encode().unwrap();
        body.extend(request.sign(signer).unwrap());
        let header = format!("POST /v1/module/fetch HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = Vec::new();
        stream.take((MAX_BODY_BYTES + 4096) as u64).read_to_end(&mut reply).await.unwrap();
        let split = reply.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&reply[..split]).unwrap().split_ascii_whitespace()
            .nth(1).unwrap().parse().unwrap();
        (status, reply.split_off(split + 4))
    }).await.unwrap()
}

#[tokio::test]
#[ignore = "requires a fresh explicitly provisioned isolated R11 PostgreSQL database"]
async fn tls_fetch_enforces_rotation_rollback_replay_and_revocation() {
    let pool = database().await;
    let grant_key = key(7);
    let root = key(8);
    let active = key(9);
    let next = key(10);
    let foreign = key(11);
    let device = key(12);
    let sessions = SessionStore::start(pool.clone(), POLICY, grant_key.clone())
        .await
        .unwrap();
    let store = PackageStore::new(sessions.clone(), *root.verifying_key(), 1).unwrap();
    let first = trust(&root, 1, &active, Some(&next), vec![]);
    assert_eq!(
        store
            .install_trust(ACTOR, &trust(&foreign, 1, &active, None, vec![]))
            .await,
        Err(PackageError::Denied)
    );
    store.install_trust(ACTOR, &first).await.unwrap();
    store.install_trust(ACTOR, &first).await.unwrap();
    assert_eq!(
        store.publish(ACTOR, scope(1), &package(&next, 1)).await,
        Err(PackageError::Denied)
    );
    assert_eq!(
        store.publish(ACTOR, scope(1), &package(&foreign, 1)).await,
        Err(PackageError::Denied)
    );

    let wrong = ReleaseScope {
        function_id: [99; 16],
        ..scope(1)
    };
    let artifact = package(&active, 1);
    assert_eq!(
        store.publish(ACTOR, wrong, &artifact).await,
        Err(PackageError::Denied)
    );
    store.publish(ACTOR, scope(1), &artifact).await.unwrap();
    assert_eq!(
        store.publish(ACTOR, scope(1), &artifact).await,
        Err(PackageError::Conflict)
    );

    let identity = IdentityStore::new(pool.clone());
    let (license_id, device_id) = enroll(&identity, &device).await;
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = session_tls_acceptor(
        vec![cert.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let server = tokio::spawn(serve_packages_tls(listener, acceptor, store.clone()));
    let connector = connector(cert.clone());
    let mut client = SessionClient::new(
        TlsEndpoint::new(address, "localhost", [cert]).unwrap(),
        SessionIdentity {
            app_id: APP,
            build_id: BUILD,
            device_id,
            generation_id: GENERATION,
            license_id,
            policy_epoch: 1,
            permission: PERMISSION,
        },
        device.clone(),
        *grant_key.verifying_key(),
    );
    let session_id = client.open().await.unwrap().binding.session_id;
    let request = ModuleFetch {
        app_id: APP,
        build_id: BUILD,
        device_id,
        session_id,
        generation_id: GENERATION,
        function_id: FUNCTION,
        module_id: MODULE,
        module_version: 1,
        purpose: ModulePurpose::Bytecode,
        sequence: 1,
        request_id: [21; 16],
    };
    assert_eq!(fetch(address, &connector, request, &foreign).await.0, 403);
    let (one, two) = tokio::join!(
        fetch(address, &connector, request, &device),
        fetch(address, &connector, request, &device)
    );
    assert_eq!(one.0, 200);
    assert_eq!(one, two);
    let frame = PackageFrame::decode(&one.1).unwrap();
    assert_eq!(frame.descriptor, artifact.descriptor_bytes());
    assert_eq!(frame.manifest, artifact.manifest_bytes());
    assert_eq!(frame.ciphertext, artifact.ciphertext());
    assert_eq!(
        fetch(
            address,
            &connector,
            ModuleFetch {
                module_version: 2,
                ..request
            },
            &device
        )
        .await
        .0,
        409
    );
    assert_eq!(
        fetch(
            address,
            &connector,
            ModuleFetch {
                function_id: [99; 16],
                ..request
            },
            &device
        )
        .await
        .0,
        403
    );

    let rotated = trust(
        &root,
        2,
        &next,
        None,
        vec![public_key_id(active.verifying_key())],
    );
    store.install_trust(ACTOR, &rotated).await.unwrap();
    assert_eq!(
        store.install_trust(ACTOR, &first).await,
        Err(PackageError::Denied)
    );
    assert_eq!(
        store
            .install_trust(ACTOR, &trust(&root, 3, &next, None, vec![]))
            .await,
        Err(PackageError::Denied)
    );
    assert_eq!(fetch(address, &connector, request, &device).await.0, 403);
    assert_eq!(
        store.publish(ACTOR, scope(2), &package(&active, 2)).await,
        Err(PackageError::Denied)
    );
    let artifact = package(&next, 2);
    store.publish(ACTOR, scope(2), &artifact).await.unwrap();
    assert_eq!(
        store.publish(ACTOR, scope(1), &package(&next, 1)).await,
        Err(PackageError::Conflict)
    );

    let old = ModuleFetch {
        request_id: [22; 16],
        ..request
    };
    assert_eq!(fetch(address, &connector, old, &device).await.0, 403);
    let request = ModuleFetch {
        request_id: [23; 16],
        module_version: 2,
        ..request
    };
    assert_eq!(fetch(address, &connector, request, &device).await.0, 200);
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT frame FROM package_releases WHERE app_id=$1 AND module_id=$2 AND version=2",
    )
    .bind(APP.as_slice())
    .bind(MODULE.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    for (bytes, expected) in [(tampered, 403), (original, 200)] {
        sqlx::query(
            "UPDATE package_releases SET frame=$3 WHERE app_id=$1 AND module_id=$2 AND version=2",
        )
        .bind(APP.as_slice())
        .bind(MODULE.as_slice())
        .bind(bytes)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            fetch(address, &connector, request, &device).await.0,
            expected
        );
    }

    assert_eq!(client.renew().await.unwrap().sequence, 2);
    assert_eq!(fetch(address, &connector, request, &device).await.0, 403);
    let request = ModuleFetch {
        request_id: [24; 16],
        sequence: 2,
        ..request
    };
    assert_eq!(fetch(address, &connector, request, &device).await.0, 200);
    store.revoke_release(ACTOR, MODULE, 2).await.unwrap();
    assert_eq!(fetch(address, &connector, request, &device).await.0, 403);

    store
        .publish(ACTOR, scope(3), &package(&next, 3))
        .await
        .unwrap();
    let request = ModuleFetch {
        request_id: [25; 16],
        module_version: 3,
        ..request
    };
    assert_eq!(fetch(address, &connector, request, &device).await.0, 200);
    identity
        .revoke(license_id, None, ACTOR, RevokeReason::Compromised)
        .await
        .unwrap();
    assert_eq!(fetch(address, &connector, request, &device).await.0, 403);
    let events: Vec<String> = sqlx::query_scalar("SELECT action FROM package_audit ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        events,
        [
            "trust_installed",
            "release_published",
            "trust_installed",
            "release_published",
            "release_revoked",
            "release_published"
        ]
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());

    let restarted = SessionStore::start(pool, POLICY, grant_key).await.unwrap();
    let restart = PackageStore::new(restarted, *root.verifying_key(), 2).unwrap();
    assert_eq!(
        restart.install_trust(ACTOR, &first).await,
        Err(PackageError::Denied)
    );
    assert_eq!(
        restart.publish(ACTOR, scope(2), &artifact).await,
        Err(PackageError::Conflict)
    );
}
