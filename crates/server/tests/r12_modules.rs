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
use vmkek_client::{ClientError, ModuleSelection, SessionClient, SessionIdentity, TlsEndpoint};
use vmkek_packager::{seal, Release, VerifiedInput};
use vmkek_protocol::{
    decode_module_key,
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, DeviceTrust, Id, ModuleFetch, ModuleOpen, ModulePurpose, PackageFrame,
    Permission, PermissionKind, Profile, SignedTrustBundle, TrustBundle, VmDescriptor, VmForm,
    ABI_VERSION,
};
use vmkek_server::{
    packages::{serve_modules_tls, ModuleKeyStore, PackageError, PackageStore, ReleaseScope},
    session::{session_tls_acceptor, SessionPolicy, SessionStore},
    IdentityStore, RevokeReason,
};

fn key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}

fn public(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
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

async fn open(
    address: SocketAddr,
    connector: &TlsConnector,
    request: ModuleOpen,
    key: &SigningKey,
) -> (u16, zeroize::Zeroizing<Vec<u8>>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let socket = TcpStream::connect(address).await.unwrap();
        let mut stream = connector.connect(ServerName::try_from("localhost").unwrap(), socket).await.unwrap();
        let mut body = request.encode().unwrap();
        let proof: Signature = key.sign_prehash(&request.signature_digest().unwrap()).unwrap();
        body.extend(proof.to_bytes());
        let header = format!("POST /v1/module/open HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = zeroize::Zeroizing::new(Vec::with_capacity(1024));
        stream.take(1024).read_to_end(&mut reply).await.unwrap();
        let split = reply.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let headers = std::str::from_utf8(&reply[..split]).unwrap();
        let status = headers.split_ascii_whitespace().nth(1).unwrap().parse().unwrap();
        if status == 200 {
            assert!(headers.lines().any(|line| line.eq_ignore_ascii_case("cache-control: no-store")));
        }
        (status, zeroize::Zeroizing::new(reply[split + 4..].to_vec()))
    }).await.unwrap()
}

#[tokio::test]
#[ignore = "requires a fresh isolated vmkek_r12_* PostgreSQL database"]
async fn key_open_is_one_shot_live_bound_and_revocable() {
    const APP: Id = [51; 16];
    const BUILD: Id = [52; 16];
    const FUNCTION: Id = [53; 16];
    const GENERATION: Id = [54; 16];
    const MODULE: Id = [55; 16];
    const ACTOR: Id = [56; 16];

    let socket = std::env::var("VMKEK_R12_PG_SOCKET").expect("isolated PostgreSQL socket");
    let database = std::env::var("VMKEK_R12_PG_DATABASE").expect("dedicated R12 test database");
    assert!(database.starts_with("vmkek_r12_"));
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(
            PgConnectOptions::new()
                .socket(socket)
                .port(55439)
                .username("r09")
                .database(&database),
        )
        .await
        .unwrap();
    let root = key(1);
    let publisher = key(2);
    let grant = key(3);
    let device = key(4);
    let permission = Permission {
        kind: PermissionKind::Function,
        id: FUNCTION,
    };
    let sessions = SessionStore::start(
        pool.clone(),
        SessionPolicy {
            app_id: APP,
            build_id: BUILD,
            generation_id: GENERATION,
            policy_epoch: 1,
            permission,
        },
        grant.clone(),
    )
    .await
    .unwrap();
    let identity = IdentityStore::new(pool.clone());
    let (license_id, activation) = identity.provision_license(APP, None).await.unwrap();
    let enrollment = identity
        .challenge(APP, &activation, public(&device), DeviceTrust::Software)
        .await
        .unwrap();
    let proof: Signature = device
        .sign_prehash(&enrollment.signature_digest().unwrap())
        .unwrap();
    let device_id = identity
        .enroll(enrollment.challenge_id, proof.to_bytes().into())
        .await
        .unwrap()
        .id;
    let packages = PackageStore::new(sessions, *root.verifying_key(), 1).unwrap();
    let bundle = SignedTrustBundle::sign(
        TrustBundle {
            app_id: APP,
            epoch: 1,
            active: public(&publisher),
            next: None,
            revoked: vec![],
            root_key_id: public_key_id(root.verifying_key()),
            extensions: vec![],
        },
        &root,
    )
    .unwrap();
    packages.install_trust(ACTOR, &bundle).await.unwrap();
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
    let make = |version| {
        seal(
            VerifiedInput::verify("r12-key-fixture", &descriptor, &code).unwrap(),
            Release {
                module_id: MODULE,
                module_version: version,
                not_before_ms: 1,
                expires_at_ms: u64::MAX,
            },
            &publisher,
        )
        .unwrap()
    };
    let scope = |version| ReleaseScope {
        build_id: BUILD,
        generation_id: GENERATION,
        function_id: FUNCTION,
        module_id: MODULE,
        version,
    };
    let first = make(1);
    let wrong_key = make(1).key;
    let swapped = vmkek_packager::SealedRelease {
        package: first.package,
        key: wrong_key,
    };
    packages
        .publish(ACTOR, scope(1), &swapped.package)
        .await
        .unwrap();
    let keys = ModuleKeyStore::new(packages.clone());
    assert_eq!(
        keys.provision(scope(1), swapped).await,
        Err(PackageError::Denied)
    );
    let selected = make(2);
    let manifest_sha256 = Sha256::digest(selected.package.manifest_bytes()).into();
    let expected_key_digest = Sha256::digest(selected.key.as_secret());
    packages
        .publish(ACTOR, scope(2), &selected.package)
        .await
        .unwrap();
    keys.provision(scope(2), selected).await.unwrap();

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let connector = connector(cert.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = session_tls_acceptor(
        vec![cert.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let server = tokio::spawn(serve_modules_tls(listener, tls, keys));
    let mut client = SessionClient::new(
        TlsEndpoint::new(address, "localhost", [cert]).unwrap(),
        SessionIdentity {
            app_id: APP,
            build_id: BUILD,
            device_id,
            generation_id: GENERATION,
            license_id,
            policy_epoch: 1,
            permission,
        },
        device.clone(),
        *grant.verifying_key(),
    );
    let session_id = client.open().await.unwrap().binding.session_id;
    let selection = ModuleSelection {
        module_id: MODULE,
        module_version: 2,
        manifest_sha256,
    };
    let opened = client.open_module(selection).await.unwrap();
    assert_eq!(Sha256::digest(opened.key()), expected_key_digest);
    assert_eq!(opened.lease_deadline(), client.lease_deadline().unwrap());
    assert_eq!(
        Sha256::digest(PackageFrame::decode(opened.frame_bytes()).unwrap().manifest).as_slice(),
        manifest_sha256
    );
    drop(opened);

    let request = ModuleOpen {
        fetch: ModuleFetch {
            app_id: APP,
            build_id: BUILD,
            device_id,
            session_id,
            generation_id: GENERATION,
            function_id: FUNCTION,
            module_id: MODULE,
            module_version: 2,
            purpose: ModulePurpose::Bytecode,
            sequence: 1,
            request_id: [61; 16],
        },
        manifest_sha256,
    };
    assert_eq!(open(address, &connector, request, &key(9)).await.0, 403);
    let (one, two) = tokio::join!(
        open(address, &connector, request, &device),
        open(address, &connector, request, &device)
    );
    let receipt = match (one, two) {
        ((200, receipt), (409, _)) | ((409, _), (200, receipt)) => receipt,
        ((first, _), (second, _)) => panic!("unexpected receipt statuses {first}, {second}"),
    };
    let opened = decode_module_key(&receipt, &request.digest().unwrap(), &manifest_sha256).unwrap();
    assert_eq!(Sha256::digest(&opened[..]), expected_key_digest);
    let wrong_manifest = ModuleOpen {
        fetch: ModuleFetch {
            request_id: [62; 16],
            ..request.fetch
        },
        manifest_sha256: [99; 32],
    };
    assert_eq!(
        open(address, &connector, wrong_manifest, &device).await.0,
        403
    );
    assert_eq!(
        open(address, &connector, wrong_manifest, &device).await.0,
        409
    );

    // The deferred trigger runs during COMMIT, after the key-open authorization checks.
    let expiry: i64 = sqlx::query_scalar(
        "UPDATE sessions SET expires_tick_ms=expires_tick_ms-28000 WHERE id=$1
         RETURNING expires_tick_ms+28000",
    )
    .bind(session_id.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION r12_delay_selected_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.delivered AND NEW.request_id = decode(repeat('41',16),'hex') THEN
                 PERFORM pg_sleep(2.25);
             END IF;
             RETURN NULL;
         END $$;
         CREATE CONSTRAINT TRIGGER r12_delay_selected_commit
         AFTER UPDATE ON package_fetch_requests DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW EXECUTE FUNCTION r12_delay_selected_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let late = ModuleOpen {
        fetch: ModuleFetch {
            request_id: [65; 16],
            ..request.fetch
        },
        ..request
    };
    let (status, body) = open(address, &connector, late, &device).await;
    assert_eq!(status, 410);
    assert!(body.is_empty());
    // Restore the fixture lease to isolate the following revoke assertions.
    sqlx::query("UPDATE sessions SET expires_tick_ms=$2 WHERE id=$1")
        .bind(session_id.as_slice())
        .bind(expiry)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(open(address, &connector, late, &device).await.0, 409);

    packages.revoke_release(ACTOR, MODULE, 2).await.unwrap();
    let after = ModuleOpen {
        fetch: ModuleFetch {
            request_id: [63; 16],
            ..request.fetch
        },
        ..request
    };
    assert_eq!(open(address, &connector, after, &device).await.0, 403);
    assert!(matches!(
        client.open_module(selection).await,
        Err(ClientError::Denied)
    ));
    assert!(client.lease_deadline().is_none());
    identity
        .revoke(license_id, None, ACTOR, RevokeReason::Compromised)
        .await
        .unwrap();
    let after = ModuleOpen {
        fetch: ModuleFetch {
            request_id: [64; 16],
            ..request.fetch
        },
        ..request
    };
    assert_eq!(open(address, &connector, after, &device).await.0, 403);

    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
