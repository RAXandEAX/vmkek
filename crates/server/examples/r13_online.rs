#[cfg(unix)]
#[path = "r13_online/access_fixture.rs"]
mod access_fixture;

#[cfg(unix)]
mod lab {
    use std::{
        env, fs,
        io::{self, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::Duration,
    };

    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use rand::{rngs::OsRng, RngCore};
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use sha2::{Digest as _, Sha256};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tokio::net::TcpListener;
    use vmkek_packager::{seal, Release, SealedRelease, VerifiedInput};
    use vmkek_protocol::{
        lab::{Instruction, LabProgram, ScalarType},
        public_key_id, Budgets, DeviceTrust, Id, Profile, SignedTrustBundle, TrustBundle,
        VmDescriptor, VmForm, ABI_VERSION, GENERATION_REGISTER, GENERATION_STACK,
    };
    use vmkek_server::{
        generation::{serve_generations_tls, GenerationStore},
        operations::{serve_hybrid_generations_tls, OperationStore, SampleOperationPolicy},
        packages::{ModuleKeyStore, PackageStore, ReleaseScope},
        session::{session_tls_acceptor, NegotiatedSessionPolicy, SessionStore},
        IdentityStore, RevokeReason,
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::access_fixture::{own_stop_recorded, AccessFixture};

    const APP: Id = [41; 16];
    const BUILD: Id = [42; 16];
    const FUNCTION: Id = [44; 16];
    const ACTOR: Id = [46; 16];
    const EPOCH: u64 = 1;

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = env::args_os().skip(1);
        let directory = PathBuf::from(args.next().ok_or("owner-only output directory required")?);
        let socket = PathBuf::from(args.next().ok_or("isolated PostgreSQL socket required")?);
        let database = args
            .next()
            .ok_or("isolated database required")?
            .into_string()
            .map_err(|_| "invalid database name")?;
        if args.next().is_some()
            || !(database.starts_with("vmkek_r13_")
                || database.starts_with("vmkek_r15_")
                || database.starts_with("vmkek_r17_"))
            || !directory.is_absolute()
        {
            return Err(
                "expected an absolute lab directory and a dedicated vmkek_r13_*, vmkek_r15_* or vmkek_r17_* database".into(),
            );
        }
        serve_fixture(directory, socket, database, false).await
    }

    pub async fn serve_fixture(
        directory: PathBuf,
        socket: PathBuf,
        database: String,
        short_release: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let r17 = database.starts_with("vmkek_r17_");
        let hybrid = database.starts_with("vmkek_r15_") || r17;
        let directory_metadata = fs::symlink_metadata(&directory)?;
        if !directory_metadata.is_dir() || directory_metadata.mode() & 0o077 != 0 {
            return Err("fixture directory must be private and must not be a symlink".into());
        }
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(
                PgConnectOptions::new()
                    .socket(socket)
                    .port(55439)
                    .username("r09")
                    .database(&database),
            )
            .await?;
        let grant_key = SigningKey::random(&mut OsRng);
        let root = SigningKey::random(&mut OsRng);
        let release_key = SigningKey::random(&mut OsRng);
        let next_key = SigningKey::random(&mut OsRng);
        let device = SigningKey::random(&mut OsRng);
        let session = SessionStore::start_negotiated(
            pool.clone(),
            NegotiatedSessionPolicy {
                app_id: APP,
                build_id: BUILD,
                policy_epoch: EPOCH,
                function_id: FUNCTION,
            },
            grant_key.clone(),
        )
        .await?;
        let identity = IdentityStore::new(pool.clone());
        let (license, activation) = identity.provision_license(APP, None).await?;
        let enrollment = identity
            .challenge(APP, &activation, sec1(&device), DeviceTrust::Software)
            .await?;
        let proof: Signature = device.sign_prehash(&enrollment.signature_digest()?)?;
        let enrolled = identity
            .enroll(enrollment.challenge_id, proof.to_bytes().into())
            .await?;
        let store = PackageStore::new(session.clone(), *root.verifying_key(), EPOCH)?;
        let trust = SignedTrustBundle::sign(
            TrustBundle {
                app_id: APP,
                epoch: EPOCH,
                active: sec1(&release_key),
                next: Some(sec1(&next_key)),
                revoked: vec![],
                root_key_id: public_key_id(root.verifying_key()),
                extensions: vec![],
            },
            &root,
        )?;
        store.install_trust(ACTOR, &trust).await?;
        let rotated = SignedTrustBundle::sign(
            TrustBundle {
                app_id: APP,
                epoch: EPOCH + 1,
                active: sec1(&next_key),
                next: None,
                revoked: vec![public_key_id(release_key.verifying_key())],
                root_key_id: public_key_id(root.verifying_key()),
                extensions: vec![],
            },
            &root,
        )?;

        let keys = ModuleKeyStore::new(store.clone());
        let generations = GenerationStore::new(keys.clone());
        if short_release {
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            prepare(
                &store,
                &generations,
                &release_key,
                VmForm::Stack,
                now + 2800,
            )
            .await?;
        }
        for form in [
            VmForm::Stack,
            VmForm::Register,
            VmForm::Stack,
            VmForm::Register,
        ] {
            prepare(&store, &generations, &release_key, form, u64::MAX).await?;
        }

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()])?;
        let cert = cert.der().clone();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?.to_string();
        let tls = session_tls_acceptor(
            vec![cert.clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )?;
        let server = if hybrid {
            let receipt_signer = SigningKey::random(&mut OsRng);
            let receipt_pin = sec1(&receipt_signer);
            let operations = OperationStore::new(
                session,
                Some(store.clone()),
                SampleOperationPolicy {
                    app_id: APP,
                    build_id: BUILD,
                    function_id: FUNCTION,
                },
                receipt_signer,
            )?;
            operations.configure(ACTOR).await?;
            write_private(&directory.join("receipt-pin.bin"), &receipt_pin)?;
            tokio::spawn(serve_hybrid_generations_tls(
                listener,
                tls,
                generations.clone(),
                operations,
            ))
        } else {
            tokio::spawn(serve_generations_tls(listener, tls, generations.clone()))
        };

        let capacity = 8
            + 5 * 16
            + 8
            + 16
            + 65
            + 65
            + 8
            + 4
            + 32
            + 4 * 4
            + address.len()
            + "localhost".len()
            + cert.len()
            + trust.as_bytes().len();
        let mut config = Zeroizing::new(Vec::with_capacity(capacity));
        config.extend(b"VMKR13\0\0");
        for id in [APP, BUILD, enrolled.id, [0; 16], license] {
            config.extend(id);
        }
        config.extend(EPOCH.to_le_bytes());
        config.extend(FUNCTION);
        config.extend(sec1(&grant_key));
        config.extend(sec1(&root));
        config.extend(EPOCH.to_le_bytes());
        config.push(GENERATION_STACK | GENERATION_REGISTER);
        config.extend(0u16.to_le_bytes());
        let flags_at = config.len();
        config.push(0);
        let mut credential = device.to_bytes();
        config.extend_from_slice(&credential);
        credential.zeroize();
        for bytes in [
            address.as_bytes(),
            b"localhost",
            cert.as_ref(),
            trust.as_bytes(),
        ] {
            config.extend(u32::try_from(bytes.len())?.to_le_bytes());
            config.extend_from_slice(bytes);
        }
        assert_eq!(config.len(), capacity);
        write_private(&directory.join("config.bin"), &config)?;
        config[flags_at] = 1;
        write_private(&directory.join("swap-config.bin"), &config)?;
        drop(config);
        write_private(&directory.join("ready"), b"ready\n")?;

        let access = r17
            .then(|| AccessFixture::new(pool.clone(), APP, ACTOR, license, EPOCH))
            .transpose()?;
        let mut decision = None;
        let mut own_stop_seen = false;
        let mut revoked = false;
        let mut rotated_once = false;
        let mut release_revoked = false;
        let mut refilled = false;
        let mut operation_stalled = false;
        let mut retry = None;
        let until = tokio::time::Instant::now() + Duration::from_secs(180);
        while tokio::time::Instant::now() < until
            && !directory.join("stop").exists()
            && !server.is_finished()
        {
            if !revoked && directory.join("revoke").exists() {
                if let Some(access) = &access {
                    decision = Some(access.apply(&pool, None).await?);
                } else {
                    identity
                        .revoke(license, None, ACTOR, RevokeReason::Administrator)
                        .await?;
                }
                write_private(&directory.join("revoked"), b"revoked\n")?;
                revoked = true;
            }
            if let Some(access) = &access {
                if directory.join("restore").exists() {
                    if let Some(prior) = decision.take() {
                        access.apply(&pool, Some(prior)).await?;
                        write_private(
                            &directory.join("restored"),
                            b"restored
",
                        )?;
                    }
                }
                if !own_stop_seen && own_stop_recorded(&pool, license).await? {
                    write_private(
                        &directory.join("observed-stop"),
                        b"observed-stop
",
                    )?;
                    own_stop_seen = true;
                }
            }
            if !release_revoked && directory.join("revoke-release").exists() {
                let module: Id = fs::read(directory.join("revoke-release"))?
                    .try_into()
                    .map_err(|_| "expected a 16-byte fixture module ID")?;
                store.revoke_release(ACTOR, module, 1).await?;
                write_private(&directory.join("release-revoked"), b"revoked\n")?;
                release_revoked = true;
            }
            if short_release && !refilled && directory.join("refill").exists() {
                for _ in 0..64 {
                    prepare(&store, &generations, &release_key, VmForm::Stack, u64::MAX).await?;
                }
                let (scope, release) =
                    publish_variant(&store, &release_key, VmForm::Register, u64::MAX).await?;
                for _ in 0..3 {
                    let blocked = generations
                        .prepare(scope, &release)
                        .await
                        .expect_err("eligible catalog capacity must stay bounded");
                    assert_eq!(
                        blocked,
                        vmkek_server::packages::PackageError::Session(
                            vmkek_server::session::SessionError::Limit
                        ),
                    );
                }
                retry = Some((scope, release));
                write_private(&directory.join("refilled"), b"refilled\n")?;
                refilled = true;
            }
            if directory.join("retry").exists() {
                if let Some((scope, release)) = retry.take() {
                    let (first, second) = tokio::join!(
                        generations.prepare(scope, &release),
                        generations.prepare(scope, &release),
                    );
                    first?;
                    second?;
                    write_private(&directory.join("retried"), b"retried\n")?;
                }
            }
            if hybrid && !operation_stalled && directory.join("stall-operation").exists() {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT app_id FROM protected_operations WHERE app_id=$1 FOR UPDATE")
                    .bind(APP.as_slice())
                    .fetch_one(&mut *tx)
                    .await?;
                write_private(&directory.join("operation-stalled"), b"stalled\n")?;
                tokio::time::sleep(Duration::from_secs(7)).await;
                tx.rollback().await?;
                operation_stalled = true;
            }
            if !rotated_once && directory.join("rotate").exists() {
                store.install_trust(ACTOR, &rotated).await?;
                write_private(&directory.join("rotated"), b"rotated\n")?;
                rotated_once = true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if server.is_finished() {
            server.await??;
        } else {
            server.abort();
            let _ = server.await;
        }
        Ok(())
    }

    async fn prepare(
        store: &PackageStore,
        generations: &GenerationStore,
        release_key: &SigningKey,
        form: VmForm,
        expires_at_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (scope, release) = publish_variant(store, release_key, form, expires_at_ms).await?;
        generations.prepare(scope, &release).await?;
        Ok(())
    }

    async fn publish_variant(
        store: &PackageStore,
        release_key: &SigningKey,
        form: VmForm,
        expires_at_ms: u64,
    ) -> Result<(ReleaseScope, SealedRelease), Box<dyn std::error::Error>> {
        let mut generation_id = [0; 16];
        let mut module_id = [0; 16];
        OsRng.try_fill_bytes(&mut generation_id)?;
        OsRng.try_fill_bytes(&mut module_id)?;
        let instructions = match form {
            VmForm::Stack => vec![
                Instruction::Argument(0),
                Instruction::JumpIfZero(4),
                Instruction::Argument(0),
                Instruction::Return,
                Instruction::Jump(4),
            ],
            VmForm::Register => vec![
                Instruction::Argument(0),
                Instruction::JumpIfZero(5),
                Instruction::Argument(0),
                Instruction::Jump(4),
                Instruction::Return,
                Instruction::Jump(5),
            ],
        };
        let code = Zeroizing::new(
            LabProgram {
                arguments: vec![ScalarType::I64],
                result: Some(ScalarType::I64),
                instructions,
            }
            .encode()?,
        );
        let descriptor = VmDescriptor {
            abi_version: ABI_VERSION,
            app_id: APP,
            build_id: BUILD,
            function_id: FUNCTION,
            generation_id,
            form,
            depth: 2,
            capabilities: vec![],
            program_sha256: Sha256::digest(&code[..]).into(),
            budgets: Budgets {
                fuel: 10_000_000,
                memory_bytes: 65536,
                deadline_ms: 5000,
                active_contexts: 1,
                call_depth: 1,
            },
            profile: Profile::Online,
            extensions: vec![],
        };
        let release = seal(
            VerifiedInput::verify_negotiated("r13-native-fixture", &descriptor, &code)?,
            Release {
                module_id,
                module_version: 1,
                not_before_ms: 1,
                expires_at_ms,
            },
            release_key,
        )?;
        let scope = ReleaseScope {
            build_id: BUILD,
            generation_id,
            function_id: FUNCTION,
            module_id,
            version: 1,
        };
        store.publish(ACTOR, scope, &release.package).await?;
        Ok((scope, release))
    }

    fn sec1(key: &SigningKey) -> [u8; 65] {
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("P-256 SEC1")
    }

    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if lab::run().await.is_err() {
        eprintln!("R13 lab fixture could not complete");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("Run the R13 lab fixture server from the Unix PostgreSQL environment");
    std::process::exit(1);
}

#[cfg(all(test, unix))]
mod tests {
    mod r17 {
        include!("r13_online/observation_tests.rs");
    }
    use std::{
        net::SocketAddr,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::{atomic::AtomicBool, Arc},
        time::{Duration, Instant},
    };

    use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
    use rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    };
    use sha2::{Digest as _, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tokio_rustls::TlsConnector;
    use vmkek_client::{
        GenerationCapabilities, GenerationSelection, SessionClient, SessionIdentity, TlsEndpoint,
    };
    use vmkek_protocol::{
        ExecutionControl, GenerationOffer, ModuleExpectation, ModulePurpose, PackageFrame,
        Permission, PermissionKind, Profile, Scalar, SessionGrant, SessionGrantExpectation,
        SignedGenerationChoice, SignedModuleManifest, SignedTrustBundle, VerifiedProgram,
        VmDescriptor, VmForm, ABI_VERSION, SCHEMA_VERSION,
    };
    use zeroize::Zeroizing;

    struct Config {
        address: SocketAddr,
        cert: CertificateDer<'static>,
        identity: SessionIdentity,
        device: SigningKey,
        grant: VerifyingKey,
        publisher: VerifyingKey,
        supported: GenerationCapabilities,
    }

    fn config(bytes: &[u8]) -> Config {
        let mut input = bytes;
        fn fixed<const N: usize>(input: &mut &[u8]) -> [u8; N] {
            let (next, rest) = input.split_at(N);
            *input = rest;
            next.try_into().unwrap()
        }
        fn field<'a>(input: &mut &'a [u8]) -> &'a [u8] {
            let size = u32::from_le_bytes(fixed(input)) as usize;
            let (next, rest) = input.split_at(size);
            *input = rest;
            next
        }
        assert_eq!(fixed::<8>(&mut input), *b"VMKR13\0\0");
        let app_id = fixed(&mut input);
        let build_id = fixed(&mut input);
        let device_id = fixed(&mut input);
        let generation_id = fixed(&mut input);
        let license_id = fixed(&mut input);
        let policy_epoch = u64::from_le_bytes(fixed(&mut input));
        let function = fixed(&mut input);
        let grant = VerifyingKey::from_sec1_bytes(&fixed::<65>(&mut input)).unwrap();
        let root = VerifyingKey::from_sec1_bytes(&fixed::<65>(&mut input)).unwrap();
        let minimum_epoch = u64::from_le_bytes(fixed(&mut input));
        let forms = fixed::<1>(&mut input)[0];
        let capabilities = u16::from_le_bytes(fixed(&mut input));
        assert_eq!(fixed::<1>(&mut input), [0]);
        let secret = Zeroizing::new(fixed::<32>(&mut input));
        let device = SigningKey::from_slice(&secret[..]).unwrap();
        let address = std::str::from_utf8(field(&mut input))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(field(&mut input), b"localhost");
        let cert = CertificateDer::from(field(&mut input).to_vec());
        let signed = SignedTrustBundle::decode(field(&mut input)).unwrap();
        assert!(input.is_empty());
        let publisher = signed
            .verify_for(&root, app_id, minimum_epoch)
            .unwrap()
            .active_key()
            .unwrap();
        Config {
            address,
            cert,
            device,
            grant,
            publisher,
            supported: GenerationCapabilities {
                forms,
                capabilities,
            },
            identity: SessionIdentity {
                app_id,
                build_id,
                device_id,
                generation_id,
                license_id,
                policy_epoch,
                permission: Permission {
                    kind: PermissionKind::Function,
                    id: function,
                },
            },
        }
    }

    fn proof(key: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
        let signature: Signature = key.sign_prehash(digest).unwrap();
        signature.to_bytes().into()
    }

    async fn post(config: &Config, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut roots = RootCertStore::empty();
        roots.add(config.cert.clone()).unwrap();
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));
        tokio::time::timeout(Duration::from_secs(5), async {
            let socket = TcpStream::connect(config.address).await.unwrap();
            let mut stream = connector.connect(ServerName::try_from("localhost").unwrap(), socket).await.unwrap();
            let header = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut response = Vec::new();
            stream.take(4096).read_to_end(&mut response).await.unwrap();
            let split = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
            let status = std::str::from_utf8(&response[..split]).unwrap().split_ascii_whitespace()
                .nth(1).unwrap().parse().unwrap();
            (status, response.split_off(split+4))
        }).await.unwrap()
    }

    async fn exercise(
        config: &Config,
        client: &mut SessionClient<SigningKey>,
        selection: GenerationSelection,
    ) -> [u8; 32] {
        let issued = client.current_grant().unwrap().issued_at_ms;
        let opened = client.open_module(selection.module).await.unwrap();
        let frame = PackageFrame::decode(opened.frame_bytes()).unwrap();
        assert_eq!(
            Sha256::digest(frame.descriptor).as_slice(),
            selection.descriptor_sha256
        );
        let mut descriptor = VmDescriptor::decode(frame.descriptor).unwrap();
        assert_eq!(descriptor.generation_id, selection.generation_id);
        assert_eq!(descriptor.form, selection.form);
        let signed = SignedModuleManifest::decode(frame.manifest).unwrap();
        let manifest = signed
            .verify_for(
                &config.publisher,
                &ModuleExpectation {
                    descriptor: &descriptor,
                    module_id: selection.module.module_id,
                    module_version: selection.module.module_version,
                    purpose: ModulePurpose::Bytecode,
                    now_ms: issued,
                },
                frame.ciphertext,
            )
            .unwrap();
        let mut plaintext = Zeroizing::new(frame.ciphertext.to_vec());
        let cipher = ChaCha20Poly1305::new(opened.key().into());
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&manifest.nonce),
                &manifest.authentication_data().unwrap(),
                &mut plaintext,
                Tag::from_slice(&manifest.tag),
            )
            .unwrap();
        descriptor.profile = Profile::Lab;
        let program = VerifiedProgram::verify(&descriptor, &plaintext).unwrap();
        let cancelled = AtomicBool::new(false);
        let result = program
            .execute(
                &[Scalar::I64(-73)],
                b"",
                0,
                &ExecutionControl {
                    cancelled: &cancelled,
                    deadline: Instant::now() + Duration::from_secs(5),
                },
            )
            .unwrap();
        assert_eq!(result.value, Some(Scalar::I64(-73)));
        descriptor.program_sha256
    }

    async fn wait_for(directory: &std::path::Path, name: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !directory.join(name).exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a fresh isolated vmkek_r13_* PostgreSQL database and private fixture path"]
    async fn live_negotiation_binds_variants_replay_and_current_packages() {
        let directory = PathBuf::from(std::env::var("VMKEK_R13_FIXTURE_DIR").unwrap());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = PathBuf::from(std::env::var("VMKEK_R13_PG_SOCKET").unwrap());
        let database = std::env::var("VMKEK_R13_PG_DATABASE").unwrap();
        assert!(database.starts_with("vmkek_r13_"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                sqlx::postgres::PgConnectOptions::new()
                    .socket(&socket)
                    .port(55439)
                    .username("r09")
                    .database(&database),
            )
            .await
            .unwrap();
        let task = {
            let directory = directory.clone();
            tokio::spawn(async move {
                super::lab::serve_fixture(directory, socket, database, true)
                    .await
                    .unwrap();
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !directory.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let bytes = Zeroizing::new(std::fs::read(directory.join("config.bin")).unwrap());
        let config = config(&bytes);
        drop(bytes);
        let endpoint =
            TlsEndpoint::new(config.address, "localhost", [config.cert.clone()]).unwrap();
        let mut client = SessionClient::new(
            endpoint,
            config.identity,
            config.device.clone(),
            config.grant,
        );
        assert!(client.open().await.is_err());
        sqlx::raw_sql(
            "CREATE FUNCTION r13_delay_selected_commit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 IF NEW.consumed AND NEW.request_id=decode(repeat('50',16),'hex') THEN
                     PERFORM pg_sleep(3.1);
                 END IF;
                 RETURN NULL;
             END $$;
             CREATE CONSTRAINT TRIGGER r13_delay_selected_commit
             AFTER UPDATE ON generation_selections DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW EXECUTE FUNCTION r13_delay_selected_commit()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let late_offer = GenerationOffer {
            app_id: config.identity.app_id,
            build_id: config.identity.build_id,
            device_id: config.identity.device_id,
            function_id: config.identity.permission.id,
            request_id: [80; 16],
            descriptor_schema: SCHEMA_VERSION,
            descriptor_abi: ABI_VERSION,
            forms: config.supported.forms,
            capabilities: config.supported.capabilities,
        };
        let mut message = late_offer.encode().unwrap();
        message.extend(proof(
            &config.device,
            &late_offer.signature_digest().unwrap(),
        ));
        let (status, bytes) = post(&config, "/v1/generation/select", &message).await;
        assert_eq!(status, 200);
        let late_choice = SignedGenerationChoice::decode(&bytes).unwrap();
        let binding = late_choice.verify_for(&config.grant).unwrap().binding;
        let short: i64 = sqlx::query_scalar(
            "SELECT release_expires_ms FROM generation_catalog WHERE generation_id=$1",
        )
        .bind(binding.generation_id.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(short, i64::MAX);
        let mut completion = late_choice.as_bytes().to_vec();
        completion.extend(proof(&config.device, &late_choice.completion_digest()));
        let (status, body) = post(&config, "/v1/generation/complete", &completion).await;
        assert_eq!(status, 410);
        assert!(body.is_empty());
        let consumed: bool =
            sqlx::query_scalar("SELECT consumed FROM generation_selections WHERE session_id=$1")
                .bind(binding.session_id.as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(consumed);
        assert_eq!(
            post(&config, "/v1/generation/complete", &completion)
                .await
                .0,
            409
        );

        let first = client
            .negotiate_generation(config.supported)
            .await
            .unwrap()
            .unwrap();
        let first_session = client.current_grant().unwrap().binding.session_id;
        assert_eq!(first.form, VmForm::Stack);
        let first_hash = exercise(&config, &mut client, first).await;
        let second = client
            .negotiate_generation(config.supported)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.form, VmForm::Register);
        assert_ne!(
            first_session,
            client.current_grant().unwrap().binding.session_id
        );
        assert_ne!(first.generation_id, second.generation_id);
        assert_ne!(first_hash, exercise(&config, &mut client, second).await);
        std::fs::write(directory.join("revoke-release"), second.module.module_id).unwrap();
        wait_for(&directory, "release-revoked").await;
        assert_eq!(
            client.renew().await.unwrap_err(),
            vmkek_client::ClientError::Denied
        );
        assert!(client.current_grant().is_none());

        let offer = GenerationOffer {
            app_id: config.identity.app_id,
            build_id: config.identity.build_id,
            device_id: config.identity.device_id,
            function_id: config.identity.permission.id,
            request_id: [81; 16],
            descriptor_schema: SCHEMA_VERSION,
            descriptor_abi: ABI_VERSION,
            forms: config.supported.forms,
            capabilities: config.supported.capabilities,
        };
        let mut raw = offer.encode().unwrap();
        raw.extend(proof(&config.device, &offer.signature_digest().unwrap()));
        let mut altered = raw.clone();
        altered[16] ^= 1;
        assert_eq!(
            post(&config, "/v1/generation/select", &altered).await.0,
            403
        );
        let (status, reply) = post(&config, "/v1/generation/select", &raw).await;
        assert_eq!(status, 200);
        assert_eq!(post(&config, "/v1/generation/select", &raw).await.0, 409);
        let signed = SignedGenerationChoice::decode(&reply).unwrap();
        let choice = signed.verify_for(&config.grant).unwrap();
        assert_eq!(choice.offer_digest, offer.digest().unwrap());
        let mut complete = signed.as_bytes().to_vec();
        complete.extend(proof(&config.device, &signed.completion_digest()));
        let (one, two) = tokio::join!(
            post(&config, "/v1/generation/complete", &complete),
            post(&config, "/v1/generation/complete", &complete)
        );
        let grant = match (one, two) {
            ((200, grant), (409, _)) | ((409, _), (200, grant)) => {
                SessionGrant::decode(&grant).unwrap()
            }
            ((one, _), (two, _)) => panic!("unexpected completion {one}, {two}"),
        };
        assert!(grant
            .verify_session(
                &config.grant,
                &SessionGrantExpectation {
                    binding: choice.binding,
                    policy_epoch: config.identity.policy_epoch,
                    sequence: 1,
                    permission: config.identity.permission,
                    challenge_digest: signed.digest(),
                }
            )
            .is_ok());
        let fourth = client
            .negotiate_generation(config.supported)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fourth.form, VmForm::Register);
        assert!(client
            .negotiate_generation(config.supported)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            client.renew().await.unwrap().binding.generation_id,
            fourth.generation_id
        );
        std::fs::write(directory.join("refill"), b"refill").unwrap();
        wait_for(&directory, "refilled").await;
        let (ready, historical): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE NOT allocated), count(*) FILTER (WHERE allocated)
             FROM generation_catalog",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ready, 64);
        assert_eq!(historical, 5);
        let allocated = client
            .negotiate_generation(config.supported)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(allocated.form, VmForm::Stack);
        std::fs::write(directory.join("retry"), b"retry").unwrap();
        wait_for(&directory, "retried").await;
        let registered = client
            .negotiate_generation(GenerationCapabilities {
                forms: GenerationCapabilities::REGISTER,
                capabilities: 0,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registered.form, VmForm::Register);
        exercise(&config, &mut client, registered).await;

        let active = *client.current_grant().map(|grant| &grant.binding).unwrap();
        let sequence = client.current_grant().unwrap().sequence + 1;
        let intent = vmkek_protocol::SessionIntent {
            operation: vmkek_protocol::SessionOperation::Renew,
            app_id: active.app_id,
            build_id: active.build_id,
            device_id: active.device_id,
            generation_id: active.generation_id,
            session_id: active.session_id,
            sequence,
            request_id: [82; 16],
        };
        let mut message = intent.encode().unwrap();
        message.extend(proof(&config.device, &intent.signature_digest().unwrap()));
        let (status, bytes) = post(&config, "/v1/session/challenge", &message).await;
        assert_eq!(status, 200);
        let challenge = vmkek_protocol::SessionChallenge::decode(&bytes).unwrap();
        let mut completion = challenge.encode().unwrap();
        completion.extend(proof(
            &config.device,
            &challenge.signature_digest().unwrap(),
        ));
        std::fs::write(directory.join("rotate"), b"rotate").unwrap();
        wait_for(&directory, "rotated").await;
        assert_eq!(post(&config, "/v1/session/renew", &completion).await.0, 403);
        assert!(client.open_module(first.module).await.is_err());
        assert!(client.current_grant().is_none());
        std::fs::write(directory.join("stop"), b"stop").unwrap();
        task.await.unwrap();
    }
}
