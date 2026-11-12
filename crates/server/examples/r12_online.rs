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
    use rand::rngs::OsRng;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use sha2::{Digest as _, Sha256};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tokio::net::TcpListener;
    use vmkek_packager::{seal, Release, VerifiedInput};
    use vmkek_protocol::{
        lab::{Instruction, LabProgram, ScalarType},
        public_key_id, Budgets, DeviceTrust, Id, Permission, PermissionKind, Profile,
        SignedTrustBundle, TrustBundle, VmDescriptor, VmForm, ABI_VERSION,
    };
    use vmkek_server::{
        packages::{serve_modules_tls, ModuleKeyStore, PackageStore, ReleaseScope},
        session::{session_tls_acceptor, SessionPolicy, SessionStore},
        IdentityStore, RevokeReason,
    };
    use zeroize::{Zeroize, Zeroizing};

    const APP: Id = [41; 16];
    const BUILD: Id = [42; 16];
    const GENERATION: Id = [43; 16];
    const FUNCTION: Id = [44; 16];
    const MODULE: Id = [45; 16];
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
        let active_contexts = match args.next().as_deref() {
            None => 1,
            Some(option) if option == "--two-contexts" => 2,
            _ => return Err("unsupported fixture option".into()),
        };
        if args.next().is_some() || !database.starts_with("vmkek_r12_") || !directory.is_absolute()
        {
            return Err(
                "expected an absolute lab directory and a dedicated vmkek_r12_* database".into(),
            );
        }
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
        let device = SigningKey::random(&mut OsRng);
        let permission = Permission {
            kind: PermissionKind::Function,
            id: FUNCTION,
        };
        let session = SessionStore::start(
            pool.clone(),
            SessionPolicy {
                app_id: APP,
                build_id: BUILD,
                generation_id: GENERATION,
                policy_epoch: EPOCH,
                permission,
            },
            grant_key.clone(),
        )
        .await?;
        let identity = IdentityStore::new(pool);
        let (license, activation) = identity.provision_license(APP, None).await?;
        let enrollment = identity
            .challenge(APP, &activation, sec1(&device), DeviceTrust::Software)
            .await?;
        let proof: Signature = device.sign_prehash(&enrollment.signature_digest()?)?;
        let enrolled = identity
            .enroll(enrollment.challenge_id, proof.to_bytes().into())
            .await?;
        let store = PackageStore::new(session, *root.verifying_key(), EPOCH)?;
        let trust = SignedTrustBundle::sign(
            TrustBundle {
                app_id: APP,
                epoch: EPOCH,
                active: sec1(&release_key),
                next: None,
                revoked: vec![],
                root_key_id: public_key_id(root.verifying_key()),
                extensions: vec![],
            },
            &root,
        )?;
        store.install_trust(ACTOR, &trust).await?;
        let wrong_signer = SigningKey::random(&mut OsRng);
        let bad_trust = SignedTrustBundle::sign(
            TrustBundle {
                app_id: APP,
                epoch: EPOCH,
                active: sec1(&wrong_signer),
                next: None,
                revoked: vec![],
                root_key_id: public_key_id(root.verifying_key()),
                extensions: vec![],
            },
            &root,
        )?;
        let code = Zeroizing::new(
            LabProgram {
                arguments: vec![ScalarType::I64],
                result: Some(ScalarType::I64),
                instructions: vec![
                    Instruction::Argument(0),
                    Instruction::JumpIfZero(4),
                    Instruction::Argument(0),
                    Instruction::Return,
                    Instruction::Jump(4),
                ],
            }
            .encode()?,
        );
        let descriptor = VmDescriptor {
            abi_version: ABI_VERSION,
            app_id: APP,
            build_id: BUILD,
            function_id: FUNCTION,
            generation_id: GENERATION,
            form: VmForm::Stack,
            depth: 2,
            capabilities: vec![],
            program_sha256: Sha256::digest(&code[..]).into(),
            budgets: Budgets {
                fuel: 10_000_000,
                memory_bytes: 65536,
                deadline_ms: 5000,
                active_contexts,
                call_depth: 1,
            },
            profile: Profile::Online,
            extensions: vec![],
        };
        let release = seal(
            VerifiedInput::verify("r12-native-fixture", &descriptor, &code)?,
            Release {
                module_id: MODULE,
                module_version: 1,
                not_before_ms: 1,
                expires_at_ms: u64::MAX,
            },
            &release_key,
        )?;
        let scope = ReleaseScope {
            build_id: BUILD,
            generation_id: GENERATION,
            function_id: FUNCTION,
            module_id: MODULE,
            version: 1,
        };
        let manifest = Sha256::digest(release.package.manifest_bytes());
        store.publish(ACTOR, scope, &release.package).await?;
        let keys = ModuleKeyStore::new(store);
        keys.provision(scope, release).await?;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()])?;
        let cert = cert.der().clone();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?.to_string();
        let tls = session_tls_acceptor(
            vec![cert.clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )?;
        let server = tokio::spawn(serve_modules_tls(listener, tls, keys));

        let capacity = 8
            + 5 * 16
            + 8
            + 16
            + 65
            + 65
            + 8
            + 16
            + 8
            + 32
            + 32
            + 4 * 4
            + address.len()
            + "localhost".len()
            + cert.len()
            + trust.as_bytes().len();
        let mut config = Zeroizing::new(Vec::with_capacity(capacity));
        config.extend(b"VMKR12\0\0");
        for id in [APP, BUILD, enrolled.id, GENERATION, license] {
            config.extend(id);
        }
        config.extend(EPOCH.to_le_bytes());
        config.extend(FUNCTION);
        config.extend(sec1(&grant_key));
        config.extend(sec1(&root));
        config.extend(EPOCH.to_le_bytes());
        config.extend(MODULE);
        config.extend(1u64.to_le_bytes());
        config.extend_from_slice(&manifest);
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
        let trust_offset = config.len() - trust.as_bytes().len();
        config[trust_offset..].copy_from_slice(bad_trust.as_bytes());
        write_private(&directory.join("bad-trust-config.bin"), &config)?;
        drop(config);
        write_private(&directory.join("ready"), b"ready\n")?;

        let mut revoked = false;
        let until = tokio::time::Instant::now() + Duration::from_secs(180);
        while tokio::time::Instant::now() < until
            && !directory.join("stop").exists()
            && !server.is_finished()
        {
            if !revoked && directory.join("revoke").exists() {
                identity
                    .revoke(license, None, ACTOR, RevokeReason::Administrator)
                    .await?;
                write_private(&directory.join("revoked"), b"revoked\n")?;
                revoked = true;
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
        eprintln!("R12 lab fixture could not complete");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("Run the R12 lab fixture server from the Unix PostgreSQL environment");
    std::process::exit(1);
}
