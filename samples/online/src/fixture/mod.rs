use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use rand::{rngs::OsRng, RngCore};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest as _, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use tokio::net::TcpListener;
use vmkek_packager::{seal, Release, VerifiedInput};
use vmkek_protocol::{
    access_command::{AccessAction, AccessCommand, AccessReason, AccessRole, SignedAccessCommand},
    lab::{Instruction, LabProgram, ScalarType},
    public_key_id, Budgets, Capability, DeviceTrust, Id, Profile, SignedTrustBundle, TrustBundle,
    VmDescriptor, VmForm, ABI_VERSION, COPY_INPUT_CAPABILITY, GENERATION_COPY_INPUT,
    GENERATION_REGISTER, GENERATION_STACK, MAX_DEADLINE_MS,
};
use vmkek_server::{
    access::{AccessAdmin, AdminPin},
    generation::GenerationStore,
    operations::{OperationStore, SampleOperationPolicy},
    packages::{ModuleKeyStore, PackageStore, ReleaseScope},
    session::{
        serve_hybrid_generations_tls, session_tls_acceptor, NegotiatedSessionPolicy, SessionStore,
        SessionTlsAcceptor,
    },
    IdentityStore,
};
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const APP: Id = [0x18; 16];
const WINDOWS_BUILD: Id = [0x21; 16];
const LINUX_BUILD: Id = [0x22; 16];
const FUNCTION: Id = [0x32; 16];
const ACTOR: Id = [0x43; 16];
const EPOCH: u64 = 1;
const INPUT: &[u8] = b"R18 synthetic buffer\x00\x7f\xff";

pub async fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().ok_or("private fixture directory required")?);
    let socket = PathBuf::from(args.next().ok_or("PostgreSQL socket directory required")?);
    let database = args
        .next()
        .ok_or("fresh test database required")?
        .into_string()
        .map_err(|_| "invalid database name")?;
    let (linux, swap_once) = match args.next().as_deref() {
        None => (false, false),
        Some(value) if value == "--linux" => (true, false),
        Some(value) if value == "--linux-swap" => (true, true),
        _ => return Err("unsupported fixture option".into()),
    };
    let prefix = if linux { "vmkek_r21_" } else { "vmkek_r18_" };
    if args.next().is_some()
        || !directory.is_absolute()
        || !socket.is_absolute()
        || !database.starts_with(prefix)
    {
        return Err("expected absolute paths and a dedicated fixture database".into());
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("fixture directory must be an owner-only real directory".into());
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
    serve(directory, pool, linux, swap_once).await
}

async fn serve(directory: PathBuf, pool: PgPool, linux: bool, swap_once: bool) -> Result<()> {
    let build = if linux { LINUX_BUILD } else { WINDOWS_BUILD };
    let grant = SigningKey::random(&mut OsRng);
    let root = SigningKey::random(&mut OsRng);
    let release = SigningKey::random(&mut OsRng);
    let receipt = SigningKey::random(&mut OsRng);
    let admin_key = SigningKey::random(&mut OsRng);
    let device_key = SigningKey::random(&mut OsRng);
    let foreign_key = SigningKey::random(&mut OsRng);
    let session = SessionStore::start_negotiated(
        pool.clone(),
        NegotiatedSessionPolicy {
            app_id: APP,
            build_id: build,
            policy_epoch: EPOCH,
            function_id: FUNCTION,
        },
        grant.clone(),
    )
    .await?;
    let identity = IdentityStore::new(pool.clone());
    let (license, device) = enroll(&identity, &device_key).await?;
    enroll(&identity, &foreign_key).await?;

    let packages = PackageStore::new(session.clone(), *root.verifying_key(), EPOCH)?;
    let trust = SignedTrustBundle::sign(
        TrustBundle {
            app_id: APP,
            epoch: EPOCH,
            active: sec1(&release),
            next: None,
            revoked: vec![],
            root_key_id: public_key_id(root.verifying_key()),
            extensions: vec![],
        },
        &root,
    )?;
    packages.install_trust(ACTOR, &trust).await?;
    let operations = OperationStore::new(
        session,
        Some(packages.clone()),
        SampleOperationPolicy {
            app_id: APP,
            build_id: build,
            function_id: FUNCTION,
        },
        receipt.clone(),
    )?;
    operations.configure(ACTOR).await?;
    let generations = GenerationStore::new(ModuleKeyStore::new(packages.clone()));
    let until = database_time(&pool)
        .await?
        .checked_add(300_000)
        .ok_or("invalid release expiry")?;
    let mut catalog = String::new();
    for form in [
        VmForm::Stack,
        VmForm::Register,
        VmForm::Stack,
        VmForm::Register,
    ] {
        catalog.push_str(&publish(&packages, &generations, &release, build, form, until).await?);
    }

    let admin = AccessAdmin::new(
        pool.clone(),
        EPOCH,
        [AdminPin {
            app_id: APP,
            actor_id: ACTOR,
            role: AccessRole::Administrator,
            key: *admin_key.verifying_key(),
        }],
    )?;
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = cert.der().clone();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let socket = listener.local_addr()?;
    let address = socket.to_string();
    let tls = session_tls_acceptor(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )?;
    let endpoint = FixtureEndpoint {
        address: &address,
        certificate: certificate.as_ref(),
        trust: trust.as_bytes(),
        build,
        swap_once,
    };
    if linux {
        for (name, key, claimed_build) in [
            ("native", &device_key, build),
            ("foreign", &foreign_key, build),
            ("wrong-build", &device_key, WINDOWS_BUILD),
        ] {
            let endpoint = FixtureEndpoint {
                build: claimed_build,
                ..endpoint
            };
            let path = directory.join(name);
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            write_private(
                &path.join("config.bin"),
                &endpoint.config(license, device, None, &grant, &root)?,
            )?;
            let bytes = Zeroizing::new(key.to_bytes());
            write_private(&path.join("device.key"), &bytes)?;
        }
    } else {
        write_private(
            &directory.join("config.bin"),
            &endpoint.config(license, device, Some(&device_key), &grant, &root)?,
        )?;
        write_private(
            &directory.join("foreign.bin"),
            &endpoint.config(license, device, Some(&foreign_key), &grant, &root)?,
        )?;
    }
    write_private(&directory.join("receipt-pin.sec1"), &sec1(&receipt))?;
    write_private(&directory.join("input.bin"), INPUT)?;
    write_private(&directory.join("catalog.tsv"), catalog.as_bytes())?;

    let mut service = FixtureService {
        socket,
        acceptor: tls,
        generations,
        operations,
        task: None,
    };
    service.start(listener);
    write_private(&directory.join("ready"), b"ready\n")?;
    let result = controls(
        &directory,
        &pool,
        &admin,
        &admin_key,
        license,
        &mut service,
        linux,
    )
    .await;
    service.stop().await;
    result
}

struct FixtureService {
    socket: std::net::SocketAddr,
    acceptor: SessionTlsAcceptor,
    generations: GenerationStore,
    operations: OperationStore,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl FixtureService {
    fn start(&mut self, listener: TcpListener) {
        self.task = Some(tokio::spawn(serve_hybrid_generations_tls(
            listener,
            self.acceptor.clone(),
            self.generations.clone(),
            self.operations.clone(),
        )));
    }

    async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    async fn resume(&mut self) -> Result<()> {
        let listener = TcpListener::bind(self.socket).await?;
        self.start(listener);
        Ok(())
    }
}

async fn enroll(store: &IdentityStore, key: &SigningKey) -> Result<(Id, Id)> {
    let (license, activation) = store.provision_license(APP, None).await?;
    let challenge = store
        .challenge(APP, &activation, sec1(key), DeviceTrust::Software)
        .await?;
    let proof: Signature = key.sign_prehash(&challenge.signature_digest()?)?;
    let device = store
        .enroll(challenge.challenge_id, proof.to_bytes().into())
        .await?;
    Ok((license, device.id))
}

async fn publish(
    packages: &PackageStore,
    generations: &GenerationStore,
    signer: &SigningKey,
    build: Id,
    form: VmForm,
    expires: u64,
) -> Result<String> {
    let generation_id = fresh_id()?;
    let module_id = fresh_id()?;
    let instructions = match form {
        VmForm::Stack => vec![
            Instruction::CopyInput,
            Instruction::Argument(0),
            Instruction::Return,
        ],
        VmForm::Register => vec![
            Instruction::CopyInput,
            Instruction::Argument(0),
            Instruction::Jump(3),
            Instruction::Return,
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
        build_id: build,
        function_id: FUNCTION,
        generation_id,
        form,
        depth: 2,
        capabilities: vec![Capability {
            id: COPY_INPUT_CAPABILITY,
            required: true,
        }],
        program_sha256: Sha256::digest(code.as_slice()).into(),
        budgets: Budgets {
            fuel: 50_000,
            memory_bytes: 65_536,
            deadline_ms: 5000,
            active_contexts: 1,
            call_depth: 1,
        },
        profile: Profile::Online,
        extensions: vec![],
    };
    let sealed = seal(
        VerifiedInput::verify_negotiated("r18-copy", &descriptor, &code)?,
        Release {
            module_id,
            module_version: 1,
            not_before_ms: 1,
            expires_at_ms: expires,
        },
        signer,
    )?;
    let scope = ReleaseScope {
        build_id: build,
        generation_id,
        function_id: FUNCTION,
        module_id,
        version: 1,
    };
    packages.publish(ACTOR, scope, &sealed.package).await?;
    generations.prepare(scope, &sealed).await?;
    Ok(format!(
        "{}\t{form:?}\t{}\t{}\n",
        hex::encode(generation_id),
        hex::encode(descriptor.sha256()?),
        hex::encode(descriptor.program_sha256)
    ))
}

struct FixtureEndpoint<'a> {
    address: &'a str,
    certificate: &'a [u8],
    trust: &'a [u8],
    build: Id,
    swap_once: bool,
}

impl FixtureEndpoint<'_> {
    fn config(
        &self,
        license: Id,
        device: Id,
        device_key: Option<&SigningKey>,
        grant: &SigningKey,
        root: &SigningKey,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let fields = [
            self.address.as_bytes(),
            b"localhost",
            self.certificate,
            self.trust,
        ];
        let capacity = 254
            + 32 * usize::from(device_key.is_some())
            + fields.iter().map(|field| 4 + field.len()).sum::<usize>();
        let mut config = Zeroizing::new(Vec::with_capacity(capacity));
        config.extend(if device_key.is_some() {
            b"VMKR13\0\0"
        } else {
            b"VMKR21\0\0"
        });
        for id in [APP, self.build, device, [0; 16], license] {
            config.extend(id);
        }
        config.extend(EPOCH.to_le_bytes());
        config.extend(FUNCTION);
        config.extend(sec1(grant));
        config.extend(sec1(root));
        config.extend(EPOCH.to_le_bytes());
        config.push(GENERATION_STACK | GENERATION_REGISTER);
        config.extend(GENERATION_COPY_INPUT.to_le_bytes());
        config.push(u8::from(self.swap_once));
        if let Some(device_key) = device_key {
            let mut secret = device_key.to_bytes();
            config.extend_from_slice(&secret);
            secret.zeroize();
        }
        for field in fields {
            config.extend(u32::try_from(field.len())?.to_le_bytes());
            config.extend_from_slice(field);
        }
        if config.len() != capacity {
            return Err("invalid fixture configuration extent".into());
        }
        Ok(config)
    }
}

async fn controls(
    directory: &Path,
    pool: &PgPool,
    admin: &AccessAdmin,
    signer: &SigningKey,
    license: Id,
    service: &mut FixtureService,
    linux: bool,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let mut revoked = None;
    let mut restored = false;
    let mut pause_done = false;
    let mut resume_done = false;
    while tokio::time::Instant::now() < deadline && !directory.join("stop").exists() {
        if service
            .task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            return Err("TLS fixture stopped unexpectedly".into());
        }
        if linux && !pause_done && directory.join("pause").is_file() {
            service.stop().await;
            write_private(&directory.join("paused"), b"paused\n")?;
            pause_done = true;
        }
        if linux && pause_done && !resume_done && directory.join("resume").is_file() {
            service.resume().await?;
            write_private(&directory.join("resumed"), b"resumed\n")?;
            resume_done = true;
        }
        if revoked.is_none() && directory.join("revoke").is_file() {
            revoked = Some(apply(pool, admin, signer, license, None).await?);
            write_private(&directory.join("revoked"), b"revoked\n")?;
        }
        if let Some(prior) = revoked.filter(|_| !restored && directory.join("restore").is_file()) {
            apply(pool, admin, signer, license, Some(prior)).await?;
            write_private(&directory.join("restored"), b"restored\n")?;
            restored = true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

async fn apply(
    pool: &PgPool,
    admin: &AccessAdmin,
    signer: &SigningKey,
    license: Id,
    prior: Option<u64>,
) -> Result<u64> {
    let now = database_time(pool).await?;
    let (action, reason) = match prior {
        Some(prior_decision_id) => (
            AccessAction::Restore { prior_decision_id },
            AccessReason::ReviewedRestore,
        ),
        None => (AccessAction::Revoke, AccessReason::Administrator),
    };
    let command = SignedAccessCommand::sign(
        AccessCommand {
            app_id: APP,
            actor_id: ACTOR,
            license_id: license,
            device_id: None,
            request_id: fresh_id()?,
            policy_version: EPOCH,
            issued_at_ms: now,
            expires_at_ms: now + u64::from(MAX_DEADLINE_MS),
            action,
            reason,
            key_id: public_key_id(signer.verifying_key()),
        },
        signer,
    )?;
    Ok(admin.apply(ACTOR, &command).await?.id)
}

async fn database_time(pool: &PgPool) -> Result<u64> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?;
    Ok(u64::try_from(now)?)
}

fn fresh_id() -> Result<Id> {
    let mut id = [0; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| "entropy unavailable")?;
    if id == [0; 16] {
        return Err("invalid random identifier".into());
    }
    Ok(id)
}

fn sec1(key: &SigningKey) -> [u8; 65] {
    let mut point = [0; 65];
    point.copy_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    point
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)?;
    Ok(())
}
