use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use sqlx::{
    migrate::Migrate,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use vmkek_packager::{seal, Release, VerifiedInput};
use vmkek_protocol::{
    access_command::{AccessAction, AccessCommand, AccessReason, AccessRole, SignedAccessCommand},
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, DeviceTrust, GenerationOffer, GrantBinding, Id, Profile,
    SignedGenerationChoice, SignedTrustBundle, TrustBundle, VmDescriptor, VmForm, ABI_VERSION,
    GENERATION_STACK, SCHEMA_VERSION,
};

use super::{AccessAdmin, AdminPin};
use crate::{
    generation::GenerationStore,
    packages::{ModuleKeyStore, PackageError, PackageStore, ReleaseScope},
    session::{NegotiatedSessionPolicy, SessionError, SessionStore},
    ActivationToken, IdentityStore,
};

const APP: Id = [1; 16];
const BUILD: Id = [2; 16];
const FUNCTION: Id = [3; 16];
const ADMIN: Id = [4; 16];

async fn database(var: &str) -> PgPool {
    let socket = std::env::var("VMKEK_R17_PG_SOCKET").expect("isolated R17 PostgreSQL socket");
    let database = std::env::var(var).expect("dedicated R17 test database");
    assert!(database.starts_with("vmkek_r17_"));
    PgPoolOptions::new()
        .max_connections(6)
        .connect_with(
            PgConnectOptions::new()
                .socket(socket)
                .port(55439)
                .username("r09")
                .database(&database),
        )
        .await
        .unwrap()
}

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

fn proof(key: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
    let signature: Signature = key.sign_prehash(digest).unwrap();
    signature.to_bytes().into()
}

async fn enroll(identity: &IdentityStore, token: &ActivationToken, key: &SigningKey) -> Id {
    let challenge = identity
        .challenge(APP, token, sec1(key), DeviceTrust::Software)
        .await
        .unwrap();
    identity
        .enroll(
            challenge.challenge_id,
            proof(key, &challenge.signature_digest().unwrap()),
        )
        .await
        .unwrap()
        .id
}

async fn seed_catalog(pool: &PgPool, grant_key: &SigningKey) -> GenerationStore {
    let root = key(12);
    let publisher = key(13);
    let session = SessionStore::start_negotiated(
        pool.clone(),
        NegotiatedSessionPolicy {
            app_id: APP,
            build_id: BUILD,
            function_id: FUNCTION,
            policy_epoch: 1,
        },
        grant_key.clone(),
    )
    .await
    .unwrap();
    let packages = PackageStore::new(session, *root.verifying_key(), 1).unwrap();
    let trust = SignedTrustBundle::sign(
        TrustBundle {
            app_id: APP,
            epoch: 1,
            active: sec1(&publisher),
            next: None,
            revoked: Vec::new(),
            root_key_id: public_key_id(root.verifying_key()),
            extensions: Vec::new(),
        },
        &root,
    )
    .unwrap();
    packages.install_trust(ADMIN, &trust).await.unwrap();
    let generations = GenerationStore::new(ModuleKeyStore::new(packages.clone()));
    for index in 0..3 {
        publish_generation(&packages, &generations, &publisher, index).await;
    }
    generations
}

async fn publish_generation(
    packages: &PackageStore,
    generations: &GenerationStore,
    publisher: &SigningKey,
    index: u8,
) {
    let code = LabProgram {
        arguments: Vec::new(),
        result: None,
        instructions: vec![Instruction::Return],
    }
    .encode()
    .unwrap();
    let scope = ReleaseScope {
        build_id: BUILD,
        generation_id: [21 + index; 16],
        function_id: FUNCTION,
        module_id: [31 + index; 16],
        version: 1,
    };
    let descriptor = VmDescriptor {
        abi_version: ABI_VERSION,
        app_id: APP,
        build_id: BUILD,
        function_id: FUNCTION,
        generation_id: scope.generation_id,
        form: VmForm::Stack,
        depth: 2,
        capabilities: Vec::new(),
        program_sha256: Sha256::digest(&code).into(),
        budgets: Budgets::default(),
        profile: Profile::Online,
        extensions: Vec::new(),
    };
    let release = seal(
        VerifiedInput::verify_negotiated("r17-generation-fixture", &descriptor, &code).unwrap(),
        Release {
            module_id: scope.module_id,
            module_version: 1,
            not_before_ms: 1,
            expires_at_ms: u64::MAX,
        },
        publisher,
    )
    .unwrap();
    packages
        .publish(ADMIN, scope, &release.package)
        .await
        .unwrap();
    generations.prepare(scope, &release).await.unwrap();
}

async fn select(
    generations: &GenerationStore,
    device: Id,
    signer: &SigningKey,
    request: u8,
) -> SignedGenerationChoice {
    let offer = GenerationOffer {
        app_id: APP,
        build_id: BUILD,
        device_id: device,
        function_id: FUNCTION,
        request_id: [request; 16],
        descriptor_schema: SCHEMA_VERSION,
        descriptor_abi: ABI_VERSION,
        forms: GENERATION_STACK,
        capabilities: 0,
    };
    generations
        .select(offer, proof(signer, &offer.signature_digest().unwrap()))
        .await
        .unwrap()
        .unwrap()
}

async fn decision(
    pool: &PgPool,
    admin: &AccessAdmin,
    signer: &SigningKey,
    license: Id,
    device: Option<Id>,
    request: u8,
    prior: Option<u64>,
) -> u64 {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    let (action, reason) = match prior {
        None => (AccessAction::Revoke, AccessReason::Administrator),
        Some(prior_decision_id) => (
            AccessAction::Restore { prior_decision_id },
            AccessReason::ReviewedRestore,
        ),
    };
    let command = AccessCommand {
        app_id: APP,
        actor_id: ADMIN,
        license_id: license,
        device_id: device,
        request_id: [request; 16],
        policy_version: 1,
        issued_at_ms: now as u64,
        expires_at_ms: now as u64 + 5_000,
        action,
        reason,
        key_id: public_key_id(signer.verifying_key()),
    };
    let signed = SignedAccessCommand::sign(command, signer).unwrap();
    admin.apply(ADMIN, &signed).await.unwrap().id
}

async fn choice_state(pool: &PgPool, binding: GrantBinding) -> (bool, bool) {
    sqlx::query_as(
        "SELECT s.consumed,c.allocated FROM generation_selections s
         JOIN generation_catalog c USING(generation_id) WHERE s.session_id=$1",
    )
    .bind(binding.session_id.as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn negotiated_choice_stays_consumed_after_restore() {
    let pool = database("VMKEK_R17_GENERATION_PG_DATABASE").await;
    let grant_key = key(11);
    let generations = seed_catalog(&pool, &grant_key).await;
    let identity = IdentityStore::new(pool.clone());
    let (license, token) = identity.provision_license(APP, Some(2)).await.unwrap();
    let main_key = key(14);
    let sibling_key = key(15);
    let main = enroll(&identity, &token, &main_key).await;
    let sibling = enroll(&identity, &token, &sibling_key).await;
    let signer = key(16);
    let admin = AccessAdmin::new(
        pool.clone(),
        1,
        [AdminPin {
            app_id: APP,
            actor_id: ADMIN,
            role: AccessRole::Administrator,
            key: *signer.verifying_key(),
        }],
    )
    .unwrap();

    let old = select(&generations, main, &main_key, 40).await;
    let sibling_choice = select(&generations, sibling, &sibling_key, 41).await;
    let old_binding = old.verify_for(grant_key.verifying_key()).unwrap().binding;
    let sibling_binding = sibling_choice
        .verify_for(grant_key.verifying_key())
        .unwrap()
        .binding;
    assert_eq!(choice_state(&pool, old_binding).await, (false, true));
    assert_eq!(choice_state(&pool, sibling_binding).await, (false, true));

    let revoked = decision(&pool, &admin, &signer, license, Some(main), 50, None).await;
    let old_proof = proof(&main_key, &old.completion_digest());
    assert!(matches!(
        generations.complete(old.clone(), old_proof).await,
        Err(PackageError::Session(SessionError::Denied))
    ));
    decision(
        &pool,
        &admin,
        &signer,
        license,
        Some(main),
        51,
        Some(revoked),
    )
    .await;
    assert_eq!(choice_state(&pool, old_binding).await, (true, true));
    assert_eq!(choice_state(&pool, sibling_binding).await, (false, true));
    assert!(matches!(
        generations.complete(old, old_proof).await,
        Err(PackageError::Conflict)
    ));

    let fresh = select(&generations, main, &main_key, 42).await;
    let fresh_binding = fresh.verify_for(grant_key.verifying_key()).unwrap().binding;
    assert_ne!(fresh_binding.session_id, old_binding.session_id);
    assert_ne!(fresh_binding.generation_id, old_binding.generation_id);
    let fresh_proof = proof(&main_key, &fresh.completion_digest());
    generations.complete(fresh, fresh_proof).await.unwrap();
    assert_eq!(choice_state(&pool, fresh_binding).await, (true, true));

    let revoked = decision(&pool, &admin, &signer, license, None, 52, None).await;
    decision(&pool, &admin, &signer, license, None, 53, Some(revoked)).await;
    assert_eq!(choice_state(&pool, sibling_binding).await, (true, true));
    let sibling_proof = proof(&sibling_key, &sibling_choice.completion_digest());
    assert!(matches!(
        generations.complete(sibling_choice, sibling_proof).await,
        Err(PackageError::Conflict)
    ));
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned isolated PostgreSQL database"]
async fn migration_consumes_legacy_choices_in_revoked_scope_only() {
    let pool = database("VMKEK_R17_UPGRADE_PG_DATABASE").await;
    let migrations = sqlx::migrate!("../../migrations");
    let mut connection = pool.acquire().await.unwrap();
    connection.ensure_migrations_table().await.unwrap();
    for migration in migrations.iter().filter(|migration| migration.version < 6) {
        connection.apply(migration).await.unwrap();
    }
    seed_legacy_choices(&mut connection).await;
    drop(connection);

    IdentityStore::new(pool.clone()).migrate().await.unwrap();
    let states: Vec<(bool, bool)> = sqlx::query_as(
        "SELECT s.consumed,c.allocated FROM generation_selections s
         JOIN generation_catalog c USING(generation_id) ORDER BY s.device_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(states, vec![(true, true), (true, true), (false, true)]);
}

async fn seed_legacy_choices(connection: &mut sqlx::PgConnection) {
    sqlx::raw_sql(
        "CREATE FUNCTION pg_temp.fixture_id(n integer, size integer) RETURNS bytea
         LANGUAGE sql IMMUTABLE AS 'SELECT set_byte(decode(repeat(''00'',size),''hex''),0,n)';
         INSERT INTO licenses (id,app_id,activation_digest,state)
         SELECT pg_temp.fixture_id(n,16),pg_temp.fixture_id(20,16),pg_temp.fixture_id(n,32),
                CASE WHEN n=1 THEN 'revoked' ELSE 'active' END FROM generate_series(1,3) n;
         INSERT INTO devices (id,license_id,key_id,public_key,trust,state)
         SELECT pg_temp.fixture_id(n+3,16),pg_temp.fixture_id(n,16),pg_temp.fixture_id(n,32),
                pg_temp.fixture_id(n,65),1,CASE WHEN n=2 THEN 'revoked' ELSE 'active' END
         FROM generate_series(1,3) n;
         INSERT INTO package_trust (app_id,epoch,wall_floor_ms,bundle)
         VALUES (pg_temp.fixture_id(20,16),1,0,pg_temp.fixture_id(0,1));
         INSERT INTO package_releases (app_id,module_id,version,frame)
         SELECT pg_temp.fixture_id(20,16),pg_temp.fixture_id(n+6,16),1,pg_temp.fixture_id(0,1)
         FROM generate_series(1,3) n;
         INSERT INTO generation_catalog (generation_id,app_id,build_id,function_id,module_id,module_version,
             descriptor_sha256,manifest_sha256,signing_key_id,release_expires_ms,form,capabilities,allocated)
         SELECT pg_temp.fixture_id(n+9,16),pg_temp.fixture_id(20,16),pg_temp.fixture_id(21,16),
                pg_temp.fixture_id(22,16),pg_temp.fixture_id(n+6,16),1,pg_temp.fixture_id(0,32),
                pg_temp.fixture_id(0,32),pg_temp.fixture_id(0,32),100,1,0,true FROM generate_series(1,3) n;
         INSERT INTO generation_offers (device_id,request_id,digest)
         SELECT pg_temp.fixture_id(n+3,16),pg_temp.fixture_id(n+12,16),pg_temp.fixture_id(0,32)
         FROM generate_series(1,3) n;
         INSERT INTO generation_selections (device_id,request_id,session_id,generation_id,
             challenge_id,choice,service_epoch,expires_tick_ms)
         SELECT pg_temp.fixture_id(n+3,16),pg_temp.fixture_id(n+12,16),pg_temp.fixture_id(n+15,16),
                pg_temp.fixture_id(n+9,16),pg_temp.fixture_id(n+18,16),pg_temp.fixture_id(0,461),1,100
         FROM generate_series(1,3) n;",
    ).execute(connection).await.unwrap();
}
