use super::*;
use vmkek_protocol::{
    session_observation::{
        ObservationAction, ObservationFinding, ObservationKind, ObservationRecord,
        SessionObservation, MAX_OBSERVATIONS,
    },
    DeviceTrust, GrantBinding, Id, ModuleFetch, ModuleOpen, SampleJob, SampleOperationRequest,
    SessionIntent, SessionOperation, SAMPLE_JOB_RECEIPT_OPERATION,
};
use vmkek_server::IdentityStore;

const REPORT: &str = "/v1/session/observation";
const CHALLENGE: &str = "/v1/session/challenge";
const FETCH: &str = "/v1/module/fetch";
const OPEN: &str = "/v1/module/open";
const GENERATION: &str = "/v1/generation/select";
const OPERATION: &str = "/v1/operation/sample-job-receipt";

fn client(
    config: &Config,
    identity: SessionIdentity,
    device: SigningKey,
) -> SessionClient<SigningKey> {
    let endpoint = TlsEndpoint::new(config.address, "localhost", [config.cert.clone()]).unwrap();
    SessionClient::new(endpoint, identity, device, config.grant)
}

fn report(binding: GrantBinding, function: Id, request: u8) -> SessionObservation {
    SessionObservation {
        app_id: binding.app_id,
        build_id: binding.build_id,
        device_id: binding.device_id,
        session_id: binding.session_id,
        generation_id: binding.generation_id,
        function_id: function,
        request_id: [request; 16],
        sequence: 1,
        detection_policy_epoch: 9,
        action: ObservationAction::ReportOnly,
        records: vec![ObservationRecord {
            kind: ObservationKind::CodeIntegrity,
            rule_id: 7,
            finding: ObservationFinding::SignedMismatch,
        }],
    }
}

fn report_bytes(report: &SessionObservation, key: &SigningKey) -> Vec<u8> {
    signed_bytes(
        report.encode().unwrap(),
        report.signature_digest().unwrap(),
        key,
    )
}

fn signed_bytes(mut bytes: Vec<u8>, digest: [u8; 32], key: &SigningKey) -> Vec<u8> {
    bytes.extend(proof(key, &digest));
    bytes
}

fn route_requests(
    report: &SessionObservation,
    config: &Config,
    selection: GenerationSelection,
) -> [(&'static str, Vec<u8>); 5] {
    let key = &config.device;
    let fetch = ModuleFetch {
        app_id: report.app_id,
        build_id: report.build_id,
        device_id: report.device_id,
        session_id: report.session_id,
        generation_id: report.generation_id,
        function_id: report.function_id,
        module_id: selection.module.module_id,
        module_version: selection.module.module_version,
        purpose: ModulePurpose::Bytecode,
        sequence: report.sequence,
        request_id: report.request_id,
    };
    let open = ModuleOpen {
        fetch,
        manifest_sha256: selection.module.manifest_sha256,
    };
    let challenge = SessionIntent {
        operation: SessionOperation::Renew,
        app_id: report.app_id,
        build_id: report.build_id,
        device_id: report.device_id,
        generation_id: report.generation_id,
        session_id: report.session_id,
        sequence: report.sequence + 1,
        request_id: report.request_id,
    };
    let offer = GenerationOffer {
        app_id: report.app_id,
        build_id: report.build_id,
        device_id: report.device_id,
        function_id: report.function_id,
        request_id: report.request_id,
        descriptor_schema: SCHEMA_VERSION,
        descriptor_abi: ABI_VERSION,
        forms: config.supported.forms,
        capabilities: config.supported.capabilities,
    };
    let operation = SampleOperationRequest {
        app_id: report.app_id,
        build_id: report.build_id,
        device_id: report.device_id,
        session_id: report.session_id,
        generation_id: report.generation_id,
        function_id: report.function_id,
        operation_id: SAMPLE_JOB_RECEIPT_OPERATION,
        request_id: report.request_id,
        sequence: report.sequence,
        job: SampleJob {
            job_id: [71; 16],
            units: 3,
        },
    };
    [
        (
            CHALLENGE,
            signed_bytes(
                challenge.encode().unwrap(),
                challenge.signature_digest().unwrap(),
                key,
            ),
        ),
        (
            FETCH,
            signed_bytes(
                fetch.encode().unwrap(),
                fetch.signature_digest().unwrap(),
                key,
            ),
        ),
        (
            OPEN,
            signed_bytes(
                open.encode().unwrap(),
                open.signature_digest().unwrap(),
                key,
            ),
        ),
        (
            GENERATION,
            signed_bytes(
                offer.encode().unwrap(),
                offer.signature_digest().unwrap(),
                key,
            ),
        ),
        (
            OPERATION,
            signed_bytes(
                operation.encode().unwrap(),
                operation.signature_digest().unwrap(),
                key,
            ),
        ),
    ]
}

async fn foreign_session(config: &Config, pool: &sqlx::PgPool) -> (SigningKey, GrantBinding) {
    let identity = IdentityStore::new(pool.clone());
    let (license_id, token) = identity
        .provision_license(config.identity.app_id, None)
        .await
        .unwrap();
    let key = SigningKey::from_slice(&[19; 32]).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let challenge = identity
        .challenge(
            config.identity.app_id,
            &token,
            public.as_bytes().try_into().unwrap(),
            DeviceTrust::Software,
        )
        .await
        .unwrap();
    let device = identity
        .enroll(
            challenge.challenge_id,
            proof(&key, &challenge.signature_digest().unwrap()),
        )
        .await
        .unwrap()
        .id;
    let mut foreign = client(
        config,
        SessionIdentity {
            license_id,
            device_id: device,
            ..config.identity
        },
        key.clone(),
    );
    foreign
        .negotiate_generation(config.supported)
        .await
        .unwrap()
        .unwrap();
    (key, foreign.current_grant().unwrap().binding)
}

#[tokio::test]
#[ignore = "requires a fresh isolated vmkek_r17_* PostgreSQL database and private fixture path"]
async fn live_untrusted_report_and_exact_own_stop() {
    let directory = PathBuf::from(std::env::var("VMKEK_R17_FIXTURE_DIR").unwrap());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = PathBuf::from(std::env::var("VMKEK_R17_PG_SOCKET").unwrap());
    let database = std::env::var("VMKEK_R17_OBSERVATION_PG_DATABASE").unwrap();
    assert!(database.starts_with("vmkek_r17_"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
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
            super::super::lab::serve_fixture(directory, socket, database, false)
                .await
                .unwrap();
        })
    };
    wait_for(&directory, "ready").await;
    let bytes = Zeroizing::new(std::fs::read(directory.join("config.bin")).unwrap());
    let config = config(&bytes);
    drop(bytes);
    let mut client = client(&config, config.identity, config.device.clone());
    let selection = client
        .negotiate_generation(config.supported)
        .await
        .unwrap()
        .unwrap();
    exercise(&config, &mut client, selection).await;
    let binding = client.current_grant().unwrap().binding;
    let function = config.identity.permission.id;
    let first = report(binding, function, 80);

    assert_scope_rejection(&config, &pool, &first).await;
    assert_replay(&config, &first, selection).await;
    assert_quota(&config, &first).await;
    let row = sqlx::query_as::<_, (String, String, bool)>(
        "SELECT l.state,d.state,s.stopped FROM sessions s
         JOIN devices d ON d.id=s.device_id JOIN licenses l ON l.id=s.license_id WHERE s.id=$1",
    )
    .bind(binding.session_id.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("active".into(), "active".into(), false));

    assert_stop_and_restore(&config, &directory, &pool, &first, selection).await;
    std::fs::write(directory.join("stop"), b"").unwrap();
    task.await.unwrap();
}

async fn assert_scope_rejection(config: &Config, pool: &sqlx::PgPool, first: &SessionObservation) {
    let (foreign_key, foreign) = foreign_session(config, pool).await;
    assert_eq!(
        post(config, REPORT, &report_bytes(first, &foreign_key)).await,
        (403, Vec::new())
    );
    let mut foreign_request = report(foreign, first.function_id, 81);
    foreign_request.session_id = first.session_id;
    foreign_request.action = ObservationAction::RequestOwnStop;
    assert_eq!(
        post(
            config,
            REPORT,
            &report_bytes(&foreign_request, &foreign_key)
        )
        .await,
        (403, Vec::new())
    );
    let mut wrong_generation = first.clone();
    wrong_generation.generation_id = [16; 16];
    assert_eq!(
        post(
            config,
            REPORT,
            &report_bytes(&wrong_generation, &config.device)
        )
        .await,
        (403, Vec::new())
    );
    assert_eq!(post(config, REPORT, &[0; 233]).await, (400, Vec::new()));
}

async fn assert_replay(
    config: &Config,
    first: &SessionObservation,
    selection: GenerationSelection,
) {
    let body = report_bytes(first, &config.device);
    assert_eq!(post(config, REPORT, &body).await, (200, Vec::new()));
    assert_eq!(post(config, REPORT, &body).await, (409, Vec::new()));
    let mut changed = first.clone();
    changed.detection_policy_epoch += 1;
    assert_eq!(
        post(config, REPORT, &report_bytes(&changed, &config.device)).await,
        (409, Vec::new())
    );
    for (route, body) in route_requests(first, config, selection) {
        assert_eq!(
            post(config, route, &body).await,
            (409, Vec::new()),
            "{route}"
        );
    }

    let mut prior_operation = first.clone();
    prior_operation.request_id = [82; 16];
    let (_, body) = route_requests(&prior_operation, config, selection)
        .into_iter()
        .last()
        .unwrap();
    let (status, receipt) = post(config, OPERATION, &body).await;
    assert_eq!(status, 200);
    assert!(!receipt.is_empty());
    assert_eq!(
        post(
            config,
            REPORT,
            &report_bytes(&prior_operation, &config.device)
        )
        .await,
        (409, Vec::new())
    );
}

async fn assert_quota(config: &Config, first: &SessionObservation) {
    let mut report = first.clone();
    report.records = (1..=MAX_OBSERVATIONS as u16)
        .map(|rule_id| ObservationRecord {
            kind: ObservationKind::CodeIntegrity,
            rule_id,
            finding: ObservationFinding::Inconclusive,
        })
        .collect();
    for index in 1..MAX_OBSERVATIONS {
        report.request_id = [90 + index as u8; 16];
        assert_eq!(
            post(config, REPORT, &report_bytes(&report, &config.device)).await,
            (200, Vec::new())
        );
    }
    report.request_id = [100; 16];
    assert_eq!(
        post(config, REPORT, &report_bytes(&report, &config.device)).await,
        (429, Vec::new())
    );
}

async fn assert_stop_and_restore(
    config: &Config,
    directory: &std::path::Path,
    pool: &sqlx::PgPool,
    first: &SessionObservation,
    selection: GenerationSelection,
) {
    let mut stop = first.clone();
    stop.request_id = [101; 16];
    stop.action = ObservationAction::RequestOwnStop;
    let body = report_bytes(&stop, &config.device);
    assert_eq!(post(config, REPORT, &body).await, (200, Vec::new()));
    wait_for(directory, "observed-stop").await;
    assert_eq!(post(config, REPORT, &body).await, (409, Vec::new()));
    let mut stale = first.clone();
    stale.request_id = [102; 16];
    for (route, body) in route_requests(&stale, config, selection) {
        if route != GENERATION {
            assert_eq!(
                post(config, route, &body).await,
                (410, Vec::new()),
                "{route}"
            );
        }
    }
    let records: Vec<(i16, i32)> = sqlx::query_as(
        "SELECT action,octet_length(records) FROM session_observation_reports
         WHERE session_id=$1 ORDER BY action,request_id",
    )
    .bind(first.session_id.as_slice())
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(records.len(), MAX_OBSERVATIONS + 1);
    assert_eq!(records[0], (1, 4));
    assert_eq!(records[1], (1, 32));
    assert_eq!(records[MAX_OBSERVATIONS], (2, 4));
    let decisions: i64 = sqlx::query_scalar("SELECT count(*) FROM access_decisions")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(decisions, 0);

    let mut new = client(config, config.identity, config.device.clone());
    let selection = new
        .negotiate_generation(config.supported)
        .await
        .unwrap()
        .unwrap();
    let new_binding = new.current_grant().unwrap().binding;
    let new_session = new_binding.session_id;
    assert_ne!(new_session, first.session_id);
    let racing = report(new_binding, first.function_id, 103);
    assert_racing_revocation(config, directory, pool, &racing, selection).await;
    assert!(new.negotiate_generation(config.supported).await.is_err());
    std::fs::write(directory.join("restore"), b"").unwrap();
    wait_for(directory, "restored").await;
    let fresh = new
        .negotiate_generation(config.supported)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(new.current_grant().unwrap().binding.session_id, new_session);
    exercise(config, &mut new, fresh).await;
}

async fn assert_racing_revocation(
    config: &Config,
    directory: &std::path::Path,
    pool: &sqlx::PgPool,
    current: &SessionObservation,
    selection: GenerationSelection,
) {
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM licenses WHERE id=$1 FOR UPDATE")
        .bind(config.identity.license_id.as_slice())
        .execute(&mut *lock)
        .await
        .unwrap();
    std::fs::write(directory.join("revoke"), b"").unwrap();
    wait_for_license_lock(pool, "SELECT state FROM licenses%", 1).await;

    let [(challenge, challenge_bytes), (fetch, fetch_bytes), (open, open_bytes), _, (op, op_bytes)] =
        route_requests(current, config, selection);
    let contenders = async {
        tokio::join!(
            post(config, challenge, &challenge_bytes),
            post(config, fetch, &fetch_bytes),
            post(config, open, &open_bytes),
            post(config, op, &op_bytes),
        )
    };
    tokio::pin!(contenders);
    tokio::select! {
        _ = &mut contenders => panic!("protected requests completed while license lock was held"),
        _ = wait_for_license_lock(pool, "SELECT l.id FROM devices%", 4) => {}
    }
    lock.commit().await.unwrap();
    let (renew, fetch, open, operation) = contenders.await;
    for reply in [renew, fetch, open, operation] {
        assert_eq!(reply, (403, Vec::new()));
    }
    wait_for(directory, "revoked").await;
}

async fn wait_for_license_lock(pool: &sqlx::PgPool, prefix: &str, expected: i64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
                   AND wait_event_type='Lock' AND query LIKE $1",
            )
            .bind(prefix)
            .fetch_one(pool)
            .await
            .unwrap();
            if blocked >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
