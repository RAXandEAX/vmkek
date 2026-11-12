use std::convert::Infallible;
use std::future::Future;
use std::sync::Mutex;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ServerConfig, SupportedProtocolVersion};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;

const DNS: &str = "session.test";

struct Server {
    address: SocketAddr,
    root: CertificateDer<'static>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn root() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn leaf(
    version: &'static SupportedProtocolVersion,
    issuer: &CertifiedIssuer<'_, KeyPair>,
    params: CertificateParams,
) -> (TlsAcceptor, CertificateDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap().der().clone();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (TlsAcceptor::from(Arc::new(config)), cert)
}

impl Server {
    async fn bind<F, Fut>(version: &'static SupportedProtocolVersion, service: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let issuer = root();
        let params = CertificateParams::new(vec![DNS.to_owned()]).unwrap();
        let (acceptor, _) = leaf(version, &issuer, params);
        Self::with_acceptor(
            issuer.der().clone(),
            Arc::new(Mutex::new(acceptor)),
            service,
        )
        .await
    }

    async fn with_acceptor<F, Fut>(
        root: CertificateDer<'static>,
        acceptor: Arc<Mutex<TlsAcceptor>>,
        service: F,
    ) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.lock().unwrap().clone();
                let service = service.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(service))
                            .await;
                    }
                });
            }
        });
        Self {
            address,
            root,
            task,
        }
    }

    fn endpoint(&self) -> TlsEndpoint {
        TlsEndpoint::new(self.address, DNS, [self.root.clone()]).unwrap()
    }
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, CONTENT)
        .body(Full::new(body))
        .unwrap()
}

async fn echo(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    assert_eq!(request.method(), hyper::Method::POST);
    assert_eq!(request.uri().path(), "/fixture");
    let body = request.into_body().collect().await.unwrap().to_bytes();
    Ok(response(StatusCode::OK, body))
}

#[tokio::test]
async fn tls13_authenticates_root_and_dns() {
    let server = Server::bind(&rustls::version::TLS13, echo).await;
    assert_eq!(
        server
            .endpoint()
            .post("/fixture", vec![1, 2])
            .await
            .unwrap(),
        &[1, 2][..]
    );
}

#[tokio::test]
async fn tls13_rejects_wrong_root() {
    let server = Server::bind(&rustls::version::TLS13, echo).await;
    let endpoint = TlsEndpoint::new(server.address, DNS, [root().der().clone()]).unwrap();
    assert_eq!(
        endpoint.post("/fixture", vec![]).await,
        Err(ClientError::Tls)
    );
}

#[tokio::test]
async fn tls13_rejects_wrong_dns() {
    let server = Server::bind(&rustls::version::TLS13, echo).await;
    let endpoint = TlsEndpoint::new(server.address, "wrong.test", [server.root.clone()]).unwrap();
    assert_eq!(
        endpoint.post("/fixture", vec![]).await,
        Err(ClientError::Tls)
    );
}

#[tokio::test]
async fn tls13_leaf_rotation_rejects_expiry_and_restores_authority() {
    let issuer = root();
    let mut valid = CertificateParams::new(vec![DNS.to_owned()]).unwrap();
    valid.not_before = date_time_ymd(2020, 1, 1);
    valid.not_after = date_time_ymd(2100, 1, 1);
    let mut expired = valid.clone();
    expired.not_before = date_time_ymd(2000, 1, 1);
    expired.not_after = date_time_ymd(2010, 1, 1);
    let (first, first_der) = leaf(&rustls::version::TLS13, &issuer, valid.clone());
    let (second, second_der) = leaf(&rustls::version::TLS13, &issuer, valid);
    let (expired, _) = leaf(&rustls::version::TLS13, &issuer, expired);
    assert_ne!(first_der, second_der);

    let peer = Peer::new();
    let service = {
        let peer = peer.clone();
        move |request| {
            let peer = peer.clone();
            async move { Ok(peer.respond(request).await) }
        }
    };
    let acceptor = Arc::new(Mutex::new(first));
    let server = Server::with_acceptor(issuer.der().clone(), acceptor.clone(), service).await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    assert_eq!(client.open().await.unwrap().sequence, 1);

    *acceptor.lock().unwrap() = expired;
    let requests = peer.requests.lock().unwrap().len();
    assert!(matches!(client.renew().await, Err(ClientError::Tls)));
    assert!(client.current_grant().is_none());
    assert_eq!(peer.requests.lock().unwrap().len(), requests);

    *acceptor.lock().unwrap() = second;
    assert_eq!(client.open().await.unwrap().sequence, 1);
    assert_eq!(client.renew().await.unwrap().sequence, 2);
}

#[tokio::test]
async fn receipt_response_limit_rejects_one_extra_byte_before_collection() {
    use vmkek_protocol::SAMPLE_OPERATION_RECEIPT_BYTES;

    let server = Server::bind(&rustls::version::TLS13, |_| async {
        Ok(response(
            StatusCode::OK,
            Bytes::from(vec![0; SAMPLE_OPERATION_RECEIPT_BYTES + 1]),
        ))
    })
    .await;
    assert_eq!(
        server
            .endpoint()
            .post_bounded(
                "/v1/operation/sample-job-receipt",
                vec![],
                SAMPLE_OPERATION_RECEIPT_BYTES
            )
            .await,
        Err(ClientError::BodyLimit),
    );
}

#[tokio::test]
async fn tls12_only_peer_is_rejected() {
    let server = Server::bind(&rustls::version::TLS12, echo).await;
    assert_eq!(
        server.endpoint().post("/fixture", vec![]).await,
        Err(ClientError::Tls)
    );
}

#[tokio::test]
async fn bounds_both_request_and_response() {
    let server = Server::bind(&rustls::version::TLS13, |_| async {
        Ok(response(
            StatusCode::OK,
            Bytes::from(vec![0; MAX_BODY_BYTES + 1]),
        ))
    })
    .await;
    let endpoint = server.endpoint();
    assert_eq!(
        endpoint.post("/fixture", vec![0; MAX_BODY_BYTES + 1]).await,
        Err(ClientError::BodyLimit)
    );
    assert_eq!(
        endpoint.post("/fixture", vec![]).await,
        Err(ClientError::BodyLimit)
    );
}

use std::sync::atomic::{AtomicU8, Ordering};

use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    public_key_id, Extension, GrantBinding, GrantPayload, Permission, PermissionKind,
    SessionChallenge, SessionGrant, SessionIntent, SessionOperation, SESSION_CHALLENGE_BYTES,
    SESSION_CHALLENGE_EXTENSION, SESSION_INTENT_BYTES,
};

use crate::{Lease, SessionClient, SessionIdentity, CHALLENGE_PATH, OPEN_PATH, RENEW_PATH};

const IDENTITY: SessionIdentity = SessionIdentity {
    app_id: [1; 16],
    build_id: [2; 16],
    device_id: [3; 16],
    generation_id: [4; 16],
    license_id: [5; 16],
    policy_epoch: 6,
    permission: Permission {
        kind: PermissionKind::Function,
        id: [7; 16],
    },
};
const SESSION: [u8; 16] = [8; 16];
const NORMAL: u8 = 0;
const DENY: u8 = 1;
const WRONG_SEQUENCE: u8 = 2;
const WRONG_CHALLENGE: u8 = 3;
const WRONG_IDENTITY: u8 = 4;

struct Peer {
    mode: AtomicU8,
    requests: Mutex<Vec<(SessionIntent, SessionChallenge)>>,
    device: SigningKey,
    grant: SigningKey,
}

impl Peer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: AtomicU8::new(NORMAL),
            requests: Mutex::new(Vec::new()),
            device: SigningKey::from_slice(&[11; 32]).unwrap(),
            grant: SigningKey::from_slice(&[12; 32]).unwrap(),
        })
    }

    async fn server(self: &Arc<Self>) -> Server {
        let peer = self.clone();
        Server::bind(&rustls::version::TLS13, move |request| {
            let peer = peer.clone();
            async move { Ok(peer.respond(request).await) }
        })
        .await
    }

    async fn respond(&self, request: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == DENY {
            return response(StatusCode::FORBIDDEN, Bytes::new());
        }
        assert_eq!(request.headers()[CONTENT_TYPE], CONTENT);
        let path = request.uri().path().to_owned();
        let body = request.into_body().collect().await.unwrap().to_bytes();
        if path == CHALLENGE_PATH {
            let (canonical, proof) = body.split_at(SESSION_INTENT_BYTES);
            let intent = SessionIntent::decode(canonical).unwrap();
            intent
                .verify(self.device.verifying_key(), proof.try_into().unwrap())
                .unwrap();
            assert_eq!(intent.app_id, IDENTITY.app_id);
            assert_eq!(intent.build_id, IDENTITY.build_id);
            assert_eq!(intent.generation_id, IDENTITY.generation_id);
            assert_eq!(intent.device_id, IDENTITY.device_id);
            assert_eq!(
                intent.session_id,
                if intent.operation == SessionOperation::Open {
                    [0; 16]
                } else {
                    SESSION
                }
            );
            let mut requests = self.requests.lock().unwrap();
            let counter = u8::try_from(requests.len() + 1).unwrap();
            let challenge = SessionChallenge {
                intent_digest: if mode == WRONG_CHALLENGE {
                    [0; 32]
                } else {
                    intent.digest().unwrap()
                },
                session_id: SESSION,
                challenge_id: [counter; 16],
                nonce: [counter; 32],
            };
            requests.push((intent, challenge));
            return response(StatusCode::OK, challenge.encode().unwrap().into());
        }
        let (canonical, proof) = body.split_at(SESSION_CHALLENGE_BYTES);
        let challenge = SessionChallenge::decode(canonical).unwrap();
        challenge
            .verify(self.device.verifying_key(), proof.try_into().unwrap())
            .unwrap();
        let (intent, expected) = *self.requests.lock().unwrap().last().unwrap();
        assert_eq!(challenge, expected);
        assert_eq!(
            path,
            if intent.operation == SessionOperation::Open {
                OPEN_PATH
            } else {
                RENEW_PATH
            }
        );
        let mut grant = self.payload(challenge, intent.sequence);
        if mode == WRONG_SEQUENCE {
            grant.sequence += 1;
        }
        if mode == WRONG_IDENTITY {
            grant.binding.device_id = [0; 16];
        }
        let signed = SessionGrant::sign(grant, &self.grant).unwrap();
        response(StatusCode::OK, Bytes::copy_from_slice(signed.as_bytes()))
    }

    fn payload(&self, challenge: SessionChallenge, sequence: u64) -> GrantPayload {
        GrantPayload {
            binding: GrantBinding {
                session_id: challenge.session_id,
                device_id: IDENTITY.device_id,
                license_id: IDENTITY.license_id,
                app_id: IDENTITY.app_id,
                build_id: IDENTITY.build_id,
                generation_id: IDENTITY.generation_id,
            },
            policy_epoch: IDENTITY.policy_epoch,
            sequence,
            issued_at_ms: 1,
            lifetime_ms: 30_000,
            permissions: vec![IDENTITY.permission],
            signing_key_id: public_key_id(self.grant.verifying_key()),
            extensions: vec![Extension {
                id: SESSION_CHALLENGE_EXTENSION,
                required: false,
                bytes: challenge.digest().unwrap().to_vec(),
            }],
        }
    }
}

#[tokio::test]
async fn session_open_and_renew_verify_device_and_pin_grant() {
    let peer = Peer::new();
    let server = peer.server().await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    assert_eq!(client.open().await.unwrap().sequence, 1);
    assert_eq!(client.renew().await.unwrap().sequence, 2);
    assert_eq!(client.current_grant().unwrap().binding.session_id, SESSION);
    {
        let requests = peer.requests.lock().unwrap();
        assert_ne!(requests[0].0.request_id, requests[1].0.request_id);
    }
    peer.mode.store(DENY, Ordering::SeqCst);
    assert_eq!(client.renew().await, Err(ClientError::Denied));
    assert!(client.current_grant().is_none());
    assert_eq!(client.renew().await, Err(ClientError::NoSession));
}

#[tokio::test]
async fn grant_pin_is_independent_of_tls_trust() {
    let peer = Peer::new();
    let server = peer.server().await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.device.verifying_key(),
    );
    assert_eq!(client.open().await, Err(ClientError::Verification));
    assert!(client.current_grant().is_none());
}

#[tokio::test]
async fn bad_challenge_and_signed_wrong_grant_clear_authority() {
    let peer = Peer::new();
    let server = peer.server().await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    for mode in [WRONG_CHALLENGE, WRONG_SEQUENCE, WRONG_IDENTITY] {
        peer.mode.store(NORMAL, Ordering::SeqCst);
        client.open().await.unwrap();
        peer.mode.store(mode, Ordering::SeqCst);
        assert_eq!(client.renew().await, Err(ClientError::Verification));
        assert!(client.current_grant().is_none());
    }
}

#[tokio::test]
async fn unreachable_peer_clears_prior_authority() {
    let peer = Peer::new();
    let server = peer.server().await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    client.open().await.unwrap();
    server.task.abort();
    while !server.task.is_finished() {
        tokio::task::yield_now().await;
    }
    assert_eq!(client.renew().await, Err(ClientError::Unavailable));
    assert!(client.current_grant().is_none());
}

#[tokio::test(start_paused = true)]
async fn monotonic_lease_counts_request_time_and_never_admits_expiry() {
    let peer = Peer::new();
    let challenge = SessionChallenge {
        intent_digest: [0; 32],
        session_id: SESSION,
        challenge_id: [0; 16],
        nonce: [0; 32],
    };
    let grant = peer.payload(challenge, 1);
    let started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(9)).await;
    let lease = Lease::new(grant.clone(), started, tokio::time::Instant::now()).unwrap();
    assert_eq!(lease.heartbeat, started + Duration::from_secs(10));
    assert_eq!(lease.expires, started + Duration::from_secs(30));
    tokio::time::advance(Duration::from_secs(21)).await;
    assert!(matches!(
        Lease::new(grant, started, tokio::time::Instant::now()),
        Err(ClientError::Expired)
    ));
}

#[tokio::test]
async fn generation_no_choice_preserves_lease_but_denial_clears_it() {
    use crate::GenerationCapabilities;
    use vmkek_protocol::{GenerationOffer, GENERATION_OFFER_BYTES};

    let peer = Peer::new();
    let server = Server::bind(&rustls::version::TLS13, {
        let peer = peer.clone();
        move |request| {
            let peer = peer.clone();
            async move {
                assert_eq!(request.uri().path(), "/v1/generation/select");
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                let (encoded, proof) = bytes.split_at(GENERATION_OFFER_BYTES);
                let offer = GenerationOffer::decode(encoded).unwrap();
                offer
                    .verify(peer.device.verifying_key(), proof.try_into().unwrap())
                    .unwrap();
                assert_eq!(offer.function_id, IDENTITY.permission.id);
                let status = if peer.mode.load(Ordering::SeqCst) == DENY {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::NO_CONTENT
                };
                Ok(response(status, Bytes::new()))
            }
        }
    })
    .await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    let challenge = SessionChallenge {
        intent_digest: [0; 32],
        session_id: SESSION,
        challenge_id: [0; 16],
        nonce: [0; 32],
    };
    let now = tokio::time::Instant::now();
    client.active = Some(Lease::new(peer.payload(challenge, 1), now, now).unwrap());
    let deadline = client.lease_deadline();
    let supported = GenerationCapabilities {
        forms: GenerationCapabilities::STACK,
        capabilities: 0,
    };
    assert!(client
        .negotiate_generation(supported)
        .await
        .unwrap()
        .is_none());
    assert_eq!(client.lease_deadline(), deadline);
    peer.mode.store(DENY, Ordering::SeqCst);
    assert!(matches!(
        client.negotiate_generation(supported).await,
        Err(ClientError::Denied)
    ));
    assert!(client.current_grant().is_none());
}

#[tokio::test]
async fn stalled_key_tls_distinguishes_local_cutoff_from_network_timeout() {
    use crate::ModuleSelection;
    use std::sync::atomic::AtomicBool;

    let peer = Peer::new();
    let server = Server::bind(&rustls::version::TLS13, |request| async move {
        assert_eq!(request.uri().path(), "/v1/module/open");
        std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
    })
    .await;
    let mut client = SessionClient::new(
        server.endpoint(),
        IDENTITY,
        peer.device.clone(),
        *peer.grant.verifying_key(),
    );
    let challenge = SessionChallenge {
        intent_digest: [0; 32],
        session_id: SESSION,
        challenge_id: [0; 16],
        nonce: [0; 32],
    };
    let now = tokio::time::Instant::now();
    client.active = Some(Lease::new(peer.payload(challenge, 1), now, now).unwrap());
    let token = client.lease_token().unwrap();
    let module = ModuleSelection {
        module_id: [3; 16],
        module_version: 1,
        manifest_sha256: [4; 32],
    };

    let started = std::time::Instant::now();
    let network = started + Duration::from_millis(MAX_DEADLINE_MS as u64);
    let attempted = AtomicBool::new(false);
    assert!(matches!(
        client
            .request_artifact_key(token, module, started, network, &attempted)
            .await,
        Err(ClientError::Expired)
    ));
    assert!(!attempted.load(Ordering::Acquire));
    let local = std::time::Instant::now() + Duration::from_millis(100);
    assert!(matches!(
        client
            .request_artifact_key(token, module, local, network, &attempted)
            .await,
        Err(ClientError::Expired)
    ));
    assert!(attempted.load(Ordering::Acquire));

    let network = std::time::Instant::now() + Duration::from_millis(MAX_DEADLINE_MS as u64);
    let attempted = AtomicBool::new(false);
    assert!(matches!(
        client
            .request_artifact_key(token, module, network, network, &attempted)
            .await,
        Err(ClientError::Timeout)
    ));
    assert!(attempted.load(Ordering::Acquire));
}
