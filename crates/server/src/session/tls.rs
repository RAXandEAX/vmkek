use std::{io, sync::Arc, time::Duration};

use axum::Router;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use vmkek_protocol::MAX_DEADLINE_MS;

use super::{
    http::{negotiated_router, session_router},
    SessionStore,
};
use crate::generation::{generation_router, GenerationStore};
use crate::operations::{operation_router, OperationStore};
use crate::packages::{module_router, package_router, ModuleKeyStore, PackageStore};

const MAX_CONNECTIONS: usize = 128;
const TIMEOUT: Duration = Duration::from_millis(MAX_DEADLINE_MS as u64);

/// TLS acceptor whose protocol and early-data settings are fixed by this module.
#[derive(Clone)]
pub struct SessionTlsAcceptor(TlsAcceptor);

pub fn session_tls_acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<SessionTlsAcceptor, rustls::Error> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.send_half_rtt_data = false;
    Ok(SessionTlsAcceptor(TlsAcceptor::from(Arc::new(config))))
}

/// Serve an R10 router on an explicit loopback listener until the task is cancelled.
pub async fn serve_sessions_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    store: SessionStore,
) -> io::Result<()> {
    serve_tls(listener, acceptor, session_router(store)).await
}

/// Serve sessions and signed ciphertext packages on the same strict loopback TLS listener.
pub async fn serve_packages_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    store: PackageStore,
) -> io::Result<()> {
    let routes = session_router(store.session().clone()).merge(package_router(store));
    serve_tls(listener, acceptor, routes).await
}

/// Serve protected module key opening only on the hardened loopback TLS listener.
pub async fn serve_modules_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    keys: ModuleKeyStore,
) -> io::Result<()> {
    let packages = keys.packages.clone();
    let routes = session_router(packages.session().clone())
        .merge(package_router(packages))
        .merge(module_router(keys));
    serve_tls(listener, acceptor, routes).await
}

/// Serve negotiated generation setup and its authorized module routes on loopback TLS.
pub async fn serve_generations_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    generations: GenerationStore,
) -> io::Result<()> {
    let keys = generations.keys.clone();
    let packages = keys.packages.clone();
    let routes = negotiated_router(packages.clone())
        .merge(package_router(packages))
        .merge(module_router(keys))
        .merge(generation_router(generations));
    serve_tls(listener, acceptor, routes).await
}

/// Serve the fixed-session sample operation on the hardened loopback listener.
pub async fn serve_operations_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    operations: OperationStore,
) -> io::Result<()> {
    if operations.session.is_negotiated() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected fixed-session authority",
        ));
    }
    let routes = session_router(operations.session.clone()).merge(operation_router(operations));
    serve_tls(listener, acceptor, routes).await
}

/// Serve modules and the sample operation on the same negotiated session authority.
pub async fn serve_hybrid_generations_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    generations: GenerationStore,
    operations: OperationStore,
) -> io::Result<()> {
    let keys = generations.keys.clone();
    let packages = keys.packages.clone();
    if !operations.session.is_negotiated()
        || !operations
            .packages
            .as_ref()
            .is_some_and(|authority| packages.shares_authority(authority))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected shared negotiated authority",
        ));
    }
    let routes = negotiated_router(packages.clone())
        .merge(package_router(packages))
        .merge(module_router(keys))
        .merge(generation_router(generations))
        .merge(operation_router(operations));
    serve_tls(listener, acceptor, routes).await
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: SessionTlsAcceptor,
    router: Router,
) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "R10 listener requires loopback",
        ));
    }
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let router = router.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(stream)) = tokio::time::timeout(TIMEOUT, acceptor.0.accept(stream)).await else {
                        return;
                    };
                    if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1") {
                        return;
                    }
                    let connection = http1::Builder::new()
                        .keep_alive(false)
                        .timer(TokioTimer::new())
                        .header_read_timeout(TIMEOUT)
                        .serve_connection(TokioIo::new(stream), service_fn(move |request: Request<Incoming>| {
                            router.clone().oneshot(request.map(axum::body::Body::new))
                        }));
                    let _ = tokio::time::timeout(TIMEOUT, connection).await;
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}
