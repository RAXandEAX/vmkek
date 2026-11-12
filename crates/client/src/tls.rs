use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vmkek_protocol::{MAX_BODY_BYTES, MAX_DEADLINE_MS, MODULE_KEY_RECEIPT_BYTES};
use zeroize::Zeroizing;

use crate::ClientError;

const CONTENT: &str = "application/octet-stream";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(MAX_DEADLINE_MS as u64);

/// One configured server and its trusted root certificates. The socket address
/// selects a transport destination; the DNS name authenticates its certificate.
pub struct TlsEndpoint {
    address: SocketAddr,
    name: DnsName<'static>,
    connector: TlsConnector,
}

impl TlsEndpoint {
    pub fn new(
        address: SocketAddr,
        dns_name: &str,
        roots: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, ClientError> {
        let name =
            DnsName::try_from(dns_name.to_owned()).map_err(|_| ClientError::Configuration)?;
        let mut store = RootCertStore::empty();
        for root in roots {
            store.add(root).map_err(|_| ClientError::Configuration)?;
        }
        if store.is_empty() {
            return Err(ClientError::Configuration);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ClientError::Configuration)?
            .with_root_certificates(store)
            .with_no_client_auth();
        config.enable_early_data = false;
        config.resumption = Resumption::disabled();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            address,
            name,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    pub(crate) async fn post(
        &self,
        path: &'static str,
        body: Vec<u8>,
    ) -> Result<Bytes, ClientError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(ClientError::BodyLimit);
        }
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.exchange(path, body, None, read_response),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub(crate) async fn post_bounded(
        &self,
        path: &'static str,
        body: Vec<u8>,
        maximum: usize,
    ) -> Result<Bytes, ClientError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(ClientError::BodyLimit);
        }
        let read = |response| read_response_bounded(response, maximum);
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.exchange(path, body, Some(16 * 1024), read),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub(crate) async fn post_generation_choice(
        &self,
        path: &'static str,
        body: Vec<u8>,
    ) -> Result<Option<Bytes>, ClientError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(ClientError::BodyLimit);
        }
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.exchange(path, body, None, read_choice),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub(crate) async fn post_secret(
        &self,
        path: &'static str,
        body: Vec<u8>,
    ) -> Result<Zeroizing<[u8; MODULE_KEY_RECEIPT_BYTES]>, ClientError> {
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.exchange(path, body, None, read_secret),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    async fn exchange<R>(
        &self,
        path: &'static str,
        body: Vec<u8>,
        read_buffer: Option<usize>,
        read: impl AsyncFnOnce(hyper::Response<hyper::body::Incoming>) -> Result<R, ClientError>,
    ) -> Result<R, ClientError> {
        let socket = TcpStream::connect(self.address)
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let stream = self
            .connector
            .connect(ServerName::DnsName(self.name.clone()), socket)
            .await
            .map_err(|_| ClientError::Tls)?;
        let mut http = http1::Builder::new();
        if let Some(maximum) = read_buffer {
            http.max_buf_size(maximum);
        }
        let (mut sender, connection) = http
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let request = Request::post(path)
            .header(
                HOST,
                format!("{}:{}", self.name.as_ref(), self.address.port()),
            )
            .header(CONTENT_TYPE, CONTENT)
            .header(CONNECTION, "close")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| ClientError::Configuration)?;

        tokio::pin!(connection);
        let reply = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| ClientError::Unavailable)?;
            read(response).await
        };
        tokio::pin!(reply);
        // The connection can close after receiving the last response frame.
        // Poll the response first so a ready result wins over a clean close.
        tokio::select! {
            biased;
            result = &mut reply => result,
            result = &mut connection => {
                result.map_err(|_| ClientError::Unavailable)?;
                reply.await
            }
        }
    }
}

async fn read_choice(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<Option<Bytes>, ClientError> {
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(None);
    }
    read_response(response).await.map(Some)
}

async fn read_response(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<Bytes, ClientError> {
    read_response_bounded(response, MAX_BODY_BYTES).await
}

async fn read_response_bounded(
    response: hyper::Response<hyper::body::Incoming>,
    maximum: usize,
) -> Result<Bytes, ClientError> {
    check_response(&response)?;
    Limited::new(response.into_body(), maximum)
        .collect()
        .await
        .map(|body| body.to_bytes())
        .map_err(|error| {
            if error.is::<LengthLimitError>() {
                ClientError::BodyLimit
            } else {
                ClientError::Unavailable
            }
        })
}

fn check_response(response: &hyper::Response<hyper::body::Incoming>) -> Result<(), ClientError> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::REQUEST_TIMEOUT => return Err(ClientError::Timeout),
        StatusCode::SERVICE_UNAVAILABLE => return Err(ClientError::Unavailable),
        status if status.is_client_error() => return Err(ClientError::Denied),
        _ => return Err(ClientError::InvalidResponse),
    }
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(CONTENT)
    {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

async fn read_secret(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<Zeroizing<[u8; MODULE_KEY_RECEIPT_BYTES]>, ClientError> {
    check_response(&response)?;
    let mut body = response.into_body();
    let mut receipt = Zeroizing::new([0; MODULE_KEY_RECEIPT_BYTES]);
    let mut length = 0;
    // The owned receipt is wiped. TLS/Hyper frame buffers are framework-owned.
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| ClientError::Unavailable)?
            .into_data()
            .map_err(|_| ClientError::InvalidResponse)?;
        let end = length + data.len();
        receipt
            .get_mut(length..end)
            .ok_or(ClientError::BodyLimit)?
            .copy_from_slice(&data);
        length = end;
    }
    if length != receipt.len() {
        return Err(ClientError::InvalidResponse);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests;
