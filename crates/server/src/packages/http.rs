use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use vmkek_protocol::{
    ModuleFetch, ModuleOpen, MODULE_FETCH_BYTES, MODULE_OPEN_BYTES, SESSION_PROOF_BYTES,
};

use super::{ModuleKeyStore, PackageError, PackageStore};

pub(crate) fn package_router(store: PackageStore) -> Router {
    Router::new()
        .route("/v1/module/fetch", post(fetch))
        .layer(DefaultBodyLimit::max(
            MODULE_FETCH_BYTES + SESSION_PROOF_BYTES,
        ))
        .with_state(store)
}

async fn fetch(State(store): State<PackageStore>, body: Bytes) -> Result<Vec<u8>, PackageError> {
    if body.len() != MODULE_FETCH_BYTES + SESSION_PROOF_BYTES {
        return Err(PackageError::Invalid);
    }
    let (request, proof) = body.split_at(MODULE_FETCH_BYTES);
    store
        .fetch(
            ModuleFetch::decode(request)?,
            proof.try_into().map_err(|_| PackageError::Invalid)?,
        )
        .await
}

impl IntoResponse for PackageError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Denied => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Session(error) => return error.into_response(),
        };
        status.into_response()
    }
}

pub(crate) fn module_router(keys: ModuleKeyStore) -> Router {
    Router::new()
        .route("/v1/module/open", post(open))
        .layer(DefaultBodyLimit::max(
            MODULE_OPEN_BYTES + SESSION_PROOF_BYTES,
        ))
        .with_state(keys)
}

async fn open(State(keys): State<ModuleKeyStore>, body: Bytes) -> Result<Response, PackageError> {
    if body.len() != MODULE_OPEN_BYTES + SESSION_PROOF_BYTES {
        return Err(PackageError::Invalid);
    }
    let (request, proof) = body.split_at(MODULE_OPEN_BYTES);
    let owned = keys
        .packages
        .open_key(
            &keys,
            ModuleOpen::decode(request)?,
            proof.try_into().map_err(|_| PackageError::Invalid)?,
        )
        .await?;
    // The application-owned response allocation is wiped when its last Bytes reference
    // drops. Hyper, TLS and OS buffers have their own independent lifetimes.
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Bytes::from_owner(owned),
    )
        .into_response())
}
