use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    routing::post,
    Router,
};
use vmkek_protocol::{SampleOperationRequest, SAMPLE_OPERATION_REQUEST_BYTES, SESSION_PROOF_BYTES};

use super::OperationStore;
use crate::packages::PackageError;

pub(crate) fn operation_router(store: OperationStore) -> Router {
    Router::new()
        .route("/v1/operation/sample-job-receipt", post(invoke))
        .layer(DefaultBodyLimit::max(
            SAMPLE_OPERATION_REQUEST_BYTES + SESSION_PROOF_BYTES,
        ))
        .with_state(store)
}

async fn invoke(State(store): State<OperationStore>, body: Bytes) -> Result<Vec<u8>, PackageError> {
    if body.len() != SAMPLE_OPERATION_REQUEST_BYTES + SESSION_PROOF_BYTES {
        return Err(PackageError::Invalid);
    }
    let (request, proof) = body.split_at(SAMPLE_OPERATION_REQUEST_BYTES);
    store
        .invoke(
            SampleOperationRequest::decode(request)?,
            proof.try_into().map_err(|_| PackageError::Invalid)?,
        )
        .await
}
