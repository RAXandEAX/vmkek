use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use vmkek_protocol::{
    GenerationOffer, SignedGenerationChoice, GENERATION_CHOICE_BYTES, GENERATION_OFFER_BYTES,
    SESSION_PROOF_BYTES,
};

use super::GenerationStore;
use crate::packages::PackageError;

pub(crate) fn generation_router(store: GenerationStore) -> Router {
    Router::new()
        .route("/v1/generation/select", post(select))
        .route("/v1/generation/complete", post(complete))
        .layer(DefaultBodyLimit::max(
            GENERATION_CHOICE_BYTES + SESSION_PROOF_BYTES,
        ))
        .with_state(store)
}

async fn select(
    State(store): State<GenerationStore>,
    body: Bytes,
) -> Result<Response, PackageError> {
    let (offer, proof) = split(&body, GENERATION_OFFER_BYTES)?;
    match store.select(GenerationOffer::decode(offer)?, proof).await? {
        Some(choice) => Ok(choice.as_bytes().to_vec().into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn complete(
    State(store): State<GenerationStore>,
    body: Bytes,
) -> Result<Vec<u8>, PackageError> {
    let (choice, proof) = split(&body, GENERATION_CHOICE_BYTES)?;
    Ok(store
        .complete(SignedGenerationChoice::decode(choice)?, proof)
        .await?
        .as_bytes()
        .to_vec())
}

fn split(body: &[u8], size: usize) -> Result<(&[u8], [u8; SESSION_PROOF_BYTES]), PackageError> {
    if body.len() != size + SESSION_PROOF_BYTES {
        return Err(PackageError::Invalid);
    }
    let (object, proof) = body.split_at(size);
    Ok((object, proof.try_into().map_err(|_| PackageError::Invalid)?))
}
