use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use vmkek_protocol::{
    session_observation::{SessionObservation, MAX_SESSION_OBSERVATION_BYTES},
    SessionChallenge, SessionIntent, SessionOperation, MAX_BODY_BYTES, MAX_DEADLINE_MS,
    SESSION_CHALLENGE_BYTES, SESSION_INTENT_BYTES, SESSION_PROOF_BYTES,
};

use super::{SessionError, SessionStore};
use crate::packages::PackageStore;

#[derive(Clone)]
struct SessionRoutes {
    store: SessionStore,
    packages: Option<PackageStore>,
}

pub(super) fn session_router(store: SessionStore) -> Router {
    routes(SessionRoutes {
        store,
        packages: None,
    })
}

pub(super) fn negotiated_router(packages: PackageStore) -> Router {
    routes(SessionRoutes {
        store: packages.session().clone(),
        packages: Some(packages),
    })
}

fn routes(state: SessionRoutes) -> Router {
    Router::new()
        .route("/v1/session/challenge", post(challenge))
        .route("/v1/session/open", post(open))
        .route("/v1/session/renew", post(renew))
        .layer(DefaultBodyLimit::max(
            MAX_BODY_BYTES.min(SESSION_INTENT_BYTES + SESSION_PROOF_BYTES),
        ))
        .merge(
            Router::new()
                .route("/v1/session/observation", post(observation))
                .layer(DefaultBodyLimit::max(
                    MAX_SESSION_OBSERVATION_BYTES + SESSION_PROOF_BYTES,
                )),
        )
        .layer(middleware::from_fn(timeout))
        .with_state(state)
}

async fn timeout(request: Request, next: Next) -> Response {
    match tokio::time::timeout(
        Duration::from_millis(MAX_DEADLINE_MS.into()),
        next.run(request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn challenge(
    State(state): State<SessionRoutes>,
    body: Bytes,
) -> Result<Vec<u8>, SessionError> {
    let (bytes, proof) = split(&body, SESSION_INTENT_BYTES)?;
    let intent = SessionIntent::decode(bytes).map_err(|_| SessionError::Invalid)?;
    state
        .store
        .issue(intent, proof)
        .await?
        .encode()
        .map_err(|_| SessionError::Unavailable)
}

async fn observation(
    State(state): State<SessionRoutes>,
    body: Bytes,
) -> Result<Vec<u8>, SessionError> {
    let length = body
        .len()
        .checked_sub(SESSION_PROOF_BYTES)
        .ok_or(SessionError::Invalid)?;
    let (bytes, proof) = split(&body, length)?;
    let report = SessionObservation::decode(bytes).map_err(|_| SessionError::Invalid)?;
    state.store.observe_session(report, proof).await?;
    Ok(Vec::new())
}

async fn open(State(state): State<SessionRoutes>, body: Bytes) -> Result<Vec<u8>, SessionError> {
    complete(&state, SessionOperation::Open, body).await
}

async fn renew(State(state): State<SessionRoutes>, body: Bytes) -> Result<Vec<u8>, SessionError> {
    complete(&state, SessionOperation::Renew, body).await
}

async fn complete(
    state: &SessionRoutes,
    op: SessionOperation,
    body: Bytes,
) -> Result<Vec<u8>, SessionError> {
    let (bytes, proof) = split(&body, SESSION_CHALLENGE_BYTES)?;
    let challenge = SessionChallenge::decode(bytes).map_err(|_| SessionError::Invalid)?;
    Ok(state
        .store
        .complete_with_packages(op, challenge, proof, state.packages.as_ref())
        .await?
        .as_bytes()
        .to_vec())
}

fn split(body: &[u8], length: usize) -> Result<(&[u8], [u8; SESSION_PROOF_BYTES]), SessionError> {
    if body.len() != length + SESSION_PROOF_BYTES {
        return Err(SessionError::Invalid);
    }
    let (bytes, proof) = body.split_at(length);
    Ok((bytes, proof.try_into().map_err(|_| SessionError::Invalid)?))
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Denied => StatusCode::FORBIDDEN,
            Self::Replay => StatusCode::CONFLICT,
            Self::Expired => StatusCode::GONE,
            Self::Limit => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        status.into_response()
    }
}
