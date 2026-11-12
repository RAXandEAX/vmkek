use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use vmkek_protocol::{DeviceTrust, MAX_BODY_BYTES, MAX_DEADLINE_MS};
use zeroize::Zeroizing;

use crate::{ActivationToken, IdentityError, IdentityStore};

pub fn router(store: IdentityStore) -> Router {
    Router::new()
        .route("/v1/identity/challenge", post(challenge))
        .route("/v1/identity/enroll", post(enroll))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(request_timeout))
        .with_state(store)
}

async fn request_timeout(request: axum::extract::Request, next: middleware::Next) -> Response {
    match tokio::time::timeout(
        Duration::from_millis(MAX_DEADLINE_MS.into()),
        next.run(request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "identity_request_timeout").into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    app_id: String,
    activation_token: SecretField,
    public_key: String,
    trust: String,
}

// Deserialized token storage is wiped even if parsing a later field fails.
// The framework-owned raw HTTP body and parser scratch buffers are outside this ownership.
struct SecretField(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretField {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        String::deserialize(input).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    challenge_id: String,
    proof: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    device_id: String,
    trust: &'static str,
}

async fn challenge(
    State(store): State<IdentityStore>,
    json: Result<Json<ChallengeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ChallengeResponse>, Response> {
    let Json(request) = json.map_err(json_rejection)?;
    let app_id = fixed(&request.app_id).map_err(error_response)?;
    let token = ActivationToken::from_hex(&request.activation_token.0).map_err(error_response)?;
    let key = fixed(&request.public_key).map_err(error_response)?;
    let trust = match request.trust.as_str() {
        "software" => DeviceTrust::Software,
        "tpm_attested" => DeviceTrust::TpmAttested,
        _ => return Err(error_response(IdentityError::Invalid)),
    };
    drop(request);
    let challenge = store
        .challenge(app_id, &token, key, trust)
        .await
        .map_err(error_response)?;
    let bytes = challenge
        .encode()
        .map_err(|_| error_response(IdentityError::Unavailable))?;
    Ok(Json(ChallengeResponse {
        challenge: hex::encode(bytes),
    }))
}

async fn enroll(
    State(store): State<IdentityStore>,
    json: Result<Json<EnrollRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<EnrollResponse>, Response> {
    let Json(request) = json.map_err(json_rejection)?;
    let challenge_id = fixed(&request.challenge_id).map_err(error_response)?;
    let proof = fixed(&request.proof).map_err(error_response)?;
    let device = store
        .enroll(challenge_id, proof)
        .await
        .map_err(error_response)?;
    let trust = match device.trust {
        DeviceTrust::Software => "software",
        DeviceTrust::TpmAttested => "tpm_attested",
    };
    Ok(Json(EnrollResponse {
        device_id: hex::encode(device.id),
        trust,
    }))
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], IdentityError> {
    let mut bytes = Zeroizing::new([0; N]);
    hex::decode_to_slice(value, &mut bytes[..]).map_err(|_| IdentityError::Invalid)?;
    Ok(*bytes)
}

fn json_rejection(error: axum::extract::rejection::JsonRejection) -> Response {
    (error.status(), "invalid_identity_request").into_response()
}

fn error_response(error: IdentityError) -> Response {
    let (status, code) = match error {
        IdentityError::Invalid => (StatusCode::BAD_REQUEST, "invalid_identity_request"),
        IdentityError::Denied => (StatusCode::FORBIDDEN, "identity_denied"),
        IdentityError::Expired => (StatusCode::GONE, "challenge_expired"),
        IdentityError::Replay => (StatusCode::CONFLICT, "challenge_used"),
        IdentityError::DeviceLimit => (StatusCode::CONFLICT, "device_limit"),
        IdentityError::RateLimit => (StatusCode::TOO_MANY_REQUESTS, "enrollment_rate_limit"),
        IdentityError::TrustUnavailable => {
            (StatusCode::UNPROCESSABLE_ENTITY, "device_trust_unavailable")
        }
        IdentityError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "identity_unavailable"),
    };
    (status, code).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static SECRET_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    impl Drop for SecretField {
        fn drop(&mut self) {
            SECRET_DROPS.with(|count| count.set(count.get() + 1));
        }
    }

    #[test]
    fn token_is_dropped_when_a_later_json_field_fails() {
        for invalid in [
            r#"{"activation_token":"test-secret","app_id":false}"#,
            r#"{"activation_token":"test-secret","activation_token":"duplicate"}"#,
            r#"{"activation_token":"test-secret","unexpected":0}"#,
        ] {
            SECRET_DROPS.with(|count| count.set(0));
            assert!(serde_json::from_str::<ChallengeRequest>(invalid).is_err());
            SECRET_DROPS.with(|count| assert_eq!(count.get(), 1));
        }
    }
}
