//! SigV4 seed-signature verification, mounted as a `tower::Layer`.
//!
//! Runs before any handler. Two paths:
//!
//!   * **Header SigV4** — `Authorization: AWS4-HMAC-SHA256 …`. Parses
//!     the header, looks up the secret for the access key, recomputes
//!     the canonical-request signature with the body marker declared
//!     by `x-amz-content-sha256`, and rejects on mismatch.
//!   * **Presigned URL** — `X-Amz-*` query parameters. Parsed and
//!     verified with the request URI re-signed minus the X-Amz-* group.
//!
//! For body-bearing methods (PUT) the seed verification covers the
//! request line and headers; the body-bytes hash is verified
//! separately as the body streams (handler-side concern).
//!
//! Compatibility with the streaming PUT body modes:
//! `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` declares
//! aws-chunked framing; the seed check accepts the marker as the
//! signed body hash, and the per-chunk signature chain is validated
//! during body decode (not in this layer).

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use aws_sigv4::http_request::SignableBody;
use http::HeaderMap;

use crate::auth::{self, AuthError};
use crate::s3::error::AppError;
use crate::s3::state::AppState;

// `x-amz-content-sha256` markers we recognise. The seed signature
// treats each of these as the literal body-hash placeholder in the
// canonical request — the actual body bytes are checked separately
// during streaming. See:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-streaming.html
const SHA_UNSIGNED:                   &str = "UNSIGNED-PAYLOAD";
const SHA_STREAMING:                  &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const SHA_STREAMING_TRAILER:          &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const SHA_STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Pull the signed request line (method + path + query) out of the
/// request URI so we can hand it to `verify_seed` exactly as the
/// client originally signed it.
fn path_and_query(req: &Request<Body>) -> String {
    req.uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned())
}

/// `axum::middleware::from_fn_with_state` entry point. The
/// `from_fn_with_state` adapter passes us the `AppState` it owns plus
/// the request; we either reject with an error response or call
/// `next.run(req).await`.
///
/// The `Rc<AuthState>` inside `state` is `!Send`, but axum requires
/// the returned future to be `Send`. We avoid capturing the `Rc` past
/// any await: `run_check` runs synchronously, completes, releases the
/// borrow, and only then do we await `next.run(req)`. The captured
/// state at the await point is just the unit-result of `run_check`,
/// which is trivially `Send`.
pub async fn sigv4(
    State(state): State<AppState>,
    req:          Request<Body>,
    next:         Next,
) -> Response {
    if let Err(e) = run_check(state.auth(), &req) {
        return AppError::Auth(e).into_response();
    }
    drop(state);
    next.run(req).await
}

fn run_check(
    auth_state: &crate::auth::AuthState,
    req:        &Request<Body>,
) -> Result<(), AuthError> {
    // --- Presigned URL path --------------------------------------------
    let auth_hdr = req.headers().get(http::header::AUTHORIZATION);
    if auth_hdr.is_none() && auth::has_presigned_query_params(req.uri()) {
        let parsed = auth::parse_presigned_query(req.uri())?;
        let secret = auth_state
            .secret_for(&parsed.access_key)
            .ok_or_else(|| AuthError::InvalidAccessKeyId(parsed.access_key.clone()))?
            .to_owned();
        return auth::verify_presigned(
            req.method().as_str(),
            req.uri(),
            req.headers(),
            &parsed,
            &secret,
            auth_state.region(),
        );
    }

    // --- Header SigV4 path --------------------------------------------
    let auth_value = auth_hdr
        .ok_or(AuthError::MissingAuth)?
        .to_str()
        .map_err(|_| AuthError::MalformedAuth("Authorization not ASCII"))?;
    let parsed = auth::parse_authorization(auth_value)?;

    let amz_date = req
        .headers()
        .get("x-amz-date")
        .ok_or(AuthError::MissingDate)?
        .to_str()
        .map_err(|_| AuthError::BadDate("non-ASCII".into()))?;
    let request_time = auth::parse_amz_date(amz_date)?;
    auth::check_skew(request_time)?;
    if amz_date.len() < 8 || parsed.scope_date != amz_date[..8] {
        return Err(AuthError::MalformedAuth("scope date does not match x-amz-date"));
    }
    let secret = auth_state
        .secret_for(&parsed.access_key)
        .ok_or_else(|| AuthError::InvalidAccessKeyId(parsed.access_key.clone()))?
        .to_owned();

    let body = signable_body_from_headers(req.headers(), req.method())?;
    auth::verify_seed(
        req.method().as_str(),
        &path_and_query(req),
        req.headers(),
        &parsed,
        &secret,
        auth_state.region(),
        request_time,
        body,
    )
}

/// Translate `x-amz-content-sha256` into the `SignableBody` value
/// `aws_sigv4::http_request::sign` expects. For methods that S3 SDKs
/// don't sign with a body hash (GET/HEAD/DELETE — they elide the
/// header) we default to `UnsignedPayload`, matching the existing
/// `authenticate_no_body` path.
fn signable_body_from_headers(
    headers: &HeaderMap,
    _method: &http::Method,
) -> Result<SignableBody<'static>, AuthError> {
    let raw = match headers.get("x-amz-content-sha256") {
        Some(h) => h
            .to_str()
            .map_err(|_| AuthError::UnsupportedContentSha("non-ASCII".into()))?
            .to_owned(),
        None => return Ok(SignableBody::UnsignedPayload),
    };
    Ok(match raw.as_str() {
        SHA_UNSIGNED => SignableBody::UnsignedPayload,
        // For all three streaming variants the *seed* signature is
        // computed using the literal marker as the body-hash
        // placeholder. The body bytes themselves get a different
        // verification path in the PUT handler (per-chunk SigV4 for
        // signed variants, trailer-header checksums for the trailer
        // variants).
        SHA_STREAMING                  => SignableBody::Precomputed(SHA_STREAMING.to_owned()),
        SHA_STREAMING_TRAILER          => SignableBody::Precomputed(SHA_STREAMING_TRAILER.to_owned()),
        SHA_STREAMING_UNSIGNED_TRAILER => SignableBody::Precomputed(SHA_STREAMING_UNSIGNED_TRAILER.to_owned()),
        hex if is_hex_sha256(hex) => SignableBody::Precomputed(raw),
        other => return Err(AuthError::UnsupportedContentSha(other.to_owned())),
    })
}

fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

