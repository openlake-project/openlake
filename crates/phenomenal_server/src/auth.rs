//! AWS SigV4 request verification for the S3 frontend.
//!
//! Built around `aws-sigv4`'s server-side primitives so we don't hand-roll
//! canonical-request construction or HMAC chaining. The library gives us
//! three entry points:
//!
//!   - `aws_sigv4::http_request::sign` — computes the canonical request
//!     and SigV4 seed signature. Invoked with the *server's* stored
//!     secret key; if its output matches the signature the client sent
//!     in the Authorization header, the request is authentic.
//!   - `aws_sigv4::sign::v4::sign_chunk` — computes one
//!     `AWS4-HMAC-SHA256-PAYLOAD` chunk signature chained off the prior
//!     signature. Used to verify each chunk in a
//!     `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body.
//!   - `aws_sigv4::sign::v4::generate_signing_key` — reproduces the
//!     per-date/region/service signing key. We rely on it transitively
//!     through `sign_chunk`.
//!
//! Supported authentication modes (all via the `Authorization` header):
//!
//!   * `x-amz-content-sha256: UNSIGNED-PAYLOAD` — request is signed but
//!     body is not. Seed signature verified with `SignableBody::
//!     UnsignedPayload`.
//!   * `x-amz-content-sha256: <hex sha256 of body>` — single-shot signed
//!     upload. Seed verified with `SignableBody::Precomputed(hex)`; the
//!     read body is hashed and compared to the header value.
//!   * `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` —
//!     aws-chunked framing. Seed verified with
//!     `SignableBody::Precomputed("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")`,
//!     then each transferred chunk is verified against its declared
//!     `chunk-signature`, chained off the seed.
//!
//! Presigned-URL authentication (SigV4 in query parameters) is not yet
//! wired; the verifier rejects it with `MalformedAuth` until the
//! presigned code path lands alongside GET/HEAD URL handlers.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, PayloadChecksumKind, PercentEncodingMode, SessionTokenMode, SignableBody,
    SignableRequest, SignatureLocation, SigningParams, SigningSettings,
    UriPathNormalizationMode,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;

use crate::config::Credential;

const ALGORITHM:              &str = "AWS4-HMAC-SHA256";
const SERVICE:                &str = "s3";
const MAX_CLOCK_SKEW:         Duration = Duration::from_secs(15 * 60);

/// Per-runtime shared auth state. `Rc`-wrapped by the caller; one copy per
/// pinned runtime thread so lookups never cross core boundaries.
pub struct AuthState {
    region: String,
    keys:   HashMap<String, String>,
}

impl AuthState {
    pub fn new(region: String, creds: &[Credential]) -> Self {
        let mut keys = HashMap::with_capacity(creds.len());
        for c in creds {
            keys.insert(c.access_key.clone(), c.secret_key.clone());
        }
        Self { region, keys }
    }

    pub fn region(&self) -> &str { &self.region }

    pub fn secret_for(&self, access_key: &str) -> Option<&str> {
        self.keys.get(access_key).map(|s| s.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing Authorization header")]
    MissingAuth,
    #[error("malformed Authorization header: {0}")]
    MalformedAuth(&'static str),
    #[error("missing x-amz-date")]
    MissingDate,
    #[error("malformed x-amz-date: {0}")]
    BadDate(String),
    #[error("request timestamp outside allowed 15-minute skew")]
    RequestTimeSkewed,
    #[error("missing x-amz-content-sha256")]
    MissingContentSha,
    #[error("unsupported x-amz-content-sha256 value: {0}")]
    UnsupportedContentSha(String),
    #[error("access key {0} is not recognized")]
    InvalidAccessKeyId(String),
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("scope region {req:?} does not match server region {server:?}")]
    RegionMismatch { req: String, server: String },
    #[error("scope service {0:?} is not {SERVICE:?}")]
    BadService(String),
    #[error("missing x-amz-decoded-content-length for streaming body")]
    MissingDecodedContentLength,
    #[error("chunk signature mismatch")]
    ChunkSignatureMismatch,
    #[error("internal signer error: {0}")]
    Signer(String),

    // Presigned-URL specific errors. They share status codes with their
    // header-auth counterparts but surface distinct messages so debug
    // logs make it clear which path rejected the request.
    #[error("presigned URL X-Amz-Algorithm must be AWS4-HMAC-SHA256, got {0:?}")]
    BadAlgorithm(String),
    #[error("malformed presigned URL: {0}")]
    MalformedPresigned(&'static str),
    #[error("presigned URL X-Amz-Expires {0} out of range (1..=604800)")]
    BadExpires(u64),
    #[error("presigned URL has expired")]
    PresignedExpired,
}

impl AuthError {
    /// Map to the S3 (status, error code) pair the client sees.
    pub fn status_and_code(&self) -> (StatusCode, &'static str) {
        use AuthError::*;
        match self {
            MissingAuth              => (StatusCode::FORBIDDEN, "AccessDenied"),
            MalformedAuth(_)         => (StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
            MissingDate | BadDate(_) => (StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
            RequestTimeSkewed        => (StatusCode::FORBIDDEN, "RequestTimeTooSkewed"),
            MissingContentSha        => (StatusCode::BAD_REQUEST, "MissingContentSHA256"),
            UnsupportedContentSha(_) => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            InvalidAccessKeyId(_)    => (StatusCode::FORBIDDEN, "InvalidAccessKeyId"),
            SignatureMismatch        => (StatusCode::FORBIDDEN, "SignatureDoesNotMatch"),
            RegionMismatch { .. }    => (StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
            BadService(_)            => (StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
            MissingDecodedContentLength => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            ChunkSignatureMismatch   => (StatusCode::FORBIDDEN, "SignatureDoesNotMatch"),
            Signer(_)                => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            BadAlgorithm(_)          => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            MalformedPresigned(_)    => (StatusCode::BAD_REQUEST, "AuthorizationQueryParametersError"),
            BadExpires(_)            => (StatusCode::BAD_REQUEST, "AuthorizationQueryParametersError"),
            PresignedExpired         => (StatusCode::FORBIDDEN, "AccessDenied"),
        }
    }
}

/// The pieces parsed out of an `Authorization: AWS4-HMAC-SHA256 …` header.
///
/// Matches the SigV4 wire format:
/// `Credential=<AK>/<date>/<region>/<service>/aws4_request,
///  SignedHeaders=<h1;h2;…>,
///  Signature=<hex64>`
#[derive(Debug, Clone)]
pub struct ParsedAuth {
    pub access_key:     String,
    pub scope_date:     String,
    pub scope_region:   String,
    pub scope_service:  String,
    pub signed_headers: Vec<String>,
    pub signature:      String,
}

pub fn parse_authorization(value: &str) -> Result<ParsedAuth, AuthError> {
    let rest = value
        .strip_prefix(ALGORITHM)
        .ok_or(AuthError::MalformedAuth("expected AWS4-HMAC-SHA256 algorithm"))?;
    let rest = rest.trim_start();

    let mut credential     : Option<&str> = None;
    let mut signed_headers : Option<&str> = None;
    let mut signature      : Option<&str> = None;
    for piece in rest.split(',') {
        let piece = piece.trim();
        if let Some(v) = piece.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = piece.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v);
        } else if let Some(v) = piece.strip_prefix("Signature=") {
            signature = Some(v);
        }
    }

    let credential     = credential    .ok_or(AuthError::MalformedAuth("Credential field missing"))?;
    let signed_headers = signed_headers.ok_or(AuthError::MalformedAuth("SignedHeaders field missing"))?;
    let signature      = signature     .ok_or(AuthError::MalformedAuth("Signature field missing"))?;

    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(AuthError::MalformedAuth("Credential scope has wrong shape"));
    }

    let headers: Vec<String> = signed_headers
        .split(';')
        .filter(|h| !h.is_empty())
        .map(|h| h.to_ascii_lowercase())
        .collect();
    if headers.is_empty() {
        return Err(AuthError::MalformedAuth("SignedHeaders must list >=1 header"));
    }

    Ok(ParsedAuth {
        access_key:     parts[0].to_owned(),
        scope_date:     parts[1].to_owned(),
        scope_region:   parts[2].to_owned(),
        scope_service:  parts[3].to_owned(),
        signed_headers: headers,
        signature:      signature.to_owned(),
    })
}

/// Parse the compact ISO-8601 timestamp S3 clients emit in `x-amz-date`
/// (`YYYYMMDDTHHMMSSZ`). Uses `time` rather than a hand-rolled calendar.
pub fn parse_amz_date(s: &str) -> Result<SystemTime, AuthError> {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    use time::PrimitiveDateTime;

    const FMT: &[FormatItem<'static>] =
        format_description!("[year][month][day]T[hour][minute][second]Z");

    let pdt = PrimitiveDateTime::parse(s, &FMT)
        .map_err(|e| AuthError::BadDate(format!("{s:?}: {e}")))?;
    let offset_dt = pdt.assume_utc();
    let unix      = offset_dt.unix_timestamp();
    if unix < 0 {
        return Err(AuthError::BadDate(format!("{s:?}: pre-epoch")));
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(unix as u64))
}

/// Reject requests whose timestamp drifted more than 15 minutes from the
/// server clock (standard S3 tolerance).
pub fn check_skew(request_time: SystemTime) -> Result<(), AuthError> {
    let now  = SystemTime::now();
    let skew = now.duration_since(request_time)
        .unwrap_or_else(|e| e.duration());
    if skew > MAX_CLOCK_SKEW {
        Err(AuthError::RequestTimeSkewed)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Presigned URL (query-parameter SigV4)
// ---------------------------------------------------------------------------

/// The fields a presigned URL carries in its query string. The wire
/// shape is exactly what `aws_sigv4::http_request::sign` emits when
/// invoked with `SignatureLocation::QueryParams`, so verification is
/// just a re-sign and a constant-time compare.
#[derive(Debug, Clone)]
pub struct PresignedQuery {
    pub access_key:     String,
    pub scope_date:     String,
    pub scope_region:   String,
    pub scope_service:  String,
    pub signed_headers: Vec<String>,
    pub signature:      String,
    pub request_time:   SystemTime,
    /// Lifetime of the URL in seconds. AWS caps this at 604800 (7 d);
    /// anything outside `[1, 604800]` is rejected.
    pub expires:        u64,
}

/// Cheap probe: does this URI carry the X-Amz-* parameters that mark a
/// presigned-URL request? Used by the S3 frontend to decide whether to
/// dispatch into the header path or the presigned path.
pub fn has_presigned_query_params(uri: &http::Uri) -> bool {
    let q = match uri.query() {
        Some(q) => q,
        None    => return false,
    };
    q.split('&').any(|pair| {
        let key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        key.eq_ignore_ascii_case("X-Amz-Algorithm")
    })
}

/// Pull the X-Amz-* fields out of a request URI. Returns
/// `MalformedPresigned` if any required field is missing or shaped wrong;
/// `BadAlgorithm` only if `X-Amz-Algorithm` is present but not
/// `AWS4-HMAC-SHA256`; `BadExpires` if `X-Amz-Expires` is outside
/// `[1, 604800]`.
pub fn parse_presigned_query(uri: &http::Uri) -> Result<PresignedQuery, AuthError> {
    let raw_query = uri.query()
        .ok_or(AuthError::MalformedPresigned("missing query string"))?;

    let mut algorithm     : Option<String> = None;
    let mut credential    : Option<String> = None;
    let mut date          : Option<String> = None;
    let mut expires       : Option<String> = None;
    let mut signed_hdrs   : Option<String> = None;
    let mut signature     : Option<String> = None;

    for pair in raw_query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None         => continue,
        };
        // Both halves are percent-encoded; the canonical decoded form is
        // what `aws_sigv4` produced so we decode here.
        let v_dec = percent_decode(v);
        match k {
            "X-Amz-Algorithm"     => algorithm   = Some(v_dec),
            "X-Amz-Credential"    => credential  = Some(v_dec),
            "X-Amz-Date"          => date        = Some(v_dec),
            "X-Amz-Expires"       => expires     = Some(v_dec),
            "X-Amz-SignedHeaders" => signed_hdrs = Some(v_dec),
            "X-Amz-Signature"     => signature   = Some(v_dec),
            _ => {}
        }
    }

    let algorithm   = algorithm  .ok_or(AuthError::MalformedPresigned("X-Amz-Algorithm missing"))?;
    let credential  = credential .ok_or(AuthError::MalformedPresigned("X-Amz-Credential missing"))?;
    let date        = date       .ok_or(AuthError::MalformedPresigned("X-Amz-Date missing"))?;
    let expires_raw = expires    .ok_or(AuthError::MalformedPresigned("X-Amz-Expires missing"))?;
    let signed_hdrs = signed_hdrs.ok_or(AuthError::MalformedPresigned("X-Amz-SignedHeaders missing"))?;
    let signature   = signature  .ok_or(AuthError::MalformedPresigned("X-Amz-Signature missing"))?;

    if algorithm != ALGORITHM {
        return Err(AuthError::BadAlgorithm(algorithm));
    }

    let expires: u64 = expires_raw.parse()
        .map_err(|_| AuthError::MalformedPresigned("X-Amz-Expires not an integer"))?;
    if expires == 0 || expires > 604_800 {
        return Err(AuthError::BadExpires(expires));
    }

    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(AuthError::MalformedPresigned("X-Amz-Credential scope has wrong shape"));
    }

    let headers: Vec<String> = signed_hdrs
        .split(';')
        .filter(|h| !h.is_empty())
        .map(|h| h.to_ascii_lowercase())
        .collect();
    if headers.is_empty() {
        return Err(AuthError::MalformedPresigned("X-Amz-SignedHeaders must list >=1 header"));
    }

    let request_time = parse_amz_date(&date)?;

    Ok(PresignedQuery {
        access_key:     parts[0].to_owned(),
        scope_date:     parts[1].to_owned(),
        scope_region:   parts[2].to_owned(),
        scope_service:  parts[3].to_owned(),
        signed_headers: headers,
        signature,
        request_time,
        expires,
    })
}

/// Verify a presigned URL: check expiry window, then re-sign with our
/// stored secret using `SignatureLocation::QueryParams` and compare.
///
/// `path_and_query` is the full `?…` URI as received on the wire — the
/// X-Amz-* parameters this function strips before re-signing are
/// reproduced internally by `aws_sigv4::sign`. Non-X-Amz query params
/// (e.g. `versionId=...`, `list-type=2`) stay in the canonical request.
#[allow(clippy::too_many_arguments)]
pub fn verify_presigned(
    method:         &str,
    uri:            &http::Uri,
    headers:        &HeaderMap,
    parsed:         &PresignedQuery,
    secret:         &str,
    server_region:  &str,
) -> Result<(), AuthError> {
    if parsed.scope_region != server_region {
        return Err(AuthError::RegionMismatch {
            req:    parsed.scope_region.clone(),
            server: server_region.to_owned(),
        });
    }
    if parsed.scope_service != SERVICE {
        return Err(AuthError::BadService(parsed.scope_service.clone()));
    }
    if parsed.scope_date.len() < 8 || parsed.scope_date.len() > 8 {
        return Err(AuthError::MalformedPresigned("X-Amz-Credential date must be YYYYMMDD"));
    }

    // Expiry window. Two checks: not in the future beyond skew, and
    // already past expiry. AWS uses `request_time + expires` strictly.
    let now = SystemTime::now();
    if let Ok(skew) = parsed.request_time.duration_since(now) {
        if skew > MAX_CLOCK_SKEW {
            return Err(AuthError::RequestTimeSkewed);
        }
    }
    let expiry_at = parsed.request_time + Duration::from_secs(parsed.expires);
    if now > expiry_at {
        return Err(AuthError::PresignedExpired);
    }

    // Strip every X-Amz-* parameter from the query string before
    // re-signing — `aws_sigv4` will add them back from `SigningSettings`.
    // Anything else (versionId, list-type, prefix, …) stays put because
    // the client signed the URI with those still present.
    let stripped_path_and_query = strip_amz_query_params(uri);

    let filtered: Vec<(String, String)> = parsed.signed_headers.iter()
        .filter_map(|name| {
            let value = headers.get(name.as_str())?.to_str().ok()?;
            Some((name.clone(), value.to_owned()))
        })
        .collect();

    let mut settings = s3_signing_settings();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in         = Some(Duration::from_secs(parsed.expires));

    let identity: Identity = Credentials::new(
        &parsed.access_key, secret, None, None, "phenomenal-config",
    ).into();
    let v4_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(server_region)
        .name(SERVICE)
        .time(parsed.request_time)
        .settings(settings)
        .build()
        .map_err(|e| AuthError::Signer(format!("build signing params: {e}")))?;
    let signing_params: SigningParams<'_> = v4_params.into();

    // Presigned URLs always commit to UNSIGNED-PAYLOAD as the body
    // hash inside the canonical request — the URL was generated with
    // no body in hand, so we must re-sign with the same assumption.
    let signable = SignableRequest::new(
        method,
        stripped_path_and_query,
        filtered.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::UnsignedPayload,
    ).map_err(|e| AuthError::Signer(format!("build signable request: {e}")))?;

    let output = sign(signable, &signing_params)
        .map_err(|e| AuthError::Signer(format!("sign: {e}")))?;

    if constant_time_eq(output.signature().as_bytes(), parsed.signature.as_bytes()) {
        Ok(())
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

/// Return `path?query` with every `X-Amz-*` parameter removed. Other
/// query parameters retain their original order and encoding.
fn strip_amz_query_params(uri: &http::Uri) -> String {
    let path = uri.path();
    let query = match uri.query() {
        Some(q) => q,
        None    => return path.to_owned(),
    };

    let kept: Vec<&str> = query.split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
            !key.starts_with("X-Amz-") && !key.starts_with("x-amz-")
        })
        .collect();

    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

/// Minimal RFC 3986 percent-decoder. `aws_sigv4` accepts decoded values
/// in `SignableRequest`, and X-Amz-Credential routinely encodes its `/`
/// separators as `%2F`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_nibble(bytes[i + 1]),
                hex_nibble(bytes[i + 2]),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _           => None,
    }
}

/// Verify the seed (request-line) SigV4 signature against the server's
/// stored secret for `parsed.access_key`. `body` describes how to hash
/// the payload inside the canonical request:
///
///   - `SignableBody::UnsignedPayload` for `UNSIGNED-PAYLOAD` requests
///   - `SignableBody::Precomputed(hex)` for single-shot signed payloads
///     (passing the client-declared sha256)
///   - `SignableBody::Precomputed("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")`
///     for streaming chunked uploads (seed signature only)
#[allow(clippy::too_many_arguments)]
pub fn verify_seed(
    method:         &str,
    path_and_query: &str,
    headers:        &HeaderMap,
    parsed:         &ParsedAuth,
    secret:         &str,
    server_region:  &str,
    request_time:   SystemTime,
    body:           SignableBody<'_>,
) -> Result<(), AuthError> {
    if parsed.scope_region != server_region {
        return Err(AuthError::RegionMismatch {
            req:    parsed.scope_region.clone(),
            server: server_region.to_owned(),
        });
    }
    if parsed.scope_service != SERVICE {
        return Err(AuthError::BadService(parsed.scope_service.clone()));
    }

    // Restrict the canonical-headers set to exactly the headers the
    // client listed in SignedHeaders. Any extra headers present on the
    // wire (e.g. amz-sdk-invocation-id, Accept) would otherwise leak
    // into the canonical request and break the signature match.
    let filtered: Vec<(String, String)> = parsed.signed_headers.iter()
        .filter_map(|name| {
            let value = headers.get(name.as_str())?.to_str().ok()?;
            Some((name.clone(), value.to_owned()))
        })
        .collect();

    let identity: Identity = Credentials::new(
        &parsed.access_key, secret, None, None, "phenomenal-config",
    ).into();
    let settings           = s3_signing_settings();
    let signing_params     = v4::SigningParams::builder()
        .identity(&identity)
        .region(server_region)
        .name(SERVICE)
        .time(request_time)
        .settings(settings)
        .build()
        .map_err(|e| AuthError::Signer(format!("build signing params: {e}")))?;
    let signing_params: SigningParams<'_> = signing_params.into();

    let signable = SignableRequest::new(
        method,
        path_and_query.to_owned(),
        filtered.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body,
    ).map_err(|e| AuthError::Signer(format!("build signable request: {e}")))?;

    let output = sign(signable, &signing_params)
        .map_err(|e| AuthError::Signer(format!("sign: {e}")))?;

    if constant_time_eq(output.signature().as_bytes(), parsed.signature.as_bytes()) {
        Ok(())
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

/// SigningSettings that mirror how AWS S3 clients sign. S3-specific
/// quirks that differ from the library default:
///   * single (not double) percent-encoding of the path
///   * URI path normalization disabled (object keys are arbitrary bytes)
///   * `x-amz-content-sha256` is part of the canonical request
fn s3_signing_settings() -> SigningSettings {
    let mut s = SigningSettings::default();
    s.percent_encoding_mode       = PercentEncodingMode::Single;
    s.payload_checksum_kind       = PayloadChecksumKind::XAmzSha256;
    s.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    s.session_token_mode          = SessionTokenMode::Include;
    s
}

/// Verify a single aws-chunked body chunk against its advertised
/// `chunk-signature`, chained off `prev_signature`. Returns the new
/// running signature on success so the caller can feed it forward to the
/// next chunk.
pub fn verify_chunk(
    chunk:           &[u8],
    prev_signature:  &str,
    given_signature: &str,
    access_key:      &str,
    secret:          &str,
    region:          &str,
    request_time:    SystemTime,
) -> Result<String, AuthError> {
    let identity: Identity = Credentials::new(
        access_key, secret, None, None, "phenomenal-config",
    ).into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(SERVICE)
        .time(request_time)
        .settings(())
        .build()
        .map_err(|e| AuthError::Signer(format!("build streaming params: {e}")))?;

    let payload = Bytes::copy_from_slice(chunk);
    let output  = v4::sign_chunk(&payload, prev_signature, &params)
        .map_err(|e| AuthError::Signer(format!("sign_chunk: {e}")))?;

    if constant_time_eq(output.signature().as_bytes(), given_signature.as_bytes()) {
        Ok(output.signature().to_string())
    } else {
        Err(AuthError::ChunkSignatureMismatch)
    }
}

/// Constant-time byte comparison; avoids timing oracles in signature checks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Streaming SigV4 verifier (single-shot signed body)
//
// `Sha256VerifyStream` wraps a source `ByteStream` and tees its bytes
// through a streaming `Sha256`. On EOF it compares the digest against
// the `x-amz-content-sha256` value the client advertised and surfaces
// a decode error if they diverge.
//
// The per-chunk path for `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` lives in
// `s3::body_source::ChunkedBodyStream`, which calls `verify_chunk`
// for every chunk it pulls.
// ---------------------------------------------------------------------------

use phenomenal_io::stream::ByteStream;
use phenomenal_io::IoResult;

pub struct Sha256VerifyStream<S: ByteStream> {
    inner:    S,
    expected: [u8; 64],     // hex digits, lowercase
    hasher:   Sha256,
    eof:      bool,
}

impl<S: ByteStream> Sha256VerifyStream<S> {
    pub fn new(inner: S, expected_hex: &str) -> Result<Self, AuthError> {
        if expected_hex.len() != 64 {
            return Err(AuthError::UnsupportedContentSha(expected_hex.to_owned()));
        }
        let mut e = [0u8; 64];
        for (i, b) in expected_hex.as_bytes().iter().enumerate() {
            e[i] = b.to_ascii_lowercase();
        }
        Ok(Self { inner, expected: e, hasher: Sha256::new(), eof: false })
    }
}

#[async_trait::async_trait(?Send)]
impl<S: ByteStream> ByteStream for Sha256VerifyStream<S> {
    async fn read(&mut self) -> IoResult<bytes::Bytes> {
        if self.eof {
            return Ok(bytes::Bytes::new());
        }
        let chunk = self.inner.read().await?;
        if !chunk.is_empty() {
            self.hasher.update(&chunk);
            return Ok(chunk);
        }
        // EOF — finalise and compare.
        self.eof = true;
        let digest = std::mem::replace(&mut self.hasher, Sha256::new()).finalize();
        let mut got = [0u8; 64];
        hex::encode_to_slice(digest, &mut got).expect("32 bytes -> 64 hex");
        if !constant_time_eq(&got, &self.expected) {
            return Err(phenomenal_io::IoError::Decode("sha256 mismatch".into()));
        }
        Ok(bytes::Bytes::new())
    }
}

pub(crate) fn find_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 { return None; }
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sigv4::http_request::{sign as client_sign, SignableBody};

    fn test_state() -> AuthState {
        AuthState::new(
            "us-east-1".into(),
            &[Credential {
                access_key: "AKIAPHENOMENAL".into(),
                secret_key: "secretsecretsecret".into(),
            }],
        )
    }

    #[test]
    fn parses_canonical_auth_header() {
        let h = "AWS4-HMAC-SHA256 \
            Credential=AKIAPHENOMENAL/20260101/us-east-1/s3/aws4_request, \
            SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
            Signature=deadbeef";
        let p = parse_authorization(h).unwrap();
        assert_eq!(p.access_key,    "AKIAPHENOMENAL");
        assert_eq!(p.scope_date,    "20260101");
        assert_eq!(p.scope_region,  "us-east-1");
        assert_eq!(p.scope_service, "s3");
        assert_eq!(p.signed_headers, vec!["host", "x-amz-content-sha256", "x-amz-date"]);
        assert_eq!(p.signature,     "deadbeef");
    }

    #[test]
    fn rejects_wrong_algorithm() {
        let err = parse_authorization("AWS3-HMAC-SHA256 Credential=a/b/c/s3/aws4_request, SignedHeaders=host, Signature=x")
            .unwrap_err();
        assert!(matches!(err, AuthError::MalformedAuth(_)));
    }

    #[test]
    fn parses_amz_date_round_trip() {
        let t = parse_amz_date("20260101T120000Z").unwrap();
        // Re-format with time crate to make sure it's what we expect.
        let dt = time::OffsetDateTime::from(t);
        assert_eq!(dt.year(), 2026);
        assert_eq!(u8::from(dt.month()), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 12);
    }

    #[test]
    fn seed_round_trips_with_unsigned_payload() {
        // Sign a fake request as a client would, then verify it — round-trip.
        let state        = test_state();
        let request_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
        let identity: Identity = Credentials::new(
            "AKIAPHENOMENAL", "secretsecretsecret", None, None, "test",
        ).into();
        let settings = s3_signing_settings();
        let params = v4::SigningParams::builder()
            .identity(&identity).region("us-east-1").name("s3")
            .time(request_time).settings(settings).build().unwrap();
        let params: SigningParams = params.into();

        let signable = SignableRequest::new(
            "PUT",
            "/bucket/key",
            [
                ("host", "example.com:9000"),
                ("x-amz-date", "20260101T000000Z"),
                ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ].into_iter(),
            SignableBody::UnsignedPayload,
        ).unwrap();
        let out = client_sign(signable, &params).unwrap();
        let client_sig = out.signature().to_string();

        // Build the Authorization header the client would send.
        let auth_hdr = format!(
            "AWS4-HMAC-SHA256 Credential=AKIAPHENOMENAL/20260101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={client_sig}"
        );
        let parsed = parse_authorization(&auth_hdr).unwrap();

        let mut hdrs = HeaderMap::new();
        hdrs.insert("host",                 "example.com:9000".parse().unwrap());
        hdrs.insert("x-amz-date",            "20260101T000000Z".parse().unwrap());
        hdrs.insert("x-amz-content-sha256",  "UNSIGNED-PAYLOAD".parse().unwrap());

        verify_seed(
            "PUT", "/bucket/key", &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
            request_time,
            SignableBody::UnsignedPayload,
        ).unwrap();
    }

    #[test]
    fn seed_mismatch_rejects() {
        let state        = test_state();
        let request_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        let parsed = ParsedAuth {
            access_key:     "AKIAPHENOMENAL".into(),
            scope_date:     "20260101".into(),
            scope_region:   "us-east-1".into(),
            scope_service:  "s3".into(),
            signed_headers: vec!["host".into(), "x-amz-date".into(), "x-amz-content-sha256".into()],
            signature:      "0000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let mut hdrs = HeaderMap::new();
        hdrs.insert("host",                 "example.com:9000".parse().unwrap());
        hdrs.insert("x-amz-date",            "20260101T000000Z".parse().unwrap());
        hdrs.insert("x-amz-content-sha256",  "UNSIGNED-PAYLOAD".parse().unwrap());

        let err = verify_seed(
            "PUT", "/bucket/key", &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
            request_time,
            SignableBody::UnsignedPayload,
        ).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn verify_chunk_round_trips_and_rejects_tamper() {
        use aws_sigv4::sign::v4::sign_chunk;
        let region = "us-east-1";
        let access = "AKIAPHENOMENAL";
        let secret = "secretsecretsecret";
        let time_  = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);

        let identity: Identity = Credentials::new(access, secret, None, None, "test").into();
        let params = v4::SigningParams::builder()
            .identity(&identity).region(region).name(SERVICE)
            .time(time_).settings(()).build().unwrap();

        let seed_sig = "f".repeat(64);
        let chunk    = Bytes::from_static(b"payload");
        let sig      = sign_chunk(&chunk, &seed_sig, &params).unwrap().signature().to_string();

        // Correct chunk + signature → succeeds and yields the next running sig.
        let next = verify_chunk(&chunk, &seed_sig, &sig, access, secret, region, time_).unwrap();
        assert_eq!(next, sig);

        // Tampered payload → ChunkSignatureMismatch.
        let err = verify_chunk(b"tampere", &seed_sig, &sig, access, secret, region, time_)
            .unwrap_err();
        assert!(matches!(err, AuthError::ChunkSignatureMismatch));
    }

    // ---- Presigned URL ---------------------------------------------------

    /// Drive `aws_sigv4::http_request::sign` with `QueryParams` to
    /// produce the same signature an SDK would compute for a presigned
    /// URL. Returns the URI shape `path?X-Amz-... &X-Amz-Signature=hex`.
    fn presign(
        method:       &str,
        path_and_query: &str,
        host:         &str,
        access:       &str,
        secret:       &str,
        region:       &str,
        time:         SystemTime,
        expires:      Duration,
    ) -> String {
        let mut settings = s3_signing_settings();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in         = Some(expires);

        let identity: Identity = Credentials::new(
            access, secret, None, None, "test",
        ).into();
        let v4_params = v4::SigningParams::builder()
            .identity(&identity).region(region).name(SERVICE)
            .time(time).settings(settings).build().unwrap();
        let signing_params: SigningParams<'_> = v4_params.into();

        let signable = SignableRequest::new(
            method,
            path_and_query.to_owned(),
            [("host", host)].into_iter(),
            SignableBody::UnsignedPayload,
        ).unwrap();

        let (instructions, _sig) = client_sign(signable, &signing_params).unwrap().into_parts();
        let extra: Vec<(&str, std::borrow::Cow<'static, str>)> =
            instructions.params().to_vec();

        // Build URI: existing query (if any) + appended X-Amz-* params.
        let mut out = path_and_query.to_owned();
        let separator = if out.contains('?') { '&' } else { '?' };
        out.push(separator);
        out.push_str(&extra.iter()
            .map(|(k, v)| format!("{}={}", k, urlencode(v)))
            .collect::<Vec<_>>()
            .join("&"));
        out
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            let unreserved = b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'_' | b'.' | b'~');
            if unreserved {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    #[test]
    fn presigned_round_trip_get() {
        let state = test_state();

        // Sign 60s ago so the verifier's expiry check (which uses
        // SystemTime::now) sees a still-valid URL. We can't mock the
        // clock without an injection point, so we sign relative to it.
        let now_time = SystemTime::now() - Duration::from_secs(60);
        let uri_str = presign(
            "GET", "/bucket/key", "example.com:9000",
            "AKIAPHENOMENAL", "secretsecretsecret",
            "us-east-1", now_time, Duration::from_secs(3600),
        );
        let uri: http::Uri = uri_str.parse().unwrap();

        let parsed = parse_presigned_query(&uri).unwrap();
        assert_eq!(parsed.access_key, "AKIAPHENOMENAL");
        assert_eq!(parsed.scope_region, "us-east-1");

        let mut hdrs = HeaderMap::new();
        hdrs.insert("host", "example.com:9000".parse().unwrap());

        verify_presigned(
            "GET", &uri, &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
        ).unwrap();
    }

    #[test]
    fn presigned_rejects_tampered_signature() {
        let state = test_state();
        let now_time = SystemTime::now() - Duration::from_secs(60);
        let uri_str = presign(
            "GET", "/bucket/key", "example.com:9000",
            "AKIAPHENOMENAL", "secretsecretsecret",
            "us-east-1", now_time, Duration::from_secs(3600),
        );
        // Flip one nibble of the signature.
        let mut bad = uri_str.clone();
        let sig_pos = bad.find("X-Amz-Signature=").unwrap() + "X-Amz-Signature=".len();
        let bad_byte = (bad.as_bytes()[sig_pos] ^ 0x01) as char;
        bad.replace_range(sig_pos..sig_pos+1, &bad_byte.to_string());

        let uri: http::Uri = bad.parse().unwrap();
        let parsed = parse_presigned_query(&uri).unwrap();
        let mut hdrs = HeaderMap::new();
        hdrs.insert("host", "example.com:9000".parse().unwrap());

        let err = verify_presigned(
            "GET", &uri, &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
        ).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn presigned_rejects_expired_url() {
        let state = test_state();
        // Signed 2 hours ago with 1 hour expiry → expired by 1 hour.
        let signed_at = SystemTime::now() - Duration::from_secs(2 * 3600);
        let uri_str = presign(
            "GET", "/bucket/key", "example.com:9000",
            "AKIAPHENOMENAL", "secretsecretsecret",
            "us-east-1", signed_at, Duration::from_secs(3600),
        );
        let uri: http::Uri = uri_str.parse().unwrap();
        let parsed = parse_presigned_query(&uri).unwrap();
        let mut hdrs = HeaderMap::new();
        hdrs.insert("host", "example.com:9000".parse().unwrap());

        let err = verify_presigned(
            "GET", &uri, &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
        ).unwrap_err();
        assert!(matches!(err, AuthError::PresignedExpired));
    }

    #[test]
    fn presigned_rejects_wrong_region() {
        let state = test_state(); // server expects us-east-1
        let now_time = SystemTime::now() - Duration::from_secs(60);
        let uri_str = presign(
            "GET", "/bucket/key", "example.com:9000",
            "AKIAPHENOMENAL", "secretsecretsecret",
            "eu-west-1",                                        // different region
            now_time, Duration::from_secs(3600),
        );
        let uri: http::Uri = uri_str.parse().unwrap();
        let parsed = parse_presigned_query(&uri).unwrap();
        let mut hdrs = HeaderMap::new();
        hdrs.insert("host", "example.com:9000".parse().unwrap());

        let err = verify_presigned(
            "GET", &uri, &hdrs, &parsed,
            state.secret_for("AKIAPHENOMENAL").unwrap(),
            state.region(),
        ).unwrap_err();
        assert!(matches!(err, AuthError::RegionMismatch { .. }));
    }

    #[test]
    fn has_presigned_query_params_detects_x_amz_algorithm() {
        let with_q: http::Uri = "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260425T000000Z"
            .parse().unwrap();
        assert!(has_presigned_query_params(&with_q));

        let without:  http::Uri = "/bucket/key?versionId=abc".parse().unwrap();
        assert!(!has_presigned_query_params(&without));

        let no_query: http::Uri = "/bucket/key".parse().unwrap();
        assert!(!has_presigned_query_params(&no_query));
    }

    #[test]
    fn strip_amz_query_params_keeps_other_params() {
        let uri: http::Uri = "/bucket/key?versionId=abc&X-Amz-Date=foo&list-type=2&X-Amz-Signature=bar"
            .parse().unwrap();
        let s = strip_amz_query_params(&uri);
        assert!(s.contains("versionId=abc"));
        assert!(s.contains("list-type=2"));
        assert!(!s.contains("X-Amz-Date"));
        assert!(!s.contains("X-Amz-Signature"));
    }
}
