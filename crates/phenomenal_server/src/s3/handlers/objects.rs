//! Object-scoped S3 endpoints.
//!
//!   * `GET    /{bucket}/{key}`   stream object body to client
//!   * `HEAD   /{bucket}/{key}`   stat (size + etag + last-modified)
//!   * `DELETE /{bucket}/{key}`   tombstone object
//!   * `PUT    /{bucket}/{key}`   pending — needs streaming SigV4
//!                                body adapter (returns 501 for now)

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_TYPE, ETAG, LAST_MODIFIED};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use send_wrapper::SendWrapper;
use serde::Deserialize;

use phenomenal_io::stream::ByteStream;
use phenomenal_io::VersioningStatus;
use phenomenal_storage::ObjectInfo;

use crate::auth::AuthError;
use crate::s3::body_source::BodySource;
use crate::s3::error::AppError;
use crate::s3::state::AppState;

// `x-amz-content-sha256` mode markers — kept in sync with
// `middleware::sigv4`. Seed verification recognises all of them; the
// PUT handler implements the simple ones (UNSIGNED + hex-sha256) and
// rejects the streaming variants with a mode-specific 501.
const SHA_UNSIGNED:                   &str = "UNSIGNED-PAYLOAD";
const SHA_STREAMING:                  &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const SHA_STREAMING_TRAILER:          &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const SHA_STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Query string accepted on object-scoped GET / HEAD endpoints. Today
/// only `versionId` is consumed; the field set lives here so future
/// flags (`partNumber`, `response-content-type`, etc.) slot in without
/// touching every handler signature.
#[derive(Debug, Default, Deserialize)]
pub struct ObjectQuery {
    #[serde(default, rename = "versionId")]
    pub version_id: Option<String>,
}

// todo: @arnav implement multi-part (multipart upload + ?partNumber on GET)
pub async fn get_object(
    State(state):       State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query):       Query<ObjectQuery>,
) -> Result<Response, AppError> {
    // Normalize + validate ?versionId. Acceptable inputs match MinIO:
    //   * absent or empty                  → latest version
    //   * literal "null"                   → the null version
    //   * a parseable UUID (with dashes)   → that specific version
    // Anything else is rejected with 400 InvalidVersionID before any
    // engine work runs.
    let version_id = parse_version_id(query.version_id.as_deref())?;

    let engine = state.engine().clone();
    let (info, byte_stream) = SendWrapper::new(async move {
        match version_id.as_deref() {
            None       => engine.get(&bucket, &key).await,
            Some(vid)  => engine.get_version(&bucket, &key, vid).await,
        }
    })
    .await?;

    Ok(stream_object_response(info, byte_stream))
}

/// `?versionId=...` validation — mirrors MinIO's `getOpts` (cmd/object-api-options.go:101-110).
///
/// Returns:
///   * `Ok(None)`            — no version requested; serve the latest.
///   * `Ok(Some("null"))`    — the null version (unversioned bucket key, or the literal AWS sentinel).
///   * `Ok(Some(uuid_str))`  — a specific UUID-tagged version.
///   * `Err(InvalidVersionID)` — anything else (garbage, wrong length, non-hex chars).
fn parse_version_id(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let s = match raw {
        None    => return Ok(None),
        Some(s) => s.trim(),
    };
    if s.is_empty() {
        return Ok(None);
    }
    if s == VersioningStatus::NULL_VERSION_ID {
        return Ok(Some(s.to_owned()));
    }
    // UUID validation: 32 hex chars after stripping dashes (matches the
    // canonical 8-4-4-4-12 layout). Cheap parse — no allocation per char.
    let hex_chars = s.chars().filter(|c| *c != '-').count();
    let all_hex   = s.chars().all(|c| c == '-' || c.is_ascii_hexdigit());
    if hex_chars == 32 && all_hex {
        return Ok(Some(s.to_owned()));
    }
    Err(AppError::BadRequest(
        "invalid versionId: must be empty, the literal \"null\", or a canonical UUID",
    ))
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let engine = state.engine().clone();
    let info = SendWrapper::new(async move {
        engine.stat(&bucket, &key).await
    })
    .await?;

    let mut headers = HeaderMap::new();
    populate_object_headers(&mut headers, &info);
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from(info.size),
    );
    Ok((StatusCode::OK, headers, Body::empty()).into_response())
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let engine = state.engine().clone();
    SendWrapper::new(async move {
        engine.delete(&bucket, &key).await
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /{bucket}?delete  — DeleteObjects (batch object delete)
// ---------------------------------------------------------------------------
//
// URL is bucket-scoped because the request carries N keys in the body
// (no single primary key fits in the URL). The operation itself is
// purely object-scoped — bucket directory and unlisted objects are
// untouched. Lives in this module alongside the rest of the object
// CRUD handlers.

const DELETE_OBJECTS_MAX_KEYS: usize = 1000;

pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    headers:      HeaderMap,
    body:         Body,
) -> Result<Response, AppError> {
    let content_length: usize = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::Malformed("DeleteObjects requires Content-Length"))?;

    // S3 requires Content-MD5 (or x-amz-checksum-*) on DeleteObjects so
    // a tampered body is detected. We accept either; absence of both
    // is a 400.
    let supplied_md5 = headers
        .get(axum::http::header::CONTENT_MD5)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let supplied_sha256 = headers
        .get("x-amz-checksum-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if supplied_md5.is_none() && supplied_sha256.is_none() {
        return Err(AppError::Malformed(
            "DeleteObjects requires Content-MD5 or x-amz-checksum-sha256",
        ));
    }

    let bytes = axum::body::to_bytes(body, content_length).await
        .map_err(|_| AppError::Malformed("DeleteObjects body unreadable"))?;

    if let Some(expected_md5) = supplied_md5.as_deref() {
        let actual_md5 = base64::engine::general_purpose::STANDARD
            .encode(md5::compute(bytes.as_ref()).as_ref());
        if actual_md5 != expected_md5 {
            return Err(AppError::Malformed("Content-MD5 does not match request body"));
        }
    }

    let request: DeleteRequest = quick_xml::de::from_reader(bytes.as_ref())
        .map_err(|_| AppError::Malformed("invalid <Delete> XML"))?;

    if request.objects.is_empty() {
        return Err(AppError::Malformed("<Delete> must contain at least one <Object>"));
    }
    if request.objects.len() > DELETE_OBJECTS_MAX_KEYS {
        return Err(AppError::Malformed(
            "<Delete> exceeds the 1000-key limit",
        ));
    }

    let quiet  = request.quiet.unwrap_or(false);
    let engine = state.engine().clone();

    // Per-key deletes run in parallel, bounded so a 1000-key request
    // doesn't fan out 1000 concurrent dsync acquires. 32 in flight is
    // enough to saturate cluster throughput without overwhelming the
    // lock service.
    use futures_util::stream::{self as fstream, StreamExt};
    let bucket = bucket.clone();
    let result = SendWrapper::new(async move {
        fstream::iter(request.objects.into_iter())
            .map(|obj| {
                let engine = engine.clone();
                let bucket = bucket.clone();
                async move {
                    let res = engine.delete(&bucket, &obj.key).await;
                    (obj.key, obj.version_id, res)
                }
            })
            .buffer_unordered(32)
            .collect::<Vec<_>>()
            .await
    })
    .await;

    let mut deleted = Vec::new();
    let mut errors  = Vec::new();
    for (key, version_id, res) in result {
        match res {
            Ok(())  => {
                if !quiet {
                    deleted.push(DeletedEntry { key, version_id });
                }
            }
            Err(e) => {
                let (code, message) = storage_error_to_s3_code(&e);
                errors.push(ErrorEntry { key, version_id, code, message });
            }
        }
    }

    let response = DeleteResult { deleted, errors };
    Ok(crate::s3::xml::Xml(response).into_response())
}

fn storage_error_to_s3_code(e: &phenomenal_storage::error::StorageError) -> (String, String) {
    use phenomenal_storage::error::StorageError;
    match e {
        StorageError::ObjectNotFound { .. }          => ("NoSuchKey".into(),       e.to_string()),
        StorageError::VersionNotFound { .. }         => ("NoSuchVersion".into(),   e.to_string()),
        StorageError::BucketNotFound(_)              => ("NoSuchBucket".into(),    e.to_string()),
        StorageError::InvalidObjectKey(_)            => ("InvalidArgument".into(), e.to_string()),
        StorageError::LockTimeout(_)                 => ("SlowDown".into(),        e.to_string()),
        StorageError::InsufficientOnlineDrives { .. } => ("ServiceUnavailable".into(), e.to_string()),
        _                                            => ("InternalError".into(),  e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Delete")]
struct DeleteRequest {
    #[serde(default, rename = "Quiet")]
    quiet: Option<bool>,
    #[serde(default, rename = "Object")]
    objects: Vec<DeleteRequestObject>,
}

#[derive(Debug, Deserialize)]
struct DeleteRequestObject {
    #[serde(rename = "Key")]
    key: String,
    #[serde(default, rename = "VersionId")]
    version_id: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename = "DeleteResult")]
pub struct DeleteResult {
    #[serde(rename = "Deleted")]
    deleted: Vec<DeletedEntry>,
    #[serde(rename = "Error")]
    errors: Vec<ErrorEntry>,
}

#[derive(Debug, serde::Serialize)]
struct DeletedEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId", skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ErrorEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId", skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

// ---------------------------------------------------------------------------
// PUT /{bucket}/{key}
// ---------------------------------------------------------------------------

/// Streaming PUT.
///
/// SigV4 seed verification has already run in the `sigv4` middleware
/// — we land here with `x-amz-content-sha256` describing how the body
/// is to be verified:
///
///   * `UNSIGNED-PAYLOAD` — body is signed only via the seed; pass
///     bytes through `BodySource::Plain` (no body hash check).
///   * hex-sha256 (single-shot signed) — `BodySource::HexSha` tees
///     bytes through a streaming SHA-256 and rejects on mismatch.
///   * `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked) — not yet
///     wired on the axum body path; rejected with 501 here. The
///     existing chunked-decoder in `auth::ChunkedSource` operates on
///     a raw `compio::io::AsyncRead` and needs to be ported to the
///     `ByteStream` trait before it can ride on top of axum's body.
pub async fn put_object(
    State(state):       State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    request:            Request<Body>,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();

    // Content-Length is required: this layer doesn't yet implement
    // chunked-transfer or auto-detect via aws-chunked decode.
    let content_length: u64 = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::Malformed("missing or invalid Content-Length"))?;

    // Body verification mode is dictated by `x-amz-content-sha256`.
    let content_sha = parts
        .headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Auth(AuthError::MissingContentSha))?
        .to_owned();

    // Streaming aws-chunked PUT: total payload size is the *decoded*
    // length declared in `x-amz-decoded-content-length` (the
    // `Content-Length` header counts the framed wire size including
    // chunk-header overhead).
    let decoded_len: Option<u64> = parts
        .headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Phenomenal accepts only BLAKE3 as the body-integrity algorithm.
    // Reject the legacy `Content-MD5` header outright — clients that
    // care about integrity must use `x-amz-checksum-blake3`.
    if parts.headers.contains_key("content-md5") {
        return Err(AppError::BadRequest(
            "Content-MD5 is not supported; use x-amz-checksum-blake3",
        ));
    }
    // One pass over the headers: any non-blake3 `x-amz-checksum-*`
    // rejects with 400; an `x-amz-checksum-blake3` header is captured
    // for post-PUT comparison against the engine's computed digest.
    let client_blake3 = extract_blake3_claim(&parts.headers)?;

    let (engine_size, mut body_src) = match content_sha.as_str() {
        SHA_UNSIGNED => (content_length, BodySource::plain(body)),
        SHA_STREAMING => {
            // Re-parse the Authorization header to recover the seed
            // signature (the rolling start of the per-chunk chain).
            // Middleware already verified seed validity, so any error
            // here is a logic bug rather than a real auth failure.
            let auth_hdr = parts
                .headers
                .get(http::header::AUTHORIZATION)
                .ok_or(AppError::Auth(AuthError::MissingAuth))?
                .to_str()
                .map_err(|_| AppError::Auth(AuthError::MalformedAuth("Authorization not ASCII")))?;
            let parsed_auth = crate::auth::parse_authorization(auth_hdr)
                .map_err(AppError::Auth)?;
            let amz_date = parts
                .headers
                .get("x-amz-date")
                .ok_or(AppError::Auth(AuthError::MissingDate))?
                .to_str()
                .map_err(|_| AppError::Auth(AuthError::BadDate("non-ASCII".into())))?;
            let request_time = crate::auth::parse_amz_date(amz_date).map_err(AppError::Auth)?;
            let secret = state
                .auth()
                .secret_for(&parsed_auth.access_key)
                .ok_or_else(|| AppError::Auth(AuthError::InvalidAccessKeyId(parsed_auth.access_key.clone())))?
                .to_owned();
            let region = state.auth().region().to_owned();
            let decoded = decoded_len.ok_or(AppError::Auth(AuthError::MissingDecodedContentLength))?;
            let src = BodySource::chunked(
                body,
                parsed_auth.signature.clone(),
                parsed_auth.access_key.clone(),
                secret,
                region,
                request_time,
            );
            (decoded, src)
        }
        SHA_STREAMING_TRAILER => {
            return Err(AppError::NotImplemented(
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER: chunked + \
                 trailer-header checksum mode pending implementation",
            ));
        }
        SHA_STREAMING_UNSIGNED_TRAILER => {
            return Err(AppError::NotImplemented(
                "STREAMING-UNSIGNED-PAYLOAD-TRAILER: chunked unsigned + \
                 trailer-header checksum mode pending implementation",
            ));
        }
        hex if is_hex_sha256(hex) => (
            content_length,
            BodySource::hex_sha(body, hex).map_err(|e| AppError::BadRequest(io_error_msg(e)))?,
        ),
        other => {
            return Err(AppError::Auth(AuthError::UnsupportedContentSha(
                other.to_owned(),
            )));
        }
    };

    let content_type: Option<String> = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let engine = state.engine().clone();
    let info = SendWrapper::new(async move {
        engine
            .put(&bucket, &key, engine_size, &mut body_src, content_type)
            .await
    })
    .await?;

    if let Some(claimed) = client_blake3 {
        if claimed != info.etag.to_ascii_lowercase() {
            let engine = state.engine().clone();
            let bucket = info.bucket.clone();
            let key    = info.key.clone();
            let _ = SendWrapper::new(async move {
                engine.delete(&bucket, &key).await
            }).await;
            return Err(AppError::BadRequest(
                "x-amz-checksum-blake3 mismatch: client-supplied digest does \
                 not match server-computed BLAKE3 of the body"
            ));
        }
    }

    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", info.etag)) {
        headers.insert(ETAG, v);
    }
    if !info.version_id.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&info.version_id) {
            headers.insert("x-amz-version-id", v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(&info.etag) {
        headers.insert("x-amz-checksum-blake3", v);
    }
    Ok((StatusCode::OK, headers).into_response())
}

fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Single pass over the request headers to enforce BLAKE3 as the
/// only accepted additional-checksum algorithm and return the
/// claimed digest if present.
///
/// Why one pass: the rejection check (`x-amz-checksum-<other>`) and
/// the extraction (`x-amz-checksum-blake3`) share a predicate, so
/// folding them avoids walking the header map twice and keeps the
/// algorithm policy in one place.
fn extract_blake3_claim(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let mut blake3: Option<String> = None;
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if !n.starts_with("x-amz-checksum-") {
            continue;
        }
        if n != "x-amz-checksum-blake3" {
            return Err(AppError::BadRequest(
                "only x-amz-checksum-blake3 is supported; other checksum \
                 algorithms (sha256/sha1/crc32/crc32c/crc64nvme/md5/sha512/\
                 xxhash*) are rejected — use blake3",
            ));
        }
        let hex = value
            .to_str()
            .map_err(|_| AppError::BadRequest("x-amz-checksum-blake3 not ASCII"))?
            .to_ascii_lowercase();
        blake3 = Some(hex);
    }
    Ok(blake3)
}

fn io_error_msg(e: phenomenal_io::IoError) -> &'static str {
    tracing::warn!(error = ?e, "PUT body initialization failed");
    "PUT body initialization failed"
}

fn stream_object_response(
    info: ObjectInfo,
    byte_stream: Box<dyn ByteStream>,
) -> Response {
    let total = info.size;
    let mut headers = HeaderMap::new();
    populate_object_headers(&mut headers, &info);
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from(total),
    );

    // Pull `Bytes` directly from the engine — zero copy on the GET
    // hot path. Each `body.read()` yields a refcounted slice (the
    // engine's stripe buffer freeze, the inline rope frame, etc.);
    // axum forwards it to the TLS layer without touching the bytes.
    let frames = SendWrapper::new(stream::unfold(
        (byte_stream, total, 0u64),
        move |(mut body, total, mut sent)| async move {
            if sent >= total {
                return None;
            }
            match body.read().await {
                Ok(chunk) if chunk.is_empty() => None,
                Ok(chunk) => {
                    // Bound the served chunk by `total - sent` so we
                    // never overshoot the declared content-length.
                    let take = (total - sent).min(chunk.len() as u64) as usize;
                    let frame = if take < chunk.len() {
                        bytes::Bytes::slice(&chunk, ..take)
                    } else {
                        chunk
                    };
                    sent += frame.len() as u64;
                    Some((
                        Ok::<bytes::Bytes, std::io::Error>(frame),
                        (body, total, sent),
                    ))
                }
                Err(e) => Some((
                    Err(std::io::Error::other(e.to_string())),
                    (body, total, sent),
                )),
            }
        },
    ));

    let body = Body::from_stream(frames);
    (StatusCode::OK, headers, body).into_response()
}

fn populate_object_headers(headers: &mut HeaderMap, info: &ObjectInfo) {
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", info.etag)) {
        headers.insert(ETAG, v);
    }
    // Algorithm-explicit checksum so clients that want to verify
    // know the digest type. `info.etag` IS the BLAKE3 hex.
    if let Ok(v) = HeaderValue::from_str(&info.etag) {
        headers.insert("x-amz-checksum-blake3", v);
    }
    if let Ok(v) = HeaderValue::from_str(&http_date_rfc1123(info.modified_ms)) {
        headers.insert(LAST_MODIFIED, v);
    }
    if let Some(ct) = &info.content_type {
        if let Ok(v) = HeaderValue::from_str(ct) {
            headers.insert(CONTENT_TYPE, v);
        }
    }
    // Echo the version_id so the client knows which version they got
    // back. Empty string means the engine had no opinion (e.g. an
    // older write that predated versioning); skip the header in that
    // case to avoid sending a literal empty `x-amz-version-id:` line.
    if !info.version_id.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&info.version_id) {
            headers.insert("x-amz-version-id", v);
        }
    }
}

/// RFC 1123 `Last-Modified` format (`Wed, 01 May 2026 12:00:00 GMT`).
fn http_date_rfc1123(ms: u64) -> String {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    use time::OffsetDateTime;

    const FMT: &[FormatItem<'static>] = format_description!(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] \
         [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT"
    );
    let secs = (ms / 1000) as i64;
    let dt = OffsetDateTime::from_unix_timestamp(secs)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    dt.format(&FMT).unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".into())
}
