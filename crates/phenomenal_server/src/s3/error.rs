//! Axum `IntoResponse` for our error types.
//!
//! Maps `AuthError` and `StorageError` onto the standard S3 XML error
//! envelope (`<Error><Code/><Message/><Resource/></Error>`) with the
//! correct HTTP status.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use phenomenal_storage::StorageError;

use crate::auth::AuthError;

/// One error kind covering every shape an S3 handler can return.
/// Variants match the S3 error-code taxonomy; mapping to HTTP status
/// and wire `Code` happens in `IntoResponse`.
#[derive(Debug)]
pub enum AppError {
    Auth(AuthError),
    Storage(StorageError),
    BadRequest(&'static str),
    Malformed(&'static str),
    NotImplemented(&'static str),
}

impl From<AuthError> for AppError {
    fn from(e: AuthError) -> Self { AppError::Auth(e) }
}
impl From<StorageError> for AppError {
    fn from(e: StorageError) -> Self { AppError::Storage(e) }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let resource = "";
        let (status, code, message) = match &self {
            AppError::Auth(e) => {
                let (status, code) = e.status_and_code();
                (status, code.to_owned(), e.to_string())
            }
            AppError::Storage(e) => map_storage(e),
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "BadRequest".into(),
                (*msg).into(),
            ),
            AppError::Malformed(msg) => (
                StatusCode::BAD_REQUEST,
                "MalformedRequest".into(),
                (*msg).into(),
            ),
            AppError::NotImplemented(msg) => (
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented".into(),
                (*msg).into(),
            ),
        };

        let body = encode_error_xml(&code, &message, resource);
        Response::builder()
            .status(status)
            .header(axum::http::header::CONTENT_TYPE, "application/xml")
            .body(axum::body::Body::from(body))
            .expect("response builder is infallible for static headers")
    }
}

fn map_storage(e: &StorageError) -> (StatusCode, String, String) {
    let (status, code) = match e {
        StorageError::ObjectNotFound { .. }            => (StatusCode::NOT_FOUND,            "NoSuchKey"),
        StorageError::VersionNotFound { .. }           => (StatusCode::NOT_FOUND,            "NoSuchVersion"),
        StorageError::BucketNotFound(_)                => (StatusCode::NOT_FOUND,            "NoSuchBucket"),
        StorageError::BucketAlreadyExists(_)           => (StatusCode::CONFLICT,             "BucketAlreadyExists"),
        StorageError::BucketNotEmpty(_)                => (StatusCode::CONFLICT,             "BucketNotEmpty"),
        StorageError::InvalidBucketName(_)             => (StatusCode::BAD_REQUEST,          "InvalidBucketName"),
        StorageError::InvalidObjectKey(_)              => (StatusCode::BAD_REQUEST,          "InvalidObjectName"),
        StorageError::LockTimeout(_)                   => (StatusCode::SERVICE_UNAVAILABLE,  "SlowDown"),
        // Both consensus failures map to 503 (transient — the cluster
        // is currently unable to satisfy this read; retry may succeed
        // once heal restores quorum). Distinct error codes so operators
        // can tell the two failure modes apart in S3 logs.
        StorageError::InsufficientOnlineDrives { .. }  => (StatusCode::SERVICE_UNAVAILABLE,  "ServiceUnavailable"),
        StorageError::InconsistentMeta { .. }          => (StatusCode::SERVICE_UNAVAILABLE,  "ServiceUnavailable"),
        StorageError::Io(_)                            => (StatusCode::INTERNAL_SERVER_ERROR,"InternalError"),
    };
    (status, code.to_owned(), e.to_string())
}

#[derive(Serialize)]
#[serde(rename = "Error")]
struct S3ErrorBody<'a> {
    #[serde(rename = "Code")]     code:     &'a str,
    #[serde(rename = "Message")]  message:  &'a str,
    #[serde(rename = "Resource")] resource: &'a str,
}

fn encode_error_xml(code: &str, message: &str, resource: &str) -> Vec<u8> {
    let payload = S3ErrorBody { code, message, resource };
    let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    quick_xml::se::to_writer(&mut s, &payload).expect("xml serialize");
    s.into_bytes()
}

/// Fallback response for paths that don't match any registered route.
pub async fn not_found(_req: Request) -> Response {
    AppError::Malformed("no route matches method+path").into_response()
}
