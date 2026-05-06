//! Typed XML response shapes and a generic `Xml<T>` responder.
//!
//! Each struct corresponds to one S3 wire type. quick-xml's serde
//! adapter handles attribute (`@name`) vs element (`Name`) vs text
//! (`$text`) by `#[serde(rename = ...)]`.
//!
//! `Xml<T>` is the analogue of `axum::Json<T>` — wrap any
//! `Serialize`-capable value, get an `IntoResponse` that emits a
//! UTF-8 XML body with `Content-Type: application/xml`.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

pub const S3_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Generic XML responder. Wraps any `Serialize` value; emits a
/// UTF-8 XML body with `Content-Type: application/xml`.
pub struct Xml<T>(pub T);

impl<T: Serialize> IntoResponse for Xml<T> {
    fn into_response(self) -> Response {
        let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        if let Err(e) = quick_xml::se::to_writer(&mut s, &self.0) {
            // Encoding a typed struct should never fail. If it ever
            // does, surface 500 with a plain-text body so the caller
            // sees something rather than a torn TCP write.
            tracing::error!("xml encode failure: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "xml encode failure").into_response();
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/xml")
            .body(Body::from(s.into_bytes()))
            .expect("response builder infallible for static headers")
    }
}

// ---------------------------------------------------------------------------
// Bucket-level responses
// ---------------------------------------------------------------------------

/// `<LocationConstraint xmlns="...">{region}</LocationConstraint>`
/// — body of `GET /{bucket}?location`.
#[derive(Serialize)]
#[serde(rename = "LocationConstraint")]
pub struct LocationConstraint {
    #[serde(rename = "@xmlns")] pub xmlns: &'static str,
    #[serde(rename = "$text")]  pub region: String,
}

impl LocationConstraint {
    pub fn new(region: String) -> Self {
        Self { xmlns: S3_NS, region }
    }
}

/// `<VersioningConfiguration xmlns="...">…</VersioningConfiguration>`
///
/// Used for both GET (Serialize) and PUT (Deserialize) of the versioning state.
/// `status == None` serializes as a self-closing tag (Unversioned bucket).
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename = "VersioningConfiguration")]
pub struct VersioningConfiguration {
    #[serde(rename = "@xmlns", default, skip_serializing_if = "str::is_empty")]
    pub xmlns: String,
    /// `Enabled` or `Suspended`; absent means the bucket is unversioned.
    #[serde(rename = "Status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl VersioningConfiguration {
    pub fn for_status(status: &phenomenal_io::VersioningStatus) -> Self {
        use phenomenal_io::VersioningStatus;
        Self {
            xmlns:  S3_NS.to_owned(),
            status: match status {
                VersioningStatus::Enabled   => Some("Enabled".to_owned()),
                VersioningStatus::Suspended => Some("Suspended".to_owned()),
                VersioningStatus::Unversioned => None,
            },
        }
    }
}

/// `<ListBucketResult xmlns="...">…</ListBucketResult>` — body of
/// `GET /{bucket}?list-type=2`. Carries the listed objects plus the
/// pagination scalars S3 clients depend on. `contents` is empty for
/// an empty-bucket response; `prefix` and `continuation_token` echo
/// back what the client supplied (or are skipped when absent).
#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    #[serde(rename = "@xmlns")]      pub xmlns:        &'static str,
    #[serde(rename = "Name")]        pub name:         String,
    #[serde(rename = "Prefix",      skip_serializing_if = "String::is_empty")] pub prefix:        String,
    #[serde(rename = "KeyCount")]    pub key_count:    u32,
    #[serde(rename = "MaxKeys")]     pub max_keys:     u32,
    #[serde(rename = "IsTruncated")] pub is_truncated: bool,
    #[serde(rename = "ContinuationToken",     skip_serializing_if = "Option::is_none")] pub continuation_token:     Option<String>,
    #[serde(rename = "NextContinuationToken", skip_serializing_if = "Option::is_none")] pub next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)] pub contents: Vec<ListBucketObject>,
}

/// One `<Contents>` entry inside `ListBucketResult`. Only the fields
/// AWS specifies for ListObjectsV2 default-output are populated here;
/// owner/storage-class extensions are gated behind opt-in flags AWS
/// clients send via additional query params and are skipped for the
/// minimal listing shape.
#[derive(Serialize)]
#[serde(rename = "Contents")]
pub struct ListBucketObject {
    #[serde(rename = "Key")]          pub key:           String,
    #[serde(rename = "LastModified")] pub last_modified: String,
    #[serde(rename = "ETag")]         pub etag:          String,
    #[serde(rename = "Size")]         pub size:          u64,
    #[serde(rename = "StorageClass")] pub storage_class: String,
}

