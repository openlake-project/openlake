//! Bucket-scoped S3 endpoints.
//!
//!   * `PUT    /{bucket}`             CreateBucket
//!   * `PUT    /{bucket}?versioning`  PutBucketVersioning (dispatched inside put_bucket)
//!   * `DELETE /{bucket}`             DeleteBucket (`?force=1` purges contents)
//!   * `HEAD   /{bucket}`             existence probe
//!   * `GET    /{bucket}?location`    region constraint
//!   * `GET    /{bucket}?versioning`  versioning state
//!   * `GET    /{bucket}?list-type=2` list objects v2 (currently empty)

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use phenomenal_io::{BucketMeta, VersioningStatus};
use send_wrapper::SendWrapper;
use serde::Deserialize;

use crate::s3::error::AppError;
use crate::s3::state::AppState;
use crate::s3::xml::{ListBucketObject, ListBucketResult, LocationConstraint, VersioningConfiguration, Xml, S3_NS};

/// Bucket-scoped sub-resources S3 defines that phenomenal does not yet
/// implement. Any of these on `GET /{bucket}?...` returns `501
/// NotImplemented` with the sub-resource name in the message rather
/// than silently falling through to the ListObjects empty stub.
const UNIMPLEMENTED_BUCKET_SUBRESOURCES: &[&str] = &[
    "acl", "policy", "policyStatus", "lifecycle", "cors", "encryption",
    "tagging", "logging", "notification", "replication", "website",
    "object-lock", "accelerate", "analytics", "inventory", "metrics",
    "ownershipControls", "publicAccessBlock", "intelligent-tiering",
    "requestPayment", "versions", "uploads",
];

fn unimplemented_subresource(query_str: &str) -> Option<&'static str> {
    for kv in query_str.split('&') {
        let key = kv.split_once('=').map(|(k, _)| k).unwrap_or(kv);
        for sub in UNIMPLEMENTED_BUCKET_SUBRESOURCES {
            if key == *sub { return Some(*sub); }
        }
    }
    None
}


// todo: @arnav check the cluster scaleup/down polcieis hwo this woudl affect chr
#[derive(Debug, Default, Deserialize)]
pub struct BucketQuery {
    #[serde(default)] pub location:   Option<String>,
    #[serde(default)] pub versioning: Option<String>,
    #[serde(default, rename = "list-type")] pub list_type: Option<String>,
    #[serde(default)] pub force: Option<String>,
    /// `?prefix=` — restrict the listing to keys starting with this string.
    #[serde(default)] pub prefix: Option<String>,
    /// `?max-keys=` — cap on the number of objects returned per call.
    /// AWS spec range: [1, 1000]. Out-of-range values are clamped server-side.
    #[serde(default, rename = "max-keys")] pub max_keys: Option<u32>,
    /// `?continuation-token=` — opaque token returned by the previous
    /// truncated response. We use the last-key-returned as the token,
    /// so resumption is "list keys strictly greater than this string."
    #[serde(default, rename = "continuation-token")] pub continuation_token: Option<String>,
    /// `?start-after=` — alternative resumption: "list keys strictly
    /// greater than this string." Identical to `continuation-token`
    /// for our minimal implementation; the only difference is the
    /// echo-back name in the response.
    #[serde(default, rename = "start-after")] pub start_after: Option<String>,
}

impl BucketQuery {
    fn flag_present(v: &Option<String>) -> bool { v.is_some() }
}

/// Spec default + ceiling for ListObjectsV2's `max-keys`.
const LIST_DEFAULT_MAX_KEYS: u32 = 1000;
const LIST_HARD_CAP_MAX_KEYS: u32 = 1000;

pub async fn put_bucket(
    State(state):  State<AppState>,
    Path(bucket):  Path<String>,
    Query(query):  Query<BucketQuery>,
    headers:       HeaderMap,
    body:          Body,
) -> Result<StatusCode, AppError> {
    if BucketQuery::flag_present(&query.versioning) {
        let content_length: usize = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or(AppError::Malformed("PutBucketVersioning requires Content-Length"))?;
        let bytes = axum::body::to_bytes(body, content_length).await
            .map_err(|_| AppError::Malformed("versioning body unreadable"))?;
        // todo: @arnav check any other configs which we should respect. for v1 this should be fine.
        let cfg: VersioningConfiguration = quick_xml::de::from_reader(bytes.as_ref())
            .map_err(|_| AppError::Malformed("invalid VersioningConfiguration XML"))?;
        let new_status = match cfg.status.as_deref() {
            Some("Enabled")   => VersioningStatus::Enabled,
            Some("Suspended") => VersioningStatus::Suspended,
            _                 => return Err(AppError::Malformed("versioning Status must be Enabled or Suspended")),
        };
        let engine = state.engine().clone();
        SendWrapper::new(async move {
            engine.put_bucket_versioning(&bucket, new_status).await
        }).await?;
    } else {
        if headers
            .get("x-amz-bucket-object-lock-enabled")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Err(AppError::NotImplemented("Object Lock is not supported"));
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let meta   = BucketMeta::new(now_ms, false);
        let engine = state.engine().clone();
        SendWrapper::new(async move { engine.create_bucket(&bucket, meta).await }).await?;
    }
    Ok(StatusCode::OK)
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
) -> Result<StatusCode, AppError> {
    let force  = BucketQuery::flag_present(&query.force);
    let engine = state.engine().clone();
    SendWrapper::new(async move { engine.delete_bucket(&bucket, force).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<StatusCode, AppError> {
    let engine = state.engine().clone();
    SendWrapper::new(async move { engine.stat_bucket(&bucket).await }).await?;
    Ok(StatusCode::OK)
}

pub async fn get_bucket_query(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    uri:          Uri,
) -> Result<Response, AppError> {
    if BucketQuery::flag_present(&query.location) {
        let region = state.auth().region().to_owned();
        return Ok(Xml(LocationConstraint::new(region)).into_response());
    }
    if BucketQuery::flag_present(&query.versioning) {
        let engine = state.engine().clone();
        let status = SendWrapper::new(async move {
            engine.get_bucket_versioning(&bucket).await
        }).await?;
        return Ok(Xml(VersioningConfiguration::for_status(&status)).into_response());
    }
    if let Some(name) = unimplemented_subresource(uri.query().unwrap_or("")) {
        return Err(AppError::NotImplemented(match name {
            "acl"                   => "GetBucketAcl is not implemented",
            "policy"                => "GetBucketPolicy is not implemented",
            "policyStatus"          => "GetBucketPolicyStatus is not implemented",
            "lifecycle"             => "GetBucketLifecycleConfiguration is not implemented",
            "cors"                  => "GetBucketCors is not implemented",
            "encryption"            => "GetBucketEncryption is not implemented",
            "tagging"               => "GetBucketTagging is not implemented",
            "logging"               => "GetBucketLogging is not implemented",
            "notification"          => "GetBucketNotificationConfiguration is not implemented",
            "replication"           => "GetBucketReplication is not implemented",
            "website"               => "GetBucketWebsite is not implemented",
            "object-lock"           => "GetObjectLockConfiguration is not implemented",
            "accelerate"            => "GetBucketAccelerateConfiguration is not implemented",
            "analytics"             => "ListBucketAnalyticsConfigurations is not implemented",
            "inventory"             => "ListBucketInventoryConfigurations is not implemented",
            "metrics"               => "ListBucketMetricsConfigurations is not implemented",
            "ownershipControls"     => "GetBucketOwnershipControls is not implemented",
            "publicAccessBlock"     => "GetPublicAccessBlock is not implemented",
            "intelligent-tiering"   => "ListBucketIntelligentTieringConfigurations is not implemented",
            "requestPayment"        => "GetBucketRequestPayment is not implemented",
            "versions"              => "ListObjectVersions is not implemented",
            "uploads"               => "ListMultipartUploads is not implemented",
            _                       => "bucket sub-resource is not implemented",
        }));
    }
    if BucketQuery::flag_present(&query.list_type) {
        return list_objects_v2(state, bucket, query).await;
    }
    let _ = bucket;
    Err(AppError::NotImplemented("ListObjects (v1) is not implemented; use ListObjectsV2 (?list-type=2)"))
}

// todo: @arnav this is inefficient but works, move to node local lsm in future
async fn list_objects_v2(
    state:  AppState,
    bucket: String,
    query:  BucketQuery,
) -> Result<Response, AppError> {
    let prefix = query.prefix.clone().unwrap_or_default();
    let max_keys = query.max_keys
        .unwrap_or(LIST_DEFAULT_MAX_KEYS)
        .clamp(1, LIST_HARD_CAP_MAX_KEYS);

    let cursor = query.continuation_token.clone().or_else(|| query.start_after.clone());

    let engine = state.engine().clone();
    let bucket_for_list = bucket.clone();
    let prefix_for_list = prefix.clone();
    let infos = SendWrapper::new(async move {
        engine.list(&bucket_for_list, &prefix_for_list).await
    }).await?;

    let mut infos = infos;
    infos.sort_by(|a, b| a.key.cmp(&b.key));

    let after_cursor: Vec<_> = match cursor.as_deref() {
        Some(c) => infos.into_iter().filter(|i| i.key.as_str() > c).collect(),
        None    => infos,
    };

    let total_after_cursor = after_cursor.len();
    let take = (max_keys as usize).min(total_after_cursor);
    let truncated = total_after_cursor > take;
    let returned: Vec<_> = after_cursor.into_iter().take(take).collect();

    let next_token = if truncated {
        returned.last().map(|i| i.key.clone())
    } else {
        None
    };

    let contents: Vec<ListBucketObject> = returned.into_iter().map(|info| ListBucketObject {
        key:           info.key,
        last_modified: rfc3339_from_ms(info.modified_ms),
        etag:          format!("\"{}\"", info.etag),
        size:          info.size,
        storage_class: storage_class_label(&info.storage_class).to_owned(),
    }).collect();

    let body = ListBucketResult {
        xmlns:                   S3_NS,
        name:                    bucket,
        prefix:                  prefix,
        key_count:               contents.len() as u32,
        max_keys:                max_keys,
        is_truncated:            truncated,
        continuation_token:      query.continuation_token,
        next_continuation_token: next_token,
        contents,
    };
    Ok(Xml(body).into_response())
}

fn storage_class_label(sc: &phenomenal_storage::StorageClass) -> &'static str {
    use phenomenal_storage::StorageClass::*;
    match sc {
        Inline | Single => "STANDARD",
    }
}

fn rfc3339_from_ms(ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}
