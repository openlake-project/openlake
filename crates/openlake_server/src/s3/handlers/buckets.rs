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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openlake_io::{BucketMeta, VersioningStatus};
use openlake_storage::ObjectInfo;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use send_wrapper::SendWrapper;
use serde::Deserialize;

use crate::s3::error::AppError;
use crate::s3::state::AppState;
use crate::s3::xml::{
    BucketEntry, BucketsList, CommonPrefix, ListAllMyBucketsResult, ListBucketObject,
    ListBucketResult, ListBucketResultV1, LocationConstraint, Owner, VersioningConfiguration, Xml,
    S3_NS,
};

/// Bucket-scoped sub-resources S3 defines that openlake does not yet
/// implement. Any of these on `GET /{bucket}?...` returns `501
/// NotImplemented` with the sub-resource name in the message rather
/// than silently falling through to the ListObjects empty stub.
const UNIMPLEMENTED_BUCKET_SUBRESOURCES: &[&str] = &[
    "acl",
    "policy",
    "policyStatus",
    "lifecycle",
    "cors",
    "encryption",
    "tagging",
    "logging",
    "notification",
    "replication",
    "website",
    "object-lock",
    "accelerate",
    "analytics",
    "inventory",
    "metrics",
    "ownershipControls",
    "publicAccessBlock",
    "intelligent-tiering",
    "requestPayment",
    "versions",
    "uploads",
];

fn unimplemented_subresource(query_str: &str) -> Option<&'static str> {
    for kv in query_str.split('&') {
        let key = kv.split_once('=').map(|(k, _)| k).unwrap_or(kv);
        for sub in UNIMPLEMENTED_BUCKET_SUBRESOURCES {
            if key == *sub {
                return Some(*sub);
            }
        }
    }
    None
}

// todo: @arnav check the cluster scaleup/down polcieis hwo this woudl affect chr
#[derive(Debug, Default, Deserialize)]
pub struct BucketQuery {
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub versioning: Option<String>,
    #[serde(default, rename = "list-type")]
    pub list_type: Option<String>,
    #[serde(default)]
    pub force: Option<String>,
    /// `?prefix=` — restrict the listing to keys starting with this string.
    #[serde(default)]
    pub prefix: Option<String>,
    /// `?max-keys=` — cap on the number of objects returned per call.
    /// AWS spec range: [1, 1000]. Out-of-range values are clamped server-side.
    #[serde(default, rename = "max-keys")]
    pub max_keys: Option<u32>,
    /// `?continuation-token=` — opaque token returned by the previous
    /// truncated response. Decodes to the last key returned, so resumption
    /// is "list keys strictly greater than the decoded key."
    #[serde(default, rename = "continuation-token")]
    pub continuation_token: Option<String>,
    /// `?start-after=` — alternative resumption: "list keys strictly
    /// greater than this string." Identical to `continuation-token`
    /// for our minimal implementation; the only difference is the
    /// echo-back name in the response.
    #[serde(default, rename = "start-after")]
    pub start_after: Option<String>,
    /// `?delimiter=` — group keys that share a common substring up to the
    /// first occurrence of this string (searched after `prefix`) into
    /// `CommonPrefixes`, S3's "directory" rollup. Only `/` is meaningful
    /// for filesystem-style listing; empty/absent yields a flat listing.
    #[serde(default)]
    pub delimiter: Option<String>,
    #[serde(default)]
    pub marker: Option<String>,
    #[serde(default, rename = "encoding-type")]
    pub encoding_type: Option<String>,
}

impl BucketQuery {
    fn flag_present(v: &Option<String>) -> bool {
        v.is_some()
    }

    fn url_encoding(&self) -> Result<bool, AppError> {
        match self.encoding_type.as_deref() {
            None => Ok(false),
            Some("url") => Ok(true),
            Some(_) => Err(AppError::InvalidArgument("encoding-type must be url")),
        }
    }
}

// Encode UTF-8 bytes except RFC 3986 unreserved characters, including '/' and '%'.
const LIST_URL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode_list_value(value: String, url_encoding: bool) -> String {
    if url_encoding {
        utf8_percent_encode(&value, LIST_URL_ENCODE_SET).to_string()
    } else {
        value
    }
}

// Tokens are opaque, not key-name fields covered by encoding-type. Base64
// keeps XML-unsafe keys out of these fields, independently of the listing mode.
const LIST_TOKEN_PREFIX: &str = "openlake-list-v1:";

fn encode_list_token(key: String) -> String {
    format!("{LIST_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(key))
}

fn decode_list_token(token: &str) -> Result<String, AppError> {
    match token.strip_prefix(LIST_TOKEN_PREFIX) {
        Some(encoded) => URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or(AppError::InvalidArgument("invalid continuation-token")),
        // Accept the previous raw-key format during an upgrade.
        None => Ok(token.to_owned()),
    }
}

/// Spec default + ceiling for ListObjectsV2's `max-keys`.
const LIST_DEFAULT_MAX_KEYS: u32 = 1000;
const LIST_HARD_CAP_MAX_KEYS: u32 = 1000;

pub async fn put_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, AppError> {
    if BucketQuery::flag_present(&query.versioning) {
        let content_length: usize = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or(AppError::Malformed(
                "PutBucketVersioning requires Content-Length",
            ))?;
        let bytes = axum::body::to_bytes(body, content_length)
            .await
            .map_err(|_| AppError::Malformed("versioning body unreadable"))?;
        // todo: @arnav check any other configs which we should respect. for v1 this should be fine.
        let cfg: VersioningConfiguration = quick_xml::de::from_reader(bytes.as_ref())
            .map_err(|_| AppError::Malformed("invalid VersioningConfiguration XML"))?;
        let new_status = match cfg.status.as_deref() {
            Some("Enabled") => VersioningStatus::Enabled,
            Some("Suspended") => VersioningStatus::Suspended,
            _ => {
                return Err(AppError::Malformed(
                    "versioning Status must be Enabled or Suspended",
                ))
            }
        };
        let engine = state.engine().clone();
        SendWrapper::new(async move { engine.put_bucket_versioning(&bucket, new_status).await })
            .await?;
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
        let meta = BucketMeta::new(now_ms, false);
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
    let force = BucketQuery::flag_present(&query.force);
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
    uri: Uri,
) -> Result<Response, AppError> {
    if BucketQuery::flag_present(&query.location) {
        let region = state.auth().region().to_owned();
        return Ok(Xml(LocationConstraint::new(region)).into_response());
    }
    if BucketQuery::flag_present(&query.versioning) {
        let engine = state.engine().clone();
        let status =
            SendWrapper::new(async move { engine.get_bucket_versioning(&bucket).await }).await?;
        return Ok(Xml(VersioningConfiguration::for_status(&status)).into_response());
    }
    if let Some(name) = unimplemented_subresource(uri.query().unwrap_or("")) {
        return Err(AppError::NotImplemented(match name {
            "acl" => "GetBucketAcl is not implemented",
            "policy" => "GetBucketPolicy is not implemented",
            "policyStatus" => "GetBucketPolicyStatus is not implemented",
            "lifecycle" => "GetBucketLifecycleConfiguration is not implemented",
            "cors" => "GetBucketCors is not implemented",
            "encryption" => "GetBucketEncryption is not implemented",
            "tagging" => "GetBucketTagging is not implemented",
            "logging" => "GetBucketLogging is not implemented",
            "notification" => "GetBucketNotificationConfiguration is not implemented",
            "replication" => "GetBucketReplication is not implemented",
            "website" => "GetBucketWebsite is not implemented",
            "object-lock" => "GetObjectLockConfiguration is not implemented",
            "accelerate" => "GetBucketAccelerateConfiguration is not implemented",
            "analytics" => "ListBucketAnalyticsConfigurations is not implemented",
            "inventory" => "ListBucketInventoryConfigurations is not implemented",
            "metrics" => "ListBucketMetricsConfigurations is not implemented",
            "ownershipControls" => "GetBucketOwnershipControls is not implemented",
            "publicAccessBlock" => "GetPublicAccessBlock is not implemented",
            "intelligent-tiering" => {
                "ListBucketIntelligentTieringConfigurations is not implemented"
            }
            "requestPayment" => "GetBucketRequestPayment is not implemented",
            "versions" => "ListObjectVersions is not implemented",
            "uploads" => "ListMultipartUploads is not implemented",
            _ => "bucket sub-resource is not implemented",
        }));
    }
    if BucketQuery::flag_present(&query.list_type) {
        return list_objects_v2(state, bucket, query).await;
    }
    list_objects_v1(state, bucket, query).await
}

async fn list_page(
    state: &AppState,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    cursor: Option<&str>,
    max_keys: usize,
) -> Result<(Vec<ListEntry>, bool, Option<String>), AppError> {
    let engine = state.engine().clone();

    if max_keys == 0 {
        let bucket_owned = bucket.to_owned();
        SendWrapper::new(async move { engine.stat_bucket(&bucket_owned).await }).await?;
        return Ok((Vec::new(), false, None));
    }

    if let Some(delim) = delimiter {
        let bucket_owned = bucket.to_owned();
        let prefix_owned = prefix.to_owned();
        let mut infos =
            SendWrapper::new(
                async move { engine.list(&bucket_owned, &prefix_owned, None, 0).await },
            )
            .await?;
        infos.sort_by(|a, b| a.key.cmp(&b.key));

        let entries = rollup_entries(infos, prefix, delim);
        let start = match cursor {
            Some(c) => entries
                .iter()
                .position(|e| entry_name(e) > c)
                .unwrap_or(entries.len()),
            None => 0,
        };
        let end = (start + max_keys).min(entries.len());
        let truncated = end < entries.len();
        let next = if truncated {
            Some(entry_name(&entries[end - 1]).to_owned())
        } else {
            None
        };
        let page: Vec<ListEntry> = entries.into_iter().skip(start).take(end - start).collect();
        Ok((page, truncated, next))
    } else {
        let bucket_owned = bucket.to_owned();
        let prefix_owned = prefix.to_owned();
        let cursor_owned = cursor.map(|c| c.to_owned());
        let mut infos = SendWrapper::new(async move {
            engine
                .list(
                    &bucket_owned,
                    &prefix_owned,
                    cursor_owned.as_deref(),
                    max_keys,
                )
                .await
        })
        .await?;
        infos.sort_by(|a, b| a.key.cmp(&b.key));

        let truncated = infos.len() > max_keys;
        let take = max_keys.min(infos.len());
        let returned: Vec<ObjectInfo> = infos.into_iter().take(take).collect();
        let next = if truncated {
            returned.last().map(|i| i.key.clone())
        } else {
            None
        };
        let page: Vec<ListEntry> = returned.into_iter().map(ListEntry::Object).collect();
        Ok((page, truncated, next))
    }
}

#[allow(clippy::redundant_field_names)]
async fn list_objects_v2(
    state: AppState,
    bucket: String,
    query: BucketQuery,
) -> Result<Response, AppError> {
    let url_encoding = query.url_encoding()?;
    let prefix = query.prefix.clone().unwrap_or_default();
    let max_keys = query
        .max_keys
        .unwrap_or(LIST_DEFAULT_MAX_KEYS)
        .clamp(0, LIST_HARD_CAP_MAX_KEYS);
    let delimiter = query.delimiter.clone().filter(|d| !d.is_empty());
    let cursor = query
        .continuation_token
        .as_deref()
        .map(decode_list_token)
        .transpose()?
        .or_else(|| query.start_after.clone());

    let (page, truncated, next_token) = list_page(
        &state,
        &bucket,
        &prefix,
        delimiter.as_deref(),
        cursor.as_deref(),
        max_keys as usize,
    )
    .await?;
    let (contents, common_prefixes) = split_page(page, None, url_encoding);

    let key_count = (contents.len() + common_prefixes.len()) as u32;
    let body = ListBucketResult {
        xmlns: S3_NS,
        name: bucket,
        prefix: encode_list_value(prefix, url_encoding),
        encoding_type: url_encoding.then_some("url"),
        key_count: key_count,
        max_keys: max_keys,
        is_truncated: truncated,
        delimiter: delimiter.map(|value| encode_list_value(value, url_encoding)),
        start_after: query
            .start_after
            .map(|value| encode_list_value(value, url_encoding)),
        continuation_token: query.continuation_token,
        next_continuation_token: next_token.map(encode_list_token),
        contents: contents,
        common_prefixes: common_prefixes,
    };
    Ok(Xml(body).into_response())
}

#[allow(clippy::redundant_field_names)]
async fn list_objects_v1(
    state: AppState,
    bucket: String,
    query: BucketQuery,
) -> Result<Response, AppError> {
    let url_encoding = query.url_encoding()?;
    let prefix = query.prefix.clone().unwrap_or_default();
    let max_keys = query
        .max_keys
        .unwrap_or(LIST_DEFAULT_MAX_KEYS)
        .clamp(0, LIST_HARD_CAP_MAX_KEYS);
    let delimiter = query.delimiter.clone().filter(|d| !d.is_empty());
    let marker = query.marker.clone();

    let (page, truncated, next_marker) = list_page(
        &state,
        &bucket,
        &prefix,
        delimiter.as_deref(),
        marker.as_deref(),
        max_keys as usize,
    )
    .await?;
    let (contents, common_prefixes) = split_page(page, Some(v1_owner()), url_encoding);

    let body = ListBucketResultV1 {
        xmlns: S3_NS,
        name: bucket,
        prefix: encode_list_value(prefix, url_encoding),
        encoding_type: url_encoding.then_some("url"),
        marker: encode_list_value(marker.unwrap_or_default(), url_encoding),
        next_marker: next_marker.map(|value| encode_list_value(value, url_encoding)),
        max_keys: max_keys,
        is_truncated: truncated,
        delimiter: delimiter.map(|value| encode_list_value(value, url_encoding)),
        contents: contents,
        common_prefixes: common_prefixes,
    };
    Ok(Xml(body).into_response())
}

/// A single rolled-up listing entry: either a concrete object or a
/// synthetic common-prefix "directory" produced by the delimiter.
enum ListEntry {
    Object(ObjectInfo),
    Prefix(String),
}

fn entry_name(entry: &ListEntry) -> &str {
    match entry {
        ListEntry::Object(info) => &info.key,
        ListEntry::Prefix(prefix) => prefix,
    }
}

/// Roll a sorted key list up against `delimiter`: any key whose remainder
/// after `prefix` contains the delimiter collapses to the substring up to
/// and including that first delimiter (a `CommonPrefix`). Consecutive keys
/// under the same prefix dedup because the input is sorted, so all keys of
/// one prefix are contiguous.
fn rollup_entries(infos: Vec<ObjectInfo>, prefix: &str, delim: &str) -> Vec<ListEntry> {
    let mut out: Vec<ListEntry> = Vec::with_capacity(infos.len());
    let mut prev_prefix: Option<String> = None;
    for info in infos {
        let rest = match info.key.strip_prefix(prefix) {
            Some(rest) => rest,
            None => {
                out.push(ListEntry::Object(info));
                continue;
            }
        };
        match rest.find(delim) {
            Some(idx) => {
                let cut = idx + delim.len();
                let common = format!("{}{}", prefix, &rest[..cut]);
                if prev_prefix.as_deref() != Some(common.as_str()) {
                    prev_prefix = Some(common.clone());
                    out.push(ListEntry::Prefix(common));
                }
            }
            None => out.push(ListEntry::Object(info)),
        }
    }
    out
}

fn split_page(
    page: Vec<ListEntry>,
    owner: Option<Owner>,
    url_encoding: bool,
) -> (Vec<ListBucketObject>, Vec<CommonPrefix>) {
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for entry in page {
        match entry {
            ListEntry::Object(mut info) => {
                info.key = encode_list_value(info.key, url_encoding);
                contents.push(object_to_xml(info, owner.clone()));
            }
            ListEntry::Prefix(prefix) => common_prefixes.push(CommonPrefix {
                prefix: encode_list_value(prefix, url_encoding),
            }),
        }
    }
    (contents, common_prefixes)
}

fn object_to_xml(info: ObjectInfo, owner: Option<Owner>) -> ListBucketObject {
    ListBucketObject {
        key: info.key,
        last_modified: rfc3339_from_ms(info.modified_ms),
        etag: format!("\"{}\"", info.etag),
        size: info.size,
        storage_class: storage_class_label(&info.storage_class).to_owned(),
        owner,
    }
}

fn v1_owner() -> Owner {
    Owner {
        id: "openlake".to_owned(),
        display_name: "openlake".to_owned(),
    }
}

fn storage_class_label(sc: &openlake_storage::StorageClass) -> &'static str {
    use openlake_storage::StorageClass::*;
    match sc {
        Inline | Single => "STANDARD",
    }
}

/// `GET /` — ListBuckets. Returns every bucket the cluster holds with
/// its creation time.
pub async fn list_buckets(State(state): State<AppState>) -> Result<Response, AppError> {
    let engine = state.engine().clone();
    let listed = SendWrapper::new(async move { engine.list_buckets().await }).await?;
    let bucket = listed
        .into_iter()
        .map(|(name, created_ms)| BucketEntry {
            name,
            creation_date: rfc3339_from_ms(created_ms),
        })
        .collect();
    let body = ListAllMyBucketsResult {
        xmlns: S3_NS,
        buckets: BucketsList { bucket },
    };
    Ok(Xml(body).into_response())
}

fn rfc3339_from_ms(ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthState;
    use crate::in_memory_store::InMemoryStore;
    use openlake_io::{BucketMeta, LocalFsBackend, StorageBackend};
    use openlake_storage::StorageClass;
    use openlake_storage::{ClusterConfig, DiskAddr, Engine, NodeAddr};
    use std::collections::HashMap;
    use std::rc::Rc;
    use tempfile::TempDir;
    use uuid::Uuid;

    async fn list_test_state() -> (Vec<TempDir>, AppState) {
        let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
        let nodes = (0..3)
            .map(|id| NodeAddr {
                id,
                rpc_addr: format!("127.0.0.1:{}", 9100 + id).parse().unwrap(),
                disk_count: 1,
            })
            .collect();
        let cluster = ClusterConfig {
            nodes,
            set_drive_count: 3,
            default_parity_count: 1,
            deployment_id: Uuid::nil(),
        };
        let backends: HashMap<DiskAddr, Rc<dyn StorageBackend>> = dirs
            .iter()
            .enumerate()
            .map(|(id, dir)| {
                (
                    DiskAddr {
                        node_id: id as u16,
                        disk_idx: 0,
                    },
                    Rc::new(LocalFsBackend::new(dir.path()).unwrap()) as Rc<dyn StorageBackend>,
                )
            })
            .collect();
        let engine = Rc::new(Engine::new(
            cluster,
            backends,
            vec![Rc::new(openlake_storage::DsyncClient::no_op())],
            0,
        ));
        engine
            .create_bucket("existing-bucket", BucketMeta::new(0, false))
            .await
            .unwrap();
        let auth = Rc::new(AuthState::new("us-east-1".into(), &[]));
        (dirs, AppState::new(engine, auth, InMemoryStore::new()))
    }

    #[compio::test]
    async fn list_objects_missing_bucket_returns_no_such_bucket_for_both_versions() {
        let (_dirs, state) = list_test_state().await;
        for list_type in [None, Some("2")] {
            for max_keys in [None, Some(0)] {
                let query = BucketQuery {
                    list_type: list_type.map(str::to_owned),
                    max_keys,
                    ..BucketQuery::default()
                };
                let uri = if list_type.is_some() {
                    "/missing-bucket?list-type=2".parse().unwrap()
                } else {
                    "/missing-bucket".parse().unwrap()
                };
                let response = get_bucket_query(
                    State(state.clone()),
                    Path("missing-bucket".into()),
                    Query(query),
                    uri,
                )
                .await
                .expect_err("missing bucket should fail")
                .into_response();
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert!(String::from_utf8_lossy(&body).contains("<Code>NoSuchBucket</Code>"));
            }
        }
    }

    #[compio::test]
    async fn list_objects_existing_empty_bucket_succeeds_for_both_versions() {
        let (_dirs, state) = list_test_state().await;
        for list_type in [None, Some("2")] {
            for max_keys in [None, Some(0)] {
                let query = BucketQuery {
                    list_type: list_type.map(str::to_owned),
                    max_keys,
                    ..BucketQuery::default()
                };
                let uri = if list_type.is_some() {
                    "/existing-bucket?list-type=2".parse().unwrap()
                } else {
                    "/existing-bucket".parse().unwrap()
                };
                let response = get_bucket_query(
                    State(state.clone()),
                    Path("existing-bucket".into()),
                    Query(query),
                    uri,
                )
                .await
                .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }
        }
    }

    async fn put_listing_keys(state: &AppState, keys: &[&str]) {
        for key in keys {
            let mut source = openlake_io::VecByteStream::new(Vec::new());
            state
                .engine()
                .put("existing-bucket", key, 0, &mut source, None, None)
                .await
                .unwrap();
        }
    }

    async fn listing_xml(state: &AppState, query: &str) -> String {
        let uri: Uri = format!("/existing-bucket?{query}").parse().unwrap();
        let parsed = Query::<BucketQuery>::try_from_uri(&uri).unwrap();
        let response = get_bucket_query(
            State(state.clone()),
            Path("existing-bucket".into()),
            parsed,
            uri,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn next_token(xml: &str) -> String {
        #[derive(Deserialize)]
        struct Page {
            #[serde(rename = "NextContinuationToken")]
            token: String,
        }
        quick_xml::de::from_str::<Page>(xml).unwrap().token
    }

    #[compio::test]
    async fn list_url_encodes_keys_for_both_versions() {
        let (_dirs, state) = list_test_state().await;
        let cases = [
            ("space key", "space%20key"),
            ("literal%2F", "literal%252F"),
            ("é猫", "%C3%A9%E7%8C%AB"),
            ("control\u{1}", "control%01"),
            ("xml<&\"", "xml%3C%26%22"),
            ("test_file(3).png", "test_file%283%29.png"),
            ("a-Z_0.~", "a-Z_0.~"),
        ];
        put_listing_keys(
            &state,
            &cases.iter().map(|(raw, _)| *raw).collect::<Vec<_>>(),
        )
        .await;
        for version in ["", "list-type=2&"] {
            let xml = listing_xml(&state, &format!("{version}encoding-type=url")).await;
            assert!(xml.contains("<EncodingType>url</EncodingType>"));
            assert!(!xml.contains('\u{1}'));
            for (_, encoded) in cases {
                assert!(xml.contains(&format!("<Key>{encoded}</Key>")), "{xml}");
            }
        }
    }

    #[compio::test]
    async fn list_without_encoding_preserves_raw_keys_and_xml_escaping() {
        let (_dirs, state) = list_test_state().await;
        put_listing_keys(&state, &["dir/a % é&<>"]).await;
        for version in ["", "list-type=2&"] {
            let xml = listing_xml(&state, &format!("{version}prefix=dir%2F")).await;
            assert!(xml.contains("<Prefix>dir/</Prefix>"));
            assert!(xml.contains("<Key>dir/a % é&amp;&lt;&gt;</Key>"));
            assert!(!xml.contains("<EncodingType>"));
        }
    }

    #[compio::test]
    async fn list_url_encoding_preserves_raw_filtering_and_pagination() {
        let (_dirs, state) = list_test_state().await;
        put_listing_keys(&state, &["root %/a child/item", "root %/b?.txt", "other"]).await;
        for version in ["", "list-type=2&"] {
            let base =
                format!("{version}encoding-type=url&prefix=root%20%25%2F&delimiter=%2F&max-keys=1");
            let first = listing_xml(&state, &base).await;
            assert!(first.contains("<Prefix>root%20%25%2F</Prefix>"));
            assert!(first.contains("<Delimiter>%2F</Delimiter>"));
            assert!(first.contains(
                "<CommonPrefixes><Prefix>root%20%25%2Fa%20child%2F</Prefix></CommonPrefixes>"
            ));
            assert!(first.contains("<IsTruncated>true</IsTruncated>"));
            let cursor = if version.is_empty() {
                assert!(first.contains("<NextMarker>root%20%25%2Fa%20child%2F</NextMarker>"));
                "marker=root%20%25%2Fa%20child%2F".to_owned()
            } else {
                // V2 tokens are opaque; encoding-type does not percent-encode them.
                format!("continuation-token={}", next_token(&first))
            };
            let second = listing_xml(&state, &format!("{base}&{cursor}")).await;
            assert!(second.contains("<Key>root%20%25%2Fb%3F.txt</Key>"));
            assert!(second.contains("<IsTruncated>false</IsTruncated>"));
            assert!(!second.contains("<CommonPrefixes>"));
            if version.is_empty() {
                assert!(second.contains("<Marker>root%20%25%2Fa%20child%2F</Marker>"));
            } else {
                assert!(second.contains(&format!(
                    "<ContinuationToken>{}</ContinuationToken>",
                    next_token(&first)
                )));
            }
        }
    }

    #[compio::test]
    async fn list_v2_tokens_are_xml_safe_and_work_across_encoding_modes() {
        let (_dirs, state) = list_test_state().await;
        put_listing_keys(&state, &["a\u{1}%2F", "b", "openlake-list-v1:YQ", "z"]).await;
        let first = listing_xml(&state, "list-type=2&encoding-type=url&max-keys=1").await;
        assert!(!first.contains('\u{1}'));
        assert!(first.contains("<Key>a%01%252F</Key>"));
        let token = next_token(&first);
        let second = listing_xml(
            &state,
            &format!("list-type=2&max-keys=1&continuation-token={token}"),
        )
        .await;
        assert!(second.contains("<Key>b</Key>"));
        let third = listing_xml(
            &state,
            &format!(
                "list-type=2&max-keys=1&continuation-token={}",
                next_token(&second)
            ),
        )
        .await;
        assert!(third.contains("<Key>openlake-list-v1:YQ</Key>"));
        let fourth = listing_xml(
            &state,
            &format!(
                "list-type=2&encoding-type=url&continuation-token={}",
                next_token(&third)
            ),
        )
        .await;
        assert!(fourth.contains("<Key>z</Key>"));
        assert!(!fourth.contains("<Key>b</Key>"));
        assert!(fourth.contains("<IsTruncated>false</IsTruncated>"));

        // Raw-key tokens issued by the previous server still resume a listing.
        let legacy = listing_xml(
            &state,
            "list-type=2&encoding-type=url&continuation-token=a%01%252F",
        )
        .await;
        assert!(legacy.contains("<Key>b</Key>"));
        assert!(!legacy.contains("<Key>a%01%252F</Key>"));
    }

    #[compio::test]
    async fn list_v2_rejects_invalid_versioned_tokens() {
        let (_dirs, state) = list_test_state().await;
        for token in ["openlake-list-v1:!", "openlake-list-v1:_w"] {
            let response = list_objects_v2(
                state.clone(),
                "existing-bucket".into(),
                BucketQuery {
                    continuation_token: Some(token.into()),
                    ..BucketQuery::default()
                },
            )
            .await
            .unwrap_err()
            .into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[compio::test]
    async fn list_url_start_after_is_not_decoded_twice() {
        let (_dirs, state) = list_test_state().await;
        put_listing_keys(&state, &["p%2F/a", "p%2F/b", "p/other"]).await;
        let xml = listing_xml(
            &state,
            "list-type=2&encoding-type=url&prefix=p%252F%2F&start-after=p%252F%2Fa",
        )
        .await;
        assert!(xml.contains("<Prefix>p%252F%2F</Prefix>"));
        assert!(xml.contains("<StartAfter>p%252F%2Fa</StartAfter>"));
        assert!(xml.contains("<Key>p%252F%2Fb</Key>"));
        assert!(!xml.contains("<Key>p%252F%2Fa</Key>"));
        assert!(!xml.contains("other"));
    }

    #[compio::test]
    async fn list_rejects_unsupported_encoding_types_for_both_versions() {
        let (_dirs, state) = list_test_state().await;
        for version in ["", "list-type=2&"] {
            for encoding in ["", "URL", "base64"] {
                let uri: Uri = format!("/existing-bucket?{version}encoding-type={encoding}")
                    .parse()
                    .unwrap();
                let parsed = Query::<BucketQuery>::try_from_uri(&uri).unwrap();
                let response = get_bucket_query(
                    State(state.clone()),
                    Path("existing-bucket".into()),
                    parsed,
                    uri,
                )
                .await
                .unwrap_err()
                .into_response();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert!(String::from_utf8_lossy(&bytes).contains("<Code>InvalidArgument</Code>"));
            }
        }
    }

    fn obj(key: &str) -> ObjectInfo {
        ObjectInfo {
            bucket: "b".to_owned(),
            key: key.to_owned(),
            size: 0,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Single,
            modified_ms: 0,
            content_type: None,
            version_id: "null".to_owned(),
            is_delete_marker: false,
        }
    }

    fn sorted(keys: &[&str]) -> Vec<ObjectInfo> {
        let mut v: Vec<ObjectInfo> = keys.iter().map(|k| obj(k)).collect();
        v.sort_by(|a, b| a.key.cmp(&b.key));
        v
    }

    fn names(entries: &[ListEntry]) -> Vec<String> {
        entries.iter().map(|e| entry_name(e).to_owned()).collect()
    }

    #[test]
    fn rollup_collapses_nested_keys_into_common_prefixes() {
        let infos = sorted(&[
            "photos/2024/feb/c.jpg",
            "photos/2024/jan/a.jpg",
            "photos/2024/jan/b.jpg",
            "photos/2025/mar/d.jpg",
        ]);
        let entries = rollup_entries(infos, "photos/", "/");
        assert_eq!(names(&entries), vec!["photos/2024/", "photos/2025/"]);
        assert!(entries.iter().all(|e| matches!(e, ListEntry::Prefix(_))));
    }

    #[test]
    fn rollup_root_mixes_objects_and_prefixes_in_sorted_order() {
        let infos = sorted(&["notes.txt", "docs/readme.txt", "photos/a.jpg"]);
        let entries = rollup_entries(infos, "", "/");
        assert_eq!(names(&entries), vec!["docs/", "notes.txt", "photos/"]);
        assert!(matches!(entries[0], ListEntry::Prefix(_)));
        assert!(matches!(entries[1], ListEntry::Object(_)));
        assert!(matches!(entries[2], ListEntry::Prefix(_)));
    }

    #[test]
    fn rollup_direct_object_under_prefix_is_content_not_prefix() {
        let infos = sorted(&["photos/cover.jpg", "photos/2024/a.jpg"]);
        let entries = rollup_entries(infos, "photos/", "/");
        assert_eq!(names(&entries), vec!["photos/2024/", "photos/cover.jpg"]);
        assert!(matches!(entries[0], ListEntry::Prefix(_)));
        assert!(matches!(entries[1], ListEntry::Object(_)));
    }

    #[test]
    fn split_page_sets_owner_for_v1_only() {
        let page = vec![
            ListEntry::Object(obj("a.txt")),
            ListEntry::Prefix("dir/".to_owned()),
        ];
        let (contents, prefixes) = split_page(page, None, false);
        assert_eq!(contents.len(), 1);
        assert!(contents[0].owner.is_none());
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix, "dir/");

        let (contents, _) = split_page(
            vec![ListEntry::Object(obj("a.txt"))],
            Some(v1_owner()),
            false,
        );
        assert!(contents[0].owner.is_some());
    }
}
