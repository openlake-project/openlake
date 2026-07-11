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
use openlake_io::{BucketMeta, VersioningStatus};
use openlake_storage::ObjectInfo;
use send_wrapper::SendWrapper;
use serde::Deserialize;

use crate::s3::error::AppError;
use crate::s3::state::AppState;
use crate::s3::xml::{
    CommonPrefix, ListBucketObject, ListBucketResult, ListBucketResultV1, LocationConstraint,
    Owner, VersioningConfiguration, Xml, S3_NS,
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
    /// truncated response. We use the last-key-returned as the token,
    /// so resumption is "list keys strictly greater than this string."
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
}

impl BucketQuery {
    fn flag_present(v: &Option<String>) -> bool {
        v.is_some()
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
    let prefix = query.prefix.clone().unwrap_or_default();
    let max_keys = query
        .max_keys
        .unwrap_or(LIST_DEFAULT_MAX_KEYS)
        .clamp(1, LIST_HARD_CAP_MAX_KEYS);
    let delimiter = query.delimiter.clone().filter(|d| !d.is_empty());
    let cursor = query
        .continuation_token
        .clone()
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
    let (contents, common_prefixes) = split_page(page, None);

    let key_count = (contents.len() + common_prefixes.len()) as u32;
    let body = ListBucketResult {
        xmlns: S3_NS,
        name: bucket,
        prefix: prefix,
        key_count: key_count,
        max_keys: max_keys,
        is_truncated: truncated,
        delimiter: delimiter,
        continuation_token: query.continuation_token,
        next_continuation_token: next_token,
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
    let prefix = query.prefix.clone().unwrap_or_default();
    let max_keys = query
        .max_keys
        .unwrap_or(LIST_DEFAULT_MAX_KEYS)
        .clamp(1, LIST_HARD_CAP_MAX_KEYS);
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
    let (contents, common_prefixes) = split_page(page, Some(v1_owner()));

    let body = ListBucketResultV1 {
        xmlns: S3_NS,
        name: bucket,
        prefix: prefix,
        marker: marker.unwrap_or_default(),
        next_marker: next_marker,
        max_keys: max_keys,
        is_truncated: truncated,
        delimiter: delimiter,
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
) -> (Vec<ListBucketObject>, Vec<CommonPrefix>) {
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for entry in page {
        match entry {
            ListEntry::Object(info) => contents.push(object_to_xml(info, owner.clone())),
            ListEntry::Prefix(prefix) => common_prefixes.push(CommonPrefix { prefix }),
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
    use openlake_storage::StorageClass;

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
        let (contents, prefixes) = split_page(page, None);
        assert_eq!(contents.len(), 1);
        assert!(contents[0].owner.is_none());
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix, "dir/");

        let (contents, _) = split_page(vec![ListEntry::Object(obj("a.txt"))], Some(v1_owner()));
        assert!(contents[0].owner.is_some());
    }
}
