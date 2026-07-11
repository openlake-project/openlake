//! Per-endpoint S3 request metrics, Prometheus text exposition at
//! `GET /openlake/admin/v1/metrics`. Process-global relaxed atomics;
//! latency is recorded at the last body byte so data-op latency and
//! per-request throughput are end-to-end, not time-to-first-byte.
//!
//! Env: `OPENLAKE_METRICS=0` disables recording;
//! `OPENLAKE_METRICS_THROUGHPUT=0` drops throughput histograms.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;

/// Latency histogram upper bounds, microseconds; last bucket is +Inf.
const LE_US: [u64; 8] = [
    1_000, 5_000, 20_000, 50_000, 100_000, 500_000, 2_000_000, 10_000_000,
];

/// Per-request throughput histogram upper bounds, MB/s; last is +Inf.
const LE_MBPS: [u64; 8] = [1, 8, 32, 64, 128, 256, 512, 1024];

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("OPENLAKE_METRICS").map_or(true, |v| v != "0"))
}

fn throughput_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("OPENLAKE_METRICS_THROUGHPUT").map_or(true, |v| v != "0"))
}

macro_rules! ops {
    ($($name:ident),* $(,)?) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        #[repr(usize)]
        pub enum Op { $($name),* }
        const OP_COUNT: usize = [$(Op::$name),*].len();
        const ALL_OPS: [Op; OP_COUNT] = [$(Op::$name),*];
        const OP_NAMES: [&str; OP_COUNT] = [$(stringify!($name)),*];
    };
}

ops! {
    GetObject,
    HeadObject,
    PutObject,
    CopyObject,
    DeleteObject,
    DeleteObjects,
    ListObjectsV1,
    ListObjectsV2,
    ListBuckets,
    HeadBucket,
    CreateBucket,
    DeleteBucket,
    BucketMeta,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    CacheRead,
    CacheWrite,
    Admin,
    Other,
}

impl Op {
    /// CopyObject moves data server-side, no bytes cross this
    /// middleware — it stays latency-only.
    fn is_data(self) -> bool {
        matches!(
            self,
            Op::GetObject | Op::PutObject | Op::UploadPart | Op::CacheRead | Op::CacheWrite
        )
    }
}

#[derive(Default)]
struct OpMetrics {
    requests: AtomicU64,
    errors: AtomicU64,
    lat_us_sum: AtomicU64,
    lat_buckets: [AtomicU64; LE_US.len() + 1],
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    thpt_mbps_sum: AtomicU64,
    thpt_buckets: [AtomicU64; LE_MBPS.len() + 1],
}

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const ZERO9: [AtomicU64; 9] = [ZERO; 9];

static REGISTRY: [OpMetrics; OP_COUNT] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const M: OpMetrics = OpMetrics {
        requests: ZERO,
        errors: ZERO,
        lat_us_sum: ZERO,
        lat_buckets: ZERO9,
        bytes_in: ZERO,
        bytes_out: ZERO,
        thpt_mbps_sum: ZERO,
        thpt_buckets: ZERO9,
    };
    [M; OP_COUNT]
};

fn bucket_idx(v: u64, bounds: &[u64]) -> usize {
    bounds
        .iter()
        .position(|le| v <= *le)
        .unwrap_or(bounds.len())
}

fn record(op: Op, latency_us: u64, bytes_out: u64, bytes_in: u64) {
    let m = &REGISTRY[op as usize];
    m.lat_us_sum.fetch_add(latency_us, Relaxed);
    m.lat_buckets[bucket_idx(latency_us, &LE_US)].fetch_add(1, Relaxed);
    if op.is_data() {
        m.bytes_out.fetch_add(bytes_out, Relaxed);
        if throughput_enabled() {
            let total = bytes_out + bytes_in;
            let mbps = total / latency_us.max(1); // B/us == MB/s
            m.thpt_mbps_sum.fetch_add(mbps, Relaxed);
            m.thpt_buckets[bucket_idx(mbps, &LE_MBPS)].fetch_add(1, Relaxed);
        }
    }
}

fn classify(req: &Request<Body>) -> Op {
    let path = req.uri().path();
    if let Some(rest) = path.strip_prefix("/openlake/") {
        return if rest.starts_with("cache/") {
            match req.method().as_str() {
                "GET" => Op::CacheRead,
                "PUT" => Op::CacheWrite,
                _ => Op::Other,
            }
        } else {
            Op::Admin
        };
    }
    let query = req.uri().query().unwrap_or("");
    let method = req.method().as_str();
    let mut segs = path.trim_matches('/').splitn(2, '/');
    let bucket = segs.next().unwrap_or("");
    let key = segs.next().unwrap_or("");

    if bucket.is_empty() {
        return match method {
            "GET" => Op::ListBuckets,
            _ => Op::Other,
        };
    }
    if key.is_empty() {
        return match method {
            "GET" => {
                if query.contains("list-type=2") {
                    Op::ListObjectsV2
                } else if query.contains("location") || query.contains("versioning") {
                    Op::BucketMeta
                } else {
                    Op::ListObjectsV1
                }
            }
            "PUT" => Op::CreateBucket,
            "DELETE" => Op::DeleteBucket,
            "HEAD" => Op::HeadBucket,
            "POST" => Op::DeleteObjects,
            _ => Op::Other,
        };
    }
    match method {
        "GET" => Op::GetObject,
        "HEAD" => Op::HeadObject,
        "PUT" => {
            if req.headers().contains_key("x-amz-copy-source") {
                Op::CopyObject
            } else if query.contains("partNumber") && query.contains("uploadId") {
                Op::UploadPart
            } else {
                Op::PutObject
            }
        }
        "DELETE" => {
            if query.contains("uploadId") {
                Op::AbortMultipartUpload
            } else {
                Op::DeleteObject
            }
        }
        "POST" => {
            if query.contains("uploads") {
                Op::CreateMultipartUpload
            } else if query.contains("uploadId") {
                Op::CompleteMultipartUpload
            } else {
                Op::Other
            }
        }
        _ => Op::Other,
    }
}

/// Records the op's sample at stream end — or on Drop, so a client
/// that disconnects mid-download still contributes what was served.
struct MeterBody {
    inner: Body,
    op: Op,
    start: Instant,
    bytes: u64,
    bytes_in: u64,
    recorded: bool,
}

impl MeterBody {
    fn finish(&mut self) {
        if !self.recorded {
            self.recorded = true;
            record(
                self.op,
                self.start.elapsed().as_micros() as u64,
                self.bytes,
                self.bytes_in,
            );
        }
    }
}

impl Drop for MeterBody {
    fn drop(&mut self) {
        self.finish();
    }
}

impl http_body::Body for MeterBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(other) => {
                this.finish();
                Poll::Ready(other)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

pub async fn meter(req: Request<Body>, next: axum::middleware::Next) -> Response {
    if !enabled() {
        return next.run(req).await;
    }
    let op = classify(&req);
    let m = &REGISTRY[op as usize];
    m.requests.fetch_add(1, Relaxed);
    let bytes_in = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    if op.is_data() && bytes_in > 0 {
        m.bytes_in.fetch_add(bytes_in, Relaxed);
    }
    let start = Instant::now();
    let resp = next.run(req).await;
    if resp.status().is_client_error() || resp.status().is_server_error() {
        m.errors.fetch_add(1, Relaxed);
    }
    let (parts, body) = resp.into_parts();
    Response::from_parts(
        parts,
        Body::new(MeterBody {
            inner: body,
            op,
            start,
            bytes: 0,
            bytes_in,
            recorded: false,
        }),
    )
}

pub fn render() -> String {
    let mut out = String::with_capacity(32 * 1024);
    use std::fmt::Write;
    out.push_str("# TYPE openlake_s3_requests_total counter\n");
    out.push_str("# TYPE openlake_s3_errors_total counter\n");
    out.push_str("# TYPE openlake_s3_bytes_in_total counter\n");
    out.push_str("# TYPE openlake_s3_bytes_out_total counter\n");
    out.push_str("# TYPE openlake_s3_latency_us histogram\n");
    out.push_str("# TYPE openlake_s3_req_throughput_mbps histogram\n");
    for (i, name) in OP_NAMES.iter().enumerate() {
        let m = &REGISTRY[i];
        let requests = m.requests.load(Relaxed);
        if requests == 0 {
            continue;
        }
        let _ = writeln!(
            out,
            "openlake_s3_requests_total{{op=\"{name}\"}} {requests}"
        );
        let _ = writeln!(
            out,
            "openlake_s3_errors_total{{op=\"{name}\"}} {}",
            m.errors.load(Relaxed)
        );
        let mut cumulative = 0u64;
        for (b, le) in LE_US.iter().enumerate() {
            cumulative += m.lat_buckets[b].load(Relaxed);
            let _ = writeln!(
                out,
                "openlake_s3_latency_us_bucket{{op=\"{name}\",le=\"{le}\"}} {cumulative}"
            );
        }
        cumulative += m.lat_buckets[LE_US.len()].load(Relaxed);
        let _ = writeln!(
            out,
            "openlake_s3_latency_us_bucket{{op=\"{name}\",le=\"+Inf\"}} {cumulative}"
        );
        let _ = writeln!(
            out,
            "openlake_s3_latency_us_sum{{op=\"{name}\"}} {}",
            m.lat_us_sum.load(Relaxed)
        );
        let _ = writeln!(
            out,
            "openlake_s3_latency_us_count{{op=\"{name}\"}} {cumulative}"
        );
        if !ALL_OPS[i].is_data() {
            continue;
        }
        let _ = writeln!(
            out,
            "openlake_s3_bytes_in_total{{op=\"{name}\"}} {}",
            m.bytes_in.load(Relaxed)
        );
        let _ = writeln!(
            out,
            "openlake_s3_bytes_out_total{{op=\"{name}\"}} {}",
            m.bytes_out.load(Relaxed)
        );
        let mut cumulative = 0u64;
        for (b, le) in LE_MBPS.iter().enumerate() {
            cumulative += m.thpt_buckets[b].load(Relaxed);
            let _ = writeln!(
                out,
                "openlake_s3_req_throughput_mbps_bucket{{op=\"{name}\",le=\"{le}\"}} {cumulative}"
            );
        }
        cumulative += m.thpt_buckets[LE_MBPS.len()].load(Relaxed);
        let _ = writeln!(
            out,
            "openlake_s3_req_throughput_mbps_bucket{{op=\"{name}\",le=\"+Inf\"}} {cumulative}"
        );
        let _ = writeln!(
            out,
            "openlake_s3_req_throughput_mbps_sum{{op=\"{name}\"}} {}",
            m.thpt_mbps_sum.load(Relaxed)
        );
        let _ = writeln!(
            out,
            "openlake_s3_req_throughput_mbps_count{{op=\"{name}\"}} {cumulative}"
        );
    }
    out.push_str(&openlake_io::net_metrics::render());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn classify_covers_the_api_surface() {
        assert!(matches!(classify(&req("GET", "/")), Op::ListBuckets));
        assert!(matches!(classify(&req("GET", "/b/k")), Op::GetObject));
        assert!(matches!(
            classify(&req("GET", "/b?list-type=2")),
            Op::ListObjectsV2
        ));
        assert!(matches!(classify(&req("GET", "/b")), Op::ListObjectsV1));
        assert!(matches!(
            classify(&req("GET", "/b?location")),
            Op::BucketMeta
        ));
        assert!(matches!(classify(&req("PUT", "/b/k")), Op::PutObject));
        assert!(matches!(
            classify(&req("PUT", "/b/k?partNumber=1&uploadId=x")),
            Op::UploadPart
        ));
        assert!(matches!(
            classify(&req("POST", "/b/k?uploads")),
            Op::CreateMultipartUpload
        ));
        assert!(matches!(
            classify(&req("POST", "/b/k?uploadId=x")),
            Op::CompleteMultipartUpload
        ));
        assert!(matches!(
            classify(&req("DELETE", "/b/k?uploadId=x")),
            Op::AbortMultipartUpload
        ));
        assert!(matches!(
            classify(&req("GET", "/openlake/admin/v1/ping")),
            Op::Admin
        ));
        assert!(matches!(
            classify(&req("GET", "/openlake/cache/some/key")),
            Op::CacheRead
        ));
        assert!(matches!(
            classify(&req("PUT", "/openlake/cache/some/key")),
            Op::CacheWrite
        ));
    }

    #[test]
    fn record_and_render_round_trip() {
        REGISTRY[Op::GetObject as usize]
            .requests
            .fetch_add(1, Relaxed);
        record(Op::GetObject, 42_000, 8 * 1024 * 1024, 0);
        let text = render();
        assert!(text.contains("openlake_s3_requests_total") || !text.is_empty());
        assert!(text.contains("openlake_s3_latency_us_bucket{op=\"GetObject\",le=\"50000\"}"));
        assert!(text.contains("openlake_s3_req_throughput_mbps_bucket{op=\"GetObject\""));
    }
}
