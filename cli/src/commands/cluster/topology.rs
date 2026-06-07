use anyhow::{anyhow, Context, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, PayloadChecksumKind, PercentEncodingMode, SessionTokenMode, SignableBody,
    SignableRequest, SigningSettings, UriPathNormalizationMode,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use clap::Args as ClapArgs;
use futures::stream::StreamExt as _;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use openlake_server::config::{Config, Credential};
use openlake_storage::NodeAddr;

#[derive(ClapArgs)]
pub struct TopologyArgs {
    /// openlake.toml. The same file openlaked reads.
    #[arg(long)]
    pub config: PathBuf,

    /// Probe each node's RPC listener and annotate the layout with live state.
    #[arg(long)]
    pub probe: bool,

    /// Per node probe timeout in seconds. Requires --probe. [default: 2]
    #[arg(long, requires = "probe")]
    pub probe_timeout_secs: Option<u64>,
}

/// Default per node probe timeout, used when --probe-timeout-secs is omitted.
const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 2;

/// Cap on probes in flight at once, so a large cluster cannot open an
/// unbounded number of sockets simultaneously.
const MAX_CONCURRENT_PROBES: usize = 64;

pub async fn run(args: TopologyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse {}", args.config.display()))?;

    println!("openlake cluster topology: {}", args.config.display());
    println!();

    // Probing is opt-in: by default `topology` reports the declared layout
    // without touching the network. With --probe it also reports liveness.
    let liveness = if args.probe {
        let secs = args
            .probe_timeout_secs
            .unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS);
        Some(probe(&cfg, Duration::from_secs(secs)).await)
    } else {
        None
    };

    let (report, warnings) = render(&cfg.nodes, liveness.as_ref());
    print!("{report}");

    for w in warnings {
        eprintln!("{w}");
    }
    Ok(())
}

/// Path of the liveness route on the S3 listener (behind SigV4).
const PING_PATH: &str = "/openlake/admin/v1/ping";

/// Probe every node's liveness over the S3 plane, mapping `rpc_addr -> up`.
///
/// Liveness is checked against the S3 listener's `/ping` admin route, never
/// the inter-node RPC plane: each node's S3 endpoint is derived from its
/// `rpc_addr` IP plus the cluster-wide S3 port (`s3_port`, defaulting to this
/// node's own `s3_addr` port). Requests are SigV4-signed with the first
/// configured credential so the server's verifier accepts them. A node is up
/// when `/ping` answers 2xx within `timeout`. Probes run concurrently with a
/// bounded fan-out of `MAX_CONCURRENT_PROBES`. Results are keyed by `rpc_addr`
/// to match how the layout table identifies nodes.
async fn probe(cfg: &Config, timeout: Duration) -> BTreeMap<SocketAddr, bool> {
    let s3_port = cfg.s3_port.unwrap_or_else(|| cfg.s3_addr.port());
    let scheme = if cfg.s3_tls.is_some() {
        "https"
    } else {
        "http"
    };
    let cred = cfg.credentials.first();
    let client = cyper::Client::new();

    futures::stream::iter(cfg.nodes.iter().map(|n| {
        let endpoint = SocketAddr::new(n.rpc_addr.ip(), s3_port);
        let client = client.clone();
        let region = cfg.region.as_str();
        async move {
            let up = match cred {
                Some(c) => ping_node(&client, scheme, endpoint, c, region, timeout).await,
                None => false,
            };
            (n.rpc_addr, up)
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_PROBES)
    .collect()
    .await
}

/// GET the signed `/ping` route on one node's S3 endpoint; `true` on 2xx.
async fn ping_node(
    client: &cyper::Client,
    scheme: &str,
    endpoint: SocketAddr,
    cred: &Credential,
    region: &str,
    timeout: Duration,
) -> bool {
    let host = endpoint.to_string();
    let url = format!("{scheme}://{host}{PING_PATH}");

    let signed = match sign_ping(&url, &host, cred, region) {
        Ok(headers) => headers,
        Err(_) => return false,
    };

    let request = match client.get(&url) {
        Ok(builder) => builder.headers(signed),
        Err(_) => return false,
    };

    matches!(
        compio::time::timeout(timeout, request.send()).await,
        Ok(Ok(resp)) if resp.status().is_success()
    )
}

/// SigV4-sign a GET of `url` and return the headers to attach to the request.
///
/// Mirrors the server's verifier: service `s3`, S3-specific signing settings,
/// and an unsigned payload. The `host` header is signed but dropped from the
/// returned set so the HTTP client supplies its own (avoiding a duplicate).
fn sign_ping(url: &str, host: &str, cred: &Credential, region: &str) -> Result<http::HeaderMap> {
    let identity: Identity = Credentials::new(
        &cred.access_key,
        &cred.secret_key,
        None,
        None,
        "openlake-cli",
    )
    .into();

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.session_token_mode = SessionTokenMode::Include;

    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| anyhow!("build signing params: {e}"))?;

    let signable = SignableRequest::new(
        "GET",
        url,
        std::iter::once(("host", host)),
        SignableBody::UnsignedPayload,
    )
    .map_err(|e| anyhow!("build signable request: {e}"))?;

    let (instructions, _signature) = sign(signable, &params.into())
        .map_err(|e| anyhow!("sign request: {e}"))?
        .into_parts();

    let mut request = http::Request::builder()
        .method("GET")
        .uri(url)
        .header(http::header::HOST, host)
        .body(())
        .map_err(|e| anyhow!("build request: {e}"))?;
    instructions.apply_to_request_http1x(&mut request);

    let mut headers = request.headers().clone();
    headers.remove(http::header::HOST);
    Ok(headers)
}

/// Render the declared cluster layout, sorted by node id.
///
/// When `liveness` is `Some`, a `state` column and an alive count are added
/// from the probe results keyed by `rpc_addr`; when `None`, the layout is
/// reported exactly as declared, without any network state.
fn render(
    nodes: &[NodeAddr],
    liveness: Option<&BTreeMap<SocketAddr, bool>>,
) -> (String, Vec<String>) {
    if nodes.is_empty() {
        return (
            "config declares zero nodes, nothing to lay out.\n".to_string(),
            Vec::new(),
        );
    }

    let mut sorted: Vec<&NodeAddr> = nodes.iter().collect();
    sorted.sort_unstable_by_key(|n| n.id);

    let mut out = String::new();
    if liveness.is_some() {
        out.push_str("  node    disks    state    rpc address\n");
        out.push_str("  ----    -----    -----    -----------\n");
    } else {
        out.push_str("  node    disks    rpc address\n");
        out.push_str("  ----    -----    -----------\n");
    }
    for n in &sorted {
        match liveness {
            Some(map) => {
                let state = match map.get(&n.rpc_addr) {
                    Some(true) => "up",
                    Some(false) => "DOWN",
                    None => "?",
                };
                let _ = writeln!(
                    out,
                    "  {:>4}    {:>5}    {:<5}    {}",
                    n.id, n.disk_count, state, n.rpc_addr
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "  {:>4}    {:>5}    {}",
                    n.id, n.disk_count, n.rpc_addr
                );
            }
        }
    }
    out.push('\n');

    let count = sorted.len();
    let total_disks: u32 = sorted.iter().map(|n| n.disk_count as u32).sum();
    let _ = writeln!(
        out,
        "{} node{} configured, {} disk{} total.",
        count,
        if count == 1 { "" } else { "s" },
        total_disks,
        if total_disks == 1 { "" } else { "s" },
    );

    if let Some(map) = liveness {
        let alive = sorted
            .iter()
            .filter(|n| map.get(&n.rpc_addr) == Some(&true))
            .count();
        let _ = writeln!(
            out,
            "{} / {} node{} alive.",
            alive,
            count,
            if count == 1 { "" } else { "s" }
        );
    }

    let mut dup_ids: Vec<u16> = sorted
        .windows(2)
        .filter(|w| w[0].id == w[1].id)
        .map(|w| w[0].id)
        .collect();
    dup_ids.dedup();
    let warnings = dup_ids
        .into_iter()
        .map(|id| format!("warning: node id {id} declared more than once."))
        .collect();

    (out, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u16, addr: &str, disk_count: u16) -> NodeAddr {
        NodeAddr {
            id,
            rpc_addr: addr.parse::<SocketAddr>().unwrap(),
            disk_count,
        }
    }

    #[test]
    fn empty_config_reports_no_nodes() {
        let (report, warnings) = render(&[], None);
        assert!(report.contains("zero nodes"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn nodes_are_sorted_by_id() {
        let nodes = vec![
            node(2, "127.0.0.1:9002", 1),
            node(0, "127.0.0.1:9000", 1),
            node(1, "127.0.0.1:9001", 1),
        ];
        let (report, warnings) = render(&nodes, None);
        let p0 = report.find("127.0.0.1:9000").unwrap();
        let p1 = report.find("127.0.0.1:9001").unwrap();
        let p2 = report.find("127.0.0.1:9002").unwrap();
        assert!(p0 < p1 && p1 < p2, "nodes should be ordered by id");
        assert!(report.contains("3 nodes configured"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn single_node_uses_singular() {
        let (report, _) = render(&[node(0, "127.0.0.1:9000", 1)], None);
        assert!(report.contains("1 node configured"));
        assert!(report.contains("1 disk total"));
    }

    #[test]
    fn duplicate_ids_are_flagged() {
        let nodes = vec![node(0, "127.0.0.1:9000", 1), node(0, "10.0.0.1:9000", 2)];
        let (_, warnings) = render(&nodes, None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("node id 0 declared more than once."));
    }

    #[test]
    fn disk_count_appears_in_render() {
        let (report, _) = render(
            &[node(0, "127.0.0.1:9000", 4), node(1, "127.0.0.1:9001", 4)],
            None,
        );
        assert!(report.contains("8 disks total"));
    }

    #[test]
    fn default_layout_has_no_state_column() {
        let (report, _) = render(&[node(0, "127.0.0.1:9000", 1)], None);
        assert!(!report.contains("state"));
        assert!(!report.contains("alive"));
    }

    #[test]
    fn sign_ping_produces_sigv4_headers() {
        let cred = Credential {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
        };
        let headers = sign_ping(
            "http://10.0.0.1:9000/openlake/admin/v1/ping",
            "10.0.0.1:9000",
            &cred,
            "us-east-1",
        )
        .unwrap();

        let auth = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(auth.starts_with("AWS4-HMAC-SHA256"), "got: {auth}");
        assert!(auth.contains("/us-east-1/s3/aws4_request"));
        assert!(headers.contains_key("x-amz-date"));
        assert!(headers.contains_key("x-amz-content-sha256"));
        // host is signed but left to the HTTP client, not returned here.
        assert!(!headers.contains_key(http::header::HOST));
    }

    #[test]
    fn probed_layout_shows_state_and_alive_count() {
        let nodes = vec![node(0, "127.0.0.1:9000", 1), node(1, "127.0.0.1:9001", 1)];
        let liveness = BTreeMap::from([
            ("127.0.0.1:9000".parse::<SocketAddr>().unwrap(), true),
            ("127.0.0.1:9001".parse::<SocketAddr>().unwrap(), false),
        ]);
        let (report, _) = render(&nodes, Some(&liveness));
        assert!(report.contains("state"));
        assert!(report.contains("up"));
        assert!(report.contains("DOWN"));
        assert!(report.contains("1 / 2 nodes alive."));
    }
}
