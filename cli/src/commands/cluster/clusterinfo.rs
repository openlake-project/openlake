use anyhow::{anyhow, Context, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, PayloadChecksumKind, PercentEncodingMode, SessionTokenMode,
    SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use clap::Args as ClapArgs;
use openlake_server::config;
use openlake_server::config::Credential;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(ClapArgs)]
pub struct ClusterInfoArgs {
    /// openlake.toml file
    #[arg(long)]
    pub config: PathBuf,
}

/// Live cluster-info admin endpoint
const CLUSTER_INFO_PATH: &str = "/openlake/admin/v1/cluster/info";

fn sign_cluster_info(
    url: &str,
    host: &str,
    cred: &Credential,
    region: &str,
) -> Result<http::HeaderMap> {
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

pub async fn run(args: ClusterInfoArgs) -> Result<()> {
    // 1. Read the config file
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;

    // 2. Parse the config
    let cfg = config::Config::from_toml(&text)
        .with_context(|| format!("parse {}", args.config.display()))?;

    // 3. Find the S3 port
    let s3_port = cfg.s3_port.unwrap_or_else(|| cfg.s3_addr.port());

    // 4. Use the first node's IP + S3 port
    let endpoint = std::net::SocketAddr::new(
        cfg.nodes[0].rpc_addr.ip(),
        s3_port,
    );

    // 5. Decide http or https
    let scheme = if cfg.s3_tls.is_some() {
        "https"
    } else {
        "http"
    };

    let host = endpoint.to_string();

    // 6. Build the cluster-info URL
    let url = format!(
        "{scheme}://{host}{CLUSTER_INFO_PATH}"
    );

    // 7. Get the first credential
    let cred = cfg
        .credentials
        .first()
        .context("no credentials configured")?;

    // 8. Sign the request
    let signed = sign_cluster_info(
        &url,
        &host,
        cred,
        &cfg.region,
    )?;

    // 9. Send the GET request
    let client = cyper::Client::new();
    let response = client
        .get(&url)?
        .headers(signed)
        .send()
        .await?;

    // 10. Print the live response
    let body = response.text().await?;
    println!("{body}");

    Ok(())
}