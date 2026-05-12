//! `ferroxd` — Ferrox S3-compatible object storage server daemon.
//!
//! Configuration is layered (highest priority wins):
//! 1. Environment variables prefixed `FERROX_`
//! 2. `ferrox.toml` in the current directory (if present)
//! 3. CLI flags
//!
//! ## TLS
//!
//! Pass `--tls-bind`, `--tls-cert`, and `--tls-key` to enable HTTPS in addition
//! to plain HTTP.  All three must be set together.
//!
//! # Example
//!
//! ```text
//! ferroxd --data-dir /var/lib/ferrox --bind 0.0.0.0:9000 \
//!         --tls-bind 0.0.0.0:9443 \
//!         --tls-cert /etc/ferrox/server.crt \
//!         --tls-key  /etc/ferrox/server.key
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{Router, ServiceExt};
use clap::Parser;
use ferrox_gateway::metrics::Metrics;
use ferrox_gateway::middleware::NormalizeAndPreserveLayer;
use ferrox_gateway::ratelimit::PerKeyRateLimiter;
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::{MetaStore, SledMeta};
use ferrox_storage::disk::DiskBackend;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;
use tracing::{info, warn};

/// Ferrox S3-compatible object storage daemon.
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Directory for object data and sled metadata.
    #[arg(long, env = "FERROX_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,

    /// TCP address to listen on (plain HTTP).
    #[arg(long, env = "FERROX_BIND", default_value = "0.0.0.0:9000")]
    bind: SocketAddr,

    /// TCP address to listen on for HTTPS (optional).
    #[arg(long, env = "FERROX_TLS_BIND")]
    tls_bind: Option<SocketAddr>,

    /// Path to PEM-encoded TLS certificate chain (required with --tls-bind).
    #[arg(long, env = "FERROX_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to PEM-encoded TLS private key (required with --tls-bind).
    #[arg(long, env = "FERROX_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// S3 access key for the single-tenant identity.
    #[arg(long, env = "FERROX_ACCESS_KEY", default_value = "minioadmin")]
    access_key: String,

    /// S3 secret key for the single-tenant identity.
    #[arg(long, env = "FERROX_SECRET_KEY", default_value = "minioadmin")]
    secret_key: String,

    /// Maximum clock skew tolerated for SigV4 timestamps (seconds).
    #[arg(long, env = "FERROX_CLOCK_SKEW_SECS", default_value_t = 900)]
    clock_skew_secs: i64,

    /// AWS region this gateway serves. SigV4 verification matches the
    /// request scope's region against this; SigV4A matches the request's
    /// `x-amz-region-set` against this.
    #[arg(long, env = "FERROX_REGION", default_value = "us-east-1")]
    region: String,

    /// Call fsync after every object write.
    #[arg(long, env = "FERROX_FSYNC", default_value_t = true)]
    fsync: bool,

    /// 64-hex-char AES-256 master key for SSE-S3. Leave unset to disable SSE.
    #[arg(long, env = "FERROX_SSE_MASTER_KEY")]
    sse_master_key: Option<String>,

    /// Per-access-key request budget (requests/sec). 0 disables rate limiting.
    #[arg(long, env = "FERROX_MAX_REQ_PER_SEC", default_value_t = 0)]
    max_req_per_sec: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg: Cli = Figment::from(Serialized::defaults(Cli::parse()))
        .merge(Toml::file("ferrox.toml"))
        .merge(Env::prefixed("FERROX_").split("__"))
        .extract()
        .context("failed to load configuration")?;

    info!(
        bind = %cfg.bind,
        data_dir = %cfg.data_dir.display(),
        access_key = %cfg.access_key,
        "starting ferroxd"
    );

    let data_dir = cfg.data_dir.clone();
    let storage = Arc::new(
        DiskBackend::new(data_dir.join("objects"), cfg.fsync)
            .await
            .context("initialising disk storage")?,
    );
    let meta =
        Arc::new(SledMeta::open(data_dir.join("meta")).context("opening sled metadata store")?);

    let sse_master_key = cfg
        .sse_master_key
        .as_deref()
        .map(ferrox_crypto::SseMasterKey::from_hex)
        .transpose()
        .context("invalid FERROX_SSE_MASTER_KEY")?;

    let config = Arc::new(GatewayConfig {
        data_dir: cfg.data_dir,
        access_key: cfg.access_key,
        secret_key: cfg.secret_key,
        fsync: cfg.fsync,
        clock_skew_secs: cfg.clock_skew_secs,
        region: cfg.region,
        sse_master_key,
        max_req_per_sec: cfg.max_req_per_sec,
    });

    let metrics = Metrics::new().context("registering Prometheus metrics")?;
    let rate_limiter = PerKeyRateLimiter::new(cfg.max_req_per_sec);

    let app = build_router(AppState {
        storage,
        meta: Arc::clone(&meta),
        config,
        metrics,
        rate_limiter,
    });

    // Validate TLS config consistency.
    let tls_config = match (&cfg.tls_bind, &cfg.tls_cert, &cfg.tls_key) {
        (Some(addr), Some(cert), Some(key)) => {
            let cfg = load_tls_config(cert, key).context("loading TLS certificate/key")?;
            Some((*addr, cfg))
        }
        (None, None, None) => None,
        _ => anyhow::bail!("--tls-bind, --tls-cert, and --tls-key must all be set together"),
    };

    // Background janitor: clean orphaned multipart staging dirs.
    let janitor_storage_root = data_dir.join("objects");
    let janitor_meta = Arc::clone(&meta);
    tokio::spawn(async move {
        multipart_janitor(janitor_storage_root, janitor_meta, 3600, 86400).await;
    });

    // HTTP listener.
    let http_listener = TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding HTTP listener to {}", cfg.bind))?;

    info!(addr = %cfg.bind, "ferroxd HTTP listening");

    // HTTPS listener (optional). Wrap the router with NormalizeAndPreserveLayer
    // BEFORE serving, so trailing slashes are trimmed prior to path matching
    // (and the original URI is preserved for SigV4 verification).
    if let Some((tls_addr, server_cfg)) = tls_config {
        let tls_listener = TcpListener::bind(tls_addr)
            .await
            .with_context(|| format!("binding HTTPS listener to {tls_addr}"))?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        info!(addr = %tls_addr, "ferroxd HTTPS listening");

        let tls_app = app.clone();
        tokio::spawn(async move {
            tls_accept_loop(tls_listener, tls_acceptor, tls_app).await;
        });
    }

    let http_app = tower::Layer::layer(&NormalizeAndPreserveLayer, app);
    axum::serve(http_listener, ServiceExt::into_make_service(http_app))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server error")?;

    info!("ferroxd shut down cleanly");
    Ok(())
}

/// Accepts TLS connections and dispatches each to the axum app.
async fn tls_accept_loop(listener: TcpListener, acceptor: TlsAcceptor, app: Router) {
    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer_addr)) => {
                let acceptor = acceptor.clone();
                let svc = app.clone();
                tokio::spawn(async move {
                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            // Bridge tower::Service (axum Router) → hyper::Service.
                            // axum Router accepts Request<Body>; hyper gives Request<Incoming>.
                            let hyper_svc = TowerToHyperService::new(svc.map_request(
                                |req: hyper::Request<hyper::body::Incoming>| {
                                    req.map(axum::body::Body::new)
                                },
                            ));
                            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(io, hyper_svc)
                                .await
                            {
                                warn!(peer = %peer_addr, "TLS connection error: {e}");
                            }
                        }
                        Err(e) => warn!(peer = %peer_addr, "TLS handshake error: {e}"),
                    }
                });
            }
            Err(e) => {
                warn!("TLS accept error: {e}");
            }
        }
    }
}

/// Build a `rustls::ServerConfig` from PEM cert chain + private key files.
fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("reading TLS cert: {}", cert_path.display()))?;
    let key_data = std::fs::read(key_path)
        .with_context(|| format!("reading TLS key: {}", key_path.display()))?;

    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut cert_data.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing TLS certificate chain")?;

    let private_key = private_key(&mut key_data.as_slice())
        .context("parsing TLS private key")?
        .context("no private key found in key file")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("building rustls ServerConfig")?;

    // Advertise HTTP/1.1 and HTTP/2 via ALPN.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

/// Periodically removes orphaned multipart staging directories.
///
/// A staging dir is considered orphaned when `interval_secs` have elapsed since
/// it was last modified AND the corresponding upload ID has no entry in the meta
/// store (i.e. the upload was never completed or the meta record was lost).
///
/// `interval_secs` — how often to scan (seconds between runs).
/// `ttl_secs`      — minimum age of a staging dir before it is eligible for removal.
async fn multipart_janitor<M: MetaStore>(
    storage_root: PathBuf,
    meta: Arc<M>,
    interval_secs: u64,
    ttl_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let staging_root = storage_root.join(".multipart");
        let mut rd = match tokio::fs::read_dir(&staging_root).await {
            Ok(rd) => rd,
            Err(_) => continue, // directory doesn't exist yet — nothing to clean
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let upload_id = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta_info) = entry.metadata().await else {
                continue;
            };
            let age_secs = meta_info
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if age_secs < ttl_secs {
                continue;
            }
            // Only remove if the meta record is also gone (truly orphaned).
            match meta.get_multipart_upload(&upload_id).await {
                Ok(_) => {} // still tracked — leave it alone
                Err(_) => {
                    let path = staging_root.join(&upload_id);
                    if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                        warn!(upload_id = %upload_id, "janitor: failed to remove staging dir: {e}");
                    } else {
                        info!(upload_id = %upload_id, "janitor: removed orphaned staging dir");
                    }
                }
            }
        }
    }
}

/// Resolves on SIGTERM or Ctrl-C.
///
/// If signal handler installation fails (e.g. running without a controlling
/// tty), we log a warning and fall through to a never-ready future. The
/// process can still be terminated externally; we just won't get clean
/// shutdown via the signal path.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "Ctrl-C handler unavailable");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm => {},
    }
    info!("shutdown signal received");
}
