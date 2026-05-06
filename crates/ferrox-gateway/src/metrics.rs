//! Prometheus metrics registry + recording layer (Phase 2 Step 29).
//!
//! Exposes `/metrics` (no auth, scrape-friendly) returning the standard
//! Prometheus text exposition format.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::Request;
use axum::http::{header, Response};
use futures::future::BoxFuture;
use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Server-wide metrics, cheap to clone (every field is `Arc`/registered).
#[derive(Clone)]
pub struct Metrics {
    /// Underlying Prometheus registry — exposed for `/metrics` rendering.
    pub registry: Arc<Registry>,
    /// `ferrox_requests_total{method, endpoint, status}`.
    pub requests_total: IntCounterVec,
    /// `ferrox_request_duration_seconds{method, endpoint}`.
    pub request_duration: HistogramVec,
    /// `ferrox_bytes_in_total{bucket}`.
    pub bytes_in: IntCounterVec,
    /// `ferrox_bytes_out_total{bucket}`.
    pub bytes_out: IntCounterVec,
    /// `ferrox_objects_total{bucket}`.
    pub objects_total: IntGaugeVec,
    /// `ferrox_storage_bytes{bucket}`.
    pub storage_bytes: GaugeVec,
    /// `ferrox_active_connections`.
    pub active_connections: Gauge,
    /// `ferrox_multipart_pending_total`.
    pub multipart_pending: Gauge,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Build a new metrics registry. Panics if metric registration fails (only
    /// possible on duplicate registration in the same process — not user input).
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());

        let requests_total = IntCounterVec::new(
            Opts::new("ferrox_requests_total", "S3 requests handled"),
            &["method", "endpoint", "status"],
        )
        .expect("metric registration");
        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "ferrox_request_duration_seconds",
                "S3 request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["method", "endpoint"],
        )
        .expect("metric registration");
        let bytes_in = IntCounterVec::new(
            Opts::new("ferrox_bytes_in_total", "Bytes received per bucket"),
            &["bucket"],
        )
        .expect("metric registration");
        let bytes_out = IntCounterVec::new(
            Opts::new("ferrox_bytes_out_total", "Bytes sent per bucket"),
            &["bucket"],
        )
        .expect("metric registration");
        let objects_total = IntGaugeVec::new(
            Opts::new("ferrox_objects_total", "Objects per bucket"),
            &["bucket"],
        )
        .expect("metric registration");
        let storage_bytes = GaugeVec::new(
            Opts::new("ferrox_storage_bytes", "Logical bytes stored per bucket"),
            &["bucket"],
        )
        .expect("metric registration");
        let active_connections = Gauge::new(
            "ferrox_active_connections",
            "Currently in-flight HTTP requests",
        )
        .expect("metric registration");
        let multipart_pending = Gauge::new(
            "ferrox_multipart_pending_total",
            "In-progress multipart uploads",
        )
        .expect("metric registration");

        for m in [
            Box::new(requests_total.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(request_duration.clone()),
            Box::new(bytes_in.clone()),
            Box::new(bytes_out.clone()),
            Box::new(objects_total.clone()),
            Box::new(storage_bytes.clone()),
            Box::new(active_connections.clone()),
            Box::new(multipart_pending.clone()),
        ] {
            registry.register(m).expect("metric registration");
        }

        Self {
            registry,
            requests_total,
            request_duration,
            bytes_in,
            bytes_out,
            objects_total,
            storage_bytes,
            active_connections,
            multipart_pending,
        }
    }

    /// Render the registry in the Prometheus text exposition format.
    pub fn render(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let metric_families = self.registry.gather();
        TextEncoder::new().encode(&metric_families, &mut buf).ok();
        buf
    }
}

/// Best-effort label for a request path. Coarse — avoids high cardinality.
fn endpoint_label(path: &str, query: Option<&str>) -> &'static str {
    if path == "/" {
        return "list_buckets";
    }
    let q = query.unwrap_or("");
    if q.contains("uploads") {
        return "multipart";
    }
    if q.contains("uploadId=") {
        return "multipart";
    }
    if q.contains("delete") {
        return "delete_objects";
    }
    if q.contains("tagging") {
        return "tagging";
    }
    if q.contains("cors") {
        return "cors";
    }
    if q.contains("encryption") {
        return "encryption";
    }
    if q.contains("versioning") {
        return "versioning";
    }
    let parts: Vec<&str> = path.trim_start_matches('/').splitn(2, '/').collect();
    if parts.len() == 1 {
        "bucket"
    } else {
        "object"
    }
}

/// Tower layer that records request count + latency into [`Metrics`].
#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Metrics,
}

impl MetricsLayer {
    /// Build a new layer wrapping the supplied [`Metrics`].
    pub fn new(metrics: Metrics) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

/// Tower service implementing the metrics recording.
#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    metrics: Metrics,
}

impl<S, B> Service<Request> for MetricsService<S>
where
    S: Service<Request, Response = Response<B>> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<B>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let metrics = self.metrics.clone();
        let mut inner = self.inner.clone();
        let method = req.method().as_str().to_string();
        let endpoint = endpoint_label(req.uri().path(), req.uri().query());
        let started = Instant::now();
        metrics.active_connections.inc();
        Box::pin(async move {
            let resp = inner.call(req).await;
            metrics.active_connections.dec();
            if let Ok(r) = &resp {
                let status = r.status().as_u16().to_string();
                metrics
                    .requests_total
                    .with_label_values(&[&method, endpoint, &status])
                    .inc();
                metrics
                    .request_duration
                    .with_label_values(&[&method, endpoint])
                    .observe(started.elapsed().as_secs_f64());
                // Attempt to extract content-length for byte counters when path
                // includes a bucket segment.
                if let Some(cl) = r
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if matches!(endpoint, "object") && method == "GET" {
                        // bucket label unknown at layer level — record under "_".
                        metrics.bytes_out.with_label_values(&["_"]).inc_by(cl);
                    }
                }
            }
            resp
        })
    }
}
