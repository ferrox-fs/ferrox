//! Service-level path normalisation that runs BEFORE axum routing.
//!
//! [`NormalizeAndPreserveLayer`] saves the original request URI as an
//! [`OriginalSignedUri`](crate::middleware::auth::OriginalSignedUri) extension
//! and strips a trailing slash from `req.uri()` so the axum router matches
//! `/{bucket}` for `/bucket/` (the form sent by AWS SDK CreateBucket).
//!
//! Must be applied at the SERVICE level (wrapping the whole `Router`), not via
//! `Router::layer`, because axum's `.layer()` wraps each route's service AFTER
//! routing — it cannot influence path matching.

use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::Uri;
use axum::response::Response;
use futures::future::BoxFuture;
use tower::{Layer, Service};

use crate::middleware::auth::OriginalSignedUri;

/// Layer constructor.
#[derive(Debug, Clone, Default)]
pub struct NormalizeAndPreserveLayer;

impl<S> Layer<S> for NormalizeAndPreserveLayer {
    type Service = NormalizeAndPreserveMiddleware<S>;
    fn layer(&self, inner: S) -> Self::Service {
        NormalizeAndPreserveMiddleware { inner }
    }
}

/// Service: stores `req.uri()` in extensions, then trims trailing slash.
#[derive(Debug, Clone)]
pub struct NormalizeAndPreserveMiddleware<S> {
    inner: S,
}

impl<S> Service<Request> for NormalizeAndPreserveMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        // Save the original URI so SigV4 verification reproduces the path
        // exactly as signed by the client.
        let original = req.uri().clone();
        req.extensions_mut().insert(OriginalSignedUri(original));

        // Strip trailing slash if the path is longer than "/" and ends with '/'.
        let path = req.uri().path().to_string();
        if path.len() > 1 && path.ends_with('/') {
            let new_path = &path[..path.len() - 1];
            let pq = match req.uri().query() {
                Some(q) => format!("{new_path}?{q}"),
                None => new_path.to_string(),
            };
            if let Ok(new_uri) = pq.parse::<Uri>() {
                let (mut parts, body) = req.into_parts();
                parts.uri = new_uri;
                req = Request::from_parts(parts, body);
            }
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}
