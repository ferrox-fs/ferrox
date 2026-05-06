//! Map [`FerroxError`] into an axum [`Response`] carrying the AWS S3
//! `<Error>` XML envelope.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use ferrox_error::FerroxError;
use ferrox_s3_api::error as s3_error;
use http_body_util::Full;

use crate::middleware::RequestId;

/// Newtype around [`FerroxError`] that implements [`IntoResponse`] so handlers
/// can `?` straight out of `Result<_, AppError>`.
#[derive(Debug)]
pub struct AppError {
    err: FerroxError,
    resource: String,
    request_id: String,
}

impl AppError {
    /// Build with explicit resource path and request id.
    pub fn new(
        err: FerroxError,
        resource: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            err,
            resource: resource.into(),
            request_id: request_id.into(),
        }
    }

    /// Build from a `FerroxError`, pulling the request id off the request
    /// extension and the resource off the URI.
    pub fn from_request(err: FerroxError, req: &axum::extract::Request) -> Self {
        let rid = req
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_default();
        Self {
            err,
            resource: req.uri().path().to_string(),
            request_id: rid,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = s3_error::render(&self.err, &self.request_id, &self.resource);
        let mut resp = Response::new(axum::body::Body::new(Full::new(Bytes::from(body))));
        *resp.status_mut() =
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        resp
    }
}

impl From<FerroxError> for AppError {
    fn from(err: FerroxError) -> Self {
        Self {
            err,
            resource: String::new(),
            request_id: String::new(),
        }
    }
}
