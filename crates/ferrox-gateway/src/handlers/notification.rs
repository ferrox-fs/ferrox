//! Bucket notification configuration handlers (Phase 3 Step 41).
//!
//! Storage of the rules; dispatch lives in [`crate::notify`].

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ferrox_error::FerroxError;
use ferrox_meta::{MetaStore, NotificationDestination, NotificationRule};
use ferrox_s3_api::names::validate_bucket_name;
use ferrox_s3_api::xml::{notification_configuration, parse_notification_configuration};
use ferrox_storage::StorageBackend;

use crate::error::{empty_response, xml_response, AppError};
use crate::middleware::RequestId;
use crate::state::AppState;

/// `PUT /{bucket}?notification` — replace bucket notification rules.
pub async fn put_bucket_notification<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;
    let raw = to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let parsed = parse_notification_configuration(&raw)
        .map_err(|m| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {m}"))))?;

    let rules: Vec<NotificationRule> = parsed
        .into_iter()
        .map(|p| NotificationRule {
            id: p.id,
            events: p.events,
            destination: if p.kind == "Topic" {
                NotificationDestination::Sns(p.destination)
            } else {
                NotificationDestination::Webhook(p.destination)
            },
        })
        .collect();

    state
        .meta
        .set_bucket_notifications(&bucket, rules)
        .await
        .map_err(to_app)?;

    Ok(empty_response(StatusCode::OK, &rid))
}

/// `GET /{bucket}?notification` — fetch notification rules.
pub async fn get_bucket_notification<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;
    let meta = state.meta.get_bucket(&bucket).await.map_err(to_app)?;

    let rules: Vec<(&str, &[String], &str, &str)> = meta
        .notifications
        .iter()
        .map(|r| {
            let (kind, dest) = match &r.destination {
                NotificationDestination::Sns(s) => ("Topic", s.as_str()),
                NotificationDestination::Webhook(w) => ("Webhook", w.as_str()),
            };
            (r.id.as_str(), r.events.as_slice(), kind, dest)
        })
        .collect();

    let xml = notification_configuration(&rules);
    Ok(xml_response(StatusCode::OK, &rid, xml))
}
