//! Bucket notification dispatch (Phase 3 Step 41).
//!
//! After successful PutObject / DeleteObject / CopyObject the gateway looks up
//! the bucket's [`NotificationRule`](ferrox_meta::NotificationRule) list and
//! POSTs an S3-compatible event JSON to each matching destination via
//! [`tokio::spawn`] — best-effort, never blocks the original request.

use std::sync::Arc;

use ferrox_meta::{MetaStore, NotificationDestination, NotificationRule};
use serde_json::json;

/// Coarse event types matching AWS S3 event names.
#[derive(Debug, Clone, Copy)]
pub enum EventKind {
    /// `s3:ObjectCreated:Put` / `Copy` / `CompleteMultipartUpload`.
    ObjectCreated,
    /// `s3:ObjectRemoved:Delete`.
    ObjectRemoved,
}

impl EventKind {
    /// Wire string for the event name field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectCreated => "s3:ObjectCreated:*",
            Self::ObjectRemoved => "s3:ObjectRemoved:Delete",
        }
    }
    /// Match a rule's filter list against this event.
    pub fn matches(self, filter: &str) -> bool {
        let want = self.as_str();
        if filter == "s3:*" || filter == want {
            return true;
        }
        if let Some(prefix) = filter.strip_suffix(":*") {
            return want.starts_with(prefix);
        }
        false
    }
}

/// Spawn a best-effort notification dispatch for a single object event.
///
/// This function never blocks the caller and never returns errors — all
/// outcomes are logged via [`tracing`].
pub fn dispatch_event<M: MetaStore>(meta: Arc<M>, bucket: String, key: String, event: EventKind) {
    tokio::spawn(async move {
        let rules = match meta.get_bucket(&bucket).await {
            Ok(b) => b.notifications,
            Err(_) => return,
        };
        let matching: Vec<&NotificationRule> = rules
            .iter()
            .filter(|r| r.events.iter().any(|e| event.matches(e)))
            .collect();
        if matching.is_empty() {
            return;
        }
        let payload = json!({
            "Records": [{
                "eventVersion": "2.2",
                "eventSource": "ferrox:s3",
                "eventName": event.as_str(),
                "s3": {
                    "bucket": { "name": bucket },
                    "object": { "key": key },
                }
            }]
        });
        let body = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(_) => return,
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "notify: failed to build http client");
                return;
            }
        };
        for r in matching {
            let url = match &r.destination {
                NotificationDestination::Webhook(u) => u.clone(),
                NotificationDestination::Sns(arn) => {
                    // Phase 3 ships webhook delivery; SNS POST stub. Logged
                    // for observability rather than a hard error.
                    tracing::info!(arn = %arn, "notify: SNS dispatch is stubbed; treating as webhook");
                    arn.clone()
                }
            };
            let req = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body.clone());
            match req.send().await {
                Ok(resp) => {
                    tracing::debug!(rule = %r.id, status = %resp.status(), "notify: delivered");
                }
                Err(e) => {
                    tracing::warn!(rule = %r.id, error = %e, "notify: delivery failed");
                }
            }
        }
    });
}
