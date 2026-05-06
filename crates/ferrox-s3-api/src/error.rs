//! AWS S3 `<Error>` XML envelope.
//!
//! AWS clients dispatch on the `<Code>` element, so the body must be
//! byte-exact. This module never relies on serde's XML output (which is
//! quirky around namespaces); it formats by hand.

use ferrox_error::FerroxError;

/// Render the body and return `(http_status, body_bytes)`.
pub fn render(err: &FerroxError, request_id: &str, resource: &str) -> (u16, Vec<u8>) {
    let code = err.s3_error_code();
    let msg = err.to_string();
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <Error><Code>{code}</Code><Message>{msg}</Message>\
         <Resource>{resource}</Resource>\
         <RequestId>{request_id}</RequestId></Error>",
        code = escape(code),
        msg = escape(&msg),
        resource = escape(resource),
        request_id = escape(request_id),
    );
    (err.http_status(), body.into_bytes())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_not_found_object_returns_no_such_key_404() {
        let err = FerroxError::NotFound {
            bucket: "b".into(),
            key: Some("k".into()),
        };
        let (status, body) = render(&err, "rid", "/b/k");
        assert_eq!(status, 404);
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("<Code>NoSuchKey</Code>"));
        assert!(s.contains("<RequestId>rid</RequestId>"));
        assert!(s.contains("<Resource>/b/k</Resource>"));
    }

    #[test]
    fn test_render_escapes_xml_special_chars() {
        let err = FerroxError::InvalidRequest("a<b&c".into());
        let (_, body) = render(&err, "rid", "/x");
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("a&lt;b&amp;c"));
    }
}
