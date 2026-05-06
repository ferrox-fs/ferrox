//! S3 XML serializers and parsers.
//!
//! Serialisation is hand-rolled (not serde-derived) because AWS requires fixed
//! namespace attributes and strict child element ordering.
//!
//! Parsing uses `quick-xml` for the `<Delete>` batch-delete request body.

use quick_xml::events::Event;
use quick_xml::Reader;
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// One entry in a `ListAllMyBucketsResult` response.
pub struct BucketEntry<'a> {
    /// Bucket name.
    pub name: &'a str,
    /// Bucket creation timestamp.
    pub creation_date: OffsetDateTime,
}

/// One entry in a `ListBucketResult` response (i.e. one object).
pub struct ContentsEntry<'a> {
    /// Object key.
    pub key: &'a str,
    /// Last-modified timestamp.
    pub last_modified: OffsetDateTime,
    /// AWS-compatible ETag (already quoted).
    pub etag: &'a str,
    /// Object byte size.
    pub size: u64,
}

/// Render `ListAllMyBucketsResult`.
pub fn list_all_my_buckets(
    owner_id: &str,
    owner_display: &str,
    buckets: &[BucketEntry<'_>],
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<ListAllMyBucketsResult xmlns=\"{NS}\">"));
    out.push_str("<Owner><ID>");
    out.push_str(&escape(owner_id));
    out.push_str("</ID><DisplayName>");
    out.push_str(&escape(owner_display));
    out.push_str("</DisplayName></Owner>");
    out.push_str("<Buckets>");
    for b in buckets {
        out.push_str("<Bucket><Name>");
        out.push_str(&escape(b.name));
        out.push_str("</Name><CreationDate>");
        out.push_str(&iso8601(b.creation_date));
        out.push_str("</CreationDate></Bucket>");
    }
    out.push_str("</Buckets></ListAllMyBucketsResult>");
    out.into_bytes()
}

/// Render `ListBucketResult` (V2).
#[allow(clippy::too_many_arguments)]
pub fn list_bucket_v2(
    bucket: &str,
    prefix: Option<&str>,
    contents: &[ContentsEntry<'_>],
    is_truncated: bool,
    next_continuation_token: Option<&str>,
    continuation_token: Option<&str>,
    max_keys: u32,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<ListBucketResult xmlns=\"{NS}\">"));
    out.push_str("<Name>");
    out.push_str(&escape(bucket));
    out.push_str("</Name>");
    out.push_str("<Prefix>");
    out.push_str(&escape(prefix.unwrap_or("")));
    out.push_str("</Prefix>");
    out.push_str(&format!("<KeyCount>{}</KeyCount>", contents.len()));
    out.push_str(&format!("<MaxKeys>{}</MaxKeys>", max_keys));
    out.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        if is_truncated { "true" } else { "false" }
    ));
    if let Some(t) = continuation_token {
        out.push_str("<ContinuationToken>");
        out.push_str(&escape(t));
        out.push_str("</ContinuationToken>");
    }
    if let Some(t) = next_continuation_token {
        out.push_str("<NextContinuationToken>");
        out.push_str(&escape(t));
        out.push_str("</NextContinuationToken>");
    }
    for c in contents {
        out.push_str("<Contents>");
        out.push_str("<Key>");
        out.push_str(&escape(c.key));
        out.push_str("</Key>");
        out.push_str("<LastModified>");
        out.push_str(&iso8601(c.last_modified));
        out.push_str("</LastModified>");
        out.push_str("<ETag>");
        out.push_str(&escape(c.etag));
        out.push_str("</ETag>");
        out.push_str(&format!("<Size>{}</Size>", c.size));
        out.push_str("<StorageClass>STANDARD</StorageClass>");
        out.push_str("</Contents>");
    }
    out.push_str("</ListBucketResult>");
    out.into_bytes()
}

/// Render `CopyObjectResult` XML.
pub fn copy_object_result(etag: &str, last_modified: OffsetDateTime) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<CopyObjectResult xmlns=\"{NS}\">"));
    out.push_str("<ETag>");
    out.push_str(&escape(etag));
    out.push_str("</ETag><LastModified>");
    out.push_str(&iso8601(last_modified));
    out.push_str("</LastModified></CopyObjectResult>");
    out.into_bytes()
}

/// Render `DeleteResult` XML for the `DeleteObjects` batch-delete response.
///
/// `deleted` — keys that were removed successfully.
/// `errors`  — `(key, code, message)` tuples for per-key failures.
pub fn delete_result(deleted: &[&str], errors: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<DeleteResult xmlns=\"{NS}\">"));
    for key in deleted {
        out.push_str("<Deleted><Key>");
        out.push_str(&escape(key));
        out.push_str("</Key></Deleted>");
    }
    for (key, code, message) in errors {
        out.push_str("<Error><Key>");
        out.push_str(&escape(key));
        out.push_str("</Key><Code>");
        out.push_str(&escape(code));
        out.push_str("</Code><Message>");
        out.push_str(&escape(message));
        out.push_str("</Message></Error>");
    }
    out.push_str("</DeleteResult>");
    out.into_bytes()
}

/// Render `VersioningConfiguration` XML for GetBucketVersioning responses.
pub fn versioning_configuration(status: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<VersioningConfiguration xmlns=\"{NS}\">"));
    if !status.is_empty() {
        out.push_str("<Status>");
        out.push_str(&escape(status));
        out.push_str("</Status>");
    }
    out.push_str("</VersioningConfiguration>");
    out.into_bytes()
}

/// Parse a `VersioningConfiguration` XML request body.
/// Returns the `Status` string (`"Enabled"` or `"Suspended"`).
pub fn parse_versioning_configuration(xml_bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);
    let mut in_status = false;
    let mut status = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.name().as_ref() == b"Status" => in_status = true,
            Ok(Event::Text(e)) if in_status => {
                status = e.unescape().map_err(|e| e.to_string())?.to_string();
                in_status = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    Ok(status)
}

/// Parse a `DeleteObjects` request body `<Delete><Object><Key>…</Key></Object>…`.
///
/// Returns the list of keys to delete (max 1 000).
/// Returns `Err` on malformed XML or if the key count exceeds 1 000.
pub fn parse_delete_request(xml_bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut keys = Vec::new();
    let mut in_key = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.name().as_ref() == b"Key" => {
                in_key = true;
            }
            Ok(Event::Text(e)) if in_key => {
                let key = e
                    .unescape()
                    .map_err(|e| format!("XML decode error: {e}"))?
                    .to_string();
                keys.push(key);
                in_key = false;
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"Key" => {
                in_key = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(format!(
                    "XML parse error at {}: {}",
                    reader.buffer_position(),
                    e
                ))
            }
            _ => {}
        }
    }

    if keys.len() > 1000 {
        return Err(format!("too many keys: {} (max 1000)", keys.len()));
    }
    Ok(keys)
}

/// Render `InitiateMultipartUploadResult` XML.
pub fn initiate_multipart_upload_result(bucket: &str, key: &str, upload_id: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<InitiateMultipartUploadResult xmlns=\"{NS}\">"));
    out.push_str("<Bucket>");
    out.push_str(&escape(bucket));
    out.push_str("</Bucket><Key>");
    out.push_str(&escape(key));
    out.push_str("</Key><UploadId>");
    out.push_str(&escape(upload_id));
    out.push_str("</UploadId></InitiateMultipartUploadResult>");
    out.into_bytes()
}

/// Render `CompleteMultipartUploadResult` XML.
pub fn complete_multipart_upload_result(
    bucket: &str,
    key: &str,
    location: &str,
    etag: &str,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<CompleteMultipartUploadResult xmlns=\"{NS}\">"));
    out.push_str("<Location>");
    out.push_str(&escape(location));
    out.push_str("</Location><Bucket>");
    out.push_str(&escape(bucket));
    out.push_str("</Bucket><Key>");
    out.push_str(&escape(key));
    out.push_str("</Key><ETag>");
    out.push_str(&escape(etag));
    out.push_str("</ETag></CompleteMultipartUploadResult>");
    out.into_bytes()
}

/// Parse a `CompleteMultipartUpload` request body.
/// Returns `(part_number, etag)` pairs in document order.
pub fn parse_complete_multipart(xml_bytes: &[u8]) -> Result<Vec<(u32, String)>, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut parts: Vec<(u32, String)> = Vec::new();
    let mut cur_part: u32 = 0;
    let mut cur_etag = String::new();
    let mut in_part_number = false;
    let mut in_etag = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"PartNumber" => in_part_number = true,
                b"ETag" => in_etag = true,
                _ => {}
            },
            Ok(Event::Text(e)) if in_part_number => {
                let s = e.unescape().map_err(|e| e.to_string())?;
                cur_part = s.trim().parse().map_err(|_| "invalid PartNumber")?;
                in_part_number = false;
            }
            Ok(Event::Text(e)) if in_etag => {
                cur_etag = e.unescape().map_err(|e| e.to_string())?.to_string();
                in_etag = false;
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"Part" => {
                if cur_part == 0 {
                    return Err("missing PartNumber".into());
                }
                parts.push((cur_part, cur_etag.clone()));
                cur_part = 0;
                cur_etag.clear();
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"ETag" => {
                in_etag = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    Ok(parts)
}

/// One in-progress upload entry for `ListMultipartUploadsResult`.
pub struct UploadEntry<'a> {
    /// Destination key.
    pub key: &'a str,
    /// Upload ID.
    pub upload_id: &'a str,
    /// When the upload was initiated.
    pub initiated: OffsetDateTime,
}

/// Render `ListMultipartUploadsResult` XML.
pub fn list_multipart_uploads_result(bucket: &str, uploads: &[UploadEntry<'_>]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<ListMultipartUploadsResult xmlns=\"{NS}\">"));
    out.push_str("<Bucket>");
    out.push_str(&escape(bucket));
    out.push_str("</Bucket>");
    for u in uploads {
        out.push_str("<Upload>");
        out.push_str("<Key>");
        out.push_str(&escape(u.key));
        out.push_str("</Key><UploadId>");
        out.push_str(&escape(u.upload_id));
        out.push_str("</UploadId><Initiated>");
        out.push_str(&iso8601(u.initiated));
        out.push_str("</Initiated></Upload>");
    }
    out.push_str("</ListMultipartUploadsResult>");
    out.into_bytes()
}

/// One part entry for `ListPartsResult`.
pub struct PartEntry {
    /// 1-based part number.
    pub part_number: u32,
    /// Part size in bytes.
    pub size: u64,
    /// AWS-compatible ETag (already quoted).
    pub etag: String,
    /// When this part was last written.
    pub last_modified: OffsetDateTime,
}

/// Render `ListPartsResult` XML.
pub fn list_parts_result(bucket: &str, key: &str, upload_id: &str, parts: &[PartEntry]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<ListPartsResult xmlns=\"{NS}\">"));
    out.push_str("<Bucket>");
    out.push_str(&escape(bucket));
    out.push_str("</Bucket><Key>");
    out.push_str(&escape(key));
    out.push_str("</Key><UploadId>");
    out.push_str(&escape(upload_id));
    out.push_str("</UploadId><IsTruncated>false</IsTruncated>");
    for p in parts {
        out.push_str("<Part>");
        out.push_str(&format!("<PartNumber>{}</PartNumber>", p.part_number));
        out.push_str("<LastModified>");
        out.push_str(&iso8601(p.last_modified));
        out.push_str("</LastModified><ETag>");
        out.push_str(&escape(&p.etag));
        out.push_str("</ETag>");
        out.push_str(&format!("<Size>{}</Size>", p.size));
        out.push_str("</Part>");
    }
    out.push_str("</ListPartsResult>");
    out.into_bytes()
}

/// Render `Tagging` XML response (used for both bucket and object tags).
pub fn tagging(tags: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<Tagging xmlns=\"{NS}\">"));
    out.push_str("<TagSet>");
    for (k, v) in tags {
        out.push_str("<Tag><Key>");
        out.push_str(&escape(k));
        out.push_str("</Key><Value>");
        out.push_str(&escape(v));
        out.push_str("</Value></Tag>");
    }
    out.push_str("</TagSet></Tagging>");
    out.into_bytes()
}

/// Parse a `Tagging` request body. Returns `(key, value)` pairs in order.
pub fn parse_tagging(xml_bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);
    let mut tags: Vec<(String, String)> = Vec::new();
    let mut cur_k = String::new();
    let mut cur_v = String::new();
    let mut in_key = false;
    let mut in_value = false;
    let mut have_k = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Key" => in_key = true,
                b"Value" => in_value = true,
                _ => {}
            },
            Ok(Event::Text(e)) if in_key => {
                cur_k = e.unescape().map_err(|e| e.to_string())?.to_string();
                in_key = false;
                have_k = true;
            }
            Ok(Event::Text(e)) if in_value => {
                cur_v = e.unescape().map_err(|e| e.to_string())?.to_string();
                in_value = false;
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"Tag" => {
                if !have_k {
                    return Err("missing Key in Tag".into());
                }
                tags.push((std::mem::take(&mut cur_k), std::mem::take(&mut cur_v)));
                have_k = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    Ok(tags)
}

/// Validate a tag set against AWS limits: ≤10 tags, key ≤128 chars, value ≤256 chars.
pub fn validate_tag_set(tags: &[(String, String)]) -> Result<(), String> {
    if tags.len() > 10 {
        return Err(format!("too many tags: {} (max 10)", tags.len()));
    }
    for (k, v) in tags {
        if k.is_empty() {
            return Err("empty tag key".into());
        }
        if k.len() > 128 {
            return Err(format!("tag key too long: {} chars (max 128)", k.len()));
        }
        if v.len() > 256 {
            return Err(format!("tag value too long: {} chars (max 256)", v.len()));
        }
    }
    Ok(())
}

/// One CORS rule for serialization.
pub struct CorsRuleXml<'a> {
    /// Allowed origins.
    pub allowed_origins: &'a [String],
    /// Allowed methods.
    pub allowed_methods: &'a [String],
    /// Allowed headers.
    pub allowed_headers: &'a [String],
    /// Exposed headers.
    pub expose_headers: &'a [String],
    /// Max-age seconds.
    pub max_age_seconds: Option<u32>,
}

/// Render `CORSConfiguration` XML.
pub fn cors_configuration(rules: &[CorsRuleXml<'_>]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<CORSConfiguration xmlns=\"{NS}\">"));
    for r in rules {
        out.push_str("<CORSRule>");
        for o in r.allowed_origins {
            out.push_str("<AllowedOrigin>");
            out.push_str(&escape(o));
            out.push_str("</AllowedOrigin>");
        }
        for m in r.allowed_methods {
            out.push_str("<AllowedMethod>");
            out.push_str(&escape(m));
            out.push_str("</AllowedMethod>");
        }
        for h in r.allowed_headers {
            out.push_str("<AllowedHeader>");
            out.push_str(&escape(h));
            out.push_str("</AllowedHeader>");
        }
        for h in r.expose_headers {
            out.push_str("<ExposeHeader>");
            out.push_str(&escape(h));
            out.push_str("</ExposeHeader>");
        }
        if let Some(s) = r.max_age_seconds {
            out.push_str(&format!("<MaxAgeSeconds>{s}</MaxAgeSeconds>"));
        }
        out.push_str("</CORSRule>");
    }
    out.push_str("</CORSConfiguration>");
    out.into_bytes()
}

/// One parsed CORS rule.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedCorsRule {
    /// AllowedOrigin entries.
    pub allowed_origins: Vec<String>,
    /// AllowedMethod entries.
    pub allowed_methods: Vec<String>,
    /// AllowedHeader entries.
    pub allowed_headers: Vec<String>,
    /// ExposeHeader entries.
    pub expose_headers: Vec<String>,
    /// MaxAgeSeconds value, if set.
    pub max_age_seconds: Option<u32>,
}

/// Parse a `CORSConfiguration` body.
pub fn parse_cors_config_xml(xml_bytes: &[u8]) -> Result<Vec<ParsedCorsRule>, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);
    let mut rules = Vec::new();
    let mut cur = ParsedCorsRule::default();
    let mut tag: Option<&'static str> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"CORSRule" => cur = ParsedCorsRule::default(),
                b"AllowedOrigin" => tag = Some("AllowedOrigin"),
                b"AllowedMethod" => tag = Some("AllowedMethod"),
                b"AllowedHeader" => tag = Some("AllowedHeader"),
                b"ExposeHeader" => tag = Some("ExposeHeader"),
                b"MaxAgeSeconds" => tag = Some("MaxAgeSeconds"),
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if let Some(name) = tag {
                    let s = e.unescape().map_err(|e| e.to_string())?.to_string();
                    match name {
                        "AllowedOrigin" => cur.allowed_origins.push(s),
                        "AllowedMethod" => {
                            let m = s.to_ascii_uppercase();
                            if !matches!(m.as_str(), "GET" | "PUT" | "POST" | "DELETE" | "HEAD") {
                                return Err(format!("invalid AllowedMethod: {m}"));
                            }
                            cur.allowed_methods.push(m);
                        }
                        "AllowedHeader" => cur.allowed_headers.push(s),
                        "ExposeHeader" => cur.expose_headers.push(s),
                        "MaxAgeSeconds" => {
                            cur.max_age_seconds =
                                Some(s.parse().map_err(|_| "invalid MaxAgeSeconds")?);
                        }
                        _ => {}
                    }
                    tag = None;
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"CORSRule" => {
                rules.push(std::mem::take(&mut cur));
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    Ok(rules)
}

/// Render `ServerSideEncryptionConfiguration` XML.
pub fn encryption_configuration(algorithm: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<ServerSideEncryptionConfiguration xmlns=\"{NS}\">"
    ));
    out.push_str("<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>");
    out.push_str(&escape(algorithm));
    out.push_str("</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>");
    out.push_str("</ServerSideEncryptionConfiguration>");
    out.into_bytes()
}

/// Parse the algorithm from a `ServerSideEncryptionConfiguration` body.
pub fn parse_encryption_configuration(xml_bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);
    let mut in_alg = false;
    let mut alg = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.name().as_ref() == b"SSEAlgorithm" => in_alg = true,
            Ok(Event::Text(e)) if in_alg => {
                alg = e.unescape().map_err(|e| e.to_string())?.to_string();
                in_alg = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    if alg.is_empty() {
        return Err("missing SSEAlgorithm".into());
    }
    Ok(alg)
}

/// Render `NotificationConfiguration` XML response.
pub fn notification_configuration(rules: &[(&str, &[String], &str, &str)]) -> Vec<u8> {
    // Tuple: (id, events, kind, destination). kind = "Topic" | "Webhook".
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<NotificationConfiguration xmlns=\"{NS}\">"));
    for (id, events, kind, dest) in rules {
        out.push_str("<TopicConfiguration>");
        out.push_str("<Id>");
        out.push_str(&escape(id));
        out.push_str("</Id>");
        if *kind == "Topic" {
            out.push_str("<Topic>");
            out.push_str(&escape(dest));
            out.push_str("</Topic>");
        } else {
            out.push_str("<Webhook>");
            out.push_str(&escape(dest));
            out.push_str("</Webhook>");
        }
        for ev in *events {
            out.push_str("<Event>");
            out.push_str(&escape(ev));
            out.push_str("</Event>");
        }
        out.push_str("</TopicConfiguration>");
    }
    out.push_str("</NotificationConfiguration>");
    out.into_bytes()
}

/// One parsed notification rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedNotificationRule {
    /// Rule id.
    pub id: String,
    /// Event filters.
    pub events: Vec<String>,
    /// `"Topic"` | `"Webhook"`.
    pub kind: String,
    /// Destination ARN/URL.
    pub destination: String,
}

/// Parse a `NotificationConfiguration` body.
pub fn parse_notification_configuration(
    xml_bytes: &[u8],
) -> Result<Vec<ParsedNotificationRule>, String> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);
    let mut rules = Vec::new();
    let mut cur = ParsedNotificationRule::default();
    let mut tag: Option<&'static str> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"TopicConfiguration" => cur = ParsedNotificationRule::default(),
                b"Id" => tag = Some("Id"),
                b"Event" => tag = Some("Event"),
                b"Topic" => tag = Some("Topic"),
                b"Webhook" => tag = Some("Webhook"),
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if let Some(name) = tag {
                    let s = e.unescape().map_err(|e| e.to_string())?.to_string();
                    match name {
                        "Id" => cur.id = s,
                        "Event" => cur.events.push(s),
                        "Topic" => {
                            cur.kind = "Topic".into();
                            cur.destination = s;
                        }
                        "Webhook" => {
                            cur.kind = "Webhook".into();
                            cur.destination = s;
                        }
                        _ => {}
                    }
                    tag = None;
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"TopicConfiguration" => {
                if cur.kind.is_empty() {
                    return Err("notification rule missing Topic/Webhook".into());
                }
                rules.push(std::mem::take(&mut cur));
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML error: {e}")),
            _ => {}
        }
    }
    Ok(rules)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn iso8601(t: OffsetDateTime) -> String {
    t.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn test_list_all_my_buckets_renders_owner_and_each_bucket() {
        let buckets = vec![BucketEntry {
            name: "photos",
            creation_date: datetime!(2026-05-04 12:00:00 UTC),
        }];
        let bytes = list_all_my_buckets("oid", "owner", &buckets);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("<ListAllMyBucketsResult"));
        assert!(s.contains("<Name>photos</Name>"));
        assert!(s.contains("<DisplayName>owner</DisplayName>"));
    }

    #[test]
    fn test_list_bucket_v2_renders_truncation_token() {
        let entries = vec![ContentsEntry {
            key: "a.txt",
            last_modified: datetime!(2026-05-04 12:00:00 UTC),
            etag: "\"abc\"",
            size: 42,
        }];
        let bytes = list_bucket_v2("b", Some("a"), &entries, true, Some("tok"), None, 1);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("<IsTruncated>true</IsTruncated>"));
        assert!(s.contains("<NextContinuationToken>tok</NextContinuationToken>"));
        assert!(s.contains("<Key>a.txt</Key>"));
        assert!(s.contains("<Size>42</Size>"));
    }
}
