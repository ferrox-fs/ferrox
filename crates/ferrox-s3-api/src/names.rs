//! Bucket / key name validators per AWS S3 spec.

use ferrox_error::FerroxError;

/// Validate a bucket name against the AWS S3 DNS-compatible naming rules.
///
/// - 3 to 63 characters
/// - lowercase letters, digits, hyphen, dot
/// - must start and end with letter or digit
/// - no consecutive dots
/// - not formatted as an IP address
///
/// Returns [`FerroxError::InvalidRequest`] when invalid.
pub fn validate_bucket_name(name: &str) -> Result<(), FerroxError> {
    let n = name.len();
    if !(3..=63).contains(&n) {
        return Err(FerroxError::InvalidRequest(format!(
            "bucket name must be 3-63 chars, got {n}"
        )));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[n - 1].is_ascii_alphanumeric() {
        return Err(FerroxError::InvalidRequest(
            "bucket name must start and end with [a-z0-9]".into(),
        ));
    }
    let mut prev_dot = false;
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.';
        if !ok {
            return Err(FerroxError::InvalidRequest(
                "bucket name has invalid characters".into(),
            ));
        }
        if b == b'.' && prev_dot {
            return Err(FerroxError::InvalidRequest(
                "bucket name has consecutive dots".into(),
            ));
        }
        prev_dot = b == b'.';
    }
    if name.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(FerroxError::InvalidRequest(
            "bucket name must not be IPv4".into(),
        ));
    }
    Ok(())
}

/// Validate an object key. AWS allows any UTF-8 string up to 1024 bytes.
pub fn validate_object_key(key: &str) -> Result<(), FerroxError> {
    let n = key.len();
    if n == 0 {
        return Err(FerroxError::InvalidRequest("empty object key".into()));
    }
    if n > 1024 {
        return Err(FerroxError::InvalidRequest(format!(
            "object key exceeds 1024 bytes (got {n})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_name_too_short_invalid() {
        assert!(validate_bucket_name("ab").is_err());
    }

    #[test]
    fn test_bucket_name_too_long_invalid() {
        let s = "a".repeat(64);
        assert!(validate_bucket_name(&s).is_err());
    }

    #[test]
    fn test_bucket_name_uppercase_invalid() {
        assert!(validate_bucket_name("MyBucket").is_err());
    }

    #[test]
    fn test_bucket_name_consecutive_dots_invalid() {
        assert!(validate_bucket_name("a..b").is_err());
    }

    #[test]
    fn test_bucket_name_leading_hyphen_invalid() {
        assert!(validate_bucket_name("-foo").is_err());
    }

    #[test]
    fn test_bucket_name_ipv4_invalid() {
        assert!(validate_bucket_name("192.168.1.1").is_err());
    }

    #[test]
    fn test_bucket_name_valid() {
        assert!(validate_bucket_name("my-bucket-1").is_ok());
        assert!(validate_bucket_name("photos").is_ok());
    }

    #[test]
    fn test_object_key_empty_invalid() {
        assert!(validate_object_key("").is_err());
    }

    #[test]
    fn test_object_key_over_1024_bytes_invalid() {
        let s = "x".repeat(1025);
        assert!(validate_object_key(&s).is_err());
    }

    #[test]
    fn test_object_key_unicode_valid() {
        assert!(validate_object_key("photos/cat.jpg").is_ok());
        assert!(validate_object_key("📷/cute.jpg").is_ok());
    }
}
