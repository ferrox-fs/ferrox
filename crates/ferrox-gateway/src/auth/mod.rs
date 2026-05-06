//! SigV4 authentication primitives: header parsing + HMAC verification.

pub mod sigv4;
pub mod sigv4a;
pub mod verifier;

pub use sigv4::SigV4Header;
pub use sigv4a::{verify_sigv4a, SigV4AHeader};
pub use verifier::{verify_presigned_url, verify_sigv4};
