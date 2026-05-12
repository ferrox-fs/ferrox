//! SigV4 + SigV4A authentication primitives: header parsing, key derivation,
//! and signature verification.

pub mod sigv4;
pub mod sigv4a;
pub mod verifier;

pub use sigv4::SigV4Header;
pub use sigv4a::{
    derive_sigv4a_signing_key, parse_sigv4a_query, region_matches_set, verify_presigned_sigv4a,
    verify_sigv4a, SigV4AHeader,
};
pub use verifier::{verify_presigned_url, verify_sigv4};
