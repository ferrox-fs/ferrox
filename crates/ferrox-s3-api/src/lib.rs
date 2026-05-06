//! AWS S3 wire-format types and validators for Ferrox.
//!
//! - [`error`]      — `<Error>` XML envelope for failure responses
//! - [`names`]      — bucket / object key validators (S3 spec)
//! - [`xml`]        — list-result XML serializers (Step 13–14)

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod names;
pub mod xml;
