#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ferrox_s3_api::names::validate_object_key(s);
        let _ = ferrox_s3_api::names::validate_bucket_name(s);
    }
});
