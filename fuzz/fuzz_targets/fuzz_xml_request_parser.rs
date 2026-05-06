#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ferrox_s3_api::xml::parse_delete_request(data);
    let _ = ferrox_s3_api::xml::parse_complete_multipart(data);
    let _ = ferrox_s3_api::xml::parse_cors_config_xml(data);
    let _ = ferrox_s3_api::xml::parse_tagging(data);
    let _ = ferrox_s3_api::xml::parse_encryption_configuration(data);
    let _ = ferrox_s3_api::xml::parse_notification_configuration(data);
});
