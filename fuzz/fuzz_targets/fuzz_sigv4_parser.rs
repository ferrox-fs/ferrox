#![no_main]

use libfuzzer_sys::fuzz_target;

// Target the SigV4 Authorization header parser. Goal: panic-freedom.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ferrox_gateway::auth::SigV4Header::from_authorization_header(s);
    }
});
