#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_quic::{decode_request, decode_response};

fuzz_target!(|data: &[u8]| {
    let _ = decode_request(data);
    let _ = decode_response(data);
});
