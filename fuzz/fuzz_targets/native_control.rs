#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_quic::{decode_request, decode_response};

fuzz_target!(|data: &[u8]| {
    let _ = decode_request(data);
    let _ = decode_response(data);
    // Existing bounded local service parser, including DPS v1. The evaluation clock
    // and all generated observations are synthetic; this is not sensor acceptance.
    if let Ok(request) = volparossa_local_control::decode_request(data)
        && let Some(volparossa_local_control::control_request::Operation::DpsAssess(input)) =
            request.operation
        && let Ok(assessment) = input.assess(1_750_000_000_000)
    {
        assert!(assessment.validate().is_ok());
    }
    let _ = volparossa_local_control::decode_response(data);
});
