#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_quic::parse_initial;

fuzz_target!(|data: &[u8]| {
    let _ = parse_initial(data);
});
