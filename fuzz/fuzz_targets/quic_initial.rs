#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_inspection::QuicInitialInspector;
use volparossa_quic::parse_initial;

fuzz_target!(|data: &[u8]| {
    let Ok(initial) = parse_initial(data) else {
        return;
    };
    let Ok(mut inspector) = QuicInitialInspector::new(initial.destination_connection_id) else {
        return;
    };
    let _ = inspector.inspect_datagram(data);
});
