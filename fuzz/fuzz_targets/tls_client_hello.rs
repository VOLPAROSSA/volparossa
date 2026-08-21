#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_inspection::{TlsClientHelloInspector, inspect_client_hello};

fuzz_target!(|data: &[u8]| {
    let _ = inspect_client_hello(data);

    let split = data
        .first()
        .map_or(0, |value| usize::from(*value) % (data.len() + 1));
    let mut stream = TlsClientHelloInspector::new();
    if stream.push(&data[..split]).is_ok() {
        let _ = stream.push(&data[split..]);
    }
});
