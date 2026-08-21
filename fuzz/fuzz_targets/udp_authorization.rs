#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_protocol::{ReplayCache, TimePolicy, UdpFlowAuthorization, verify_control_message};

fuzz_target!(|data: &[u8]| {
    let mut replay = ReplayCache::new(256).expect("fixed replay-cache capacity is valid");
    let _ = verify_control_message::<UdpFlowAuthorization>(
        data,
        1_750_000_000_000,
        TimePolicy::default(),
        &mut replay,
    );
});
