#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, NodeAdvertisement, ReplayCache, SignedEnvelope, TimePolicy,
    decode_canonical, verify_control_message,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_canonical::<SignedEnvelope>(data, MAX_CONTROL_MESSAGE_SIZE);
    let mut replay = ReplayCache::new(256).expect("fixed replay-cache capacity is valid");
    let _ = verify_control_message::<NodeAdvertisement>(
        data,
        1_750_000_000_000,
        TimePolicy::default(),
        &mut replay,
    );
});
