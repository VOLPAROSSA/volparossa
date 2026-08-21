#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use volparossa_policy::{
    PolicyMode, TrustStore, TrustedMaintainer, VerificationPolicy, verify_manifest,
};

fn trust_store() -> TrustStore {
    let maintainers = [1_u8, 2, 3, 4, 5]
        .into_iter()
        .map(|seed| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            TrustedMaintainer::production(key.verifying_key())
        })
        .collect();
    TrustStore::new(PolicyMode::Production, maintainers)
        .expect("five distinct production keys form a valid trust store")
}

fuzz_target!(|data: &[u8]| {
    let store = trust_store();
    let _ = verify_manifest(
        data,
        1_750_000_000_000,
        &store,
        VerificationPolicy::default(),
    );
});
