// SPDX-License-Identifier: GPL-3.0-only
//! Explicit secret-input entrypoints for bounded linked-codegen review.
//! These wrappers and value tests do not prove constant-time execution.
use ctutils::{Choice, CtGt, CtLt};
use hmac::{digest::CtOutput, Hmac};
use poly1305::{
    universal_hash::{KeyInit, UniversalHash},
    Poly1305,
};
use sha2::Sha256;

macro_rules! masks_and_selects {
    ($(($ty:ty, $mask:ident, $select:ident, $method:ident, $select_method:ident)),*) => {$ (
        #[no_mangle]
        #[inline(never)]
        pub fn $mask(secret: u8) -> $ty {
            Choice::from_u8_lsb(secret).$method()
        }
        #[no_mangle]
        #[inline(never)]
        pub fn $select(secret: u8, a: $ty, b: $ty) -> $ty {
            Choice::from_u8_lsb(secret).$select_method(a, b)
        }
    )*};
}
masks_and_selects!(
    (u8, ct_mask_u8, ct_select_u8, to_u8_mask, select_u8),
    (u16, ct_mask_u16, ct_select_u16, to_u16_mask, select_u16),
    (u32, ct_mask_u32, ct_select_u32, to_u32_mask, select_u32),
    (u64, ct_mask_u64, ct_select_u64, to_u64_mask, select_u64),
    (
        u128,
        ct_mask_u128,
        ct_select_u128,
        to_u128_mask,
        select_u128
    )
);

#[no_mangle]
#[inline(never)]
pub fn ct_select_i64(secret: u8, a: i64, b: i64) -> i64 {
    Choice::from_u8_lsb(secret).select_i64(a, b)
}
#[no_mangle]
#[inline(never)]
pub fn ct_lt_u128(a: u128, b: u128) -> u8 {
    Choice::from_u128_lt(a, b).to_u8()
}
#[no_mangle]
#[inline(never)]
pub fn ct_le_u128(a: u128, b: u128) -> u8 {
    Choice::from_u128_le(a, b).to_u8()
}
#[no_mangle]
#[inline(never)]
pub fn ct_trait_lt_u128(a: u128, b: u128) -> u8 {
    a.ct_lt(&b).to_u8()
}
#[no_mangle]
#[inline(never)]
pub fn ct_trait_gt_u128(a: u128, b: u128) -> u8 {
    a.ct_gt(&b).to_u8()
}

/// Real digest output-comparison path used by the HMAC/HPKE dependency family.
#[no_mangle]
#[inline(never)]
pub fn ct_digest_output_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    CtOutput::<Hmac<Sha256>>::new((*a).into()) == CtOutput::<Hmac<Sha256>>::new((*b).into())
}

/// Real universal-hash verification path with an actual Poly1305 computation.
#[no_mangle]
#[inline(never)]
pub fn ct_poly1305_verify(key: &[u8; 32], block: &[u8; 16], expected: &[u8; 16]) -> bool {
    let mut hash = Poly1305::new_from_slice(key).expect("fixed key length");
    hash.update_padded(block);
    hash.verify(&(*expected).into()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_secret_byte_masks_and_selection_keep_exact_values() {
        for secret in 0..=u8::MAX {
            let selected = secret & 1 != 0;
            macro_rules! check {
                ($mask:ident, $select:ident, $ty:ty) => {
                    assert_eq!($mask(secret), if selected { <$ty>::MAX } else { 0 });
                    assert_eq!($select(secret, 7, 42), if selected { 42 } else { 7 });
                };
            }
            check!(ct_mask_u8, ct_select_u8, u8);
            check!(ct_mask_u16, ct_select_u16, u16);
            check!(ct_mask_u32, ct_select_u32, u32);
            check!(ct_mask_u64, ct_select_u64, u64);
            check!(ct_mask_u128, ct_select_u128, u128);
            assert_eq!(
                ct_select_i64(secret, i64::MIN, i64::MAX),
                if selected { i64::MAX } else { i64::MIN }
            );
        }
    }

    #[test]
    fn real_digest_and_poly1305_consumers_reject_every_altered_tag_byte() {
        let value = [0x5a; 32];
        assert!(ct_digest_output_eq(&value, &value));
        for index in 0..32 {
            let mut bad = value;
            bad[index] ^= 1;
            assert!(!ct_digest_output_eq(&value, &bad));
        }
        let key = [0x42; 32];
        let block = [0x5a; 16];
        let mut hash = Poly1305::new_from_slice(&key).unwrap();
        hash.update_padded(&block);
        let tag: [u8; 16] = hash.finalize().into();
        assert!(ct_poly1305_verify(&key, &block, &tag));
        for index in 0..16 {
            let mut bad = tag;
            bad[index] ^= 1;
            assert!(!ct_poly1305_verify(&key, &block, &bad));
        }
    }
}
