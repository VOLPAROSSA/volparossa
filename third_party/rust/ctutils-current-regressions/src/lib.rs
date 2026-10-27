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

macro_rules! arithmetic_witnesses {
    ($ty:ty, $wide:ident, $sub:ident, $borrow:ident, $addback:ident, $leading:ident, $trailing:ident, $lz:ident, $tz:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub fn $borrow(a: $ty, b: $ty, incoming: u8) -> ($ty, u8) {
            let (value, borrow) = ctutils::primitives::$sub(a, b, Choice::from_u8_lsb(incoming));
            (value, borrow.to_u8())
        }
        /// Exact borrow/masked add-back witness for the optimizer-sensitive carry path.
        #[no_mangle]
        #[inline(never)]
        pub fn $addback(a: $ty, b: $ty, incoming: u8, modulus: $ty) -> $ty {
            let (value, borrow) = ctutils::primitives::$sub(a, b, Choice::from_u8_lsb(incoming));
            value.wrapping_add(borrow.$wide() & modulus)
        }
        #[no_mangle]
        #[inline(never)]
        pub fn $leading(a: $ty) -> u32 {
            ctutils::primitives::$lz(a)
        }
        #[no_mangle]
        #[inline(never)]
        pub fn $trailing(a: $ty) -> u32 {
            ctutils::primitives::$tz(a)
        }
    };
}
arithmetic_witnesses!(
    u32,
    to_u32_mask,
    borrowing_sub_u32,
    ct_borrow_u32,
    ct_addback_u32,
    ct_leading_zeros_u32,
    ct_trailing_zeros_u32,
    leading_zeros_u32,
    trailing_zeros_u32
);
arithmetic_witnesses!(
    u64,
    to_u64_mask,
    borrowing_sub_u64,
    ct_borrow_u64,
    ct_addback_u64,
    ct_leading_zeros_u64,
    ct_trailing_zeros_u64,
    leading_zeros_u64,
    trailing_zeros_u64
);

/// Wide carry primitive used by crypto-bigint on 32-bit word targets.
#[no_mangle]
#[inline(never)]
pub fn ct_overflowing_add_u64(a: u64, b: u64) -> (u64, u8) {
    let (sum, carry) = ctutils::primitives::overflowing_add_u64(a, b);
    (sum, carry.to_u8())
}

/// Wide carry primitive used by crypto-bigint on 64-bit word targets.
#[no_mangle]
#[inline(never)]
pub fn ct_overflowing_add_u128(a: u128, b: u128) -> (u128, u8) {
    let (sum, carry) = ctutils::primitives::overflowing_add_u128(a, b);
    (sum, carry.to_u8())
}

/// Actual P384 public verification path, linking its crypto-bigint arithmetic.
/// Inputs here are public; this is not a secret-key signing witness.
#[no_mangle]
#[inline(never)]
pub fn ct_p384_verify(key: &[u8], prehash: &[u8; 48], signature: &[u8; 96]) -> bool {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let Ok(key) = VerifyingKey::from_sec1_bytes(key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_prehash(prehash, &signature).is_ok()
}

#[cfg(test)]
mod primitive_tests {
    use super::*;
    #[test]
    fn wide_carry_matches_integer_arithmetic() {
        macro_rules! check {
            ($ty:ty, $add:ident) => {
                let values: &[$ty] = &[0, 1, 2, <$ty>::MAX / 2, (<$ty>::MAX / 2) + 1,
                    <$ty>::MAX - 1, <$ty>::MAX];
                for &a in values {
                    for &b in values {
                        let (sum, carry) = a.overflowing_add(b);
                        assert_eq!($add(a, b), (sum, u8::from(carry)));
                    }
                }
            };
        }
        check!(u64, ct_overflowing_add_u64);
        check!(u128, ct_overflowing_add_u128);
    }

    #[test]
    fn borrow_masked_addback_and_zero_counts_match_integer_arithmetic() {
        macro_rules! check {
            ($ty:ty, $borrow:ident, $addback:ident, $leading:ident, $trailing:ident) => {
                let values: &[$ty] = &[0, 1, 2, 3, 7, 0xff, 0xffff, <$ty>::MAX / 2,
                    (<$ty>::MAX / 2) + 1, <$ty>::MAX - 1, <$ty>::MAX];
                for &a in values {
                    assert_eq!($leading(a), a.leading_zeros());
                    assert_eq!($trailing(a), a.trailing_zeros());
                    for bit in 0..<$ty>::BITS {
                        assert_eq!($leading((1 as $ty) << bit), <$ty>::BITS - bit - 1);
                        assert_eq!($trailing((1 as $ty) << bit), bit);
                    }
                    for &b in values {
                        for incoming in 0..=u8::MAX {
                            let (first, borrow1) = a.overflowing_sub(b);
                            let (expected, borrow2) = first.overflowing_sub((incoming & 1) as $ty);
                            let borrow = borrow1 || borrow2;
                            assert_eq!($borrow(a, b, incoming), (expected, u8::from(borrow)));
                            for &modulus in values {
                                assert_eq!($addback(a, b, incoming, modulus),
                                    expected.wrapping_add(if borrow { modulus } else { 0 }));
                            }
                        }
                    }
                }
            };
        }
        check!(u32, ct_borrow_u32, ct_addback_u32, ct_leading_zeros_u32, ct_trailing_zeros_u32);
        check!(u64, ct_borrow_u64, ct_addback_u64, ct_leading_zeros_u64, ct_trailing_zeros_u64);
    }
}
