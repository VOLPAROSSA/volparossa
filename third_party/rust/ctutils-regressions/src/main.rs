// SPDX-License-Identifier: GPL-3.0-only
use std::hint::black_box as opaque;
use volparossa_ctutils_regressions::*;

fn main() {
    let secret = opaque(1u8);
    let a = opaque((1u128 << 96) - 1);
    let b = opaque(1u128 << 96);
    opaque(ct_mask_u8(secret));
    opaque(ct_mask_u16(secret));
    opaque(ct_mask_u32(secret));
    opaque(ct_mask_u64(secret));
    opaque(ct_mask_u128(secret));
    opaque(ct_select_u8(secret, 7, 42));
    opaque(ct_select_u16(secret, 7, 42));
    opaque(ct_select_u32(secret, 7, 42));
    opaque(ct_select_u64(secret, 7, 42));
    opaque(ct_select_u128(secret, a, b));
    opaque(ct_select_i64(secret, i64::MIN, i64::MAX));
    opaque(ct_lt_u128(a, b));
    opaque(ct_le_u128(a, b));
    opaque(ct_trait_lt_u128(a, b));
    opaque(ct_trait_gt_u128(a, b));
    opaque(ct_digest_output_eq(
        opaque(&[0x5a; 32]),
        opaque(&[0x5a; 32]),
    ));
    opaque(ct_poly1305_verify(
        opaque(&[0x42; 32]),
        opaque(&[0x5a; 16]),
        opaque(&[0x5a; 16]),
    ));
}
