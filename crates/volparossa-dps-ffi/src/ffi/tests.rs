use std::{mem, ptr};

use super::{catch_assessment, volparossa_dps_assess_v1};
use crate::{DpsBridgeError, DpsQualityV1, MAX_DPS_INPUT_BYTES, REQUIRED_LIMITATIONS_MASK};

const EMPTY: &[u8] = include_bytes!("../../tests/fixtures/empty.pb");
const NOW: u64 = 1_000_000;

fn sentinel() -> DpsQualityV1 {
    DpsQualityV1 {
        abi_version: 91,
        dps_version: 92,
        status: 93,
        frame_kind: 94,
        observation_count: 95,
        eligible_count: 96,
        excluded_count: 97,
        conflict_count: 98,
        limitations_mask: 99,
    }
}

#[test]
fn native_quality_ffi_layout_and_actual_success() {
    assert_eq!(size_of::<DpsQualityV1>(), 36);
    assert_eq!(align_of::<DpsQualityV1>(), 4);
    assert_eq!(mem::offset_of!(DpsQualityV1, limitations_mask), 32);
    let mut output = sentinel();
    // SAFETY: owned live input/output allocations are disjoint and correctly sized.
    let code =
        unsafe { volparossa_dps_assess_v1(EMPTY.as_ptr(), EMPTY.len(), NOW, &raw mut output, 36) };
    assert_eq!(code, 0);
    output.validate().unwrap();
    assert_eq!(output.status, 0);
    assert_eq!(output.observation_count, 0);
    assert_eq!(output.limitations_mask, REQUIRED_LIMITATIONS_MASK);
}

#[test]
fn native_quality_ffi_closed_errors_never_overwrite_output() {
    let oversized = vec![0; MAX_DPS_INPUT_BYTES + 1];
    let mut noncanonical = EMPTY.to_vec();
    noncanonical.extend_from_slice(&[0x78, 1]);
    for (input, now, expected) in [
        (&[0x80][..], NOW, DpsBridgeError::InvalidMessage),
        (EMPTY, 0, DpsBridgeError::InvalidRequest),
        (noncanonical.as_slice(), NOW, DpsBridgeError::InvalidMessage),
        (oversized.as_slice(), NOW, DpsBridgeError::InputBound),
        (&[][..], NOW, DpsBridgeError::InputBound),
    ] {
        let mut output = sentinel();
        // SAFETY: allocations are valid; the empty/oversized input shapes reject
        // before reading and all other inputs are fully owned readable bytes.
        let code = unsafe {
            volparossa_dps_assess_v1(input.as_ptr(), input.len(), now, &raw mut output, 36)
        };
        assert_eq!(code, expected as i32);
        assert_eq!(output, sentinel());
    }
}

#[test]
fn native_quality_ffi_rejects_pointer_shapes_before_access() {
    let mut output = sentinel();
    let target = &raw mut output;
    let misaligned = target.wrapping_byte_add(1);
    let overflowing_input = EMPTY.as_ptr().with_addr(usize::MAX - 1);
    let overflowing_output = target.with_addr(usize::MAX & !3);
    let cases = [
        (ptr::null(), EMPTY.len(), target, 36),
        (EMPTY.as_ptr(), EMPTY.len(), ptr::null_mut(), 36),
        (EMPTY.as_ptr(), EMPTY.len(), misaligned, 36),
        (EMPTY.as_ptr(), EMPTY.len(), target, 35),
        (overflowing_input, EMPTY.len(), target, 36),
        (EMPTY.as_ptr(), EMPTY.len(), overflowing_output, 36),
        (target.cast_const().cast::<u8>(), 1, target, 36),
    ];
    for (input, length, destination, size) in cases {
        // SAFETY: these documented invalid shapes must reject before any access;
        // no arbitrary dangling pointer is supplied to a shape-valid call.
        let code = unsafe { volparossa_dps_assess_v1(input, length, NOW, destination, size) };
        assert_eq!(code, DpsBridgeError::InvalidArgument as i32);
        assert_eq!(output, sentinel());
    }
}

#[test]
fn native_quality_ffi_unaligned_byte_input_is_valid_and_not_modified() {
    let mut input = vec![0];
    input.extend_from_slice(EMPTY);
    let original = input.clone();
    let mut output = sentinel();
    // SAFETY: bytes have alignment one; the offset is fully within this owned
    // input allocation and the independently owned output is aligned/disjoint.
    let code = unsafe {
        volparossa_dps_assess_v1(input.as_ptr().add(1), EMPTY.len(), NOW, &raw mut output, 36)
    };
    assert_eq!(code, 0);
    assert_eq!(input, original);
    output.validate().unwrap();
}

#[test]
fn native_quality_ffi_catches_unwind_without_changing_global_hooks() {
    // The existing process hook may print this fixed synthetic panic. Do not
    // replace it or claim suppression of host diagnostics/aborting panics.
    assert_eq!(
        catch_assessment(|| panic!("fixed synthetic native-quality panic")),
        Err(DpsBridgeError::Internal)
    );
    assert_eq!(
        catch_assessment(|| Err(DpsBridgeError::InvalidRequest)),
        Err(DpsBridgeError::InvalidRequest)
    );
}

#[test]
fn native_quality_ffi_uses_all_seven_exact_closed_limitations() {
    use volparossa_local_control::dps::AssessmentLimitation;
    let variants = [
        AssessmentLimitation::CallerSuppliedEvidence,
        AssessmentLimitation::PhysicalIntegrityUnverified,
        AssessmentLimitation::PhysicalIndependenceUnverified,
        AssessmentLimitation::UncertaintyConfidenceUnknown,
        AssessmentLimitation::NoSensorFusion,
        AssessmentLimitation::NoSensorOrClockVerification,
        AssessmentLimitation::PairwiseConsistencyOnly,
    ];
    let bits = variants.map(|value| 1_u32 << u32::try_from(value as i32).unwrap());
    assert_eq!(bits, [1, 2, 4, 8, 16, 32, 64]);
    assert_eq!(
        bits.into_iter().fold(0, |mask, bit| mask | bit),
        REQUIRED_LIMITATIONS_MASK
    );
}
