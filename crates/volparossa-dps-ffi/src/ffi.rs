//! The only native-pointer/unsafe-export boundary in this package.

use std::{panic, slice};

use crate::{DpsBridgeError, DpsGeodeticClaimV1, DpsQualityV1, MAX_DPS_INPUT_BYTES, assess_quality};

#[cfg(test)]
mod tests;

fn arguments(
    input: *const u8,
    input_len: usize,
    output: *mut DpsQualityV1,
    output_size: usize,
) -> Result<(), DpsBridgeError> {
    if input.is_null()
        || output.is_null()
        || output_size != size_of::<DpsQualityV1>()
        || !output.is_aligned()
    {
        return Err(DpsBridgeError::InvalidArgument);
    }
    if input_len == 0 || input_len > MAX_DPS_INPUT_BYTES {
        return Err(DpsBridgeError::InputBound);
    }
    let input_end = input
        .addr()
        .checked_add(input_len)
        .ok_or(DpsBridgeError::InvalidArgument)?;
    let output_end = output
        .addr()
        .checked_add(output_size)
        .ok_or(DpsBridgeError::InvalidArgument)?;
    if input.addr() < output_end && output.addr() < input_end {
        return Err(DpsBridgeError::InvalidArgument);
    }
    Ok(())
}

fn catch_assessment(
    work: impl FnOnce() -> Result<DpsQualityV1, DpsBridgeError> + panic::UnwindSafe,
) -> Result<DpsQualityV1, DpsBridgeError> {
    panic::catch_unwind(work).unwrap_or(Err(DpsBridgeError::Internal))
}

/// # Safety
/// The caller must own writable, aligned storage for the validated summary.
unsafe fn finish(output: *mut DpsQualityV1, result: Result<DpsQualityV1, DpsBridgeError>) -> i32 {
    match result {
        Ok(quality) => {
            // SAFETY: required by the caller, written only after successful assessment.
            unsafe { output.write(quality) };
            0
        }
        Err(error) => error as i32,
    }
}

/// Assess one caller-owned canonical request into a caller-owned fixed summary.
///
/// Zero means success; nonzero values are the closed `DpsBridgeError` codes.
/// On every returned error the output storage remains unchanged. No Rust unwind
/// crosses this boundary. Existing process panic hooks may still run; aborting
/// panics, allocator failure and OS faults are not recoverable by this wrapper.
/// The workspace release profile uses panic=abort; no global hook is changed.
///
/// # Safety
/// Beyond the rejected null/alignment/size/range/overlap shapes, the caller must
/// own readable input for `input_len` bytes and aligned writable output for the
/// complete `DpsQualityV1`. Both allocations must remain live throughout the call,
/// be disjoint, and not be concurrently mutated/accessed incompatibly. A non-null
/// pointer does not prove valid mapped memory. This is not a pointer sandbox.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn volparossa_dps_assess_v1(
    input: *const u8,
    input_len: usize,
    now_unix_ms: u64,
    output: *mut DpsQualityV1,
    output_size: usize,
) -> i32 {
    if let Err(error) = arguments(input, input_len, output, output_size) {
        return error as i32;
    }
    // SAFETY: structural guards ran above; allocation validity, lifetime and
    // exclusive output ownership are explicit obligations of this unsafe API.
    let result = catch_assessment(|| {
        let bytes = unsafe { slice::from_raw_parts(input, input_len) };
        assess_quality(bytes, now_unix_ms)
    });
    // SAFETY: output validated above and owned by the caller.
    unsafe { finish(output, result) }
}

/// Assess one already-held geodetic observation into the same quality-only output.
/// Fallible conversion and assessment leave the output untouched on error.
///
/// # Safety
/// The caller must provide live, aligned, exclusively writable output as for
/// `volparossa_dps_assess_v1`. The input is passed by value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn volparossa_dps_assess_geodetic_v1(
    claim: DpsGeodeticClaimV1,
    now_unix_ms: u64,
    output: *mut DpsQualityV1,
    output_size: usize,
) -> i32 {
    if let Err(error) = arguments(
        (&raw const claim).cast(),
        size_of::<DpsGeodeticClaimV1>(),
        output,
        output_size,
    ) {
        return error as i32;
    }
    let result = catch_assessment(|| claim.assess(now_unix_ms));
    // SAFETY: output validated above and owned by the caller.
    unsafe { finish(output, result) }
}
