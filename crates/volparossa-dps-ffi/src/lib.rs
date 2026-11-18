//! Quality-only native adapter to the existing stateless DPS assessor.
//!
//! Inputs are bare canonical `DpsAssessRequest` messages, never administrative
//! control envelopes. This library acquires no sensors, clocks, sockets or files,
//! and deliberately returns no positions or request-local identities.

#![deny(unsafe_code)]

use std::fmt;

use prost::Message;
use volparossa_local_control::dps::{
    AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, DpsAssessment, FrameKind,
    MAX_DPS_OBSERVATIONS, ObservationDisposition,
};

#[allow(unsafe_code)]
mod ffi;

/// Version of the native quality layout and function contract.
pub const DPS_QUALITY_ABI_VERSION: u32 = 1;
/// Decode input bound, applied before invoking Protobuf decoding.
pub const MAX_DPS_INPUT_BYTES: usize = 16 * 1024;
/// Every one of the seven service-v1 limitations must remain present.
pub const REQUIRED_LIMITATIONS_MASK: u32 = 0x7f;

/// Closed native errors. None contains a parser error or caller-supplied data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum DpsBridgeError {
    /// Invalid pointer shape, output size, range arithmetic or overlap.
    InvalidArgument = 1,
    /// Input length is zero or exceeds the native decode bound.
    InputBound = 2,
    /// Protobuf is malformed or not its exact canonical re-encoding.
    InvalidMessage = 3,
    /// The shared request validator or explicit assessment clock rejected input.
    InvalidRequest = 4,
    /// An invalid internal result or a caught unwinding panic; no success implied.
    Internal = 5,
}

impl fmt::Display for DpsBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "dps_bridge_argument",
            Self::InputBound => "dps_bridge_bound",
            Self::InvalidMessage => "dps_bridge_message",
            Self::InvalidRequest => "dps_bridge_request",
            Self::Internal => "dps_bridge_internal",
        })
    }
}

impl std::error::Error for DpsBridgeError {}

/// Fixed nine-`u32` ABI. Counts describe supplied claims, never physical trust.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct DpsQualityV1 {
    /// Native interface version; exactly one.
    pub abi_version: u32,
    /// Shared DPS service version; exactly one.
    pub dps_version: u32,
    /// Shared `AssessmentStatus` numeric value, from zero through three.
    pub status: u32,
    /// Caller-asserted `FrameKind`; one is ECEF and two is local Cartesian.
    pub frame_kind: u32,
    /// Number of supplied observations, at most 32.
    pub observation_count: u32,
    /// Number of eligible claims, not independent or verified sources.
    pub eligible_count: u32,
    /// Number of excluded claims; zero is not evidence of physical accuracy.
    pub excluded_count: u32,
    /// Number of conflicting eligible pairs, at most 496.
    pub conflict_count: u32,
    /// Exact mandatory limitation bits zero through six, all set.
    pub limitations_mask: u32,
}

impl DpsQualityV1 {
    /// Validate the complete quality-only ABI, including status/count relations.
    ///
    /// # Errors
    /// Returns a closed internal error for contradictory or unsupported output.
    pub fn validate(&self) -> Result<(), DpsBridgeError> {
        if self.abi_version != DPS_QUALITY_ABI_VERSION
            || self.dps_version != DPS_SERVICE_VERSION
            || !matches!(self.frame_kind, 1..=2)
            || self.observation_count > 32
            || self.eligible_count > self.observation_count
            || self.excluded_count != self.observation_count - self.eligible_count
            || self.limitations_mask != REQUIRED_LIMITATIONS_MASK
        {
            return Err(DpsBridgeError::Internal);
        }
        let maximum_pairs = self.eligible_count * self.eligible_count.saturating_sub(1) / 2;
        let valid = match self.status {
            0 => self.eligible_count == 0 && self.conflict_count == 0,
            1 => self.eligible_count == 1 && self.conflict_count == 0,
            2 => self.eligible_count >= 2 && self.conflict_count == 0,
            3 => self.eligible_count >= 2 && (1..=maximum_pairs).contains(&self.conflict_count),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(DpsBridgeError::Internal)
        }
    }
}

fn project(assessment: &DpsAssessment) -> Result<DpsQualityV1, DpsBridgeError> {
    assessment
        .validate()
        .map_err(|_| DpsBridgeError::Internal)?;
    let count = |value| u32::try_from(value).map_err(|_| DpsBridgeError::Internal);
    let eligible = assessment
        .observations
        .iter()
        .filter(|row| row.disposition == ObservationDisposition::Eligible as i32)
        .count();
    let mut limitations_mask = 0;
    for limitation in &assessment.limitations {
        let bit = u32::try_from(*limitation).map_err(|_| DpsBridgeError::Internal)?;
        limitations_mask |= 1_u32.checked_shl(bit).ok_or(DpsBridgeError::Internal)?;
    }
    let result = DpsQualityV1 {
        abi_version: DPS_QUALITY_ABI_VERSION,
        dps_version: assessment.dps_version,
        status: u32::try_from(assessment.status).map_err(|_| DpsBridgeError::Internal)?,
        frame_kind: u32::try_from(
            assessment
                .desired_frame
                .as_ref()
                .ok_or(DpsBridgeError::Internal)?
                .kind,
        )
        .map_err(|_| DpsBridgeError::Internal)?,
        observation_count: count(assessment.observations.len())?,
        eligible_count: count(eligible)?,
        excluded_count: count(assessment.observations.len() - eligible)?,
        conflict_count: count(assessment.conflicts.len())?,
        limitations_mask,
    };
    result.validate()?;
    Ok(result)
}

/// Assess canonical bytes without any native-pointer operations or platform I/O.
///
/// Unknown fields, duplicate singular fields, explicit default values, reordered
/// fields and overlong varints fail exact re-encoding. Observation order itself
/// is preserved by Protobuf; the shared assessor supplies order independence.
/// Ordinary invalid geometry, stale claims and mismatching frames keep the
/// shared service's exclusion semantics instead of becoming adapter errors.
///
/// # Errors
/// Returns closed bound/message/request/internal errors, never raw parser text.
pub fn assess_quality(input: &[u8], now_unix_ms: u64) -> Result<DpsQualityV1, DpsBridgeError> {
    if input.is_empty() || input.len() > MAX_DPS_INPUT_BYTES {
        return Err(DpsBridgeError::InputBound);
    }
    let request = DpsAssessRequest::decode(input).map_err(|_| DpsBridgeError::InvalidMessage)?;
    request
        .validate()
        .map_err(|_| DpsBridgeError::InvalidRequest)?;
    if request.encode_to_vec() != input {
        return Err(DpsBridgeError::InvalidMessage);
    }
    let assessment = request
        .assess(now_unix_ms)
        .map_err(|_| DpsBridgeError::InvalidRequest)?;
    project(&assessment)
}

// Bind numeric projection assumptions to shared enums without a second assessor.
const _: () = {
    assert!(MAX_DPS_OBSERVATIONS == 32);
    assert!(AssessmentStatus::Unavailable as u32 == 0);
    assert!(AssessmentStatus::SingleClaim as u32 == 1);
    assert!(AssessmentStatus::ConsistentClaims as u32 == 2);
    assert!(AssessmentStatus::Conflict as u32 == 3);
    assert!(FrameKind::Wgs84Ecef as u32 == 1);
    assert!(FrameKind::LocalCartesian as u32 == 2);
};
