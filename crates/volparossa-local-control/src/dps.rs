//! Stateless assessment of explicitly supplied positioning claims.
//!
//! This service performs no sensor access, collection, persistence, logging, sharing or
//! OS-location override. Source identity, reference frames, timestamps, authentication,
//! uncertainty and independence groups are caller assertions. Consistency is not proof
//! of a correct physical position, independent sources, or detection of GNSS attacks.

use std::{collections::BTreeSet, fmt};

use prost::Message;

use crate::ControlProtocolError;

/// Pure caller-input coordinate conversion; no sensor or platform authority.
pub mod geodetic;

#[cfg(test)]
mod tests;

/// Exact supported positioning service version, independent of the socket version.
pub const DPS_SERVICE_VERSION: u32 = 1;
/// Maximum claims assessed in one bounded, stateless request.
pub const MAX_DPS_OBSERVATIONS: usize = 32;
/// Largest caller-selected freshness window (one minute).
pub const MAX_DPS_AGE_MS: u64 = 60_000;
/// Finite coordinate component limit in metres; not an accuracy claim.
pub const MAX_DPS_COMPONENT_METRES: f64 = 100_000_000.0;
/// Largest supplied comparison radius in metres; not a proven error bound.
pub const MAX_DPS_RADIUS_METRES: f64 = 1_000_000.0;

/// Coordinate reference asserted by the caller; no anchor is independently verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum FrameKind {
    /// Unsupported or absent coordinate reference.
    Unspecified = 0,
    /// WGS84 Earth-centred Earth-fixed Cartesian metres, asserted absolute.
    Wgs84Ecef = 1,
    /// Relative Cartesian metres in one caller-selected local frame.
    LocalCartesian = 2,
}

/// An exact coordinate frame. Local frames are never inferred to be geographic.
#[derive(Clone, PartialEq, Eq, Message)]
#[prost(skip_debug)]
pub struct PositionFrame {
    /// Explicit reference kind.
    #[prost(enumeration = "FrameKind", tag = "1")]
    pub kind: i32,
    /// Per-request opaque 16-byte local frame binding; empty for WGS84 ECEF.
    #[prost(bytes = "vec", tag = "2")]
    pub local_frame_id: Vec<u8>,
}

/// Sensor or reference type claimed by the caller, not an active hardware adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum SourceKind {
    /// Missing modality, rejected before assessment.
    Unspecified = 0,
    /// GNSS-derived position claim.
    Gnss = 1,
    /// Wi-Fi round-trip-time-derived position claim.
    WifiRtt = 2,
    /// Ultra-wideband-derived position claim.
    Uwb = 3,
    /// Bluetooth-derived position claim.
    Bluetooth = 4,
    /// Peer-ranging-derived position claim.
    PeerRanging = 5,
    /// Inertial position claim.
    Inertial = 6,
    /// Visual-inertial position claim.
    VisualInertial = 7,
    /// Fixed-reference-derived position claim.
    FixedReference = 8,
    /// Another explicitly supplied position claim.
    Other = 9,
}

/// Claimed GNSS navigation-message authentication, never physical-position trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum NavigationAuthentication {
    /// No authentication evidence supplied.
    Unknown = 0,
    /// Caller reports unauthenticated navigation messages.
    Unauthenticated = 1,
    /// Caller reports authenticated navigation messages; this service verifies none.
    ClaimedAuthenticated = 2,
}

/// One explicit unverified input position. Debug deliberately omits all input data.
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
pub struct PositionObservation {
    /// Unique per-request opaque identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub observation_id: Vec<u8>,
    /// Per-request source binding (16 bytes), never a required permanent device ID.
    #[prost(bytes = "vec", tag = "2")]
    pub source_id: Vec<u8>,
    /// Caller-declared correlation bucket (16 bytes), not verified independence.
    #[prost(bytes = "vec", tag = "3")]
    pub declared_independence_group: Vec<u8>,
    /// Claimed source modality.
    #[prost(enumeration = "SourceKind", tag = "4")]
    pub source_kind: i32,
    /// Claimed measurement frame.
    #[prost(message, optional, tag = "5")]
    pub frame: Option<PositionFrame>,
    /// Cartesian x coordinate in metres.
    #[prost(double, tag = "6")]
    pub x_metres: f64,
    /// Cartesian y coordinate in metres.
    #[prost(double, tag = "7")]
    pub y_metres: f64,
    /// Cartesian z coordinate in metres.
    #[prost(double, tag = "8")]
    pub z_metres: f64,
    /// Positive supplied 3D comparison radius; confidence and physical bound unknown.
    #[prost(double, tag = "9")]
    pub supplied_radius_metres: f64,
    /// Claimed measurement wall time. No adapter clock provenance is established.
    #[prost(uint64, tag = "10")]
    pub observed_at_unix_ms: u64,
    /// Caller-reported navigation-message authentication; no trust upgrade follows.
    #[prost(enumeration = "NavigationAuthentication", tag = "11")]
    pub navigation_authentication: i32,
}

/// Explicit one-shot request; it grants no sensor, contribution or storage authority.
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
pub struct DpsAssessRequest {
    /// Exact DPS service version.
    #[prost(uint32, tag = "1")]
    pub dps_version: u32,
    /// Desired exact frame; incompatible inputs are explicitly excluded.
    #[prost(message, optional, tag = "2")]
    pub desired_frame: Option<PositionFrame>,
    /// Maximum accepted claimed age, from 1 through 60,000 milliseconds.
    #[prost(uint64, tag = "3")]
    pub maximum_age_ms: u64,
    /// At most 32 caller-supplied claims. Empty is explicitly unavailable.
    #[prost(message, repeated, tag = "4")]
    pub observations: Vec<PositionObservation>,
}

/// Input consistency only; no value denotes verified physical integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum AssessmentStatus {
    /// No eligible input in the requested frame and freshness window.
    Unavailable = 0,
    /// Exactly one eligible claim, with no independent confirmation.
    SingleClaim = 1,
    /// Multiple eligible claims have overlapping pairwise supplied radii.
    ConsistentClaims = 2,
    /// Some eligible pair exceeds its supplied comparison radii; no candidate returned.
    Conflict = 3,
}

/// Reason an input is eligible or excluded. Exclusion does not identify an attack.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ObservationDisposition {
    /// Valid bounded coordinates, claimed fresh time and exact requested frame.
    Eligible = 0,
    /// Coordinate components or radius are non-finite or outside service bounds.
    InvalidGeometry = 1,
    /// Claimed observation time is zero.
    MissingTimestamp = 2,
    /// Claimed observation time exceeds the service's evaluation clock.
    FutureTimestamp = 3,
    /// Claimed age exceeds the requested window.
    Stale = 4,
    /// Valid observation asserts a different coordinate reference or local frame.
    DifferentFrame = 5,
}

/// Content-free classification tied only to an input's per-request identifier.
#[derive(Clone, PartialEq, Eq, Message)]
#[prost(skip_debug)]
pub struct ObservationAssessment {
    /// Exact input identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub observation_id: Vec<u8>,
    /// Exact input source binding.
    #[prost(bytes = "vec", tag = "2")]
    pub source_id: Vec<u8>,
    /// Exact caller-declared correlation bucket.
    #[prost(bytes = "vec", tag = "3")]
    pub declared_independence_group: Vec<u8>,
    /// Claimed source modality, retained without verification.
    #[prost(enumeration = "SourceKind", tag = "4")]
    pub source_kind: i32,
    /// Why this claim was eligible or excluded.
    #[prost(enumeration = "ObservationDisposition", tag = "5")]
    pub disposition: i32,
    /// Claimed age according to the evaluation clock; absent for missing/future time.
    #[prost(uint64, optional, tag = "6")]
    pub claimed_age_ms: Option<u64>,
    /// Authentication assertion retained separately from physical consistency.
    #[prost(enumeration = "NavigationAuthentication", tag = "7")]
    pub navigation_authentication: i32,
}

/// An inconsistent pair of eligible claims, including claims from the same group.
#[derive(Clone, PartialEq, Eq, Message)]
#[prost(skip_debug)]
pub struct PositionConflict {
    /// Lexicographically smaller input identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub first_observation_id: Vec<u8>,
    /// Lexicographically larger input identifier.
    #[prost(bytes = "vec", tag = "2")]
    pub second_observation_id: Vec<u8>,
}

/// Mandatory limits of this first service, present in every result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum AssessmentLimitation {
    /// Source, frame, timestamp and authentication metadata are caller assertions.
    CallerSuppliedEvidence = 0,
    /// Physical position and spoofing/jamming resistance have not been verified.
    PhysicalIntegrityUnverified = 1,
    /// Different declared group labels do not prove physically independent sources.
    PhysicalIndependenceUnverified = 2,
    /// Supplied radius has unknown confidence and is not a proven error bound.
    UncertaintyConfidenceUnknown = 3,
    /// A candidate is one original input, with no fusion or accuracy improvement.
    NoSensorFusion = 4,
    /// No sensor or platform clock adapter has established measurement provenance.
    NoSensorOrClockVerification = 5,
    /// Pairwise overlap alone does not prove a common feasible position.
    PairwiseConsistencyOnly = 6,
}

const LIMITATIONS: [i32; 7] = [0, 1, 2, 3, 4, 5, 6];

/// Typed result for the same caller; no observations are retained after the request.
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
pub struct DpsAssessment {
    /// Exact DPS version.
    #[prost(uint32, tag = "1")]
    pub dps_version: u32,
    /// Evaluation clock supplied by the hosting service, not input timestamp proof.
    #[prost(uint64, tag = "2")]
    pub evaluated_at_unix_ms: u64,
    /// Exact requested output frame.
    #[prost(message, optional, tag = "3")]
    pub desired_frame: Option<PositionFrame>,
    /// Claim consistency or explicit unavailability.
    #[prost(enumeration = "AssessmentStatus", tag = "4")]
    pub status: i32,
    /// Deterministically selected original eligible input, never a fused or trusted fix.
    /// Absent when unavailable or any eligible input pair conflicts.
    #[prost(message, optional, tag = "5")]
    pub unverified_input_position: Option<PositionObservation>,
    /// Input classifications, sorted by per-request observation identifier.
    #[prost(message, repeated, tag = "6")]
    pub observations: Vec<ObservationAssessment>,
    /// All conflicting eligible pairs, sorted by their identifiers.
    #[prost(message, repeated, tag = "7")]
    pub conflicts: Vec<PositionConflict>,
    /// Count of eligible declared correlation buckets, not independent-source evidence.
    #[prost(uint32, tag = "8")]
    pub declared_independence_groups: u32,
    /// Mandatory explicit limitations; never an integrity or safety certificate.
    #[prost(enumeration = "AssessmentLimitation", repeated, tag = "9")]
    pub limitations: Vec<i32>,
    /// Exact requested freshness window, applied to caller-asserted timestamps.
    #[prost(uint64, tag = "10")]
    pub maximum_age_ms: u64,
}

macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => {$(
        impl fmt::Debug for $kind {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($kind), " { [REDACTED] }"))
            }
        }
    )+};
}

redacted_debug!(
    PositionFrame,
    PositionObservation,
    DpsAssessRequest,
    ObservationAssessment,
    PositionConflict,
    DpsAssessment,
);

fn invalid() -> ControlProtocolError {
    ControlProtocolError::Invalid("DPS message")
}

fn identifier(bytes: &[u8]) -> Result<(), ControlProtocolError> {
    if bytes.len() == 16 {
        Ok(())
    } else {
        Err(invalid())
    }
}

impl PositionFrame {
    fn validate(&self) -> Result<(), ControlProtocolError> {
        match FrameKind::try_from(self.kind).map_err(|_| invalid())? {
            FrameKind::Wgs84Ecef if self.local_frame_id.is_empty() => Ok(()),
            FrameKind::LocalCartesian => identifier(&self.local_frame_id),
            _ => Err(invalid()),
        }
    }
}

fn source_metadata(kind: i32, authentication: i32) -> Result<(), ControlProtocolError> {
    let kind = SourceKind::try_from(kind).map_err(|_| invalid())?;
    let authentication =
        NavigationAuthentication::try_from(authentication).map_err(|_| invalid())?;
    if kind == SourceKind::Unspecified
        || (kind != SourceKind::Gnss && authentication != NavigationAuthentication::Unknown)
    {
        return Err(invalid());
    }
    Ok(())
}

impl PositionObservation {
    fn validate_shape(&self) -> Result<(), ControlProtocolError> {
        identifier(&self.observation_id)?;
        identifier(&self.source_id)?;
        identifier(&self.declared_independence_group)?;
        source_metadata(self.source_kind, self.navigation_authentication)?;
        self.frame.as_ref().ok_or_else(invalid)?.validate()
    }

    fn valid_geometry(&self) -> bool {
        [self.x_metres, self.y_metres, self.z_metres]
            .iter()
            .all(|value| value.is_finite() && value.abs() <= MAX_DPS_COMPONENT_METRES)
            && self.supplied_radius_metres.is_finite()
            && self.supplied_radius_metres > 0.0
            && self.supplied_radius_metres <= MAX_DPS_RADIUS_METRES
    }

    fn disposition(&self, request: &DpsAssessRequest, now: u64) -> ObservationDisposition {
        if !self.valid_geometry() {
            ObservationDisposition::InvalidGeometry
        } else if self.observed_at_unix_ms == 0 {
            ObservationDisposition::MissingTimestamp
        } else if self.observed_at_unix_ms > now {
            ObservationDisposition::FutureTimestamp
        } else if now - self.observed_at_unix_ms > request.maximum_age_ms {
            ObservationDisposition::Stale
        } else if self.frame != request.desired_frame {
            ObservationDisposition::DifferentFrame
        } else {
            ObservationDisposition::Eligible
        }
    }
}

impl DpsAssessRequest {
    /// Validate bounded structural input. Invalid geometry is classified, never used.
    ///
    /// # Errors
    /// Rejects unsupported versions, invalid frame/metadata/identifiers, duplicate input
    /// identifiers, inconsistent source-group bindings, and oversized input or age bounds.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.dps_version != DPS_SERVICE_VERSION
            || !(1..=MAX_DPS_AGE_MS).contains(&self.maximum_age_ms)
            || self.observations.len() > MAX_DPS_OBSERVATIONS
        {
            return Err(invalid());
        }
        self.desired_frame
            .as_ref()
            .ok_or_else(invalid)?
            .validate()?;
        let mut ids = BTreeSet::new();
        for observation in &self.observations {
            observation.validate_shape()?;
            if !ids.insert(&observation.observation_id)
                || self.observations.iter().any(|other| {
                    other.source_id == observation.source_id
                        && other.declared_independence_group
                            != observation.declared_independence_group
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Assess only supplied claims, using the service's explicit wall-clock evaluation time.
    ///
    /// All eligible pairs are checked, including correlated sources. Ordering does not
    /// affect the result. A candidate is the lexicographically first eligible original
    /// observation, never an average, corrected GNSS position or verified physical fix.
    ///
    /// # Errors
    /// Rejects invalid structural input or an unavailable (zero) service clock.
    pub fn assess(&self, now_unix_ms: u64) -> Result<DpsAssessment, ControlProtocolError> {
        self.validate()?;
        if now_unix_ms == 0 {
            return Err(invalid());
        }
        let mut inputs: Vec<_> = self.observations.iter().collect();
        inputs.sort_by(|first, second| first.observation_id.cmp(&second.observation_id));
        let mut eligible = Vec::new();
        let mut groups = BTreeSet::new();
        let mut observations = Vec::with_capacity(inputs.len());
        for input in inputs {
            let disposition = input.disposition(self, now_unix_ms);
            if disposition == ObservationDisposition::Eligible {
                eligible.push(input);
                groups.insert(&input.declared_independence_group);
            }
            observations.push(ObservationAssessment {
                observation_id: input.observation_id.clone(),
                source_id: input.source_id.clone(),
                declared_independence_group: input.declared_independence_group.clone(),
                source_kind: input.source_kind,
                disposition: disposition as i32,
                claimed_age_ms: now_unix_ms
                    .checked_sub(input.observed_at_unix_ms)
                    .filter(|_| input.observed_at_unix_ms != 0),
                navigation_authentication: input.navigation_authentication,
            });
        }
        let mut conflicts = Vec::new();
        for (index, first) in eligible.iter().enumerate() {
            for second in &eligible[index + 1..] {
                let separation = (first.x_metres - second.x_metres)
                    .hypot(first.y_metres - second.y_metres)
                    .hypot(first.z_metres - second.z_metres);
                if separation > first.supplied_radius_metres + second.supplied_radius_metres {
                    conflicts.push(PositionConflict {
                        first_observation_id: first.observation_id.clone(),
                        second_observation_id: second.observation_id.clone(),
                    });
                }
            }
        }
        let status = if conflicts.is_empty() {
            match eligible.len() {
                0 => AssessmentStatus::Unavailable,
                1 => AssessmentStatus::SingleClaim,
                _ => AssessmentStatus::ConsistentClaims,
            }
        } else {
            AssessmentStatus::Conflict
        };
        Ok(DpsAssessment {
            dps_version: DPS_SERVICE_VERSION,
            evaluated_at_unix_ms: now_unix_ms,
            desired_frame: self.desired_frame.clone(),
            status: status as i32,
            unverified_input_position: if conflicts.is_empty() {
                eligible.first().map(|input| (*input).clone())
            } else {
                None
            },
            observations,
            conflicts,
            declared_independence_groups: u32::try_from(groups.len()).map_err(|_| invalid())?,
            limitations: LIMITATIONS.to_vec(),
            maximum_age_ms: self.maximum_age_ms,
        })
    }
}

impl DpsAssessment {
    /// Validate bounded response structure and consistency of explicit quality metadata.
    ///
    /// # Errors
    /// Rejects unsupported versions/statuses, missing limits, invalid metadata, candidate
    /// contradictions and conflicts that do not bind distinct eligible observations.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.dps_version != DPS_SERVICE_VERSION
            || self.evaluated_at_unix_ms == 0
            || !(1..=MAX_DPS_AGE_MS).contains(&self.maximum_age_ms)
            || self.observations.len() > MAX_DPS_OBSERVATIONS
            || self.conflicts.len() > MAX_DPS_OBSERVATIONS * (MAX_DPS_OBSERVATIONS - 1) / 2
            || self.limitations != LIMITATIONS
        {
            return Err(invalid());
        }
        self.desired_frame
            .as_ref()
            .ok_or_else(invalid)?
            .validate()?;
        let status = AssessmentStatus::try_from(self.status).map_err(|_| invalid())?;
        let mut ids = BTreeSet::new();
        let mut eligible = BTreeSet::new();
        let mut groups = BTreeSet::new();
        for observation in &self.observations {
            identifier(&observation.observation_id)?;
            identifier(&observation.source_id)?;
            identifier(&observation.declared_independence_group)?;
            source_metadata(
                observation.source_kind,
                observation.navigation_authentication,
            )?;
            let disposition =
                ObservationDisposition::try_from(observation.disposition).map_err(|_| invalid())?;
            if !ids.insert(&observation.observation_id) {
                return Err(invalid());
            }
            let valid_age = match disposition {
                ObservationDisposition::Eligible | ObservationDisposition::DifferentFrame => {
                    observation.claimed_age_ms.is_some_and(|age| {
                        age <= self.maximum_age_ms && age < self.evaluated_at_unix_ms
                    })
                }
                ObservationDisposition::Stale => observation.claimed_age_ms.is_some_and(|age| {
                    age > self.maximum_age_ms && age < self.evaluated_at_unix_ms
                }),
                ObservationDisposition::MissingTimestamp
                | ObservationDisposition::FutureTimestamp => observation.claimed_age_ms.is_none(),
                ObservationDisposition::InvalidGeometry => observation
                    .claimed_age_ms
                    .is_none_or(|age| age < self.evaluated_at_unix_ms),
            };
            if !valid_age
                || self.observations.iter().any(|other| {
                    other.source_id == observation.source_id
                        && other.declared_independence_group
                            != observation.declared_independence_group
                })
            {
                return Err(invalid());
            }
            if disposition == ObservationDisposition::Eligible {
                eligible.insert(observation.observation_id.clone());
                groups.insert(&observation.declared_independence_group);
            }
        }
        if usize::try_from(self.declared_independence_groups).map_err(|_| invalid())?
            != groups.len()
            || (status == AssessmentStatus::Unavailable) != eligible.is_empty()
            || (status == AssessmentStatus::Conflict) == self.conflicts.is_empty()
            || (status == AssessmentStatus::SingleClaim && eligible.len() != 1)
            || (status == AssessmentStatus::ConsistentClaims && eligible.len() < 2)
        {
            return Err(invalid());
        }
        let mut pairs = BTreeSet::new();
        for conflict in &self.conflicts {
            if conflict.first_observation_id >= conflict.second_observation_id
                || !eligible.contains(&conflict.first_observation_id)
                || !eligible.contains(&conflict.second_observation_id)
                || !pairs.insert((
                    &conflict.first_observation_id,
                    &conflict.second_observation_id,
                ))
            {
                return Err(invalid());
            }
        }
        self.validate_candidate(status, &eligible)
    }

    fn validate_candidate(
        &self,
        status: AssessmentStatus,
        eligible: &BTreeSet<Vec<u8>>,
    ) -> Result<(), ControlProtocolError> {
        match (&self.unverified_input_position, status) {
            (None, AssessmentStatus::Unavailable | AssessmentStatus::Conflict) => {}
            (
                Some(candidate),
                AssessmentStatus::SingleClaim | AssessmentStatus::ConsistentClaims,
            ) => {
                candidate.validate_shape()?;
                if !candidate.valid_geometry()
                    || eligible.first() != Some(&candidate.observation_id)
                    || candidate.frame != self.desired_frame
                    || candidate.observed_at_unix_ms == 0
                    || self
                        .evaluated_at_unix_ms
                        .checked_sub(candidate.observed_at_unix_ms)
                        .is_none_or(|age| age > self.maximum_age_ms)
                    || !self.observations.iter().any(|observation| {
                        observation.observation_id == candidate.observation_id
                            && observation.disposition == ObservationDisposition::Eligible as i32
                            && observation.source_id == candidate.source_id
                            && observation.declared_independence_group
                                == candidate.declared_independence_group
                            && observation.source_kind == candidate.source_kind
                            && observation.navigation_authentication
                                == candidate.navigation_authentication
                            && observation.claimed_age_ms
                                == Some(self.evaluated_at_unix_ms - candidate.observed_at_unix_ms)
                    })
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
