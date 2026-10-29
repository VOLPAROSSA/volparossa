// SPDX-License-Identifier: GPL-3.0-only
//! Forward WGS84 geodetic-to-ECEF conversion of caller-supplied coordinates.
//!
//! This pure adapter obtains no sensors, time, permissions or history. Latitude,
//! longitude and ellipsoidal height are caller assertions: conversion verifies
//! neither their reference/provenance nor accuracy, physical integrity or anchors.
//! It performs no vertical-datum transformation or uncertainty/time propagation.
//!
//! Ellipsoid constants: [NGA WGS84](https://earth-info.nga.mil/index.php?action=wgs84&dir=wgs84).
//! Forward equations: [IOGP 373-7-2 (2019), section 4.1.1, EPSG 9602](https://www.iogp.org/wp-content/uploads/2019/09/373-07-02.pdf).

use std::fmt;

use super::MAX_DPS_COMPONENT_METRES;

#[cfg(test)]
mod tests;

// NGA's defining WGS84 semi-major axis and inverse flattening, in metres/unitless.
const SEMI_MAJOR_METRES: f64 = 6_378_137.0;
const INVERSE_FLATTENING: f64 = 298.257_223_563;

/// Explicit vertical reference supplied by the caller; never inferred from height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightReference {
    /// Caller asserts height above the WGS84 reference ellipsoid, in metres.
    Wgs84Ellipsoid,
    /// Mean-sea-level/orthometric height; unsupported without a geoid model.
    MeanSeaLevel,
    /// No usable vertical reference supplied; unsupported.
    Unknown,
}

/// Unverified WGS84 geodetic input. Debug deliberately omits all coordinates.
#[derive(Clone, Copy, PartialEq)]
pub struct Wgs84GeodeticPosition {
    /// Latitude in degrees north, inclusive range -90 through +90.
    pub latitude_degrees: f64,
    /// Longitude in degrees east, inclusive range -180 through +180.
    pub longitude_degrees: f64,
    /// Signed height in metres relative to the explicitly declared reference.
    pub height_metres: f64,
    /// Caller-asserted height reference; only WGS84 ellipsoidal height is accepted.
    pub height_reference: HeightReference,
}

/// Bounded WGS84 ECEF Cartesian metres, still an unverified caller-derived position.
///
/// This type is not a wire message, trusted fix or assessment. It carries no time,
/// uncertainty radius, source identity or permission that a caller could inherit.
#[derive(Clone, Copy, PartialEq)]
pub struct EcefCoordinates {
    components_metres: [f64; 3],
}

/// Closed conversion failures. Error text and Debug contain no supplied values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GeodeticError {
    /// A geoid model or explicit supported height reference is missing.
    #[error("unsupported geodetic height reference")]
    UnsupportedHeightReference,
    /// At least one supplied angle/height is not finite.
    #[error("non-finite geodetic input")]
    NonFiniteInput,
    /// Latitude falls outside the accepted degree range.
    #[error("geodetic latitude outside degree range")]
    LatitudeOutOfRange,
    /// Longitude falls outside the accepted degree range; no wrapping is inferred.
    #[error("geodetic longitude outside degree range")]
    LongitudeOutOfRange,
    /// Result is non-finite or exceeds the existing DPS Cartesian component bound.
    #[error("geodetic result exceeds DPS component bound")]
    EcefOutOfRange,
}

impl fmt::Debug for Wgs84GeodeticPosition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Wgs84GeodeticPosition { [REDACTED] }")
    }
}

impl fmt::Debug for EcefCoordinates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EcefCoordinates { [REDACTED] }")
    }
}

impl Wgs84GeodeticPosition {
    /// Convert degrees and asserted WGS84 ellipsoidal metres to ECEF metres.
    ///
    /// Negative ellipsoidal heights are accepted. Unknown/MSL references are not
    /// silently treated as ellipsoidal. The resulting coordinates may populate an
    /// existing WGS84 ECEF observation; its other metadata remains caller-supplied.
    ///
    /// # Errors
    /// Rejects unsupported height reference, non-finite input, angles outside the
    /// inclusive degree bounds, and results outside the existing DPS component bound.
    pub fn to_ecef(self) -> Result<EcefCoordinates, GeodeticError> {
        if self.height_reference != HeightReference::Wgs84Ellipsoid {
            return Err(GeodeticError::UnsupportedHeightReference);
        }
        if ![
            self.latitude_degrees,
            self.longitude_degrees,
            self.height_metres,
        ]
        .iter()
        .all(|value| value.is_finite())
        {
            return Err(GeodeticError::NonFiniteInput);
        }
        if !(-90.0..=90.0).contains(&self.latitude_degrees) {
            return Err(GeodeticError::LatitudeOutOfRange);
        }
        if !(-180.0..=180.0).contains(&self.longitude_degrees) {
            return Err(GeodeticError::LongitudeOutOfRange);
        }
        let flattening = 1.0 / INVERSE_FLATTENING;
        let eccentricity_squared = flattening * (2.0 - flattening);
        let (sin_latitude, cos_latitude) = self.latitude_degrees.to_radians().sin_cos();
        let (sin_longitude, cos_longitude) = self.longitude_degrees.to_radians().sin_cos();
        let prime_vertical_metres =
            SEMI_MAJOR_METRES / (1.0 - eccentricity_squared * sin_latitude * sin_latitude).sqrt();
        let components_metres = [
            (prime_vertical_metres + self.height_metres) * cos_latitude * cos_longitude,
            (prime_vertical_metres + self.height_metres) * cos_latitude * sin_longitude,
            (prime_vertical_metres * (1.0 - eccentricity_squared) + self.height_metres)
                * sin_latitude,
        ];
        if !components_metres
            .iter()
            .all(|value| value.is_finite() && value.abs() <= MAX_DPS_COMPONENT_METRES)
        {
            return Err(GeodeticError::EcefOutOfRange);
        }
        Ok(EcefCoordinates { components_metres })
    }
}

impl EcefCoordinates {
    /// Explicitly access Cartesian `[x, y, z]` metres to populate an existing observation.
    pub const fn components_metres(self) -> [f64; 3] {
        self.components_metres
    }
}
