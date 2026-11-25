/* SPDX-License-Identifier: GPL-3.0-only */
/* Exercise the installed native ABI using a fictional observation. */
#include "volparossa_dps.h"
#include <assert.h>
#include <math.h>
#include <string.h>

_Static_assert(offsetof(DpsGeodeticClaimV1, height_reference) == 0, "datum offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, reserved) == 4, "reserved offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, latitude_degrees) == 8, "latitude offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, longitude_degrees) == 16, "longitude offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, height_metres) == 24, "height offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, comparison_radius_metres) == 32, "radius offset");
_Static_assert(offsetof(DpsGeodeticClaimV1, observed_at_unix_ms) == 40, "time offset");

static void rejected(DpsGeodeticClaimV1 claim, uint64_t now) {
  DpsQualityV1 output;
  memset(&output, 0xa5, sizeof(output));
  const DpsQualityV1 original = output;
  assert(volparossa_dps_assess_geodetic_v1(claim, now, &output, sizeof(output)) == VOLPAROSSA_DPS_REQUEST);
  assert(memcmp(&output, &original, sizeof(output)) == 0);
}

int main(void) {
  const uint64_t now = 50000;
  const DpsGeodeticClaimV1 sample = {VOLPAROSSA_DPS_WGS84_ELLIPSOID, 0, 12.5, -45.0, -5.0, 3.0, now - 5000};
  DpsGeodeticClaimV1 claim = sample;
  DpsQualityV1 output = {0};
  assert(volparossa_dps_assess_geodetic_v1(claim, now, &output, sizeof(output)) == VOLPAROSSA_DPS_OK);
  assert(output.abi_version == 1 && output.dps_version == 1 && output.status == 1 && output.frame_kind == 1);
  assert(output.observation_count == 1 && output.eligible_count == 1 && output.excluded_count == 0);
  assert(output.conflict_count == 0 && output.limitations_mask == VOLPAROSSA_DPS_REQUIRED_LIMITATIONS);
  const uint64_t unavailable[] = {0, now - 5001, now + 1};
  for (size_t i = 0; i < sizeof(unavailable) / sizeof(*unavailable); ++i) {
    claim.observed_at_unix_ms = unavailable[i];
    assert(volparossa_dps_assess_geodetic_v1(claim, now, &output, sizeof(output)) == VOLPAROSSA_DPS_OK);
    assert(output.status == 0 && output.eligible_count == 0 && output.excluded_count == 1);
  }
  claim = sample;
  rejected(claim, 0);
  const double invalid_radii[] = {0.0, -1.0, NAN, INFINITY, 1000001.0};
  for (size_t i = 0; i < sizeof(invalid_radii) / sizeof(*invalid_radii); ++i) {
    claim.comparison_radius_metres = invalid_radii[i];
    rejected(claim, now);
  }
  claim = sample;
  claim.height_reference = 0;
  rejected(claim, now);
  claim.height_reference = 2;
  rejected(claim, now);
  claim = sample;
  claim.latitude_degrees = 91.0;
  rejected(claim, now);
  claim = sample;
  claim.longitude_degrees = -181.0;
  rejected(claim, now);
  claim = sample;
  claim.height_metres = NAN;
  rejected(claim, now);
  claim = sample;
  claim.reserved = 1;
  rejected(claim, now);
  assert(volparossa_dps_assess_geodetic_v1(sample, now, NULL, sizeof(output)) == VOLPAROSSA_DPS_ARGUMENT);
  assert(volparossa_dps_assess_geodetic_v1(sample, now, &output, sizeof(output) - 1) == VOLPAROSSA_DPS_ARGUMENT);
  return 0;
}
