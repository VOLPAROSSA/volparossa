/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef VOLPAROSSA_DPS_QUALITY_V1_H
#define VOLPAROSSA_DPS_QUALITY_V1_H

#include <stddef.h>
#include <stdint.h>

#define VOLPAROSSA_DPS_ABI_VERSION UINT32_C(1)
#define VOLPAROSSA_DPS_SERVICE_VERSION UINT32_C(1)
#define VOLPAROSSA_DPS_MAX_INPUT_BYTES ((size_t)16384)
#define VOLPAROSSA_DPS_REQUIRED_LIMITATIONS UINT32_C(0x7f)

/* Every bit is mandatory. None denotes verified physical positioning. */
#define VOLPAROSSA_DPS_CALLER_SUPPLIED_EVIDENCE (UINT32_C(1) << 0)
#define VOLPAROSSA_DPS_PHYSICAL_INTEGRITY_UNVERIFIED (UINT32_C(1) << 1)
#define VOLPAROSSA_DPS_PHYSICAL_INDEPENDENCE_UNVERIFIED (UINT32_C(1) << 2)
#define VOLPAROSSA_DPS_UNCERTAINTY_CONFIDENCE_UNKNOWN (UINT32_C(1) << 3)
#define VOLPAROSSA_DPS_NO_SENSOR_FUSION (UINT32_C(1) << 4)
#define VOLPAROSSA_DPS_NO_SENSOR_OR_CLOCK_VERIFICATION (UINT32_C(1) << 5)
#define VOLPAROSSA_DPS_PAIRWISE_CONSISTENCY_ONLY (UINT32_C(1) << 6)

enum VolparossaDpsResult {
  VOLPAROSSA_DPS_OK = 0,
  VOLPAROSSA_DPS_ARGUMENT = 1,
  VOLPAROSSA_DPS_BOUND = 2,
  VOLPAROSSA_DPS_MESSAGE = 3,
  VOLPAROSSA_DPS_REQUEST = 4,
  VOLPAROSSA_DPS_INTERNAL = 5
};

/* status: 0 unavailable, 1 single claim, 2 consistent claims, 3 conflict.
 * frame_kind: 1 caller-asserted WGS84 ECEF, 2 caller-asserted local Cartesian.
 * Counts are claims/pairs, never independent-source or physical-trust evidence.
 * No coordinate, identity, correlation group or timestamp is returned. */
typedef struct DpsQualityV1 {
  uint32_t abi_version;
  uint32_t dps_version;
  uint32_t status;
  uint32_t frame_kind;
  uint32_t observation_count;
  uint32_t eligible_count;
  uint32_t excluded_count;
  uint32_t conflict_count;
  uint32_t limitations_mask;
} DpsQualityV1;

#if defined(__cplusplus)
static_assert(sizeof(DpsQualityV1) == 36, "DPS ABI size");
static_assert(alignof(DpsQualityV1) == 4, "DPS ABI alignment");
extern "C" {
#else
_Static_assert(sizeof(DpsQualityV1) == 36, "DPS ABI size");
_Static_assert(_Alignof(DpsQualityV1) == 4, "DPS ABI alignment");
#endif

/* Bare canonical DpsAssessRequest, NOT ControlRequest or a socket operation.
 * No I/O, permissions, sensors, persistence or OS-location replacement.
 * now_unix_ms is explicit caller-supplied evaluation time, not clock proof.
 *
 * Caller MUST provide readable, live input and aligned writable, live output;
 * allocations must be disjoint and free of conflicting concurrent accesses.
 * input_len must be 1..16384, output_size exactly sizeof(DpsQualityV1).
 * Null/misaligned/range-overflow/overlapping shapes reject before dereference.
 * Other invalid/dangling/unmapped/read-only pointers cannot be detected safely.
 * Nonzero return leaves output unchanged. Rust unwinding does not cross C, but
 * existing process panic hooks may still emit diagnostics. Aborting panics,
 * allocation failures and OS faults are outside the recoverable-error contract.
 */
int32_t volparossa_dps_assess_v1(const uint8_t *input, size_t input_len,
                              uint64_t now_unix_ms, DpsQualityV1 *output,
                              size_t output_size);

#if defined(__cplusplus)
}
#endif
#endif
