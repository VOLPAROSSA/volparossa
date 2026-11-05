/* SPDX-License-Identifier: GPL-3.0-only */
/* Synthetic C/C++ caller; not Android, a sensor or a positioning trial. */
#include "volparossa_dps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define STATIC_ASSERT static_assert
#else
#define STATIC_ASSERT _Static_assert
#endif

STATIC_ASSERT(offsetof(DpsQualityV1, abi_version) == 0, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, dps_version) == 4, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, status) == 8, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, frame_kind) == 12, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, observation_count) == 16, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, eligible_count) == 20, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, excluded_count) == 24, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, conflict_count) == 28, "ABI offset");
STATIC_ASSERT(offsetof(DpsQualityV1, limitations_mask) == 32, "ABI offset");
STATIC_ASSERT((VOLPAROSSA_DPS_CALLER_SUPPLIED_EVIDENCE |
               VOLPAROSSA_DPS_PHYSICAL_INTEGRITY_UNVERIFIED |
               VOLPAROSSA_DPS_PHYSICAL_INDEPENDENCE_UNVERIFIED |
               VOLPAROSSA_DPS_UNCERTAINTY_CONFIDENCE_UNKNOWN |
               VOLPAROSSA_DPS_NO_SENSOR_FUSION |
               VOLPAROSSA_DPS_NO_SENSOR_OR_CLOCK_VERIFICATION |
               VOLPAROSSA_DPS_PAIRWISE_CONSISTENCY_ONLY) == 0x7f, "ABI limitations");

#define CHECK(CONDITION) do { \
  if (!(CONDITION)) { fputs("native_quality_contract_failed\n", stderr); return 1; } \
} while (0)

#define EXPECT_FAILURE(DATA, LENGTH, NOW, DEST, SIZE, ERROR) do { \
  DpsQualityV1 previous = output; \
  int32_t result = volparossa_dps_assess_v1((DATA), (LENGTH), (NOW), (DEST), (SIZE)); \
  CHECK(result == (ERROR)); \
  CHECK(memcmp(&output, &previous, sizeof(output)) == 0); \
  ++cases; \
} while (0)

struct Vector {
  const char *name;
  uint32_t status;
  uint32_t observations;
  uint32_t eligible;
  uint32_t conflicts;
};

static int load(const char *directory, const char *name, uint8_t *data, size_t *length) {
  char path[512];
  int written = snprintf(path, sizeof(path), "%s/%s", directory, name);
  CHECK(written > 0 && (size_t)written < sizeof(path));
  FILE *source = fopen(path, "rb");
  CHECK(source != NULL);
  *length = fread(data, 1, VOLPAROSSA_DPS_MAX_INPUT_BYTES + 1, source);
  int bad = ferror(source);
  int closed = fclose(source);
  CHECK(!bad && !closed && *length > 0 && *length <= VOLPAROSSA_DPS_MAX_INPUT_BYTES);
  return 0;
}

int main(int argc, char **argv) {
  const struct Vector vectors[] = {
    {"relative_consistent.pb", 2, 2, 2, 0},
    {"relative_conflict.pb", 3, 2, 2, 1},
    {"stale.pb", 0, 1, 0, 0},
    {"empty.pb", 0, 0, 0, 0}
  };
  uint8_t input[VOLPAROSSA_DPS_MAX_INPUT_BYTES + 1];
  size_t length = 0;
  unsigned cases = 0;
  CHECK(argc == 2);
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    const struct Vector *vector = &vectors[i];
    DpsQualityV1 quality = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(load(argv[1], vector->name, input, &length) == 0);
    CHECK(volparossa_dps_assess_v1(input, length, UINT64_C(1000000), &quality,
                                 sizeof(quality)) == VOLPAROSSA_DPS_OK);
    CHECK(quality.abi_version == 1 && quality.dps_version == 1 && quality.frame_kind == 2);
    CHECK(quality.status == vector->status && quality.observation_count == vector->observations);
    CHECK(quality.eligible_count == vector->eligible);
    CHECK(quality.excluded_count == vector->observations - vector->eligible);
    CHECK(quality.conflict_count == vector->conflicts && quality.limitations_mask == 0x7f);
    ++cases;
  }
  /* input now holds the canonical empty request. All boundary calls use
   * sentinel output; errors must leave its complete allocation untouched. */
  DpsQualityV1 output = {91, 92, 93, 94, 95, 96, 97, 98, 99};
  uint8_t malformed[] = {0x80};
  EXPECT_FAILURE(malformed, sizeof(malformed), 1000000, &output, sizeof(output), VOLPAROSSA_DPS_MESSAGE);
  input[1] = 2;
  EXPECT_FAILURE(input, length, 1000000, &output, sizeof(output), VOLPAROSSA_DPS_REQUEST);
  input[1] = 1;
  EXPECT_FAILURE(input, length, 0, &output, sizeof(output), VOLPAROSSA_DPS_REQUEST);
  input[length] = 0x78; input[length + 1] = 1;
  EXPECT_FAILURE(input, length + 2, 1000000, &output, sizeof(output), VOLPAROSSA_DPS_MESSAGE);
  EXPECT_FAILURE(input, 0, 1000000, &output, sizeof(output), VOLPAROSSA_DPS_BOUND);
  EXPECT_FAILURE(input, sizeof(input), 1000000, &output, sizeof(output), VOLPAROSSA_DPS_BOUND);
  EXPECT_FAILURE(NULL, length, 1000000, &output, sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  EXPECT_FAILURE(input, length, 1000000, NULL, sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  EXPECT_FAILURE(input, length, 1000000, &output, sizeof(output) - 1, VOLPAROSSA_DPS_ARGUMENT);
  /* Linux amd64 fixture: integer-to-pointer address representation is
   * implementation-defined. Avoid C11's misaligned object-pointer conversion;
   * no access occurs, and the Rust boundary must reject this numeric shape. */
  EXPECT_FAILURE(input, length, 1000000, (DpsQualityV1 *)((uintptr_t)&output + 1),
                 sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  EXPECT_FAILURE((const uint8_t *)(UINTPTR_MAX - 1), length, 1000000, &output,
                 sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  EXPECT_FAILURE(input, length, 1000000, (DpsQualityV1 *)(UINTPTR_MAX & ~(uintptr_t)3),
                 sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  EXPECT_FAILURE((const uint8_t *)&output, 1, 1000000, &output,
                 sizeof(output), VOLPAROSSA_DPS_ARGUMENT);
  /* Byte-alignment one is supported, without mutating supplied bytes. */
  memmove(input + 1, input, length);
  CHECK(volparossa_dps_assess_v1(input + 1, length, UINT64_C(1000000), &output,
                               sizeof(output)) == VOLPAROSSA_DPS_OK);
  CHECK(output.status == 0 && output.observation_count == 0 && output.limitations_mask == 0x7f);
  ++cases;
  CHECK(cases == 18);
  printf("{\"schema\":1,\"abi\":1,\"service\":1,\"native_cases\":%u,\"golden_cases\":4,"
         "\"synthetic_only\":true,\"actual_android_acceptance\":false,"
         "\"physical_positioning_acceptance\":false}\n", cases);
  return 0;
}
