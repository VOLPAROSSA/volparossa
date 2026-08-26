// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_TUNNEL_ASSIGNMENT_H
#define VOLPAROSSA_MPQUIC_TUNNEL_ASSIGNMENT_H

#include "volparossa_mpquic_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum vmp_tunnel_assignment_phase {
    VMP_TUNNEL_ASSIGNMENT_CLEARED = 0,
    VMP_TUNNEL_ASSIGNMENT_EXPECTING,
    VMP_TUNNEL_ASSIGNMENT_ACTIVE,
} vmp_tunnel_assignment_phase_t;

typedef enum vmp_tunnel_assignment_accept_result {
    VMP_TUNNEL_ASSIGNMENT_ACCEPTED = 0,
    VMP_TUNNEL_ASSIGNMENT_DUPLICATE,
    VMP_TUNNEL_ASSIGNMENT_INVALID,
    VMP_TUNNEL_ASSIGNMENT_CONFLICT,
    VMP_TUNNEL_ASSIGNMENT_WRONG_PHASE,
} vmp_tunnel_assignment_accept_result_t;

typedef struct vmp_tunnel_assignment_state {
    vmp_tunnel_assignment_phase_t phase;
    vmp_tunnel_assignment_t assignment;
} vmp_tunnel_assignment_state_t;

/* Initializes a fresh one-use state that expects exactly one assignment. */
void vmp_tunnel_assignment_state_init(
    vmp_tunnel_assignment_state_t *state);

/* Validates the exact VOLPAROSSA v1 client/server pool and MTU policy. */
bool vmp_tunnel_assignment_candidate_is_valid(
    const vmp_tunnel_assignment_t *candidate);

/* Retains a valid candidate by value while EXPECTING. Once ACTIVE, only an
 * identical candidate is accepted as an idempotent duplicate. */
vmp_tunnel_assignment_accept_result_t vmp_tunnel_assignment_state_accept(
    vmp_tunnel_assignment_state_t *state,
    const vmp_tunnel_assignment_t *candidate);

/* Copies the retained assignment only while the state is ACTIVE. */
bool vmp_tunnel_assignment_state_snapshot(
    const vmp_tunnel_assignment_state_t *state,
    vmp_tunnel_assignment_t *out_assignment);

/* Validates an exact inner IP packet and checks that its source or destination
 * is the retained client address. IPv6 is rejected when it was not assigned. */
bool vmp_tunnel_assignment_packet_source_is_owned(
    const vmp_tunnel_assignment_state_t *state,
    const uint8_t *packet, size_t packet_len);
bool vmp_tunnel_assignment_packet_destination_is_owned(
    const vmp_tunnel_assignment_state_t *state,
    const uint8_t *packet, size_t packet_len);

/* Securely clears assignment material and leaves the one-use state CLEARED. */
void vmp_tunnel_assignment_state_wipe(
    vmp_tunnel_assignment_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
