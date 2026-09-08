// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_MQVPN_BACKEND_STATE_H
#define VOLPAROSSA_MPQUIC_MQVPN_BACKEND_STATE_H

#include "tunnel_assignment.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_MQVPN_BACKEND_MAX_PATHS VMP_MAX_PATHS
/* The negotiated tunnel assignment is capped at 1420 bytes. Keeping compact
 * slots lets the client absorb a bounded HTTP/3 burst without the former
 * eight-datagram cliff or allocating a 64 KiB protocol frame per slot. */
#define VMP_MQVPN_REVERSE_PACKET_BYTES 1420U
#define VMP_MQVPN_REVERSE_MAX_PACKETS 128U
#define VMP_MQVPN_REVERSE_MAX_BYTES (256U * 1024U)

/* These phases deliberately mirror only the mqvpn client phases consumed by
 * the backend. Keeping them independent makes the lifecycle policy testable
 * without linking libmqvpn. */
typedef enum vmp_mqvpn_observed_phase {
    VMP_MQVPN_PHASE_IDLE = 0,
    VMP_MQVPN_PHASE_CONNECTING,
    VMP_MQVPN_PHASE_AUTHENTICATING,
    VMP_MQVPN_PHASE_TUNNEL_READY,
    VMP_MQVPN_PHASE_ESTABLISHED,
    VMP_MQVPN_PHASE_RECONNECTING,
    VMP_MQVPN_PHASE_CLOSED,
} vmp_mqvpn_observed_phase_t;

typedef enum vmp_mqvpn_backend_lifecycle {
    VMP_MQVPN_BACKEND_EXPECTING = 0,
    VMP_MQVPN_BACKEND_ACTIVATING,
    VMP_MQVPN_BACKEND_ACTIVE,
    VMP_MQVPN_BACKEND_TERMINAL,
} vmp_mqvpn_backend_lifecycle_t;

typedef enum vmp_mqvpn_backend_terminal {
    VMP_MQVPN_TERMINAL_NONE = 0,
    VMP_MQVPN_TERMINAL_ENGINE,
    VMP_MQVPN_TERMINAL_OVERFLOW,
} vmp_mqvpn_backend_terminal_t;

typedef enum vmp_mqvpn_assignment_action {
    VMP_MQVPN_ASSIGNMENT_ACTIVATE = 0,
    VMP_MQVPN_ASSIGNMENT_DUPLICATE,
    VMP_MQVPN_ASSIGNMENT_TERMINAL,
} vmp_mqvpn_assignment_action_t;

typedef enum vmp_mqvpn_backend_result {
    VMP_MQVPN_RESULT_NONE = 0,
    VMP_MQVPN_RESULT_EMPTY,
    VMP_MQVPN_RESULT_RESOURCE,
    VMP_MQVPN_RESULT_ENGINE,
    VMP_MQVPN_RESULT_OVERFLOW,
} vmp_mqvpn_backend_result_t;

typedef struct vmp_mqvpn_reverse_packet {
    uint8_t bytes[VMP_MQVPN_REVERSE_PACKET_BYTES];
    size_t len;
} vmp_mqvpn_reverse_packet_t;

typedef struct vmp_mqvpn_backend_state {
    vmp_mqvpn_backend_lifecycle_t lifecycle;
    vmp_mqvpn_observed_phase_t observed_phase;
    vmp_mqvpn_backend_terminal_t terminal;
    vmp_tunnel_assignment_state_t assignment;
    vmp_mqvpn_reverse_packet_t
        reverse_queue[VMP_MQVPN_REVERSE_MAX_PACKETS];
    size_t reverse_head;
    size_t reverse_tail;
    size_t reverse_count;
    size_t reverse_bytes;
} vmp_mqvpn_backend_state_t;

/* Initializes a one-use client lifecycle in IDLE/EXPECTING. */
void vmp_mqvpn_backend_state_init(vmp_mqvpn_backend_state_t *state);

/* Records a synchronous state-change callback, requiring old_phase to equal
 * the retained phase. Only the exact forward pre-assignment transitions and
 * ACTIVATING's TUNNEL_READY -> ESTABLISHED transition are accepted. mqvpn
 * never emits self-transition callbacks, so duplicates fail closed. */
bool vmp_mqvpn_backend_state_observe_transition(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t old_phase,
    vmp_mqvpn_observed_phase_t new_phase);

/* Pins a synchronous current-state sample without treating it as a callback. */
bool vmp_mqvpn_backend_state_sample_phase(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t phase);

/* Offers the assignment delivered by tunnel_config_ready. A first valid
 * assignment is actionable only in EXPECTING/TUNNEL_READY. Once ACTIVE, an
 * identical ESTABLISHED offer is an idempotent duplicate. Every other offer
 * enters the terminal ENGINE state and wipes the retained assignment. */
vmp_mqvpn_assignment_action_t vmp_mqvpn_backend_state_offer_assignment(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t observed_phase,
    const vmp_tunnel_assignment_t *candidate);

/* Completes the synchronous set_tun_active call. Success requires both the
 * state-change callback and the post-call sample to observe ESTABLISHED. */
bool vmp_mqvpn_backend_state_finish_activation(
    vmp_mqvpn_backend_state_t *state, bool activation_call_succeeded,
    vmp_mqvpn_observed_phase_t post_call_phase);

/* The first non-NONE terminal reason wins. Entering any terminal state wipes
 * the retained assignment. NONE is a no-op. */
void vmp_mqvpn_backend_state_enter_terminal(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_backend_terminal_t reason);

/* Always initializes all output fields. EXPECTING and ACTIVATING produce a
 * valid empty snapshot. Only ACTIVE/ESTABLISHED publishes an assignment and
 * tunnel readiness. TERMINAL or inconsistent state returns false. */
bool vmp_mqvpn_backend_state_snapshot(
    vmp_mqvpn_backend_state_t *state, bool *out_tunnel_ready,
    bool *out_has_assignment,
    vmp_tunnel_assignment_t *out_assignment);

/* Owns callback-produced inner packets until the adapter consumes them.
 * Enqueue is permitted only in ACTIVE/ESTABLISHED and independently enforces
 * the retained assignment's destination. Any malformed or misaddressed packet
 * enters terminal ENGINE; either resource ceiling enters terminal OVERFLOW. */
vmp_mqvpn_backend_result_t vmp_mqvpn_backend_state_enqueue_reverse(
    vmp_mqvpn_backend_state_t *state, const uint8_t *packet,
    size_t packet_len);

/* Initializes out_len on every call. A short non-null output buffer returns
 * RESOURCE without consuming or changing the FIFO. Corruption or a null
 * output for a queued packet enters terminal ENGINE. EMPTY is non-terminal. */
vmp_mqvpn_backend_result_t vmp_mqvpn_backend_state_dequeue_reverse(
    vmp_mqvpn_backend_state_t *state, uint8_t *out,
    size_t out_capacity, size_t *out_len);

/* Path records are normalized before they cross this seam; in particular an
 * upstream STANDBY state is represented as PENDING and metrics_valid retains
 * the supported per-field bitmask rather than collapsing it to a boolean. */
typedef enum vmp_mqvpn_path_state {
    VMP_MQVPN_PATH_PENDING = 0,
    VMP_MQVPN_PATH_ACTIVE,
    VMP_MQVPN_PATH_DEGRADED,
    VMP_MQVPN_PATH_CLOSED,
} vmp_mqvpn_path_state_t;

typedef struct vmp_mqvpn_path_record {
    int64_t handle;
    vmp_mqvpn_path_state_t state;
    uint64_t metrics_valid;
    uint64_t smoothed_rtt_us;
    uint64_t packets_lost;
    uint64_t congestion_window_bytes;
    uint64_t bytes_in_flight;
    uint64_t estimated_rate_bytes_per_sec;
    uint64_t acked_transport_bytes;
} vmp_mqvpn_path_record_t;

/* Projects an exact observed handle set into deterministic expected-handle
 * order. Counts and sets must match exactly, every handle must be unique and
 * non-negative, and every normalized state must be valid. Output and count
 * are cleared on failure. Arrays may alias because projection is staged. */
bool vmp_mqvpn_backend_project_paths(
    const int64_t *expected_handles, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count,
    vmp_mqvpn_path_record_t *out, size_t out_capacity,
    size_t *out_count);

/* Selects the adapter-owned current handle set from an upstream snapshot.
 * Upstream may retain historical records after removal, but every unmatched
 * record must be CLOSED. Current handles remain an exact, unique set and are
 * projected in deterministic expected-handle order. */
bool vmp_mqvpn_backend_select_current_paths(
    const int64_t *expected_handles, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count,
    vmp_mqvpn_path_record_t *out, size_t out_capacity,
    size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif
