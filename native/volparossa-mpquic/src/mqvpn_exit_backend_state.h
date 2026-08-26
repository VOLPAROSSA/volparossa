// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_MQVPN_EXIT_BACKEND_STATE_H
#define VOLPAROSSA_MPQUIC_MQVPN_EXIT_BACKEND_STATE_H

#include "tunnel_assignment.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_MQVPN_EXIT_SESSION_ID 2U
#define VMP_MQVPN_EXIT_MIN_PACKET_MTU 1280U
#define VMP_MQVPN_EXIT_PACKET_MTU 1420U
#define VMP_MQVPN_EXIT_MAX_PACKETS 8U
#define VMP_MQVPN_EXIT_MAX_BYTES (256U * 1024U)

/* A dependency-free copy of the evidence fields supplied by an mqvpn server
 * tunnel callback. The adapter must copy fields, not cast an upstream ABI
 * object to this type. Keeping has_ipv6 integer-valued lets this seam reject
 * upstream values other than the documented zero or one. */
typedef struct vmp_mqvpn_exit_raw_tunnel_info {
    uint8_t assigned_ipv4[4];
    uint32_t assigned_prefix_v4;
    uint8_t server_ipv4[4];
    uint32_t server_prefix_v4;
    int32_t mtu;
    uint8_t assigned_ipv6[16];
    uint32_t assigned_prefix_v6;
    int32_t has_ipv6;
} vmp_mqvpn_exit_raw_tunnel_info_t;

typedef enum vmp_mqvpn_exit_lifecycle {
    VMP_MQVPN_EXIT_STARTING = 0,
    VMP_MQVPN_EXIT_LISTENING,
    VMP_MQVPN_EXIT_CONNECTED,
    VMP_MQVPN_EXIT_TERMINAL,
    VMP_MQVPN_EXIT_DESTROYING,
} vmp_mqvpn_exit_lifecycle_t;

typedef enum vmp_mqvpn_exit_terminal {
    VMP_MQVPN_EXIT_TERMINAL_NONE = 0,
    VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED,
    VMP_MQVPN_EXIT_TERMINAL_ENGINE,
    VMP_MQVPN_EXIT_TERMINAL_OVERFLOW,
    VMP_MQVPN_EXIT_TERMINAL_INVARIANT,
} vmp_mqvpn_exit_terminal_t;

typedef enum vmp_mqvpn_exit_result {
    VMP_MQVPN_EXIT_RESULT_NONE = 0,
    VMP_MQVPN_EXIT_RESULT_EMPTY,
    VMP_MQVPN_EXIT_RESULT_RESOURCE,
    VMP_MQVPN_EXIT_RESULT_ENGINE,
    VMP_MQVPN_EXIT_RESULT_OVERFLOW,
    VMP_MQVPN_EXIT_RESULT_INVARIANT,
} vmp_mqvpn_exit_result_t;

typedef enum vmp_mqvpn_exit_packet_kind {
    VMP_MQVPN_EXIT_PACKET_NONE = 0,
    VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK,
    VMP_MQVPN_EXIT_PACKET_SERVER_ICMP,
} vmp_mqvpn_exit_packet_kind_t;

typedef struct vmp_mqvpn_exit_assignment {
    vmp_tunnel_assignment_t tunnel;
    uint8_t server_ipv6[16];
    uint32_t server_prefix_v6;
} vmp_mqvpn_exit_assignment_t;

typedef struct vmp_mqvpn_exit_packet {
    vmp_mqvpn_exit_packet_kind_t kind;
    uint8_t bytes[VMP_MQVPN_EXIT_PACKET_MTU];
    size_t len;
} vmp_mqvpn_exit_packet_t;

/* This pure state machine has no internal synchronization. One caller must
 * serialize every operation, callback, snapshot and teardown; concurrent
 * access is invalid and must not be introduced by future runtime wiring. */
typedef struct vmp_mqvpn_exit_backend_state {
    vmp_mqvpn_exit_lifecycle_t lifecycle;
    vmp_mqvpn_exit_terminal_t terminal;
    uint8_t pool_ready;
    uint8_t start_completed;
    uint8_t pool_has_ipv6;
    uint32_t session_id;
    uint8_t server_ipv6[16];
    uint32_t server_prefix_v6;
    vmp_tunnel_assignment_state_t assignment;
    vmp_mqvpn_exit_packet_t queue[VMP_MQVPN_EXIT_MAX_PACKETS];
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
    size_t queue_bytes;
} vmp_mqvpn_exit_backend_state_t;

/* Initializes a fresh, one-use server lifecycle in STARTING. */
void vmp_mqvpn_exit_backend_state_init(
    vmp_mqvpn_exit_backend_state_t *state);

/* Records the tunnel_config_ready callback emitted synchronously by
 * mqvpn_server_start. Evidence must describe exactly 10.76.0.0/24 with the
 * server at .1, MTU 1420 and, when enabled, fd76:6f6c:7062::1/112. */
bool vmp_mqvpn_exit_backend_observe_tunnel_ready(
    vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence);

/* Must be called immediately after mqvpn_server_start returns. Success is
 * accepted only if the tunnel-ready callback already moved STARTING to
 * LISTENING. */
bool vmp_mqvpn_exit_backend_finish_start(
    vmp_mqvpn_exit_backend_state_t *state, bool start_succeeded);

/* Records exactly one client at a canonical pool/session offset in 2..254 and
 * retains the VOLPAROSSA assignment by value. The IPv4 last octet, optional
 * IPv6 last octet and session ID must all be the same offset. The negotiated
 * inner MTU is retained exactly in the enforced 1280..1420 range. Duplicate,
 * conflicting and wrong-order callbacks fail closed. */
bool vmp_mqvpn_exit_backend_observe_client_connected(
    vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence,
    uint32_t session_id);

/* A disconnect is terminal and wipes the assignment and queued packets. */
bool vmp_mqvpn_exit_backend_observe_client_disconnected(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id);

/* The first terminal reason wins. Invalid reasons become INVARIANT. Owned
 * assignment and queue memory are wiped in the same serialized transition. */
void vmp_mqvpn_exit_backend_enter_terminal(
    vmp_mqvpn_exit_backend_state_t *state,
    vmp_mqvpn_exit_terminal_t reason);

/* Begins one-way teardown and wipes all owned state. Once DESTROYING,
 * callbacks cannot rearm the lifecycle or replace its first reason. */
bool vmp_mqvpn_exit_backend_begin_destroy(
    vmp_mqvpn_exit_backend_state_t *state);

/* Valid output objects are initialized before state inspection. All four
 * output ranges must be mutually disjoint and must not overlap state storage;
 * an invalid layout fails a live state closed without writing through any
 * output parameter.
 * Only CONNECTED publishes a session and exact assignment; LISTENING publishes
 * neither. */
bool vmp_mqvpn_exit_backend_snapshot(
    vmp_mqvpn_exit_backend_state_t *state, bool *out_listening,
    bool *out_connected, uint32_t *out_session_id,
    vmp_mqvpn_exit_assignment_t *out_assignment);

/* Owns a session-correlated packet produced from a client. The packet source
 * must be the retained client address and session_id must match exactly. */
vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_enqueue_client_uplink(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id,
    const uint8_t *packet, size_t packet_len);

/* Owns server-generated ICMP. Its source must be the canonical server. */
vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_enqueue_server_icmp(
    vmp_mqvpn_exit_backend_state_t *state, const uint8_t *packet,
    size_t packet_len);

/* Valid scalar outputs are initialized on every defined non-aliasing return.
 * Those objects and the actual packet range written to out must be mutually
 * disjoint and must not overlap state storage; an invalid writable layout
 * fails a live state closed without writing through any output parameter. A
 * short or empty buffer returns RESOURCE without consuming or mutating the
 * head. For both packet kinds out_session_id identifies the sole active client
 * session that owns the tunnel. */
vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_dequeue(
    vmp_mqvpn_exit_backend_state_t *state, uint8_t *out,
    size_t out_capacity, size_t *out_len,
    vmp_mqvpn_exit_packet_kind_t *out_kind, uint32_t *out_session_id);

/* Validates a return packet before mqvpn_server_on_tun_packet: exact session,
 * exact packet length/MTU and a destination owned by that client. Invalid
 * input fails the one-use state closed. */
vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_validate_downlink(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id,
    const uint8_t *packet, size_t packet_len);

#ifdef __cplusplus
}
#endif

#endif
