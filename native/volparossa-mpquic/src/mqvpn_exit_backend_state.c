// SPDX-License-Identifier: GPL-3.0-only

#include "mqvpn_exit_backend_state.h"

#include <string.h>

_Static_assert(
    sizeof(((vmp_mqvpn_exit_backend_state_t *)0)->queue) <=
        VMP_MQVPN_EXIT_MAX_BYTES,
    "Exit FIFO storage exceeds its hard byte bound");

static const uint8_t VMP_EXIT_POOL_IPV4[4] = {10U, 76U, 0U, 0U};
static const uint8_t VMP_EXIT_SERVER_IPV4[4] = {10U, 76U, 0U, 1U};
static const uint8_t VMP_EXIT_SERVER_IPV6[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,   0U,   0U,   0U,   0U,   0U,   0U, 1U,
};
static const uint8_t VMP_EXIT_CLIENT_IPV6_BASE[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,   0U,   0U,   0U,   0U,   0U,   0U, 0U,
};

static void secure_zero(void *memory, size_t length)
{
    volatile uint8_t *bytes = memory;
    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}

static bool memory_is_zero(const void *memory, size_t length)
{
    const uint8_t *bytes = memory;
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

static bool memory_ranges_overlap(const void *left, size_t left_length,
                                  const void *right, size_t right_length)
{
    if (left_length == 0U || right_length == 0U) return false;
    const uintptr_t left_start = (uintptr_t)left;
    const uintptr_t right_start = (uintptr_t)right;
    if (left_start > UINTPTR_MAX - left_length ||
        right_start > UINTPTR_MAX - right_length) {
        return true;
    }
    const uintptr_t left_end = left_start + left_length;
    const uintptr_t right_end = right_start + right_length;
    return left_start < right_end && right_start < left_end;
}

typedef struct vmp_output_range {
    const void *pointer;
    size_t length;
} vmp_output_range_t;

static bool output_ranges_are_valid(
    const vmp_mqvpn_exit_backend_state_t *state,
    const vmp_output_range_t *ranges, size_t range_count)
{
    if (ranges == NULL || range_count == 0U) return false;
    for (size_t left = 0U; left < range_count; ++left) {
        if (ranges[left].pointer == NULL || ranges[left].length == 0U ||
            (state != NULL &&
             memory_ranges_overlap(ranges[left].pointer, ranges[left].length,
                                   state, sizeof(*state)))) {
            return false;
        }
        for (size_t right = 0U; right < left; ++right) {
            if (memory_ranges_overlap(ranges[left].pointer,
                                      ranges[left].length,
                                      ranges[right].pointer,
                                      ranges[right].length)) {
                return false;
            }
        }
    }
    return true;
}

static void fail_live_state_for_invalid_outputs(
    vmp_mqvpn_exit_backend_state_t *state)
{
    if (state != NULL && state->lifecycle != VMP_MQVPN_EXIT_DESTROYING &&
        state->lifecycle != VMP_MQVPN_EXIT_TERMINAL) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    }
}

static void initialize_dequeue_outputs(
    size_t *out_len, vmp_mqvpn_exit_packet_kind_t *out_kind,
    uint32_t *out_session_id)
{
    *out_len = 0U;
    *out_kind = VMP_MQVPN_EXIT_PACKET_NONE;
    *out_session_id = 0U;
}

static bool terminal_is_valid(vmp_mqvpn_exit_terminal_t reason)
{
    switch (reason) {
    case VMP_MQVPN_EXIT_TERMINAL_NONE:
    case VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED:
    case VMP_MQVPN_EXIT_TERMINAL_ENGINE:
    case VMP_MQVPN_EXIT_TERMINAL_OVERFLOW:
    case VMP_MQVPN_EXIT_TERMINAL_INVARIANT:
        return true;
    default:
        return false;
    }
}

static bool packet_kind_is_valid(vmp_mqvpn_exit_packet_kind_t kind)
{
    return kind == VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK ||
           kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
}

static void wipe_queue(vmp_mqvpn_exit_backend_state_t *state)
{
    secure_zero(state->queue, sizeof(state->queue));
    state->queue_head = 0U;
    state->queue_tail = 0U;
    state->queue_count = 0U;
    state->queue_bytes = 0U;
}

static void wipe_owned_state(vmp_mqvpn_exit_backend_state_t *state)
{
    state->pool_ready = 0U;
    state->start_completed = 0U;
    state->pool_has_ipv6 = 0U;
    state->session_id = 0U;
    secure_zero(state->server_ipv6, sizeof(state->server_ipv6));
    state->server_prefix_v6 = 0U;
    vmp_tunnel_assignment_state_wipe(&state->assignment);
    wipe_queue(state);
}

static bool queue_is_wiped(const vmp_mqvpn_exit_backend_state_t *state)
{
    return state->queue_head == 0U && state->queue_tail == 0U &&
           state->queue_count == 0U && state->queue_bytes == 0U &&
           memory_is_zero(state->queue, sizeof(state->queue));
}

static bool owned_state_is_wiped(
    const vmp_mqvpn_exit_backend_state_t *state)
{
    return state->pool_ready == 0U && state->start_completed == 0U &&
           state->pool_has_ipv6 == 0U && state->session_id == 0U &&
           memory_is_zero(state->server_ipv6,
                          sizeof(state->server_ipv6)) &&
           state->server_prefix_v6 == 0U &&
           state->assignment.phase == VMP_TUNNEL_ASSIGNMENT_CLEARED &&
           memory_is_zero(&state->assignment.assignment,
                          sizeof(state->assignment.assignment)) &&
           queue_is_wiped(state);
}

static bool pool_server_state_is_valid(
    const vmp_mqvpn_exit_backend_state_t *state)
{
    if (state->pool_ready != 1U || state->pool_has_ipv6 > 1U) {
        return false;
    }
    if (state->pool_has_ipv6 == 0U) {
        return state->server_prefix_v6 == 0U &&
               memory_is_zero(state->server_ipv6,
                              sizeof(state->server_ipv6));
    }
    return state->server_prefix_v6 == 112U &&
           memcmp(state->server_ipv6, VMP_EXIT_SERVER_IPV6,
                  sizeof(VMP_EXIT_SERVER_IPV6)) == 0;
}

static bool client_ipv4_offset(const uint8_t address[4],
                               uint8_t *out_offset)
{
    if (memcmp(address, VMP_EXIT_POOL_IPV4, 3U) != 0 ||
        address[3] < 2U || address[3] > 254U) {
        return false;
    }
    if (out_offset != NULL) *out_offset = address[3];
    return true;
}

static bool client_ipv6_has_offset(const uint8_t address[16],
                                   uint8_t offset)
{
    return memcmp(address, VMP_EXIT_CLIENT_IPV6_BASE, 15U) == 0 &&
           address[15] == offset;
}

static bool canonical_assignment_is_valid(
    const vmp_mqvpn_exit_backend_state_t *state)
{
    if (state->assignment.phase != VMP_TUNNEL_ASSIGNMENT_ACTIVE ||
        !vmp_tunnel_assignment_candidate_is_valid(
            &state->assignment.assignment)) {
        return false;
    }
    const vmp_tunnel_assignment_t *assignment =
        &state->assignment.assignment;
    uint8_t offset = 0U;
    if (!client_ipv4_offset(assignment->assigned_ipv4, &offset) ||
        state->session_id != (uint32_t)offset ||
        assignment->assigned_prefix_v4 != 32U ||
        memcmp(assignment->server_ipv4, VMP_EXIT_SERVER_IPV4,
               sizeof(VMP_EXIT_SERVER_IPV4)) != 0 ||
        assignment->server_prefix_v4 != 32U ||
        assignment->mtu < VMP_MQVPN_EXIT_MIN_PACKET_MTU ||
        assignment->mtu > VMP_MQVPN_EXIT_PACKET_MTU ||
        assignment->has_ipv6 != (state->pool_has_ipv6 == 1U)) {
        return false;
    }
    if (!assignment->has_ipv6) {
        return assignment->assigned_prefix_v6 == 0U &&
               memory_is_zero(assignment->assigned_ipv6,
                              sizeof(assignment->assigned_ipv6));
    }
    return assignment->assigned_prefix_v6 == 112U &&
           client_ipv6_has_offset(assignment->assigned_ipv6, offset);
}

static bool server_packet_source_is_owned(
    const vmp_mqvpn_exit_backend_state_t *state, const uint8_t *packet,
    size_t packet_len)
{
    vmp_tunnel_assignment_state_t server = state->assignment;
    memcpy(server.assignment.assigned_ipv4, VMP_EXIT_SERVER_IPV4,
           sizeof(VMP_EXIT_SERVER_IPV4));
    if (server.assignment.has_ipv6) {
        memcpy(server.assignment.assigned_ipv6, state->server_ipv6,
               sizeof(server.assignment.assigned_ipv6));
    }
    const bool owned = vmp_tunnel_assignment_packet_source_is_owned(
        &server, packet, packet_len);
    secure_zero(&server, sizeof(server));
    return owned;
}

static bool server_packet_is_icmp(const uint8_t *packet, size_t packet_len)
{
    if (packet == NULL || packet_len == 0U) return false;
    const uint8_t version = (uint8_t)(packet[0] >> 4U);
    if (version == 4U) {
        if (packet_len < 20U || packet[9] != 1U) return false;
        const size_t header_len = (size_t)(packet[0] & 0x0fU) * 4U;
        return header_len >= 20U && header_len <= packet_len &&
               packet_len - header_len >= 8U;
    }
    /* Requiring ICMPv6 directly in the base header deliberately rejects
     * extension-header chains at this bounded seam. */
    return version == 6U && packet_len >= 48U && packet[6] == 58U;
}

static bool queued_packet_is_valid(
    const vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_packet_t *entry)
{
    if (!packet_kind_is_valid(entry->kind) || entry->len == 0U ||
        entry->len > VMP_MQVPN_EXIT_PACKET_MTU ||
        entry->len > (size_t)state->assignment.assignment.mtu) {
        return false;
    }
    if (entry->kind == VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK) {
        return vmp_tunnel_assignment_packet_source_is_owned(
            &state->assignment, entry->bytes, entry->len);
    }
    return server_packet_is_icmp(entry->bytes, entry->len) &&
           server_packet_source_is_owned(state, entry->bytes, entry->len);
}

static bool queue_metadata_is_bounded(
    const vmp_mqvpn_exit_backend_state_t *state)
{
    if (state->queue_head >= VMP_MQVPN_EXIT_MAX_PACKETS ||
        state->queue_tail >= VMP_MQVPN_EXIT_MAX_PACKETS ||
        state->queue_count > VMP_MQVPN_EXIT_MAX_PACKETS ||
        state->queue_bytes > VMP_MQVPN_EXIT_MAX_BYTES) {
        return false;
    }
    return state->queue_tail ==
               (state->queue_head + state->queue_count) %
                   VMP_MQVPN_EXIT_MAX_PACKETS &&
           (state->queue_count != 0U || state->queue_bytes == 0U);
}

static bool queue_is_valid(const vmp_mqvpn_exit_backend_state_t *state)
{
    if (!queue_metadata_is_bounded(state) ||
        !canonical_assignment_is_valid(state)) {
        return false;
    }

    bool occupied[VMP_MQVPN_EXIT_MAX_PACKETS];
    memset(occupied, 0, sizeof(occupied));
    size_t byte_sum = 0U;
    for (size_t offset = 0U; offset < state->queue_count; ++offset) {
        const size_t index =
            (state->queue_head + offset) % VMP_MQVPN_EXIT_MAX_PACKETS;
        const vmp_mqvpn_exit_packet_t *entry = &state->queue[index];
        if (entry->len > VMP_MQVPN_EXIT_MAX_BYTES - byte_sum ||
            !queued_packet_is_valid(state, entry)) {
            return false;
        }
        occupied[index] = true;
        byte_sum += entry->len;
    }
    if (byte_sum != state->queue_bytes) return false;
    for (size_t index = 0U; index < VMP_MQVPN_EXIT_MAX_PACKETS;
         ++index) {
        if (!occupied[index] &&
            !memory_is_zero(&state->queue[index],
                            sizeof(state->queue[index]))) {
            return false;
        }
    }
    return true;
}

static bool state_is_valid(const vmp_mqvpn_exit_backend_state_t *state)
{
    if (state == NULL || !terminal_is_valid(state->terminal)) return false;
    switch (state->lifecycle) {
    case VMP_MQVPN_EXIT_STARTING:
        return state->terminal == VMP_MQVPN_EXIT_TERMINAL_NONE &&
               state->pool_ready == 0U && state->start_completed == 0U &&
               state->pool_has_ipv6 == 0U && state->session_id == 0U &&
               memory_is_zero(state->server_ipv6,
                              sizeof(state->server_ipv6)) &&
               state->server_prefix_v6 == 0U &&
               state->assignment.phase ==
                   VMP_TUNNEL_ASSIGNMENT_EXPECTING &&
               memory_is_zero(&state->assignment.assignment,
                              sizeof(state->assignment.assignment)) &&
               queue_is_wiped(state);
    case VMP_MQVPN_EXIT_LISTENING:
        return state->terminal == VMP_MQVPN_EXIT_TERMINAL_NONE &&
               state->start_completed <= 1U && state->session_id == 0U &&
               pool_server_state_is_valid(state) &&
               state->assignment.phase ==
                   VMP_TUNNEL_ASSIGNMENT_EXPECTING &&
               memory_is_zero(&state->assignment.assignment,
                              sizeof(state->assignment.assignment)) &&
               queue_is_wiped(state);
    case VMP_MQVPN_EXIT_CONNECTED:
        return state->terminal == VMP_MQVPN_EXIT_TERMINAL_NONE &&
               state->start_completed == 1U &&
               state->session_id >= 2U && state->session_id <= 254U &&
               pool_server_state_is_valid(state) &&
               canonical_assignment_is_valid(state) &&
               queue_is_valid(state);
    case VMP_MQVPN_EXIT_TERMINAL:
        return state->terminal != VMP_MQVPN_EXIT_TERMINAL_NONE &&
               owned_state_is_wiped(state);
    case VMP_MQVPN_EXIT_DESTROYING:
        return owned_state_is_wiped(state);
    default:
        return false;
    }
}

static vmp_mqvpn_exit_result_t terminal_result(
    const vmp_mqvpn_exit_backend_state_t *state)
{
    if (state == NULL) return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    switch (state->terminal) {
    case VMP_MQVPN_EXIT_TERMINAL_OVERFLOW:
        return VMP_MQVPN_EXIT_RESULT_OVERFLOW;
    case VMP_MQVPN_EXIT_TERMINAL_INVARIANT:
        return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    case VMP_MQVPN_EXIT_TERMINAL_NONE:
    case VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED:
    case VMP_MQVPN_EXIT_TERMINAL_ENGINE:
    default:
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
}

static bool raw_v6_absent(
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence)
{
    return evidence->has_ipv6 == 0 &&
           evidence->assigned_prefix_v6 == 0U &&
           memory_is_zero(evidence->assigned_ipv6,
                          sizeof(evidence->assigned_ipv6));
}

static bool pool_evidence_is_valid(
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence)
{
    if (evidence == NULL ||
        memcmp(evidence->assigned_ipv4, VMP_EXIT_SERVER_IPV4,
               sizeof(VMP_EXIT_SERVER_IPV4)) != 0 ||
        evidence->assigned_prefix_v4 != 24U ||
        memcmp(evidence->server_ipv4, VMP_EXIT_POOL_IPV4,
               sizeof(VMP_EXIT_POOL_IPV4)) != 0 ||
        evidence->server_prefix_v4 != 24U ||
        evidence->mtu != (int32_t)VMP_MQVPN_EXIT_PACKET_MTU ||
        (evidence->has_ipv6 != 0 && evidence->has_ipv6 != 1)) {
        return false;
    }
    if (evidence->has_ipv6 == 0) return raw_v6_absent(evidence);
    return evidence->assigned_prefix_v6 == 112U &&
           memcmp(evidence->assigned_ipv6, VMP_EXIT_SERVER_IPV6,
                  sizeof(VMP_EXIT_SERVER_IPV6)) == 0;
}

static bool connected_evidence_is_valid(
    const vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence,
    uint32_t session_id)
{
    if (evidence == NULL || session_id < 2U || session_id > 254U) {
        return false;
    }
    uint8_t offset = 0U;
    if (!client_ipv4_offset(evidence->assigned_ipv4, &offset) ||
        session_id != (uint32_t)offset ||
        evidence->assigned_prefix_v4 != 32U ||
        memcmp(evidence->server_ipv4, VMP_EXIT_POOL_IPV4,
               sizeof(VMP_EXIT_POOL_IPV4)) != 0 ||
        evidence->server_prefix_v4 != 24U ||
        evidence->mtu < (int32_t)VMP_MQVPN_EXIT_MIN_PACKET_MTU ||
        evidence->mtu > (int32_t)VMP_MQVPN_EXIT_PACKET_MTU ||
        (evidence->has_ipv6 != 0 && evidence->has_ipv6 != 1) ||
        evidence->has_ipv6 != (int32_t)state->pool_has_ipv6) {
        return false;
    }
    if (evidence->has_ipv6 == 0) return raw_v6_absent(evidence);
    return evidence->assigned_prefix_v6 == 112U &&
           client_ipv6_has_offset(evidence->assigned_ipv6, offset);
}

static void normalized_assignment(
    const vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence,
    vmp_tunnel_assignment_t *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->assigned_ipv4, evidence->assigned_ipv4,
           sizeof(out->assigned_ipv4));
    out->assigned_prefix_v4 = 32U;
    memcpy(out->server_ipv4, VMP_EXIT_SERVER_IPV4,
           sizeof(VMP_EXIT_SERVER_IPV4));
    out->server_prefix_v4 = 32U;
    out->mtu = (uint32_t)evidence->mtu;
    out->has_ipv6 = state->pool_has_ipv6 == 1U;
    if (out->has_ipv6) {
        memcpy(out->assigned_ipv6, evidence->assigned_ipv6,
               sizeof(out->assigned_ipv6));
        out->assigned_prefix_v6 = 112U;
    }
}

void vmp_mqvpn_exit_backend_state_init(
    vmp_mqvpn_exit_backend_state_t *state)
{
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->lifecycle = VMP_MQVPN_EXIT_STARTING;
    state->terminal = VMP_MQVPN_EXIT_TERMINAL_NONE;
    vmp_tunnel_assignment_state_init(&state->assignment);
}

void vmp_mqvpn_exit_backend_enter_terminal(
    vmp_mqvpn_exit_backend_state_t *state,
    vmp_mqvpn_exit_terminal_t reason)
{
    if (state == NULL || reason == VMP_MQVPN_EXIT_TERMINAL_NONE) return;
    const bool destroying = state->lifecycle == VMP_MQVPN_EXIT_DESTROYING;
    if (!terminal_is_valid(state->terminal)) {
        state->terminal = VMP_MQVPN_EXIT_TERMINAL_INVARIANT;
    } else if (state->terminal == VMP_MQVPN_EXIT_TERMINAL_NONE) {
        state->terminal = terminal_is_valid(reason)
                              ? reason
                              : VMP_MQVPN_EXIT_TERMINAL_INVARIANT;
    }
    state->lifecycle = destroying ? VMP_MQVPN_EXIT_DESTROYING
                                  : VMP_MQVPN_EXIT_TERMINAL;
    wipe_owned_state(state);
}

bool vmp_mqvpn_exit_backend_observe_tunnel_ready(
    vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_EXIT_DESTROYING ||
        state->lifecycle == VMP_MQVPN_EXIT_TERMINAL) {
        return false;
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_STARTING ||
        !pool_evidence_is_valid(evidence)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return false;
    }

    state->pool_ready = 1U;
    state->pool_has_ipv6 = (uint8_t)evidence->has_ipv6;
    if (state->pool_has_ipv6 == 1U) {
        memcpy(state->server_ipv6, VMP_EXIT_SERVER_IPV6,
               sizeof(VMP_EXIT_SERVER_IPV6));
        state->server_prefix_v6 = 112U;
    }
    state->lifecycle = VMP_MQVPN_EXIT_LISTENING;
    return true;
}

bool vmp_mqvpn_exit_backend_finish_start(
    vmp_mqvpn_exit_backend_state_t *state, bool start_succeeded)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_EXIT_DESTROYING ||
        state->lifecycle == VMP_MQVPN_EXIT_TERMINAL) {
        return false;
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    if (!start_succeeded || state->lifecycle != VMP_MQVPN_EXIT_LISTENING ||
        state->start_completed != 0U) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return false;
    }
    state->start_completed = 1U;
    return true;
}

bool vmp_mqvpn_exit_backend_observe_client_connected(
    vmp_mqvpn_exit_backend_state_t *state,
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence,
    uint32_t session_id)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_EXIT_DESTROYING ||
        state->lifecycle == VMP_MQVPN_EXIT_TERMINAL) {
        return false;
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_LISTENING ||
        state->start_completed != 1U ||
        !connected_evidence_is_valid(state, evidence, session_id)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return false;
    }

    vmp_tunnel_assignment_t assignment;
    normalized_assignment(state, evidence, &assignment);
    const vmp_tunnel_assignment_accept_result_t accepted =
        vmp_tunnel_assignment_state_accept(&state->assignment,
                                           &assignment);
    secure_zero(&assignment, sizeof(assignment));
    if (accepted != VMP_TUNNEL_ASSIGNMENT_ACCEPTED) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    state->session_id = session_id;
    state->lifecycle = VMP_MQVPN_EXIT_CONNECTED;
    return true;
}

bool vmp_mqvpn_exit_backend_observe_client_disconnected(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_EXIT_DESTROYING ||
        state->lifecycle == VMP_MQVPN_EXIT_TERMINAL) {
        return false;
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED ||
        session_id != state->session_id) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return false;
    }
    vmp_mqvpn_exit_backend_enter_terminal(
        state, VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED);
    return true;
}

bool vmp_mqvpn_exit_backend_begin_destroy(
    vmp_mqvpn_exit_backend_state_t *state)
{
    if (state == NULL || state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        return false;
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    }
    state->lifecycle = VMP_MQVPN_EXIT_DESTROYING;
    wipe_owned_state(state);
    return true;
}

bool vmp_mqvpn_exit_backend_snapshot(
    vmp_mqvpn_exit_backend_state_t *state, bool *out_listening,
    bool *out_connected, uint32_t *out_session_id,
    vmp_mqvpn_exit_assignment_t *out_assignment)
{
    const vmp_output_range_t outputs[] = {
        {.pointer = out_listening, .length = sizeof(*out_listening)},
        {.pointer = out_connected, .length = sizeof(*out_connected)},
        {.pointer = out_session_id, .length = sizeof(*out_session_id)},
        {.pointer = out_assignment, .length = sizeof(*out_assignment)},
    };
    if (!output_ranges_are_valid(state, outputs,
                                 sizeof(outputs) / sizeof(outputs[0]))) {
        fail_live_state_for_invalid_outputs(state);
        return false;
    }
    *out_listening = false;
    *out_connected = false;
    *out_session_id = 0U;
    memset(out_assignment, 0, sizeof(*out_assignment));
    if (state == NULL) return false;
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return false;
    }
    if (state->lifecycle == VMP_MQVPN_EXIT_TERMINAL ||
        state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        return false;
    }
    if (state->lifecycle == VMP_MQVPN_EXIT_STARTING) return true;
    if (state->lifecycle == VMP_MQVPN_EXIT_LISTENING) {
        *out_listening = state->start_completed == 1U;
        return true;
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED ||
        !vmp_tunnel_assignment_state_snapshot(
            &state->assignment, &out_assignment->tunnel)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        memset(out_assignment, 0, sizeof(*out_assignment));
        return false;
    }
    if (state->pool_has_ipv6 == 1U) {
        memcpy(out_assignment->server_ipv6, state->server_ipv6,
               sizeof(out_assignment->server_ipv6));
        out_assignment->server_prefix_v6 = state->server_prefix_v6;
    }
    *out_listening = true;
    *out_connected = true;
    *out_session_id = state->session_id;
    return true;
}

static vmp_mqvpn_exit_result_t enqueue_packet(
    vmp_mqvpn_exit_backend_state_t *state,
    vmp_mqvpn_exit_packet_kind_t kind, const uint8_t *packet,
    size_t packet_len)
{
    if (state == NULL) return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    if (state->lifecycle == VMP_MQVPN_EXIT_TERMINAL ||
        state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        return terminal_result(state);
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED || packet == NULL ||
        packet_len == 0U || packet_len > VMP_MQVPN_EXIT_PACKET_MTU ||
        packet_len > (size_t)state->assignment.assignment.mtu) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
    const bool packet_owned =
        kind == VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK
            ? vmp_tunnel_assignment_packet_source_is_owned(
                  &state->assignment, packet, packet_len)
            : kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP &&
                  server_packet_is_icmp(packet, packet_len) &&
                  server_packet_source_is_owned(state, packet, packet_len);
    if (!packet_owned) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
    if (state->queue_count == VMP_MQVPN_EXIT_MAX_PACKETS ||
        packet_len > VMP_MQVPN_EXIT_MAX_BYTES - state->queue_bytes) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_OVERFLOW);
        return VMP_MQVPN_EXIT_RESULT_OVERFLOW;
    }

    vmp_mqvpn_exit_packet_t *entry = &state->queue[state->queue_tail];
    secure_zero(entry, sizeof(*entry));
    entry->kind = kind;
    memcpy(entry->bytes, packet, packet_len);
    entry->len = packet_len;
    state->queue_tail =
        (state->queue_tail + 1U) % VMP_MQVPN_EXIT_MAX_PACKETS;
    ++state->queue_count;
    state->queue_bytes += packet_len;
    return VMP_MQVPN_EXIT_RESULT_NONE;
}

vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_enqueue_client_uplink(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id,
    const uint8_t *packet, size_t packet_len)
{
    if (state == NULL) return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    if (state->lifecycle == VMP_MQVPN_EXIT_TERMINAL ||
        state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        return terminal_result(state);
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED ||
        session_id != state->session_id) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
    return enqueue_packet(state, VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK,
                          packet, packet_len);
}

vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_enqueue_server_icmp(
    vmp_mqvpn_exit_backend_state_t *state, const uint8_t *packet,
    size_t packet_len)
{
    return enqueue_packet(state, VMP_MQVPN_EXIT_PACKET_SERVER_ICMP,
                          packet, packet_len);
}

vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_dequeue(
    vmp_mqvpn_exit_backend_state_t *state, uint8_t *out,
    size_t out_capacity, size_t *out_len,
    vmp_mqvpn_exit_packet_kind_t *out_kind, uint32_t *out_session_id)
{
    const vmp_output_range_t scalar_outputs[] = {
        {.pointer = out_len, .length = sizeof(*out_len)},
        {.pointer = out_kind, .length = sizeof(*out_kind)},
        {.pointer = out_session_id, .length = sizeof(*out_session_id)},
    };
    if ((out == NULL && out_capacity != 0U) ||
        !output_ranges_are_valid(
            state, scalar_outputs,
            sizeof(scalar_outputs) / sizeof(scalar_outputs[0]))) {
        fail_live_state_for_invalid_outputs(state);
        return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    }
    if (state == NULL) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    }
    if (state->lifecycle == VMP_MQVPN_EXIT_TERMINAL ||
        state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        return terminal_result(state);
    }
    if (!state_is_valid(state)) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
    if (state->queue_count == 0U) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        return VMP_MQVPN_EXIT_RESULT_EMPTY;
    }

    vmp_mqvpn_exit_packet_t *entry = &state->queue[state->queue_head];
    if (out_capacity < entry->len) {
        initialize_dequeue_outputs(out_len, out_kind, out_session_id);
        return VMP_MQVPN_EXIT_RESULT_RESOURCE;
    }
    const vmp_output_range_t all_outputs[] = {
        {.pointer = out_len, .length = sizeof(*out_len)},
        {.pointer = out_kind, .length = sizeof(*out_kind)},
        {.pointer = out_session_id, .length = sizeof(*out_session_id)},
        {.pointer = out, .length = entry->len},
    };
    if (!output_ranges_are_valid(
            state, all_outputs,
            sizeof(all_outputs) / sizeof(all_outputs[0]))) {
        fail_live_state_for_invalid_outputs(state);
        return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    }
    initialize_dequeue_outputs(out_len, out_kind, out_session_id);
    const size_t packet_len = entry->len;
    const vmp_mqvpn_exit_packet_kind_t kind = entry->kind;
    memcpy(out, entry->bytes, packet_len);
    secure_zero(entry, sizeof(*entry));
    state->queue_head =
        (state->queue_head + 1U) % VMP_MQVPN_EXIT_MAX_PACKETS;
    --state->queue_count;
    state->queue_bytes -= packet_len;
    *out_len = packet_len;
    *out_kind = kind;
    *out_session_id = state->session_id;
    return VMP_MQVPN_EXIT_RESULT_NONE;
}

vmp_mqvpn_exit_result_t vmp_mqvpn_exit_backend_validate_downlink(
    vmp_mqvpn_exit_backend_state_t *state, uint32_t session_id,
    const uint8_t *packet, size_t packet_len)
{
    if (state == NULL) return VMP_MQVPN_EXIT_RESULT_INVARIANT;
    if (state->lifecycle == VMP_MQVPN_EXIT_TERMINAL ||
        state->lifecycle == VMP_MQVPN_EXIT_DESTROYING) {
        return terminal_result(state);
    }
    if (!state_is_valid(state)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_EXIT_CONNECTED ||
        session_id != state->session_id || packet == NULL ||
        packet_len == 0U || packet_len > VMP_MQVPN_EXIT_PACKET_MTU ||
        packet_len > (size_t)state->assignment.assignment.mtu ||
        !vmp_tunnel_assignment_packet_destination_is_owned(
            &state->assignment, packet, packet_len)) {
        vmp_mqvpn_exit_backend_enter_terminal(
            state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
        return VMP_MQVPN_EXIT_RESULT_ENGINE;
    }
    return VMP_MQVPN_EXIT_RESULT_NONE;
}
