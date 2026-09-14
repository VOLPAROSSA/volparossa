// SPDX-License-Identifier: GPL-3.0-only

#include "mqvpn_backend_state.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IPV4_PACKET_LEN 20U

static const uint8_t ASSIGNED_IPV4[4] = {10U, 76U, 0U, 2U};
static const uint8_t SERVER_IPV4[4] = {10U, 76U, 0U, 1U};
static const uint8_t OTHER_IPV4[4] = {10U, 76U, 0U, 3U};

static vmp_tunnel_assignment_t valid_assignment(void)
{
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    assignment.assigned_ipv4[0] = 10U;
    assignment.assigned_ipv4[1] = 76U;
    assignment.assigned_ipv4[3] = 2U;
    assignment.assigned_prefix_v4 = 32U;
    assignment.server_ipv4[0] = 10U;
    assignment.server_ipv4[1] = 76U;
    assignment.server_ipv4[3] = 1U;
    assignment.server_prefix_v4 = 32U;
    assignment.mtu = 1420U;
    return assignment;
}

static void make_ipv4_packet(uint8_t packet[IPV4_PACKET_LEN],
                             const uint8_t destination[4],
                             uint8_t marker)
{
    memset(packet, 0, IPV4_PACKET_LEN);
    packet[0] = 0x45U;
    packet[3] = IPV4_PACKET_LEN;
    packet[5] = marker;
    packet[8] = 64U;
    packet[9] = 17U;
    memcpy(&packet[12], SERVER_IPV4, 4U);
    memcpy(&packet[16], destination, 4U);
}

static void expect_assignment_wiped(
    const vmp_mqvpn_backend_state_t *state)
{
    const uint8_t *bytes =
        (const uint8_t *)(const void *)&state->assignment;
    for (size_t index = 0U; index < sizeof(state->assignment); ++index) {
        assert(bytes[index] == 0U);
    }
}

static void expect_fifo_wiped(const vmp_mqvpn_backend_state_t *state)
{
    assert(state->reverse_head == 0U);
    assert(state->reverse_tail == 0U);
    assert(state->reverse_count == 0U);
    assert(state->reverse_bytes == 0U);
    const uint8_t *bytes =
        (const uint8_t *)(const void *)state->reverse_queue;
    for (size_t index = 0U; index < sizeof(state->reverse_queue);
         ++index) {
        assert(bytes[index] == 0U);
    }
}

static void expect_fifo_empty(const vmp_mqvpn_backend_state_t *state)
{
    assert(state->reverse_head == state->reverse_tail);
    assert(state->reverse_count == 0U);
    assert(state->reverse_bytes == 0U);
    const uint8_t *bytes =
        (const uint8_t *)(const void *)state->reverse_queue;
    for (size_t index = 0U; index < sizeof(state->reverse_queue);
         ++index) {
        assert(bytes[index] == 0U);
    }
}

static void expect_empty_snapshot(
    vmp_mqvpn_backend_state_t *state, bool expected_result)
{
    bool tunnel_ready = true;
    bool has_assignment = true;
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0xa5, sizeof(assignment));
    assert(vmp_mqvpn_backend_state_snapshot(
               state, &tunnel_ready, &has_assignment, &assignment) ==
           expected_result);
    assert(!tunnel_ready);
    assert(!has_assignment);
    const uint8_t *bytes = (const uint8_t *)(const void *)&assignment;
    for (size_t index = 0U; index < sizeof(assignment); ++index) {
        assert(bytes[index] == 0U);
    }
}

static void advance_to_tunnel_ready(vmp_mqvpn_backend_state_t *state)
{
    assert(vmp_mqvpn_backend_state_observe_transition(
        state, VMP_MQVPN_PHASE_IDLE, VMP_MQVPN_PHASE_CONNECTING));
    assert(vmp_mqvpn_backend_state_observe_transition(
        state, VMP_MQVPN_PHASE_CONNECTING,
        VMP_MQVPN_PHASE_AUTHENTICATING));
    assert(vmp_mqvpn_backend_state_observe_transition(
        state, VMP_MQVPN_PHASE_AUTHENTICATING,
        VMP_MQVPN_PHASE_TUNNEL_READY));
}

static void advance_to_active(vmp_mqvpn_backend_state_t *state,
                              const vmp_tunnel_assignment_t *assignment)
{
    advance_to_tunnel_ready(state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               state, VMP_MQVPN_PHASE_TUNNEL_READY, assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    assert(state->lifecycle == VMP_MQVPN_BACKEND_ACTIVATING);
    assert(vmp_mqvpn_backend_state_observe_transition(
        state, VMP_MQVPN_PHASE_TUNNEL_READY,
        VMP_MQVPN_PHASE_ESTABLISHED));
    assert(vmp_mqvpn_backend_state_finish_activation(
        state, true, VMP_MQVPN_PHASE_ESTABLISHED));
    assert(state->lifecycle == VMP_MQVPN_BACKEND_ACTIVE);
}

static void test_normal_ordering_duplicate_and_snapshots(void)
{
    vmp_mqvpn_backend_state_t state;
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_init(&state);
    assert(state.lifecycle == VMP_MQVPN_BACKEND_EXPECTING);
    assert(state.observed_phase == VMP_MQVPN_PHASE_IDLE);
    assert(state.terminal == VMP_MQVPN_TERMINAL_NONE);
    expect_empty_snapshot(&state, true);

    advance_to_tunnel_ready(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    expect_empty_snapshot(&state, true);
    assert(vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_TUNNEL_READY,
        VMP_MQVPN_PHASE_ESTABLISHED));
    expect_empty_snapshot(&state, true);
    assert(vmp_mqvpn_backend_state_finish_activation(
        &state, true, VMP_MQVPN_PHASE_ESTABLISHED));

    bool tunnel_ready = false;
    bool has_assignment = false;
    vmp_tunnel_assignment_t snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    assert(vmp_mqvpn_backend_state_snapshot(
        &state, &tunnel_ready, &has_assignment, &snapshot));
    assert(tunnel_ready);
    assert(has_assignment);
    assert(memcmp(&snapshot, &assignment, sizeof(snapshot)) == 0);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_ESTABLISHED, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_DUPLICATE);
    assert(state.lifecycle == VMP_MQVPN_BACKEND_ACTIVE);
    assert(vmp_mqvpn_backend_state_sample_phase(
        &state, VMP_MQVPN_PHASE_ESTABLISHED));

    assert(!vmp_mqvpn_backend_state_snapshot(
        NULL, &tunnel_ready, &has_assignment, &snapshot));
    assert(!tunnel_ready && !has_assignment);
    tunnel_ready = true;
    memset(&snapshot, 0xa5, sizeof(snapshot));
    assert(!vmp_mqvpn_backend_state_snapshot(
        &state, NULL, &has_assignment, &snapshot));
    assert(!has_assignment);
    const uint8_t *snapshot_bytes =
        (const uint8_t *)(const void *)&snapshot;
    for (size_t index = 0U; index < sizeof(snapshot); ++index) {
        assert(snapshot_bytes[index] == 0U);
    }
    has_assignment = true;
    assert(!vmp_mqvpn_backend_state_snapshot(
        &state, &tunnel_ready, NULL, &snapshot));
    assert(!tunnel_ready);
    assert(!vmp_mqvpn_backend_state_snapshot(
        &state, &tunnel_ready, &has_assignment, NULL));
    assert(!tunnel_ready && !has_assignment);
}

static void test_invalid_conflict_and_wrong_order_are_terminal(void)
{
    vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;

    vmp_mqvpn_backend_state_init(&state);
    advance_to_tunnel_ready(&state);
    assignment.mtu = 1421U;
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);

    assignment = valid_assignment();
    vmp_mqvpn_backend_state_init(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_IDLE, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    assignment.assigned_ipv4[3] = 3U;
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_ESTABLISHED, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    expect_assignment_wiped(&state);

    assignment = valid_assignment();
    vmp_mqvpn_backend_state_init(&state);
    advance_to_tunnel_ready(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    assert(!vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_IDLE,
        VMP_MQVPN_PHASE_AUTHENTICATING));
    assert(state.lifecycle == VMP_MQVPN_BACKEND_TERMINAL);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    state.observed_phase = VMP_MQVPN_PHASE_ESTABLISHED;
    expect_empty_snapshot(&state, false);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);

    assert(vmp_mqvpn_backend_state_offer_assignment(
               NULL, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    vmp_mqvpn_backend_state_init(NULL);
}

static void test_activation_failures_and_callback_terminal(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;

    vmp_mqvpn_backend_state_init(&state);
    advance_to_tunnel_ready(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    assert(!vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_TUNNEL_READY,
        VMP_MQVPN_PHASE_CLOSED));
    assert(!vmp_mqvpn_backend_state_finish_activation(
        &state, true, VMP_MQVPN_PHASE_ESTABLISHED));
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_tunnel_ready(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    assert(vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_TUNNEL_READY,
        VMP_MQVPN_PHASE_ESTABLISHED));
    assert(!vmp_mqvpn_backend_state_finish_activation(
        &state, false, VMP_MQVPN_PHASE_ESTABLISHED));
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_tunnel_ready(&state);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_ACTIVATE);
    assert(!vmp_mqvpn_backend_state_finish_activation(
        &state, true, VMP_MQVPN_PHASE_ESTABLISHED));
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    assert(!vmp_mqvpn_backend_state_finish_activation(
        &state, true, VMP_MQVPN_PHASE_ESTABLISHED));
    expect_assignment_wiped(&state);
}

static void test_terminal_reason_is_first_error_and_wipes(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, VMP_MQVPN_TERMINAL_NONE);
    assert(state.lifecycle == VMP_MQVPN_BACKEND_ACTIVE);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, VMP_MQVPN_TERMINAL_OVERFLOW);
    assert(state.lifecycle == VMP_MQVPN_BACKEND_TERMINAL);
    assert(state.terminal == VMP_MQVPN_TERMINAL_OVERFLOW);
    expect_assignment_wiped(&state);
    expect_empty_snapshot(&state, false);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, VMP_MQVPN_TERMINAL_ENGINE);
    assert(state.terminal == VMP_MQVPN_TERMINAL_OVERFLOW);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, VMP_MQVPN_TERMINAL_ENGINE);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, VMP_MQVPN_TERMINAL_OVERFLOW);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    vmp_mqvpn_backend_state_enter_terminal(
        &state, (vmp_mqvpn_backend_terminal_t)99);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    vmp_mqvpn_backend_state_enter_terminal(NULL,
                                            VMP_MQVPN_TERMINAL_ENGINE);
}

static void test_transition_pin_and_terminal_cannot_rearm(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;

    vmp_mqvpn_backend_state_init(&state);
    assert(!vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_CONNECTING,
        VMP_MQVPN_PHASE_AUTHENTICATING));
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    assert(!vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_IDLE, VMP_MQVPN_PHASE_IDLE));
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    assert(!vmp_mqvpn_backend_state_observe_transition(
        &state, VMP_MQVPN_PHASE_ESTABLISHED,
        VMP_MQVPN_PHASE_ESTABLISHED));
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    assert(vmp_mqvpn_backend_state_offer_assignment(
               &state, VMP_MQVPN_PHASE_TUNNEL_READY, &assignment) ==
           VMP_MQVPN_ASSIGNMENT_TERMINAL);
    assert(!vmp_mqvpn_backend_state_finish_activation(
        &state, true, VMP_MQVPN_PHASE_ESTABLISHED));
    assert(!vmp_mqvpn_backend_state_sample_phase(
        &state, VMP_MQVPN_PHASE_ESTABLISHED));
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, ASSIGNED_IPV4, 1U);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_ENGINE);
    uint8_t out[IPV4_PACKET_LEN];
    size_t out_len = 99U;
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out), &out_len) ==
           VMP_MQVPN_RESULT_ENGINE);
    assert(out_len == 0U);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);
}

static void test_reverse_fifo_order_and_resource_preservation(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;
    uint8_t first[IPV4_PACKET_LEN];
    uint8_t second[IPV4_PACKET_LEN];
    uint8_t out[IPV4_PACKET_LEN];
    make_ipv4_packet(first, ASSIGNED_IPV4, 1U);
    make_ipv4_packet(second, ASSIGNED_IPV4, 2U);
    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);

    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, first, sizeof(first)) ==
           VMP_MQVPN_RESULT_NONE);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, second, sizeof(second)) ==
           VMP_MQVPN_RESULT_NONE);
    assert(state.reverse_count == 2U);
    assert(state.reverse_bytes == sizeof(first) + sizeof(second));

    size_t out_len = 99U;
    memset(out, 0xa5, sizeof(out));
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out) - 1U, &out_len) ==
           VMP_MQVPN_RESULT_RESOURCE);
    assert(out_len == 0U);
    assert(state.reverse_count == 2U);
    assert(state.reverse_bytes == sizeof(first) + sizeof(second));

    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out), &out_len) ==
           VMP_MQVPN_RESULT_NONE);
    assert(out_len == sizeof(first));
    assert(memcmp(out, first, sizeof(first)) == 0);
    assert(state.reverse_count == 1U);
    assert(state.reverse_bytes == sizeof(second));
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out), &out_len) ==
           VMP_MQVPN_RESULT_NONE);
    assert(out_len == sizeof(second));
    assert(memcmp(out, second, sizeof(second)) == 0);
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out), &out_len) ==
           VMP_MQVPN_RESULT_EMPTY);
    assert(out_len == 0U);
    expect_fifo_empty(&state);

    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, first, sizeof(first)) ==
           VMP_MQVPN_RESULT_NONE);
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, NULL, 0U, &out_len) ==
           VMP_MQVPN_RESULT_ENGINE);
    assert(out_len == 0U);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);
}

static void test_reverse_fifo_overflow_and_complete_wipe(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, ASSIGNED_IPV4, 7U);
    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);

    for (size_t index = 0U; index < VMP_MQVPN_REVERSE_MAX_PACKETS;
         ++index) {
        packet[5] = (uint8_t)index;
        assert(vmp_mqvpn_backend_state_enqueue_reverse(
                   &state, packet, sizeof(packet)) ==
               VMP_MQVPN_RESULT_NONE);
    }
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_OVERFLOW);
    assert(state.terminal == VMP_MQVPN_TERMINAL_OVERFLOW);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_OVERFLOW);

    /* The bounded queue retains enough assignment-sized datagrams to absorb a
     * transport burst without allocating the protocol's 64 KiB maximum for
     * every slot. A forged byte counter is corruption, not a legitimate
     * resource overflow, and therefore fails as ENGINE. */
    assert(VMP_MQVPN_REVERSE_MAX_BYTES >
           VMP_MQVPN_REVERSE_MAX_PACKETS * 1420U);
    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_NONE);
    state.reverse_bytes = VMP_MQVPN_REVERSE_MAX_BYTES;
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_ENGINE);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);
}

static void test_reverse_fifo_rejects_packets_and_corruption(void)
{
    const vmp_tunnel_assignment_t assignment = valid_assignment();
    vmp_mqvpn_backend_state_t state;
    uint8_t packet[IPV4_PACKET_LEN];

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    make_ipv4_packet(packet, OTHER_IPV4, 1U);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    make_ipv4_packet(packet, ASSIGNED_IPV4, 2U);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_NONE);
    state.reverse_queue[state.reverse_head].bytes[19] = 3U;
    uint8_t out[IPV4_PACKET_LEN];
    size_t out_len = 99U;
    assert(vmp_mqvpn_backend_state_dequeue_reverse(
               &state, out, sizeof(out), &out_len) ==
           VMP_MQVPN_RESULT_ENGINE);
    assert(out_len == 0U);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);

    vmp_mqvpn_backend_state_init(&state);
    advance_to_active(&state, &assignment);
    make_ipv4_packet(packet, ASSIGNED_IPV4, 3U);
    assert(vmp_mqvpn_backend_state_enqueue_reverse(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_RESULT_NONE);
    state.reverse_bytes = 0U;
    bool tunnel_ready = true;
    bool has_assignment = true;
    vmp_tunnel_assignment_t snapshot;
    memset(&snapshot, 0xa5, sizeof(snapshot));
    assert(!vmp_mqvpn_backend_state_snapshot(
        &state, &tunnel_ready, &has_assignment, &snapshot));
    assert(!tunnel_ready && !has_assignment);
    assert(state.terminal == VMP_MQVPN_TERMINAL_ENGINE);
    expect_assignment_wiped(&state);
    expect_fifo_wiped(&state);
}

static vmp_mqvpn_path_record_t path_record(
    int64_t handle, vmp_mqvpn_path_state_t state, uint64_t metric_seed)
{
    vmp_mqvpn_path_record_t record;
    memset(&record, 0, sizeof(record));
    record.handle = handle;
    record.state = state;
    record.metrics_valid = UINT64_C(0x25);
    record.smoothed_rtt_us = metric_seed;
    record.packets_lost = metric_seed + 1U;
    record.congestion_window_bytes = metric_seed + 2U;
    record.bytes_in_flight = metric_seed + 3U;
    record.estimated_rate_bytes_per_sec = metric_seed + 4U;
    record.acked_transport_bytes = metric_seed + 5U;
    return record;
}

static void expect_path_output_zero(
    const vmp_mqvpn_path_record_t *out, size_t capacity)
{
    const uint8_t *bytes = (const uint8_t *)(const void *)out;
    for (size_t index = 0U; index < capacity * sizeof(*out); ++index) {
        assert(bytes[index] == 0U);
    }
}

static void test_exact_path_projection_and_order(void)
{
    const int64_t expected[4] = {20, 10, 40, 30};
    vmp_mqvpn_path_record_t observed[4] = {
        path_record(10, VMP_MQVPN_PATH_ACTIVE, 100U),
        path_record(30, VMP_MQVPN_PATH_CLOSED, 300U),
        path_record(20, VMP_MQVPN_PATH_PENDING, 200U),
        path_record(40, VMP_MQVPN_PATH_DEGRADED, 400U),
    };
    vmp_mqvpn_path_record_t out[4];
    memset(out, 0xa5, sizeof(out));
    size_t count = 99U;
    assert(vmp_mqvpn_backend_project_paths(
        expected, 4U, observed, 4U, out, 4U, &count));
    assert(count == 4U);
    for (size_t index = 0U; index < 4U; ++index) {
        assert(out[index].handle == expected[index]);
    }
    assert(out[0].state == VMP_MQVPN_PATH_PENDING);
    assert(out[0].metrics_valid == UINT64_C(0x25));
    assert(out[0].smoothed_rtt_us == 200U);
    assert(out[1].state == VMP_MQVPN_PATH_ACTIVE);
    assert(out[2].state == VMP_MQVPN_PATH_DEGRADED);
    assert(out[3].state == VMP_MQVPN_PATH_CLOSED);

    count = 99U;
    assert(vmp_mqvpn_backend_project_paths(
        NULL, 0U, NULL, 0U, NULL, 0U, &count));
    assert(count == 0U);

    vmp_mqvpn_path_record_t alias[4];
    memcpy(alias, observed, sizeof(alias));
    count = 99U;
    assert(vmp_mqvpn_backend_project_paths(
        expected, 4U, alias, 4U, alias, 4U, &count));
    assert(count == 4U);
    for (size_t index = 0U; index < 4U; ++index) {
        assert(alias[index].handle == expected[index]);
    }
}

static void assert_projection_fails(
    const int64_t *expected, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count,
    size_t capacity)
{
    vmp_mqvpn_path_record_t out[VMP_MQVPN_BACKEND_MAX_PATHS];
    memset(out, 0xa5, sizeof(out));
    size_t count = 99U;
    assert(!vmp_mqvpn_backend_project_paths(
        expected, expected_count, observed, observed_count, out,
        capacity, &count));
    assert(count == 0U);
    expect_path_output_zero(out, capacity);
}

static void test_path_projection_rejects_ambiguity(void)
{
    int64_t expected[2] = {10, 20};
    vmp_mqvpn_path_record_t observed[2] = {
        path_record(10, VMP_MQVPN_PATH_ACTIVE, 1U),
        path_record(20, VMP_MQVPN_PATH_PENDING, 2U),
    };

    assert_projection_fails(expected, 2U, observed, 1U, 2U);
    assert_projection_fails(expected, 1U, observed, 2U, 2U);
    assert_projection_fails(expected, 2U, observed, 2U, 1U);

    expected[1] = 10;
    assert_projection_fails(expected, 2U, observed, 2U, 2U);
    expected[1] = 20;
    observed[1].handle = 10;
    assert_projection_fails(expected, 2U, observed, 2U, 2U);
    observed[1] = path_record(30, VMP_MQVPN_PATH_PENDING, 2U);
    assert_projection_fails(expected, 2U, observed, 2U, 2U);
    observed[1] = path_record(20, (vmp_mqvpn_path_state_t)99, 2U);
    assert_projection_fails(expected, 2U, observed, 2U, 2U);
    observed[1] = path_record(20, VMP_MQVPN_PATH_PENDING, 2U);
    expected[1] = -1;
    assert_projection_fails(expected, 2U, observed, 2U, 2U);
    expected[1] = 20;
    observed[1].handle = -1;
    assert_projection_fails(expected, 2U, observed, 2U, 2U);

    size_t count = 99U;
    assert(!vmp_mqvpn_backend_project_paths(
        expected, 2U, observed, 2U, NULL, 2U, &count));
    assert(count == 0U);
    assert(!vmp_mqvpn_backend_project_paths(
        expected, 2U, observed, 2U, observed, 2U, NULL));
}

static void assert_current_selection_fails(
    const int64_t *expected, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count)
{
    vmp_mqvpn_path_record_t out[VMP_MQVPN_BACKEND_MAX_PATHS];
    memset(out, 0xa5, sizeof(out));
    size_t count = 99U;
    assert(!vmp_mqvpn_backend_select_current_paths(
        expected, expected_count, observed, observed_count, out,
        VMP_MQVPN_BACKEND_MAX_PATHS, &count));
    assert(count == 0U);
    expect_path_output_zero(out, VMP_MQVPN_BACKEND_MAX_PATHS);
}

static void test_current_path_selection_allows_only_retired_closed(void)
{
    const int64_t expected[2] = {20, 10};
    vmp_mqvpn_path_record_t observed[4] = {
        path_record(10, VMP_MQVPN_PATH_ACTIVE, 100U),
        path_record(1, VMP_MQVPN_PATH_CLOSED, 1U),
        path_record(20, VMP_MQVPN_PATH_PENDING, 200U),
        path_record(2, VMP_MQVPN_PATH_CLOSED, 2U),
    };
    vmp_mqvpn_path_record_t out[2];
    memset(out, 0xa5, sizeof(out));
    size_t count = 99U;
    assert(vmp_mqvpn_backend_select_current_paths(
        expected, 2U, observed, 4U, out, 2U, &count));
    assert(count == 2U);
    assert(out[0].handle == 20);
    assert(out[0].state == VMP_MQVPN_PATH_PENDING);
    assert(out[0].smoothed_rtt_us == 200U);
    assert(out[1].handle == 10);
    assert(out[1].state == VMP_MQVPN_PATH_ACTIVE);

    for (vmp_mqvpn_path_state_t state = VMP_MQVPN_PATH_PENDING;
         state <= VMP_MQVPN_PATH_DEGRADED;
         state = (vmp_mqvpn_path_state_t)((int)state + 1)) {
        observed[1] = path_record(1, state, 1U);
        assert_current_selection_fails(expected, 2U, observed, 4U);
    }

    observed[1] = path_record(10, VMP_MQVPN_PATH_CLOSED, 1U);
    assert_current_selection_fails(expected, 2U, observed, 4U);
    observed[1] = path_record(1, VMP_MQVPN_PATH_CLOSED, 1U);
    observed[2] = path_record(30, VMP_MQVPN_PATH_CLOSED, 200U);
    assert_current_selection_fails(expected, 2U, observed, 4U);

    const vmp_mqvpn_path_record_t retired_only[2] = {
        path_record(1, VMP_MQVPN_PATH_CLOSED, 1U),
        path_record(2, VMP_MQVPN_PATH_CLOSED, 2U),
    };
    count = 99U;
    assert(vmp_mqvpn_backend_select_current_paths(
        NULL, 0U, retired_only, 2U, NULL, 0U, &count));
    assert(count == 0U);
}

int main(void)
{
    test_normal_ordering_duplicate_and_snapshots();
    test_invalid_conflict_and_wrong_order_are_terminal();
    test_activation_failures_and_callback_terminal();
    test_terminal_reason_is_first_error_and_wipes();
    test_transition_pin_and_terminal_cannot_rearm();
    test_reverse_fifo_order_and_resource_preservation();
    test_reverse_fifo_overflow_and_complete_wipe();
    test_reverse_fifo_rejects_packets_and_corruption();
    test_exact_path_projection_and_order();
    test_path_projection_rejects_ambiguity();
    test_current_path_selection_allows_only_retired_closed();
    puts("mqvpn backend state tests passed");
    return 0;
}
