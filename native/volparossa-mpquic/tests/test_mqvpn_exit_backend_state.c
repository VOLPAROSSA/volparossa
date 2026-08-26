// SPDX-License-Identifier: GPL-3.0-only

#include "mqvpn_exit_backend_state.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IPV4_PACKET_LEN 24U
#define IPV4_ICMP_PACKET_LEN 28U
#define IPV6_PACKET_LEN 48U
#define NEGOTIATED_MTU 1382U

static const uint8_t POOL_IPV4[4] = {10U, 76U, 0U, 0U};
static const uint8_t SERVER_IPV4[4] = {10U, 76U, 0U, 1U};
static const uint8_t CLIENT_IPV4[4] = {10U, 76U, 0U, 2U};
static const uint8_t OTHER_IPV4[4] = {203U, 0U, 113U, 9U};
static const uint8_t SERVER_IPV6[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,   0U,   0U,   0U,   0U,   0U,   0U, 1U,
};
static const uint8_t CLIENT_IPV6[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,   0U,   0U,   0U,   0U,   0U,   0U, 2U,
};
static const uint8_t OTHER_IPV6[16] = {
    0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
    0U,    0U,    0U,    0U,    0U, 0U, 0U, 9U,
};

static bool memory_is_zero(const void *memory, size_t length)
{
    const uint8_t *bytes = memory;
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

static vmp_mqvpn_exit_raw_tunnel_info_t pool_evidence(bool with_ipv6)
{
    vmp_mqvpn_exit_raw_tunnel_info_t evidence;
    memset(&evidence, 0, sizeof(evidence));
    memcpy(evidence.assigned_ipv4, SERVER_IPV4,
           sizeof(evidence.assigned_ipv4));
    evidence.assigned_prefix_v4 = 24U;
    memcpy(evidence.server_ipv4, POOL_IPV4,
           sizeof(evidence.server_ipv4));
    evidence.server_prefix_v4 = 24U;
    evidence.mtu = (int32_t)VMP_MQVPN_EXIT_PACKET_MTU;
    evidence.has_ipv6 = with_ipv6 ? 1 : 0;
    if (with_ipv6) {
        memcpy(evidence.assigned_ipv6, SERVER_IPV6,
               sizeof(evidence.assigned_ipv6));
        evidence.assigned_prefix_v6 = 112U;
    }
    return evidence;
}

static vmp_mqvpn_exit_raw_tunnel_info_t client_evidence_at(
    bool with_ipv6, uint8_t offset, int32_t mtu)
{
    vmp_mqvpn_exit_raw_tunnel_info_t evidence;
    memset(&evidence, 0, sizeof(evidence));
    memcpy(evidence.assigned_ipv4, CLIENT_IPV4,
           sizeof(evidence.assigned_ipv4));
    evidence.assigned_ipv4[3] = offset;
    evidence.assigned_prefix_v4 = 32U;
    memcpy(evidence.server_ipv4, POOL_IPV4,
           sizeof(evidence.server_ipv4));
    evidence.server_prefix_v4 = 24U;
    evidence.mtu = mtu;
    evidence.has_ipv6 = with_ipv6 ? 1 : 0;
    if (with_ipv6) {
        memcpy(evidence.assigned_ipv6, CLIENT_IPV6,
               sizeof(evidence.assigned_ipv6));
        evidence.assigned_ipv6[15] = offset;
        evidence.assigned_prefix_v6 = 112U;
    }
    return evidence;
}

static vmp_mqvpn_exit_raw_tunnel_info_t client_evidence(bool with_ipv6)
{
    return client_evidence_at(with_ipv6,
                              (uint8_t)VMP_MQVPN_EXIT_SESSION_ID,
                              (int32_t)NEGOTIATED_MTU);
}

static void make_ipv4_packet_sized(uint8_t *packet, size_t packet_len,
                                   const uint8_t source[4],
                                   const uint8_t destination[4],
                                   uint8_t protocol, uint8_t tag)
{
    assert(packet != NULL && packet_len >= 21U && packet_len <= 65535U);
    memset(packet, 0, packet_len);
    packet[0] = 0x45U;
    packet[2] = (uint8_t)(packet_len >> 8U);
    packet[3] = (uint8_t)packet_len;
    packet[8] = 64U;
    packet[9] = protocol;
    memcpy(&packet[12], source, 4U);
    memcpy(&packet[16], destination, 4U);
    packet[20] = tag;
}

static void make_ipv4_packet(uint8_t packet[IPV4_PACKET_LEN],
                             const uint8_t source[4],
                             const uint8_t destination[4],
                             uint8_t protocol, uint8_t tag)
{
    make_ipv4_packet_sized(packet, IPV4_PACKET_LEN, source, destination,
                           protocol, tag);
}

static void make_ipv6_packet_sized(uint8_t *packet, size_t packet_len,
                                   const uint8_t source[16],
                                   const uint8_t destination[16],
                                   uint8_t next_header, uint8_t tag)
{
    assert(packet != NULL && packet_len >= 41U &&
           packet_len - 40U <= 65535U);
    memset(packet, 0, packet_len);
    packet[0] = 0x60U;
    const size_t payload_len = packet_len - 40U;
    packet[4] = (uint8_t)(payload_len >> 8U);
    packet[5] = (uint8_t)payload_len;
    packet[6] = next_header;
    packet[7] = 64U;
    memcpy(&packet[8], source, 16U);
    memcpy(&packet[24], destination, 16U);
    packet[40] = tag;
}

static void make_ipv6_packet(uint8_t packet[IPV6_PACKET_LEN],
                             const uint8_t source[16],
                             const uint8_t destination[16],
                             uint8_t next_header, uint8_t tag)
{
    make_ipv6_packet_sized(packet, IPV6_PACKET_LEN, source, destination,
                           next_header, tag);
}

static void expect_wiped(const vmp_mqvpn_exit_backend_state_t *state)
{
    assert(state->pool_ready == 0U);
    assert(state->start_completed == 0U);
    assert(state->pool_has_ipv6 == 0U);
    assert(state->session_id == 0U);
    assert(memory_is_zero(state->server_ipv6,
                          sizeof(state->server_ipv6)));
    assert(state->server_prefix_v6 == 0U);
    assert(state->assignment.phase == VMP_TUNNEL_ASSIGNMENT_CLEARED);
    assert(memory_is_zero(&state->assignment.assignment,
                          sizeof(state->assignment.assignment)));
    assert(state->queue_head == 0U);
    assert(state->queue_tail == 0U);
    assert(state->queue_count == 0U);
    assert(state->queue_bytes == 0U);
    assert(memory_is_zero(state->queue, sizeof(state->queue)));
}

static void advance_to_listening(vmp_mqvpn_exit_backend_state_t *state,
                                 bool with_ipv6)
{
    const vmp_mqvpn_exit_raw_tunnel_info_t pool =
        pool_evidence(with_ipv6);
    vmp_mqvpn_exit_backend_state_init(state);
    assert(vmp_mqvpn_exit_backend_observe_tunnel_ready(state, &pool));
    assert(state->lifecycle == VMP_MQVPN_EXIT_LISTENING);
    assert(vmp_mqvpn_exit_backend_finish_start(state, true));
    assert(state->start_completed == 1U);
}

static void advance_to_connected(vmp_mqvpn_exit_backend_state_t *state,
                                 bool with_ipv6)
{
    const vmp_mqvpn_exit_raw_tunnel_info_t client =
        client_evidence(with_ipv6);
    advance_to_listening(state, with_ipv6);
    assert(vmp_mqvpn_exit_backend_observe_client_connected(
        state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state->lifecycle == VMP_MQVPN_EXIT_CONNECTED);
}

static void advance_to_connected_at(vmp_mqvpn_exit_backend_state_t *state,
                                    bool with_ipv6, uint8_t offset,
                                    int32_t mtu)
{
    const vmp_mqvpn_exit_raw_tunnel_info_t client =
        client_evidence_at(with_ipv6, offset, mtu);
    advance_to_listening(state, with_ipv6);
    assert(vmp_mqvpn_exit_backend_observe_client_connected(
        state, &client, (uint32_t)offset));
    assert(state->lifecycle == VMP_MQVPN_EXIT_CONNECTED);
}

static void expect_snapshot_empty(vmp_mqvpn_exit_backend_state_t *state,
                                  bool expected_listening)
{
    bool listening = true;
    bool connected = true;
    uint32_t session_id = 99U;
    vmp_mqvpn_exit_assignment_t assignment;
    memset(&assignment, 0xa5, sizeof(assignment));
    assert(vmp_mqvpn_exit_backend_snapshot(
        state, &listening, &connected, &session_id, &assignment));
    assert(listening == expected_listening);
    assert(!connected);
    assert(session_id == 0U);
    assert(memory_is_zero(&assignment, sizeof(assignment)));
}

static void test_synchronous_start_and_exact_normalization(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    const vmp_mqvpn_exit_raw_tunnel_info_t pool = pool_evidence(true);
    const vmp_mqvpn_exit_raw_tunnel_info_t client = client_evidence(true);

    vmp_mqvpn_exit_backend_state_init(&state);
    assert(state.lifecycle == VMP_MQVPN_EXIT_STARTING);
    expect_snapshot_empty(&state, false);
    assert(vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &pool));
    expect_snapshot_empty(&state, false);
    assert(vmp_mqvpn_exit_backend_finish_start(&state, true));
    expect_snapshot_empty(&state, true);
    assert(vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));

    bool listening = false;
    bool connected = false;
    uint32_t session_id = 0U;
    vmp_mqvpn_exit_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    assert(vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(listening && connected);
    assert(session_id == VMP_MQVPN_EXIT_SESSION_ID);
    assert(memcmp(assignment.tunnel.assigned_ipv4, CLIENT_IPV4, 4U) == 0);
    assert(assignment.tunnel.assigned_prefix_v4 == 32U);
    assert(memcmp(assignment.tunnel.server_ipv4, SERVER_IPV4, 4U) == 0);
    assert(assignment.tunnel.server_prefix_v4 == 32U);
    assert(assignment.tunnel.mtu == NEGOTIATED_MTU);
    assert(assignment.tunnel.has_ipv6);
    assert(memcmp(assignment.tunnel.assigned_ipv6, CLIENT_IPV6, 16U) == 0);
    assert(assignment.tunnel.assigned_prefix_v6 == 112U);
    assert(memcmp(assignment.server_ipv6, SERVER_IPV6, 16U) == 0);
    assert(assignment.server_prefix_v6 == 112U);
}

static void expect_pool_rejected(
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence)
{
    vmp_mqvpn_exit_backend_state_t state;
    vmp_mqvpn_exit_backend_state_init(&state);
    assert(!vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, evidence));
    assert(state.lifecycle == VMP_MQVPN_EXIT_TERMINAL);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

static void test_pool_evidence_and_synchronous_callback_are_exact(void)
{
    vmp_mqvpn_exit_raw_tunnel_info_t evidence = pool_evidence(false);
    evidence.assigned_ipv4[3] = 2U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.assigned_prefix_v4 = 32U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.server_ipv4[3] = 1U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.server_prefix_v4 = 32U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.mtu = 1419;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.mtu = 1421;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.has_ipv6 = 2;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(false);
    evidence.assigned_ipv6[15] = 1U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(true);
    evidence.assigned_ipv6[15] = 2U;
    expect_pool_rejected(&evidence);
    evidence = pool_evidence(true);
    evidence.assigned_prefix_v6 = 128U;
    expect_pool_rejected(&evidence);

    vmp_mqvpn_exit_backend_state_t state;
    vmp_mqvpn_exit_backend_state_init(&state);
    assert(!vmp_mqvpn_exit_backend_finish_start(&state, true));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);

    const vmp_mqvpn_exit_raw_tunnel_info_t valid = pool_evidence(false);
    vmp_mqvpn_exit_backend_state_init(&state);
    assert(vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &valid));
    assert(!vmp_mqvpn_exit_backend_finish_start(&state, false));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

static void expect_client_rejected(
    const vmp_mqvpn_exit_raw_tunnel_info_t *evidence,
    uint32_t session_id, bool pool_has_ipv6)
{
    vmp_mqvpn_exit_backend_state_t state;
    advance_to_listening(&state, pool_has_ipv6);
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, evidence, session_id));
    assert(state.lifecycle == VMP_MQVPN_EXIT_TERMINAL);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

static void expect_client_mtu_accepted(int32_t mtu)
{
    vmp_mqvpn_exit_backend_state_t state;
    vmp_mqvpn_exit_raw_tunnel_info_t evidence = client_evidence(false);
    evidence.mtu = mtu;
    advance_to_listening(&state, false);
    assert(vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &evidence, VMP_MQVPN_EXIT_SESSION_ID));

    bool listening = false;
    bool connected = false;
    uint32_t session_id = 0U;
    vmp_mqvpn_exit_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    assert(vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(listening && connected);
    assert(session_id == VMP_MQVPN_EXIT_SESSION_ID);
    assert(assignment.tunnel.mtu == (uint32_t)mtu);
    assert(vmp_mqvpn_exit_backend_begin_destroy(&state));
    expect_wiped(&state);
}

static void test_connection_evidence_order_and_duplicates_fail_closed(void)
{
    vmp_mqvpn_exit_raw_tunnel_info_t evidence = client_evidence(false);
    expect_client_rejected(&evidence, 3U, false);
    evidence.assigned_ipv4[3] = 3U;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(false);
    evidence.assigned_prefix_v4 = 24U;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(false);
    evidence.server_ipv4[3] = 1U;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(false);
    evidence.server_prefix_v4 = 32U;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(false);
    evidence.mtu = 1279;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(false);
    evidence.mtu = 1421;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(true);
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, false);
    evidence = client_evidence(true);
    evidence.assigned_ipv6[15] = 3U;
    expect_client_rejected(&evidence, VMP_MQVPN_EXIT_SESSION_ID, true);

    expect_client_mtu_accepted(
        (int32_t)VMP_MQVPN_EXIT_MIN_PACKET_MTU);
    expect_client_mtu_accepted((int32_t)VMP_MQVPN_EXIT_PACKET_MTU);

    vmp_mqvpn_exit_backend_state_t state;
    const vmp_mqvpn_exit_raw_tunnel_info_t pool = pool_evidence(false);
    const vmp_mqvpn_exit_raw_tunnel_info_t client = client_evidence(false);
    vmp_mqvpn_exit_backend_state_init(&state);
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);

    vmp_mqvpn_exit_backend_state_init(&state);
    assert(vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &pool));
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);

    advance_to_connected(&state, false);
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);

    advance_to_listening(&state, false);
    assert(!vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &pool));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

static void test_dynamic_client_offset_is_correlated_and_retained(void)
{
    /* mqvpn does not rewind its allocator after releasing a failed .2
     * allocation. A subsequent valid callback is therefore .3/session 3. */
    vmp_mqvpn_exit_backend_state_t state;
    vmp_mqvpn_exit_raw_tunnel_info_t evidence =
        client_evidence_at(true, 3U, (int32_t)NEGOTIATED_MTU);
    advance_to_listening(&state, true);
    assert(vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &evidence, 3U));
    memset(&evidence, 0, sizeof(evidence));

    bool listening = false;
    bool connected = false;
    uint32_t session_id = 0U;
    vmp_mqvpn_exit_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    assert(vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(listening && connected && session_id == 3U);
    assert(assignment.tunnel.assigned_ipv4[3] == 3U);
    assert(assignment.tunnel.assigned_ipv6[15] == 3U);
    assert(assignment.tunnel.mtu == NEGOTIATED_MTU);

    uint8_t client_three[4] = {10U, 76U, 0U, 3U};
    uint8_t uplink[IPV4_PACKET_LEN];
    make_ipv4_packet(uplink, client_three, OTHER_IPV4, 17U, 1U);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, 3U, uplink, sizeof(uplink)) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    uint8_t client_three_v6[16];
    memcpy(client_three_v6, CLIENT_IPV6, sizeof(client_three_v6));
    client_three_v6[15] = 3U;
    uint8_t icmp_v6[IPV6_PACKET_LEN];
    make_ipv6_packet(icmp_v6, SERVER_IPV6, OTHER_IPV6, 58U, 2U);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, icmp_v6, sizeof(icmp_v6)) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    uint8_t downlink_v6[IPV6_PACKET_LEN];
    make_ipv6_packet(downlink_v6, OTHER_IPV6, client_three_v6, 17U, 3U);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, 3U, downlink_v6, sizeof(downlink_v6)) ==
           VMP_MQVPN_EXIT_RESULT_NONE);

    advance_to_connected_at(&state, true, 3U,
                            (int32_t)NEGOTIATED_MTU);
    make_ipv6_packet(downlink_v6, OTHER_IPV6, CLIENT_IPV6, 17U, 4U);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, 3U, downlink_v6, sizeof(downlink_v6)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    evidence = client_evidence_at(false, 3U,
                                  (int32_t)NEGOTIATED_MTU);
    expect_client_rejected(&evidence, 2U, false);
    evidence = client_evidence_at(true, 3U,
                                  (int32_t)NEGOTIATED_MTU);
    evidence.assigned_ipv6[15] = 2U;
    expect_client_rejected(&evidence, 3U, true);
    evidence = client_evidence_at(true, 2U,
                                  (int32_t)NEGOTIATED_MTU);
    evidence.assigned_ipv4[3] = 3U;
    expect_client_rejected(&evidence, 3U, true);
    evidence = client_evidence_at(false, 1U,
                                  (int32_t)NEGOTIATED_MTU);
    expect_client_rejected(&evidence, 1U, false);
    evidence = client_evidence_at(false, 255U,
                                  (int32_t)NEGOTIATED_MTU);
    expect_client_rejected(&evidence, 255U, false);

    advance_to_connected_at(&state, true, 254U,
                            (int32_t)VMP_MQVPN_EXIT_PACKET_MTU);
    memset(&assignment, 0, sizeof(assignment));
    assert(vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(session_id == 254U);
    assert(assignment.tunnel.assigned_ipv4[3] == 254U);
    assert(assignment.tunnel.assigned_ipv6[15] == 254U);
}

static void test_fifo_order_short_buffer_and_ipv4_ownership(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t uplink[IPV4_PACKET_LEN];
    uint8_t icmp[IPV4_ICMP_PACKET_LEN];
    uint8_t downlink[IPV4_PACKET_LEN];
    make_ipv4_packet(uplink, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);
    make_ipv4_packet_sized(icmp, sizeof(icmp), SERVER_IPV4, OTHER_IPV4,
                           1U, 2U);
    make_ipv4_packet(downlink, OTHER_IPV4, CLIENT_IPV4, 17U, 3U);
    advance_to_connected(&state, false);

    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, uplink,
               sizeof(uplink)) == VMP_MQVPN_EXIT_RESULT_NONE);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, icmp, sizeof(icmp)) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    assert(state.queue_count == 2U);
    assert(state.queue_bytes == sizeof(uplink) + sizeof(icmp));
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, downlink,
               sizeof(downlink)) == VMP_MQVPN_EXIT_RESULT_NONE);

    uint8_t out[IPV4_ICMP_PACKET_LEN];
    memset(out, 0xa5, sizeof(out));
    size_t out_len = 99U;
    vmp_mqvpn_exit_packet_kind_t kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    uint32_t session_id = 99U;
    const size_t original_head = state.queue_head;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, NULL, 0U, &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_RESOURCE);
    assert(out_len == 0U && kind == VMP_MQVPN_EXIT_PACKET_NONE &&
           session_id == 0U);
    assert(state.queue_head == original_head && state.queue_count == 2U);

    out_len = 99U;
    kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(uplink) - 1U, &out_len, &kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_RESOURCE);
    assert(out_len == 0U);
    assert(kind == VMP_MQVPN_EXIT_PACKET_NONE);
    assert(session_id == 0U);
    assert(state.queue_head == original_head && state.queue_count == 2U);

    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    assert(out_len == sizeof(uplink));
    assert(kind == VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK);
    assert(session_id == VMP_MQVPN_EXIT_SESSION_ID);
    assert(memcmp(out, uplink, sizeof(uplink)) == 0);
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    assert(out_len == sizeof(icmp));
    assert(kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP);
    assert(memcmp(out, icmp, sizeof(icmp)) == 0);
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_EMPTY);
    assert(out_len == 0U && kind == VMP_MQVPN_EXIT_PACKET_NONE &&
           session_id == 0U);
}

static void test_ipv6_packet_ownership(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t uplink[IPV6_PACKET_LEN];
    uint8_t icmp[IPV6_PACKET_LEN];
    uint8_t downlink[IPV6_PACKET_LEN];
    make_ipv6_packet(uplink, CLIENT_IPV6, OTHER_IPV6, 17U, 1U);
    make_ipv6_packet(icmp, SERVER_IPV6, OTHER_IPV6, 58U, 2U);
    make_ipv6_packet(downlink, OTHER_IPV6, CLIENT_IPV6, 17U, 3U);
    advance_to_connected(&state, true);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, uplink,
               sizeof(uplink)) == VMP_MQVPN_EXIT_RESULT_NONE);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, icmp, sizeof(icmp)) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, downlink,
               sizeof(downlink)) == VMP_MQVPN_EXIT_RESULT_NONE);
}

static void test_dequeue_rejects_state_alias(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t packet[IPV4_PACKET_LEN];
    uint8_t out[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);
    memset(out, 0xa5, sizeof(out));
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);

    size_t out_len = 99U;
    vmp_mqvpn_exit_packet_kind_t kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    uint32_t session_id = 99U;
    uint8_t *const aliased_output =
        state.queue[state.queue_head].bytes;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, aliased_output, sizeof(packet), &out_len, &kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(out_len == 99U && kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP &&
           session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &state.queue_head, &kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    out_len = 99U;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &state.queue[1].kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(out_len == 99U && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    out_len = 99U;
    kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind,
               &state.server_prefix_v6) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(out_len == 99U && kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    union {
        size_t length;
        vmp_mqvpn_exit_packet_kind_t packet_kind;
    } shared_scalar;
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    shared_scalar.length = 99U;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &shared_scalar.length,
               &shared_scalar.packet_kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(shared_scalar.length == 99U && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    union {
        uint8_t bytes[IPV4_PACKET_LEN];
        size_t length_alignment;
        vmp_mqvpn_exit_packet_kind_t kind_alignment;
        uint32_t session_alignment;
    } shared_buffer;
    uint8_t expected_buffer[IPV4_PACKET_LEN];
    memset(expected_buffer, 0xa5, sizeof(expected_buffer));

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    memcpy(shared_buffer.bytes, expected_buffer, sizeof(shared_buffer.bytes));
    kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, shared_buffer.bytes, sizeof(shared_buffer.bytes),
               (size_t *)(void *)shared_buffer.bytes, &kind,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(memcmp(shared_buffer.bytes, expected_buffer,
                  sizeof(shared_buffer.bytes)) == 0);
    assert(kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    memcpy(shared_buffer.bytes, expected_buffer, sizeof(shared_buffer.bytes));
    out_len = 99U;
    session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, shared_buffer.bytes, sizeof(shared_buffer.bytes),
               &out_len,
               (vmp_mqvpn_exit_packet_kind_t *)(void *)shared_buffer.bytes,
               &session_id) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(memcmp(shared_buffer.bytes, expected_buffer,
                  sizeof(shared_buffer.bytes)) == 0);
    assert(out_len == 99U && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    memcpy(shared_buffer.bytes, expected_buffer, sizeof(shared_buffer.bytes));
    out_len = 99U;
    kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, shared_buffer.bytes, sizeof(shared_buffer.bytes),
               &out_len, &kind,
               (uint32_t *)(void *)shared_buffer.bytes) ==
           VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(memcmp(shared_buffer.bytes, expected_buffer,
                  sizeof(shared_buffer.bytes)) == 0);
    assert(out_len == 99U && kind == VMP_MQVPN_EXIT_PACKET_SERVER_ICMP);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);
}

static void test_snapshot_rejects_output_aliases(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    bool listening = true;
    bool connected = true;
    uint32_t session_id = 99U;
    vmp_mqvpn_exit_assignment_t assignment;
    vmp_mqvpn_exit_assignment_t expected_assignment;
    memset(&expected_assignment, 0xa5, sizeof(expected_assignment));

    advance_to_connected(&state, false);
    assignment = expected_assignment;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &state.assignment.assignment.has_ipv6, &connected,
        &session_id, &assignment));
    assert(connected && session_id == 99U &&
           memcmp(&assignment, &expected_assignment, sizeof(assignment)) ==
               0);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    listening = true;
    connected = true;
    assignment = expected_assignment;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &state.server_prefix_v6,
        &assignment));
    assert(listening && connected &&
           memcmp(&assignment, &expected_assignment, sizeof(assignment)) ==
               0);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    listening = true;
    connected = true;
    session_id = 99U;
    vmp_mqvpn_exit_assignment_t *const aliased_assignment =
        (vmp_mqvpn_exit_assignment_t *)(void *)&state.assignment.assignment;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, aliased_assignment));
    assert(listening && connected && session_id == 99U);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    listening = true;
    connected = true;
    assignment = expected_assignment;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &assignment.server_prefix_v6,
        &assignment));
    assert(listening && connected &&
           memcmp(&assignment, &expected_assignment, sizeof(assignment)) ==
               0);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    bool shared_boolean = true;
    session_id = 99U;
    assignment = expected_assignment;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &shared_boolean, &shared_boolean, &session_id, &assignment));
    assert(shared_boolean && session_id == 99U &&
           memcmp(&assignment, &expected_assignment, sizeof(assignment)) ==
               0);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);
}

static void expect_exact_mtu_packets_accepted(int32_t mtu)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t packet[VMP_MQVPN_EXIT_PACKET_MTU];
    uint8_t out[VMP_MQVPN_EXIT_PACKET_MTU];
    make_ipv4_packet_sized(packet, (size_t)mtu, CLIENT_IPV4,
                           OTHER_IPV4, 17U, 1U);
    advance_to_connected_at(&state, false,
                            (uint8_t)VMP_MQVPN_EXIT_SESSION_ID, mtu);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet, (size_t)mtu) ==
           VMP_MQVPN_EXIT_RESULT_NONE);

    size_t out_len = 0U;
    vmp_mqvpn_exit_packet_kind_t kind = VMP_MQVPN_EXIT_PACKET_NONE;
    uint32_t session_id = 0U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    assert(out_len == (size_t)mtu &&
           kind == VMP_MQVPN_EXIT_PACKET_CLIENT_UPLINK &&
           session_id == VMP_MQVPN_EXIT_SESSION_ID);
    assert(memcmp(out, packet, (size_t)mtu) == 0);

    make_ipv4_packet_sized(packet, (size_t)mtu, SERVER_IPV4,
                           OTHER_IPV4, 1U, 2U);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, packet, (size_t)mtu) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
    make_ipv4_packet_sized(packet, (size_t)mtu, OTHER_IPV4,
                           CLIENT_IPV4, 17U, 3U);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet, (size_t)mtu) ==
           VMP_MQVPN_EXIT_RESULT_NONE);
}

static void test_negotiated_mtu_bounds_every_packet_path(void)
{
    expect_exact_mtu_packets_accepted(
        (int32_t)VMP_MQVPN_EXIT_MIN_PACKET_MTU);
    expect_exact_mtu_packets_accepted((int32_t)NEGOTIATED_MTU);
    expect_exact_mtu_packets_accepted(
        (int32_t)VMP_MQVPN_EXIT_PACKET_MTU);

    const size_t oversized_len = (size_t)NEGOTIATED_MTU + 1U;
    uint8_t packet[VMP_MQVPN_EXIT_PACKET_MTU];
    vmp_mqvpn_exit_backend_state_t state;
    make_ipv4_packet_sized(packet, oversized_len, CLIENT_IPV4,
                           OTHER_IPV4, 17U, 1U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               oversized_len) == VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    make_ipv4_packet_sized(packet, oversized_len, SERVER_IPV4,
                           OTHER_IPV4, 1U, 2U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, packet, oversized_len) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    make_ipv4_packet_sized(packet, oversized_len, OTHER_IPV4,
                           CLIENT_IPV4, 17U, 3U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               oversized_len) == VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);
}

static void test_truncated_icmp_and_extension_headers_fail_closed(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t truncated_v4[IPV4_ICMP_PACKET_LEN - 1U];
    make_ipv4_packet_sized(truncated_v4, sizeof(truncated_v4),
                           SERVER_IPV4, OTHER_IPV4, 1U, 1U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, truncated_v4, sizeof(truncated_v4)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    uint8_t truncated_v4_options[31U];
    make_ipv4_packet_sized(truncated_v4_options,
                           sizeof(truncated_v4_options), SERVER_IPV4,
                           OTHER_IPV4, 1U, 2U);
    truncated_v4_options[0] = 0x46U;
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, truncated_v4_options,
               sizeof(truncated_v4_options)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    uint8_t truncated_v6[IPV6_PACKET_LEN - 1U];
    make_ipv6_packet_sized(truncated_v6, sizeof(truncated_v6),
                           SERVER_IPV6, OTHER_IPV6, 58U, 3U);
    advance_to_connected(&state, true);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, truncated_v6, sizeof(truncated_v6)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    uint8_t extension_v6[IPV6_PACKET_LEN];
    make_ipv6_packet(extension_v6, SERVER_IPV6, OTHER_IPV6, 0U, 4U);
    advance_to_connected(&state, true);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, extension_v6, sizeof(extension_v6)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);
}

static void expect_uplink_engine(uint32_t session_id,
                                 const uint8_t *packet,
                                 size_t packet_len)
{
    vmp_mqvpn_exit_backend_state_t state;
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, session_id, packet, packet_len) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

static void test_packet_rejections_fail_closed(void)
{
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);
    expect_uplink_engine(3U, packet, sizeof(packet));
    make_ipv4_packet(packet, OTHER_IPV4, CLIENT_IPV4, 17U, 2U);
    expect_uplink_engine(VMP_MQVPN_EXIT_SESSION_ID, packet,
                         sizeof(packet));

    vmp_mqvpn_exit_backend_state_t state;
    make_ipv4_packet(packet, CLIENT_IPV4, CLIENT_IPV4, 1U, 3U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    make_ipv4_packet(packet, SERVER_IPV4, CLIENT_IPV4, 17U, 5U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_server_icmp(
               &state, packet, sizeof(packet)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    make_ipv4_packet(packet, OTHER_IPV4, OTHER_IPV4, 17U, 6U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    make_ipv4_packet(packet, OTHER_IPV4, CLIENT_IPV4, 17U, 7U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, 3U, packet, sizeof(packet)) ==
           VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);

    packet[3] = (uint8_t)(sizeof(packet) - 1U);
    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_validate_downlink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_ENGINE);
    expect_wiped(&state);
}

static void test_overflow_is_sticky_and_atomic(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);
    advance_to_connected(&state, false);
    for (size_t index = 0U; index < VMP_MQVPN_EXIT_MAX_PACKETS;
         ++index) {
        packet[20] = (uint8_t)index;
        assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
                   &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
                   sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    }
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_OVERFLOW);
    assert(state.lifecycle == VMP_MQVPN_EXIT_TERMINAL);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_OVERFLOW);
    expect_wiped(&state);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_OVERFLOW);
    vmp_mqvpn_exit_backend_enter_terminal(
        &state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_OVERFLOW);
    vmp_mqvpn_exit_backend_enter_terminal(
        &state, VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_OVERFLOW);
}

static void test_corruption_is_invariant_before_arithmetic(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);

    advance_to_connected(&state, false);
    state.queue_head = SIZE_MAX;
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    state.queue_bytes = VMP_MQVPN_EXIT_MAX_BYTES;
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    state.queue[state.queue_head].bytes[12] = 11U;
    uint8_t out[IPV4_PACKET_LEN];
    size_t out_len = 99U;
    vmp_mqvpn_exit_packet_kind_t kind = VMP_MQVPN_EXIT_PACKET_SERVER_ICMP;
    uint32_t session_id = 99U;
    assert(vmp_mqvpn_exit_backend_dequeue(
               &state, out, sizeof(out), &out_len, &kind, &session_id) ==
           VMP_MQVPN_EXIT_RESULT_INVARIANT);
    assert(out_len == 0U && kind == VMP_MQVPN_EXIT_PACKET_NONE &&
           session_id == 0U);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    state.assignment.assignment.assigned_ipv4[3] = 3U;
    bool listening = true;
    bool connected = true;
    vmp_mqvpn_exit_assignment_t assignment;
    memset(&assignment, 0xa5, sizeof(assignment));
    session_id = 99U;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(!listening && !connected && session_id == 0U);
    assert(memory_is_zero(&assignment, sizeof(assignment)));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected_at(&state, true, 3U,
                            (int32_t)NEGOTIATED_MTU);
    state.session_id = 4U;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);

    advance_to_connected(&state, false);
    state.terminal = (vmp_mqvpn_exit_terminal_t)99;
    assert(!vmp_mqvpn_exit_backend_snapshot(
        &state, &listening, &connected, &session_id, &assignment));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_INVARIANT);
    expect_wiped(&state);
}

static void test_disconnect_and_teardown_never_rearm(void)
{
    vmp_mqvpn_exit_backend_state_t state;
    const vmp_mqvpn_exit_raw_tunnel_info_t pool = pool_evidence(false);
    const vmp_mqvpn_exit_raw_tunnel_info_t client = client_evidence(false);
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, CLIENT_IPV4, OTHER_IPV4, 17U, 1U);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_enqueue_client_uplink(
               &state, VMP_MQVPN_EXIT_SESSION_ID, packet,
               sizeof(packet)) == VMP_MQVPN_EXIT_RESULT_NONE);
    assert(vmp_mqvpn_exit_backend_observe_client_disconnected(
        &state, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state.lifecycle == VMP_MQVPN_EXIT_TERMINAL);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED);
    expect_wiped(&state);
    assert(!vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &pool));
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_DISCONNECTED);

    advance_to_connected(&state, false);
    assert(vmp_mqvpn_exit_backend_begin_destroy(&state));
    assert(state.lifecycle == VMP_MQVPN_EXIT_DESTROYING);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_NONE);
    expect_wiped(&state);
    assert(!vmp_mqvpn_exit_backend_observe_tunnel_ready(&state, &pool));
    assert(!vmp_mqvpn_exit_backend_observe_client_connected(
        &state, &client, VMP_MQVPN_EXIT_SESSION_ID));
    assert(!vmp_mqvpn_exit_backend_observe_client_disconnected(
        &state, VMP_MQVPN_EXIT_SESSION_ID));
    vmp_mqvpn_exit_backend_enter_terminal(
        &state, VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    assert(state.lifecycle == VMP_MQVPN_EXIT_DESTROYING);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    vmp_mqvpn_exit_backend_enter_terminal(
        &state, VMP_MQVPN_EXIT_TERMINAL_OVERFLOW);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
    assert(!vmp_mqvpn_exit_backend_begin_destroy(&state));

    advance_to_connected(&state, false);
    assert(!vmp_mqvpn_exit_backend_observe_client_disconnected(&state, 3U));
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    assert(vmp_mqvpn_exit_backend_begin_destroy(&state));
    assert(state.lifecycle == VMP_MQVPN_EXIT_DESTROYING);
    assert(state.terminal == VMP_MQVPN_EXIT_TERMINAL_ENGINE);
    expect_wiped(&state);
}

int main(void)
{
    test_synchronous_start_and_exact_normalization();
    test_pool_evidence_and_synchronous_callback_are_exact();
    test_connection_evidence_order_and_duplicates_fail_closed();
    test_dynamic_client_offset_is_correlated_and_retained();
    test_fifo_order_short_buffer_and_ipv4_ownership();
    test_ipv6_packet_ownership();
    test_dequeue_rejects_state_alias();
    test_snapshot_rejects_output_aliases();
    test_negotiated_mtu_bounds_every_packet_path();
    test_truncated_icmp_and_extension_headers_fail_closed();
    test_packet_rejections_fail_closed();
    test_overflow_is_sticky_and_atomic();
    test_corruption_is_invariant_before_arithmetic();
    test_disconnect_and_teardown_never_rearm();
    puts("mqvpn exit backend state tests passed");
    return 0;
}
