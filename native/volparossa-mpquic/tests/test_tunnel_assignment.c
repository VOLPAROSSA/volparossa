// SPDX-License-Identifier: GPL-3.0-only

#include "tunnel_assignment.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IPV4_PACKET_LEN 20U
#define IPV6_PACKET_LEN 48U

static const uint8_t ASSIGNED_IPV4[4] = {10U, 76U, 0U, 2U};
static const uint8_t OTHER_IPV4[4] = {10U, 76U, 0U, 3U};
static const uint8_t ASSIGNED_IPV6[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,    0U,    0U,    0U,    0U,    0U,    0U, 2U,
};
static const uint8_t OTHER_IPV6[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U, 0U, 0U,
    0U,    0U,    0U,    0U,    0U,    0U,    0U, 3U,
};

static vmp_tunnel_assignment_t valid_assignment(bool has_ipv6)
{
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    memcpy(assignment.assigned_ipv4, ASSIGNED_IPV4,
           sizeof(assignment.assigned_ipv4));
    assignment.assigned_prefix_v4 = 32U;
    assignment.server_ipv4[0] = 10U;
    assignment.server_ipv4[1] = 76U;
    assignment.server_ipv4[3] = 1U;
    assignment.server_prefix_v4 = 32U;
    assignment.mtu = 1280U;
    assignment.has_ipv6 = has_ipv6;
    if (has_ipv6) {
        memcpy(assignment.assigned_ipv6, ASSIGNED_IPV6,
               sizeof(assignment.assigned_ipv6));
        assignment.assigned_prefix_v6 = 112U;
    }
    return assignment;
}

static void make_ipv4_packet(uint8_t packet[IPV4_PACKET_LEN],
                             const uint8_t source[4],
                             const uint8_t destination[4])
{
    memset(packet, 0, IPV4_PACKET_LEN);
    packet[0] = 0x45U;
    packet[2] = 0U;
    packet[3] = IPV4_PACKET_LEN;
    packet[8] = 64U;
    packet[9] = 17U;
    memcpy(&packet[12], source, 4U);
    memcpy(&packet[16], destination, 4U);
}

static void make_ipv6_packet(uint8_t packet[IPV6_PACKET_LEN],
                             const uint8_t source[16],
                             const uint8_t destination[16])
{
    memset(packet, 0, IPV6_PACKET_LEN);
    packet[0] = 0x60U;
    packet[5] = IPV6_PACKET_LEN - 40U;
    packet[6] = 17U;
    packet[7] = 64U;
    memcpy(&packet[8], source, 16U);
    memcpy(&packet[24], destination, 16U);
}

static vmp_tunnel_assignment_state_t active_state(bool has_ipv6)
{
    vmp_tunnel_assignment_state_t state;
    vmp_tunnel_assignment_t assignment = valid_assignment(has_ipv6);
    vmp_tunnel_assignment_state_init(&state);
    assert(vmp_tunnel_assignment_state_accept(&state, &assignment) ==
           VMP_TUNNEL_ASSIGNMENT_ACCEPTED);
    return state;
}

static void test_candidate_policy_boundaries(void)
{
    vmp_tunnel_assignment_t assignment = valid_assignment(false);
    assert(vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.assigned_ipv4[3] = 254U;
    assignment.mtu = 1420U;
    assert(vmp_tunnel_assignment_candidate_is_valid(&assignment));

    assignment.assigned_ipv4[3] = 1U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.assigned_ipv4[3] = 255U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.assigned_ipv4[2] = 1U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.assigned_prefix_v4 = 31U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.server_ipv4[3] = 2U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.server_prefix_v4 = 31U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.mtu = 1279U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.mtu = 1421U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));

    assignment = valid_assignment(false);
    assignment.assigned_prefix_v6 = 112U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(false);
    assignment.assigned_ipv6[15] = 2U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));

    assignment = valid_assignment(true);
    assert(vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.assigned_ipv6[15] = 254U;
    assert(vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.assigned_ipv6[15] = 1U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment.assigned_ipv6[15] = 255U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(true);
    assignment.assigned_ipv6[5] = 0x63U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(true);
    assignment.assigned_ipv6[14] = 1U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assignment = valid_assignment(true);
    assignment.assigned_prefix_v6 = 111U;
    assert(!vmp_tunnel_assignment_candidate_is_valid(&assignment));
    assert(!vmp_tunnel_assignment_candidate_is_valid(NULL));
}

static void test_state_copy_duplicate_conflict_and_wipe(void)
{
    vmp_tunnel_assignment_state_t state;
    vmp_tunnel_assignment_t candidate = valid_assignment(true);
    vmp_tunnel_assignment_t original = candidate;
    vmp_tunnel_assignment_t snapshot;
    memset(&snapshot, 0xa5, sizeof(snapshot));

    vmp_tunnel_assignment_state_init(&state);
    assert(state.phase == VMP_TUNNEL_ASSIGNMENT_EXPECTING);
    assert(!vmp_tunnel_assignment_state_snapshot(&state, &snapshot));
    const uint8_t *snapshot_bytes =
        (const uint8_t *)(const void *)&snapshot;
    for (size_t index = 0U; index < sizeof(snapshot); ++index) {
        assert(snapshot_bytes[index] == 0U);
    }
    assert(vmp_tunnel_assignment_state_accept(&state, &candidate) ==
           VMP_TUNNEL_ASSIGNMENT_ACCEPTED);
    assert(state.phase == VMP_TUNNEL_ASSIGNMENT_ACTIVE);

    candidate.assigned_ipv4[3] = 99U;
    candidate.assigned_ipv6[15] = 99U;
    candidate.mtu = 1400U;
    assert(vmp_tunnel_assignment_state_snapshot(&state, &snapshot));
    assert(memcmp(snapshot.assigned_ipv4, original.assigned_ipv4, 4U) == 0);
    assert(memcmp(snapshot.assigned_ipv6, original.assigned_ipv6, 16U) == 0);
    assert(snapshot.mtu == original.mtu);
    assert(vmp_tunnel_assignment_state_snapshot(&state, &state.assignment));
    assert(state.assignment.mtu == original.mtu);
    assert(vmp_tunnel_assignment_state_accept(&state, &original) ==
           VMP_TUNNEL_ASSIGNMENT_DUPLICATE);

    original.mtu = 1281U;
    assert(vmp_tunnel_assignment_state_accept(&state, &original) ==
           VMP_TUNNEL_ASSIGNMENT_CONFLICT);
    original.mtu = 1279U;
    assert(vmp_tunnel_assignment_state_accept(&state, &original) ==
           VMP_TUNNEL_ASSIGNMENT_INVALID);
    assert(vmp_tunnel_assignment_state_accept(NULL, &original) ==
           VMP_TUNNEL_ASSIGNMENT_INVALID);
    assert(vmp_tunnel_assignment_state_accept(&state, NULL) ==
           VMP_TUNNEL_ASSIGNMENT_INVALID);
    assert(!vmp_tunnel_assignment_state_snapshot(NULL, &snapshot));
    assert(!vmp_tunnel_assignment_state_snapshot(&state, NULL));

    vmp_tunnel_assignment_state_wipe(&state);
    const uint8_t *state_bytes = (const uint8_t *)(const void *)&state;
    for (size_t index = 0U; index < sizeof(state); ++index) {
        assert(state_bytes[index] == 0U);
    }
    original = valid_assignment(false);
    assert(vmp_tunnel_assignment_state_accept(&state, &original) ==
           VMP_TUNNEL_ASSIGNMENT_WRONG_PHASE);
    assert(!vmp_tunnel_assignment_state_snapshot(&state, &snapshot));

    vmp_tunnel_assignment_state_init(NULL);
    vmp_tunnel_assignment_state_wipe(NULL);
}

static void test_ipv4_packet_ownership_and_structure(void)
{
    vmp_tunnel_assignment_state_t state = active_state(false);
    uint8_t packet[IPV4_PACKET_LEN];
    make_ipv4_packet(packet, ASSIGNED_IPV4, OTHER_IPV4);
    assert(vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));

    make_ipv4_packet(packet, OTHER_IPV4, ASSIGNED_IPV4);
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    assert(vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));

    packet[0] = 0x44U;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    packet[0] = 0x46U;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    make_ipv4_packet(packet, ASSIGNED_IPV4, OTHER_IPV4);
    packet[3] = IPV4_PACKET_LEN - 1U;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    packet[3] = IPV4_PACKET_LEN;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, IPV4_PACKET_LEN - 1U));
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, NULL, sizeof(packet)));
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        NULL, packet, sizeof(packet)));

    vmp_tunnel_assignment_state_wipe(&state);
    make_ipv4_packet(packet, ASSIGNED_IPV4, OTHER_IPV4);
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
}

static void test_ipv6_packet_ownership_and_structure(void)
{
    vmp_tunnel_assignment_state_t state = active_state(true);
    uint8_t packet[IPV6_PACKET_LEN];
    make_ipv6_packet(packet, ASSIGNED_IPV6, OTHER_IPV6);
    assert(vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));

    make_ipv6_packet(packet, OTHER_IPV6, ASSIGNED_IPV6);
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, sizeof(packet)));
    assert(vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));

    packet[0] = 0x70U;
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));
    make_ipv6_packet(packet, OTHER_IPV6, ASSIGNED_IPV6);
    packet[5] = 1U;
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, sizeof(packet)));
    packet[5] = IPV6_PACKET_LEN - 40U;
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, IPV6_PACKET_LEN - 1U));
    packet[5] = 0U;
    assert(!vmp_tunnel_assignment_packet_destination_is_owned(
        &state, packet, 40U));

    vmp_tunnel_assignment_state_t ipv4_only = active_state(false);
    make_ipv6_packet(packet, ASSIGNED_IPV6, OTHER_IPV6);
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &ipv4_only, packet, sizeof(packet)));
}

static void test_packet_mtu_is_enforced(void)
{
    vmp_tunnel_assignment_state_t state = active_state(false);
    uint8_t packet[1421];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45U;
    packet[2] = 5U;
    packet[3] = 0U;
    memcpy(&packet[12], ASSIGNED_IPV4, 4U);
    memcpy(&packet[16], OTHER_IPV4, 4U);
    assert(vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, 1280U));

    packet[2] = 5U;
    packet[3] = 1U;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, 1281U));

    vmp_tunnel_assignment_t assignment = valid_assignment(false);
    assignment.mtu = 1420U;
    vmp_tunnel_assignment_state_init(&state);
    assert(vmp_tunnel_assignment_state_accept(&state, &assignment) ==
           VMP_TUNNEL_ASSIGNMENT_ACCEPTED);
    packet[2] = 5U;
    packet[3] = 140U;
    assert(vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, 1420U));
    packet[3] = 141U;
    assert(!vmp_tunnel_assignment_packet_source_is_owned(
        &state, packet, 1421U));
}

int main(void)
{
    test_candidate_policy_boundaries();
    test_state_copy_duplicate_conflict_and_wipe();
    test_ipv4_packet_ownership_and_structure();
    test_ipv6_packet_ownership_and_structure();
    test_packet_mtu_is_enforced();
    puts("tunnel assignment tests passed");
    return 0;
}
