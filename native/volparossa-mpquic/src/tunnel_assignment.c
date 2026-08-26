// SPDX-License-Identifier: GPL-3.0-only

#include "tunnel_assignment.h"

#include <string.h>

#define VMP_IPV4_HEADER_MIN_LEN 20U
#define VMP_IPV6_HEADER_LEN 40U

static const uint8_t VMP_SERVER_IPV4[4] = {10U, 76U, 0U, 1U};
static const uint8_t VMP_IPV6_POOL_PREFIX[6] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x62U,
};

static bool bytes_are_zero(const uint8_t *bytes, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

static bool assigned_ipv4_is_valid(const uint8_t address[4])
{
    return address[0] == 10U && address[1] == 76U &&
           address[2] == 0U && address[3] >= 2U && address[3] <= 254U;
}

static bool assigned_ipv6_is_valid(const uint8_t address[16])
{
    return memcmp(address, VMP_IPV6_POOL_PREFIX,
                  sizeof(VMP_IPV6_POOL_PREFIX)) == 0 &&
           bytes_are_zero(&address[6], 9U) && address[15] >= 2U &&
           address[15] <= 254U;
}

static void copy_assignment(vmp_tunnel_assignment_t *destination,
                            const vmp_tunnel_assignment_t *source)
{
    vmp_tunnel_assignment_t copy;
    memset(&copy, 0, sizeof(copy));
    memcpy(copy.assigned_ipv4, source->assigned_ipv4,
           sizeof(copy.assigned_ipv4));
    copy.assigned_prefix_v4 = source->assigned_prefix_v4;
    memcpy(copy.server_ipv4, source->server_ipv4,
           sizeof(copy.server_ipv4));
    copy.server_prefix_v4 = source->server_prefix_v4;
    copy.mtu = source->mtu;
    copy.has_ipv6 = source->has_ipv6;
    memcpy(copy.assigned_ipv6, source->assigned_ipv6,
           sizeof(copy.assigned_ipv6));
    copy.assigned_prefix_v6 = source->assigned_prefix_v6;
    memcpy(destination, &copy, sizeof(*destination));
}

static bool assignments_are_equal(const vmp_tunnel_assignment_t *left,
                                  const vmp_tunnel_assignment_t *right)
{
    return memcmp(left->assigned_ipv4, right->assigned_ipv4,
                  sizeof(left->assigned_ipv4)) == 0 &&
           left->assigned_prefix_v4 == right->assigned_prefix_v4 &&
           memcmp(left->server_ipv4, right->server_ipv4,
                  sizeof(left->server_ipv4)) == 0 &&
           left->server_prefix_v4 == right->server_prefix_v4 &&
           left->mtu == right->mtu && left->has_ipv6 == right->has_ipv6 &&
           memcmp(left->assigned_ipv6, right->assigned_ipv6,
                  sizeof(left->assigned_ipv6)) == 0 &&
           left->assigned_prefix_v6 == right->assigned_prefix_v6;
}

static bool packet_address(const vmp_tunnel_assignment_state_t *state,
                           const uint8_t *packet, size_t packet_len,
                           bool source, const uint8_t **out_address,
                           size_t *out_address_len)
{
    if (state == NULL || state->phase != VMP_TUNNEL_ASSIGNMENT_ACTIVE ||
        packet == NULL || out_address == NULL || out_address_len == NULL ||
        packet_len == 0U || packet_len > (size_t)state->assignment.mtu) {
        return false;
    }

    const uint8_t version = (uint8_t)(packet[0] >> 4U);
    if (version == 4U) {
        if (packet_len < VMP_IPV4_HEADER_MIN_LEN) return false;
        const size_t header_len = (size_t)(packet[0] & 0x0fU) * 4U;
        const size_t total_len = ((size_t)packet[2] << 8U) |
                                 (size_t)packet[3];
        if (header_len < VMP_IPV4_HEADER_MIN_LEN || header_len > packet_len ||
            total_len != packet_len || total_len < header_len) {
            return false;
        }
        *out_address = &packet[source ? 12U : 16U];
        *out_address_len = 4U;
        return true;
    }

    if (version == 6U) {
        if (!state->assignment.has_ipv6 || packet_len < VMP_IPV6_HEADER_LEN) {
            return false;
        }
        const size_t payload_len = ((size_t)packet[4] << 8U) |
                                   (size_t)packet[5];
        if (payload_len == 0U ||
            payload_len != packet_len - VMP_IPV6_HEADER_LEN) {
            return false;
        }
        *out_address = &packet[source ? 8U : 24U];
        *out_address_len = 16U;
        return true;
    }

    return false;
}

static bool packet_address_is_owned(
    const vmp_tunnel_assignment_state_t *state, const uint8_t *packet,
    size_t packet_len, bool source)
{
    const uint8_t *address = NULL;
    size_t address_len = 0U;
    if (!packet_address(state, packet, packet_len, source, &address,
                        &address_len)) {
        return false;
    }
    if (address_len == 4U) {
        return memcmp(address, state->assignment.assigned_ipv4, 4U) == 0;
    }
    return address_len == 16U &&
           memcmp(address, state->assignment.assigned_ipv6, 16U) == 0;
}

void vmp_tunnel_assignment_state_init(vmp_tunnel_assignment_state_t *state)
{
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->phase = VMP_TUNNEL_ASSIGNMENT_EXPECTING;
}

bool vmp_tunnel_assignment_candidate_is_valid(
    const vmp_tunnel_assignment_t *candidate)
{
    if (candidate == NULL ||
        !assigned_ipv4_is_valid(candidate->assigned_ipv4) ||
        candidate->assigned_prefix_v4 != 32U ||
        memcmp(candidate->server_ipv4, VMP_SERVER_IPV4,
               sizeof(VMP_SERVER_IPV4)) != 0 ||
        candidate->server_prefix_v4 != 32U || candidate->mtu < 1280U ||
        candidate->mtu > 1420U) {
        return false;
    }
    if (!candidate->has_ipv6) {
        return candidate->assigned_prefix_v6 == 0U &&
               bytes_are_zero(candidate->assigned_ipv6,
                              sizeof(candidate->assigned_ipv6));
    }
    return candidate->assigned_prefix_v6 == 112U &&
           assigned_ipv6_is_valid(candidate->assigned_ipv6);
}

vmp_tunnel_assignment_accept_result_t vmp_tunnel_assignment_state_accept(
    vmp_tunnel_assignment_state_t *state,
    const vmp_tunnel_assignment_t *candidate)
{
    if (state == NULL ||
        !vmp_tunnel_assignment_candidate_is_valid(candidate)) {
        return VMP_TUNNEL_ASSIGNMENT_INVALID;
    }
    if (state->phase == VMP_TUNNEL_ASSIGNMENT_EXPECTING) {
        copy_assignment(&state->assignment, candidate);
        state->phase = VMP_TUNNEL_ASSIGNMENT_ACTIVE;
        return VMP_TUNNEL_ASSIGNMENT_ACCEPTED;
    }
    if (state->phase == VMP_TUNNEL_ASSIGNMENT_ACTIVE) {
        return assignments_are_equal(&state->assignment, candidate)
                   ? VMP_TUNNEL_ASSIGNMENT_DUPLICATE
                   : VMP_TUNNEL_ASSIGNMENT_CONFLICT;
    }
    return VMP_TUNNEL_ASSIGNMENT_WRONG_PHASE;
}

bool vmp_tunnel_assignment_state_snapshot(
    const vmp_tunnel_assignment_state_t *state,
    vmp_tunnel_assignment_t *out_assignment)
{
    if (out_assignment == NULL) return false;
    vmp_tunnel_assignment_t copy;
    memset(&copy, 0, sizeof(copy));
    const bool active = state != NULL &&
                        state->phase == VMP_TUNNEL_ASSIGNMENT_ACTIVE;
    if (active) copy_assignment(&copy, &state->assignment);
    memset(out_assignment, 0, sizeof(*out_assignment));
    if (active) copy_assignment(out_assignment, &copy);
    memset(&copy, 0, sizeof(copy));
    return active;
}

bool vmp_tunnel_assignment_packet_source_is_owned(
    const vmp_tunnel_assignment_state_t *state,
    const uint8_t *packet, size_t packet_len)
{
    return packet_address_is_owned(state, packet, packet_len, true);
}

bool vmp_tunnel_assignment_packet_destination_is_owned(
    const vmp_tunnel_assignment_state_t *state,
    const uint8_t *packet, size_t packet_len)
{
    return packet_address_is_owned(state, packet, packet_len, false);
}

void vmp_tunnel_assignment_state_wipe(vmp_tunnel_assignment_state_t *state)
{
    if (state == NULL) return;
    volatile uint8_t *bytes = (volatile uint8_t *)(void *)state;
    for (size_t index = 0U; index < sizeof(*state); ++index) {
        bytes[index] = 0U;
    }
}
