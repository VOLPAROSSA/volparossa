// SPDX-License-Identifier: GPL-3.0-only

#include "mqvpn_backend_state.h"

#include <string.h>

_Static_assert(
    sizeof(((vmp_mqvpn_backend_state_t *)0)->reverse_queue) <=
        VMP_MQVPN_REVERSE_MAX_BYTES,
    "reverse FIFO storage exceeds its hard byte bound");

static bool phase_is_valid(vmp_mqvpn_observed_phase_t phase)
{
    switch (phase) {
    case VMP_MQVPN_PHASE_IDLE:
    case VMP_MQVPN_PHASE_CONNECTING:
    case VMP_MQVPN_PHASE_AUTHENTICATING:
    case VMP_MQVPN_PHASE_TUNNEL_READY:
    case VMP_MQVPN_PHASE_ESTABLISHED:
    case VMP_MQVPN_PHASE_RECONNECTING:
    case VMP_MQVPN_PHASE_CLOSED:
        return true;
    default:
        return false;
    }
}

static bool pre_assignment_transition_is_valid(
    vmp_mqvpn_observed_phase_t current,
    vmp_mqvpn_observed_phase_t next)
{
    switch (current) {
    case VMP_MQVPN_PHASE_IDLE:
        return next == VMP_MQVPN_PHASE_CONNECTING;
    case VMP_MQVPN_PHASE_CONNECTING:
        return next == VMP_MQVPN_PHASE_AUTHENTICATING;
    case VMP_MQVPN_PHASE_AUTHENTICATING:
        return next == VMP_MQVPN_PHASE_TUNNEL_READY;
    case VMP_MQVPN_PHASE_TUNNEL_READY:
    case VMP_MQVPN_PHASE_ESTABLISHED:
    case VMP_MQVPN_PHASE_RECONNECTING:
    case VMP_MQVPN_PHASE_CLOSED:
    default:
        return false;
    }
}

static void secure_zero(void *memory, size_t length)
{
    volatile uint8_t *bytes = memory;
    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}

static void wipe_reverse_fifo(vmp_mqvpn_backend_state_t *state)
{
    secure_zero(state->reverse_queue, sizeof(state->reverse_queue));
    state->reverse_head = 0U;
    state->reverse_tail = 0U;
    state->reverse_count = 0U;
    state->reverse_bytes = 0U;
}

static vmp_mqvpn_backend_result_t terminal_result(
    const vmp_mqvpn_backend_state_t *state)
{
    return state != NULL &&
                   state->terminal == VMP_MQVPN_TERMINAL_OVERFLOW
               ? VMP_MQVPN_RESULT_OVERFLOW
               : VMP_MQVPN_RESULT_ENGINE;
}

static bool reverse_fifo_metadata_is_bounded(
    const vmp_mqvpn_backend_state_t *state)
{
    return state->reverse_head < VMP_MQVPN_REVERSE_MAX_PACKETS &&
           state->reverse_tail < VMP_MQVPN_REVERSE_MAX_PACKETS &&
           state->reverse_count <= VMP_MQVPN_REVERSE_MAX_PACKETS &&
           state->reverse_bytes <= VMP_MQVPN_REVERSE_MAX_BYTES &&
           state->reverse_tail ==
               (state->reverse_head + state->reverse_count) %
                   VMP_MQVPN_REVERSE_MAX_PACKETS &&
           (state->reverse_count != 0U || state->reverse_bytes == 0U);
}

static bool reverse_fifo_is_empty(
    const vmp_mqvpn_backend_state_t *state)
{
    if (state->reverse_head != 0U || state->reverse_tail != 0U ||
        state->reverse_count != 0U || state->reverse_bytes != 0U) {
        return false;
    }
    for (size_t index = 0U; index < VMP_MQVPN_REVERSE_MAX_PACKETS;
         ++index) {
        if (state->reverse_queue[index].len != 0U) return false;
    }
    return true;
}

static bool reverse_fifo_is_valid(
    const vmp_mqvpn_backend_state_t *state)
{
    if (!reverse_fifo_metadata_is_bounded(state) ||
        state->assignment.phase != VMP_TUNNEL_ASSIGNMENT_ACTIVE ||
        !vmp_tunnel_assignment_candidate_is_valid(
            &state->assignment.assignment)) {
        return false;
    }

    bool occupied[VMP_MQVPN_REVERSE_MAX_PACKETS];
    memset(occupied, 0, sizeof(occupied));
    size_t byte_sum = 0U;
    for (size_t offset = 0U; offset < state->reverse_count; ++offset) {
        const size_t index =
            (state->reverse_head + offset) %
            VMP_MQVPN_REVERSE_MAX_PACKETS;
        const vmp_mqvpn_reverse_packet_t *entry =
            &state->reverse_queue[index];
        if (entry->len == 0U ||
            entry->len > VMP_MQVPN_REVERSE_PACKET_BYTES ||
            entry->len > VMP_MQVPN_REVERSE_MAX_BYTES - byte_sum ||
            !vmp_tunnel_assignment_packet_destination_is_owned(
                &state->assignment, entry->bytes, entry->len)) {
            return false;
        }
        occupied[index] = true;
        byte_sum += entry->len;
    }
    if (byte_sum != state->reverse_bytes) return false;
    for (size_t index = 0U; index < VMP_MQVPN_REVERSE_MAX_PACKETS;
         ++index) {
        if (!occupied[index] && state->reverse_queue[index].len != 0U) {
            return false;
        }
    }
    return true;
}

static bool path_state_is_valid(vmp_mqvpn_path_state_t state)
{
    switch (state) {
    case VMP_MQVPN_PATH_PENDING:
    case VMP_MQVPN_PATH_ACTIVE:
    case VMP_MQVPN_PATH_DEGRADED:
    case VMP_MQVPN_PATH_CLOSED:
        return true;
    default:
        return false;
    }
}

static void copy_path_record(vmp_mqvpn_path_record_t *destination,
                             const vmp_mqvpn_path_record_t *source)
{
    memset(destination, 0, sizeof(*destination));
    destination->handle = source->handle;
    destination->state = source->state;
    destination->metrics_valid = source->metrics_valid;
    destination->smoothed_rtt_us = source->smoothed_rtt_us;
    destination->packets_lost = source->packets_lost;
    destination->congestion_window_bytes =
        source->congestion_window_bytes;
    destination->bytes_in_flight = source->bytes_in_flight;
    destination->estimated_rate_bytes_per_sec =
        source->estimated_rate_bytes_per_sec;
    destination->acked_transport_bytes = source->acked_transport_bytes;
}

static void clear_path_output(vmp_mqvpn_path_record_t *out,
                              size_t capacity, size_t *out_count)
{
    if (out_count != NULL) *out_count = 0U;
    if (out != NULL && capacity <= VMP_MQVPN_BACKEND_MAX_PATHS) {
        memset(out, 0, capacity * sizeof(*out));
    }
}

void vmp_mqvpn_backend_state_init(vmp_mqvpn_backend_state_t *state)
{
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->lifecycle = VMP_MQVPN_BACKEND_EXPECTING;
    state->observed_phase = VMP_MQVPN_PHASE_IDLE;
    state->terminal = VMP_MQVPN_TERMINAL_NONE;
    vmp_tunnel_assignment_state_init(&state->assignment);
}

void vmp_mqvpn_backend_state_enter_terminal(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_backend_terminal_t reason)
{
    if (state == NULL || reason == VMP_MQVPN_TERMINAL_NONE) return;
    if (reason != VMP_MQVPN_TERMINAL_ENGINE &&
        reason != VMP_MQVPN_TERMINAL_OVERFLOW) {
        reason = VMP_MQVPN_TERMINAL_ENGINE;
    }
    if (state->terminal == VMP_MQVPN_TERMINAL_NONE) {
        state->terminal = reason;
    }
    state->lifecycle = VMP_MQVPN_BACKEND_TERMINAL;
    vmp_tunnel_assignment_state_wipe(&state->assignment);
    wipe_reverse_fifo(state);
}

bool vmp_mqvpn_backend_state_observe_transition(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t old_phase,
    vmp_mqvpn_observed_phase_t new_phase)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) return false;
    if (!phase_is_valid(old_phase) || !phase_is_valid(new_phase) ||
        old_phase != state->observed_phase ||
        new_phase == VMP_MQVPN_PHASE_RECONNECTING ||
        new_phase == VMP_MQVPN_PHASE_CLOSED) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return false;
    }

    bool accepted = false;
    switch (state->lifecycle) {
    case VMP_MQVPN_BACKEND_EXPECTING:
        accepted = pre_assignment_transition_is_valid(
            old_phase, new_phase);
        break;
    case VMP_MQVPN_BACKEND_ACTIVATING:
    case VMP_MQVPN_BACKEND_ACTIVE:
        accepted = state->lifecycle == VMP_MQVPN_BACKEND_ACTIVATING &&
                   old_phase == VMP_MQVPN_PHASE_TUNNEL_READY &&
                   new_phase == VMP_MQVPN_PHASE_ESTABLISHED;
        break;
    case VMP_MQVPN_BACKEND_TERMINAL:
    default:
        accepted = false;
        break;
    }
    if (!accepted) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return false;
    }
    state->observed_phase = new_phase;
    return true;
}

bool vmp_mqvpn_backend_state_sample_phase(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t phase)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) return false;
    const bool phase_matches =
        phase_is_valid(phase) && phase == state->observed_phase &&
        phase != VMP_MQVPN_PHASE_RECONNECTING &&
        phase != VMP_MQVPN_PHASE_CLOSED;
    bool lifecycle_matches = false;
    switch (state->lifecycle) {
    case VMP_MQVPN_BACKEND_EXPECTING:
        lifecycle_matches = phase <= VMP_MQVPN_PHASE_TUNNEL_READY;
        break;
    case VMP_MQVPN_BACKEND_ACTIVATING:
        lifecycle_matches = phase == VMP_MQVPN_PHASE_TUNNEL_READY ||
                            phase == VMP_MQVPN_PHASE_ESTABLISHED;
        break;
    case VMP_MQVPN_BACKEND_ACTIVE:
        lifecycle_matches = phase == VMP_MQVPN_PHASE_ESTABLISHED;
        break;
    case VMP_MQVPN_BACKEND_TERMINAL:
    default:
        lifecycle_matches = false;
        break;
    }
    if (!phase_matches || !lifecycle_matches) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return false;
    }
    return true;
}

vmp_mqvpn_assignment_action_t vmp_mqvpn_backend_state_offer_assignment(
    vmp_mqvpn_backend_state_t *state,
    vmp_mqvpn_observed_phase_t observed_phase,
    const vmp_tunnel_assignment_t *candidate)
{
    if (state == NULL) return VMP_MQVPN_ASSIGNMENT_TERMINAL;
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) {
        return VMP_MQVPN_ASSIGNMENT_TERMINAL;
    }

    const bool first_offer =
        state->lifecycle == VMP_MQVPN_BACKEND_EXPECTING &&
        state->observed_phase == VMP_MQVPN_PHASE_TUNNEL_READY &&
        observed_phase == VMP_MQVPN_PHASE_TUNNEL_READY &&
        reverse_fifo_is_empty(state);
    const bool duplicate_offer =
        state->lifecycle == VMP_MQVPN_BACKEND_ACTIVE &&
        state->observed_phase == VMP_MQVPN_PHASE_ESTABLISHED &&
        observed_phase == VMP_MQVPN_PHASE_ESTABLISHED &&
        reverse_fifo_is_valid(state);
    if (!first_offer && !duplicate_offer) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_MQVPN_ASSIGNMENT_TERMINAL;
    }

    const vmp_tunnel_assignment_accept_result_t accepted =
        vmp_tunnel_assignment_state_accept(&state->assignment,
                                           candidate);
    if (first_offer && accepted == VMP_TUNNEL_ASSIGNMENT_ACCEPTED) {
        state->lifecycle = VMP_MQVPN_BACKEND_ACTIVATING;
        return VMP_MQVPN_ASSIGNMENT_ACTIVATE;
    }
    if (duplicate_offer &&
        accepted == VMP_TUNNEL_ASSIGNMENT_DUPLICATE) {
        return VMP_MQVPN_ASSIGNMENT_DUPLICATE;
    }

    vmp_mqvpn_backend_state_enter_terminal(
        state, VMP_MQVPN_TERMINAL_ENGINE);
    return VMP_MQVPN_ASSIGNMENT_TERMINAL;
}

bool vmp_mqvpn_backend_state_finish_activation(
    vmp_mqvpn_backend_state_t *state, bool activation_call_succeeded,
    vmp_mqvpn_observed_phase_t post_call_phase)
{
    if (state == NULL) return false;
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) return false;
    if (state->lifecycle != VMP_MQVPN_BACKEND_ACTIVATING ||
        !activation_call_succeeded ||
        !phase_is_valid(post_call_phase) ||
        post_call_phase != VMP_MQVPN_PHASE_ESTABLISHED ||
        state->observed_phase != VMP_MQVPN_PHASE_ESTABLISHED ||
        !reverse_fifo_is_empty(state) ||
        state->assignment.phase != VMP_TUNNEL_ASSIGNMENT_ACTIVE ||
        !vmp_tunnel_assignment_candidate_is_valid(
            &state->assignment.assignment)) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return false;
    }
    state->lifecycle = VMP_MQVPN_BACKEND_ACTIVE;
    return true;
}

bool vmp_mqvpn_backend_state_snapshot(
    vmp_mqvpn_backend_state_t *state, bool *out_tunnel_ready,
    bool *out_has_assignment,
    vmp_tunnel_assignment_t *out_assignment)
{
    if (out_tunnel_ready != NULL) *out_tunnel_ready = false;
    if (out_has_assignment != NULL) *out_has_assignment = false;
    if (out_assignment != NULL) {
        memset(out_assignment, 0, sizeof(*out_assignment));
    }
    if (out_tunnel_ready == NULL || out_has_assignment == NULL ||
        out_assignment == NULL) {
        return false;
    }
    if (state == NULL || state->terminal != VMP_MQVPN_TERMINAL_NONE) {
        return false;
    }

    switch (state->lifecycle) {
    case VMP_MQVPN_BACKEND_EXPECTING:
        if (state->assignment.phase ==
                VMP_TUNNEL_ASSIGNMENT_EXPECTING &&
            phase_is_valid(state->observed_phase) &&
            state->observed_phase <= VMP_MQVPN_PHASE_TUNNEL_READY &&
            reverse_fifo_is_empty(state)) {
            return true;
        }
        break;
    case VMP_MQVPN_BACKEND_ACTIVATING:
        if (state->assignment.phase == VMP_TUNNEL_ASSIGNMENT_ACTIVE &&
            vmp_tunnel_assignment_candidate_is_valid(
                &state->assignment.assignment) &&
            (state->observed_phase ==
                 VMP_MQVPN_PHASE_TUNNEL_READY ||
             state->observed_phase ==
                 VMP_MQVPN_PHASE_ESTABLISHED) &&
            reverse_fifo_is_empty(state)) {
            return true;
        }
        break;
    case VMP_MQVPN_BACKEND_ACTIVE:
        if (state->observed_phase == VMP_MQVPN_PHASE_ESTABLISHED &&
            vmp_tunnel_assignment_state_snapshot(
                &state->assignment, out_assignment) &&
            vmp_tunnel_assignment_candidate_is_valid(out_assignment) &&
            reverse_fifo_is_valid(state)) {
            *out_has_assignment = true;
            *out_tunnel_ready = true;
            return true;
        }
        memset(out_assignment, 0, sizeof(*out_assignment));
        break;
    case VMP_MQVPN_BACKEND_TERMINAL:
    default:
        break;
    }
    vmp_mqvpn_backend_state_enter_terminal(
        state, VMP_MQVPN_TERMINAL_ENGINE);
    return false;
}

vmp_mqvpn_backend_result_t vmp_mqvpn_backend_state_enqueue_reverse(
    vmp_mqvpn_backend_state_t *state, const uint8_t *packet,
    size_t packet_len)
{
    if (state == NULL) return VMP_MQVPN_RESULT_ENGINE;
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) {
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_BACKEND_ACTIVE ||
        state->observed_phase != VMP_MQVPN_PHASE_ESTABLISHED ||
        state->terminal != VMP_MQVPN_TERMINAL_NONE || packet == NULL ||
        packet_len == 0U ||
        packet_len > VMP_MQVPN_REVERSE_PACKET_BYTES ||
        !vmp_tunnel_assignment_packet_destination_is_owned(
            &state->assignment, packet, packet_len) ||
        !reverse_fifo_metadata_is_bounded(state)) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_MQVPN_RESULT_ENGINE;
    }
    if (!reverse_fifo_is_valid(state)) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_MQVPN_RESULT_ENGINE;
    }
    if (state->reverse_count == VMP_MQVPN_REVERSE_MAX_PACKETS ||
        packet_len >
            VMP_MQVPN_REVERSE_MAX_BYTES - state->reverse_bytes) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_OVERFLOW);
        return VMP_MQVPN_RESULT_OVERFLOW;
    }

    vmp_mqvpn_reverse_packet_t *entry =
        &state->reverse_queue[state->reverse_tail];
    secure_zero(entry, sizeof(*entry));
    memcpy(entry->bytes, packet, packet_len);
    entry->len = packet_len;
    state->reverse_tail =
        (state->reverse_tail + 1U) % VMP_MQVPN_REVERSE_MAX_PACKETS;
    ++state->reverse_count;
    state->reverse_bytes += packet_len;
    return VMP_MQVPN_RESULT_NONE;
}

vmp_mqvpn_backend_result_t vmp_mqvpn_backend_state_dequeue_reverse(
    vmp_mqvpn_backend_state_t *state, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0U;
    if (state == NULL || out_len == NULL) {
        if (state != NULL) {
            vmp_mqvpn_backend_state_enter_terminal(
                state, VMP_MQVPN_TERMINAL_ENGINE);
        }
        return VMP_MQVPN_RESULT_ENGINE;
    }
    if (state->lifecycle == VMP_MQVPN_BACKEND_TERMINAL) {
        return terminal_result(state);
    }
    if (state->lifecycle != VMP_MQVPN_BACKEND_ACTIVE ||
        state->observed_phase != VMP_MQVPN_PHASE_ESTABLISHED ||
        state->terminal != VMP_MQVPN_TERMINAL_NONE ||
        !reverse_fifo_is_valid(state)) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_MQVPN_RESULT_ENGINE;
    }
    if (state->reverse_count == 0U) return VMP_MQVPN_RESULT_EMPTY;

    vmp_mqvpn_reverse_packet_t *entry =
        &state->reverse_queue[state->reverse_head];
    if (out == NULL) {
        vmp_mqvpn_backend_state_enter_terminal(
            state, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_MQVPN_RESULT_ENGINE;
    }
    if (out_capacity < entry->len) {
        return VMP_MQVPN_RESULT_RESOURCE;
    }
    const size_t packet_len = entry->len;
    memcpy(out, entry->bytes, packet_len);
    secure_zero(entry, sizeof(*entry));
    state->reverse_head =
        (state->reverse_head + 1U) % VMP_MQVPN_REVERSE_MAX_PACKETS;
    --state->reverse_count;
    state->reverse_bytes -= packet_len;
    *out_len = packet_len;
    return VMP_MQVPN_RESULT_NONE;
}

bool vmp_mqvpn_backend_project_paths(
    const int64_t *expected_handles, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count,
    vmp_mqvpn_path_record_t *out, size_t out_capacity,
    size_t *out_count)
{
    vmp_mqvpn_path_record_t projected[VMP_MQVPN_BACKEND_MAX_PATHS];
    int64_t expected[VMP_MQVPN_BACKEND_MAX_PATHS];
    memset(projected, 0, sizeof(projected));
    memset(expected, 0, sizeof(expected));

    if (out_count == NULL || expected_count > VMP_MQVPN_BACKEND_MAX_PATHS ||
        observed_count > VMP_MQVPN_BACKEND_MAX_PATHS ||
        out_capacity > VMP_MQVPN_BACKEND_MAX_PATHS ||
        expected_count != observed_count || out_capacity < expected_count ||
        (expected_count > 0U && expected_handles == NULL) ||
        (observed_count > 0U && observed == NULL) ||
        (out_capacity > 0U && out == NULL)) {
        clear_path_output(out, out_capacity, out_count);
        return false;
    }
    *out_count = 0U;

    for (size_t index = 0U; index < expected_count; ++index) {
        expected[index] = expected_handles[index];
        if (expected[index] < 0) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        for (size_t earlier = 0U; earlier < index; ++earlier) {
            if (expected[earlier] == expected[index]) {
                clear_path_output(out, out_capacity, out_count);
                return false;
            }
        }
    }

    for (size_t index = 0U; index < observed_count; ++index) {
        if (observed[index].handle < 0 ||
            !path_state_is_valid(observed[index].state)) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        for (size_t earlier = 0U; earlier < index; ++earlier) {
            if (observed[earlier].handle == observed[index].handle) {
                clear_path_output(out, out_capacity, out_count);
                return false;
            }
        }
    }

    for (size_t expected_index = 0U; expected_index < expected_count;
         ++expected_index) {
        const vmp_mqvpn_path_record_t *match = NULL;
        for (size_t observed_index = 0U;
             observed_index < observed_count; ++observed_index) {
            if (observed[observed_index].handle ==
                expected[expected_index]) {
                match = &observed[observed_index];
                break;
            }
        }
        if (match == NULL) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        copy_path_record(&projected[expected_index], match);
    }

    clear_path_output(out, out_capacity, out_count);
    for (size_t index = 0U; index < expected_count; ++index) {
        copy_path_record(&out[index], &projected[index]);
    }
    *out_count = expected_count;
    return true;
}

bool vmp_mqvpn_backend_select_current_paths(
    const int64_t *expected_handles, size_t expected_count,
    const vmp_mqvpn_path_record_t *observed, size_t observed_count,
    vmp_mqvpn_path_record_t *out, size_t out_capacity,
    size_t *out_count)
{
    vmp_mqvpn_path_record_t current[VMP_MQVPN_BACKEND_MAX_PATHS];
    bool expected_seen[VMP_MQVPN_BACKEND_MAX_PATHS];
    memset(current, 0, sizeof(current));
    memset(expected_seen, 0, sizeof(expected_seen));

    if (out_count == NULL || expected_count > VMP_MQVPN_BACKEND_MAX_PATHS ||
        observed_count > VMP_MQVPN_BACKEND_MAX_PATHS ||
        out_capacity > VMP_MQVPN_BACKEND_MAX_PATHS ||
        out_capacity < expected_count ||
        (expected_count > 0U && expected_handles == NULL) ||
        (observed_count > 0U && observed == NULL) ||
        (out_capacity > 0U && out == NULL)) {
        clear_path_output(out, out_capacity, out_count);
        return false;
    }
    *out_count = 0U;

    for (size_t index = 0U; index < expected_count; ++index) {
        if (expected_handles[index] < 0) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        for (size_t earlier = 0U; earlier < index; ++earlier) {
            if (expected_handles[earlier] == expected_handles[index]) {
                clear_path_output(out, out_capacity, out_count);
                return false;
            }
        }
    }

    size_t current_count = 0U;
    for (size_t observed_index = 0U; observed_index < observed_count;
         ++observed_index) {
        const vmp_mqvpn_path_record_t *record = &observed[observed_index];
        if (record->handle < 0 || !path_state_is_valid(record->state)) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        for (size_t earlier = 0U; earlier < observed_index; ++earlier) {
            if (observed[earlier].handle == record->handle) {
                clear_path_output(out, out_capacity, out_count);
                return false;
            }
        }

        size_t expected_index = expected_count;
        for (size_t candidate = 0U; candidate < expected_count;
             ++candidate) {
            if (expected_handles[candidate] == record->handle) {
                expected_index = candidate;
                break;
            }
        }
        if (expected_index == expected_count) {
            if (record->state != VMP_MQVPN_PATH_CLOSED) {
                clear_path_output(out, out_capacity, out_count);
                return false;
            }
            continue;
        }
        if (expected_seen[expected_index] ||
            current_count == VMP_MQVPN_BACKEND_MAX_PATHS) {
            clear_path_output(out, out_capacity, out_count);
            return false;
        }
        expected_seen[expected_index] = true;
        copy_path_record(&current[current_count], record);
        ++current_count;
    }

    if (current_count != expected_count) {
        clear_path_output(out, out_capacity, out_count);
        return false;
    }
    return vmp_mqvpn_backend_project_paths(
        expected_handles, expected_count, current, current_count, out,
        out_capacity, out_count);
}
