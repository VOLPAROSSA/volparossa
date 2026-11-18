// SPDX-License-Identifier: GPL-3.0-only
// Exercise the production turn-state transition with bounded callback doubles.
// No model, real KV cache, inference or cross-owner reuse is claimed.
#include "session-state.h"
#include <cassert>
#include <initializer_list>
#include <stdexcept>

namespace {
struct backend {
    unsigned checks = 0, synchronized = 0, truncated = 0, resets = 0;
    unsigned cancel_at = 99, throw_at = 99;
    uint32_t observed_prefix = 99;
    bool truncate_ok = true;

    int32_t begin(vp::session_state & value, uint32_t prefix, uint32_t capacity = 13312) {
        return vp::begin_session_turn(value, prefix, capacity,
            [&] { assert(!value.ready); return checks++ == cancel_at; },
            [&] {
                ++synchronized;
                if (throw_at == 0) { throw std::runtime_error("synthetic sync"); }
            },
            [&](uint32_t retained) {
                ++truncated;
                observed_prefix = retained;
                if (throw_at == 1) { throw std::runtime_error("synthetic truncate"); }
                return truncate_ok;
            },
            [&] {
                ++resets;
                if (throw_at == 2) { throw std::runtime_error("synthetic reset"); }
            });
    }
};

vp::session_state previous() {
    vp::session_state value;
    value.used = 16;
    value.generated = 4;
    value.ready = true;
    value.session_active = true;
    return value;
}

void fresh_and_retained_turns() {
    vp::session_state first;
    backend initial;
    assert(initial.begin(first, 0) == VP_OK);
    assert(first.session_active && !first.failed && !first.ready);
    assert(first.used == 0 && first.generated == 0 && initial.observed_prefix == 0);
    assert(initial.checks == 4 && initial.synchronized == 1 && initial.truncated == 1 && initial.resets == 1);
    for (uint32_t prefix : {0u, 1u, 15u, 16u}) {
        auto value = previous();
        backend next;
        assert(next.begin(value, prefix) == VP_OK);
        assert(value.used == prefix && value.generated == 0 && !value.ready && !value.failed);
        assert(next.observed_prefix == prefix && next.resets == 1);
    }
}

void invalid_retention_poisoned_without_backend_work() {
    for (unsigned variant = 0; variant < 5; ++variant) {
        auto value = previous();
        uint32_t prefix = 17, capacity = 13312;
        if (variant == 1) { prefix = 16; capacity = 16; }
        if (variant == 2) { prefix = 12288; value.used = 12288; }
        if (variant == 3) { prefix = 0; capacity = 15; }
        if (variant == 4) { prefix = 0; value.failed = true; }
        backend next;
        assert(next.begin(value, prefix, capacity) == VP_INVALID);
        assert(value.failed && !value.ready);
        assert(next.checks == 0 && next.synchronized == 0 && next.truncated == 0 && next.resets == 0);
        assert(next.begin(value, 0) == VP_INVALID); // No cold restart after refusal.
    }
}

void truncation_failure_never_resets_or_reuses() {
    auto value = previous();
    backend next;
    next.truncate_ok = false;
    assert(next.begin(value, 8) == VP_BACKEND);
    assert(value.failed && !value.ready && value.used == 16 && value.generated == 4);
    assert(next.truncated == 1 && next.resets == 0);
    next.truncate_ok = true;
    assert(next.begin(value, 0) == VP_INVALID);
    assert(next.truncated == 1 && next.resets == 0);
}

void cancellation_at_every_backend_boundary() {
    for (unsigned cancel = 0; cancel < 4; ++cancel) {
        auto value = previous();
        backend next;
        next.cancel_at = cancel;
        assert(next.begin(value, 8) == VP_ABORTED);
        assert(value.failed && !value.ready && value.used == 16 && value.generated == 4);
        assert(next.synchronized == (cancel >= 1 ? 1u : 0u));
        assert(next.truncated == (cancel >= 2 ? 1u : 0u));
        assert(next.resets == (cancel >= 3 ? 1u : 0u));
    }
}

void exceptions_never_cross_the_turn_boundary() {
    for (unsigned stage = 0; stage < 3; ++stage) {
        auto value = previous();
        backend next;
        next.throw_at = stage;
        assert(next.begin(value, 8) == VP_BACKEND);
        assert(value.failed && !value.ready);
    }
    auto value = previous();
    assert(vp::begin_session_turn(value, 8, 13312,
        []() -> bool { throw std::runtime_error("synthetic callback"); },
        [] { assert(false); }, [](uint32_t) { assert(false); return true; },
        [] { assert(false); }) == VP_BACKEND);
    assert(value.failed && !value.ready);
}

void prompt_generation_and_legacy_boundaries() {
    vp::session_state value;
    value.used = 12288;
    assert(vp::session_sample_allowed(value));
    value.used = 12289;
    assert(!vp::session_sample_allowed(value));
    value.generated = 1;
    assert(vp::session_sample_allowed(value));
    value.generated = 1023;
    assert(vp::session_sample_allowed(value));
    value.generated = 1024;
    assert(!vp::session_sample_allowed(value));
    value.ready = true;
    assert(vp::invalid_session(&value) == VP_INVALID);
    assert(!value.failed && value.ready); // Unrequested legacy behavior unchanged.
    value.session_active = true;
    assert(vp::invalid_session(&value) == VP_INVALID);
    assert(value.failed && !value.ready);
    assert(vp::invalid_session(nullptr) == VP_INVALID);
}

struct growing_backend {
    uint32_t capacity = 1280;
    unsigned checks = 0, synchronized = 0, destroyed = 0, created = 0;
    unsigned cancel_at = 99, throw_at = 99, live_contexts = 1;
    bool create_ok = true;

    int32_t grow(vp::session_state & value, uint32_t requested = 1536) {
        return vp::grow_session_context(value, capacity, requested,
            [&] { assert(!value.ready); return checks++ == cancel_at; },
            [&] {
                assert(live_contexts == 1);
                ++synchronized;
                if (throw_at == 0) { throw std::runtime_error("synthetic sync"); }
            },
            [&] {
                assert(synchronized == 1 && live_contexts == 1);
                ++destroyed;
                if (throw_at == 1) { throw std::runtime_error("synthetic destroy"); }
                live_contexts = 0;
            },
            [&](uint32_t next) {
                assert(destroyed == 1 && live_contexts == 0 && next == requested);
                ++created;
                if (throw_at == 2) { throw std::runtime_error("synthetic create"); }
                if (create_ok) { live_contexts = 1; }
                return create_ok;
            });
    }
};

void growth_destroys_before_create_and_forgets_all_old_positions() {
    auto value = previous();
    growing_backend next;
    assert(next.grow(value) == VP_OK);
    assert(next.capacity == 1536 && next.live_contexts == 1);
    assert(next.synchronized == 1 && next.destroyed == 1 && next.created == 1 && next.checks == 4);
    assert(value.used == 0 && value.generated == 0 && !value.ready && !value.failed && value.session_active);
    backend turn;
    assert(turn.begin(value, 0, next.capacity) == VP_OK);
    assert(value.used == 0 && !value.ready); // A complete new prompt must still be decoded.
    auto cannot_retain = previous();
    growing_backend other;
    assert(other.grow(cannot_retain) == VP_OK);
    assert(turn.begin(cannot_retain, 1, other.capacity) == VP_INVALID);
}

void growth_rejects_invalid_state_capacity_and_preserves_maximum() {
    for (unsigned variant = 0; variant < 6; ++variant) {
        auto value = previous();
        growing_backend next;
        uint32_t requested = 1280;
        if (variant == 1) { requested = 1279; }
        if (variant == 2) { requested = 13313; }
        if (variant == 3) { requested = 1536; value.failed = true; }
        if (variant == 4) { requested = 1536; value.session_active = false; }
        if (variant == 5) { requested = 1536; value.used = 1281; }
        assert(next.grow(value, requested) == VP_INVALID);
        assert(value.failed && !value.ready);
        assert(next.capacity == 1280 && next.checks == 0 && next.destroyed == 0 && next.created == 0);
    }
    auto value = previous();
    growing_backend maximum;
    assert(maximum.grow(value, 13312) == VP_OK && maximum.capacity == 13312);
}

void growth_cancellation_never_commits_capacity_or_reuses_partial_state() {
    for (unsigned cancel = 0; cancel < 4; ++cancel) {
        auto value = previous();
        growing_backend next;
        next.cancel_at = cancel;
        assert(next.grow(value) == VP_ABORTED);
        assert(value.failed && !value.ready && next.capacity == 1280);
        assert(next.synchronized == (cancel >= 1 ? 1u : 0u));
        assert(next.destroyed == (cancel >= 2 ? 1u : 0u));
        assert(next.created == (cancel >= 3 ? 1u : 0u));
        const auto checked = next.checks;
        assert(next.grow(value) == VP_INVALID && next.checks == checked);
    }
}

void growth_allocation_failure_or_exception_poison_without_second_context() {
    auto value = previous();
    growing_backend failed;
    failed.create_ok = false;
    assert(failed.grow(value) == VP_BACKEND);
    assert(value.failed && !value.ready && failed.live_contexts == 0 && failed.capacity == 1280);
    assert(failed.grow(value) == VP_INVALID && failed.created == 1);
    for (unsigned stage = 0; stage < 3; ++stage) {
        auto subject = previous();
        growing_backend next;
        next.throw_at = stage;
        assert(next.grow(subject) == VP_BACKEND);
        assert(subject.failed && !subject.ready && next.capacity == 1280);
        assert(next.live_contexts <= 1);
    }
}
}

int main() {
    fresh_and_retained_turns();
    invalid_retention_poisoned_without_backend_work();
    truncation_failure_never_resets_or_reuses();
    cancellation_at_every_backend_boundary();
    exceptions_never_cross_the_turn_boundary();
    prompt_generation_and_legacy_boundaries();
    growth_destroys_before_create_and_forgets_all_old_positions();
    growth_rejects_invalid_state_capacity_and_preserves_maximum();
    growth_cancellation_never_commits_capacity_or_reuses_partial_state();
    growth_allocation_failure_or_exception_poison_without_second_context();
}
