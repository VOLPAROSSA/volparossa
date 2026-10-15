// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "adapter.h"

namespace vp {
// Process-local state of one handle, never a transferable cache or owner ID.
// Legacy calls leave session_active false and retain their existing behavior.
struct session_state {
    uint32_t used = 0;
    uint32_t generated = 0;
    bool ready = false;
    bool failed = false;
    bool session_active = false;
};

inline int32_t invalid_session(session_state * value) {
    if (value && value->session_active) {
        value->ready = false;
        value->failed = true;
    }
    return VP_INVALID;
}

inline bool session_sample_allowed(const session_state & value) {
    return value.generated < 1024 && (value.generated != 0 || value.used <= 12288);
}

// The production callbacks operate on the same already-synchronized context.
// Tests can exercise every failure boundary without a model or synthetic KV
// contents being admitted as an inference result. Any partial reset poisons the
// handle: callers must close it, never silently clear/reload and continue.
template<class Cancelled, class Synchronize, class Truncate, class Reset>
int32_t begin_session_turn(session_state & value, uint32_t retained, uint32_t capacity,
    Cancelled cancelled, Synchronize synchronize, Truncate truncate, Reset reset) {
    value.ready = false; // Old logits can never be sampled after begin_turn.
    if (value.failed || value.used > capacity || retained > value.used ||
        retained >= capacity || retained >= 12288) {
        value.failed = true;
        return VP_INVALID;
    }
    try {
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        synchronize();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        if (!truncate(retained)) { value.failed = true; return VP_BACKEND; }
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        reset();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        value.used = retained;
        value.generated = 0;
        value.session_active = true;
        return VP_OK;
    } catch (...) {
        value.failed = true;
        return VP_BACKEND;
    }
}

// The single model is outside this transition. Destroying the old context must
// complete before creating another; a failed or cancelled transition can only
// be closed. This is capacity growth, never a retry of an admitted generation.
template<class Cancelled, class Synchronize, class Destroy, class Create>
int32_t grow_session_context(session_state & value, uint32_t & capacity, uint32_t requested,
    Cancelled cancelled, Synchronize synchronize, Destroy destroy, Create create) {
    value.ready = false;
    if (value.failed || !value.session_active || value.used > capacity ||
        requested <= capacity || requested > 13312) {
        value.failed = true;
        return VP_INVALID;
    }
    try {
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        synchronize();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        destroy();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        if (!create(requested)) { value.failed = true; return VP_BACKEND; }
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        capacity = requested;
        value.used = 0;
        value.generated = 0;
        return VP_OK;
    } catch (...) {
        value.failed = true;
        return VP_BACKEND;
    }
}
}
