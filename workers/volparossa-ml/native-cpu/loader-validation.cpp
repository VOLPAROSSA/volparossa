// SPDX-License-Identifier: GPL-3.0-only
// The included launch/join fragments come from the hash-verified staged MIT
// loader. Only the surrounding toy tensors and observation harness are ours.
// This is not a full model load or inference/latency proof.
#include "ggml.h"
#include <cassert>
#include <chrono>
#include <future>
#include <limits>
#include <stdexcept>
#include <thread>
#include <vector>

static int validations = 0;
static std::thread::id execution_thread;
static bool checked_validation(ggml_type type, const void * data, size_t size) {
    assert(std::this_thread::get_id() == execution_thread);
    ++validations;
    return ggml_validate_row_data(type, data, size);
}

using pending = std::vector<std::future<std::pair<ggml_tensor *, bool>>>;
// Instrument calls, not their result: real ggml checks still run completely.
#define ggml_validate_row_data checked_validation
static void mapped(pending & validation_result, ggml_tensor * cur, uint8_t * data, size_t n_size) {
#include "validation-mapped.inc"
}
static void host(pending & validation_result, ggml_tensor * cur, size_t n_size) {
#include "validation-host.inc"
}
#undef ggml_validate_row_data

static int polls = 0;
static int cancel_on_poll = 0;
static bool progress(float, void *) {
    assert(std::this_thread::get_id() == execution_thread);
    return ++polls != cancel_on_poll;
}
static bool join(pending & validation_result) {
    const size_t size_done = 1, size_data = 1;
    auto progress_callback = progress;
    void * progress_callback_user_data = nullptr;
    // The production logger remains disabled; the toy contains no private data.
#define LLAMA_LOG_ERROR(...) ((void) 0)
#include "validation-join.inc"
#undef LLAMA_LOG_ERROR
    return true;
}

static void run(bool invalid, int cancellation) {
    constexpr int count = 398;
    validations = polls = 0;
    cancel_on_poll = cancellation;
    execution_thread = std::this_thread::get_id();
    float valid[2] = {1.0f, -1.0f};
    float corrupt[2] = {std::numeric_limits<float>::quiet_NaN(), 0.0f};
    std::vector<ggml_tensor> tensors(count);
    pending validation_result;
    for (int i = 0; i < count; ++i) {
        auto * cur = &tensors[i];
        cur->type = GGML_TYPE_F32;
        cur->data = invalid && i == 0 ? corrupt : valid;
        if (i % 2 == 0) {
            mapped(validation_result, cur, static_cast<uint8_t *>(cur->data), sizeof(valid));
        } else {
            host(validation_result, cur, sizeof(valid));
        }
    }
    assert(validations == 0);
    for (auto & future : validation_result) {
        assert(future.wait_for(std::chrono::seconds(0)) == std::future_status::deferred);
    }
    bool complete = false, rejected = false;
    try { complete = join(validation_result); }
    catch (const std::runtime_error &) { rejected = true; }
    if (cancellation != 0) {
        assert(!complete && !rejected && validations == cancellation - 1 && polls == cancellation);
    } else {
        assert(complete == !invalid && rejected == invalid && validations == count && polls == count);
    }
}

int main() {
    run(false, 0);
    run(true, 0); // A bad first tensor must not skip the other validation results.
    run(false, 1);
    run(false, 3);
    run(false, 398);
    run(false, 0); // A fresh attempt after cancellation checks every tensor again.
}
