// SPDX-License-Identifier: GPL-3.0-only
#include "adapter.h"
#include "llama.h"
#include "output-constraint.h"
#include "session-state.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
constexpr uint32_t max_context = 12288 + 1024;
constexpr uint32_t max_batch = 128;
constexpr int32_t vocabulary = 151936;
constexpr const char * source = "7fe450e19305b828c199d602c23a8337aaa1f03b";
struct state : vp::session_state {
    llama_model * model = nullptr;
    llama_context * context = nullptr;
    llama_sampler * sampler = nullptr;
    vp_abort_v1 abort = nullptr;
    void * opaque = nullptr;
    uint32_t capacity = 0;
    uint32_t threads = 0;
    std::unique_ptr<vp::tool_constraint> constraint;
    ~state() {
        if (context) { llama_synchronize(context); }
        constraint.reset();
        if (sampler) { llama_sampler_free(sampler); }
        if (context) { llama_free(context); }
        if (model) { llama_model_free(model); }
    }
};
bool aborted(void * pointer) {
    auto * value = static_cast<state *>(pointer);
    return value->abort(value->opaque) != 0;
}
bool load_progress(float, void * pointer) { return !aborted(pointer); }
llama_context * create_context(state * value, uint32_t capacity) {
    auto params = llama_context_default_params();
    params.n_ctx = capacity;
    params.n_batch = max_batch;
    params.n_ubatch = max_batch;
    params.n_seq_max = 1;
    params.n_threads = static_cast<int32_t>(value->threads);
    params.n_threads_batch = static_cast<int32_t>(value->threads);
    params.type_k = GGML_TYPE_BF16;
    params.type_v = GGML_TYPE_BF16;
    params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
    params.offload_kqv = false;
    params.op_offload = false;
    params.abort_callback = aborted;
    params.abort_callback_data = value;
    return llama_init_from_model(value->model, params);
}
bool token_piece(const llama_vocab * vocab, llama_token token, std::string & piece) {
    std::array<char, vp::tool_json_wire_bytes> bytes{};
    const auto size = llama_token_to_piece(vocab, token, bytes.data(), bytes.size(), 0, true);
    if (size < 1 || size > static_cast<int32_t>(bytes.size())) { return false; }
    piece.assign(bytes.data(), static_cast<std::size_t>(size));
    return true;
}

int32_t constrained_sample(state * value, int32_t * output) {
    if (value->generated >= 1024 || (!value->generated && value->used > 12288)) {
        value->failed = true; return VP_INVALID;
    }
    const auto * logits = llama_get_logits_ith(value->context, -1);
    if (!logits) { value->failed = true; return VP_BACKEND; }
    const auto * vocab = llama_model_get_vocab(value->model);
    std::vector<llama_token_data> candidates;
    candidates.reserve(vocabulary);
    for (int32_t id = 0; id < vocabulary; ++id) {
        if ((id % 4096) == 0 && aborted(value)) { value->failed = true; return VP_ABORTED; }
        if (std::isfinite(logits[id]) && (id == 151645 || !llama_vocab_is_control(vocab, id))) {
            candidates.push_back({id, logits[id], 0.0f});
        }
    }
    if (candidates.empty()) { value->failed = true; return VP_BACKEND; }
    llama_token_data_array array{candidates.data(), candidates.size(), -1, false};
    value->constraint->filter(array);
    // Linear heap construction, then highest finite permitted logit. Ascending
    // token ID breaks ties exactly as the unchanged upstream greedy sampler.
    std::string piece;
    llama_token selected = -1;
    const auto result = vp::select_candidate(candidates, [&](llama_token id) {
        piece.clear();
        const bool eos = id == 151645;
        return (eos || token_piece(vocab, id, piece)) && value->constraint->permits(piece, eos);
    }, [&] { return aborted(value); }, selected);
    if (result == vp::selection::chosen && !aborted(value)) {
        value->constraint->accept(piece, selected == 151645);
        *output = selected;
        ++value->generated;
        value->ready = false;
        return VP_OK;
    }
    value->failed = true;
    return result == vp::selection::cancelled || aborted(value) ? VP_ABORTED : VP_BACKEND;
}
void discard_log(ggml_log_level, const char *, void *) {}
std::once_flag initialized;
thread_local uint32_t open_stage = VP_OPEN_NONE;
}

extern "C" uint32_t vp_llama_abi_v1(void) { return 1; }
extern "C" const char * vp_llama_source_v1(void) { return source; }
extern "C" uint32_t vp_llama_open_stage_v1(void) { return open_stage; }
extern "C" uint32_t vp_llama_output_constraint_abi_v1(void) { return 1; }
extern "C" uint32_t vp_llama_native_session_abi_v1(void) { return 1; }
extern "C" uint32_t vp_llama_context_capacity_abi_v1(void) { return 1; }

extern "C" int32_t vp_llama_reserve_context_v1(void * handle, uint32_t capacity,
                                               vp_abort_v1 abort, void * opaque) {
    auto * value = static_cast<state *>(handle);
    if (!value) { return VP_INVALID; }
    if (!abort || !value->context || !value->model || !value->sampler) {
        value->ready = false;
        value->failed = true;
        return VP_INVALID;
    }
    // Replace the expired previous turn's callback before any owner check.
    value->abort = abort;
    value->opaque = opaque;
    return vp::grow_session_context(*value, value->capacity, capacity,
        [&] { return aborted(value); },
        [&] { llama_synchronize(value->context); },
        [&] {
            value->constraint.reset();
            llama_sampler_reset(value->sampler);
            llama_free(value->context);
            value->context = nullptr;
        },
        [&](uint32_t requested) {
            value->context = create_context(value, requested);
            return value->context != nullptr;
        });
}

extern "C" int32_t vp_llama_begin_turn_v1(void * handle, uint32_t retained,
                                          uint32_t mode, uint32_t count,
                                          vp_abort_v1 abort, void * opaque) {
    auto * value = static_cast<state *>(handle);
    if (!value) { return VP_INVALID; }
    if (!abort || value->failed || !((mode == 0 && count == 0) ||
            (mode == 1 && count >= 1 && count <= 32))) {
        value->ready = false;
        value->failed = true;
        return VP_INVALID;
    }
    // The context's original callback still points to this handle; only the
    // handle-local owner callback changes, before any new backend operation.
    value->abort = abort;
    value->opaque = opaque;
    return vp::begin_session_turn(*value, retained, value->capacity,
        [&] { return aborted(value); },
        [&] { llama_synchronize(value->context); },
        [&](uint32_t prefix) {
            const auto memory = llama_get_memory(value->context);
            return memory && llama_memory_seq_rm(memory, 0, static_cast<llama_pos>(prefix), -1);
        },
        [&] {
            std::unique_ptr<vp::tool_constraint> next;
            if (mode == 1) {
                const auto * vocab = llama_model_get_vocab(value->model);
                std::string open, close;
                if (llama_vocab_is_control(vocab, 151657) || llama_vocab_is_control(vocab, 151658) ||
                    !token_piece(vocab, 151657, open) || open != "<tool_call>" ||
                    !token_piece(vocab, 151658, close) || close != "</tool_call>") {
                    throw std::invalid_argument("constraint vocabulary");
                }
                next = std::make_unique<vp::tool_constraint>(vocab, count);
            }
            llama_sampler_reset(value->sampler);
            value->constraint = std::move(next);
        });
}

extern "C" int32_t vp_llama_set_output_constraint_v1(void * handle, uint32_t mode, uint32_t count) {
    auto * value = static_cast<state *>(handle);
    if (value && value->session_active) { return vp::invalid_session(value); }
    if (!value || value->failed || value->used || value->constraint || mode != 1 || count < 1 || count > 32) {
        return VP_INVALID;
    }
    try {
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        const auto * vocab = llama_model_get_vocab(value->model);
        std::string open, close;
        if (llama_vocab_is_control(vocab, 151657) || llama_vocab_is_control(vocab, 151658) ||
            !token_piece(vocab, 151657, open) || open != "<tool_call>" ||
            !token_piece(vocab, 151658, close) || close != "</tool_call>") { return VP_INVALID; }
        value->constraint = std::make_unique<vp::tool_constraint>(vocab, count);
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        return VP_OK;
    } catch (...) { value->failed = true; return VP_BACKEND; }
}

extern "C" int32_t vp_llama_open_v1(const char * path, uint32_t capacity,
                                     uint32_t threads, vp_abort_v1 abort,
                                     void * opaque, void ** handle) {
    open_stage = VP_OPEN_ARGUMENT;
    if (!handle) { return VP_INVALID; }
    *handle = nullptr;
    if (!path || path[0] != '/' || std::strlen(path) > 4096 || !abort ||
        capacity < 2 || capacity > max_context || threads < 1 || threads > 2) {
        return VP_INVALID;
    }
    open_stage = VP_OPEN_CPU;
#if defined(__x86_64__) && defined(__GNUC__)
    if (!__builtin_cpu_supports("avx2") || !__builtin_cpu_supports("fma") ||
        !__builtin_cpu_supports("f16c")) { return VP_INVALID; }
#else
    return VP_INVALID;
#endif
    try {
        open_stage = VP_OPEN_BACKEND;
        std::call_once(initialized, [] {
            // No private text, paths, tensor names or backend errors on stdout/stderr.
            llama_log_set(discard_log, nullptr);
            ggml_log_set(discard_log, nullptr);
            llama_backend_init();
        });
        auto value = std::make_unique<state>();
        value->abort = abort;
        value->opaque = opaque;
        value->capacity = capacity;
        value->threads = threads;
        if (aborted(value.get())) { return VP_ABORTED; }
        auto model_params = llama_model_default_params();
        model_params.n_gpu_layers = 0;
        model_params.use_extra_bufts = false;
        model_params.check_tensors = true;
        model_params.progress_callback = load_progress;
        model_params.progress_callback_user_data = value.get();
        open_stage = VP_OPEN_MODEL;
        value->model = llama_model_load_from_file(path, model_params);
        if (aborted(value.get())) { return VP_ABORTED; }
        if (!value->model) { return VP_BACKEND; }
        open_stage = VP_OPEN_VOCABULARY;
        const auto * vocab = llama_model_get_vocab(value->model);
        if (llama_vocab_n_tokens(vocab) != vocabulary || llama_vocab_eos(vocab) != 151645) {
            return VP_INVALID;
        }
        open_stage = VP_OPEN_CONTEXT;
        value->context = create_context(value.get(), capacity);
        if (aborted(value.get())) { return VP_ABORTED; }
        if (!value->context) { return VP_BACKEND; }
        open_stage = VP_OPEN_SAMPLER;
        value->sampler = llama_sampler_init_greedy();
        if (!value->sampler) { return VP_BACKEND; }
        *handle = value.release();
        open_stage = VP_OPEN_READY;
        return VP_OK;
    } catch (...) { return VP_BACKEND; }
}

extern "C" int32_t vp_llama_decode_v1(void * handle, const int32_t * tokens, uint32_t count) {
    auto * value = static_cast<state *>(handle);
    if (!value || !tokens || value->failed || !count || count > max_batch ||
        value->used > value->capacity || count > value->capacity - value->used) {
        return vp::invalid_session(value);
    }
    if (value->session_active && value->generated == 0 && value->used + count > 12288) {
        return vp::invalid_session(value);
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (tokens[i] < 0 || tokens[i] >= vocabulary) { return vp::invalid_session(value); }
    }
    try {
        value->ready = false;
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        // Upstream's synchronous decode never borrows this array after return.
        auto batch = llama_batch_get_one(const_cast<int32_t *>(tokens), static_cast<int32_t>(count));
        const auto result = llama_decode(value->context, batch);
        llama_synchronize(value->context);
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        if (result != 0) { value->failed = true; return VP_BACKEND; }
        value->used += count;
        value->ready = true;
        return VP_OK;
    } catch (...) { value->failed = true; return VP_BACKEND; }
}

extern "C" int32_t vp_llama_sample_v1(void * handle, int32_t * token) {
    auto * value = static_cast<state *>(handle);
    if (!value || !token || value->failed || !value->ready) { return vp::invalid_session(value); }
    try {
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        if (value->session_active && !vp::session_sample_allowed(*value)) {
            value->failed = true; return VP_INVALID;
        }
        if (value->constraint) { return constrained_sample(value, token); }
        const auto generated = llama_sampler_sample(value->sampler, value->context, -1);
        if (generated < 0 || generated >= vocabulary) { value->failed = true; return VP_BACKEND; }
        *token = generated;
        if (value->session_active) { ++value->generated; }
        value->ready = false;
        return VP_OK;
    } catch (...) { value->failed = true; return VP_BACKEND; }
}

extern "C" void vp_llama_close_v1(void * handle) { delete static_cast<state *>(handle); }
