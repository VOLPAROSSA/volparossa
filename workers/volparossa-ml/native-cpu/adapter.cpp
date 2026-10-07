// SPDX-License-Identifier: GPL-3.0-only
#include "adapter.h"
#include "llama.h"
#include <cstring>
#include <memory>
#include <mutex>
#include <new>

namespace {
constexpr uint32_t max_context = 12288 + 1024;
constexpr uint32_t max_batch = 128;
constexpr int32_t vocabulary = 151936;
constexpr const char * source = "7fe450e19305b828c199d602c23a8337aaa1f03b";
struct state {
    llama_model * model = nullptr;
    llama_context * context = nullptr;
    llama_sampler * sampler = nullptr;
    vp_abort_v1 abort = nullptr;
    void * opaque = nullptr;
    uint32_t capacity = 0;
    uint32_t used = 0;
    bool ready = false;
    bool failed = false;
    ~state() {
        if (context) { llama_synchronize(context); }
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
void discard_log(ggml_log_level, const char *, void *) {}
std::once_flag initialized;
thread_local uint32_t open_stage = VP_OPEN_NONE;
}

extern "C" uint32_t vp_llama_abi_v1(void) { return 1; }
extern "C" const char * vp_llama_source_v1(void) { return source; }
extern "C" uint32_t vp_llama_open_stage_v1(void) { return open_stage; }

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
        auto context_params = llama_context_default_params();
        context_params.n_ctx = capacity;
        context_params.n_batch = max_batch;
        context_params.n_ubatch = max_batch;
        context_params.n_seq_max = 1;
        context_params.n_threads = static_cast<int32_t>(threads);
        context_params.n_threads_batch = static_cast<int32_t>(threads);
        context_params.type_k = GGML_TYPE_BF16;
        context_params.type_v = GGML_TYPE_BF16;
        context_params.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_DISABLED;
        context_params.offload_kqv = false;
        context_params.op_offload = false;
        context_params.abort_callback = aborted;
        context_params.abort_callback_data = value.get();
        open_stage = VP_OPEN_CONTEXT;
        value->context = llama_init_from_model(value->model, context_params);
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
        value->used > value->capacity || count > value->capacity - value->used) { return VP_INVALID; }
    for (uint32_t i = 0; i < count; ++i) {
        if (tokens[i] < 0 || tokens[i] >= vocabulary) { return VP_INVALID; }
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
    if (!value || !token || value->failed || !value->ready) { return VP_INVALID; }
    try {
        if (aborted(value)) { value->failed = true; return VP_ABORTED; }
        const auto generated = llama_sampler_sample(value->sampler, value->context, -1);
        if (generated < 0 || generated >= vocabulary) { value->failed = true; return VP_BACKEND; }
        *token = generated;
        value->ready = false;
        return VP_OK;
    } catch (...) { value->failed = true; return VP_BACKEND; }
}

extern "C" void vp_llama_close_v1(void * handle) { delete static_cast<state *>(handle); }
