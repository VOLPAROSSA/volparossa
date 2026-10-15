// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Our versioned ABI, not a copied upstream struct layout. A handle is owned by
// one Python execution thread. Callback exceptions must never cross this ABI.
typedef int32_t (*vp_abort_v1)(void *);
enum vp_status_v1 { VP_OK = 0, VP_INVALID = 1, VP_ABORTED = 2, VP_BACKEND = 3 };
// Closed last-open phase on the calling execution thread. No exception text or
// paths cross the ABI. Existing v1 entry points/status values remain unchanged.
enum vp_open_stage_v1 {
    VP_OPEN_NONE = 0, VP_OPEN_ARGUMENT = 1, VP_OPEN_CPU = 2,
    VP_OPEN_BACKEND = 3, VP_OPEN_MODEL = 4, VP_OPEN_VOCABULARY = 5,
    VP_OPEN_CONTEXT = 6, VP_OPEN_SAMPLER = 7, VP_OPEN_READY = 8
};
uint32_t vp_llama_abi_v1(void);
const char * vp_llama_source_v1(void);
uint32_t vp_llama_open_stage_v1(void);
// Optional, additive ABI. Mode 1 is qwen_tagged_tool_json_v1, with aliases
// vp_0..vp_(tool_count-1), count 1..32 and JSON nesting <=16 (arguments object
// is depth 1; fixed envelope excluded). Configure once before any decode.
// Absence preserves the original greedy_v1 path.
uint32_t vp_llama_output_constraint_abi_v1(void);
int32_t vp_llama_set_output_constraint_v1(void * handle, uint32_t mode, uint32_t tool_count);
// Optional same-owner, same-thread in-memory session. No state crosses handles
// or owners. The caller retains only the exact token LCP of already decoded
// tokens, at most new_prompt_length-1, and must decode a nonempty suffix before
// sampling. Mode/count is either 0/0 (greedy) or 1/1..32 (fresh fixed grammar).
// A failed begin/decode/sample requires close, never a cold fallback. The caller
// keeps each callback/opaque alive until replacement or close has returned.
uint32_t vp_llama_native_session_abi_v1(void);
int32_t vp_llama_begin_turn_v1(void * handle, uint32_t retained_tokens,
                              uint32_t constraint_mode, uint32_t tool_count,
                              vp_abort_v1 abort, void * opaque);
// Optional context-capacity extension for an already active session. Grow only,
// at most 13312 tokens, under the new turn's callback. Synchronize and destroy
// the old context before allocating its replacement around the SAME model.
// Success discards all previous KV/logits; begin_turn_v1(..., 0, ...) and the
// entire new prompt must follow. Any failure poisons the handle until close.
// Callers lacking this extension keep their original fixed-capacity behavior.
uint32_t vp_llama_context_capacity_abi_v1(void);
int32_t vp_llama_reserve_context_v1(void * handle, uint32_t context_tokens,
                                   vp_abort_v1 abort, void * opaque);
int32_t vp_llama_open_v1(const char * model_path, uint32_t context_tokens,
                         uint32_t threads, vp_abort_v1 abort, void * opaque,
                         void ** handle);
int32_t vp_llama_decode_v1(void * handle, const int32_t * tokens, uint32_t count);
int32_t vp_llama_sample_v1(void * handle, int32_t * token);
void vp_llama_close_v1(void * handle);

#ifdef __cplusplus
}
#endif
