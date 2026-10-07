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
int32_t vp_llama_open_v1(const char * model_path, uint32_t context_tokens,
                         uint32_t threads, vp_abort_v1 abort, void * opaque,
                         void ** handle);
int32_t vp_llama_decode_v1(void * handle, const int32_t * tokens, uint32_t count);
int32_t vp_llama_sample_v1(void * handle, int32_t * token);
void vp_llama_close_v1(void * handle);

#ifdef __cplusplus
}
#endif
