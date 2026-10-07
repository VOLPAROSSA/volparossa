// SPDX-License-Identifier: GPL-3.0-only
// No model is loaded. Invalid calls and abort-before-file-open exercise our real
// compiled ABI; upstream tensor tests are a separate target, not a model proof.
#include "adapter.h"
#include <cassert>
#include <cstring>

static int32_t abort_immediately(void * opaque) {
    ++*static_cast<int *>(opaque);
    return 1;
}

int main() {
    assert(vp_llama_abi_v1() == 1);
    assert(vp_llama_open_stage_v1() == VP_OPEN_NONE);
    assert(std::strcmp(vp_llama_source_v1(), "7fe450e19305b828c199d602c23a8337aaa1f03b") == 0);
    void * handle = nullptr;
    int callbacks = 0;
    assert(vp_llama_open_v1(nullptr, 16, 2, abort_immediately, &callbacks, &handle) == VP_INVALID);
    assert(vp_llama_open_stage_v1() == VP_OPEN_ARGUMENT);
    assert(vp_llama_open_v1("relative", 16, 2, abort_immediately, &callbacks, &handle) == VP_INVALID);
    assert(vp_llama_open_v1("/never-read-model", 13313, 2, abort_immediately, &callbacks, &handle) == VP_INVALID);
    assert(vp_llama_open_v1("/never-read-model", 16, 3, abort_immediately, &callbacks, &handle) == VP_INVALID);
    assert(vp_llama_open_v1("/never-read-model", 16, 2, nullptr, nullptr, &handle) == VP_INVALID);
    assert(vp_llama_decode_v1(nullptr, nullptr, 0) == VP_INVALID);
    assert(vp_llama_sample_v1(nullptr, nullptr) == VP_INVALID);
    assert(handle == nullptr && callbacks == 0);
    const auto status = vp_llama_open_v1("/never-read-model", 16, 2, abort_immediately, &callbacks, &handle);
    // Unsupported instruction set is a legitimate explicit refusal, not a pass
    // of model loading. On this capable build host, the callback aborts first.
    assert((status == VP_ABORTED && callbacks == 1) || (status == VP_INVALID && callbacks == 0));
    assert(vp_llama_open_stage_v1() == (status == VP_ABORTED ? VP_OPEN_BACKEND : VP_OPEN_CPU));
    assert(handle == nullptr);
    vp_llama_close_v1(nullptr);
}
