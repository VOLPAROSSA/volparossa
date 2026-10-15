// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "llama.h"
#include <memory>
#include <string>
#include <functional>
#include <vector>

namespace vp {
// Fixed, optional profile. No caller-provided grammar or schema is accepted.
constexpr unsigned tool_json_depth = 16;
constexpr unsigned tool_json_wire_bytes = 4096;
enum class selection { chosen, empty, cancelled };
selection select_candidate(std::vector<llama_token_data> & candidates,
    const std::function<bool(llama_token)> & permitted,
    const std::function<bool()> & cancelled, llama_token & selected);
class tool_constraint {
public:
    tool_constraint(const llama_vocab * vocab, unsigned count);
    ~tool_constraint();
    tool_constraint(const tool_constraint &) = delete;
    tool_constraint & operator=(const tool_constraint &) = delete;
    void filter(llama_token_data_array & candidates) const;
    bool permits(const std::string & piece, bool eos) const;
    void accept(const std::string & piece, bool eos);
private:
    struct implementation;
    std::unique_ptr<implementation> value;
};
}
