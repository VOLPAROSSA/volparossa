// SPDX-License-Identifier: GPL-3.0-only
#include "output-constraint.h"
#include "llama-grammar.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace vp {
namespace {
constexpr const char * opening = "<tool_call>";
using grammar_ptr = std::unique_ptr<llama_grammar, decltype(&llama_grammar_free_impl)>;

std::string grammar(unsigned count) {
    if (count < 1 || count > 32) { throw std::invalid_argument("constraint count"); }
    std::string result = R"gbnf(root ::= "<tool_call>" ws "{" ws "\"name\"" ws ":" ws tool-name ws "," ws "\"arguments\"" ws ":" ws obj1 ws "}" ws "</tool_call>" ws
ws ::= [ \t\n\r]*
string ::= "\"" ([^"\\\x00-\x1F] | "\\" (["\\/bfnrt] | "u" unicode))* "\""
hex ::= [0-9a-fA-F]
unicode ::= [0-9a-cA-Ce-fE-F] hex hex hex | [dD] [0-7] hex hex | [dD] [89aAbB] hex hex "\\u" [dD] [c-fC-F] hex hex
number ::= "-"? ("0" | [1-9] [0-9]*) ("." [0-9]+)? ([eE] [+-]? [0-9]+)?
scalar ::= string | number | "true" | "false" | "null"
tool-name ::= )gbnf";
    for (unsigned index = 0; index < count; ++index) {
        if (index) { result += " | "; }
        result += "\"\\\"vp_" + std::to_string(index) + "\\\"\"";
    }
    result += '\n';
    for (unsigned depth = 1; depth <= tool_json_depth; ++depth) {
        const auto suffix = std::to_string(depth);
        const auto element = depth == tool_json_depth ? "scalar" : "value" + std::to_string(depth + 1);
        result += "value" + suffix + " ::= scalar | obj" + suffix + " | arr" + suffix + "\n";
        result += "obj" + suffix + " ::= \"{\" ws (string ws \":\" ws " + element +
            " (ws \",\" ws string ws \":\" ws " + element + ")*)? ws \"}\"\n";
        result += "arr" + suffix + " ::= \"[\" ws (" + element + " (ws \",\" ws " +
            element + ")*)? ws \"]\"\n";
    }
    return result;
}

// Validate all bytes, including token-split UTF-8. The bound matches Python's
// ensure_ascii JSON string encoding, including its two surrounding quotes.
bool wire_prefix(const std::string & text, bool & complete) {
    std::size_t cost = 2;
    complete = true;
    for (std::size_t index = 0; index < text.size();) {
        const auto first = static_cast<unsigned char>(text[index]);
        if (!first) { return false; }
        if (first < 0x80) {
            cost += first == '"' || first == '\\' || first == '\b' || first == '\f' ||
                first == '\n' || first == '\r' || first == '\t' ? 2 : first < 0x20 || first == 0x7f ? 6 : 1;
            ++index;
        } else {
            const unsigned length = first >= 0xc2 && first <= 0xdf ? 2 :
                first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
            if (!length) { return false; }
            cost += length == 4 ? 12 : 6;
            for (unsigned offset = 1; offset < length; ++offset) {
                if (index + offset >= text.size()) { complete = false; break; }
                const auto next = static_cast<unsigned char>(text[index + offset]);
                if (next < 0x80 || next > 0xbf || (offset == 1 &&
                    ((first == 0xe0 && next < 0xa0) || (first == 0xed && next > 0x9f) ||
                     (first == 0xf0 && next < 0x90) || (first == 0xf4 && next > 0x8f)))) { return false; }
            }
            index += length;
        }
        if (cost > tool_json_wire_bytes) { return false; }
    }
    return true;
}

bool preface(const std::string & text) {
    if (text.find("<tool_call") != std::string::npos || text.find("</tool_call") != std::string::npos ||
        text.find("```") != std::string::npos || text.find("~~~") != std::string::npos) { return false; }
    const bool blank = text.find_first_not_of(" \t\n\r\f\v") == std::string::npos;
    return blank || (!text.empty() && text.back() == '\n');
}

bool completed(const llama_grammar & value) {
    return value.partial_utf8.n_remain == 0 &&
        std::any_of(value.stacks.begin(), value.stacks.end(), [](const auto & stack) { return stack.empty(); });
}

bool viable(const llama_grammar & value) {
    if (value.stacks.empty() || value.partial_utf8.n_remain < 0) { return false; }
    if (value.partial_utf8.n_remain == 0) { return true; }
    const uint32_t end = 0;
    const llama_grammar_candidates candidates{{0, &end, value.partial_utf8, 0}};
    for (const auto & stack : value.stacks) {
        if (llama_grammar_reject_candidates_for_stack(value.rules, stack, candidates).empty()) { return true; }
    }
    return false;
}
}

struct tool_constraint::implementation {
    grammar_ptr parser{nullptr, llama_grammar_free_impl};
    std::string text;
    bool active = false;
    bool ended = false;
    explicit implementation(const llama_vocab * vocab, unsigned count) {
        const auto rules = grammar(count);
        parser.reset(llama_grammar_init_impl(vocab, rules.c_str(), "root", false, nullptr, 0, nullptr, 0));
        if (!parser) { throw std::runtime_error("constraint initialization"); }
    }
    grammar_ptr advance(const std::string & piece) const {
        grammar_ptr next(llama_grammar_clone_impl(*parser), llama_grammar_free_impl);
        if (!next) { throw std::runtime_error("constraint clone"); }
        // This character API throws on an invalid prefix. Unlike token accept,
        // it cannot invoke the upstream fatal EOS assertion. No text is logged.
        llama_grammar_accept_str(*next, piece);
        return next;
    }
};

tool_constraint::tool_constraint(const llama_vocab * vocab, unsigned count)
    : value(std::make_unique<implementation>(vocab, count)) {}
tool_constraint::~tool_constraint() = default;

selection select_candidate(std::vector<llama_token_data> & candidates,
    const std::function<bool(llama_token)> & permitted,
    const std::function<bool()> & cancelled, llama_token & selected) {
    selected = -1;
    if (cancelled()) { return selection::cancelled; }
    candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
        [](const auto & candidate) { return !std::isfinite(candidate.logit); }), candidates.end());
    const auto lower = [](const auto & left, const auto & right) {
        return left.logit < right.logit || (left.logit == right.logit && left.id > right.id);
    };
    std::make_heap(candidates.begin(), candidates.end(), lower);
    while (!candidates.empty()) {
        if (cancelled()) { return selection::cancelled; }
        const auto candidate = candidates.front();
        if (permitted(candidate.id)) { selected = candidate.id; return selection::chosen; }
        std::pop_heap(candidates.begin(), candidates.end(), lower);
        candidates.pop_back();
    }
    return selection::empty;
}

void tool_constraint::filter(llama_token_data_array & candidates) const {
    if (value->active) {
        if (!value->parser->vocab || !candidates.data || !candidates.size) {
            throw std::invalid_argument("constraint filter");
        }
        llama_grammar_apply_impl(*value->parser, &candidates);
    }
}

bool tool_constraint::permits(const std::string & piece, bool eos) const {
    if (value->ended || (!eos && piece.empty()) || piece.size() > tool_json_wire_bytes ||
        value->text.size() + piece.size() > tool_json_wire_bytes) { return false; }
    const auto next = value->text + piece;
    bool complete = false;
    if (!wire_prefix(next, complete)) { return false; }
    for (const auto * forbidden : {"<think", "</think", "<|im_", "<|endoftext|>"}) {
        if (next.find(forbidden) != std::string::npos) { return false; }
    }
    if (eos) {
        if (!piece.empty() || !complete) { return false; }
        if (value->active) { return completed(*value->parser); }
        return next.find_first_not_of(" \t\n\r\f\v") != std::string::npos &&
            next.find("<tool_call") == std::string::npos && next.find("</tool_call") == std::string::npos;
    }
    if (value->active) {
        try { return viable(*value->advance(piece)); }
        catch (const std::runtime_error &) { return false; }
    }
    const auto start = next.find(opening);
    if (start == std::string::npos) {
        const auto partial = next.find("<tool_call");
        return next.find("</tool_call") == std::string::npos &&
            (partial == std::string::npos ||
             (partial + 10 == next.size() && preface(next.substr(0, partial))));
    }
    if (!preface(next.substr(0, start))) { return false; }
    try { return viable(*value->advance(next.substr(start))); }
    catch (const std::runtime_error &) { return false; }
}

void tool_constraint::accept(const std::string & piece, bool eos) {
    if (!permits(piece, eos)) { throw std::invalid_argument("constraint candidate"); }
    if (eos) { value->ended = true; return; }
    const auto next = value->text + piece;
    const auto start = next.find(opening);
    if (value->active) { value->parser = value->advance(piece); }
    else if (start != std::string::npos) {
        value->parser = value->advance(next.substr(start));
        value->active = true;
    }
    value->text = next;
}
}
