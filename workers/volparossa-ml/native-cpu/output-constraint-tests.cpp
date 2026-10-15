// SPDX-License-Identifier: GPL-3.0-only
// Real pinned upstream GBNF engine, synthetic pieces/logits only. No model,
// native inference, tool execution or protected-network claim.
#include "output-constraint.h"
#include <cassert>
#include <limits>
#include <stdexcept>

namespace {
const std::string call = "<tool_call>{\"name\":\"vp_0\",\"arguments\":{\"input\":\"ok\"}}</tool_call>";

void feed(vp::tool_constraint & value, const std::string & text) {
    assert(value.permits(text, false));
    value.accept(text, false);
}

void ordinary_and_optional() {
    vp::tool_constraint value(nullptr, 1);
    assert(!value.permits("", true));
    feed(value, "A normal answer, not a tool.");
    assert(value.permits("", true));
    value.accept("", true);
    assert(!value.permits("more", false));
    for (unsigned count : {0u, 33u}) {
        bool rejected = false;
        try { vp::tool_constraint invalid(nullptr, count); }
        catch (const std::invalid_argument &) { rejected = true; }
        assert(rejected);
    }
}

void atomic_split_and_tail() {
    for (std::size_t split = 0; split <= call.size(); ++split) {
        vp::tool_constraint value(nullptr, 1);
        if (split) { feed(value, call.substr(0, split)); }
        if (split < call.size()) { feed(value, call.substr(split)); }
        assert(value.permits("", true));
        assert(!value.permits(call, false)); // No second call after the first.
        assert(!value.permits(" trailing prose", false));
    }
    vp::tool_constraint value(nullptr, 1);
    feed(value, "I will inspect it.\n<tool_");
    assert(!value.permits("call>{bad}", false));
    assert(!value.permits("call>{\"name\":\"vp_1\"", false));
    feed(value, "call>");
    assert(!value.permits("", true));
    assert(!value.permits("{\"arguments\":{}}", false));
    feed(value, "{\"name\":\"vp_0\",\"arguments\":{}}");
    assert(!value.permits("", true));
    feed(value, "</tool_call>");
    assert(value.permits("", true));
    // Invalid lookahead did not mutate the actual chosen grammar state.
    value.accept("", true);
}

void preface_and_aliases() {
    for (const auto & prefix : {"Same line ", "```\n", "~~~\n", "<think>\n", "</tool_call>\n"}) {
        vp::tool_constraint value(nullptr, 1);
        assert(!value.permits(prefix + call, false));
        assert(!value.permits(std::string(prefix) + "<tool_call", false));
    }
    for (const auto & prefix : {"", " \n", "Allowed preface\n"}) {
        vp::tool_constraint value(nullptr, 1);
        feed(value, prefix + call);
        assert(value.permits("", true));
    }
    vp::tool_constraint value(nullptr, 32);
    feed(value, "<tool_call>{\"name\":\"vp_31\",\"arguments\":{}}</tool_call>");
    assert(value.permits("", true));
    for (const auto & name : {"vp_32", "other", "vp_00"}) {
        vp::tool_constraint invalid(nullptr, 32);
        assert(!invalid.permits(std::string("<tool_call>{\"name\":\"") + name + "\",", false));
    }
    vp::tool_constraint partial(nullptr, 1);
    feed(partial, "<tool_call");
    assert(!partial.permits("", true));
    assert(!partial.permits("x", false));
}

void utf8_and_escapes() {
    const std::string prefix = "<tool_call>{\"name\":\"vp_0\",\"arguments\":{\"s\":\"";
    const std::string suffix = "\"}}</tool_call>";
    for (const auto & text : {std::string("caf\xc3\xa9"), std::string("\xf0\x9f\xa6\x8a"),
            std::string("\\\"\\\\\\n\\u00e9\\uD83E\\uDD8A")}) {
        vp::tool_constraint value(nullptr, 1);
        feed(value, prefix);
        for (char byte : text) { feed(value, std::string(1, byte)); }
        feed(value, suffix);
        assert(value.permits("", true));
    }
    for (const auto & text : {std::string("\xc0\x80"), std::string("\xed\xa0\x80"),
            std::string("\xf4\x90\x80\x80"), std::string("\\x00"), std::string("\\uD800x"),
            std::string("\0", 1)}) {
        vp::tool_constraint value(nullptr, 1);
        feed(value, prefix);
        assert(!value.permits(text + suffix, false));
    }
    vp::tool_constraint partial(nullptr, 1);
    feed(partial, "plain \xc3");
    assert(!partial.permits("", true));
    assert(!partial.permits("bad", false));
    feed(partial, "\xa9");
    assert(partial.permits("", true));
    vp::tool_constraint wrong_position(nullptr, 1);
    assert(!wrong_position.permits("<tool_call>\xc3", false));
}

void depth_and_wire_bounds() {
    for (unsigned depth : {16u, 17u}) {
        vp::tool_constraint value(nullptr, 1);
        std::string body = "{}";
        for (unsigned level = 1; level < depth; ++level) { body = "{\"a\":" + body + "}"; }
        const std::string text = "<tool_call>{\"name\":\"vp_0\",\"arguments\":" + body + "}</tool_call>";
        assert(value.permits(text, false) == (depth == 16));
    }
    vp::tool_constraint exact(nullptr, 1);
    feed(exact, std::string(4094, 'a'));
    assert(exact.permits("", true));
    assert(!exact.permits("a", false));
    vp::tool_constraint escapes(nullptr, 1);
    feed(escapes, std::string(2047, '\n'));
    assert(!escapes.permits("\n", false));
    vp::tool_constraint long_piece(nullptr, 1);
    assert(!long_piece.permits(std::string(4097, 'a'), false));
}

void json_values_and_incomplete_suffix() {
    const std::string prefix = "<tool_call>{\"name\":\"vp_0\",\"arguments\":";
    const std::string suffix = "}</tool_call>";
    for (const auto & body : {"{}", "{\"v\":[null,true,false,-1,0,1.25e-3,{\"x\":[]}]}",
            "{\"v\":\"a marker </tool_call> inside a JSON string\"}"}) {
        vp::tool_constraint value(nullptr, 1);
        feed(value, prefix + body + suffix);
        assert(value.permits("", true));
    }
    for (const auto & body : {"[]", "null", "{\"v\":01}", "{\"v\":1.}", "{\"v\":NaN}",
            "{\"v\":+1}", "{\"v\":true,}", "{\"v\":[1,]}"}) {
        vp::tool_constraint value(nullptr, 1);
        assert(!value.permits(prefix + body + suffix, false));
    }
    vp::tool_constraint partial(nullptr, 1);
    feed(partial, prefix + "{}}</tool_");
    assert(!partial.permits("", true));
    assert(!partial.permits("call>x", false));
    feed(partial, "call>");
    assert(partial.permits("", true));
    assert(!partial.permits("\xc3", false)); // No incomplete UTF-8 after complete grammar.
}

void finite_selection_and_cancel() {
    vp::tool_constraint optional(nullptr, 1);
    std::vector<llama_token_data> ordinary{{0, 3.0f, 0.0f}, {1, 2.0f, 0.0f}};
    llama_token ordinary_choice = -1;
    assert(vp::select_candidate(ordinary, [&](llama_token id) {
        return optional.permits(id == 0 ? "No tool is needed." : call, false);
    }, [] { return false; }, ordinary_choice) == vp::selection::chosen);
    assert(ordinary_choice == 0); // An offered tool never forces a tool call.
    vp::tool_constraint value(nullptr, 1);
    feed(value, "<tool_");
    const std::vector<std::string> pieces{"call>{bad}", "call>{\"name\":\"vp_0\",\"arguments\":{}}</tool_call>"};
    const float inf = std::numeric_limits<float>::infinity();
    const float nan = std::numeric_limits<float>::quiet_NaN();
    std::vector<llama_token_data> candidates{{0, 100.0f, 0.0f}, {1, 1.0f, 0.0f},
        {2, inf, 0.0f}, {3, -inf, 0.0f}, {4, nan, 0.0f}};
    llama_token chosen = -1;
    assert(vp::select_candidate(candidates, [&](llama_token id) {
        assert(id == 0 || id == 1);
        return value.permits(pieces[id], false);
    }, [] { return false; }, chosen) == vp::selection::chosen);
    assert(chosen == 1);
    feed(value, pieces[chosen]);
    assert(value.permits("", true));
    candidates = {{1, 2.0f, 0.0f}, {0, 2.0f, 0.0f}};
    assert(vp::select_candidate(candidates, [](llama_token) { return true; },
        [] { return false; }, chosen) == vp::selection::chosen);
    assert(chosen == 0); // Same finite greedy tie order, not forced tool selection.
    candidates = {{0, nan, 0.0f}, {1, inf, 0.0f}};
    assert(vp::select_candidate(candidates, [](llama_token) { assert(false); return true; },
        [] { return false; }, chosen) == vp::selection::empty);
    assert(chosen == -1);
    candidates = {{0, 1.0f, 0.0f}};
    assert(vp::select_candidate(candidates, [](llama_token) { return false; },
        [] { return false; }, chosen) == vp::selection::empty);
    assert(chosen == -1);
    candidates = {{0, 1.0f, 0.0f}};
    assert(vp::select_candidate(candidates, [](llama_token) { assert(false); return true; },
        [] { return true; }, chosen) == vp::selection::cancelled);
    assert(chosen == -1);
    candidates = {{0, 2.0f, 0.0f}, {1, 1.0f, 0.0f}};
    unsigned inspected = 0;
    assert(vp::select_candidate(candidates, [&](llama_token) { ++inspected; return false; },
        [&] { return inspected != 0; }, chosen) == vp::selection::cancelled);
    assert(inspected == 1 && chosen == -1); // Cancellation also during candidate rejection.
}

void independent_turn_grammars() {
    auto value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    feed(*value, call);
    value->accept("", true);
    assert(!value->permits(call, false));
    // The native begin-turn path constructs a fresh grammar, not a clone of
    // the previous tool call's ended state or its old offered alias set.
    value = std::make_unique<vp::tool_constraint>(nullptr, 2);
    const std::string second = "<tool_call>{\"name\":\"vp_1\",\"arguments\":{}}</tool_call>";
    feed(*value, second);
    value->accept("", true);
    value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    assert(!value->permits(second, false));
    feed(*value, "A fresh ordinary answer remains permitted.");
    assert(value->permits("", true));
    value->accept("", true);
    value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    feed(*value, "<tool_");
    value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    feed(*value, call); // No unfinished marker from the old turn.
    assert(value->permits("", true));
    value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    feed(*value, "plain \xc3");
    assert(!value->permits("", true));
    value = std::make_unique<vp::tool_constraint>(nullptr, 1);
    feed(*value, call); // No incomplete UTF-8 state from the old turn.
    assert(value->permits("", true));
}
}

int main() {
    ordinary_and_optional();
    atomic_split_and_tail();
    preface_and_aliases();
    utf8_and_escapes();
    depth_and_wire_bounds();
    json_values_and_incomplete_suffix();
    finite_selection_and_cancel();
    independent_turn_grammars();
}
