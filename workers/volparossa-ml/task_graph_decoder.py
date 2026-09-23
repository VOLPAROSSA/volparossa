# SPDX-License-Identifier: GPL-3.0-only AND MIT
"""Strict LMFE 0.11.3 adapter for a single greedy task-graph generation.

Only GraphDecoder construction imports the pinned optional backend. The worker
must still validate the complete original output independently. Opt-in graph
rules constrain question form and prior dependencies, never question meaning.
No generated text is returned, rewritten, logged or saved by this module.

The tokenizer adaptation and TokenEnforcer overrides derive from:
https://github.com/noamgat/lm-format-enforcer/tree/v0.11.3/lmformatenforcer
(tokenenforcer.py and integrations/transformers.py). Unlike upstream's generic
batch adapter, parser errors never log a prefix or become a forced EOS.

MIT License

Copyright (c) 2023 Noam Gat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import copy
from bisect import bisect_left
import importlib
import importlib.metadata
import json


class DecoderError(Exception):
    """Fixed, non-content-bearing worker failure; never carries parser text."""


def decoder_metadata():
    return {"implementation": "lm-format-enforcer", "version": "0.11.3",
            "adapter_version": 1, "schema_version": 3,
            "dependencies": {"interegular": "0.3.3", "pydantic": "1.10.24"}}


def graph_schema(question_max_bytes=512):
    # LMFE's numeric enum path converts numbers to text correctly; its 0.11.3
    # numeric const path does not. No question/task/dependency is preselected.
    if type(question_max_bytes) is not int or not 1 <= question_max_bytes <= 512:
        raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
    return {"type": "object", "required": ["version", "tasks"], "additionalProperties": False,
            "properties": {"version": {"type": "integer", "enum": [3]},
                "tasks": {"type": "array", "minItems": 1, "maxItems": 4, "items": {
                    "type": "object", "required": ["question", "depends_on"],
                    "additionalProperties": False, "properties": {
                        "question": {"type": "string", "minLength": 1, "maxLength": question_max_bytes},
                        "depends_on": {"type": "array", "minItems": 0, "maxItems": 3,
                            "items": {"type": "integer", "enum": [0, 1, 2]}}}}}}}


def _load_backend(check):
    for name, expected in (("lm-format-enforcer", "0.11.3"),
                           ("interegular", "0.3.3"), ("pydantic", "1.10.24")):
        check()
        try:
            actual = importlib.metadata.version(name)
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_UNAVAILABLE") from None
        if actual != expected:
            raise DecoderError("TASK_GRAPH_DECODER_VERSION_MISMATCH")
    modules = []
    for name in ("jsonschemaparser", "tokenenforcer", "tokenlist"):
        check()
        try:
            modules.append(importlib.import_module("lmformatenforcer." + name))
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_UNAVAILABLE") from None
    check()
    try:
        return (modules[0].JsonSchemaParser, modules[1].TokenEnforcerTokenizerData,
                modules[1].TokenEnforcer, modules[2].TokenList)
    except Exception:
        raise DecoderError("TASK_GRAPH_DECODER_UNAVAILABLE") from None


class _SourceQuoteTable:
    """Sorted canonical lexemes: no allocation of a trie node for every prefix."""

    def __init__(self, values, check):
        if type(values) is not list or not 1 <= len(values) <= 65536:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
        pairs, total = [], 0
        for value in values:
            check()
            if type(value) is not str or not value.strip() or "\0" in value:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
            try:
                size = len(value.encode("utf-8"))
            except UnicodeError:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None
            total += size
            if not 1 <= size <= 128 or total > 8 * 1024 * 1024:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
            pairs.append((json.dumps(value, ensure_ascii=False), value))
        check()
        pairs.sort()
        self.lexemes, self.values = tuple(zip(*pairs))
        self.original = tuple(values)
        check()


def _source_quote_tables(schema, check):
    tables = []

    def visit(value):
        if type(value) is dict:
            if "x-volparossa-source-quotes" in value:
                if value["x-volparossa-source-quotes"] is not True or value.get("type") != "string":
                    raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
                tables.append(_SourceQuoteTable(value.get("enum"), check))
            for key, child in value.items():
                if key != "enum":
                    visit(child)
        elif type(value) is list:
            for child in value:
                visit(child)

    visit(schema)
    return tables


def _source_quote_state(base):
    class SourceQuoteState(base):
        # Remain a StringParsingState so the pinned parent retains exact decoded
        # last_parsed_string and recognizes strings when popping its stack.
        def __init__(self, root, table):
            super().__init__(root, table.original, require_opening_quote=True)
            self.table, self.prefix = table, ""
            self.low, self.high = 0, len(table.lexemes)
            self._allowed = None

        def get_allowed_characters(self):
            if self.seen_closing_quote:
                return ""
            if not self.seen_opening_quote:
                return '" \t\r\n'
            if self._allowed is None:
                offset = len(self.prefix)
                self._allowed = "".join(sorted({self.table.lexemes[index][offset]
                    for index in range(self.low, self.high)}))
            return self._allowed

        def add_character(self, character):
            if not self.seen_opening_quote and character in " \t\r\n":
                return self
            if character not in self.get_allowed_characters():
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
            updated = copy.copy(self)
            updated.prefix += character
            # Every lexeme begins with a quote, so an exclusive lexical upper
            # bound always exists, including for a literal U+10FFFF codepoint.
            upper = updated.prefix
            while ord(upper[-1]) == 0x10FFFF:
                upper = upper[:-1]
            upper = upper[:-1] + chr(ord(upper[-1]) + 1)
            updated.low = bisect_left(self.table.lexemes, updated.prefix, self.low, self.high)
            updated.high = bisect_left(self.table.lexemes, upper, updated.low, self.high)
            updated.seen_opening_quote = True
            updated.seen_closing_quote = self.table.lexemes[updated.low] == updated.prefix
            updated.parsed_string = self.table.values[updated.low] if updated.seen_closing_quote else ""
            updated._allowed = None
            return updated

        def can_end(self):
            return self.seen_closing_quote

    return SourceQuoteState


def _install_source_quote_parser(module, tables):
    original = getattr(module.get_parser, "_volparossa_original", module.get_parser)
    state = _source_quote_state(module.StringParsingState)
    cached = {}

    def get_parser(root, schema):
        extras = schema.extras or {}
        if "x-volparossa-source-quotes" not in extras:
            return original(root, schema)
        if extras["x-volparossa-source-quotes"] is not True or schema.type != "string":
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
        known = cached.get(id(schema))
        if known is None:
            values = tuple(schema.enum or ())
            table = next((table for table in tables if table.original == values), None)
            if table is None:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
            cached[id(schema)] = (schema, table)
        else:
            table = known[1]
        return state(root, table)

    get_parser._volparossa_original = original
    module.get_parser = get_parser


class _CompactJsonParser:
    """Explicit ordered JSON: remove formatting, never whitespace inside strings."""

    def __init__(self, inner, string_type):
        self.inner, self.string_type = inner, string_type

    def _inside_string(self):
        return any(isinstance(state, self.string_type) and state.seen_opening_quote
                   and not state.seen_closing_quote for state in self.inner.object_stack)

    @property
    def config(self):
        return self.inner.config

    @config.setter
    def config(self, config):
        # TokenEnforcer replaces parser.config to add the tokenizer alphabet.
        # Preserve our explicit field order through that pinned upstream step.
        config = copy.copy(config)
        config.force_json_field_order = True
        self.inner.config = config
        self.inner.context.alphabet_without_quotes = config.alphabet.replace('"', '')

    def add_character(self, character):
        inner = self.inner.add_character(character)
        result = _CompactJsonParser(inner, self.string_type)
        if result._inside_string():
            # Upstream counts whitespace globally, even inside a JSON string.
            # It is source data here; structural formatting remains forbidden.
            inner.num_consecutive_whitespaces = 0
        return result

    def get_allowed_characters(self):
        allowed = self.inner.get_allowed_characters()
        return allowed if self._inside_string() else "".join(c for c in allowed if c not in " \t\r\n")

    def can_end(self):
        return self.inner.can_end()

    def cache_key(self):
        return self.inner.cache_key()

    def shortcut_key(self):
        return self.inner.shortcut_key()


class _UniquePrinciplesJsonParser:
    """Branch-local enum exclusion only at reasoning[*].principle.

    Use the pinned syntax parser's object stack, not substrings of quoted source
    or reasoning text. Keys themselves have a different ObjectParsingStage and
    cannot be mistaken for the preceding property's value.
    """

    def __init__(self, inner, string_type, choices, used=frozenset()):
        self.inner, self.string_type, self.choices, self.used = inner, string_type, choices, used

    @property
    def config(self):
        return self.inner.config

    @config.setter
    def config(self, config):
        self.inner.config = config

    def _principle_state(self):
        stack = self.inner.inner.object_stack  # The explicitly ordered compact parser.
        if not stack or not isinstance(stack[-1], self.string_type):
            return None
        objects = [state for state in stack if hasattr(state, "current_key")]
        if (len(objects) != 2 or objects[0].current_key != "reasoning"
                or objects[1].current_key != "principle"
                or getattr(objects[1].current_stage, "name", None) != "PARSING_VALUE"):
            return None
        return stack[-1]

    def _characters(self, state):
        prefix = state.parsed_string
        choices = [name for name in self.choices if name not in self.used and name.startswith(prefix)]
        return {name[len(prefix)] if len(name) > len(prefix) else '"' for name in choices}

    def add_character(self, character):
        used = self.used
        state = self._principle_state()
        if state is not None and state.seen_opening_quote and not state.seen_closing_quote:
            if character not in self._characters(state):
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
            if character == '"':
                used = used | {state.parsed_string}
        return _UniquePrinciplesJsonParser(self.inner.add_character(character), self.string_type, self.choices, used)

    def get_allowed_characters(self):
        allowed = self.inner.get_allowed_characters()
        state = self._principle_state()
        if state is None or not state.seen_opening_quote or state.seen_closing_quote:
            return allowed
        remaining = self._characters(state)
        return "".join(character for character in allowed if character in remaining)

    def can_end(self):
        return self.inner.can_end()

    def cache_key(self):
        # Identical syntax states with different previous rows are not equivalent.
        return None

    def shortcut_key(self):
        return None if self._principle_state() is not None else self.inner.shortcut_key()


class _GraphRules:
    """Immutable prefix state for the one fixed graph schema, not a JSON repairer."""

    def __init__(self, goal, requirement, question_max_bytes=512):
        if type(question_max_bytes) is not int or not 1 <= question_max_bytes <= 512:
            raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
        self.question_max_bytes = question_max_bytes
        self.goal, self.requirement = goal.strip(), requirement
        self.questions, self.parents = (), ()
        self.has_dependency = False
        self.text, self.text_bytes, self.escape, self.high_surrogate = "", 0, "", None
        self._literal('{"version":3,"tasks":[{"question":"', "question")

    def _literal(self, text, after):
        self.phase, self.literal, self.after = "literal", text, after

    def _question_complete(self):
        value = self.text.strip()
        return (bool(value) and value.endswith("?") and value != self.goal
                and value not in self.questions and self.escape == "" and self.high_surrogate is None)

    def _text_can_finish(self, text, size):
        if size < self.question_max_bytes - 1:
            return True
        value = text.strip()
        if value and value.endswith("?") and value != self.goal and value not in self.questions:
            return True
        # With one byte left, '?' is the only possible non-whitespace ending.
        # Do not admit a prefix whose only completion copies a forbidden question.
        value = (text + "?").strip()
        return size == self.question_max_bytes - 1 and value != self.goal and value not in self.questions

    def _append_text(self, character):
        if character == "\0" or 0xD800 <= ord(character) <= 0xDFFF:
            return False
        size = self.text_bytes + len(character.encode("utf-8"))
        if size > self.question_max_bytes:
            return False
        self.text += character
        self.text_bytes = size
        # Do not enter an irreversibly overfull/non-question/duplicate scalar.
        return self._text_can_finish(self.text, size)

    def _scalar_range_can_finish(self, low, high):
        remaining = self.question_max_bytes - self.text_bytes
        # A scalar that leaves room can still be followed by a question mark.
        # Split the BMP around surrogate code units; NUL is never admissible.
        for first, last, width in ((1, 0x7f, 1), (0x80, 0x7ff, 2), (0x800, 0xd7ff, 3),
                                   (0xe000, 0xffff, 3), (0x10000, 0x10ffff, 4)):
            start, end = max(low, first), min(high, last)
            if width < remaining and start <= end:
                if width + 1 < remaining:
                    return True
                # One byte would remain: check that '?' can still finish the
                # question. At most the few forbidden questions and leading
                # whitespace can reject distinct scalars before a viable one.
                if any(self._text_can_finish(self.text + chr(scalar), self.text_bytes + width)
                       for scalar in range(start, end + 1)):
                    return True
        # Exactly filling the byte budget is viable only with '?' or trailing
        # whitespace after an already complete, distinct question. This bounded
        # set covers Python's Unicode whitespace without scanning 65,536 values
        # for every partial escape in the tokenizer trie.
        endings = "?\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
        for character in endings:
            if low <= ord(character) <= high and len(character.encode("utf-8")) == remaining:
                if self._text_can_finish(self.text + character, self.question_max_bytes):
                    return True
        return False

    def _unicode_prefix_can_finish(self, digits):
        # A hexadecimal prefix describes one interval of UTF-16 code units.
        # Admit it only if some completion encodes an admissible scalar; a high
        # surrogate also needs a possible low-surrogate continuation and room.
        shift = 4 * (4 - len(digits))
        low = int(digits or "0", 16) << shift
        high = low + (1 << shift) - 1
        if self.high_surrogate is not None:
            low, high = max(low, 0xdc00), min(high, 0xdfff)
            base = 0x10000 + (self.high_surrogate - 0xd800) * 0x400
            return low <= high and self._scalar_range_can_finish(base + low - 0xdc00, base + high - 0xdc00)
        if self._scalar_range_can_finish(low, high):
            return True
        low, high = max(low, 0xd800), min(high, 0xdbff)
        return low <= high and self._scalar_range_can_finish(
            0x10000 + (low - 0xd800) * 0x400, 0x10000 + (high - 0xd800) * 0x400 + 0x3ff)

    def _question_character(self, character):
        if self.escape == "\\":
            self.escape = ""
            if character == "u":
                self.escape = "u"
                return self._unicode_prefix_can_finish("")
            escaped = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
            return (self.high_surrogate is None and character in escaped
                    and self._append_text(escaped[character]))
        if self.escape.startswith("u"):
            if character not in "0123456789abcdefABCDEF":
                return False
            self.escape += character
            if not self._unicode_prefix_can_finish(self.escape[1:]):
                return False
            if len(self.escape) < 5:
                return True
            codepoint = int(self.escape[1:], 16)
            self.escape = ""
            if self.high_surrogate is not None:
                if not 0xDC00 <= codepoint <= 0xDFFF:
                    return False
                codepoint = 0x10000 + ((self.high_surrogate - 0xD800) << 10) + codepoint - 0xDC00
                self.high_surrogate = None
            elif 0xD800 <= codepoint <= 0xDBFF:
                if self.text_bytes + 4 > self.question_max_bytes:
                    return False
                self.high_surrogate = codepoint
                return True
            return self._append_text(chr(codepoint))
        if character == "\\":
            self.escape = "\\"
            return self._unicode_prefix_can_finish("")
        if self.high_surrogate is not None:
            return False
        if character == '"':
            if not self._question_complete():
                return False
            self.questions += (self.text.strip(),)
            self.parents = ()
            self._literal(',"depends_on":[', "parents")
            return True
        return ord(character) >= 0x20 and self._append_text(character)

    def advance(self, character):
        if type(character) is not str or len(character) != 1:
            return None
        updated = copy.copy(self)
        if self.phase == "literal":
            if character != self.literal[0]:
                return None
            updated.literal = self.literal[1:]
            if not updated.literal:
                updated.phase = self.after
        elif self.phase == "question":
            if not updated._question_character(character):
                return None
        elif self.phase in ("parents", "parent_required", "parent_after"):
            available = {str(index) for index in range(len(self.questions) - 1) if index not in self.parents}
            if self.phase != "parent_after" and character in available:
                updated.parents += (int(character),)
                updated.has_dependency = True
                updated.phase = "parent_after"
            elif self.phase == "parent_after" and character == "," and available:
                updated.phase = "parent_required"
            elif self.phase != "parent_required" and character == "]":
                if self.requirement and len(self.questions) == 4 and not self.has_dependency:
                    return None
                updated._literal("}", "tasks_after")
            else:
                return None
        elif self.phase == "tasks_after":
            if character == "," and len(self.questions) < 4:
                updated.text, updated.text_bytes, updated.escape, updated.high_surrogate = "", 0, "", None
                updated._literal('{"question":"', "question")
            elif character == "]" and (not self.requirement or len(self.questions) >= 2 and self.has_dependency):
                updated._literal("}", "done")
            else:
                return None
        else:
            return None
        return updated

    def allows(self, character):
        # The tokenizer trie asks about the whole alphabet at every visited
        # prefix. Do not clone/append a graph state for every candidate letter:
        # only the selected trie edge needs advance(). Keep exceptional escape
        # and boundary handling identical to the authoritative transition.
        if type(character) is not str or len(character) != 1:
            return False
        if self.phase == "literal":
            return character == self.literal[0]
        if self.phase != "question" or self.escape or self.high_surrogate is not None:
            return self.advance(character) is not None
        if character == '"':
            return self._question_complete()
        if character == "\\":
            return self._unicode_prefix_can_finish("")
        codepoint = ord(character)
        if codepoint < 0x20 or 0xD800 <= codepoint <= 0xDFFF:
            return False
        if self.text_bytes <= self.question_max_bytes - 6:
            return True  # Even a four-byte scalar leaves two bytes for completion.
        size = self.text_bytes + len(character.encode("utf-8"))
        return size <= self.question_max_bytes and self._text_can_finish(self.text + character, size)


class _GraphJsonParser:
    """Intersect pinned JSON syntax with branch-local graph contract constraints."""

    def __init__(self, inner, rules):
        self.inner, self.rules = inner, rules
        self._allowed = None

    @property
    def config(self):
        return self.inner.config

    @config.setter
    def config(self, config):
        self.inner.config = config
        self._allowed = None

    def add_character(self, character):
        rules = self.rules.advance(character)
        if rules is None:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
        return _GraphJsonParser(self.inner.add_character(character), rules)

    def get_allowed_characters(self):
        if self._allowed is None:
            self._allowed = "".join(character for character in dict.fromkeys(self.inner.get_allowed_characters())
                                    if self.rules.allows(character))
        return self._allowed

    def can_end(self):
        return self.rules.phase == "done" and self.inner.can_end()

    def cache_key(self):
        return None

    def shortcut_key(self):
        # LMFE's free-text shortcut bypasses per-character filtering, including
        # a question's closing quote. These graph constraints must see each one.
        return None


def _strict_enforcer(base, token_list):
    class StrictEnforcer(base):
        def _collect_allowed_tokens(self, parser, tree_node, allowed, shortcut_key):
            if not isinstance(parser, _GraphJsonParser):
                return super()._collect_allowed_tokens(parser, tree_node, allowed, shortcut_key)
            # Same traversal as pinned LMFE, but intersect the available trie
            # edges before applying graph rules. Filtering the whole tokenizer
            # alphabet at every node repeats work for characters absent from
            # that node (including every terminal leaf). Graph has no freetext
            # shortcut: quotes, escapes and byte boundaries still use the
            # authoritative parser transition on every explored edge.
            allowed.extend(tree_node.tokens)
            if not tree_node.children:
                return
            syntax = parser.inner.get_allowed_characters()
            for character, child in tree_node.children.items():
                if character in syntax and parser.rules.allows(character):
                    self._collect_allowed_tokens(parser.add_character(character), child, allowed, None)

        # These error-handling overrides deliberately do NOT call the upstream
        # implementations, which log parser plaintext and/or force EOS.
        def _compute_allowed_tokens(self, _state_tokens, state):
            try:
                key = state.parser.cache_key()
                if key is not None and key in self.allowed_token_cache:
                    state.allowed_tokens = self.allowed_token_cache[key]
                    return
                allowed = token_list(self.use_bitmask, self.vocab_size)
                self._collect_allowed_tokens(state.parser, self.tokenizer_tree.root,
                                             allowed, state.parser.shortcut_key())
                if state.parser.can_end():
                    allowed.append(self.eos_token_id)
                if not allowed.allowed_tokens:
                    raise DecoderError("TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS")
                state.allowed_tokens = allowed
                if key is not None:
                    self.allowed_token_cache[key] = allowed
            except DecoderError:
                raise
            except Exception:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None

        def _apply_new_characters(self, state, token_sequence):
            try:
                result = self.OutputTensorState(parser=state.parser)
                token = token_sequence[-1]
                if token in self.tokenizer_tree.new_word_tokens:
                    result.current_word_tokens = [token]
                    characters = self.tokenizer_tree.tokens_to_strs[token]
                else:
                    result.current_word_tokens = state.current_word_tokens + [token]
                    previous = self.decoder(state.current_word_tokens)
                    current = self.decoder(result.current_word_tokens)
                    if not current.startswith(previous):
                        raise DecoderError("TASK_GRAPH_DECODER_TOKENIZATION_CHANGED")
                    characters = current[len(previous):]
                for character in characters:
                    result.parser = result.parser.add_character(character)
                return result
            except DecoderError:
                raise
            except Exception:
                raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None

    return StrictEnforcer


class GraphDecoder:
    """Build once per worker, then new_attempt(prompt_ids, remaining_tokens).

    `check` is the owner's existing synchronous pause/cancel/deadline checkpoint.
    `accepts_graph_bytes` must return a bool using the worker's independent strict
    complete-graph validator bound to the original public question. It is NOT a
    model callback, text repair or semantic-quality assertion.
    """

    def __init__(self, tokenizer, check, accepts_graph_bytes, *, schema=None,
                 prompt_limit=512, output_limit=16384, generation_limit=384,
                 ordered_json=False, graph_goal=None, graph_requirement=None, unique_principles=None,
                 graph_question_max_bytes=512):
        # Only compiled worker code supplies this schema/limits, never a dataset.
        # Defaults preserve the original graph profile and historical contract.
        if (type(prompt_limit) is not int or not 1 <= prompt_limit <= 1024
                or type(output_limit) is not int or not 1 <= output_limit <= 16384
                or type(generation_limit) is not int or not 1 <= generation_limit <= 512
                or type(graph_question_max_bytes) is not int or not 1 <= graph_question_max_bytes <= 512
                or graph_goal is None and graph_question_max_bytes != 512
                or type(ordered_json) is not bool
                or schema is not None and type(schema) is not dict):
            raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
        self.check = check
        self.tokenizer = tokenizer
        self.accepts_graph_bytes = accepts_graph_bytes
        self.schema = graph_schema() if schema is None else schema
        self.unique_principles = None
        if unique_principles is not None:
            try:
                choices = tuple(unique_principles)
                value_schema = self.schema["properties"]["reasoning"]["items"]["properties"]["principle"]
                valid = (type(unique_principles) in (list, tuple) and len(choices) == 14
                         and all(type(name) is str and name.isascii() and name.isalpha() and 1 <= len(name) <= 32
                                 for name in choices) and len(set(choices)) == 14
                         and value_schema["type"] == "string" and tuple(value_schema["enum"]) == choices
                         and ordered_json is True and graph_goal is None and graph_requirement is None)
            except (KeyError, TypeError):
                valid = False
            if not valid:
                raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
            self.unique_principles = choices
        self.graph_goal, self.graph_requirement = graph_goal, graph_requirement
        self.graph_question_max_bytes = graph_question_max_bytes
        if graph_goal is not None or graph_requirement is not None:
            try:
                valid_goal = (type(graph_goal) is str and bool(graph_goal.strip()) and "\0" not in graph_goal
                              and 1 <= len(graph_goal.encode("utf-8")) <= 512)
            except UnicodeError:
                valid_goal = False
            if (not valid_goal or graph_requirement not in (None, "dependent_analysis_v1")
                    or (prompt_limit, output_limit, generation_limit) != (512, 16384, 384)):
                raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
            expected = graph_schema(graph_question_max_bytes)
            if graph_requirement:
                expected["properties"]["tasks"]["minItems"] = 2
            if schema is None:
                self.schema = expected
            elif schema != expected:
                raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
            ordered_json = True
        self.prompt_limit, self.output_limit = prompt_limit, output_limit
        self.generation_limit = generation_limit
        parser, data, base, token_list = _load_backend(check)
        self.parser = parser
        self.parser_options = {}
        self.ordered_string_type = None
        if ordered_json:
            check()
            try:
                config_type = importlib.import_module(
                    "lmformatenforcer.characterlevelparser").CharacterLevelParserConfig
                self.parser_options["config"] = config_type(force_json_field_order=True)
                parser_module = importlib.import_module("lmformatenforcer.jsonschemaparser")
                self.ordered_string_type = parser_module.StringParsingState
            except Exception:
                raise DecoderError("TASK_GRAPH_DECODER_UNAVAILABLE") from None
            tables = _source_quote_tables(self.schema, check)
            if tables:
                _install_source_quote_parser(parser_module, tables)
        self.enforcer = _strict_enforcer(base, token_list)
        check()
        try:
            self.vocab_size = len(tokenizer)
            self.eos = tokenizer.eos_token_id
            self.special = frozenset(tokenizer.all_special_ids)
            if (type(self.vocab_size) is not int or not 1 <= self.vocab_size <= 131072
                    or type(self.eos) is not int or not 0 <= self.eos < self.vocab_size
                    or self.eos not in self.special):
                raise ValueError()
            zero = tokenizer.encode("0")[-1]
            if self._decode([zero]) != "0":
                raise ValueError()
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_TOKENIZER_INVALID") from None
        regular = []
        for token in range(self.vocab_size):
            # Each iteration handles at most two tokenizer decodes. The actual
            # owner's deadline and control channel remain live during setup.
            check()
            if token in self.special:
                continue
            try:
                after_zero = self._decode([zero, token])[1:]
                alone = self._decode([token])
                regular.append((token, after_zero, len(after_zero) > len(alone)))
            except Exception:
                raise DecoderError("TASK_GRAPH_DECODER_TOKENIZER_INVALID") from None
        check()
        try:
            # The incomplete UTF-8 view is parser-only, exactly as in LMFE's
            # adapter. Final worker decoding/artifact bytes never use rstrip.
            self.data = data(regular, lambda tokens: self._decode(tokens).rstrip("\ufffd"),
                             self.eos, False, self.vocab_size)
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_TOKENIZER_INVALID") from None
        check()
        self.metadata = decoder_metadata()

    def _decode(self, tokens):
        return self.tokenizer.decode(tokens, skip_special_tokens=False,
                                     clean_up_tokenization_spaces=False)

    def new_attempt(self, prompt_ids, max_new_tokens):
        self.check()
        if (type(prompt_ids) is not list or not 1 <= len(prompt_ids) <= self.prompt_limit
                or any(type(token) is not int or not 0 <= token < self.vocab_size for token in prompt_ids)
                or type(max_new_tokens) is not int or not 1 <= max_new_tokens <= self.generation_limit):
            raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
        try:
            parser = self.parser(copy.deepcopy(self.schema), **self.parser_options)
            if self.ordered_string_type is not None:
                parser = _CompactJsonParser(parser, self.ordered_string_type)
            if self.unique_principles is not None:
                parser = _UniquePrinciplesJsonParser(parser, self.ordered_string_type, self.unique_principles)
            if self.graph_goal is not None:
                parser = _GraphJsonParser(parser, _GraphRules(self.graph_goal, self.graph_requirement,
                                                            self.graph_question_max_bytes))
            enforcer = self.enforcer(self.data, parser)
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None
        self.check()
        return _Attempt(self, enforcer, tuple(prompt_ids), max_new_tokens)


class _Attempt:
    def __init__(self, decoder, enforcer, prompt, limit):
        self.decoder, self.enforcer = decoder, enforcer
        self.prompt, self.limit = prompt, limit
        self.previous, self.allowed = None, None

    def __call__(self, batch_id, sent):
        decoder = self.decoder
        decoder.check()
        try:
            sequence = sent.tolist()
            if (type(batch_id) is not int or batch_id != 0 or type(sequence) is not list
                    or any(type(token) is not int or not 0 <= token < decoder.vocab_size for token in sequence)):
                raise DecoderError("TASK_GRAPH_DECODER_PREFIX_CHANGED")
            tokens = tuple(sequence)
            generated = tokens[len(self.prompt):]
            if (tokens[:len(self.prompt)] != self.prompt or not 0 <= len(generated) < self.limit
                    or any(token in decoder.special for token in generated)):
                raise DecoderError("TASK_GRAPH_DECODER_PREFIX_CHANGED")
            if self.previous is None:
                if tokens != self.prompt:
                    raise DecoderError("TASK_GRAPH_DECODER_PREFIX_CHANGED")
            elif tokens != self.previous and (tokens[:-1] != self.previous or tokens[-1] not in self.allowed):
                raise DecoderError("TASK_GRAPH_DECODER_PREFIX_CHANGED")
            allowed = list(self.enforcer.get_allowed_tokens(sequence).allowed_tokens)
            if any(type(token) is not int or not 0 <= token < decoder.vocab_size
                   or token in decoder.special and token != decoder.eos for token in allowed):
                raise DecoderError("TASK_GRAPH_DECODER_ALLOWED_TOKENS_INVALID")
            if decoder.eos in allowed:
                raw = decoder._decode(list(generated)).encode("utf-8")
                accepted = len(raw) <= decoder.output_limit and decoder.accepts_graph_bytes(raw) is True
                if not accepted:
                    allowed = [token for token in allowed if token != decoder.eos]
            if not allowed:
                # Distinguish complete-syntax EOS rejection from an empty
                # parser prefix, without retaining the generated text.
                raise DecoderError("TASK_GRAPH_DECODER_REJECTED_EOS")
        except DecoderError:
            raise
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None
        decoder.check()
        self.previous, self.allowed = tokens, frozenset(allowed)
        return allowed
