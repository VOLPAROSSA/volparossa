# SPDX-License-Identifier: GPL-3.0-only AND MIT
"""Strict LMFE 0.11.3 adapter for a single greedy task-graph generation.

Only GraphDecoder construction imports the pinned optional backend. The worker
must still validate the complete original output independently. Opt-in graph
rules constrain question form and prior dependencies, never question meaning.
No generated text is returned, rewritten, logged or saved by this module.

The tokenizer adaptation and two TokenEnforcer overrides derive from:
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


def graph_schema():
    # LMFE's numeric enum path converts numbers to text correctly; its 0.11.3
    # numeric const path does not. No question/task/dependency is preselected.
    return {"type": "object", "required": ["version", "tasks"], "additionalProperties": False,
            "properties": {"version": {"type": "integer", "enum": [3]},
                "tasks": {"type": "array", "minItems": 1, "maxItems": 4, "items": {
                    "type": "object", "required": ["question", "depends_on"],
                    "additionalProperties": False, "properties": {
                        "question": {"type": "string", "minLength": 1, "maxLength": 512},
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


class _GraphRules:
    """Immutable prefix state for the one fixed graph schema, not a JSON repairer."""

    def __init__(self, goal, requirement):
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

    def _append_text(self, character):
        if character == "\0" or 0xD800 <= ord(character) <= 0xDFFF:
            return False
        size = self.text_bytes + len(character.encode("utf-8"))
        if size > 512:
            return False
        self.text += character
        self.text_bytes = size
        # Do not enter an irreversibly overfull/non-question scalar.
        return size < 512 or self._question_complete()

    def _question_character(self, character):
        if self.escape == "\\":
            self.escape = ""
            if character == "u":
                self.escape = "u"
                return True
            escaped = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
            return (self.high_surrogate is None and character in escaped
                    and self._append_text(escaped[character]))
        if self.escape.startswith("u"):
            if character not in "0123456789abcdefABCDEF":
                return False
            self.escape += character
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
                if self.text_bytes + 4 > 512:
                    return False
                self.high_surrogate = codepoint
                return True
            return self._append_text(chr(codepoint))
        if character == "\\":
            self.escape = "\\"
            return True
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


class _GraphJsonParser:
    """Intersect pinned JSON syntax with branch-local graph contract constraints."""

    def __init__(self, inner, rules):
        self.inner, self.rules = inner, rules

    @property
    def config(self):
        return self.inner.config

    @config.setter
    def config(self, config):
        self.inner.config = config

    def add_character(self, character):
        rules = self.rules.advance(character)
        if rules is None:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED")
        return _GraphJsonParser(self.inner.add_character(character), rules)

    def get_allowed_characters(self):
        return "".join(character for character in dict.fromkeys(self.inner.get_allowed_characters())
                       if self.rules.advance(character) is not None)

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
        # These overrides deliberately do NOT call the upstream implementations:
        # they catch parser errors by logging plaintext and/or forcing EOS.
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
                 ordered_json=False, graph_goal=None, graph_requirement=None):
        # Only compiled worker code supplies this schema/limits, never a dataset.
        # Defaults preserve the original graph profile and historical contract.
        if (type(prompt_limit) is not int or not 1 <= prompt_limit <= 1024
                or type(output_limit) is not int or not 1 <= output_limit <= 16384
                or type(generation_limit) is not int or not 1 <= generation_limit <= 512
                or type(ordered_json) is not bool
                or schema is not None and type(schema) is not dict):
            raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
        self.check = check
        self.tokenizer = tokenizer
        self.accepts_graph_bytes = accepts_graph_bytes
        self.schema = graph_schema() if schema is None else schema
        self.graph_goal, self.graph_requirement = graph_goal, graph_requirement
        if graph_goal is not None or graph_requirement is not None:
            try:
                valid_goal = (type(graph_goal) is str and bool(graph_goal.strip()) and "\0" not in graph_goal
                              and 1 <= len(graph_goal.encode("utf-8")) <= 512)
            except UnicodeError:
                valid_goal = False
            if (not valid_goal or graph_requirement not in (None, "dependent_analysis_v1")
                    or (prompt_limit, output_limit, generation_limit) != (512, 16384, 384)):
                raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
            expected = graph_schema()
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
            if self.graph_goal is not None:
                parser = _GraphJsonParser(parser, _GraphRules(self.graph_goal, self.graph_requirement))
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
                raise DecoderError("TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS")
        except DecoderError:
            raise
        except Exception:
            raise DecoderError("TASK_GRAPH_DECODER_PARSER_FAILED") from None
        decoder.check()
        self.previous, self.allowed = tokens, frozenset(allowed)
        return allowed
