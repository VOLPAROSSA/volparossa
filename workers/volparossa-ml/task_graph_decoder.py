# SPDX-License-Identifier: GPL-3.0-only AND MIT
"""Strict LMFE 0.11.3 adapter for a single greedy task-graph generation.

Only GraphDecoder construction imports the pinned optional backend. The worker
must still validate the complete original output independently: this schema does
not enforce earlier/unique dependencies, UTF-8 byte lengths or question meaning.
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

import importlib
import importlib.metadata


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

    def __init__(self, tokenizer, check, accepts_graph_bytes):
        self.check = check
        self.tokenizer = tokenizer
        self.accepts_graph_bytes = accepts_graph_bytes
        parser, data, base, token_list = _load_backend(check)
        self.parser = parser
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
        if (type(prompt_ids) is not list or not 1 <= len(prompt_ids) <= 512
                or any(type(token) is not int or not 0 <= token < self.vocab_size for token in prompt_ids)
                or type(max_new_tokens) is not int or not 1 <= max_new_tokens <= 384):
            raise DecoderError("TASK_GRAPH_DECODER_ATTEMPT_INVALID")
        try:
            enforcer = self.enforcer(self.data, self.parser(graph_schema()))
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
                accepted = len(raw) <= 16384 and decoder.accepts_graph_bytes(raw) is True
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
