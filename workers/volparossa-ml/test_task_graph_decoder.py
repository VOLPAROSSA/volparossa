#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adapter contract tests with tiny core doubles; no LMFE/model execution claim."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("graph_decoder", Path(__file__).with_name("task_graph_decoder.py"))
DECODER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECODER)
RAW = b'{ "version":3, "tasks":[{"question":"Which limit applies?","depends_on":[]}] }'


class Tokenizer:
    eos_token_id = 2
    all_special_ids = [0, 2]
    pieces = ["<start>", "0", "<end>", "{", "}", " ", "?", RAW.decode(), "\ufffd", "\ufffd", "word", "!"]

    def __init__(self):
        self.calls = 0

    def __len__(self):
        return len(self.pieces)

    def encode(self, text):
        assert text == "0"
        return [1]

    def decode(self, tokens, **options):
        assert options == {"skip_special_tokens": False, "clean_up_tokenization_spaces": False}
        self.calls += 1
        text, index = "", 0
        while index < len(tokens):
            token = tokens[index]
            if tokens[index:index + 2] == [8, 9]:
                text += "é"
                index += 2
            else:
                text += (" " if token == 10 and index > 0 else "") + self.pieces[token]
                index += 1
        return text


class TokenList:
    def __init__(self, bitmask, _size):
        assert not bitmask
        self.allowed_tokens = []

    def append(self, token):
        self.allowed_tokens.append(token)

    def extend(self, tokens):
        self.allowed_tokens.extend(tokens)


class Data:
    def __init__(self, regular, decoder, eos, bitmask, size):
        self.regular_tokens, self.decoder, self.eos_token_id = regular, decoder, eos
        self.use_bitmask, self.vocab_size = bitmask, size
        self.tokenizer_tree = SimpleNamespace(root=object(),
            new_word_tokens={token for token, _text, newword in regular if newword},
            tokens_to_strs={token: text for token, text, _newword in regular})


class Parser:
    def __init__(self, schema, text=""):
        self.schema, self.text = schema, text

    def add_character(self, character):
        if character == "!":
            raise ValueError("PRIVATE PARSER CONTENT")
        return Parser(self.schema, self.text + character)

    def can_end(self):
        try:
            return isinstance(json.loads(self.text), dict)
        except ValueError:
            return False

    def cache_key(self):
        return None

    def shortcut_key(self):
        return None


class Core:
    """Only LMFE's state-dispatch interface; deliberately not a schema parser."""

    class OutputTensorState:
        def __init__(self, parser):
            self.parser, self.current_word_tokens, self.allowed_tokens = parser, [], None

    def __init__(self, data, parser):
        self.__dict__.update(vars(data))
        self.root_parser = parser
        self.prefix_states, self.allowed_token_cache = {}, {}

    def get_allowed_tokens(self, sequence):
        key = tuple(sequence)
        if key not in self.prefix_states:
            previous = self.prefix_states.get(key[:-1])
            state = (self.OutputTensorState(self.root_parser) if previous is None
                     else self._apply_new_characters(previous, sequence))
            self.prefix_states[key] = state
            self._compute_allowed_tokens(key, state)
        return self.prefix_states[key].allowed_tokens

    def _collect_allowed_tokens(self, _parser, _node, allowed, _shortcut):
        allowed.extend(token for token, _text, _newword in self.regular_tokens)

    def _compute_allowed_tokens(self, *_args):
        raise AssertionError("unsafe upstream fallback called")

    def _apply_new_characters(self, *_args):
        raise AssertionError("unsafe upstream fallback called")


class Tensor:
    def __init__(self, *tokens):
        self.tokens = list(tokens)

    def tolist(self):
        return self.tokens[:]


def decoder(check=lambda: None, accepts=lambda raw: raw == RAW, tokenizer=None):
    with mock.patch.object(DECODER, "_load_backend", return_value=(Parser, Data, Core, TokenList)):
        return DECODER.GraphDecoder(tokenizer or Tokenizer(), check, accepts)


class DecoderTests(unittest.TestCase):
    def test_metadata_and_schema_do_not_choose_tasks(self):
        value = decoder()
        self.assertEqual(value.metadata, DECODER.decoder_metadata())
        schema = DECODER.graph_schema()
        self.assertEqual(schema["properties"]["version"], {"type": "integer", "enum": [3]})
        tasks = schema["properties"]["tasks"]
        self.assertEqual((tasks["minItems"], tasks["maxItems"]), (1, 4))
        question = tasks["items"]["properties"]["question"]
        self.assertEqual(question, {"type": "string", "minLength": 1, "maxLength": 512})

    def test_actual_dependency_versions_required_before_import(self):
        versions = {"lm-format-enforcer": "0.11.3", "interegular": "0.3.3", "pydantic": "1.10.24"}
        for name in versions:
            wrong = dict(versions, **{name: "0.0"})
            with self.subTest(name=name), mock.patch.object(DECODER.importlib.metadata, "version", side_effect=wrong.get), \
                    mock.patch.object(DECODER.importlib, "import_module") as importing:
                with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_VERSION_MISMATCH$"):
                    DECODER._load_backend(lambda: None)
                importing.assert_not_called()
        with mock.patch.object(DECODER.importlib.metadata, "version", side_effect=ValueError("PRIVATE PATH")):
            with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_UNAVAILABLE$"):
                DECODER._load_backend(lambda: None)

    def test_missing_core_has_fixed_failure(self):
        versions = {"lm-format-enforcer": "0.11.3", "interegular": "0.3.3", "pydantic": "1.10.24"}
        with mock.patch.object(DECODER.importlib.metadata, "version", side_effect=versions.get), \
                mock.patch.object(DECODER.importlib, "import_module", side_effect=ImportError("PRIVATE PATH")):
            with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_UNAVAILABLE$"):
                DECODER._load_backend(lambda: None)

    def test_vocabulary_once_fresh_parser_each_attempt(self):
        tokenizer = Tokenizer()
        value = decoder(tokenizer=tokenizer)
        calls = tokenizer.calls
        first, second = value.new_attempt([0], 384), value.new_attempt([0], 21)
        self.assertEqual(tokenizer.calls, calls)
        self.assertIsNot(first.enforcer.root_parser, second.enforcer.root_parser)
        self.assertIs(first.enforcer.tokenizer_tree, second.enforcer.tokenizer_tree)
        self.assertEqual(first.enforcer.prefix_states, {})
        self.assertEqual(second.enforcer.prefix_states, {})

    def test_whole_original_bytes_required_for_eos(self):
        observed = []
        value = decoder(accepts=lambda raw: observed.append(raw) is None and raw == RAW)
        callback = value.new_attempt([0], 384)
        self.assertNotIn(2, callback(0, Tensor(0)))
        self.assertIn(2, callback(0, Tensor(0, 7)))
        self.assertEqual(observed, [RAW])
        self.assertEqual(callback.enforcer.prefix_states[(0, 7)].parser.text.encode(), RAW)
        # Syntactically complete is insufficient; independent validation rejects
        # the graph without repairing text or replacing it by an EOS.
        rejected = decoder(accepts=lambda _raw: False).new_attempt([0], 384)
        rejected(0, Tensor(0))
        self.assertNotIn(2, rejected(0, Tensor(0, 7)))

    def test_partial_utf8_and_new_word_semantics(self):
        value = decoder()
        callback = value.new_attempt([0], 384)
        callback(0, Tensor(0))
        callback(0, Tensor(0, 8))
        self.assertEqual(callback.enforcer.prefix_states[(0, 8)].parser.text, "")
        callback(0, Tensor(0, 8, 9))
        self.assertEqual(callback.enforcer.prefix_states[(0, 8, 9)].parser.text, "é")
        callback(0, Tensor(0, 8, 9, 10))
        state = callback.enforcer.prefix_states[(0, 8, 9, 10)]
        self.assertEqual(state.parser.text, "é word")
        self.assertEqual(state.current_word_tokens, [10])
        # Only the incremental parser view strips an unfinished replacement.
        self.assertEqual(value._decode([8]), "\ufffd")

    def test_parser_exceptions_never_log_or_force_eos(self):
        for failing in ("apply", "compute"):
            with self.subTest(failing=failing):
                callback = decoder().new_attempt([0], 384)
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    if failing == "apply":
                        callback(0, Tensor(0))
                        call = lambda: callback(0, Tensor(0, 11))
                    else:
                        callback.enforcer._collect_allowed_tokens = mock.Mock(side_effect=ValueError("PRIVATE PREFIX"))
                        call = lambda: callback(0, Tensor(0))
                    with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_PARSER_FAILED$"):
                        call()
                self.assertEqual(output.getvalue(), "")

    def test_empty_allowed_set_does_not_invent_eos(self):
        callback = decoder().new_attempt([0], 384)
        callback.enforcer._collect_allowed_tokens = lambda *_args: None
        with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS$"):
            callback(0, Tensor(0))

    def test_prefix_budget_and_special_tokens_stay_exact(self):
        for tokens, batch in (([0, 7], 0), ([1], 0), ([0], 1), ([0, 2], 0)):
            with self.subTest(tokens=tokens, batch=batch):
                callback = decoder().new_attempt([0], 384)
                with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_PREFIX_CHANGED$"):
                    callback(batch, Tensor(*tokens))
        callback = decoder().new_attempt([0], 1)
        callback(0, Tensor(0))
        with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_PREFIX_CHANGED$"):
            callback(0, Tensor(0, 7))
        for prompt, limit in (([0] * 513, 1), ([0], 385), ([0], 0), ([True], 1)):
            with self.assertRaisesRegex(DECODER.DecoderError, "^TASK_GRAPH_DECODER_ATTEMPT_INVALID$"):
                decoder().new_attempt(prompt, limit)

    def test_owner_cancellation_during_setup_and_each_callback_propagates(self):
        class Cancelled(Exception):
            pass
        calls = []

        def check():
            calls.append(True)
            if len(calls) == 5:
                raise Cancelled("JOB_CANCELLED")

        with self.assertRaises(Cancelled):
            decoder(check=check)
        self.assertEqual(len(calls), 5)
        control = mock.Mock()
        callback = decoder(check=control).new_attempt([0], 384)
        before = control.call_count
        callback(0, Tensor(0))
        self.assertEqual(control.call_count, before + 2)
        control.side_effect = Cancelled("JOB_CANCELLED")
        with self.assertRaises(Cancelled):
            callback(0, Tensor(0, 7))
        self.assertNotIn((0, 7), callback.enforcer.prefix_states)


if __name__ == "__main__":
    unittest.main()
