#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adapter contract tests with tiny core doubles; no LMFE/model execution claim."""

import contextlib
import copy
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
    def __init__(self, schema, text="", config=None):
        self.schema, self.text, self.config = schema, text, config

    def add_character(self, character):
        if character == "!":
            raise ValueError("PRIVATE PARSER CONTENT")
        return Parser(self.schema, self.text + character, self.config)

    def can_end(self):
        try:
            return isinstance(json.loads(self.text), dict)
        except ValueError:
            return False

    def cache_key(self):
        return None

    def shortcut_key(self):
        return None


class StringState:
    """Pinned StringParsingState initialization shape, not its enum algorithm."""

    def __init__(self, root, allowed_strings, require_opening_quote):
        self.root, self.allowed_strings = root, allowed_strings
        self.seen_opening_quote, self.seen_closing_quote = not require_opening_quote, False
        self.parsed_string = ""


class ScalarRoot:
    """Only pinned root stack/config/whitespace behavior around one scalar."""

    def __init__(self):
        self.object_stack = []
        self.config = SimpleNamespace(force_json_field_order=False, alphabet=' abc"')
        self.context = SimpleNamespace(alphabet_without_quotes=" abc")
        self.num_consecutive_whitespaces = 0

    def add_character(self, character):
        updated = copy.copy(self)
        updated.object_stack = [self.object_stack[0].add_character(character)]
        updated.num_consecutive_whitespaces = self.num_consecutive_whitespaces + 1 if character in " \t\r\n" else 0
        return updated

    def get_allowed_characters(self):
        result = self.object_stack[0].get_allowed_characters()
        return "".join(c for c in result if c not in " \t\r\n") if self.num_consecutive_whitespaces >= 12 else result

    def can_end(self):
        return self.object_stack[0].can_end()

    def cache_key(self):
        return None

    def shortcut_key(self):
        return None


class GraphSyntaxDouble:
    """Broad alphabet plus whole-JSON completion, deliberately no graph semantics."""

    def __init__(self, text=""):
        self.text = text
        self.config = None

    def add_character(self, character):
        return GraphSyntaxDouble(self.text + character)

    def get_allowed_characters(self):
        return "".join(chr(value) for value in range(128)) + 'é🙂漢字\U0010ffff'

    def can_end(self):
        try:
            return isinstance(json.loads(self.text), dict)
        except ValueError:
            return False

    def shortcut_key(self):
        return ('json_freetext', 0, 1, 512)


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
    def graph_parser(self, tasks, requirement=None, goal="Main goal?", ascii_only=False):
        raw = json.dumps({"version": 3, "tasks": tasks}, ensure_ascii=ascii_only, separators=(",", ":"))
        parser = DECODER._GraphJsonParser(GraphSyntaxDouble(), DECODER._GraphRules(goal, requirement))
        for character in raw:
            previous, text = parser.rules, parser.inner.text
            self.assertIn(character, parser.get_allowed_characters())
            parser = parser.add_character(character)
            self.assertEqual(previous.phase == "done", False)
            self.assertEqual(parser.inner.text, text + character)
        self.assertTrue(parser.can_end())
        self.assertEqual(parser.inner.text, raw)
        self.assertIsNone(parser.shortcut_key())
        self.assertIsNone(parser.cache_key())
        return parser

    def test_guarded_graph_accepts_model_selected_counts_and_arbitrary_valid_branches(self):
        def task(question, parents=()):
            return {"question": question, "depends_on": list(parents)}
        alternatives = [
            [task("Which source fact applies?")],
            [task("Which fact applies?"), task("What remains unknown?")],
            [task("Which fact applies?"), task("What follows?", [0]), task("What else?", [0])],
            [task('What does "é🙂" imply?'), task("What follows?", [0]),
             task("Which assumption remains?"), task("How do these results compare?", [2, 0])],
        ]
        for tasks in alternatives:
            self.graph_parser(tasks)
        for tasks in alternatives[2:]:
            self.graph_parser(tasks, "dependent_analysis_v1")
        # Alternate legal JSON escaping remains untouched, not rewritten.
        self.graph_parser([task('  What about "é🙂" and \\ paths?  ')], ascii_only=True)

    def test_guarded_graph_masks_bad_questions_and_dependency_edges_before_completion(self):
        def task(question, parents=()):
            return {"question": question, "depends_on": list(parents)}
        invalid = [
            [task("Main goal?")], [task("  Main goal?  ")], [task("Not a question")],
            [task("Same?"), task(" Same? ")], [task("Null\0?")],
            [task("First?", [0])], [task("First?"), task("Second?", [1])],
            [task("First?"), task("Second?", [2])],
            [task("First?"), task("Second?"), task("Third?", [0, 0])],
            [task("First?"), task("Second?", [True])],
        ]
        for tasks in invalid:
            raw = json.dumps({"version": 3, "tasks": tasks}, separators=(",", ":"))
            parser = DECODER._GraphJsonParser(GraphSyntaxDouble(), DECODER._GraphRules("Main goal?", None))
            rejected = False
            for index, character in enumerate(raw):
                if character not in parser.get_allowed_characters():
                    with self.assertRaisesRegex(DECODER.DecoderError, '^TASK_GRAPH_DECODER_PARSER_FAILED$'):
                        parser.add_character(character)
                    self.assertLess(index, len(raw) - 1)
                    rejected = True
                    break
                parser = parser.add_character(character)
            self.assertTrue(rejected, repr(tasks))
        # Escaping does not hide a duplicate or a copy of the original question.
        for raw in ('{"version":3,"tasks":[{"question":"\\u004dain goal?","depends_on":[]}]}',
                    '{"version":3,"tasks":[{"question":"Same?","depends_on":[]},'
                    '{"question":"\\u0053ame?","depends_on":[]}]}'):
            rules = DECODER._GraphRules("Main goal?", None)
            for character in raw:
                following = rules.advance(character)
                if following is None:
                    break
                rules = following
            else:
                self.fail("escaped duplicate/copy reached the completed graph")

    def test_guarded_dependency_requirement_keeps_edge_choice_with_model(self):
        prefix = '{"version":3,"tasks":[{"question":"First?","depends_on":[]}'
        rules = DECODER._GraphRules("Main goal?", "dependent_analysis_v1")
        for character in prefix:
            rules = rules.advance(character)
            self.assertIsNotNone(rules)
        self.assertIsNone(rules.advance("]"))
        self.assertIsNotNone(rules.advance(","))
        # With no earlier edge, the final task must choose one, not receive one.
        for suffix in (',{"question":"Second?","depends_on":[]}',
                       ',{"question":"Third?","depends_on":[]}',
                       ',{"question":"Fourth?","depends_on":['):
            for character in suffix:
                rules = rules.advance(character)
                self.assertIsNotNone(rules)
        self.assertIsNone(rules.advance("]"))
        for index in ("0", "1", "2"):
            self.assertEqual(rules.advance(index).parents, (int(index),))
        self.assertEqual(rules.parents, ())
        self.assertFalse(rules.has_dependency)

    def test_guarded_questions_obey_utf8_bound_and_surrogate_pair_identity(self):
        self.graph_parser([{"question": "é" * 255 + "?", "depends_on": []}], ascii_only=True)
        self.graph_parser([{"question": "x" * 511 + "?", "depends_on": []}])
        opening = '{"version":3,"tasks":[{"question":"'
        for content in ("x" * 512, "é" * 256, "\\ud800?", "\\udc00", "\\u0000"):
            rules = DECODER._GraphRules("Main goal?", None)
            for character in opening + content:
                following = rules.advance(character)
                if following is None:
                    break
                rules = following
            else:
                self.fail("irrecoverable question prefix remained admissible")

    def test_guarded_options_bind_goal_requirement_schema_and_original_budgets(self):
        module = SimpleNamespace(CharacterLevelParserConfig=mock.Mock(return_value=object()), StringParsingState=StringState)
        with mock.patch.object(DECODER, "_load_backend", return_value=(Parser, Data, Core, TokenList)), \
                mock.patch.object(DECODER.importlib, "import_module", return_value=module):
            value = DECODER.GraphDecoder(Tokenizer(), lambda: None, lambda _raw: True,
                graph_goal="Main goal?", graph_requirement="dependent_analysis_v1")
        first, second = value.new_attempt([0], 384), value.new_attempt([0], 12)
        self.assertIsInstance(first.enforcer.root_parser, DECODER._GraphJsonParser)
        self.assertIsNot(first.enforcer.root_parser.rules, second.enforcer.root_parser.rules)
        self.assertEqual(first.enforcer.root_parser.rules.questions, ())
        self.assertEqual(value.schema["properties"]["tasks"]["minItems"], 2)
        self.assertEqual((value.prompt_limit, value.generation_limit), (512, 384))
        self.assertNotIsInstance(decoder().new_attempt([0], 384).enforcer.root_parser, DECODER._GraphJsonParser)
        for options in ({"graph_goal": " "}, {"graph_goal": "x" * 513}, {"graph_goal": "\ud800"},
                        {"graph_requirement": "dependent_analysis_v1"},
                        {"graph_goal": "Main?", "graph_requirement": "arbitrary"},
                        {"graph_goal": "Main?", "generation_limit": 512},
                        {"graph_goal": "Main?", "prompt_limit": 1024},
                        {"graph_goal": "Main?", "schema": {"type": "object"}}):
            with mock.patch.object(DECODER, "_load_backend") as loading:
                with self.assertRaisesRegex(DECODER.DecoderError, '^TASK_GRAPH_DECODER_ATTEMPT_INVALID$'):
                    DECODER.GraphDecoder(Tokenizer(), lambda: None, lambda _raw: True, **options)
                loading.assert_not_called()

    def test_graph_alphabet_probe_matches_transitions_without_cloning_ordinary_text(self):
        alphabet = ''.join(chr(code) for code in range(128)) + 'é漢🙂\ud800\udfff'
        prefixes = [
            '{"version":3,"tasks":[{"question":"Which constraint matters?',
            '{"version":3,"tasks":[{"question":"Which fact?","depends_on":[]},'
            '{"question":"What follows?","depends_on":[0]}]}',
            '{"version":3,"tasks":[{"question":"' + 'x' * 510 + '? ',
            '{"version":3,"tasks":[{"question":"What about \\u00e9 or \\ud83d\\ude42?',
        ]
        for prefix in prefixes:
            rules = DECODER._GraphRules("Main goal?", "dependent_analysis_v1")
            for character in prefix:
                for candidate in alphabet:
                    self.assertEqual(rules.allows(candidate), rules.advance(candidate) is not None,
                                     (rules.phase, rules.text_bytes, repr(candidate)))
                rules = rules.advance(character)
                self.assertIsNotNone(rules)
        rules = DECODER._GraphRules("Main goal?", None)
        for character in '{"version":3,"tasks":[{"question":"Which ':
            rules = rules.advance(character)
        parser = DECODER._GraphJsonParser(GraphSyntaxDouble(), rules)
        with mock.patch.object(DECODER._GraphRules, "advance", side_effect=AssertionError("alphabet clone")):
            allowed = parser.get_allowed_characters()
            self.assertIn('x', allowed)
            self.assertNotIn('"', allowed)
            self.assertEqual(parser.get_allowed_characters(), allowed)

    def test_explicit_ordered_principle_budget_does_not_change_graph_defaults(self):
        module = SimpleNamespace(CharacterLevelParserConfig=mock.Mock(return_value=object()), StringParsingState=StringState)
        with mock.patch.object(DECODER, "_load_backend", return_value=(Parser, Data, Core, TokenList)), \
                mock.patch.object(DECODER.importlib, "import_module", return_value=module) as importing:
            value = DECODER.GraphDecoder(Tokenizer(), lambda: None, lambda raw: raw == RAW,
                schema={"type": "object"}, prompt_limit=1024, output_limit=1024,
                generation_limit=512, ordered_json=True)
        self.assertEqual(importing.call_args_list, [mock.call("lmformatenforcer.characterlevelparser"),
                                                   mock.call("lmformatenforcer.jsonschemaparser")])
        module.CharacterLevelParserConfig.assert_called_once_with(force_json_field_order=True)
        callback = value.new_attempt([0], 512)
        self.assertIs(callback.enforcer.root_parser.config, module.CharacterLevelParserConfig.return_value)
        self.assertIsNone(decoder().new_attempt([0], 384).enforcer.root_parser.config)
        for instance, limit in ((value, 513), (decoder(), 385)):
            with self.assertRaisesRegex(DECODER.DecoderError, "ATTEMPT_INVALID"):
                instance.new_attempt([0], limit)

    def test_source_literal_roundtrips_escapes_unicode_and_long_literal_whitespace(self):
        values = ['a"b', 'a\\b', 'a\nb', 'a\tb', 'a\rb', 'a\fb', 'a\bb', 'a\x01b',
                  'é🙂漢字', '\U0010ffffz', ' ' * 20 + 'leading', 'trailing' + ' ' * 20, 'a', 'ab']
        table = DECODER._SourceQuoteTable(values, lambda: None)
        state_type = DECODER._source_quote_state(StringState)
        for value in values:
            with self.subTest(value=repr(value)):
                root = ScalarRoot()
                root.object_stack = [state_type(root, table)]
                parser = DECODER._CompactJsonParser(root, StringState)
                self.assertEqual(parser.get_allowed_characters(), '"')
                for character in json.dumps(value, ensure_ascii=False):
                    previous = parser.inner.object_stack[0]
                    prefix = previous.prefix
                    self.assertIn(character, parser.get_allowed_characters())
                    parser = parser.add_character(character)
                    self.assertEqual(previous.prefix, prefix)  # Immutable branching state.
                self.assertTrue(parser.can_end())
                self.assertEqual(parser.inner.object_stack[0].parsed_string, value)
                self.assertEqual(parser.get_allowed_characters(), "")

    def test_source_literal_rejects_wrong_escape_and_raw_control_without_repair(self):
        state_type = DECODER._source_quote_state(StringState)
        for value, wrong, prefix in [('a"b', '"', '"a'), ('a\\b', 'n', '"a\\'),
                                     ('a\nb', '\n', '"a'), ('é', '\\', '"')]:
            table = DECODER._SourceQuoteTable([value], lambda: None)
            state = state_type(ScalarRoot(), table)
            for character in prefix:
                state = state.add_character(character)
            self.assertNotIn(wrong, state.get_allowed_characters())
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaisesRegex(DECODER.DecoderError, '^TASK_GRAPH_DECODER_PARSER_FAILED$'):
                    state.add_character(wrong)
            self.assertEqual(output.getvalue(), "")

    def test_quote_hook_is_marker_only_and_keeps_original_string_class(self):
        original = mock.Mock(return_value=object())
        original._volparossa_original = original
        module = SimpleNamespace(get_parser=original, StringParsingState=StringState)
        schema = {"type": "object", "properties": {"quote": {"type": "string", "enum": ['say "yes"'],
                  "x-volparossa-source-quotes": True}}}
        tables = DECODER._source_quote_tables(schema, lambda: None)
        DECODER._install_source_quote_parser(module, tables)
        unmarked = SimpleNamespace(type="string", extras={}, enum=['say "yes"'])
        root = ScalarRoot()
        self.assertIs(module.get_parser(root, unmarked), original.return_value)
        original.assert_called_once_with(root, unmarked)
        marked = SimpleNamespace(type="string", extras={"x-volparossa-source-quotes": True}, enum=['say "yes"'])
        state = module.get_parser(root, marked)
        self.assertIsInstance(state, StringState)
        self.assertIs(module.StringParsingState, StringState)
        self.assertIs(module.get_parser(root, marked).table, state.table)
        for bad in (SimpleNamespace(type="string", extras={"x-volparossa-source-quotes": False}, enum=marked.enum),
                    SimpleNamespace(type="string", extras=marked.extras, enum=["not the compiled source"])):
            with self.assertRaisesRegex(DECODER.DecoderError, '^TASK_GRAPH_DECODER_PARSER_FAILED$'):
                module.get_parser(root, bad)

    def test_compact_wrapper_preserves_open_key_escape_and_value_spaces_and_order(self):
        root = ScalarRoot()
        root.get_allowed_characters = lambda: ' \t\r\n"}x'
        wrapper = DECODER._CompactJsonParser(root, StringState)
        self.assertEqual(wrapper.get_allowed_characters(), '"}x')
        state = StringState(root, [], require_opening_quote=False)
        root.object_stack = [state, object()]  # Escape subparser above an open string.
        self.assertEqual(wrapper.get_allowed_characters(), ' \t\r\n"}x')
        state.seen_closing_quote = True
        self.assertEqual(wrapper.get_allowed_characters(), '"}x')
        replacement = SimpleNamespace(force_json_field_order=False, alphabet='é "')
        wrapper.config = replacement  # Actual TokenEnforcer constructor does this.
        self.assertTrue(wrapper.config.force_json_field_order)
        self.assertFalse(replacement.force_json_field_order)
        self.assertEqual(wrapper.config.alphabet, replacement.alphabet)
        self.assertEqual(root.context.alphabet_without_quotes, 'é ')

    def test_source_table_bounds_and_owner_cancellation_before_backend_work(self):
        for values in ([], [' '], ['\0'], ['é' * 65], ['\ud800'], [True], ['a'] * 65537):
            with self.assertRaisesRegex(DECODER.DecoderError, '^TASK_GRAPH_DECODER_PARSER_FAILED$'):
                DECODER._SourceQuoteTable(values, lambda: None)
        class Cancelled(Exception):
            pass
        calls = []
        def check():
            calls.append(True)
            if len(calls) == 2:
                raise Cancelled('JOB_CANCELLED')
        with self.assertRaises(Cancelled):
            DECODER._SourceQuoteTable(['a', 'b', 'c'], check)
        self.assertEqual(len(calls), 2)

    def test_compiled_policy_schema_uses_same_strict_core_with_explicit_prompt_bound(self):
        schema = {"type": "object", "properties": {"outcome": {"enum": ["allow", "deny", "undetermined"]}}}
        with mock.patch.object(DECODER, "_load_backend", return_value=(Parser, Data, Core, TokenList)):
            value = DECODER.GraphDecoder(Tokenizer(), lambda: None, lambda raw: raw == RAW,
                schema=schema, prompt_limit=1024, output_limit=1024)
        callback = value.new_attempt([0] * 1024, 256)
        self.assertEqual(callback.enforcer.root_parser.schema, schema)
        self.assertIsNot(callback.enforcer.root_parser.schema, schema)
        self.assertNotIn(2, callback(0, Tensor(*([0] * 1024))))
        self.assertIn(2, callback(0, Tensor(*([0] * 1024 + [7]))))
        with self.assertRaisesRegex(DECODER.DecoderError, "ATTEMPT_INVALID"):
            value.new_attempt([0] * 1025, 256)
        with self.assertRaisesRegex(DECODER.DecoderError, "ATTEMPT_INVALID"):
            decoder().new_attempt([0] * 513, 256)

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
