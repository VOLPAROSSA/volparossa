#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert rejection and provenance controls; no media/runtime acceptance claims."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("weather-demo-0-package")
U = load("weather-demo-0-usage")


class Presentation(unittest.TestCase):
    def test_explanation_distinguishes_summary_and_held_frame(self):
        vtt, text = P.captions(120, 75)
        self.assertTrue(vtt.startswith("WEBVTT\n"))
        self.assertIn("do not assert exact action timestamps", vtt)
        self.assertIn("completed run", vtt)
        self.assertIn("After 75.000 seconds", text)
        self.assertIn("No continuing runtime activity", text)

    def test_filter_paths_are_data_not_expressions(self):
        for bad in ("/tmp/file:movie=x", "/tmp/a,b", "/tmp/a'", "/tmp/a[0]", "/tmp/a\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                P.filter_path(bad)

    def test_preview_writes_nothing_and_cannot_accept_media(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            base = Path(name)
            evidence = base / "evidence"
            evidence.mkdir()
            output = base / "presentation"
            result = P.prepare(evidence, output)
            self.assertFalse(result["executed"])
            self.assertFalse(result["publication_authorized"])
            self.assertFalse(output.exists())
            with patch.dict(P.os.environ, {}, clear=True), self.assertRaises(ValueError):
                P.prepare(evidence, output, execute=True)

    def test_different_run_is_rejected_before_media_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            base = Path(name)
            evidence = base / "evidence"
            evidence.mkdir()
            environment = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_SHA="a" * 40,
                GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
            media = dict(identity=dict(core_commit="a" * 40, run_id="124", run_attempt="1"))
            with patch.dict(P.os.environ, environment, clear=True), patch.object(P.os, "getuid", return_value=1000), \
                    patch.object(P.os, "geteuid", return_value=1000), \
                    patch.object(P.runpy, "run_path", return_value={"verify": lambda _: media}), \
                    patch.object(P, "video_info") as inspect_video:
                with self.assertRaises(ValueError):
                    P.prepare(evidence, base / "presentation", execute=True)
                inspect_video.assert_not_called()


    def test_selected_image_captions_describe_full_clip_and_distinct_held_image(self):
        vtt, text = P.captions(120, 75, hold_image="screen-003.png")
        self.assertIn("full 75.000-second raw clip at normal speed", text)
        self.assertIn("selected genuine same-run image screen-003.png", text)
        self.assertIn("No continuing runtime activity", text)
        self.assertIn("NOTE After the full", vtt)
        self.assertIn("00:01:15.000 --> 00:02:00.000\nHeld app frame from this run; original clip has ended.", vtt)
        self.assertNotIn("holds the final genuine frame", text)

    def test_held_caption_cues_have_monotonic_start_times(self):
        import re
        for duration, raw_duration in [(120, 75), (121, 119.999), (120, 81.999)]:
            with self.subTest(raw_duration=raw_duration):
                vtt, _ = P.captions(duration, raw_duration, hold_image="screen-003.png")
                starts = re.findall(r"^([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}) -->", vtt, re.M)
                self.assertEqual(starts, sorted(starts))
                self.assertEqual(len(starts), 7)
                self.assertIn(f"{P.timestamp(raw_duration)} --> {P.timestamp(duration)}", vtt)

    def test_optional_renderer_preserves_raw_input_and_default_graph(self):
        for selected in [False, True]:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                base = Path(name)
                stage = base / "stage"
                stage.mkdir()
                raw, image, font = [base / value for value in ["raw.mp4", "screen-003.png", "font.ttf"]]
                for path in [raw, image, font]:
                    path.write_bytes(b"inert file; never decoded")
                calls = []
                def command(args, **kwargs):
                    calls.append(args)
                    label = (stage / "text/held.txt").read_text()
                    self.assertEqual(label, "Held app frame from this run" if selected else "Held frame from this run")
                    Path(args[-1]).write_bytes(b"synthetic renderer stub")
                with patch.object(P, "FONT", font), patch.object(P, "command", side_effect=command), \
                        patch.object(P, "video_info", return_value=dict(duration_seconds=120)):
                    P.render_video(raw, stage, 120, dict(duration_seconds=75), [],
                                   hold_image=image if selected else None)
                args = calls[0]
                graph = args[args.index("-filter_complex") + 1]
                self.assertEqual(args[args.index("-i") + 1], str(raw))
                self.assertEqual(args.count("-i"), 2 if selected else 1)
                if selected:
                    self.assertIn(str(image), args)
                    self.assertIn("[clip][held]concat=n=2:v=1:a=0", graph)
                    raw_graph = graph.split("[clip];")[0]
                    self.assertNotIn("trim", raw_graph)
                    self.assertNotIn("tpad", raw_graph)
                    self.assertIn("setpts=PTS-STARTPTS,fps=30", raw_graph)
                    self.assertIn("trim=duration=45.000000", graph)
                else:
                    self.assertIn("tpad=stop_mode=clone:stop_duration=120", graph)
                    self.assertNotIn("concat=", graph)
                self.assertEqual(raw.read_bytes(), b"inert file; never decoded")
                self.assertFalse((stage / "text").exists())

    def test_selected_renderer_rejects_fractional_interval_below_one_second(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            image, font = base / "screen-003.png", base / "font.ttf"
            image.write_bytes(b"inert PNG placeholder")
            font.write_bytes(b"inert font placeholder")
            with patch.object(P, "FONT", font), patch.object(P, "command") as command:
                with self.assertRaisesRegex(ValueError, "at least one second"):
                    P.render_video(base / "raw.mp4", base, 120, dict(duration_seconds=119.999), [], image)
                command.assert_not_called()

    def test_render_rejection_attaches_only_numeric_probe_and_output_facts(self):
        profile = dict(streams=[dict(codec_name='h264', width=5000, height=1080)], format=dict(duration='120.0'))
        with patch.object(P, 'command', return_value=json.dumps(profile).encode()):
            with self.assertRaises(ValueError) as rejected:
                P.video_info(Path('/inert/not-decoded.mp4'))
        self.assertEqual(rejected.exception.render_rejection,
            dict(phase='probe-profile', facts=dict(stream_count=1, width=5000, height=1080, duration_ms=120000)))
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            font = base / 'font.ttf'
            font.write_bytes(b'inert font')
            def rendered(args, **kwargs):
                Path(args[-1]).write_bytes(b'synthetic movie')
            with patch.object(P, 'FONT', font), patch.object(P, 'command', side_effect=rendered), \
                    patch.object(P, 'video_info', return_value=dict(duration_seconds=119, width=1920, height=1080)):
                with self.assertRaises(ValueError) as rejected:
                    P.render_video(base / 'raw.mp4', base, 120, dict(duration_seconds=65.579), [])
            detail = rejected.exception.render_rejection
            self.assertEqual(detail['phase'], 'output-check')
            self.assertEqual(detail['facts']['duration_ms'], 119000)
            self.assertEqual(detail['facts']['requested_duration_ms'], 120000)
            self.assertEqual(detail['facts']['width'], 1920)

    def test_shared_panel_remains_a_completed_run_summary(self):
        identity = dict(core_commit="a" * 40, weather_commit="b" * 40, run_id="123")
        products = dict(weather=dict(cold_peer_bytes=1234), air_quality=dict(cold_peer_bytes=5678))
        text = " ".join(line[0] for line in P.presentation_lines(identity, products))
        self.assertIn("COMPLETED-RUN EVIDENCE / not live counters", text)
        self.assertIn("weather 1,234", text)
        self.assertIn("particulate 5,678", text)
        self.assertIn("Run 123 / Core aaaaaaaaaaaa", text)


    def test_scoped_captions_and_panel_separate_visible_and_report_only_scope(self):
        vtt, text = P.scoped_captions(120, 65.579, '206')
        self.assertIn("Reviewed pixels show temperature, PM2.5 and source validity", text)
        self.assertIn("first refresh completing, HOME and an app return animation", text)
        self.assertIn("successful background/resume lifecycle and retained mounted tables are supported by unchanged completed-run reports", text)
        self.assertIn("not claimed from these pixels", text)
        self.assertIn("original run remains failed", text)
        self.assertIn("full 65.579-second original clip plays at normal speed", text)
        self.assertIn("00:01:05.579 --> 00:02:00.000", vtt)
        starts = [line.split(' -->')[0] for line in vtt.splitlines() if ' --> ' in line]
        self.assertEqual(starts, sorted(starts))
        identity = dict(core_commit='a' * 40, weather_commit='b' * 40, run_id='123')
        products = dict(weather=dict(cold_peer_bytes=12), air_quality=dict(cold_peer_bytes=34))
        panel = ' '.join(line[0] for line in P.presentation_lines(identity, products, scoped_demo=True))
        self.assertIn('COMPLETED-RUN EVIDENCE / not live counters', panel)
        self.assertIn('Reports: two cache-backed refreshes', panel)
        self.assertIn('Pixels: first refresh / HOME / return animation', panel)


class RecordedUsage(unittest.TestCase):
    def test_uses_deltas_and_excludes_previous_turn_and_duplicate_snapshot(self):
        selected = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        def event(kind, **kwargs):
            return dict(type="event_msg", payload=dict(type=kind, **kwargs))
        def usage(n, cached, output):
            return event("token_count", info=dict(total_token_usage=dict(input_tokens=n,
                cached_input_tokens=cached, output_tokens=output, reasoning_output_tokens=output // 2)))
        entries = [dict(type="session_meta", payload=dict(id="thread-one", source="vscode")),
            usage(100, 80, 20), event("task_started", root_turn_id=selected),
            dict(type="turn_context", payload=dict(model="gpt-6.1-sol", effort="medium")),
            usage(130, 100, 26), usage(130, 100, 26),
            event("task_complete", root_turn_id=selected), usage(140, 105, 28)]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "session.jsonl"
            path.write_text("".join(json.dumps(x) + "\n" for x in entries))
            report = U.collect([path], selected)
            row = report["threads"][0]["models"][0]
            self.assertEqual((row["input_tokens"], row["cached_input_tokens"], row["uncached_input_tokens"], row["output_tokens"]),
                (30, 20, 10, 6))
            self.assertEqual(report["threads"][0]["nonzero_usage_events"], 1)
            self.assertFalse(report["billing_estimate"])
            with self.assertRaises(ValueError):
                U.collect([path, path], selected)


    @staticmethod
    def event(kind, **kwargs):
        return dict(type="event_msg", payload=dict(type=kind, **kwargs))

    @classmethod
    def usage(cls, n, cached, output):
        return cls.event("token_count", info=dict(total_token_usage=dict(input_tokens=n,
            cached_input_tokens=cached, output_tokens=output, reasoning_output_tokens=output // 2)))

    @classmethod
    def resumed_entries(cls):
        first = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        second = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        gap = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        entries = [dict(type="session_meta", payload=dict(id="synthetic-thread", source="vscode")),
            cls.usage(100, 80, 20), cls.event("task_started", root_turn_id=first),
            dict(type="turn_context", payload=dict(model="gpt-6.1-sol", effort="medium")),
            cls.usage(130, 100, 26), cls.usage(130, 100, 26),
            cls.event("task_complete", root_turn_id=first),
            cls.event("task_started", root_turn_id=gap), cls.usage(180, 140, 40),
            cls.event("task_complete", root_turn_id=gap),
            cls.event("task_started", root_turn_id=second), cls.usage(220, 170, 48),
            dict(type="response_item", payload=dict(prompt="synthetic private text never exported")),
            cls.event("task_complete", root_turn_id=second), cls.usage(230, 175, 50)]
        return first, second, entries

    @staticmethod
    def write_session(path, entries):
        path.write_text("".join(json.dumps(entry) + "\n" for entry in entries))

    def test_union_adds_both_selected_turns_and_excludes_gap(self):
        first, second, entries = self.resumed_entries()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "synthetic.jsonl"
            self.write_session(path, entries)
            before = path.read_bytes()
            report = U.collect_many([path], [second, first, first])
            self.assertEqual(report["root_turn_ids"], [first, second])
            self.assertNotIn("root_turn_id", report)
            row = report["threads"][0]["models"][0]
            self.assertEqual((row["input_tokens"], row["cached_input_tokens"],
                row["uncached_input_tokens"], row["output_tokens"], row["reasoning_output_tokens"]),
                (70, 50, 20, 14, 7))
            self.assertEqual(report["threads"][0]["nonzero_usage_events"], 2)
            self.assertTrue(report["snapshot_incomplete"])
            self.assertFalse(report["billing_estimate"])
            self.assertIn("subset of output", " ".join(report["notes"]))
            self.assertNotIn(str(path), json.dumps(report))
            self.assertNotIn("synthetic private text", json.dumps(report))
            self.assertEqual(path.read_bytes(), before)

    def test_union_deduplicates_session_aliases_and_preserves_single_api(self):
        first, _, entries = self.resumed_entries()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "synthetic.jsonl"
            alias = Path(name) / "alias.jsonl"
            self.write_session(path, entries)
            alias.symlink_to(path)
            report = U.collect_many([path, path, alias], [first, first])
            self.assertEqual(len(report["threads"]), 1)
            self.assertEqual(report["root_turn_id"], first)
            self.assertEqual(report["root_turn_ids"], [first])
            self.assertEqual(U.collect_many([path], first), report)
            expected = dict(report)
            expected.pop("root_turn_ids")
            self.assertEqual(U.collect([path], first), expected)
            with self.assertRaisesRegex(ValueError, "duplicate session"):
                U.collect([path, alias], first)

    def test_distinct_files_with_same_selected_thread_fail_closed(self):
        first, second, entries = self.resumed_entries()
        with tempfile.TemporaryDirectory() as name:
            paths = [Path(name) / "original.jsonl", Path(name) / "copy.jsonl"]
            for path in paths:
                self.write_session(path, entries)
            with self.assertRaisesRegex(ValueError, "duplicate thread.*manual reconciliation"):
                U.collect_many(paths, [first, second])

    def test_union_can_span_distinct_threads_without_missing_turns(self):
        first, second, _ = self.resumed_entries()
        with tempfile.TemporaryDirectory() as name:
            paths = []
            for index, (turn, before, after) in enumerate([
                    (first, (100, 80, 20), (130, 100, 26)),
                    (second, (180, 140, 40), (220, 170, 48))]):
                path = Path(name) / f"thread-{index}.jsonl"
                self.write_session(path, [dict(type="session_meta", payload=dict(id=f"thread-{index}")),
                    self.usage(*before), self.event("task_started", root_turn_id=turn),
                    dict(type="turn_context", payload=dict(model="gpt-6.1-sol", effort="medium")),
                    self.usage(*after), self.event("task_complete", root_turn_id=turn)])
                paths.append(path)
            report = U.collect_many(paths, [first, second])
            self.assertEqual([row["thread_id"] for row in report["threads"]], ["thread-0", "thread-1"])
            self.assertEqual(sum(row["models"][0]["input_tokens"] for row in report["threads"]), 70)

    def test_counter_reset_in_selected_turn_or_unselected_gap_fails_closed(self):
        first, second, entries = self.resumed_entries()
        for index in [4, 8]:
            with self.subTest(index=index), tempfile.TemporaryDirectory() as name:
                path = Path(name) / "reset.jsonl"
                changed = list(entries)
                changed[index] = self.usage(1, 0, 0)
                self.write_session(path, changed)
                with self.assertRaisesRegex(ValueError, "counter reset: manual reconciliation"):
                    U.collect_many([path], [first, second])

    def test_union_rejects_malformed_or_missing_selected_turn(self):
        first, _, entries = self.resumed_entries()
        missing = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "synthetic.jsonl"
            self.write_session(path, entries)
            for turns in [[], [first, "-" * 36], [first, 42], [first, missing]]:
                with self.subTest(turns=turns), self.assertRaises(ValueError):
                    U.collect_many([path], turns)

    def test_missing_cache_fields_are_annotated_without_claiming_zero(self):
        first, _, entries = self.resumed_entries()
        # A missing baseline field also makes the following selected delta uncertain.
        entries[1]["payload"]["info"]["total_token_usage"].pop("cached_input_tokens")
        for index in [4, 5]:
            entries[index]["payload"]["info"]["total_token_usage"]["cached_input_tokens"] = 10
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "legacy-counters.jsonl"
            self.write_session(path, entries)
            report = U.collect_many([path], [first])
            thread = report["threads"][0]
            self.assertEqual(thread["missing_counter_fields"],
                ["cache_write_input_tokens", "cached_input_tokens"])
            self.assertEqual(thread["counter_availability"]["cache_write_input_tokens"],
                "legacy_zero_default_used")
            self.assertEqual(thread["counter_availability"]["cached_input_tokens"],
                "legacy_zero_default_used")
            self.assertEqual(thread["counter_availability"]["input_tokens"],
                "observed_in_delta_snapshots")
            self.assertEqual(thread["models"][0]["cache_write_input_tokens"], 0)
            self.assertIn("not confirmed measurements", " ".join(report["notes"]))

    def test_gap_without_intermediate_snapshot_remains_an_uncertain_delta(self):
        first, _, _ = self.resumed_entries()
        gap = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        entries = [dict(type="session_meta", payload=dict(id="synthetic-gap-thread")),
            self.usage(100, 80, 20), self.event("task_started", root_turn_id=gap),
            # Deliberately no counter snapshot before the selected task starts.
            self.event("task_complete", root_turn_id=gap),
            self.event("task_started", root_turn_id=first),
            dict(type="turn_context", payload=dict(model="gpt-6.1-sol", effort="medium")),
            self.usage(160, 120, 32), self.event("task_complete", root_turn_id=first)]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "unmeasured-gap.jsonl"
            self.write_session(path, entries)
            report = U.collect_many([path], [first])
            self.assertEqual(report["threads"][0]["models"][0]["input_tokens"], 60)
            notes = " ".join(report["notes"])
            self.assertIn("can include unselected work", notes)
            self.assertIn("not exact task consumption or billed consumption", notes)
            self.assertTrue(report["snapshot_incomplete"])
            self.assertFalse(report["billing_estimate"])

    def test_cli_repeatable_selection_projects_synthetic_counters_only(self):
        import subprocess
        import sys
        first, second, entries = self.resumed_entries()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "synthetic.jsonl"
            self.write_session(path, entries)
            before = path.read_bytes()
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/weather-demo-0-usage.py"),
                "--root-turn", first, "--root-turn", second, "--root-turn", first, str(path), str(path)],
                capture_output=True, check=True, timeout=10)
            report = json.loads(result.stdout)
            self.assertEqual(report["root_turn_ids"], [first, second])
            self.assertEqual(report["threads"][0]["models"][0]["input_tokens"], 70)
            self.assertNotIn(str(path), result.stdout.decode())
            self.assertNotIn("synthetic private text", result.stdout.decode())
            self.assertEqual(result.stderr, b"")
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
