#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert fixture and evidence checks, without synthesizing or recognizing speech."""
from pathlib import Path
import json
import runpy
import struct
import tempfile
import unittest
import wave

F = runpy.run_path(str(Path(__file__).with_name("speech-recognition-fixture.py")))


def receipt_inputs(directory):
    recordings = {}
    for index, (name, phrase) in enumerate(F["PHRASES"].items(), 1):
        samples = 400 + index
        path = directory / (name + ".wav")
        with wave.open(str(path), "wb") as wav:
            wav.setparams((1, 2, 16000, samples, "NONE", "not compressed"))
            wav.writeframes(struct.pack("<h", index) * samples)
        recordings[name] = {"samples": samples, "sha256": F["sha256"](path.read_bytes())}
        result = {"version": 1, "operation": "compute_transcribe", "model_profile": "whisper-tiny-v1",
            "elapsed_ms": 50, "max_observed_rss_bytes": 20480,
            "language": "en", "transcript": phrase, "audio_samples": samples, "cleanup": {"complete": True}}
        (directory / (name + ".result.json")).write_text(json.dumps(result))
    (directory / "reference.json").write_text(json.dumps({"version": 1, "source": "espeak-ng",
        "voice": "en-us", "words_per_minute": 145,
        "packages": dict.fromkeys(F["PACKAGES"], F["ENGINE"]), "recordings": recordings}))


class SpeechFixture(unittest.TestCase):
    def test_scoring_counts_insertions_deletions_and_substitutions(self):
        self.assertEqual(F["words"]("We're ON Sunday, 17. Ja!"), ["we're", "on", "sunday", "17", "ja"])
        distance = F["word_errors"]
        self.assertEqual(distance(["blue", "bike"], ["blue", "green", "car"]), 2)
        self.assertEqual(distance(["blue", "bike"], ["bike"]), 1)
        self.assertEqual(distance(["blue"], []), 1)

    def test_conversion_keeps_fixed_rate_and_signed_pcm(self):
        raw = struct.pack("<hhhh", -20000, -10000, 0, 10000)
        self.assertEqual(struct.unpack("<hh", F["to_16k"](raw)), (-20000, -6219))

    def test_independent_scores_detect_wrong_clip_and_do_not_export_transcripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt_inputs(directory)
            report = F["score"](directory)
            self.assertTrue(report["passed"])
            self.assertEqual(report["clips"]["station"]["word_errors"], 0)
            self.assertNotIn(F["PHRASES"]["bicycle"], json.dumps(report))
            path = directory / "station.result.json"
            result = json.loads(path.read_text())
            result["transcript"] = F["PHRASES"]["bicycle"]
            path.write_text(json.dumps(result))
            self.assertFalse(F["score"](directory)["passed"])
            result["cleanup"]["complete"] = False
            path.write_text(json.dumps(result))
            with self.assertRaises(ValueError):
                F["score"](directory)

    def test_export_requires_both_original_results_and_recomputes_scores_and_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt_inputs(directory)
            revision = "a" * 40
            receipt = {"version": 1, "source_revision": revision, "scope": "synthetic_english_speech",
                "model_sha256": "7ebd0e69e78190ffe1438491fa05cc1f5c1aa3a4c4db3bc1723adbb551ea2395",
                "phase": "complete", "passed": True, "live_worker_cancelled_and_joined": True,
                "signals": ["SIGINT", "SIGTERM"], "digital_silence_refused": True, "score": F["score"](directory)}
            (directory / "speech-recognition-smoke.json").write_text(json.dumps(receipt))
            (directory / "reference.json").rename(directory / "speech-reference.json")
            for name in F["PHRASES"]:
                (directory / (name + ".result.json")).rename(directory / ("speech-" + name + ".json"))
            self.assertTrue(F["verify_export"](directory, revision)["passed"])
            path = directory / "speech-bicycle.json"
            original = json.loads(path.read_text())
            for key, value in (("elapsed_ms", 51), ("max_observed_rss_bytes", True),
                               ("transcript", F["PHRASES"]["station"]), ("audio_samples", 1)):
                path.write_text(json.dumps(dict(original, **{key: value})))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    F["verify_export"](directory, revision)
            path.unlink()
            with self.assertRaises(ValueError):
                F["verify_export"](directory, revision)

    def test_changed_pcm_and_duplicate_receipt_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt_inputs(directory)
            path = directory / "station.wav"
            data = path.read_bytes()
            path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with self.assertRaises(ValueError):
                F["score"](directory)
            path = directory / "duplicate.json"
            path.write_text('{"transcript":"one","transcript":"two"}')
            with self.assertRaises(ValueError):
                F["load"](path)


if __name__ == "__main__":
    unittest.main()
