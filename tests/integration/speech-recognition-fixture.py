#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate two synthetic reference clips and score original Core transcription results."""
import argparse
from array import array
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unicodedata
import wave

PHRASES = {
    "bicycle": "The green bicycle is next to the window.",
    "station": "We will meet at the station on Sunday.",
}
ENGINE = "1.52.0+dfsg-5"
PACKAGES = ("espeak-ng", "espeak-ng-data", "libespeak-ng1")
RATE = 16000
MAX_SECONDS = 30


def require(condition):
    if not condition:
        raise ValueError("speech fixture contract")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def words(text):
    normalized = unicodedata.normalize("NFKC", text).casefold().replace("’", "'")
    return re.findall(r"[^\W_]+(?:'[^\W_]+)*", normalized)


def word_errors(expected, actual):
    # Levenshtein distance on words. Keep only the preceding and current rows.
    previous = list(range(len(actual) + 1))
    for index, reference in enumerate(expected, 1):
        current = [index]
        for column, hypothesis in enumerate(actual, 1):
            current.append(min(current[-1] + 1, previous[column] + 1,
                               previous[column - 1] + (reference != hypothesis)))
        previous = current
    return previous[-1]


def original_wave(path, expected_rate):
    size = path.stat().st_size
    require(0 < size <= MAX_SECONDS * expected_rate * 2 + 4096)
    with wave.open(str(path), "rb") as wav:
        count = wav.getnframes()
        require(wav.getnchannels() == 1 and wav.getsampwidth() == 2 and wav.getcomptype() == "NONE"
                and wav.getframerate() == expected_rate and 0 < count <= expected_rate * MAX_SECONDS)
        pcm = wav.readframes(count)
    require(len(pcm) == count * 2)
    return pcm


def to_16k(raw):
    source_rate = 22050
    samples = array("h")
    samples.frombytes(raw)
    if sys.byteorder != "little":
        samples.byteswap()
    require(0 < len(samples) <= source_rate * MAX_SECONDS)
    count = (len(samples) * RATE) // source_rate
    require(count > 0)
    result = array("h")
    for index in range(count):
        left, fraction = divmod(index * source_rate, RATE)
        right = min(left + 1, len(samples) - 1)
        result.append((samples[left] * (RATE - fraction) + samples[right] * fraction) // RATE)
    if sys.byteorder != "little":
        result.byteswap()
    return result.tobytes()


def engine_packages():
    env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
    guest = subprocess.check_output(["/usr/bin/systemd-detect-virt", "--vm"], env=env, timeout=5)
    require(guest.strip() == b"kvm")
    output = subprocess.check_output(["/usr/bin/dpkg-query", "-W",
        "-f=${Package} ${Architecture} ${Version} ${db:Status-Status}\\n", *PACKAGES],
        env=env, text=True, timeout=5)
    require(set(output.splitlines()) == {f"{pkg} amd64 {ENGINE} installed" for pkg in PACKAGES})
    return {pkg: ENGINE for pkg in PACKAGES}


def prepare(directory):
    packages = engine_packages()
    directory.mkdir(mode=0o700)
    recordings = {}
    with tempfile.TemporaryDirectory(dir=directory, prefix="synth-") as temporary:
        for name, phrase in PHRASES.items():
            intermediate = Path(temporary) / (name + ".wav")
            subprocess.run(["/usr/bin/espeak-ng", "-v", "en-us", "-s", "145",
                "-w", str(intermediate), phrase], check=True, timeout=15, cwd=temporary,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": temporary},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            raw = to_16k(original_wave(intermediate, 22050))
            require(any(raw))
            destination = directory / (name + ".wav")
            with destination.open("xb") as stream, wave.open(stream, "wb") as wav:
                os.fchmod(stream.fileno(), 0o600)
                wav.setparams((1, 2, RATE, len(raw) // 2, "NONE", "not compressed"))
                wav.writeframes(raw)
            recordings[name] = {"samples": len(raw) // 2, "sha256": sha256(destination.read_bytes())}
    evidence = {"version": 1, "source": "espeak-ng", "packages": packages,
                "voice": "en-us", "words_per_minute": 145, "recordings": recordings}
    with (directory / "reference.json").open("x") as out:
        json.dump(evidence, out, sort_keys=True)


def load(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16384)
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs))
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def score(directory):
    reference = load(directory / "reference.json")
    require(reference["version"] == 1 and reference["source"] == "espeak-ng"
            and reference["packages"] == {pkg: ENGINE for pkg in PACKAGES}
            and reference["voice"] == "en-us" and reference["words_per_minute"] == 145
            and set(reference["recordings"]) == set(PHRASES))
    clips = {}
    for name, phrase in PHRASES.items():
        path = directory / (name + ".wav")
        require(not path.is_symlink())
        samples = len(original_wave(path, RATE)) // 2
        digest = sha256(path.read_bytes())
        require(reference["recordings"][name] == {"samples": samples, "sha256": digest})
        result = load(directory / (name + ".result.json"))
        transcript = result["transcript"]
        require(result["version"] == 1 and result["operation"] == "compute_transcribe"
                and result["model_profile"] == "whisper-tiny-v1" and result["language"] == "en"
                and type(result["audio_samples"]) is int and result["audio_samples"] == samples
                and result["cleanup"]["complete"] is True and isinstance(transcript, str)
                and len(transcript.encode()) <= 4096)
        expected, actual = words(phrase), words(transcript)
        errors = word_errors(expected, actual)
        clips[name] = {"wav_sha256": digest, "audio_samples": samples,
            "transcript_sha256": sha256(transcript.encode()), "reference_words": len(expected),
            "hypothesis_words": len(actual), "word_errors": errors, "word_error_rate": errors / len(expected),
            "cleanup_complete": True, "passed": 4 * errors <= len(expected)}
    require(len({row["wav_sha256"] for row in clips.values()}) == len(clips))
    passed = all(row["passed"] for row in clips.values())
    return {"version": 1, "scope": "synthetic_english_speech", "model_profile": "whisper-tiny-v1",
            "maximum_word_error_rate_per_clip": 0.25, "clips": clips, "passed": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "score"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.operation == "prepare":
        prepare(args.directory.absolute())
        return 0
    result = score(args.directory)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError, OSError, EOFError, wave.Error, subprocess.SubprocessError):
        print(json.dumps({"version": 1, "passed": False, "error": "speech_fixture_unavailable"}))
        raise SystemExit(1)
