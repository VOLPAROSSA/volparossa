# SPDX-License-Identifier: GPL-3.0-only
"""Fixed worker for an owner-selected PCM recording in the shared compute sandbox."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import wave


def require(condition):
    if not condition:
        raise ValueError("invalid speech task")


class WorkerFailure(Exception):
    """Contains only a fixed local stage code."""


@contextmanager
def stage(code):
    try:
        yield
    except Exception:
        raise WorkerFailure(code) from None


def verified_model(root, pins):
    require({entry.name for entry in root.iterdir()} == {item["path"] for item in pins["files"]})
    for item in pins["files"]:
        file = root / item["path"]
        info = file.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == item["bytes"])
        with file.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == item["sha256"])


def samples(path):
    with wave.open(str(path), "rb") as wav:
        count = wav.getnframes()
        require(wav.getcomptype() == "NONE" and wav.getframerate() == 16000
                and wav.getnchannels() == 1 and wav.getsampwidth() == 2 and 0 < count <= 480000)
        pcm = wav.readframes(count)
        require(len(pcm) == count * 2)
        return pcm


def transcribe(request):
    with stage("BACKEND_IMPORT_FAILED"):
        import numpy as np
        import torch
        from transformers import AutoTokenizer, WhisperFeatureExtractor, WhisperForConditionalGeneration

    root = Path("/model")
    with stage("MODEL_WEIGHTS_CHANGED_ON_DISK"):
        verified_model(root, json.loads(PINS_JSON))
    with stage("SPEECH_INPUT_INVALID"):
        pcm = samples(Path("/audio.wav"))
        signal = np.frombuffer(pcm, dtype="<i2").astype(np.float32) / 32768.0
        require(np.max(signal) != np.min(signal))
    with stage("SPEECH_MODEL_LOAD_FAILED"):
        torch.set_num_threads(request["threads"])
        torch.set_num_interop_threads(1)
        extractor = WhisperFeatureExtractor.from_pretrained(root, local_files_only=True)
        tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True, trust_remote_code=False)
        model = WhisperForConditionalGeneration.from_pretrained(root, local_files_only=True, use_safetensors=True)
        model.eval()
    language = request["language"]
    with stage("SPEECH_LANGUAGE_UNSUPPORTED"):
        require("<|" + language + "|>" in model.generation_config.lang_to_id)
    with stage("SPEECH_FEATURES_FAILED"):
        features = extractor(signal, sampling_rate=16000, return_tensors="pt", return_attention_mask=True)
    with stage("SPEECH_GENERATION_FAILED"), torch.inference_mode():
        # Whisper removes EOS from its default short-form text tensor. The documented
        # structured output preserves decoder input and EOS for completion validation.
        output = model.generate(**features, task="transcribe", language=language, do_sample=False,
                                num_beams=1, max_new_tokens=128, return_timestamps=False,
                                return_dict_in_generate=True)
    with stage("SPEECH_RESULT_INVALID"):
        tokens = output.sequences
        require(int(tokens[0, -1]) == model.generation_config.eos_token_id)
        text = tokenizer.batch_decode(tokens, skip_special_tokens=True)[0].strip()
        require(0 < len(text.encode("utf-8")) <= 4096 and not any(ord(char) < 32 for char in text))
    return dict(language=language, transcript=text, audio_samples=len(signal), model_profile="whisper-tiny-v1")


def main():
    identifier = "0" * 32
    try:
        require(os.geteuid() != 0)
        raw = sys.stdin.buffer.readline(513)
        require(len(raw) <= 512 and raw.endswith(b"\n"))
        request = json.loads(raw)
        require(set(request) == {"version", "id", "language", "threads"} and request["version"] == 1
                and re.fullmatch(r"[a-f0-9]{32}", request["id"])
                and re.fullmatch(r"[a-z]{2,3}", request["language"]) and request["threads"] in (1, 2))
        identifier = request["id"]
        result = transcribe(request)
    except WorkerFailure as error:
        code = error.args[0]
    except Exception:
        code = "SPEECH_INPUT_INVALID"
    else:
        print(json.dumps(dict(version=1, id=identifier, kind="result", status="ok", **result)), flush=True)
        return 0
    print(json.dumps(dict(version=1, id=identifier, kind="result", status="error", code=code)), flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
