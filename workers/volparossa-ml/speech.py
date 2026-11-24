# SPDX-License-Identifier: GPL-3.0-only
"""Fixed worker for an owner-selected PCM recording in the shared compute sandbox."""
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
    import numpy as np
    import torch
    from transformers import WhisperFeatureExtractor, WhisperForConditionalGeneration, AutoTokenizer

    root = Path("/model")
    verified_model(root, json.loads(PINS_JSON))
    pcm = samples(Path("/audio.wav"))
    signal = np.frombuffer(pcm, dtype="<i2").astype(np.float32) / 32768.0
    language = request["language"]
    # Constant digital silence has no speech and must not seed a hallucinated transcript.
    require(np.max(signal) != np.min(signal))
    torch.set_num_threads(request["threads"])
    torch.set_num_interop_threads(1)
    extractor = WhisperFeatureExtractor.from_pretrained(root, local_files_only=True)
    tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True, trust_remote_code=False)
    model = WhisperForConditionalGeneration.from_pretrained(root, local_files_only=True, use_safetensors=True)
    model.eval()
    require("<|" + language + "|>" in model.generation_config.lang_to_id)
    features = extractor(signal, sampling_rate=16000, return_tensors="pt", return_attention_mask=True)
    with torch.inference_mode():
        tokens = model.generate(**features, task="transcribe", language=language, do_sample=False,
                                num_beams=1, max_new_tokens=128, return_timestamps=False)
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
    except Exception:
        print(json.dumps(dict(version=1, id=identifier, kind="result", status="error", code="SPEECH_FAILED")), flush=True)
        return 1
    print(json.dumps(dict(version=1, id=identifier, kind="result", status="ok", **result)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
