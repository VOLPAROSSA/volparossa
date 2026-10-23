#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare an unpublished presentation from verified same-run real Android media."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs/demos/weather-demo-0"
FONT = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")


def require(ok, message="Demo presentation rejected"):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, *, seconds=30, capture=False):
    result = subprocess.run(args, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=seconds, check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    if capture:
        require(len(result.stdout) <= 65536)
        return result.stdout


def video_info(path):
    value = json.loads(command(["/usr/bin/ffprobe", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=codec_name,width,height:format=duration", "-of", "json", str(path)], capture=True))
    facts = {}
    streams = value.get("streams") if type(value) is dict else None
    if type(streams) is list:
        facts["stream_count"] = min(len(streams), 128)
        if len(streams) == 1 and type(streams[0]) is dict:
            for key in ("width", "height"):
                if type(streams[0].get(key)) is int and 0 <= streams[0][key] <= 16384:
                    facts[key] = streams[0][key]
    try:
        require(len(value["streams"]) == 1)
        stream = value["streams"][0]
        duration = float(value["format"]["duration"])
        if math.isfinite(duration) and 0 <= duration <= 86400:
            facts["duration_ms"] = round(duration * 1000)
        require(math.isfinite(duration) and 1 <= duration <= 185)
        require(stream["codec_name"] == "h264" and all(type(stream[k]) is int
            and 100 <= stream[k] <= 1920 for k in ("width", "height")))
        return dict(duration_seconds=duration, codec="h264", width=stream["width"], height=stream["height"])
    except ValueError as error:
        error.render_rejection = dict(phase="probe-profile", facts=facts)
        raise


def filter_path(path):
    # Strict subset keeps paths out of FFmpeg's filter-expression language.
    require(re.fullmatch(r"[A-Za-z0-9_./-]+", str(path)) is not None)
    return str(path)


def timestamp(seconds):
    millis = round(seconds * 1000)
    return f"{millis // 3600000:02}:{millis // 60000 % 60:02}:{millis // 1000 % 60:02}.{millis % 1000:03}"


def captions(duration, raw_duration, hold_image=None):
    sections = [
        (0, 18, "VOLPAROSSA Weather / Overmorrow. Actual installed Android app in an emulator. Core runs externally in Debian 13."),
        (18, 38, "Real weather and particulate forecasts. Native forecast times, units and precipitation windows matter. Missing values remain unavailable."),
        (38, 60, "The evidence panel summarizes this completed run. Original source acquisition is separate from peer retrieval."),
        (60, 82, "The accepted trial checks cold peer retrieval and two cache-backed refreshes per product. Refresh can reuse the same valid forecast."),
        (82, 103, "Actual Android taps and background/resume are checked. The recording runs at normal speed; semantic checks and pixels are distinct evidence."),
        (103, duration, "Developer demonstration: no standalone mobile Core, physical-device acceptance, proven expiry recovery or production release authority."),
    ]
    lines = ["WEBVTT", "", "NOTE Explanatory narration; cue times do not assert exact action timestamps.", ""]
    transcript, cues = [], []
    for start, stop, text in sections:
        if stop <= start or start >= duration:
            continue
        cues.append((start, min(stop, duration), text))
        transcript.append(text)
    if raw_duration < duration:
        if hold_image is None:
            transcript.append(f"After {raw_duration:.3f} seconds, the presentation holds the final genuine frame. No continuing runtime activity is implied.")
        else:
            note = (f"After the full {raw_duration:.3f}-second raw clip at normal speed, the presentation holds "
                f"the selected genuine same-run image {hold_image}. No continuing runtime activity is implied.")
            transcript.append(note)
            lines.extend(["NOTE " + note, ""])
            cues.append((raw_duration, duration, "Held app frame from this run; original clip has ended."))
    for start, stop, text in sorted(cues, key=lambda cue: cue[0]):
        lines.extend([f"{timestamp(start)} --> {timestamp(stop)}", text, ""])
    return "\n".join(lines), "\n\n".join(transcript) + "\n"



def scoped_captions(duration, raw_duration, hold_image):
    """Narration for the explicitly reviewed scope; cue times are not action timestamps."""
    sections = [
        (0, 18, "VOLPAROSSA Weather / Overmorrow in an Android emulator. Core runs externally in Debian 13. This is a scoped developer demonstration."),
        (18, 38, "Reviewed pixels show temperature, PM2.5 and source validity. These are forecast products; missing observations remain unavailable."),
        (38, 60, "Reviewed pixels show the first refresh completing, HOME and an app return animation. These summaries do not assert exact input timestamps."),
        (60, 82, "The second refresh completing and successful background/resume lifecycle and retained mounted tables are supported by unchanged completed-run reports, not claimed from these pixels."),
        (82, 103, "Network and cache counters summarize the completed run. Source acquisition is separate from peer retrieval; cache refresh may reuse the same valid forecast."),
        (103, duration, "The original run remains failed at its encoded-duration admission gate. This separate scoped demo grants no publication, production or standalone-mobile authority."),
        (raw_duration, duration, "Held app frame from this run; original clip has ended."),
    ]
    lines = ["WEBVTT", "", "NOTE Explanatory summaries; cue times do not assert exact action timestamps.", ""]
    transcript = []
    for start, stop, text in sorted(sections, key=lambda row: row[0]):
        if start < duration and stop > start:
            lines.extend([f"{timestamp(start)} --> {timestamp(min(stop, duration))}", text, ""])
            transcript.append(text)
    transcript.append(f"The full {raw_duration:.3f}-second original clip plays at normal speed, followed by genuine native frame {hold_image}. No continuing runtime activity is implied.")
    return "\n".join(lines), "\n\n".join(transcript) + "\n"


def render_video(raw_video, stage, duration, raw_info, lines, hold_image=None):
    """Render only; callers separately establish whether the input is real demo media."""
    require(FONT.is_file() and not FONT.is_symlink())
    text_dir = stage / "text"
    text_dir.mkdir()
    overlays, y = [], 65
    for index, (text, size, color) in enumerate(lines):
        path = text_dir / f"line-{index:02}.txt"
        path.write_text(text)
        overlays.append(f"drawtext=fontfile={filter_path(FONT)}:textfile={filter_path(path)}:fontsize={size}:fontcolor={color}:x=650:y={y}")
        y += 100 if index == 0 else 50
    hold = text_dir / "held.txt"
    hold.write_text("Held frame from this run" if hold_image is None else "Held app frame from this run")
    overlays.append(f"drawtext=fontfile={filter_path(FONT)}:textfile={filter_path(hold)}:fontsize=24:fontcolor=000000:box=1:boxcolor=0xfbbf24:boxborderw=10:x=110:y=1020:enable='gte(t,{raw_info['duration_seconds']:.3f})'")
    inputs = ["-i", str(raw_video)]
    if hold_image is None:
        phone = ("[0:v]setpts=PTS-STARTPTS,fps=30,scale=480:960:force_original_aspect_ratio=decrease,"
            "pad=480:960:(ow-iw)/2:(oh-ih)/2:color=0x09111f,tpad=stop_mode=clone:stop_duration=120[phone];")
    else:
        hold_image = Path(hold_image)
        require(hold_image.is_file() and not hold_image.is_symlink()
            and duration - raw_info["duration_seconds"] >= 1,
            "A held image requires at least one second after the full raw clip")
        inputs += ["-loop", "1", "-framerate", "30", "-i", str(hold_image)]
        geometry = ("scale=480:960:force_original_aspect_ratio=decrease,"
            "pad=480:960:(ow-iw)/2:(oh-ih)/2:color=0x09111f,setsar=1")
        # The raw input is complete and untrimmed. Only the still-image segment is bounded.
        phone = (f"[0:v]setpts=PTS-STARTPTS,fps=30,{geometry}[clip];"
            f"[1:v]setpts=PTS-STARTPTS,fps=30,{geometry},"
            f"trim=duration={duration - raw_info['duration_seconds']:.6f},setpts=PTS-STARTPTS[held];"
            "[clip][held]concat=n=2:v=1:a=0[phone];")
    graph = (phone + f"color=c=0x09111f:s=1920x1080:r=30:d={duration}[bg];"
        "[bg][phone]overlay=90:60:shortest=1," + ",".join(overlays) + "[out]")
    video = stage / "weather-demo-0.mp4"
    command(["/usr/bin/ffmpeg", "-nostdin", "-v", "error", *inputs,
        "-filter_complex", graph, "-map", "[out]", "-an", "-t", str(duration),
        "-c:v", "libx264", "-threads", "2", "-preset", "fast", "-crf", "20",
        "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-map_metadata", "-1", str(video)], seconds=1200)
    try:
        info = video_info(video)
    except ValueError as error:
        if not hasattr(error, "render_rejection"):
            error.render_rejection = dict(phase="probe-json", facts={})
        raise
    if not (abs(info["duration_seconds"] - duration) < 0.1 and video.stat().st_size <= 128 * 1024**2):
        error = ValueError("Demo presentation rejected")
        error.render_rejection = dict(phase="output-check", facts=dict(duration_ms=round(info["duration_seconds"] * 1000),
            requested_duration_ms=round(duration * 1000), width=info.get("width", 0), height=info.get("height", 0),
            output_bytes=min(video.stat().st_size, 256 * 1024**2)))
        raise error
    shutil.rmtree(text_dir)
    return video, info


def presentation_lines(identity, products, scoped_demo=False):
    """Fixed completed-run summary; never live counters or new stage assertions."""
    return [
        ("VOLPAROSSA WEATHER", 50, "ffffff"),
        ("Demo 0 / Overmorrow", 34, "7dd3fc"),
        ("Android emulator + EXTERNAL Debian Core", 29, "fbbf24"),
        ("Actual app pixels / normal-speed recording", 27, "cbd5e1"),
        ("App -> local adapter -> external Core -> peers", 28, "ffffff"),
        ("COMPLETED-RUN EVIDENCE / not live counters", 25, "7dd3fc"),
        (f"Cold peer bytes: weather {products['weather']['cold_peer_bytes']:,}", 29, "ffffff"),
        (f"Cold peer bytes: particulate {products['air_quality']['cold_peer_bytes']:,}", 29, "ffffff"),
        ("Reports: two cache-backed refreshes" if scoped_demo else "Two cache-backed refreshes per product", 29, "ffffff"),
        ("No origin body/range fallback during retrieval", 27, "ffffff"),
        ("Pixels: first refresh / HOME / return animation" if scoped_demo else "Real Android taps + background / resume", 25 if scoped_demo else 29, "ffffff"),
        ("Joined delivery and cleanup: passed", 29, "86efac"),
        (f"Run {identity['run_id']} / Core {identity['core_commit'][:12]}", 24, "cbd5e1"),
        (f"Weather {identity['weather_commit'][:12]}", 24, "cbd5e1"),
        ("Technical demo / no standalone mobile Core", 27, "fbbf24"),
        ("No physical-device, expiry-recovery or production claim", 25, "cbd5e1"),
        ("ECMWF IFS + NOAA GEFS-Aerosols forecasts", 24, "cbd5e1"),
    ]


def prepare(evidence, output, execute=False):
    evidence, output = Path(evidence), Path(output)
    require(evidence.is_absolute() and evidence.resolve(strict=True) == evidence
        and evidence.is_dir() and evidence.is_relative_to(ROOT) and evidence != ROOT)
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
        and output.is_relative_to(ROOT) and output != ROOT
        and not output.exists() and not output.is_symlink())
    preview = dict(schema=1, kind="weather-demo-presentation-preview", executed=False,
        publication_authorized=False, includes_installable_binaries=False,
        requires="Same-run original acceptance and separately verified actual Android media")
    if not execute:
        return preview
    require(os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa"
        and os.getuid() == os.geteuid() != 0, "Disposable hosted presentation only")
    verifier = runpy.run_path(str(ROOT / "tests/integration/weather-demo-media.py"))
    media = verifier["verify"](evidence)
    identity = media["identity"]
    require(identity["core_commit"] == os.environ.get("GITHUB_SHA")
        and identity["run_id"] == os.environ.get("GITHUB_RUN_ID")
        and identity["run_attempt"] == os.environ.get("GITHUB_RUN_ATTEMPT"))
    require(media["joined_core_acceptance"] is True and media["production_authority"] is False)
    raw_video = evidence / "demo-media/screen.mp4"
    raw_info = video_info(raw_video)
    require(FONT.is_file() and not FONT.is_symlink())
    duration = max(120, math.ceil(raw_info["duration_seconds"]))
    require(duration <= 180)
    acceptance_path = evidence / "weather-android-hosted-acceptance.json"
    acceptance = json.loads(acceptance_path.read_bytes())
    require(sha(acceptance_path) == media["acceptance_sha256"] and acceptance["identity"] == identity)
    products = acceptance["observations"]["products"]
    lines = presentation_lines(identity, products)
    stage = Path(tempfile.mkdtemp(prefix=".weather-demo-presentation-", dir=output.parent))
    try:
        video, info = render_video(raw_video, stage, duration, raw_info, lines)
        vtt, transcript = captions(duration, raw_info["duration_seconds"])
        (stage / "captions.vtt").write_text(vtt)
        (stage / "transcript.txt").write_text(transcript)
        for name in ("README.md", "release-notes.md", "NOTICES.md", "storyboard.md"):
            shutil.copyfile(DOCS / name, stage / name)
        (stage / "release-notes.md").write_text(
            "# VOLPAROSSA Weather Demo 0 — unpublished review package\n\n"
            "Proposed prerelease: `weather-demo-0.1.0`. Publication requires explicit user approval.\n\n"
            f"Original new-run acceptance: https://github.com/VOLPAROSSA/volparossa/actions/runs/{identity['run_id']}\n\n"
            f"Core `{identity['core_commit']}`; Weather `{identity['weather_commit']}`; attempt `{identity['run_attempt']}`.\n\n"
            "The original delivery/cleanup acceptance and the separate same-run media validator passed. "
            "Actual media still requires visual review. Core runs externally to the Android emulator, "
            "inside the disposable Debian 13 topology. No installable binary is included.\n\n"
            f"Cold peer bytes: weather {products['weather']['cold_peer_bytes']}, "
            f"particulate {products['air_quality']['cold_peer_bytes']}. "
            "Each product has two following cache-backed refreshes; source acquisition is separate "
            "from measured peer retrieval. These are forecasts, not current observations.\n\n"
            "The edited presentation retains the captured clip at normal speed and labels any held "
            "final frame. The evidence panel summarizes the completed run; it is not a live counter. "
            "Original capture and generic sampled screenshots remain included. Exact action timestamps "
            "and screenshot stage labels are not automatically asserted.\n\n"
            "No standalone mobile Core, physical-device/iOS acceptance, concurrent bulk multipath, "
            "forecast-accuracy improvement, real expired-product recovery or production authority is claimed. "
            "See README.md for reproduction, presentation.json for hashes/edits and NOTICES.md for attribution.\n")
        for name in ("weather-android-hosted-acceptance.json", "weather-android-owner-join.json",
                     "weather-android-delivery-evidence.json", "weather-android-vm-cleanup.json"):
            shutil.copyfile(evidence / name, stage / name)
        shutil.copytree(evidence / "demo-media", stage / "demo-media")
        shutil.copytree(DOCS / "reference", stage / "reference")
        if (DOCS / "trials").is_dir():
            shutil.copytree(DOCS / "trials", stage / "trials")
        files = {p.relative_to(stage).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p))
                 for p in sorted(stage.rglob("*")) if p.is_file()}
        result = dict(schema=1, kind="weather-demo-unpublished-presentation", identity=identity,
            original_baseline=dict(core="aac5be7f602fae9754153cdcb5c401ecb9ee7cb6",
                weather="3b90442a9d5be4db73ccf83cba2028364980c3ca", run_id="38717988016"),
            acceptance_sha256=media["acceptance_sha256"], recording_sha256=sha(raw_video),
            video=info, original_video=raw_info, actual_app_pixels=True,
            edits=dict(speed=1, explanatory_panel=True, counters="completed-run summary",
                held_frame_after_seconds=raw_info["duration_seconds"] if duration > raw_info["duration_seconds"] else None,
                exact_action_timestamps_asserted=False),
            external_core=True, physical_device=False, production_authority=False,
            publication_authorized=False, visual_review_required=True,
            includes_installable_binaries=False, ffmpeg_version=command(["/usr/bin/ffmpeg", "-version"], capture=True).decode().splitlines()[0],
            font_sha256=sha(FONT), files=files)
        (stage / "presentation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        sums = {**files, "presentation.json": dict(sha256=sha(stage / "presentation.json"))}
        (stage / "SHA256SUMS").write_text("".join(f"{value['sha256']}  {name}\n" for name, value in sorted(sums.items())))
        require(not output.exists() and not output.is_symlink())
        stage.rename(output)
        return dict(schema=1, kind=result["kind"], identity=identity, executed=True,
            publication_authorized=False, visual_review_required=True, duration_seconds=duration)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.evidence, args.output, args.execute), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        parser.exit(1, "Demo presentation failed; original evidence is unchanged.\n")


if __name__ == "__main__":
    main()
