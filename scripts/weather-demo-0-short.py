#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Presentation-only, hosted-only assembly of an authenticated existing recording."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REVIEW = runpy.run_path(str(ROOT / 'scripts/weather-demo-0-review.py'))
PACKAGE = runpy.run_path(str(ROOT / 'scripts/weather-demo-0-package.py'))
require, digest, decode = (REVIEW[k] for k in ('require', 'digest', 'decode'))
DOCS = ROOT / 'docs/demos/weather-demo-0'
TRIAL = DOCS / 'trials/40017379373'
ARTIFACT = dict(id=12529072030,
    name='weather-demo-scoped-demo-39998753810-1-5c7c5470cef31c37d0cb4f961f221529bda080fb',
    size_in_bytes=94136114,
    digest='sha256:a6f012f993f6ed17fc2566c1fe3b84b20d9abc9e5c2c60c0f7b5896117922b06')
SOURCE = '5c7c5470cef31c37d0cb4f961f221529bda080fb'
MANIFEST_SHA = 'ec69f97dc17c103f750c9e62667e6af5b745118621e24d7dbed5c4fd2292527b'
RAW_SHA = 'bca54a8f677238f26daff6921bb3af0c661e1b39d0aada5ce3f161fda380d5c8'
TECHNICAL_SHA = 'e4f72aa6d8236c56ef9d638d5f40563d7865b5411b6d3e7510dd43cee42c4d40'
DURATION = 65.578911
STATE = {'stage': 'arguments', 'owned_output': False, 'facts': {}}
# Explanatory cards, not exact action-time assertions. Boundaries follow already
# reviewed native PTS; no runtime inference is made by this presentation tool.
PHASES = (
    (0, 8, 'Real forecasts', 'On screen',
     ('Weather / Overmorrow', 'Actual installed Android app.'),
     ('Recorded developer demo.', 'Core runs externally.')),
    (8, 18, 'From peers', 'On screen',
     ('The app opens and loads.',),
     ('Acceptance reports', 'Real forecast products', 'retrieved through Core peers.')),
    (18, 28.536533, 'Two products', 'On screen',
     ('The forecast view is loading.',),
     ('Acceptance reports', 'Temperature and PM2.5', 'forecasts delivered to the app.')),
    (28.536533, 31.266356, 'Real forecasts', 'On screen',
     ('Temperature, then PM2.5.', 'Native source validity.'),
     ('Forecasts, not observations.', 'Read native units and times.')),
    (31.266356, 45.965578, 'Cached refresh', 'On screen',
     ('Refresh in progress;', 'then the forecast returns.'),
     ('Acceptance reports', 'Refresh can reuse a valid', 'forecast from the cache.')),
    (45.965578, 58.799733, 'Another refresh', 'On screen',
     ('Second refresh starts.',),
     ('Acceptance reports', 'Its completion is verified', 'by reports, not these pixels.')),
    (58.799733, DURATION, 'Background / return', 'On screen',
     ('HOME, then return', 'animation only.', 'No settled resume frame.'),
     ('Acceptance reports', 'Background / resume checked.', 'Networking is report evidence.')),
)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def selected_artifact():
    api = REVIEW['api']
    base = 'repos/VOLPAROSSA/volparossa/actions/runs/40017379373'
    latest, run = api(base), api(base + '/attempts/1')
    for record in (latest, run):
        require(record.get('id') == 40017379373 and record.get('run_attempt') == 1
            and record.get('head_sha') == SOURCE and record.get('status') == 'completed'
            and record.get('conclusion') == 'success'
            and record.get('repository', {}).get('full_name') == REVIEW['REPOSITORY']
            and record.get('head_repository', {}).get('full_name') == REVIEW['REPOSITORY'],
            'exact successful source attempt required')
    artifact = api('repos/VOLPAROSSA/volparossa/actions/artifacts/12529072030')
    require(all(artifact.get(k) == v for k, v in ARTIFACT.items())
        and artifact.get('expired') is False
        and artifact.get('workflow_run', {}).get('id') == 40017379373
        and artifact.get('workflow_run', {}).get('head_sha') == SOURCE,
        'pinned artifact identity rejected')
    utc = REVIEW['utc']
    require(utc(run['run_started_at']) <= utc(artifact['created_at'])
        <= utc(artifact['updated_at']) <= utc(run['updated_at']), 'artifact time window rejected')
    return dict(artifact=ARTIFACT, run=run)


def archive_members(archive):
    entries, total = {}, 0
    require(len(archive.infolist()) <= 2048, 'ZIP entry budget')
    for info in archive.infolist():
        name = info.filename
        require(re.fullmatch(r'[A-Za-z0-9_./-]+', name) and not name.startswith('/')
            and all(part and part not in {'.', '..', '.git'} for part in name.rstrip('/').split('/')),
            'ZIP path rejected')
        mode = info.external_attr >> 16
        require(name.rstrip('/') not in entries and not info.flag_bits & 1
            and stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}
            and info.is_dir() == name.endswith('/')
            and (not stat.S_ISDIR(mode) or info.is_dir())
            and (not info.is_dir() or info.file_size == 0), 'ZIP duplicate or type rejected')
        total += info.file_size
        require(0 <= info.file_size <= REVIEW['MAX_ZIP'] and total <= REVIEW['MAX_EXPANDED'],
            'ZIP expanded budget')
        entries[name.rstrip('/')] = info
    return entries


def extract_selected(archive_path, output):
    require(archive_path.stat().st_size == ARTIFACT['size_in_bytes']
        and 'sha256:' + digest(archive_path) == ARTIFACT['digest'], 'pinned ZIP mismatch')
    original = output / 'technical-original'
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive_members(archive)
        manifest_raw = archive.read(entries['presentation/presentation.json'])
        require(hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA, 'original manifest mismatch')
        manifest = decode(manifest_raw)
        require(manifest_raw == (TRIAL / 'presentation.json').read_bytes(), 'committed manifest mismatch')
        for name in ('scoped-admission.json', 'native-timing.json'):
            require(archive.read(entries[name]) == (TRIAL / name).read_bytes(), 'committed admission mismatch')
        files = manifest['files']
        expected = {'captions.vtt', 'preview-090.png', 'screen.mp4', 'transcript.txt',
                    'visual-review.json', 'weather-demo-0.mp4'} | {
                    f'screenshots/frame-{n}.png' for n in ('206', '215', '240', '348', '439', '489')}
        require(set(files) == expected and files['screen.mp4']['sha256'] == RAW_SHA
            and files['weather-demo-0.mp4']['sha256'] == TECHNICAL_SHA, 'selected inventory mismatch')
        # Read only fixed admitted presentation members; never unpack the archive.
        for name in sorted(expected):
            info = entries['presentation/' + name]
            require(REVIEW['zip_hash'](archive, info) == files[name], 'original member hash mismatch')
        original.mkdir(mode=0o700)
        for name in sorted(expected):
            target = original / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(archive.read(entries['presentation/' + name]))
        (original / 'presentation.json').write_bytes(manifest_raw)
        for name in ('scoped-admission.json', 'native-timing.json'):
            (original / name).write_bytes(archive.read(entries[name]))
    return manifest


def captions():
    lines = ['WEBVTT', '', 'NOTE Explanatory summaries, not exact action timestamps.', '']
    transcript = ['VOLPAROSSA Weather / Overmorrow. Android emulator; EXTERNAL Debian Core.',
        'Full original recording, normal speed, resampled to 30 fps. No held ending.',
        'The original runtime failed its duration admission gate. Separate scoped media admission passed.']
    for start, stop, title, label, body, note in PHASES:
        text = '. '.join((title, label + ': ' + ' '.join(body), ' '.join(note)))
        lines.extend([f"{PACKAGE['timestamp'](start)} --> {PACKAGE['timestamp'](stop)}", text, ''])
        transcript.append(text)
    transcript.append('Data: ECMWF and NOAA. App: Overmorrow. Font: DejaVu. See NOTICES.md. '
        'This presentation grants no publication or production authority.')
    return '\n'.join(lines), '\n\n'.join(transcript) + '\n'


def overlay_graph(text_dir):
    text_dir.mkdir(mode=0o700)
    overlays = []
    def draw(text, x, y, size, color='ffffff', enable=None):
        path = text_dir / f'line-{len(overlays):03}.txt'
        path.write_text(text, encoding='utf-8')
        part = (f"drawtext=fontfile={PACKAGE['filter_path'](PACKAGE['FONT'])}:"
            f"textfile={PACKAGE['filter_path'](path)}:expansion=none:fontsize={size}:"
            f"fontcolor={color}:x={x}:y={y}")
        if enable is not None:
            part += f":enable='{enable}'"
        overlays.append(part)
    draw('VOLPAROSSA Weather / Overmorrow', 32, 22, 36)
    draw('Android emulator  •  EXTERNAL Debian Core', 32, 78, 32, 'fbbf24')
    draw('Recorded demo • normal speed • no held ending', 778, 160, 20, 'a7c6ed')
    for start, stop, title, label, body, note in PHASES:
        enable = f'gte(t,{start:.6f})*lt(t,{stop:.6f})'
        draw(title, 778, 236, 30, enable=enable)
        draw(label, 778, 326, 27, '7dd3fc', enable)
        for i, text in enumerate(body):
            draw(text, 778, 382 + i * 42, 25, enable=enable)
        for i, text in enumerate(note):
            draw(text, 778, 586 + i * 42, 25, 'cbd5e1', enable)
    draw('Recorded pixels and acceptance reports', 778, 1010, 23, 'cbd5e1')
    draw('are different kinds of evidence.', 778, 1050, 23, 'cbd5e1')
    draw('Developer demo • external Core', 778, 1190, 26, 'fbbf24')
    draw('Not a standalone phone release', 778, 1232, 25, 'fbbf24')
    draw('Data: ECMWF / NOAA • App: Overmorrow • Font: DejaVu • See NOTICES.md', 32, 1416, 18, 'cbd5e1')
    return ('[0:v:0]setpts=PTS-STARTPTS,fps=30,setsar=1,'
            'pad=1280:1440:32:120:color=0x09111f,' + ','.join(overlays) + '[out]')


def check_font(font, expected_sha256):
    # Data identity is pinned by content; executable tool ownership is checked
    # separately by REVIEW['tool']. Match the accepted presentation font guard.
    regular = font.is_file() and not font.is_symlink()
    STATE['facts'] = dict(font_regular_nonsymlink=regular)
    require(regular, 'fixed data font rejected')
    STATE['facts']['font_sha256_matches'] = digest(font) == expected_sha256
    require(STATE['facts']['font_sha256_matches'], 'fixed data font rejected')


def render(output, original_manifest):
    STATE['stage'] = 'tool-and-font'
    ffmpeg = REVIEW['tool']('/usr/bin/ffmpeg')
    REVIEW['tool']('/usr/bin/ffprobe')
    font = PACKAGE['FONT']
    check_font(font, original_manifest['font_sha256'])
    command = REVIEW['command']
    # Use bounded shared child supervisor, including ffprobe, without its separate
    # unbounded subprocess helper. This does not rerun native timing admission.
    PACKAGE['video_info'].__globals__['command'] = lambda args, **kw: command(
        args, seconds=kw.get('seconds', 30), maximum=65536, reject_stderr=True)
    raw = output / 'technical-original/screen.mp4'
    STATE['stage'] = 'raw-profile'
    raw_info = PACKAGE['video_info'](raw)
    STATE['facts'] = dict(duration_ms=round(raw_info['duration_seconds'] * 1000),
        width=raw_info['width'], height=raw_info['height'])
    require(raw_info == original_manifest['original_video'], 'raw video profile changed')
    text_dir = output / 'render-text'
    graph = overlay_graph(text_dir)
    video = output / 'weather-demo-0-short.mp4'
    STATE['stage'] = 'render-video'
    command([ffmpeg, '-nostdin', '-v', 'error', '-i', str(raw), '-filter_complex', graph,
        '-map', '[out]', '-an', '-c:v', 'libx264', '-threads', '2', '-preset', 'fast',
        '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-map_metadata', '-1',
        str(video)], seconds=1200, reject_stderr=True)
    STATE['stage'] = 'output-profile'
    video_info = PACKAGE['video_info'](video)
    STATE['facts'] = dict(duration_ms=round(video_info['duration_seconds'] * 1000),
        width=video_info['width'], height=video_info['height'],
        output_bytes=min(video.stat().st_size, REVIEW['MAX_ZIP'] + 1))
    require(60 <= video_info['duration_seconds'] <= 75
        and abs(video_info['duration_seconds'] - DURATION) < 0.1
        and (video_info['width'], video_info['height']) == (1280, 1440)
        and video.stat().st_size <= REVIEW['MAX_ZIP'], 'short video profile rejected')
    STATE['stage'] = 'previews'
    for second in (29, 40, 65):
        command([ffmpeg, '-nostdin', '-v', 'error', '-ss', str(second), '-i', str(video),
            '-frames:v', '1', '-threads', '1', str(output / f'preview-{second:03}.png')],
            seconds=60, reject_stderr=True)
    STATE['stage'] = 'thumbnail'
    # Actual admitted native frame, rendered through the same labelled layout.
    command([ffmpeg, '-nostdin', '-v', 'error', '-i',
        str(output / 'technical-original/screenshots/frame-206.png'), '-filter_complex', graph,
        '-map', '[out]', '-frames:v', '1', '-threads', '1', str(output / 'thumbnail.png')],
        seconds=60, reject_stderr=True)
    STATE['stage'] = 'font-after-render'
    check_font(font, original_manifest['font_sha256'])
    STATE['stage'] = 'export'
    vtt, transcript = captions()
    (output / 'captions.vtt').write_text(vtt, encoding='utf-8')
    (output / 'transcript.txt').write_text(transcript, encoding='utf-8')
    (output / 'NOTICES.md').write_bytes((DOCS / 'NOTICES.md').read_bytes())
    (output / 'attribution.txt').write_text('ECMWF / NOAA data; Overmorrow app; DejaVu font.\n'
        'Full original notices are preserved unchanged in NOTICES.md.\n', encoding='utf-8')
    result = dict(schema=1, kind='weather-demo-short-presentation', source_artifact=ARTIFACT,
        admitted_source=dict(run_id='40017379373', run_attempt='1', core_commit=SOURCE),
        identity=original_manifest['identity'], original_recording_sha256=RAW_SHA,
        original_technical_video_sha256=TECHNICAL_SHA, original_technical_manifest_sha256=MANIFEST_SHA,
        original_run_conclusion='failure', original_encoded_duration_failure_preserved=True,
        new_runtime_executed=False, publication_authorized=False, production_authority=False,
        standalone_mobile_core=False, final_presentation_visual_review_required=True,
        video=video_info, pixel_scope=original_manifest['pixel_scope'],
        report_only_scope=original_manifest['report_only_scope'],
        edits=dict(speed=1, full_original_clip=True, raw_clip_trimmed=False, held_ending=False,
            presentation_cadence='30fps CFR; source frames may repeat or be omitted by resampling',
            native_app_pixels='720x1280, unscaled and uncropped', exact_action_timestamps_asserted=False),
        thumbnail=dict(source='technical-original/screenshots/frame-206.png',
            source_pts_seconds=28.536533, layout_card_time_seconds=0),
        presentation_execution={k: os.environ[k] for k in
            ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
        ffmpeg_version=command([ffmpeg, '-version'], maximum=16384, seconds=10).decode().splitlines()[0],
        font_sha256=digest(font))
    result['files'] = {p.relative_to(output).as_posix(): dict(bytes=p.stat().st_size, sha256=digest(p))
        for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'input.zip'}
    write_json(output / 'short-presentation.json', result)
    return result


def prepare(output, *, execute=False):
    STATE.update(stage='arguments', owned_output=False, facts={})
    require(output.is_absolute() and output.resolve() == output
        and output.is_relative_to(ROOT / '.cache')
        and re.fullmatch(r'[A-Za-z0-9_./-]+', str(output)) is not None,
        'new absolute workspace .cache path required')
    require(not output.exists(), 'output already exists')
    preview = dict(execute=execute, source_artifact=ARTIFACT, output=str(output),
        new_runtime_executed=False, publication_authorized=False)
    if not execute:
        return preview
    STATE['stage'] = 'hosted-guard'
    REVIEW['hosted']()
    require('VERSION_ID="24.04"' in Path('/etc/os-release').read_text(),
        'approved Ubuntu 24.04 runner required')
    STATE['stage'] = 'source-api'
    identity = selected_artifact()
    output.mkdir(mode=0o700, parents=True)
    STATE['owned_output'] = True
    STATE['stage'] = 'source-download'
    REVIEW['download'](ARTIFACT, output / 'input.zip')
    write_json(output / 'download-record.json', identity)
    STATE['stage'] = 'source-extraction'
    manifest = extract_selected(output / 'input.zip', output)
    # This is our temporary authenticated download, not the retained original ZIP.
    # The API receipt, digest and exact selected byte copies remain in the output.
    (output / 'input.zip').unlink()
    return render(output, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        result = prepare(args.output, execute=args.execute)
    except Exception as error:
        # Preserve partial outputs and bounded diagnostics; no cleanup discards
        # failed render evidence. This fixed-message projection never emits a token.
        if STATE['owned_output']:
            facts = dict(STATE['facts'])
            if hasattr(error, 'render_rejection'):
                facts = error.render_rejection['facts']
            category = ('native-child-failed' if isinstance(error, REVIEW['ChildFailure'])
                else 'io' if isinstance(error, OSError) else 'validation')
            if isinstance(error, REVIEW['ChildFailure']):
                facts['child_status'] = error.status if -255 <= error.status <= 255 else None
            literal = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else ''
            category = {'child timeout': 'native-timeout',
                'child emitted error diagnostics': 'native-diagnostics',
                'child diagnostic limit exceeded': 'native-diagnostic-budget',
                'child output limit exceeded': 'native-output-budget'}.get(literal, category)
            write_json(args.output / 'short-failure.json', dict(schema=1,
                stage=STATE['stage'], category=category, facts=facts,
                new_runtime_executed=False, publication_authorized=False))
        print('short presentation rejected: ' + type(error).__name__, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
