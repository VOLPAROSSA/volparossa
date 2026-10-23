#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Final editorial presentation of authenticated footage; native execution is hosted-only."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import runpy
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SHORT = runpy.run_path(str(ROOT / 'scripts/weather-demo-0-short.py'))
REVIEW, PACKAGE = SHORT['REVIEW'], SHORT['PACKAGE']
require, digest, write_json = (SHORT[k] for k in ('require', 'digest', 'write_json'))
STATE = {'stage': 'arguments', 'owned_output': False, 'facts': {}}
RAW_DURATION = SHORT['DURATION']
MOVING_DURATION = RAW_DURATION - 10
DURATION = MOVING_DURATION + 5
OLD_SHORT_SHA = 'b1a95bbddcdb249759483749756d6c4d3ee6ba8a8cc21204742b40c18d15d725'
EDIT_MAP = (
    dict(output_start=0, output_end=3, source_start=28.4, source_end=31.4, speed=1, kind='replayed-preview'),
    dict(output_start=3, output_end=15, source_start=0, source_end=12, speed=1, kind='earlier-loading'),
    dict(output_start=15, output_end=MOVING_DURATION, source_start=25, source_end=RAW_DURATION, speed=1, kind='continuation'),
    dict(output_start=MOVING_DURATION, output_end=DURATION, kind='closing-card'),
)
CUES = (
    (0, 3, ('Recorded preview; excerpt replayed later.',)),
    (3, 10, ('Earlier footage; loading is abbreviated.', 'Core runs externally to Android.')),
    (10, 15, ('Real Android app footage at normal speed.',)),
    (15, 18.5, ('Editorial cut; 13 seconds omitted.',)),
    (18.5, 21.266356, ('Temperature, then air-quality forecasts.',)),
    (21.266356, 35.965578, ('First refresh loads; forecasts return.', 'Reports verify cached product reuse.')),
    (35.965578, 48.799733, ('Second refresh starts.', 'Reports verify both cached refreshes.')),
    (48.799733, MOVING_DURATION, ('HOME, then a brief return animation.', 'Reports verify background and resume.')),
    (MOVING_DURATION, DURATION, ('VOLPAROSSA Weather Demo 0.', 'Development preview with external Core.')),
)
PHASES = (
    (0, 3, 'A real forecast', ('Recorded preview', 'Replayed later in this edit.'), ('Not an extra retrieval.',)),
    (3, 15, 'Earlier: loading', ('The installed app opens.', 'Loading is abbreviated.'), ('Not a latency measurement.',)),
    (15, 18.536533, 'Continue loading', ('13 seconds omitted.', 'All moving footage: 1x.'), ('Not a latency measurement.',)),
    (18.536533, 21.266356, 'Real forecasts', ('Temperature, then PM2.5.', 'Native values and validity.'), ('Model forecasts,', 'not observations.')),
    (21.266356, 35.965578, 'Cached refresh', ('First refresh loads.', 'Then forecasts return.'), ('Acceptance reports verify', 'cached product reuse.')),
    (35.965578, 48.799733, 'Another refresh', ('Second refresh starts.',), ('Both cache refreshes', 'verified in reports.', 'Completion not visible here.')),
    (48.799733, MOVING_DURATION, 'Background / return', ('HOME, then a brief', 'return animation.'), ('Lifecycle checked in reports.', 'No settled resume frame.')),
)


def captions():
    lines = ['WEBVTT', '', 'NOTE Descriptive captions for silent footage; no narration.',
             'Editorial boundaries are not exact input timestamps.', '']
    transcript = [
        'VOLPAROSSA Weather Demo 0. Silent descriptive transcript; no spoken audio.',
        'Genuine Android emulator recording; Core runs externally in a Debian test environment.',
        'Edit: source 28.4–31.4 is a three-second forecast preview, replayed later, not another retrieval. '
        'Source 0–12 follows at output 3–15. The explicit cut at output 15 skips source 12–25 '
        '(13 seconds). Source 25–65.578911 continues at output 15–55.578911. '
        'A five-second editorial closing card follows. Moving app footage remains at 1x; '
        '30fps resampling can repeat or omit frames. The abbreviated loading is not a measured latency.',
        'Original runtime 39998753810 failed its media duration gate. Separate scoped media validation '
        '40017379373 passed at source ' + SHORT['SOURCE'] + '; neither result is relabelled. '
        'Artifact 12529072030; raw SHA-256 ' + SHORT['RAW_SHA'] + '.',
    ]
    for start, end, text in CUES:
        interval = PACKAGE['timestamp'](start) + ' --> ' + PACKAGE['timestamp'](end)
        lines.extend([interval, *text, ''])
        transcript.append(interval + '\n' + ' '.join(text))
    transcript.extend([
        'Pixels show temperature at source 28.536533 (output 18.536533), air quality at source '
        '29.068/30.551 (output 19.068/20.551), first refresh starting at source 31.266356 '
        '(output 21.266356) and completing near source 45.391 (output 35.391), second refresh '
        'starting at source 45.965578 (output 35.965578), HOME near source 58.799733 '
        '(output 48.799733), and a return animation near source 65.39 (output 55.39). '
        'No visible second-refresh completion or settled return view is claimed.',
        'Retained acceptance reports verify real weather and air-quality products retrieved through '
        'peers, two cache-backed refreshes per product, and background/resume behavior. Pixels alone '
        'do not prove networking. Complete wind, precipitation and PM10 columns are not claimed. '
        'Native source times and units matter; forecasts are not observations.',
        'Development preview only: no standalone Android Core, physical-device compatibility or '
        'production readiness is established. Thumbnail topology is conceptual, not packet evidence.',
        'Data: ECMWF and NOAA. App: Overmorrow. Font: DejaVu. See unchanged NOTICES.md. '
        'No product builds or network trials were rerun. Publication remains subject to approval.',
    ])
    return '\n'.join(lines), '\n\n'.join(transcript) + '\n'


class Layout:
    """Text lives outside the genuine app pane; no replacement UI is drawn."""
    def __init__(self, directory):
        directory.mkdir(mode=0o700)
        self.directory, self.parts = directory, []

    def text(self, value, x, y, size, color='ffffff', enable=None):
        path = self.directory / f'line-{len(self.parts):03}.txt'
        path.write_text(value, encoding='utf-8')
        part = (f"drawtext=fontfile={PACKAGE['filter_path'](PACKAGE['FONT'])}:"
                f"textfile={PACKAGE['filter_path'](path)}:expansion=none:fontsize={size}:"
                f"fontcolor={color}:x={x}:y={y}")
        if enable:
            part += f":enable='{enable}'"
        self.parts.append(part)

    def box(self, x, y, w, h, color):
        self.parts.append(f'drawbox=x={x}:y={y}:w={w}:h={h}:color={color}:t=fill')

    def graph(self):
        return ','.join(self.parts)


def video_graph(output):
    layout = Layout(output / 'video-text')
    layout.text('VOLPAROSSA Weather', 32, 18, 38)
    layout.text('Android emulator  /  EXTERNAL Debian Core', 32, 72, 30, 'e2b95e')
    for start, end, title, body, notes in PHASES:
        enabled = f'gte(t,{start:.6f})*lt(t,{end:.6f})'
        layout.text(title, 778, 238, 29, 'e2b95e', enabled)
        layout.text('On screen', 778, 332, 25, '8ecce8', enabled)
        for index, line in enumerate(body):
            layout.text(line, 778, 390 + index * 42, 24, enable=enabled)
        for index, line in enumerate(notes):
            layout.text(line, 778, 612 + index * 42, 24, 'cbd5e1', enabled)
    layout.text('Recorded preview — excerpt', 778, 142, 24, 'e2b95e', 'lt(t,3)')
    layout.text('Earlier footage', 778, 142, 25, 'e2b95e', 'gte(t,3)*lt(t,15)')
    layout.text('— loading abbreviated', 778, 178, 24, 'e2b95e', 'gte(t,3)*lt(t,15)')
    layout.text('CUT: 13 seconds omitted', 778, 142, 25, 'e2b95e', 'gte(t,15)*lt(t,18.5)')
    layout.text('Not measured loading latency', 778, 184, 23, 'e2b95e', 'gte(t,15)*lt(t,18.5)')
    layout.text('Development preview', 778, 1190, 25, 'e2b95e')
    layout.text('Core runs outside Android', 778, 1232, 24, 'e2b95e')
    layout.text('Data: ECMWF / NOAA • App: Overmorrow • Font: DejaVu • See NOTICES.md', 32, 1416, 18, 'cbd5e1')
    closing = Layout(output / 'closing-text')
    closing.box(110, 360, 1060, 4, '0xe2b95e')
    closing.text('VOLPAROSSA', '(w-text_w)/2', 440, 84, 'e2b95e')
    closing.text('One shared core. Multiple applications.', '(w-text_w)/2', 580, 40)
    closing.text('Weather Demo 0', '(w-text_w)/2', 760, 48)
    closing.text('Real forecasts through cooperating peers', '(w-text_w)/2', 850, 34, 'cbd5e1')
    closing.text('github.com/VOLPAROSSA', '(w-text_w)/2', 1030, 36, 'e2b95e')
    closing.text('Development preview — Core runs externally to Android', '(w-text_w)/2', 1260, 28, 'cbd5e1')
    return ('[0:v]setpts=PTS-STARTPTS,fps=30,split=3[p][e][c];'
        '[p]trim=start=28.4:end=31.4,setpts=PTS-STARTPTS[p0];'
        '[e]trim=start=0:end=12,setpts=PTS-STARTPTS[e0];'
        f'[c]trim=start=25:end={RAW_DURATION},setpts=PTS-STARTPTS[c0];'
        '[p0][e0][c0]concat=n=3:v=1:a=0,setsar=1,'
        'pad=1280:1440:32:120:color=0x09111f,' + layout.graph() + '[moving];'
        'color=c=0x09111f:s=1280x1440:r=30:d=5,' + closing.graph() + '[closing];'
        '[moving][closing]concat=n=2:v=1:a=0[out]')


def thumbnail_graph(output):
    design = Layout(output / 'thumbnail-text')
    design.box(100, 110, 80, 6, '0xe2b95e')
    design.text('VOLPAROSSA', 100, 155, 46, 'e2b95e')
    design.text('Weather', 92, 228, 136)
    design.text('Real forecasts.', 100, 408, 56)
    design.text('Shared through peers.', 100, 480, 56)
    design.text('Conceptual topology', 100, 645, 28, 'a9b6c9')
    for x, width, label in ((100, 220, 'Weather'), (390, 290, 'External Core'), (750, 195, 'Peers')):
        design.box(x, 705, width, 76, '0x1c2c43')
        design.text(label, x + 22, 725, 30, 'e2b95e')
    design.text('→', 337, 717, 40, 'e2b95e')
    design.text('→', 697, 717, 40, 'e2b95e')
    design.text('Technical demo — external Core', 100, 930, 36, 'e2b95e')
    design.text('Recorded Android app / Overmorrow', 1185, 969, 23, 'a9b6c9')
    return ('color=c=0x09111f:s=1920x1080[bg];'
        '[0:v]scale=450:800:flags=lanczos,setsar=1[app];'
        '[bg][app]overlay=1300:130,' + design.graph() + '[out]')


def verify_video(video, info):
    command = REVIEW['command']
    # Full decode: error-level diagnostic output is rejected, not discarded.
    command(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-i', str(video), '-map', '0:v:0',
             '-f', 'null', '-'], seconds=600, reject_stderr=True)
    value = json.loads(command(['/usr/bin/ffprobe', '-v', 'error', '-select_streams', 'v:0',
        '-show_frames', '-show_entries', 'frame=best_effort_timestamp_time', '-of', 'json', str(video)],
        maximum=512000, seconds=120, reject_stderr=True))
    times = [float(frame['best_effort_timestamp_time']) for frame in value['frames']]
    require(1800 <= len(times) <= 1900 and all(math.isfinite(t) for t in times)
        and abs(times[0]) < 0.0001 and all(abs(b-a-1/30) < 0.00001 for a, b in zip(times, times[1:]))
        and abs(times[-1] + 1/30 - info['duration_seconds']) < 0.01, 'frame PTS rejected')
    return dict(full_decode_to_null=True, error_diagnostics_rejected=True, decoded_frames=len(times),
        first_pts=times[0], last_pts=times[-1], cadence='30fps CFR', human_full_realtime_playback=False,
        visual_review_required=True, contact_sheet_interval_seconds=1,
        contact_sheet_coverage='Every integer second from 0 through 60 inclusive; 2 sheets')


def render(output, original):
    command = REVIEW['command']
    STATE['stage'] = 'tool-and-font'
    for tool in ('ffmpeg', 'ffprobe'):
        REVIEW['tool']('/usr/bin/' + tool)
    SHORT['check_font'](PACKAGE['FONT'], original['font_sha256'])
    PACKAGE['video_info'].__globals__['command'] = lambda args, **kw: command(
        args, seconds=kw.get('seconds', 30), maximum=65536, reject_stderr=True)
    raw = output / 'technical-original/screen.mp4'
    STATE['stage'] = 'source-profile'
    raw_info = PACKAGE['video_info'](raw)
    require(raw_info == original['original_video'], 'original profile changed')
    STATE['facts'] = dict(duration_ms=round(raw_info['duration_seconds']*1000),
                          width=raw_info['width'], height=raw_info['height'])
    graph = video_graph(output)
    video = output / 'weather-demo-0-final.mp4'
    render_command = ['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-i', str(raw),
        '-filter_complex', graph, '-map', '[out]', '-an', '-c:v', 'libx264', '-threads', '2',
        '-preset', 'fast', '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
        '-map_metadata', '-1', str(video)]
    STATE['stage'] = 'render-video'
    command(render_command, seconds=1200, reject_stderr=True)
    STATE['stage'] = 'verify-video'
    info = PACKAGE['video_info'](video)
    STATE['facts'] = dict(duration_ms=round(info['duration_seconds']*1000), width=info['width'], height=info['height'])
    require(abs(info['duration_seconds']-DURATION) < 0.1 and (info['width'],info['height']) == (1280,1440)
            and video.stat().st_size <= REVIEW['MAX_ZIP'], 'final video profile rejected')
    verification = verify_video(video, info)
    STATE['stage'] = 'contact-sheets'
    font = PACKAGE['filter_path'](PACKAGE['FONT'])
    command(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-i', str(video), '-vf',
        f"fps=1,scale=213:240,drawtext=fontfile={font}:text='%{{pts\\:hms}}':fontsize=15:fontcolor=white:box=1:boxcolor=black:x=3:y=3,tile=6x6:padding=4:margin=4:color=0x09111f",
        '-frames:v', '2', '-threads', '1', str(output / 'contact-sheet-%02d.png')], seconds=180, reject_stderr=True)
    for name, second in (('opening', 0.5), ('before-cut', 14.9), ('after-cut', 15.1),
                         ('weather', 18.55), ('refresh', 30), ('return', 55.5), ('closing', 58)):
        command(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-ss', str(second), '-i', str(video),
            '-frames:v', '1', '-threads', '1', str(output / f'preview-{name}.png')], seconds=60, reject_stderr=True)
    STATE['stage'] = 'thumbnail'
    command(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-i',
        str(output / 'technical-original/screenshots/frame-206.png'), '-filter_complex', thumbnail_graph(output),
        '-map', '[out]', '-frames:v', '1', '-threads', '1', str(output / 'thumbnail-final.png')],
        seconds=60, reject_stderr=True)
    command(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-i', str(output / 'thumbnail-final.png'),
        '-vf', 'scale=960:540:flags=lanczos', '-frames:v', '1', '-c:v', 'libwebp', '-quality', '85',
        '-threads', '1', str(output / 'thumbnail-final-web.webp')], seconds=60, reject_stderr=True)
    SHORT['check_font'](PACKAGE['FONT'], original['font_sha256'])
    STATE['stage'] = 'export'
    vtt, transcript = captions()
    (output / 'captions.vtt').write_text(vtt, encoding='utf-8')
    (output / 'transcript.txt').write_text(transcript, encoding='utf-8')
    (output / 'NOTICES.md').write_bytes((SHORT['DOCS'] / 'NOTICES.md').read_bytes())
    (output / 'attribution.txt').write_text('ECMWF / NOAA data; Overmorrow app; DejaVu font.\nFull unchanged notices: NOTICES.md.\n')
    (output / 'README.md').write_bytes((SHORT['DOCS'] / 'final-presentation.md').read_bytes())
    result = dict(schema=1, kind='weather-demo-final-presentation', source_artifact=SHORT['ARTIFACT'],
        admitted_source=dict(run_id='40017379373', attempt=1, source=SHORT['SOURCE']),
        original_recording_sha256=SHORT['RAW_SHA'], original_technical_video_sha256=SHORT['TECHNICAL_SHA'],
        previous_short_video_sha256=OLD_SHORT_SHA, original_manifest_sha256=SHORT['MANIFEST_SHA'],
        original_run_conclusion='failure', original_encoded_duration_failure_preserved=True,
        new_runtime_executed=False, publication_authorized=False, standalone_mobile_core=False,
        video=info, edits=EDIT_MAP, moving_speed=1, app_pane='720x1280 unscaled, uncropped',
        cadence='30fps resampling; no interpolation or speedup', verification=verification,
        thumbnail=dict(source='technical-original/screenshots/frame-206.png', native_pts=28.536533,
            dimensions=[1920,1080], web_dimensions=[960,540], web_quality=85, topology='conceptual, not runtime evidence'),
        pixel_scope=original['pixel_scope'], report_only_scope=original['report_only_scope'],
        render_command=render_command, tool_identities={name: dict(path='/usr/bin/'+name,
            sha256=digest(Path('/usr/bin/'+name)), version=command(['/usr/bin/'+name,'-version'],
            maximum=16384,seconds=10).decode().splitlines()[0]) for name in ('ffmpeg','ffprobe')},
        font_sha256=digest(PACKAGE['FONT']), presentation_execution={key: os.environ[key] for key in
            ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')})
    result['files'] = {path.relative_to(output).as_posix(): dict(bytes=path.stat().st_size,sha256=digest(path))
        for path in sorted(output.rglob('*')) if path.is_file()}
    write_json(output / 'presentation-manifest.json', result)
    inventory = [path for path in sorted(output.rglob('*')) if path.is_file()]
    (output / 'SHA256SUMS').write_text(''.join(digest(path)+'  '+path.relative_to(output).as_posix()+'\n' for path in inventory))
    with zipfile.ZipFile(output / 'weather-demo-0-final-review.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.rglob('*')):
            if path.is_file() and path.suffix != '.zip':
                archive.write(path, path.relative_to(output).as_posix())
    write_json(output / 'review-archive.json', dict(file='weather-demo-0-final-review.zip',
        sha256=digest(output / 'weather-demo-0-final-review.zip'), publication_authorized=False))
    return result


def prepare(output, *, execute=False):
    STATE.update(stage='arguments', owned_output=False, facts={})
    require(output.is_absolute() and output.resolve() == output and output.is_relative_to(ROOT / '.cache')
        and re.fullmatch(r'[A-Za-z0-9_./-]+', str(output)), 'new absolute workspace .cache path required')
    require(not output.exists(), 'output already exists')
    preview = dict(execute=execute, output=str(output), edit_map=EDIT_MAP, expected_duration=DURATION,
                   source_artifact=SHORT['ARTIFACT'], new_runtime_executed=False, publication_authorized=False)
    if not execute:
        return preview
    STATE['stage'] = 'hosted-guard'
    REVIEW['hosted']()
    require('VERSION_ID="24.04"' in Path('/etc/os-release').read_text(), 'Ubuntu 24.04 required')
    STATE['stage'] = 'source-api'
    identity = SHORT['selected_artifact']()
    output.mkdir(mode=0o700, parents=True)
    STATE['owned_output'] = True
    STATE['stage'] = 'source-download'
    REVIEW['download'](SHORT['ARTIFACT'], output / 'input.zip')
    write_json(output / 'download-record.json', identity)
    STATE['stage'] = 'source-extraction'
    original = SHORT['extract_selected'](output / 'input.zip', output)
    (output / 'input.zip').unlink()
    return render(output, original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        result = prepare(args.output, execute=args.execute)
    except Exception as error:
        if STATE['owned_output']:
            category = 'io' if isinstance(error, OSError) else 'validation'
            if isinstance(error, REVIEW['ChildFailure']):
                category = 'native-child-failed'
            literal = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else ''
            category = {'child timeout':'native-timeout', 'child emitted error diagnostics':'native-diagnostics',
                'child diagnostic limit exceeded':'native-diagnostic-budget',
                'child output limit exceeded':'native-output-budget'}.get(literal, category)
            write_json(args.output / 'final-failure.json', dict(schema=1, stage=STATE['stage'],
                category=category, facts=STATE['facts'], new_runtime_executed=False, publication_authorized=False))
        print('final presentation rejected: '+type(error).__name__, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
