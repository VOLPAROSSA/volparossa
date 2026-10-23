#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only contact sheets from retained accepted Weather demo media.

Default preview is read-only. No Android rerun, SDK, installation or publication.
Packaging identity remains distinct from the original accepted runtime identity.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'VOLPAROSSA/volparossa'
WEATHER = '85e9eda9bb6105866db2510758e76c9930fdde91'
PREFIX = 'weather-demo-presentation/'  # upload-artifact removes the common .cache ancestor
MAX_ZIP = 128 * 1024**2
MAX_EXPANDED = 256 * 1024**2
FONT = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
REPORTS = {'weather-android-hosted-acceptance.json', 'weather-android-owner-join.json',
           'weather-android-delivery-evidence.json', 'weather-android-vm-cleanup.json'}
STATE = {'stage': 'arguments'}
SAMPLING_RULES = frozenset(('selection-count', 'font', 'child-timeout', 'child-png-budget',
    'child-stderr-limit', 'child-output-limit', 'child-exit', 'child-stderr', 'child-io', 'child-other',
    'frame-inventory', 'png-total-budget', 'native-frame-count', 'png-size', 'png-dimensions', 'sampling-other'))
SAMPLING_NUMBERS = {'expected_frame_count': 21600, 'actual_frame_count': 21600,
    'total_png_bytes': MAX_EXPANDED, 'png_bytes': 4 * 1024**2 + 1,
    'width': 8192, 'height': 8192, 'stderr_bytes': 131072}
SAMPLING_ENUMS = {'native_error_category': frozenset(('unobserved', 'none', 'stderr', 'process', 'timeout',
    'output-limit', 'stderr-limit', 'png-budget', 'io', 'other')),
    'stderr_class': frozenset(('unobserved', 'none', 'non-monotonic-dts', 'other'))}


def sampling_rejection(rule, facts):
    require(rule in SAMPLING_RULES and type(facts) is dict
        and set(facts) <= set(SAMPLING_NUMBERS) | set(SAMPLING_ENUMS) | {'child_status'}, 'sampling diagnostic rejected')
    for key, value in facts.items():
        if key in SAMPLING_NUMBERS:
            require(value is None or type(value) is int and 0 <= value <= SAMPLING_NUMBERS[key], 'sampling diagnostic number rejected')
        elif key == 'child_status':
            require(value is None or type(value) is int and -255 <= value <= 255, 'sampling diagnostic status rejected')
        else:
            require(type(value) is str and value in SAMPLING_ENUMS[key], 'sampling diagnostic category rejected')
    value = dict(schema=1, rule=rule, facts=facts)
    require(len(json.dumps(value, sort_keys=True)) <= 2048, 'sampling diagnostic size rejected')
    return value


def sampling_require(condition, message, rule, **facts):
    if not condition:
        error = ValueError(message)
        error.sampling_rejection = sampling_rejection(rule, facts)
        raise error


def sampling_command_failure(error, errors, status):
    # Compare only this command's fixed internal guard messages. No exception
    # text, command arguments, raw stderr or paths enter the public projection.
    messages = {'child timeout': ('child-timeout', 'timeout'),
        'generated image budget exceeded': ('child-png-budget', 'png-budget'),
        'child diagnostic limit exceeded': ('child-stderr-limit', 'stderr-limit'),
        'child output limit exceeded': ('child-output-limit', 'output-limit'),
        'child emitted error diagnostics': ('child-stderr', 'stderr')}
    if isinstance(error, ChildFailure): rule, category = 'child-exit', 'process'
    elif isinstance(error, subprocess.TimeoutExpired): rule, category = 'child-timeout', 'timeout'
    elif isinstance(error, OSError): rule, category = 'child-io', 'io'
    else:
        literal = error.args[0] if isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str else None
        rule, category = messages.get(literal, ('child-other', 'other'))
    # FFmpeg n6.1.1 libavformat/mux.c emits the first fixed marker. This
    # classification observes a marker, not a diagnosis of its underlying cause.
    dts = (b'Application provided invalid, non monotonically increasing dts to muxer' in errors
        or b'Non-monotonic DTS in output stream' in errors)
    return sampling_rejection(rule, dict(native_error_category=category,
        stderr_bytes=len(errors) if len(errors) <= 131072 else None,
        stderr_class='non-monotonic-dts' if dts else 'other' if errors else 'none',
        child_status=status if type(status) is int and -255 <= status <= 255 else None))


def sampling_snapshot(samples):
    try:
        frames = list(samples.glob('frame-*.png'))
        count = len(frames)
        total = sum(path.lstat().st_size for path in frames)
        return dict(actual_frame_count=count if count <= 21600 else None,
            total_png_bytes=total if 0 <= total <= MAX_EXPANDED else None)
    except OSError:
        return dict(actual_frame_count=None, total_png_bytes=None)


class ChildFailure(ValueError):
    def __init__(self, status):
        super().__init__('child failed with status ' + str(status))
        self.status = status


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(raw, maximum=2 * 1024**2):
    require(0 < len(raw) <= maximum, 'JSON size rejected')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tool(path):
    path = Path(path)
    info = path.stat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
            and info.st_uid == 0 and not info.st_mode & 0o022, 'root-owned distro tool required')
    return str(path)


def command(args, *, maximum=2 * 1024**2, destination=None, seconds=30, budget=None, reject_stderr=False, sampling=False):
    """Bound both pipes, elapsed time and optional generated PNG storage."""
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'GH_HOST': 'github.com'}
    if args[0] == '/usr/bin/gh' and 'GH_TOKEN' in os.environ:
        env['GH_TOKEN'] = os.environ['GH_TOKEN']
    output, errors, total = bytearray(), bytearray(), 0
    target = destination.open('xb') if destination is not None else None
    try:
        with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env) as child:
            try:
                deadline = time.monotonic() + seconds
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, 'out')
                    selector.register(child.stderr, selectors.EVENT_READ, 'err')
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, 'child timeout')
                        if budget is not None:
                            require(sum(p.stat().st_size for p in budget.glob('*.png')) <= MAX_ZIP,
                                    'generated image budget exceeded')
                        for key, _ in selector.select(min(remaining, 0.25)):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            elif key.data == 'err':
                                errors.extend(chunk)
                                require(len(errors) <= 65536, 'child diagnostic limit exceeded')
                            else:
                                total += len(chunk)
                                require(total <= maximum, 'child output limit exceeded')
                                if target is not None:
                                    target.write(chunk)
                                else:
                                    output.extend(chunk)
                    child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if child.returncode:
                        raise ChildFailure(child.returncode)
                    require(not reject_stderr or not errors, 'child emitted error diagnostics')
            except BaseException as error:
                # Freeze this command's status/diagnostic classification before
                # kill/join changes it. Native failures still reject unchanged.
                if sampling:
                    error.sampling_rejection = sampling_command_failure(error, errors, child.poll())
                child.kill()
                child.wait()
                raise
    finally:
        if target is not None:
            target.close()
    return bytes(output)


def api(endpoint):
    # Every caller constructs this path from constants and strict numeric IDs.
    require(re.fullmatch(r'repos/VOLPAROSSA/volparossa/actions/[A-Za-z0-9_/?=&-]+', endpoint),
            'API endpoint rejected')
    return decode(command([tool('/usr/bin/gh'), 'api', '--method', 'GET', endpoint]))


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
            'API timestamp rejected')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')


def selected_artifact(run_id, attempt, revision, *, quarantine=False):
    STATE['stage'] = 'run-metadata'
    base = f'repos/{REPOSITORY}/actions/runs/{run_id}'
    latest = api(base)
    run = api(base + '/attempts/' + attempt)
    for value in [latest, run]:
        require(type(value.get('id')) is int and str(value['id']) == run_id
                and type(value.get('run_attempt')) is int and str(value['run_attempt']) == attempt
                and value.get('head_sha') == revision and value.get('status') == 'completed'
                and value.get('conclusion') in ({'success', 'failure'} if quarantine else {'success'})
                and value.get('repository', {}).get('full_name') == REPOSITORY
                and value.get('head_repository', {}).get('full_name') == REPOSITORY,
                'successful exact latest run attempt required')
    require(latest['conclusion'] == run['conclusion'], 'run conclusion disagreement')
    started, finished = utc(run['run_started_at']), utc(run['updated_at'])
    require(started <= finished, 'run time window rejected')
    STATE['stage'] = 'artifact-metadata'
    listing = api(base + '/artifacts?per_page=100')
    require(type(listing.get('total_count')) is int and 1 <= listing['total_count'] <= 100
            and type(listing.get('artifacts')) is list
            and len(listing['artifacts']) == listing['total_count'], 'artifact listing incomplete')
    artifact_prefix = 'weather-demo-capture-quarantine-' if quarantine else 'weather-demo-review-'
    matches = [item for item in listing['artifacts']
               if item.get('name') == artifact_prefix + revision]
    require(len(matches) == 1, 'exact review artifact missing or ambiguous')
    artifact = matches[0]
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ZIP
            and type(artifact.get('digest')) is str
            and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest'])
            and artifact.get('workflow_run', {}).get('id') == int(run_id)
            and artifact.get('workflow_run', {}).get('head_sha') == revision
            and started <= utc(artifact['created_at']) <= utc(artifact['updated_at']) <= finished,
            'artifact identity, lifetime or digest rejected')
    # The artifact API has no attempt field. Require latest attempt and its exact creation window.
    selected = {key: artifact[key] for key in ['id', 'name', 'size_in_bytes', 'digest', 'created_at', 'updated_at']}
    if quarantine:
        selected['original_run_conclusion'] = run['conclusion']
    return selected


def download(artifact, path):
    STATE['stage'] = 'artifact-download'
    endpoint = f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'
    command([tool('/usr/bin/gh'), 'api', '--method', 'GET', endpoint],
            maximum=MAX_ZIP, destination=path, seconds=120)
    require(path.stat().st_size == artifact['size_in_bytes']
            and 'sha256:' + digest(path) == artifact['digest'], 'artifact bytes or SHA-256 mismatch')


def canonical_name(name, *, quarantine=False):
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name)
            and not name.startswith('/') and '\\' not in name, 'ZIP path rejected')
    parts = name.rstrip('/').split('/')
    require(all(p and p not in {'.', '..'} for p in parts)
            and '.git' not in parts, 'noncanonical ZIP path')
    roots = {'capture.json', 'original-acceptance', 'source-capture'} if quarantine else {
        'weather-demo-presentation', 'weather-demo-sources'}
    require(parts[0] in roots, 'unexpected archive root')
    return name


def zip_entries(archive, *, quarantine=False):
    entries, total = {}, 0
    require(len(archive.infolist()) <= 2048, 'ZIP entry limit exceeded')
    for info in archive.infolist():
        name = canonical_name(info.filename, quarantine=quarantine)
        require(name.rstrip('/') not in entries and not info.flag_bits & 1, 'duplicate or encrypted ZIP entry')
        mode = info.external_attr >> 16
        require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}
                and not stat.S_ISLNK(mode), 'ZIP nonregular entry rejected')
        require(info.is_dir() == (name.endswith('/'))
                and (not stat.S_ISDIR(mode) or info.is_dir())
                and (not info.is_dir() or info.file_size == 0), 'ZIP file type mismatch')
        total += info.file_size
        require(0 <= info.file_size <= MAX_ZIP and total <= MAX_EXPANDED, 'ZIP expanded size limit')
        entries[name.rstrip('/')] = info
    return entries


def zip_hash(archive, info):
    hashed, count = hashlib.sha256(), 0
    with archive.open(info) as stream:
        while data := stream.read(65536):
            count += len(data)
            require(count <= info.file_size and count <= MAX_ZIP, 'ZIP member size mismatch')
            hashed.update(data)
    require(count == info.file_size, 'ZIP member truncated')
    return dict(bytes=count, sha256=hashed.hexdigest())


def evidence(archive_path, destination, identity):
    STATE['stage'] = 'archive-validation'
    with zipfile.ZipFile(archive_path) as archive:
        entries = zip_entries(archive)
        require(PREFIX + 'presentation.json' in entries, 'presentation manifest missing')
        info = entries[PREFIX + 'presentation.json']
        require(info.file_size <= 2 * 1024**2, 'presentation manifest too large')
        presentation = decode(archive.read(info))
        require(presentation.get('schema') == 1
                and presentation.get('kind') == 'weather-demo-unpublished-presentation'
                and presentation.get('identity') == identity
                and presentation.get('actual_app_pixels') is True
                and presentation.get('external_core') is True
                and all(presentation.get(k) is False for k in ['physical_device', 'production_authority',
                    'publication_authorized', 'includes_installable_binaries'])
                and presentation.get('visual_review_required') is True,
                'presentation identity or scope rejected')
        files = presentation['files']
        require(type(files) is dict and 1 <= len(files) <= 2048, 'presentation inventory rejected')
        actual = {name[len(PREFIX):] for name, info in entries.items()
                  if name.startswith(PREFIX) and not info.is_dir()}
        require(actual == set(files) | {'presentation.json', 'SHA256SUMS'}, 'presentation ZIP inventory mismatch')
        selected = REPORTS | {'demo-media/recording.json', 'demo-media/screen.mp4'}
        selected |= {name for name in files if re.fullmatch(r'demo-media/screen-[0-9]{3}\.png', name)}
        require(selected <= set(files), 'original evidence subset missing')
        # Hash every manifest member in place; never extract source tarballs, rendered video or documents.
        for name, expected in sorted(files.items()):
            canonical_name(PREFIX + name)
            require(type(expected) is dict and set(expected) == {'bytes', 'sha256'}
                    and type(expected['bytes']) is int and expected['bytes'] > 0
                    and type(expected['sha256']) is str and re.fullmatch('[a-f0-9]{64}', expected['sha256'])
                    and zip_hash(archive, entries[PREFIX + name]) == expected, 'presentation member hash mismatch')
        destination.mkdir(mode=0o700)
        (destination / 'demo-media').mkdir(mode=0o700)
        for name in sorted(selected | {'presentation.json'}):
            info = entries[PREFIX + name]
            maximum = MAX_ZIP if name.endswith('.mp4') else 4 * 1024**2 if name.endswith('.png') else 2 * 1024**2
            require(info.file_size <= maximum, 'selected evidence file too large')
            with archive.open(info) as source, (destination / name).open('xb') as target:
                shutil.copyfileobj(source, target, length=65536)
            (destination / name).chmod(0o600)
    STATE['stage'] = 'original-closed-verifier'
    # verify(), unlike export(), uses the original artifact identity. Do not fake GITHUB_SHA/run env.
    verifier_path = ROOT / 'tests/integration/weather-demo-media.py'
    verifier = runpy.run_path(str(verifier_path))
    saved_token = os.environ.pop('GH_TOKEN', None)
    try:
        media = verifier['verify'](destination)
    finally:
        if saved_token is not None:
            os.environ['GH_TOKEN'] = saved_token
    require(media['identity'] == identity and media['joined_core_acceptance'] is True
            and media['production_authority'] is False, 'original media identity rejected')
    acceptance = decode((destination / 'weather-android-hosted-acceptance.json').read_bytes(), 65536)
    require(acceptance['identity'] == identity and acceptance['passed'] is True
            and acceptance['joined_core_acceptance'] is True and acceptance['vm_cleanup_pending'] is False
            and acceptance['production_authority'] is False
            and presentation['acceptance_sha256'] == media['acceptance_sha256']
            and presentation['recording_sha256'] == media['files']['screen.mp4']['sha256']
            and media['video']['has_audio'] is False
            and presentation['original_video'] == {key: media['video'][key]
                for key in ('codec', 'width', 'height', 'duration_seconds')}, 'cross-artifact binding rejected')
    return presentation, media, digest(verifier_path)



def quarantine_evidence(archive_path, destination, identity):
    """Recheck delivery and source capture for inspection, never admit encoded coverage."""
    STATE['stage'] = 'quarantine-archive'
    with zipfile.ZipFile(archive_path) as archive:
        entries = zip_entries(archive, quarantine=True)
        require('capture.json' in entries and entries['capture.json'].file_size <= 65536,
                'quarantine capture manifest missing or oversized')
        capture = decode(archive.read(entries['capture.json']), 65536)
        require(type(capture) is dict and set(capture) == {'schema', 'kind', 'identity', 'files',
                'original_acceptance_sha256', 'original_android_report_sha256', 'capture', 'driver_window',
                'original_core_acceptance_passed', 'media_accepted', 'joined_media_acceptance',
                'production_authority', 'review_required'}
                and type(capture['schema']) is int and capture['schema'] == 1
                and capture['kind'] == 'weather-demo-quarantined-capture' and capture['identity'] == identity
                and capture['original_core_acceptance_passed'] is True and capture['review_required'] is True
                and all(capture[key] is False for key in ['media_accepted', 'joined_media_acceptance',
                    'production_authority']), 'quarantine identity or nonadmission flags rejected')
        files = capture['files']
        required = {'original-acceptance/' + name for name in REPORTS} | {
            'source-capture/rawrecording.json', 'source-capture/driver-window.json', 'source-capture/screen.mp4'}
        require(type(files) is dict and required <= set(files)
                and all(name in required or re.fullmatch(r'source-capture/screen-[0-9]{3}\.png', name)
                        for name in files)
                and 1 <= len(set(files) - required) <= 36
                and {name for name, info in entries.items() if not info.is_dir()} == set(files) | {'capture.json'}
                and {name for name, info in entries.items() if info.is_dir()} <= {'original-acceptance', 'source-capture'},
                'strict quarantine inventory rejected')
        for name, expected in files.items():
            require(type(expected) is dict and set(expected) == {'bytes', 'sha256'}
                    and type(expected['bytes']) is int and expected['bytes'] > 0
                    and type(expected['sha256']) is str and re.fullmatch('[a-f0-9]{64}', expected['sha256'])
                    and zip_hash(archive, entries[name]) == expected, 'quarantine member hash mismatch')
        destination.mkdir(mode=0o700)
        for name in ['source-capture', 'original-acceptance']:
            (destination / name).mkdir(mode=0o700)
        for name in sorted(set(files) | {'capture.json'}):
            info = entries[name]
            maximum = 100 * 1024**2 if name.endswith('.mp4') else 4 * 1024**2 if name.endswith('.png') else 65536
            require(0 < info.file_size <= maximum, 'quarantine member size rejected')
            # Duplicate-key validation also applies to every original JSON report.
            if name.endswith('.json'):
                decode(archive.read(info), 65536)
            with archive.open(info) as source, (destination / name).open('xb') as target:
                shutil.copyfileobj(source, target, length=65536)
            (destination / name).chmod(0o600)
    STATE['stage'] = 'quarantine-original-delivery'
    verifier_path = ROOT / 'tests/integration/weather-demo-media.py'
    module = runpy.run_path(str(verifier_path))
    saved_tokens = {key: os.environ.pop(key) for key in ['GH_TOKEN', 'GITHUB_TOKEN',
        'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'] if key in os.environ}
    try:
        acceptance, joined = module['accepted'](destination / 'original-acceptance')
        require(acceptance['identity'] == identity and acceptance['passed'] is True
                and acceptance['joined_core_acceptance'] is True and acceptance['vm_cleanup_pending'] is False
                and acceptance['production_authority'] is False
                and capture['original_acceptance_sha256'] == digest(destination / 'original-acceptance/weather-android-hosted-acceptance.json')
                and capture['original_android_report_sha256'] == joined['original_android_report_sha256'],
                'quarantine original acceptance binding rejected')
        pixels = destination / 'source-capture'
        raw = decode((pixels / 'rawrecording.json').read_bytes(), 65536)
        window = decode((pixels / 'driver-window.json').read_bytes(), 65536)
        require(type(raw) is dict and set(raw) == {'schema', 'kind', 'started_unix_ms', 'completed_unix_ms',
                'elapsed_ms', 'source', 'files', 'screenshots', 'recorder_joined', 'guest_file_removed',
                'stage_labels_verified', 'ui_values_verified', 'joined_core_acceptance', 'production_authority'}
                and type(raw['schema']) is int and raw['schema'] == 1
                and raw['kind'] == 'weather-demo-android-recording'
                and raw['source'] == 'android-screenrecord-and-screencap'
                and raw['recorder_joined'] is True and raw['guest_file_removed'] is True
                and all(raw[key] is False for key in ['stage_labels_verified', 'ui_values_verified',
                    'joined_core_acceptance', 'production_authority'])
                and type(window) is dict and set(window) == {'schema', 'started_unix_ms',
                    'completed_unix_ms', 'installed_report_sha256'}
                and type(window['schema']) is int and window['schema'] == 1
                and window['installed_report_sha256'] == joined['original_android_report_sha256'],
                'quarantine source recording profile rejected')
        require(capture['capture'] == {key: raw[key] for key in ['started_unix_ms', 'completed_unix_ms', 'elapsed_ms']}
                and capture['driver_window'] == {key: window[key] for key in ['started_unix_ms', 'completed_unix_ms']}
                and {name: files['source-capture/' + name] for name in raw['files']} == raw['files']
                and {name for name in files if name.startswith('source-capture/')} == {
                    'source-capture/' + name for name in raw['files']} | {
                    'source-capture/rawrecording.json', 'source-capture/driver-window.json'},
                'quarantine capture/window/inventory mismatch')
        module['window_bounds'](capture['capture'], capture['driver_window'])
        STATE['stage'] = 'quarantine-source-media'
        module['media_files'](pixels, raw['files'], raw['screenshots'])
        video = module['probe_video'](pixels / 'screen.mp4')
    finally:
        os.environ.update(saved_tokens)
    # probe_video checks the stream profile only. The failed encoded-duration gate is deliberately not called.
    return capture, dict(video=video, files=raw['files']), digest(verifier_path)


def sample_window(start, stop, fps, duration=None, *, native=False):
    require(all(type(value) in {int, float} and math.isfinite(value) for value in [start, fps])
            and 0 <= start < 180 and 1 <= fps <= 30, 'sampling start/FPS rejected')
    if duration is not None:
        require(type(duration) in {int, float} and math.isfinite(duration) and 0 < duration <= 180,
                'source video duration rejected')
    if stop is None:
        stop = duration
    if stop is not None:
        require(type(stop) in {int, float} and math.isfinite(stop)
                and start < stop <= (180 if duration is None else duration)
                and (native or math.ceil((stop - start) * fps) <= 900), 'sampling window or frame budget rejected')
    return stop


def source_frame_timeline(video, duration):
    STATE['stage'] = 'quarantine-source-frame-timeline'
    value = decode(command([tool('/usr/bin/ffprobe'), '-v', 'error', '-protocol_whitelist', 'file,pipe',
        '-select_streams', 'v:0', '-show_frames', '-show_entries',
        'frame=pts_time,best_effort_timestamp_time,pkt_duration_time', '-of', 'json', str(video)],
        maximum=8 * 1024**2, seconds=60, reject_stderr=True), 8 * 1024**2)
    require(type(value) is dict and set(value) == {'frames'} and type(value['frames']) is list
            and 1 <= len(value['frames']) <= 21600, 'source frame timeline shape or count rejected')
    clean, previous = [], None
    for index, frame in enumerate(value['frames']):
        keys = {'pts_time', 'best_effort_timestamp_time', 'pkt_duration_time'}
        require(type(frame) is dict and set(frame) <= keys | {'side_data_list'}
                and ('pts_time' in frame or 'best_effort_timestamp_time' in frame), 'frame timing fields rejected')
        record = dict(frame_index=index)
        for key in keys & set(frame):
            item = frame[key]
            require(type(item) is str and re.fullmatch(r'-?[0-9]{1,7}(?:\.[0-9]{1,9})?', item),
                    'nonnumeric source frame timing rejected')
            number = float(item)
            require(math.isfinite(number) and abs(number) <= 1000000
                    and (key != 'pkt_duration_time' or 0 <= number <= 180), 'source frame timing out of range')
            record[key] = number
        timestamp = record.get('best_effort_timestamp_time', record.get('pts_time'))
        require(previous is None or previous <= timestamp, 'nonmonotonic source frame timeline')
        previous = timestamp
        record['clip_relative_pts_seconds'] = timestamp - (clean[0]['source_pts_seconds'] if clean else timestamp)
        record['source_pts_seconds'] = timestamp
        clean.append(record)
    return dict(schema=1, kind='weather-demo-source-video-frame-timeline', source_video_sha256=digest(video),
        video_duration_seconds=duration, frames=clean, side_data_retained=False,
        os_input_timestamps_inferred=False, sample_to_source_frame_mapping_verified=False,
        timestamp_domain='source video PTS; clip-relative origin is first decoded video frame; not host UTC')


def quarantine_samples(original, output, media, start, stop, fps, *, native=False):
    duration = media['video']['duration_seconds']
    stop = sample_window(start, stop, fps, duration, native=native)
    timeline = source_frame_timeline(original / 'source-capture/screen.mp4', duration)
    (output / 'frame-timeline.json').write_text(json.dumps(timeline, sort_keys=True, indent=2) + '\n')
    (output / 'frame-timeline.json').chmod(0o600)
    STATE['stage'] = 'quarantine-video-sampling'
    selected, samples, command_returned = None, output / 'samples', False
    try:
        ffmpeg = tool('/usr/bin/ffmpeg')
        sampling_require(FONT.is_file() and not FONT.is_symlink(), 'fixed distro font required', 'font')
        samples = output / 'samples'
        samples.mkdir(mode=0o700)
        selected = [frame for frame in timeline['frames'] if start <= frame['clip_relative_pts_seconds'] < stop]
        sampling_require(not native or 1 <= len(selected) <= 900, 'native frame count exceeds inspection budget',
            'selection-count', expected_frame_count=len(selected) if len(selected) <= 21600 else None)
        label = ("drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf:"
            "text='Clip PTS %{pts\\:hms}':fontsize=25:fontcolor=white:box=1:boxcolor=black@0.8:x=8:y=8")
        if native:
            limit = len(selected)
            graph = f'setpts=PTS-STARTPTS,trim=start={start:.9f}:end={stop:.9f}'
            # FFmpeg n6.1.1 doc/ffmpeg.texi:1620-1641 and
            # fftools/ffmpeg_filter.c:1709-1770: default encoding uses inverse
            # framerate; demux retains source tick precision for variable PTS.
            # This changes no pixel filter, frame count or stderr rejection.
            timing = ['-fps_mode', 'passthrough', '-enc_time_base:v', 'demux']
        else:
            limit = math.ceil((stop - start) * fps)
            graph = (f'setpts=PTS-STARTPTS,trim=start={start:.9f}:end={stop:.9f},setpts=PTS-STARTPTS,'
                f'fps={fps:.9f}:start_time=0,setpts=PTS+{start:.9f}/TB,' + label.replace('Clip PTS', 'Nominal'))
            timing = []
        command([ffmpeg, '-nostdin', '-v', 'error', '-protocol_whitelist', 'file,pipe', '-i',
            str(original / 'source-capture/screen.mp4'), '-vf', graph, '-an', *timing, '-frames:v', str(limit),
            '-threads', '2', '-compression_level', '6', '-start_number', '0', str(samples / 'frame-%03d.png')],
            maximum=65536, seconds=240, budget=samples, reject_stderr=native, sampling=True)
        command_returned = True
        frames = sorted(samples.glob('frame-*.png'))
        total_png_bytes = sum(p.stat().st_size for p in frames)
        sampling_require(1 <= len(frames) <= limit and [p.name for p in frames] == [f'frame-{i:03d}.png' for i in range(len(frames))],
            'quarantine sample inventory or budget rejected', 'frame-inventory')
        sampling_require(total_png_bytes <= MAX_ZIP, 'quarantine sample inventory or budget rejected', 'png-total-budget')
        sampling_require(not native or len(frames) == len(selected), 'native decoded frame count differs from source PTS timeline',
            'native-frame-count')
        for path in frames:
            png_size = path.stat().st_size
            sampling_require(0 < png_size <= 4 * 1024**2, 'quarantine sample PNG size rejected', 'png-size',
                png_bytes=png_size if 0 <= png_size <= 4 * 1024**2 + 1 else None)
            with path.open('rb') as stream:
                prefix = stream.read(24)
            dimensions = tuple(int.from_bytes(prefix[i:i + 4], 'big') for i in [16, 20]) if len(prefix) == 24 else (None, None)
            sampling_require(len(prefix) == 24 and prefix[:8] == b'\x89PNG\r\n\x1a\n' and prefix[12:16] == b'IHDR'
                    and dimensions == (720, 1280), 'quarantine sample PNG dimensions rejected', 'png-dimensions',
                width=dimensions[0] if dimensions[0] is not None and dimensions[0] <= 8192 else None,
                height=dimensions[1] if dimensions[1] is not None and dimensions[1] <= 8192 else None)
            path.chmod(0o600)
    except BaseException as error:
        value = getattr(error, 'sampling_rejection', sampling_rejection('sampling-other', {}))
        facts = dict(value['facts'])
        facts.setdefault('native_error_category', 'none' if command_returned and native else 'unobserved')
        facts.setdefault('stderr_class', 'none' if command_returned and native else 'unobserved')
        facts.setdefault('stderr_bytes', 0 if command_returned and native else None)
        facts.update(sampling_snapshot(samples))
        facts['expected_frame_count'] = (len(selected) if selected is not None and len(selected) <= 21600 else None) if native else None
        error.sampling_rejection = sampling_rejection(value['rule'], facts)
        raise
    STATE['stage'] = 'quarantine-contact-sheets'
    sheets = []
    for start_frame in range(0, len(frames), 30):
        sheet = output / f'contact-{start_frame // 30:02d}.png'
        command([ffmpeg, '-nostdin', '-v', 'error', '-framerate', '1', '-start_number', str(start_frame),
            '-i', str(samples / 'frame-%03d.png'), '-vf',
            'scale=180:320,tile=6x5:padding=4:margin=4:color=0x101827',
            '-frames:v', '1', '-threads', '2', str(sheet)], maximum=65536, seconds=60)
        require(sheet.is_file() and 0 < sheet.stat().st_size <= 8 * 1024**2, 'inspection contact sheet rejected')
        sheet.chmod(0o600)
        sheets.append(sheet.name)
    result = dict(sample_start_seconds=start, sample_stop_seconds=stop, sample_fps=None if native else fps,
        native_frames=native, sampled_frames=len(frames), contact_sheets=sheets,
        source_frame_timeline='frame-timeline.json', exact_action_timestamps_asserted=False,
        os_input_timestamps_inferred=False, sample_to_source_frame_mapping_verified=native,
        timestamp_domain='clip-relative video PTS; not host UTC or OS input timestamps',
        inspection_only=True, media_accepted=False, font_sha256=digest(FONT))
    if native:
        result['mapping_basis'] = 'native decoder passthrough order; exact count match to ffprobe decoded-frame timeline'
        result['decoded_frames'] = [dict(file='samples/' + path.name, **frame) for path, frame in zip(frames, selected)]
    else:
        result['nominal_sample_seconds'] = [start + index / fps for index in range(len(frames))]
    return result


def contact_sheets(evidence_root, output, media):
    STATE['stage'] = 'actual-video-sampling'
    ffmpeg = tool('/usr/bin/ffmpeg')
    tool('/usr/bin/ffprobe')
    # Font data is not an executable. Match the fixed-font check of the
    # already exercised presentation renderer; keep executable checks strict.
    require(FONT.is_file() and not FONT.is_symlink(), 'fixed distro font required')
    duration = media['video']['duration_seconds']
    require(type(duration) in {int, float} and math.isfinite(duration) and 0 < duration <= 180,
            'video duration rejected')
    samples = output / 'samples'
    samples.mkdir(mode=0o700)
    # Literal controlled filter; no paths or artifact text are interpolated as filter expressions.
    graph = ('fps=1:start_time=0,drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf:'
             "text='Nominal %{pts\\:hms}':fontsize=25:fontcolor=white:box=1:boxcolor=black@0.8:x=8:y=8")
    command([ffmpeg, '-nostdin', '-v', 'error', '-protocol_whitelist', 'file,pipe', '-i',
        str(evidence_root / 'demo-media/screen.mp4'), '-vf', graph, '-an', '-frames:v', '180',
        '-threads', '2', '-compression_level', '6', '-start_number', '0', str(samples / 'frame-%03d.png')],
        maximum=65536, seconds=180, budget=samples)
    frames = sorted(samples.glob('frame-*.png'))
    require(1 <= len(frames) <= 180 and sum(p.stat().st_size for p in frames) <= MAX_ZIP
            and [p.name for p in frames] == [f'frame-{i:03d}.png' for i in range(len(frames))],
            'sample inventory rejected')
    for frame in frames:
        require(0 < frame.stat().st_size <= 4 * 1024**2, 'sample PNG size rejected')
        frame.chmod(0o600)
    STATE['stage'] = 'contact-sheet-render'
    sheets = []
    for start in range(0, len(frames), 30):
        sheet = output / f'contact-{start // 30:02d}.png'
        command([ffmpeg, '-nostdin', '-v', 'error', '-framerate', '1', '-start_number', str(start),
            '-i', str(samples / 'frame-%03d.png'), '-vf',
            'scale=180:320,tile=6x5:padding=4:margin=4:color=0x101827',
            '-frames:v', '1', '-threads', '2', str(sheet)], maximum=65536, seconds=60)
        require(sheet.is_file() and 0 < sheet.stat().st_size <= 8 * 1024**2, 'contact sheet rejected')
        sheet.chmod(0o600)
        sheets.append(sheet.name)
    poster_frame = frames[len(frames) // 2]
    shutil.copyfile(poster_frame, output / 'poster.png')
    (output / 'poster.png').chmod(0o600)
    return dict(font_sha256=digest(FONT), sample_hz=1, sampling='FFmpeg fps=1 at normal clip timing; nominal times, no semantic stage labels',
                sampled_frames=len(frames), contact_sheets=sheets,
                poster_source='samples/' + poster_frame.name, synthesized_app_pixels=False,
                exact_action_timestamps_asserted=False)


def render_held_image(original, output, media, basename):
    """Render only after evidence() rechecked the original closed same-run media."""
    STATE['stage'] = 'selected-held-image'
    require(type(basename) is str and re.fullmatch(r'screen-[0-9]{3}\.png', basename)
            and basename in media['files'], 'admitted same-run image basename required')
    image = original / 'demo-media' / basename
    info = image.lstat()
    require(stat.S_ISREG(info.st_mode) and not image.is_symlink()
            and 0 < info.st_size <= 4 * 1024**2
            and media['files'][basename] == dict(bytes=info.st_size, sha256=digest(image)),
            'selected held image hash mismatch')
    with image.open('rb') as stream:
        prefix = stream.read(24)
    require(len(prefix) == 24 and prefix[:8] == b'\x89PNG\r\n\x1a\n'
            and prefix[12:16] == b'IHDR'
            and tuple(int.from_bytes(prefix[i:i + 4], 'big') for i in [16, 20]) == (1080, 1920),
            'selected admitted PNG dimensions rejected')
    acceptance_path = original / 'weather-android-hosted-acceptance.json'
    acceptance = decode(acceptance_path.read_bytes(), 65536)
    require(acceptance['identity'] == media['identity'] and acceptance['passed'] is True
            and digest(acceptance_path) == media['acceptance_sha256'], 'held-image acceptance binding rejected')
    raw_video = original / 'demo-media/screen.mp4'
    require(digest(raw_video) == media['files']['screen.mp4']['sha256'], 'original recording hash mismatch')
    tool('/usr/bin/ffmpeg')
    tool('/usr/bin/ffprobe')
    package = runpy.run_path(str(ROOT / 'scripts/weather-demo-0-package.py'))
    raw_info = {key: media['video'][key] for key in ['codec', 'width', 'height', 'duration_seconds']}
    duration = max(120, math.ceil(raw_info['duration_seconds'] + 1))
    require(duration <= 180, 'no held-image interval within bounded presentation duration')
    lines = package['presentation_lines'](media['identity'], acceptance['observations']['products'])
    STATE['stage'] = 'selected-held-image-render'
    _, video = package['render_video'](raw_video, output, duration, raw_info, lines, hold_image=image)
    require(digest(image) == media['files'][basename]['sha256'], 'held image changed during render')
    captions, transcript = package['captions'](duration, raw_info['duration_seconds'], hold_image=basename)
    for name, text in [('captions.vtt', captions), ('transcript.txt', transcript)]:
        (output / name).write_text(text, encoding='utf-8')
        (output / name).chmod(0o600)
    (output / 'weather-demo-0.mp4').chmod(0o600)
    return dict(video=video, identity=media['identity'],
        held_image=dict(file=basename, **media['files'][basename]),
        edits=dict(speed=1, full_original_clip=True, raw_clip_trimmed=False,
            held_frame_after_seconds=raw_info['duration_seconds'],
            held_image_label='Held app frame from this run', counters='completed-run summary',
            exact_action_timestamps_asserted=False),
        publication_authorized=False, production_authority=False,
        visual_review_required=True, visual_acceptance_claimed=False)


SCOPED_IDENTITY = dict(core_commit='6bc0abdb524b79e5244f9381d2d8d45a9100b41d',
    weather_commit=WEATHER, run_id='39998753810', run_attempt='1')
SCOPED_VIDEO = 'bca54a8f677238f26daff6921bb3af0c661e1b39d0aada5ce3f161fda380d5c8'
SCOPED_ZIP = 'sha256:307ebd6239de51d40b17c429658fe751b4201abcda8a0e4abd5688184121230c'
SCOPED_CLAIMS = {'temperature-visible': 206, 'pm25-visible': 240, 'source-validity-visible': 206,
    'first-refresh-completes': 348, 'home-visible': 439, 'app-return-animation': 489}
SCOPED_SCREENSHOTS = (206, 215, 240, 348, 439, 489)


def committed_visual_review(path):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    require(path == path.resolve(strict=True) and path.is_relative_to(ROOT) and path.is_file()
            and 0 < path.stat().st_size <= 65536, 'scoped visual-review path rejected')
    relative = path.relative_to(ROOT).as_posix()
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', relative) and '.git' not in path.relative_to(ROOT).parts,
            'scoped visual-review path rejected')
    raw = path.read_bytes()
    committed = command([tool('/usr/bin/git'), '--no-optional-locks', '-c', 'core.hooksPath=/dev/null',
        '-C', str(ROOT), 'show', 'HEAD:' + relative], maximum=65536, seconds=15, reject_stderr=True)
    require(raw == committed, 'visual review must equal its committed source bytes')
    return raw, decode(raw, 65536)


def scoped_visual_witnesses(review, output, identity, rendered, timeline):
    require(type(review) is dict and set(review) == {'schema', 'kind', 'identity', 'source_video_sha256',
                'scope', 'hold_frame_index', 'witnesses'}
            and type(review['schema']) is int and review['schema'] == 1
            and review['kind'] == 'weather-demo-scoped-visual-review'
            and review['identity'] == identity == SCOPED_IDENTITY
            and review['source_video_sha256'] == SCOPED_VIDEO
            and review['scope'] == 'weather-demo-0-native-timing-v1'
            and type(review['hold_frame_index']) is int and review['hold_frame_index'] == 206,
            'scoped visual-review schema, identity or scope rejected')
    rows = rendered['decoded_frames']
    require(rendered['native_frames'] is True and rendered['sample_to_source_frame_mapping_verified'] is True
            and rendered['sample_start_seconds'] == 0
            and rendered['sample_stop_seconds'] == timeline['video_duration_seconds']
            and timeline['source_video_sha256'] == SCOPED_VIDEO
            and len(rows) == len(timeline['frames']) and 490 <= len(rows) <= 900
            and [row['frame_index'] for row in rows] == list(range(len(rows))),
            'scoped admission requires whole-clip native frame inspection')
    frames = {}
    for index in set(SCOPED_SCREENSHOTS):
        row, source = rows[index], timeline['frames'][index]
        expected = 'samples/frame-' + f'{index:03d}' + '.png'
        require(row['file'] == expected and row['frame_index'] == source['frame_index'] == index
                and row['source_pts_seconds'] == source['source_pts_seconds'], 'scoped source frame binding rejected')
        path = output / expected
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 4 * 1024**2,
                'scoped PNG file rejected')
        frames[index] = dict(frame_index=index, source_pts_seconds=row['source_pts_seconds'],
            file=expected, bytes=info.st_size, png_sha256=digest(path))
    witnesses = review['witnesses']
    require(type(witnesses) is list and len(witnesses) == len(SCOPED_CLAIMS), 'scoped visual witnesses missing')
    seen, validated = set(), []
    for witness in witnesses:
        require(type(witness) is dict and set(witness) == {'claim', 'frame_index', 'source_pts_seconds', 'png_sha256'}
                and type(witness['claim']) is str and witness['claim'] in SCOPED_CLAIMS
                and witness['claim'] not in seen and type(witness['frame_index']) is int
                and witness['frame_index'] == SCOPED_CLAIMS[witness['claim']]
                and type(witness['source_pts_seconds']) in {int, float} and math.isfinite(witness['source_pts_seconds'])
                and type(witness['png_sha256']) is str and re.fullmatch('[a-f0-9]{64}', witness['png_sha256']),
                'scoped visual witness duplicate, index or fields rejected')
        actual = frames[witness['frame_index']]
        require(witness['source_pts_seconds'] == actual['source_pts_seconds']
                and witness['png_sha256'] == actual['png_sha256'], 'scoped visual witness hash or PTS rejected')
        seen.add(witness['claim'])
        validated.append(dict(claim=witness['claim'], **actual))
    require(seen == set(SCOPED_CLAIMS), 'scoped visual claims missing')
    return validated, frames


def admit_scoped_demo(output, identity, capture, media, artifact, rendered, visual_path, packaging):
    """Separate scoped decision; inspection and the original failed run remain unchanged."""
    hosted()
    STATE['stage'] = 'scoped-visual-review'
    raw_review, review = committed_visual_review(visual_path)
    require(identity == SCOPED_IDENTITY and artifact['original_run_conclusion'] == 'failure'
            and artifact['digest'] == SCOPED_ZIP and capture['original_core_acceptance_passed'] is True
            and capture['media_accepted'] is False and capture['joined_media_acceptance'] is False
            and media['files']['screen.mp4']['sha256'] == SCOPED_VIDEO,
            'scoped original failed-run binding rejected')
    timeline = decode((output / 'frame-timeline.json').read_bytes(), 8 * 1024**2)
    witnesses, frames = scoped_visual_witnesses(review, output, identity, rendered, timeline)
    original = output / 'original'
    video_path = original / 'source-capture/screen.mp4'
    require(digest(video_path) == SCOPED_VIDEO, 'scoped original clip hash rejected')
    STATE['stage'] = 'scoped-native-timing'
    timing_path = ROOT / 'tests/integration/weather-demo-native-timing.py'
    technical = runpy.run_path(str(timing_path))['validate'](video_path, timeline)
    require(type(technical) is dict and type(technical.get('schema')) is int and technical['schema'] == 1
            and technical.get('kind') == 'weather-demo-native-timing-coherence'
            and technical.get('technical_coherence_passed') is True
            and technical.get('source_video_sha256') == SCOPED_VIDEO
            and all(technical.get(key) is False for key in ['media_accepted', 'visual_acceptance_claimed',
                'publication_authorized', 'production_authority']), 'scoped technical coherence rejected')
    timing_record = dict(schema=1, kind='weather-demo-validated-native-timing', identity=identity,
        review_execution=packaging, original_run_conclusion='failure', original_recording_sha256=SCOPED_VIDEO,
        timing_validator_sha256=digest(timing_path), technical_report=technical,
        technical_coherence_passed=True, scoped_demo_admitted=False, media_accepted=False,
        visual_acceptance_claimed=False, publication_authorized=False, production_authority=False)
    timing_record_path = output / 'native-timing.json'
    timing_record_path.write_text(json.dumps(timing_record, sort_keys=True, indent=2) + '\n')
    timing_record_path.chmod(0o600)
    STATE['stage'] = 'scoped-presentation-render'
    package = runpy.run_path(str(ROOT / 'scripts/weather-demo-0-package.py'))
    stage = output / 'presentation'
    stage.mkdir(mode=0o700)
    acceptance = decode((original / 'original-acceptance/weather-android-hosted-acceptance.json').read_bytes(), 65536)
    require(acceptance['identity'] == identity and acceptance['passed'] is True
            and digest(original / 'original-acceptance/weather-android-hosted-acceptance.json') == capture['original_acceptance_sha256'],
            'scoped original acceptance changed')
    raw_info = {key: media['video'][key] for key in ['codec', 'width', 'height', 'duration_seconds']}
    duration = max(120, math.ceil(raw_info['duration_seconds'] + 1))
    require(duration <= 180, 'scoped presentation duration rejected')
    STATE['presentation_facts'] = dict(requested_duration_ms=round(duration * 1000),
        raw_duration_ms=round(raw_info['duration_seconds'] * 1000), held_frame_index=206)
    lines = package['presentation_lines'](identity, acceptance['observations']['products'], scoped_demo=True)
    hold = output / frames[206]['file']
    _, video_info = package['render_video'](video_path, stage, duration, raw_info, lines, hold_image=hold)
    require(digest(hold) == frames[206]['png_sha256'] and digest(video_path) == SCOPED_VIDEO,
            'scoped presentation source changed')
    STATE['stage'] = 'scoped-presentation-preview'
    preview = stage / 'preview-090.png'
    command([tool('/usr/bin/ffmpeg'), '-nostdin', '-v', 'error', '-protocol_whitelist', 'file,pipe',
        '-i', str(stage / 'weather-demo-0.mp4'), '-ss', '90', '-frames:v', '1', '-threads', '2', str(preview)],
        maximum=65536, seconds=30, reject_stderr=True)
    require(preview.is_file() and 0 < preview.stat().st_size <= 8 * 1024**2, 'scoped presentation preview size rejected')
    with preview.open('rb') as stream:
        prefix = stream.read(24)
    require(len(prefix) == 24 and prefix[:8] == b'\x89PNG\r\n\x1a\n' and prefix[12:16] == b'IHDR'
            and tuple(int.from_bytes(prefix[index:index + 4], 'big') for index in [16, 20]) == (1920, 1080),
            'scoped presentation preview dimensions rejected')
    STATE['stage'] = 'scoped-presentation-export'
    captions, transcript = package['scoped_captions'](duration, raw_info['duration_seconds'], '206')
    (stage / 'captions.vtt').write_text(captions, encoding='utf-8')
    (stage / 'transcript.txt').write_text(transcript, encoding='utf-8')
    (stage / 'visual-review.json').write_bytes(raw_review)
    shutil.copyfile(video_path, stage / 'screen.mp4')
    (stage / 'screenshots').mkdir(mode=0o700)
    for index, frame in frames.items():
        shutil.copyfile(output / frame['file'], stage / 'screenshots' / f'frame-{index:03d}.png')
    STATE['stage'] = 'scoped-presentation-provenance'
    require(FONT.is_file() and not FONT.is_symlink(), 'fixed distro font required')
    files = {p.relative_to(stage).as_posix(): dict(bytes=p.stat().st_size, sha256=digest(p))
             for p in sorted(stage.rglob('*')) if p.is_file()}
    presentation = dict(schema=1, kind='weather-demo-scoped-presentation', identity=identity,
        review_execution=packaging, original_run_conclusion='failure', scope=review['scope'],
        video=video_info, original_video=raw_info, original_recording_sha256=SCOPED_VIDEO,
        visual_review_sha256=hashlib.sha256(raw_review).hexdigest(),
        hold_frame=dict(frames[206], file='screenshots/frame-206.png', source_inspection_file=frames[206]['file']),
        edits=dict(speed=1, full_original_clip=True, raw_clip_trimmed=False,
            held_frame_after_seconds=raw_info['duration_seconds'], held_frame_label='Held app frame from this run',
            network_and_cache_facts='completed-run evidence', exact_action_timestamps_asserted=False,
            presentation_cadence='30fps CFR; source display frames may be repeated or omitted by resampling',
            phone_geometry='fit within 480x960 padded pane on 1920x1080 canvas', original_capture_preserved=True),
        layout_preview=dict(file='preview-090.png', presentation_time_seconds=90,
            final_layout_visual_review_required=True),
        pixel_scope=sorted(SCOPED_CLAIMS), report_only_scope=['second-refresh-completion', 'background-resume-lifecycle-and-mounted-tables'],
        ffmpeg_version=command([tool('/usr/bin/ffmpeg'), '-version'], maximum=16384, seconds=10,
            reject_stderr=True).decode('ascii').splitlines()[0],
        font_sha256=digest(FONT),
        publication_authorized=False, production_authority=False, standalone_mobile_core=False,
        final_presentation_visual_review_required=True, includes_installable_binaries=False, files=files)
    STATE['stage'] = 'scoped-presentation-export'
    (stage / 'presentation.json').write_text(json.dumps(presentation, sort_keys=True, indent=2) + '\n')
    record = dict(schema=1, kind='weather-demo-scoped-admission', identity=identity,
        review_execution=packaging, scope=review['scope'], original_run_conclusion='failure',
        original_artifact=artifact, original_recording_sha256=SCOPED_VIDEO,
        original_acceptance_sha256=capture['original_acceptance_sha256'], original_core_acceptance_passed=True,
        original_encoded_duration_failure_preserved=True, original_duration_verify_called=False,
        visual_review_sha256=hashlib.sha256(raw_review).hexdigest(), technical_report=technical,
        timing_validator_sha256=digest(timing_path), native_timing_sha256=digest(timing_record_path),
        validated_witnesses=witnesses, held_frame=frames[206], scoped_demo_admitted=True,
        publication_authorized=False, production_authority=False, standalone_mobile_core=False,
        new_runtime_executed=False, final_presentation_visual_review_required=True,
        presentation_manifest_sha256=digest(stage / 'presentation.json'))
    (output / 'scoped-admission.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    for path in list(stage.rglob('*')) + [output / 'scoped-admission.json']:
        if path.is_file():
            path.chmod(0o600)
    return record


def hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.getuid() == os.geteuid() != 0, 'unprivileged GitHub-hosted execution required')
    require(re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', ''))
            and all(re.fullmatch('[1-9][0-9]{0,19}', os.environ.get(k, ''))
                    for k in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']), 'review execution identity missing')


def prepare(run_id, attempt, revision, output, execute=False, hold_image=None, *,
            inspect_quarantine=False, sample_start=0, sample_stop=None, sample_fps=None, native_frames=False,
            admit_scoped=False, visual_review=None):
    STATE['stage'] = 'arguments'
    STATE.pop('presentation_facts', None)
    hold_image = None if hold_image == '' else hold_image
    require(hold_image is None or type(hold_image) is str
            and re.fullmatch(r'screen-[0-9]{3}\.png', hold_image), 'strict held-image basename required')
    require(not inspect_quarantine or hold_image is None, 'quarantine inspection cannot render a held image')
    require(not admit_scoped or (inspect_quarantine and native_frames and sample_start == 0
            and sample_stop is None and hold_image is None and visual_review is not None),
            'scoped admission requires whole-clip native quarantine inspection and committed visual review')
    require(visual_review is None or admit_scoped, 'visual review requires explicit scoped admission')
    if inspect_quarantine:
        sample_fps = 5 if sample_fps is None else sample_fps
        sample_window(sample_start, sample_stop, sample_fps, native=native_frames)
    else:
        require(sample_start == 0 and sample_stop is None and sample_fps is None and not native_frames,
                'sampling controls require quarantine inspection')
    require(all(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}', v) for v in [run_id, attempt])
            and type(revision) is str and re.fullmatch('[a-f0-9]{40}', revision), 'strict run/attempt/SHA required')
    output = Path(output)
    require(output.is_absolute() and output == output.resolve() and output.parent.is_dir()
            and output.is_relative_to(ROOT) and output != ROOT
            and '.git' not in output.relative_to(ROOT).parts
            and not output.exists() and not output.is_symlink(), 'new workspace output required')
    identity = dict(core_commit=revision, weather_commit=WEATHER, run_id=run_id, run_attempt=attempt)
    require(not admit_scoped or identity == SCOPED_IDENTITY, 'scoped admission original identity rejected')
    preview = dict(schema=1, kind='weather-demo-media-review-preview', identity=identity,
                   executed=False, publication_authorized=False, visual_review_required=True,
                   downloads='Only exact same-run weather-demo-review-' + revision,
                   held_image_requested=hold_image)
    if inspect_quarantine:
        preview.update(kind='weather-demo-quarantine-inspection-preview', media_accepted=False,
            joined_media_acceptance=False, inspection_only=True,
            downloads='Only exact same-run weather-demo-capture-quarantine-' + revision,
            sampling=dict(start=sample_start, stop=sample_stop, fps=sample_fps, native_frames=native_frames))
    if admit_scoped:
        preview.update(scoped_demo_admission_requested=True, scoped_demo_admitted=False,
            visual_review_required=True, original_failed_run_preserved=True)
    if not execute:
        return preview
    hosted()
    packaging = dict(core_commit=os.environ['GITHUB_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
                     run_attempt=os.environ['GITHUB_RUN_ATTEMPT'])
    output.mkdir(mode=0o700)  # Exclusive: existing output is never repaired or overwritten.
    artifact, inspection_complete = None, False
    try:
        artifact = (selected_artifact(run_id, attempt, revision, quarantine=True) if inspect_quarantine
                    else selected_artifact(run_id, attempt, revision))
        archive = output / 'review.zip'
        download(artifact, archive)
        original = output / 'original'
        if inspect_quarantine:
            capture, media, verifier_sha = quarantine_evidence(archive, original, identity)
            archive.unlink()
            rendered = quarantine_samples(original, output, media, sample_start, sample_stop, sample_fps,
                                           native=native_frames)
            result = dict(schema=1, kind='weather-demo-quarantine-inspection', identity=identity,
                review_execution=packaging, executed=True, artifact=artifact,
                original_run_conclusion=artifact['original_run_conclusion'],
                original_media_verifier_sha256=verifier_sha,
                original_acceptance_sha256=capture['original_acceptance_sha256'],
                original_recording_sha256=media['files']['screen.mp4']['sha256'],
                original_core_acceptance_passed=True, joined_core_acceptance_rechecked=True,
                media_accepted=False, joined_media_acceptance=False, encoded_duration_admission_performed=False,
                new_runtime_executed=False, publication_authorized=False, production_authority=False,
                visual_review_required=True, visual_acceptance_claimed=False, inspection_only=True,
                capture=capture['capture'], driver_window=capture['driver_window'], video=media['video'], rendered=rendered)
        else:
            presentation, media, verifier_sha = evidence(archive, original, identity)
            archive.unlink()
            rendered = contact_sheets(original, output, media)
            revised = render_held_image(original, output, media, hold_image) if hold_image is not None else None
            result = dict(schema=1, kind='weather-demo-retained-media-review', identity=identity,
                review_execution=packaging, executed=True, artifact=artifact,
                original_media_verifier_sha256=verifier_sha,
                original_acceptance_sha256=presentation['acceptance_sha256'],
                original_recording_sha256=presentation['recording_sha256'],
                joined_core_acceptance_rechecked=True, new_runtime_executed=False,
                publication_authorized=False, production_authority=False,
                visual_review_required=True, visual_acceptance_claimed=False, rendered=rendered)
            if revised is not None:
                result['revised_presentation'] = revised
        result['files'] = {p.relative_to(output).as_posix(): dict(bytes=p.stat().st_size, sha256=digest(p))
                           for p in sorted(output.rglob('*')) if p.is_file()}
        (output / 'review.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        (output / 'review.json').chmod(0o600)
        inspection_complete = inspect_quarantine
        if admit_scoped:
            admit_scoped_demo(output, identity, capture, media, artifact, rendered, visual_review, packaging)
        return result
    except BaseException as error:
        # Keep a closed source/run-bound failure record after removing partial downloads/frames.
        keep_inspection = inspection_complete and admit_scoped
        for child in output.iterdir():
            if not keep_inspection or child.name in {'presentation', 'scoped-admission.json'}:
                shutil.rmtree(child) if child.is_dir() else child.unlink()
        category = ('process' if isinstance(error, (ChildFailure, subprocess.SubprocessError)) else
            'io' if isinstance(error, OSError) else 'value' if isinstance(error, ValueError) else
            'key' if isinstance(error, KeyError) else 'type' if isinstance(error, TypeError) else 'unknown')
        failure = dict(schema=1, kind='weather-demo-retained-media-review-failure', identity=identity,
            review_execution=packaging, stage=STATE['stage'], category=category,
            partial_output_removed=True, visual_acceptance_claimed=False, publication_authorized=False)
        if inspect_quarantine:
            failure.update(kind='weather-demo-quarantine-inspection-failure', media_accepted=False,
                joined_media_acceptance=False, inspection_only=True, new_runtime_executed=False,
                production_authority=False,
                original_run_conclusion=artifact.get('original_run_conclusion') if artifact else None)
        if STATE['stage'] == 'quarantine-video-sampling' and hasattr(error, 'sampling_rejection'):
            detail = error.sampling_rejection
            failure['sampling_rejection'] = sampling_rejection(detail['rule'], detail['facts'])
        if isinstance(error, ChildFailure):
            failure['child_status'] = error.status if type(error.status) is int and -255 <= error.status <= 255 else None
        failure_name = 'review-failure.json'
        if keep_inspection:
            failure_name = 'scoped-admission-failure.json'
            failure.update(kind='weather-demo-scoped-admission-failure', scoped_demo_admitted=False,
                completed_inspection_preserved=True)
            failure['stage'] = STATE['stage'] if STATE['stage'] in {
                'scoped-visual-review', 'scoped-native-timing', 'scoped-presentation',
                'scoped-presentation-render', 'scoped-presentation-preview',
                'scoped-presentation-provenance', 'scoped-presentation-export'} else 'unknown'
            if STATE['stage'].startswith('scoped-presentation-'):
                rules = {'Demo presentation rejected': 'render-check',
                    'A held image requires at least one second after the full raw clip': 'held-margin',
                    'scoped original acceptance changed': 'original-acceptance',
                    'scoped presentation duration rejected': 'duration',
                    'scoped presentation source changed': 'source-binding',
                    'scoped presentation preview size rejected': 'preview-size',
                    'scoped presentation preview dimensions rejected': 'preview-dimensions',
                    'root-owned distro tool required': 'trusted-file',
                    'child emitted error diagnostics': 'child-stderr'}
                failure['presentation_rejection'] = rules.get(str(error), category)
                limits = dict(requested_duration_ms=180000, raw_duration_ms=180000, held_frame_index=899)
                failure['presentation_facts'] = {key: value for key, value in STATE.get('presentation_facts', {}).items()
                    if key in limits and type(value) is int and 0 <= value <= limits[key]}
                detail = getattr(error, 'render_rejection', None)
                if type(detail) is dict and set(detail) == {'phase', 'facts'} and type(detail['phase']) is str and detail['phase'] in {
                        'probe-profile', 'probe-json', 'output-check'} and type(detail['facts']) is dict:
                    render_limits = dict(duration_ms=86400000, requested_duration_ms=180000,
                        width=16384, height=16384, stream_count=128, output_bytes=256 * 1024**2)
                    if all(key in render_limits and type(value) is int and 0 <= value <= render_limits[key]
                           for key, value in detail['facts'].items()):
                        failure['render_rejection'] = detail
            if (output / 'native-timing.json').is_file():
                failure['native_timing_sha256'] = digest(output / 'native-timing.json')
            if isinstance(error, ValueError) and re.fullmatch(r'native_timing_[a-z0-9_]{1,80}', str(error)):
                failure['native_timing_rejection'] = str(error)
                if STATE['stage'] == 'scoped-native-timing' and hasattr(error, 'native_timing_observation'):
                    try:
                        validator = runpy.run_path(str(ROOT / 'tests/integration/weather-demo-native-timing.py'))['validate_observation']
                        failure['native_timing_observation'] = validator(error.native_timing_observation)
                    except (ValueError, TypeError, KeyError, OSError):
                        # A malformed attachment never replaces the original
                        # failure or permits unfiltered diagnostic disclosure.
                        pass
        (output / failure_name).write_text(json.dumps(failure, sort_keys=True, indent=2) + '\n')
        (output / failure_name).chmod(0o600)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True)
    parser.add_argument('--core-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--hold-image', default=None,
                        help='explicit admitted screen-NNN.png to hold after the full raw clip')
    parser.add_argument('--inspect-quarantine', action='store_true', help='inspection only, never media admission')
    parser.add_argument('--sample-start', type=float, default=0)
    parser.add_argument('--sample-stop', type=float)
    parser.add_argument('--sample-fps', type=float)
    parser.add_argument('--native-frames', action='store_true', help='inspect every selected native decoded frame')
    parser.add_argument('--admit-scoped-demo', action='store_true', help='separate explicitly scoped demo admission')
    parser.add_argument('--visual-review', type=Path, help='committed exact-source visual-review JSON')
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(*_):
        raise InterruptedError('retained media review interrupted')
    try:
        if args.execute:
            signal.signal(signal.SIGTERM, interrupted)
        options = {}
        if args.inspect_quarantine or args.sample_start != 0 or args.sample_stop is not None or args.sample_fps is not None or args.native_frames:
            options = dict(inspect_quarantine=args.inspect_quarantine, sample_start=args.sample_start,
                sample_stop=args.sample_stop, sample_fps=args.sample_fps, native_frames=args.native_frames)
        if args.admit_scoped_demo or args.visual_review is not None:
            options.update(admit_scoped=args.admit_scoped_demo, visual_review=args.visual_review)
        value = prepare(args.run_id, args.attempt, args.core_revision, args.output, args.execute, args.hold_image, **options)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, KeyboardInterrupt):
        print('Retained-media review rejected; no new runtime or visual acceptance claimed.', file=sys.stderr)
        return 1
    finally:
        if args.execute:
            signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    sys.exit(main())
