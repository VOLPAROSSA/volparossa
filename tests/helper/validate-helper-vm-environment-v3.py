#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate the explicitly selected Rust1.89.0 current profile; v1/v2 evidence stays immutable."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('compiler', ROOT / 'scripts/provision-rust189.py')
COMPILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER)
IMAGE = '184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003'
KINDS = {'boundary': ('volparossa-helper-boundary-vm-environment', 'validate-helper-boundary-evidence-v1.sh'),
         'restart': ('volparossa-helper-restart-vm-environment', 'validate-helper-restart-exact-present-evidence-v1.sh')}


def read_input(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= 32768:
        raise ValueError('input must be one bounded single-link regular file')
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode():
        raise ValueError('input must be canonical JSON without duplicate fields')
    identity = tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    return value, (identity, hashlib.sha256(raw).hexdigest())


def validate(value, report, kind, commit, image):
    if kind not in KINDS or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', commit) or set(commit) == {'0'}:
        raise ValueError('unknown profile or invalid source revision')
    if image != IMAGE:
        raise ValueError('image must be the exact reviewed Debian13 image')
    expected = {'schema_version': 3, 'expected_commit': commit, 'image_release_build': '20260826-2582',
                'image_sha512': IMAGE, 'proof_network': {'external_https': 'denied', 'mode': 'qemu-user-restrict-on'},
                'report_kind': KINDS[kind][0], 'status': 'PASS',
                'guest': {'architecture': 'amd64', 'cargo_commit': 'c24e10642', 'debian_version': '13',
                          'rustc_version': '1.89.0', 'systemd_version': 257, 'virtualization': 'kvm'}}
    if set(value) != set(expected) | {'report_sha256', 'toolchain'}:
        raise ValueError('successor environment keys are not exact')
    if any(value[k] != v for k, v in expected.items()):
        raise ValueError('successor environment does not match the reviewed profile')
    COMPILER.validate_receipt(value['toolchain'])
    if value['report_sha256'] != hashlib.sha256(report.read_bytes()).hexdigest():
        raise ValueError('report digest mismatch')
    if json.loads(report.read_text())['observed_source']['commit_sha'] != commit:
        raise ValueError('report source mismatch')


def main(args):
    if len(args) != 5:
        raise ValueError('usage: KIND ENV REPORT COMMIT IMAGE_SHA512')
    kind, environment, report, commit, image = args
    if kind not in KINDS: raise ValueError('unknown environment profile')
    environment, report = Path(environment), Path(report)
    value, before_env = read_input(environment)
    _, before_report = read_input(report)
    validate(value, report, kind, commit, image)
    validator = Path(__file__).with_name(KINDS[kind][1])
    subprocess.run([str(validator), str(report)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)
    if read_input(environment)[1] != before_env or read_input(report)[1] != before_report:
        raise ValueError('evidence input changed during validation')


if __name__ == '__main__':
    try: main(sys.argv[1:])
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit('invalid helper VM environment v3: ' + str(error))
