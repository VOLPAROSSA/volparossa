#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure the two-job Firefox builder and KVM prerequisites on the runner."""
import fcntl
import json
import os
import shutil
import sys


def main():
    workspace, revision = sys.argv[1:]
    require_bytes = 60 * 1024**3
    free_bytes = shutil.disk_usage(workspace).free
    try:
        with open("/dev/kvm", "rb+", buffering=0) as kvm:
            api_version = fcntl.ioctl(kvm, 0xAE00)  # KVM_GET_API_VERSION
    except OSError:
        api_version = None
    cpus = len(os.sched_getaffinity(0))
    admitted = os.getuid() != 0 and api_version == 12 and cpus >= 2 and free_bytes >= require_bytes
    print(json.dumps(dict(kind="firefox-native-build-capacity", core_revision=revision,
        free_bytes=free_bytes, required_free_bytes=require_bytes, available_cpus=cpus,
        build_jobs=2, kvm_api_version=api_version, unprivileged=os.getuid() != 0,
        admitted=admitted)), flush=True)
    return 0 if admitted else 1


if __name__ == "__main__":
    raise SystemExit(main())
