#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit v2 B-loss variant of the actual core/owner/protected-provider trial."""
import runpy
from pathlib import Path

M = runpy.run_path(str(Path(__file__).with_name('private-storage-maintenance-smoke.py')))
M['configure_adaptive']()
# Functions retain their module globals, including the explicit adaptive profile.
G = M['main'].__globals__

if __name__ == '__main__':
    import json
    import signal
    import subprocess
    import sys

    def interrupted(_signal, _frame):
        raise InterruptedError('fixture interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    try:
        M['main'](sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps(dict(version=1, success=False,
            kind='private-storage-adaptive-maintenance-failure', stage=G['STAGE'])))
        sys.exit(1)
