#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the requested Mail stage with only this participant's state and Client socket."""
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "paired-mail-sandbox.py"))


def launch(bundle, parent, cli, control, role, operation, args):
    os.umask(0o077)
    if (os.geteuid() == 0 or not stat.S_ISSOCK(control.stat().st_mode) or
            control.stat().st_gid not in {os.getegid(), *os.getgroups()} or
            stat.S_IMODE(cli.stat().st_mode) != 0o500 or cli.stat().st_uid != os.geteuid() or
            parent.stat().st_uid != os.geteuid() or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise ValueError("private inputs required")
    if operation == "init":
        for name in ("app", "store"):
            (parent/name).mkdir(mode=0o700)
    cmd = BASE["mounts"](bundle, parent, cli, control)
    cmd += ["--ro-bind", HERE/"paired-mail-peer-guest.py", "/trial/peer.py", "--",
            "/usr/bin/python3", "-I", "-B", "/trial/peer.py", role, operation, *args]
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=600)
    if len(result.stdout) > 65536:
        raise ValueError("oversized result")
    record = json.loads(result.stdout)
    if result.returncode:
        stages = runpy.run_path(str(HERE/"paired-mail-guest.py"))["APP_STAGES"] | {"enroll", "invite"}
        stage = record.get("failed_stage")
        print(json.dumps(dict(failed_stage=stage if isinstance(stage, str) and stage in stages else "namespace")))
        raise ValueError("application failed")
    return record


if __name__ == "__main__":
    try:
        print(json.dumps(launch(BASE["BUNDLE"], *(Path(arg) for arg in sys.argv[1:4]), *sys.argv[4:6], sys.argv[6:])))
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        sys.exit("PAIRED_MAIL_PEER_STAGE_INCOMPLETE")
