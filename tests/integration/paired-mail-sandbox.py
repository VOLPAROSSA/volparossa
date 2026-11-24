#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Mount only the tested Mail binaries, private app state and one Client socket."""
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BUNDLE = Path("/var/tmp/volparossa-paired-mail-runtime")


def command(bundle, private, phase, cli, control):
    product, runtime = bundle / "source", bundle / "runtime"
    args = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--clearenv",
            "--setenv", "PATH", "/trial/bin:/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
            "--setenv", "HOME", "/tmp", "--dir", "/run", "--cap-drop", "ALL",
            "--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs", "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf", "--ro-bind", "/usr", "/usr", "--tmpfs", "/usr/local",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/r/providers",
            "--ro-bind", product, "/mail", "--ro-bind", runtime / "node_modules", "/mail/integration/signal-mail/node_modules",
            "--ro-bind", runtime / "bin/node", "/trial/bin/node",
            "--ro-bind", runtime / "bin/stalwart", "/usr/local/libexec/volparossa-mail/stalwart",
            "--ro-bind", product / "packaging/systemd/store.json", "/usr/local/libexec/volparossa-mail/store.json",
            "--ro-bind", cli, "/trial/core/volparossa", "--ro-bind", control, "/trial/core/agent.sock",
            "--bind", private / "app", "/trial/state", "--bind", private / "store", "/var/lib/volparossa-mail",
            "--ro-bind", HERE / "paired-mail-guest.py", "/trial/driver.py"]
    for name in (("a", "b") if phase == "send" else ("b",)):
        args.extend(["--ro-bind", private / "providers" / name, "/tmp/r/providers/" + name])
    return [*args, "--", "/usr/bin/python3", "-I", "-B", "/trial/driver.py", phase]


def launch(phase, parent, cli, control, keys):
    os.umask(0o077)
    if (phase not in {"send", "receive"} or os.geteuid() == 0 or not stat.S_ISSOCK(control.stat().st_mode)
        or control.stat().st_gid not in {os.getegid(), *os.getgroups()} or stat.S_IMODE(cli.stat().st_mode) != 0o500
        or cli.stat().st_uid != os.geteuid() or parent.stat().st_uid != os.geteuid()
        or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise ValueError("invalid private application inputs")
    if phase == "send":
        for name in ("app", "store"):
            (parent / name).mkdir(mode=0o700)
        # Same unmodified CLI, two independently authenticated provider keys and private identities
        # as the native Chat trial. The recipient has a separate grant from the generic mailbox fixture.
        runpy.run_path(str(HERE / "signal-mailbox-native.py"))["prepare"](parent / "providers", cli, control, keys)
    record = subprocess.run(command(BUNDLE, parent, phase, cli, control), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, timeout=600, check=False)
    if len(record.stdout) > 65536:
        raise ValueError("oversized Mail observations")
    if record.returncode:
        try:
            stage = json.loads(record.stdout).get("failed_stage")
        except (ValueError, AttributeError):
            stage = None
        allowed = runpy.run_path(str(HERE/"paired-mail-guest.py"))["APP_STAGES"]
        print(json.dumps({"failed_stage": stage if isinstance(stage, str) and stage in allowed else "namespace"}))
        raise ValueError("paired Mail guest failed")
    receipt = json.loads(record.stdout)
    if phase == "send":
        shutil.rmtree(parent / "providers/a")
    else:
        for item in (parent / "providers", parent / "store", parent / "app"):
            shutil.rmtree(item)
        if any(parent.iterdir()):
            raise ValueError("private Mail state remains")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        launch(sys.argv[1], *(Path(arg) for arg in sys.argv[2:5]), sys.argv[5:])
    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
        sys.exit("PAIRED_MAIL_STAGE_INCOMPLETE")
