# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the owner CLI on a private PTY using only fictitious local inputs."""
import errno
import hashlib
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import time


def session(args, digest, accept):
    pid, terminal = pty.fork()
    if pid == 0:
        os.execv(args[0], args)
    output = bytearray()
    deadline = time.monotonic() + 40
    decision_sent = password_sent = joined = False
    try:
        while time.monotonic() < deadline:
            if not select.select([terminal], [], [], max(0, deadline - time.monotonic()))[0]:
                raise TimeoutError("owner terminal deadline")
            try:
                data = os.read(terminal, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            output.extend(data)
            assert len(output) <= 32768
            if not decision_sent and b"or press Enter to cancel: " in output:
                assert all(value.encode() in output for value in (
                    "site-review-fixture", "/index.html", "/style.css", digest,
                    args[args.index("--expected-publisher-key") + 1],
                    hashlib.sha256(Path("first/index.html").read_bytes()).hexdigest(),
                ))
                if accept:
                    Path("tested.vps").write_bytes(b"replacement after inventory review")
                answer = ("SIGN " + digest[:12]).encode() if accept else b""
                os.write(terminal, answer + b"\n")
                decision_sent = True
            if not password_sent and b"VOLPAROSSA identity passphrase: " in output:
                assert accept and decision_sent
                os.write(terminal, b"owner-review-fixture-password\n")
                password_sent = True
        else:
            raise TimeoutError("owner terminal deadline")
        _, status = os.waitpid(pid, 0)
        joined = True
        assert decision_sent and password_sent == accept
        assert (os.waitstatus_to_exitcode(status) == 0) == accept
        return output
    finally:
        os.close(terminal)
        if not joined:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


binary, key, digest = sys.argv[1:]
args = [binary, "--control-socket", "absent.sock", "content", "publish", "--review-site",
        "--input", "tested.vps", "--identity", "identity.key", "--expected-publisher-key", key,
        "--name", "site-review-fixture", "--revision", "5", "--lifetime-seconds", "300",
        "--cache", "reviewed-cache", "--manifest", "reviewed.manifest", "--min-free-bytes", "0"]
for extra in ([], ["--contribute"], ["--passphrase-file", "fixture-password"]):
    result = subprocess.run(args + extra, input=("SIGN " + digest[:12] + "\n").encode(),
                            capture_output=True, start_new_session=True, timeout=10, check=False)
    assert result.returncode != 0
    assert not Path("reviewed-cache").exists() and not Path("reviewed.manifest").exists()

declined = session(args, digest, False)
assert b"owner cancelled" in declined and not Path("reviewed-cache").exists()
assert not Path("reviewed.manifest").exists()
accepted = session(args, digest, True)
expiry = re.search(rb"Expires at\s+(\d+) UTC", accepted)[1].decode()
assert ('"expires_unix_seconds":' + expiry).encode() in accepted
assert ('"terminal_reviewed_bundle_sha256":"' + digest + '"').encode() in accepted
