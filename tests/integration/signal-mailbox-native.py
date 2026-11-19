#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run two pinned Signal Desktops with real routed mailbox grants in the disposable guest."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

RUNTIME = Path("/home/vpci/signal-backup-runtime")
INSIDE = Path("/tmp/r/providers")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def write_private(path, data):
    with path.open("xb") as out:
        out.write(data)


def invoke(cli, control, args):
    result = subprocess.run([cli, "--control-socket", control, *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180, check=True)
    require(len(result.stdout) <= 65536, "unexpected Core output size")
    return json.loads(result.stdout)


def prepare(root, cli, control, providers):
    require(len(providers) == 2 and len(set(providers)) == 2 and all(HEX.fullmatch(k) for k in providers),
            "two distinct signed provider keys required")
    root.mkdir(mode=0o700)
    users = {}
    for name in ("a", "b"):
        directory = root / name
        directory.mkdir(mode=0o700)
        identity, password = directory / "identity.key", directory / "passphrase"
        write_private(password, secrets.token_hex(48).encode("ascii"))
        args = ["--identity", identity, "--passphrase-file", password]
        # init emits a short human-readable message, recipient-key emits JSON.
        subprocess.run([cli, "--control-socket", control, "init", *args], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=True)
        key = invoke(cli, control, ["content", "recipient-key", *args])["identity_public_key_hex"]
        require(HEX.fullmatch(key), "invalid public application key")
        users[name] = dict(args=args, key=key, invitation=directory / "invitation")
    require(users["a"]["key"] != users["b"]["key"], "application identities must be distinct")
    for name, peer in (("a", "b"), ("b", "a")):
        user = users[name]
        args = [*user["args"], "--invitation", user["invitation"]]
        grant = invoke(cli, control, ["content", "mailbox", "invite", *args, "--sender-key", users[peer]["key"],
                                     "--provider-key", providers[0], "--provider-key", providers[1],
                                     "--lifetime-seconds", "1800"])
        require(grant["owner_key_hex"] == user["key"] and grant["registered_providers"] == 0,
                "unexpected grant owner")
        enrolled = invoke(cli, control, ["content", "mailbox", "enroll", *args])
        require(enrolled["registered_providers"] == 2, "both real providers must acknowledge enrollment")
        user["hash"] = hashlib.sha256(user["invitation"].read_bytes()).hexdigest()
        user["expires"] = grant["expires_unix_seconds"]
    expiry = (min(user["expires"] for user in users.values()) - 1) * 1000
    for name, peer in (("a", "b"), ("b", "a")):
        user, other = users[name], users[peer]
        local = INSIDE / name
        config = dict(executable="/trial/core/volparossa", socket="/trial/core/agent.sock",
                      identity=str(local / "identity.key"), passphrase=str(local / "passphrase"),
                      sendInvitation=str(INSIDE / peer / "invitation"), receiveInvitation=str(local / "invitation"),
                      remoteOwner=other["key"])
        grants = dict(sendGrant=other["hash"], receiveGrant=user["hash"], expires=expiry)
        for filename, value in (("core.json", config), ("grants.json", grants)):
            write_private(root / name / filename, json.dumps(value).encode())
    write_private(root / "ready", b"ready\n")



def native_failure_phase(path):
    phases = {
        "bootstrap", "register-a", "register-b", "open-before", "warm-send", "warm-receive", "warm-reply",
        "stock-acknowledgements", "pair", "offline-send", "offline-compose", "outgoing-row",
        "private-outbox", "outbox-binding", "provider-custody", "offline-fetch", "recipient-reopen",
        "confirm-native-import", "peer-receipt", "sender-reopen", "complete",
    }
    try:
        with path.open("rb") as source:
            phase = source.read(65).decode("ascii")
    except FileNotFoundError:
        return "bootstrap"
    except (OSError, UnicodeDecodeError):
        return "unknown"
    return phase if phase in phases else "unknown"


def launch(parent, cli, control, providers):
    os.umask(0o077)
    require(os.geteuid() != 0 and parent.stat().st_uid == os.geteuid() and stat.S_IMODE(parent.stat().st_mode) == 0o700,
            "private worker-owned directory required")
    require(control.stat().st_gid in os.getgroups() and stat.S_ISSOCK(control.stat().st_mode),
            "protected client control socket unavailable")
    provision = json.loads((Path(__file__).with_name("signal-mailbox-runtime.json")).read_bytes())
    pins = json.loads(Path(__file__).with_name("signal-mailbox-pins.json").read_bytes())
    require(provision["success"] is True and provision["chat_revision"] == pins["chat_revision"] and
            provision["signal_revision"] == pins["signal_revision"], "unverified native runtime")
    candidate = RUNTIME / provision["candidate"]
    node = (RUNTIME / provision["node"]).parent
    for name, expected in provision["runtime_sha256"].items():
        with (candidate / name).open("rb") as source:
            require(hashlib.file_digest(source, "sha256").hexdigest() == expected, "changed native runtime")
    runtime_scripts = RUNTIME / "scripts"
    runner = runpy.run_path(str(runtime_scripts / "run_native_mailbox.py"))
    sandbox = runpy.run_path(str(runtime_scripts / "run_native_receipts.py"))["sandbox"]
    with tempfile.TemporaryDirectory(dir=parent, prefix="native-") as tmp:
        private = Path(tmp)
        prepare(private / "providers", cli, control, providers)
        fixture = RUNTIME / "tests/native/paired-mailbox_test.node.ts"
        driver = runtime_scripts / "run_native_mailbox.py"
        mounts = [(cli, "/trial/core/volparossa"), (control, "/trial/core/agent.sock"),
                  (runtime_scripts / "signal_mailbox.py", "/trial/signal_mailbox.py"),
                  (Path(shutil.which("Xvfb")).resolve(strict=True), "/trial/Xvfb")]
        command = sandbox(private, candidate, node, fixture, runner["TARGET"], driver, mounts)
        command.append("--prepared-providers")
        # Desktop logs, user databases, grants and test account keys remain private in this guest.
        with (private / "desktop.log").open("xb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=420)
        if result.returncode:
            print(json.dumps({"native_trial_completed": False, "phase": native_failure_phase(private / "phase")}))
            raise ValueError("native Desktop trial failed")
        observed = json.loads((private / "result.json").read_bytes())
        require(json.dumps(observed, sort_keys=True) == json.dumps(runner["OBSERVATIONS"], sort_keys=True),
                "native Desktop observations differ")
        receipt = dict(native=observed, chat_revision=provision["chat_revision"], signal_revision=provision["signal_revision"],
                       native_runtime_sha256=provision["runtime_sha256"], two_signed_grants_enrolled=True,
                       control_socket_gid_checked=True)
    require(not list(parent.iterdir()), "private Desktop state remains")
    print(json.dumps(dict(receipt, private_test_state_removed=True), sort_keys=True))


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 6, "expected private directory, Core CLI, client socket and two provider keys")
        launch(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4:])
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        print("SIGNAL_MAILBOX_NATIVE_FAILED", file=sys.stderr)
        raise SystemExit(1) from None
