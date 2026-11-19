#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One Mail participant with one private identity and one mounted Core Client agent."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import socket
import subprocess
import sys

STATE = Path("/trial/state")
CORE = "/trial/core/volparossa"
CONTROL = "/trial/core/agent.sock"
MAIL = runpy.run_path("/trial/driver.py")
require, command = MAIL["require"], MAIL["command"]


def local_config():
    return dict(executable=CORE, socket=CONTROL, identity=str(STATE/"identity.key"), passphrase=str(STATE/"passphrase"))


def initialize(role):
    cfg = local_config()
    (STATE/"passphrase").write_bytes(secrets.token_hex(48).encode())
    subprocess.run([CORE, "--control-socket", CONTROL, "init", *MAIL["identity"](cfg)], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
    public = command([CORE, "--control-socket", CONTROL, "content", "recipient-key", *MAIL["identity"](cfg)], "identity")
    key = public["identity_public_key_hex"]
    require(re.fullmatch("[0-9a-f]{64}", key), "public Core key")
    bundle = STATE/"public.bundle"
    init = command([MAIL["NODE"], MAIL["SIGNAL"], "init", "--profile", STATE/role, "--bundle", bundle], "Signal init")
    fingerprint = hashlib.sha256(bundle.read_bytes()).hexdigest()
    require(init["bundle_sha256"] == fingerprint, "public Signal fingerprint")
    (STATE/"core.json").write_text(json.dumps(cfg))
    return dict(core_key=key, signal_bundle_sha256=fingerprint)


def pair(role, key, fingerprint):
    bundle = STATE/"peer.bundle"
    require(re.fullmatch("[0-9a-f]{64}", key) and hashlib.sha256(bundle.read_bytes()).hexdigest() == fingerprint,
            "untrusted peer")
    command([MAIL["NODE"], MAIL["SIGNAL"], "pair", "--profile", STATE/role, "--peer-bundle", bundle,
             "--trusted-bundle-sha256", fingerprint, "--core-owner-key", key], "Signal pair")
    bundle.unlink()
    return dict(peer_key=key, paired_bundle_sha256=fingerprint)


def enroll(sender, *providers):
    require(len(providers) == len(set(providers)) == 2, "external providers")
    invitation = STATE/"invitation"
    args = [CORE, "--control-socket", CONTROL, "content", "mailbox"]
    flags = ["--invitation", invitation, *MAIL["identity"](local_config())]
    grant = command([*args, "invite", *flags, "--sender-key", sender, "--provider-key", providers[0],
                     "--provider-key", providers[1], "--lifetime-seconds", "3600"], "invite")
    result = command([*args, "enroll", *flags], "enroll")
    require(result["registered_providers"] == 2 and grant["registered_providers"] == 0, "signed enrollment")
    return dict(owner_key=grant["owner_key_hex"], invitation_sha256=hashlib.sha256(invitation.read_bytes()).hexdigest(),
                storage_receipts=result["storage_receipts"])


def run(role, operation, *args):
    require(role in {"sender", "recipient"} and socket.if_nameindex() == [(1, "lo")] and os.getuid() != 0 and
            not (STATE/("recipient" if role == "sender" else "sender")).exists(), "private participant")
    if operation == "init":
        return initialize(role)
    if operation == "pair":
        return pair(role, *args)
    if operation == "enroll" and role == "recipient":
        return enroll(*args)
    if operation == "send" and role == "sender":
        return MAIL["send_mime"](STATE/role, STATE/"core.json", STATE/"invitation", *args, retain_signed=True)
    if operation == "receive" and role == "recipient":
        return MAIL["receive"](dict(**local_config(), receiveInvitation=str(STATE/"invitation")))
    raise ValueError("unsupported stage")


if __name__ == "__main__":
    try:
        os.umask(0o077)
        print(json.dumps(run(*sys.argv[1:]), sort_keys=True))
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        phase = command.__globals__["PHASE"]
        print(json.dumps({"failed_stage": phase if phase in MAIL["APP_STAGES"] | {"invite", "enroll"} else "namespace"}))
        sys.exit(1)
