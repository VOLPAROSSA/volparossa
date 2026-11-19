#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the ordinary paired-Mail sender and Stalwart recipient on separate route phases."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import socket
import subprocess
import sys

STATE = Path("/trial/state")
PROVIDERS = Path("/tmp/r/providers")
MAIL = Path("/mail")
SIGNAL = MAIL / "integration/signal-mail/cli.mjs"
ACCEPT = MAIL / "integration/peer-mail/accept.py"
CORE = "/trial/core/volparossa"
NODE = "/trial/bin/node"
OWNER = "owner@volparossa.test"
# Include an attachment large enough to measure the actual ciphertext return on the Exit.
ATTACHMENT = base64.encodebytes(hashlib.shake_256(b"paired-mail-KVM-attachment").digest(65536)).replace(b"\n", b"\r\n")
MIME = ("From: Peer <sender@example.test>\r\nTo: owner@volparossa.test\r\n"
        "Subject: Paired Mail\r\nMessage-ID: <routed-mail@example.test>\r\n"
        'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="paired-routed"\r\n\r\n'
        "--paired-routed\r\nContent-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\nDe ontvanger was vóór de verzending offline.\r\n"
        "--paired-routed\r\nContent-Type: application/octet-stream\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n").encode() + ATTACHMENT + b"--paired-routed--\r\n"
DIGEST = hashlib.sha256(MIME).hexdigest()
PHASE = "namespace"
APP_STAGES = {"namespace", "identity", "Signal init", "Signal pair", "Mail send", "Mail send resume", "Core fetch",
              "owner initialization", "owner session", "Stalwart accept", "signed acknowledgements", "fetch empty"}


def require(value, message):
    if not value:
        raise ValueError(message)


def command(args, stage, password=None):
    global PHASE
    PHASE = stage
    result = subprocess.run(args, input=password or b"", capture_output=True, timeout=240)
    require(result.returncode == 0 and 0 < len(result.stdout) < 131072, stage)
    return json.loads(result.stdout)


def config(role):
    result = json.loads((PROVIDERS / role / "core.json").read_bytes())
    require(result["executable"] == CORE and Path(result["socket"]).is_socket(), "Core binding")
    return result


def identity(role):
    return ["--identity", role["identity"], "--passphrase-file", role["passphrase"]]


def send():
    a, b = config("a"), config("b")
    people = [(STATE / "sender", STATE / "sender.bundle"), (STATE / "recipient", STATE / "recipient.bundle")]
    keys = []
    for cfg, (profile, bundle) in zip((a, b), people):
        key = command([CORE, "--control-socket", cfg["socket"], "content", "recipient-key", *identity(cfg)], "identity")
        keys.append(key["identity_public_key_hex"])
        initialized = command([NODE, SIGNAL, "init", "--profile", profile, "--bundle", bundle], "Signal init")
        require(initialized["bundle_sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest(), "bundle digest")
    require(keys[0] != keys[1] and [a["remoteOwner"], b["remoteOwner"]] == keys[::-1], "independent owners")
    for (profile, _), (_, other), peer in zip(people, reversed(people), reversed(keys)):
        command([NODE, SIGNAL, "pair", "--profile", profile, "--peer-bundle", other, "--core-owner-key", peer,
                 "--trusted-bundle-sha256", hashlib.sha256(other.read_bytes()).hexdigest()], "Signal pair")
    original, invitation = STATE / "selected.eml", STATE / "selected.invitation"
    original.write_bytes(MIME)
    invitation.write_bytes(Path(a["sendInvitation"]).read_bytes())
    operation = secrets.token_hex(32)
    sender = [NODE, SIGNAL, "send", "--id", operation, "--profile", people[0][0],
              "--core-config", PROVIDERS / "a/core.json"]
    record = command([*sender, "--input", original, "--invitation", invitation, "--core-owner-key", keys[1]], "Mail send")
    packet = (people[0][0] / "core-send" / operation / "packet").read_bytes()
    require(record["operation"] == "send" and record["confirmed_providers"] == 2 and
            record["message_sha256"] == DIGEST and record["message_bytes"] == len(MIME) and
            record["packet_sha256"] == hashlib.sha256(packet).hexdigest() and MIME not in packet, "protected deposit")
    original.unlink()
    invitation.unlink()
    require(command([*sender, "--resume"], "Mail send resume") == record, "resume binding")
    shutil.rmtree(people[0][0])
    for _, bundle in people:
        bundle.unlink()
    return dict(confirmed_providers=2, resumed_without_inputs=True, message_sha256=DIGEST, message_bytes=len(MIME),
                packet_sha256=record["packet_sha256"], packet_bytes=len(packet), sender_profile_removed=True,
                message_id=record["message_id"])


def receive():
    global PHASE
    require(not (STATE / "sender").exists() and not (STATE / "selected.eml").exists(), "sender still present")
    recipient = config("b")
    def fetch(name):
        return command([CORE, "--control-socket", recipient["socket"], "content", "mailbox", "fetch",
                        *identity(recipient), "--invitation", recipient["receiveInvitation"], "--output-dir", STATE / name],
                       "fetch empty" if name == "empty" else "Core fetch")
    first = fetch("received")
    require(first["messages_fetched"] == 1 and first["listed_providers"] == 2 and
            first["provider_custody_consumed"] is False and first["acknowledged_providers_per_message"] == 0, "premature ACK")
    handoff, = (STATE / "received").iterdir()
    require(handoff.is_dir() and re.fullmatch("[a-f0-9]{64}", handoff.name), "invalid handoff")
    packet = (handoff / "payload").read_bytes()
    packet_sha = hashlib.sha256(packet).hexdigest()
    owner = runpy.run_path(str(MAIL / "packaging/systemd/initialize-owner.py"))
    password = "privé-" + secrets.token_urlsafe(32)
    PHASE = "owner initialization"
    owner["initialize"](OWNER, password)
    PHASE = "owner session"
    receipts = STATE / "accepted"
    receipts.mkdir(mode=0o700)
    with owner["server"](owner["STATE"], OWNER.split("@")[1], OWNER, password) as session:
        account = session["primaryAccounts"][owner["MAIL"]]
        def request(method, args):
            return owner["request"](OWNER, password, method, {"accountId": account, **args})
        inbox, = (m["id"] for m in request("Mailbox/get", {"properties": ["id", "role"]})["list"] if m["role"] == "inbox")
        require(request("Email/query", {"limit": 2})["ids"] == [], "owner inbox not empty")
        destination = STATE / "owner.json"
        destination.write_text(json.dumps(dict(server="http://127.0.0.1:8080", username=OWNER, accountId=account,
            mailboxId=inbox, controlSocket=recipient["socket"], identity=recipient["identity"], passphraseFile=recipient["passphrase"])))
        accepted = command([sys.executable, "-B", ACCEPT, "--node", NODE, "--core", CORE, "--profile", STATE / "recipient",
            "--handoff", handoff, "--connection", destination, "--state-dir", receipts], "Stalwart accept", password.encode())
        require(accepted["message_id"] == handoff.name and accepted["signal_packet_sha256"] == packet_sha and
                accepted["message_sha256"] == DIGEST and accepted["message_bytes"] == len(MIME) and
                accepted["acknowledged_providers"] == 2, "accepted message binding")
        require(request("Email/query", {"limit": 2})["ids"] == [accepted["email_id"]], "owner email readback")
    PHASE = "signed acknowledgements"
    confirmed = json.loads((handoff / "confirmed.json").read_bytes())
    require(confirmed["message_id"] == handoff.name and confirmed["acknowledged_providers"] == 2 and
            confirmed["consumer_import_attested"] is True, "Core confirmations")
    empty = fetch("empty")
    require(empty["messages_fetched"] == 0 and empty["listed_providers"] == 2 and not list((STATE / "empty").iterdir()),
            "nonempty repeated fetch")
    return dict(fetched_messages=1, preimport_acks=0, confirmed_providers=2, messages_after_ack=0, exact_raw_bytes=True,
                owner_emails=1, message_sha256=DIGEST, message_bytes=len(MIME), packet_sha256=packet_sha,
                packet_bytes=len(packet), message_id=handoff.name, acknowledgement_receipts=confirmed["acknowledgement_receipts"])


if __name__ == "__main__":
    try:
        require(os.geteuid() != 0 and socket.if_nameindex() == [(1, "lo")], "private application namespace")
        os.umask(0o077)
        print(json.dumps({"send": send, "receive": receive}[sys.argv[1]](), sort_keys=True))
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        # Only literal phase identifiers above may leave the private application namespace.
        print(json.dumps({"failed_stage": PHASE if PHASE in APP_STAGES else "namespace"}))
        print("PAIRED_MAIL_GUEST_FAILED", file=sys.stderr)
        sys.exit(1)
