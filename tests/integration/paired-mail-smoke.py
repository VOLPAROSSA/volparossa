#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Join actual Mail, signed provider ACKs, raw MPTCP privacy captures and host cleanup."""
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "content-mailbox-smoke.py"))
ROLES, read, require = BASE["ROLES"], BASE["read"], BASE["require"]
PHASES = ("send", "receive")
NAMES = {"paired-mail-smoke.json", "paired-mail-supply.json", "content-mailbox-smoke.json"} | {name for p in PHASES for name in (
    f"paired-mail-{p}.json", f"paired-mail-{p}-route-diagnostic.json", f"content-mailbox-paired-{p}-live-selection.json", f"content-mailbox-paired-{p}-gates.json",
    f"content-provider-mailbox-paired-{p}-control.json", *(f"content-mailbox-paired-{p}-privacy-{r}.json" for r in ROLES))}


def verify_provider_acks(observations, keys, message_id):
    require(len(observations) == 2 and {r["provider_key"] for r in observations} == keys and
            all(r["message_id"] == message_id for r in observations), "wrong signed ACK providers or message")
    BASE["receipts"]([r["receipt"] for r in observations], keys, 5, message_id)
    signature = runpy.run_path(str(HERE / "content-retain-smoke.py"))["verify_signature"]
    for observation in observations:
        envelope = BASE["fields"](bytes.fromhex(observation["receipt"]))
        signature(envelope[1], envelope[2], bytes.fromhex(observation["provider_key"]), b"VOLPAROSSA/native-mailbox/v1\0")


def verify(report, revision):
    require(report["success"] is True and report["source_revision"] == revision and
            report["report_kind"] == "volparossa-paired-mail" and report["runner_exit_status"] == 0, "invalid guest outcome")
    BASE["validate_report"](report["mailbox"], revision)
    pins = read(HERE / "paired-mail-pins.json")
    supply = report["supply"]
    require(supply["mail_revision"] == pins["mail_revision"] and all(supply[key] == value for key, value in pins["actions"].items()),
            "Mail runtime differs from the verified original QA artifact")
    native = "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node"
    require(supply["files"] > 100 and supply["native_binaries"] == {
        "bin/stalwart": pins["actions"]["stalwart_sha256"], native: pins["actions"]["libsignal_sha256"],
        "bin/node": "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"}, "wrong native closure")
    base = report["mailbox"]["mailbox"]
    sent, received = report["app"]["send"], report["app"]["receive"]
    fixture = runpy.run_path(str(HERE / "paired-mail-guest.py"))
    require(sent["confirmed_providers"] == received["confirmed_providers"] == 2 and sent["resumed_without_inputs"] is True
        and sent["sender_profile_removed"] is True and received["fetched_messages"] == received["owner_emails"] == 1
        and received["messages_after_ack"] == received["preimport_acks"] == 0 and received["exact_raw_bytes"] is True,
        "incomplete Mail send, import or retirement")
    require(all(sent[k] == received[k] for k in ("message_id","packet_bytes","packet_sha256","message_sha256","message_bytes"))
        and sent["message_sha256"] == fixture["DIGEST"] and sent["message_bytes"] == len(fixture["MIME"])
        and sent["packet_bytes"] > sent["message_bytes"], "inconsistent protected MIME handoff")
    receipts = received["acknowledgement_receipts"]
    keys = set(base["provider_keys"].values())
    verify_provider_acks(receipts, keys, sent["message_id"])
    for name in PHASES:
        route = report["routes"][name]
        BASE["validate_phase"](route, base["expected_peers"], base["provider_nodes"], sent["packet_bytes"], name == "receive")
        require(route["selected_route"]["route_context_id"] == base["phases"][name]["selected_route"]["route_context_id"],
                "Mail did not use the original sender and reopened recipient routes")


def assemble(root, revision, exit_status, blocker):
    report = dict(report_kind="volparossa-paired-mail", source_revision=revision, runner_exit_status=int(exit_status),
                  success=False, observed_blocker=None if blocker=="NONE" else blocker)
    if exit_status == "0":
        base = read(root/"content-mailbox-smoke.json")
        routes = {}
        for phase in PHASES:
            prefix = f"content-mailbox-paired-{phase}"
            routes[phase] = dict(selected_route=read(root/f"{prefix}-live-selection.json"),
                gates=read(root/f"{prefix}-gates.json"), control=read(root/f"content-provider-mailbox-paired-{phase}-control.json"),
                control_relay_peer_id=base["mailbox"]["phases"][phase]["control_relay_peer_id"],
                privacy={r:read(root/f"{prefix}-privacy-{r}.json") for r in ROLES})
        report.update(success=True, mailbox=base, supply=read(root/"paired-mail-supply.json"), routes=routes, app={p:read(root/f"paired-mail-{p}.json") for p in PHASES})
        verify(report, revision)
    return report


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["export-names"]:
            print("\n".join(sorted(NAMES)))
        elif len(sys.argv) == 6 and sys.argv[1] == "assemble":
            print(json.dumps(assemble(Path(sys.argv[2]), *sys.argv[3:]), separators=(",",":")))
        elif len(sys.argv) == 4 and sys.argv[1] == "report":
            verify(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("unsupported arguments")
    except (KeyError, OSError, TypeError, ValueError):
        sys.exit("PAIRED_MAIL_EVIDENCE_INCOMPLETE")
