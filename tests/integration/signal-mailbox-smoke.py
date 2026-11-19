#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check native two-Desktop receipts against the same guest's protected mailbox captures."""

import json
from pathlib import Path
import re
import runpy
import sys

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "content-mailbox-smoke.py"))
ROLES, read, require = BASE["ROLES"], BASE["read"], BASE["require"]
NATIVE = dict(version=1, standalone_desktops=2, mailbox_providers=2, stock_messaging_before_pairing=True,
              receiver_offline_during_deposit=True, sender_offline_during_pickup=True, repeat_fetch_before_import=True,
              confirm_before_import=0, native_row_survived_restart=True, repeat_import_preserved_ratchet=True,
              delivered_after_sender_restart=True, paired_stock_submissions=0, both_provider_inboxes_empty=True)
NAMES = {"signal-mailbox-smoke.json", "signal-mailbox-native.json", "content-mailbox-smoke.json",
         "content-mailbox-desktop-live-selection.json", "content-mailbox-desktop-gates.json",
         "content-provider-mailbox-desktop-control.json"} | {f"content-mailbox-desktop-privacy-{r}.json" for r in ROLES}


def verified(report, revision):
    require(report["source_revision"] == revision and re.fullmatch(r"[0-9a-f]{40}", revision)
            and report["report_kind"] == "volparossa-signal-mailbox" and report["success"] is True,
            "incomplete native protected mailbox trial")
    base, native = report["mailbox"], report["desktops"]
    BASE["validate_report"](base, revision)
    pins = read(HERE / "signal-mailbox-pins.json")
    require(native["chat_revision"] == pins["chat_revision"] and native["signal_revision"] == pins["signal_revision"]
            and json.dumps(native["native"], sort_keys=True) == json.dumps(NATIVE, sort_keys=True)
            and native["two_signed_grants_enrolled"] is True and native["control_socket_gid_checked"] is True
            and native["private_test_state_removed"] is True, "Desktop observations differ")
    expected_runtime = {"node_modules/electron/dist/electron", "node_modules/@signalapp/ringrtc/build/linux/libringrtc-x64.node",
                        "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node",
                        "node_modules/@signalapp/sqlcipher/prebuilds/linux-x64/@signalapp+sqlcipher.node",
                        "bundles/main.js", "bundles/preload/main.js", "bundles/workers/sql.js"}
    require(set(native["native_runtime_sha256"]) == expected_runtime
            and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in native["native_runtime_sha256"].values()),
            "native runtime digests missing")
    evidence, route = base["mailbox"], report["desktop_route"]
    require(route["selected_route"]["route_context_id"] == evidence["phases"]["receive"]["selected_route"]["route_context_id"],
            "Desktop did not use the independently captured receiver route")
    BASE["validate_phase"](route, evidence["expected_peers"], evidence["provider_nodes"], 0, False)
    gates = route["gates"]
    require(min(gates["exit_mptcp_tls_completed"], gates["exact_provider_lookups"]) >= 12,
            "native phase lacks protected provider exchanges")
    require(report["host_state"] == base["host_state"] and report["cleanup"] == base["cleanup"],
            "guest cleanup differs from the protected trial")


def assemble(root, revision, status, blocker):
    report = dict(schema_version=1, report_kind="volparossa-signal-mailbox", source_revision=revision,
                  success=False, observed_blocker=None if blocker == "NONE" else blocker,
                  independent_client_nodes=1, standalone_desktops=2)
    if status == "0":
        base = read(root / "content-mailbox-smoke.json")
        route = dict(selected_route=read(root / "content-mailbox-desktop-live-selection.json"),
                     control_relay_peer_id=base["mailbox"]["phases"]["receive"]["control_relay_peer_id"],
                     privacy={r: read(root / f"content-mailbox-desktop-privacy-{r}.json") for r in ROLES},
                     control=read(root / "content-provider-mailbox-desktop-control.json"),
                     gates=read(root / "content-mailbox-desktop-gates.json"))
        report.update(success=True, mailbox=base, desktops=read(root / "signal-mailbox-native.json"),
                      desktop_route=route, host_state=base["host_state"], cleanup=base["cleanup"])
        verified(report, revision)
    return report


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["export-names"]:
            print("\n".join(sorted(NAMES)))
        elif len(sys.argv) == 6 and sys.argv[1] == "assemble":
            print(json.dumps(assemble(Path(sys.argv[2]), *sys.argv[3:]), separators=(",", ":")))
        elif len(sys.argv) == 4 and sys.argv[1] == "report":
            verified(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("unsupported command")
    except (KeyError, TypeError, ValueError, OSError):
        sys.exit("SIGNAL_MAILBOX_EVIDENCE_INCOMPLETE")
