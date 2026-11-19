#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Cross-check native observations, grants, route receipts and closed artifact exports."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SMOKE = runpy.run_path(str(HERE / "signal-mailbox-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-mailbox-smoke.py"))
SOURCE = "a" * 40
PINS = json.loads((HERE / "signal-mailbox-pins.json").read_bytes())


def receipt():
    evidence = BASE["fixture"]()
    cleanup = dict(complete=True, remaining_owned_objects=0)
    host = dict(unchanged=True, before_sha256="b"*64, after_sha256="b"*64)
    base = dict(report_kind="volparossa-private-mailbox", source_revision=SOURCE, success=True, runner_exit_status=0,
                cleanup=cleanup, host_state=host, independent_sender_node_claimed=False, full_c07_claimed=False,
                full_alpha_acceptance_claimed=False, mailbox=evidence)
    phase = copy.deepcopy(evidence["phases"]["receive"])
    phase["gates"].update(exit_mptcp_tls_completed=12, exact_provider_lookups=12)
    native = dict(chat_revision=PINS["chat_revision"], signal_revision=PINS["signal_revision"],
                  two_signed_grants_enrolled=True, private_test_state_removed=True, control_socket_gid_checked=True,
                  native=SMOKE["NATIVE"].copy(), native_runtime_sha256={n:"c"*64 for n in (
                    "node_modules/electron/dist/electron", "node_modules/@signalapp/ringrtc/build/linux/libringrtc-x64.node",
                    "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node",
                    "node_modules/@signalapp/sqlcipher/prebuilds/linux-x64/@signalapp+sqlcipher.node",
                    "bundles/main.js", "bundles/preload/main.js", "bundles/workers/sql.js")})
    return dict(source_revision=SOURCE,report_kind="volparossa-signal-mailbox",success=True,mailbox=base,
                desktops=native,desktop_route=phase,host_state=host,cleanup=cleanup)


class RoutedNativeMailbox(unittest.TestCase):
    def test_staged_cli_keeps_source_bytes_and_is_executable_only_by_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            original = work / "compiled"
            original.mkdir()
            (work / "bin").mkdir()
            (original / "volparossa").write_bytes(b"compiled Core CLI")
            command = ['sh', '-c', '. "$1"; signal_mailbox_stage_cli', 'check',
                       str(HERE / 'signal-mailbox-smoke.sh')]
            env = dict(os.environ, WORK=folder, WORKER_UID=str(os.getuid()), WORKER_GID=str(os.getgid()),
                       binary_directory=str(original))
            subprocess.run(command, env=env, check=True)
            cli = work / 'bin/signal-mailbox-volparossa'
            self.assertEqual(cli.read_bytes(), (original / 'volparossa').read_bytes())
            self.assertEqual(cli.stat().st_uid, os.getuid())
            self.assertEqual(cli.stat().st_mode & 0o777, 0o500)
            self.assertNotEqual(subprocess.run(command, env=env).returncode, 0)

    def test_native_failure_receipt_exposes_only_fixed_local_phases(self):
        observed = runpy.run_path(str(HERE / "signal-mailbox-native.py"))["native_failure_phase"]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "phase"
            self.assertEqual(observed(marker), "bootstrap")
            for value in ("offline-compose", "outgoing-row", "private-outbox", "outbox-binding"):
                marker.write_text(value)
                self.assertEqual(observed(marker), value)
            for value in (b"unrelated detail", b"x" * 70, bytes([255])):
                marker.write_bytes(value)
                self.assertEqual(observed(marker), "unknown")

    def test_actual_two_phase_contract(self):
        record = receipt()
        SMOKE["verified"](record, SOURCE)
        for change in (lambda r:r["desktops"]["native"].update(receiver_offline_during_deposit=False),
                       lambda r:r["desktops"]["native"].update(confirm_before_import=False),
                       lambda r:r["desktop_route"]["gates"].update(exact_provider_lookups=11),
                       lambda r:r["desktop_route"]["privacy"]["client"].update(direct_client_exit_packets=1),
                       lambda r:r["desktops"].update(chat_revision="0"*40),
                       lambda r:r["desktop_route"]["selected_route"].update(route_context_id="9"*32)):
            modified = copy.deepcopy(record)
            change(modified)
            with self.assertRaises(ValueError):
                SMOKE["verified"](modified, SOURCE)

    def test_guest_export_is_closed_and_matches_driver(self):
        names=SMOKE["NAMES"]
        self.assertTrue(all(n.endswith(".json") and "/" not in n for n in names))
        self.assertFalse(any(x in n for n in names for x in ("identity", "grant", "passphrase","profile")))
        src=(HERE/"run-alpha-topology-vm.sh").read_text()
        block=src[src.index("SIGNAL_MAILBOX_NAMES ="):src.index("SIGNAL_NAMES =")]
        data={}
        exec(block,data)
        self.assertEqual(data["SIGNAL_MAILBOX_NAMES"], names | {"current-phase","guest-exit-status",
                           "signal-backup-provision.json","host-state-before.json","host-state-after.json"})
        for script in ("run-alpha-topology-vm.sh","kvm-alpha-topology.sh"):
            out=subprocess.check_output(["sh",HERE/script,"--preview","--scenario","signal-mailbox"],text=True)
            self.assertIn("two standalone desktops",out.lower().replace("signal desktops","desktops"))

    def test_failure_preserves_only_a_closed_selection_reason_per_mailbox_phase(self):
        script = HERE / "benchmark-selection.sh"
        with tempfile.TemporaryDirectory() as folder:
            command = """
                set -eu
                . "$1"
                WORK=$2
                signal_mailbox=yes
                benchmark_connect_count=1; benchmark_connect_exit=1; benchmark_connect_reason=PRESELECTION_UNAVAILABLE
                benchmark_draw=0; benchmark_poll=0; benchmark_snapshot_status=null
                for phase in send receive; do
                    benchmark_label=content-mailbox-$phase
                    benchmark_image_route_diagnostic connect CONNECT_TRANSIENT
                done
                benchmark_label=unknown
                if benchmark_route_diagnostic_prefix; then exit 1; fi
            """
            subprocess.run(["sh","-c",command,"sh",script,folder],check=True)
            files=list(Path(folder).iterdir())
            self.assertEqual({f.name for f in files},
                             {f"signal-mailbox-{phase}-route-diagnostic.json" for phase in ("send","receive")})
            for f in files:
                data=json.loads(f.read_bytes())
                self.assertEqual(data["last_connect_reason"],"PRESELECTION_UNAVAILABLE")
                self.assertEqual(set(data),{"schema_version","stage","reason","last_connect_reason","connect_exit_status",
                                          "attempts","retries","redraws","path_polls","path_status"})

    def test_both_grants_use_private_canonical_paths_and_the_lower_expiry(self):
        worker = runpy.run_path(str(HERE / "signal-mailbox-native.py"))
        from unittest.mock import patch
        grants=[]
        def cli(_, __, args):
            side = Path(args[args.index("--identity")+1]).parent.name
            key = {"a":"a"*64,"b":"b"*64}[side]
            if args[1]=="recipient-key":
                return {"identity_public_key_hex":key}
            path = Path(args[args.index("--invitation")+1])
            if args[2]=="invite":
                path.write_bytes(side.encode())
                return {"owner_key_hex":key,"registered_providers":0,"expires_unix_seconds":{"a":100,"b":105}[side]}
            grants.append(side);return {"registered_providers":2}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(worker["prepare"].__globals__, invoke=cli), patch("subprocess.run"):
            root=Path(tmp)/"providers"
            worker["prepare"](root,"/fake-cli","/fake-agent",["c"*64,"d"*64])
            self.assertEqual(grants,["a","b"])
            self.assertTrue((root/"ready").is_file())
            a,b=[json.loads((root/s/"grants.json").read_bytes()) for s in grants]
            self.assertEqual(a["sendGrant"],b["receiveGrant"])
            self.assertEqual(a["expires"],99000)
            self.assertEqual(b["expires"],99000)
            cfg=json.loads((root/"a/core.json").read_bytes())
            self.assertEqual((cfg["socket"],cfg["sendInvitation"]),("/trial/core/agent.sock","/tmp/r/providers/b/invitation"))

if __name__=="__main__":
    unittest.main()
