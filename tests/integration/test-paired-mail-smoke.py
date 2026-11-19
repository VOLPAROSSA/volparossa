#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Test the paired-Mail guest boundary and reject incomplete external runtime catalogs."""
import ast
import io
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SMOKE = runpy.run_path(str(HERE/"paired-mail-smoke.py"))
SANDBOX = runpy.run_path(str(HERE/"paired-mail-sandbox.py"))
SUPPLY = runpy.run_path(str(HERE/"paired-mail-bundle.py"))


class PairedMailTests(unittest.TestCase):
    def test_closed_exports_and_both_supported_preview_entry_points(self):
        script = (HERE/"run-alpha-topology-vm.sh").read_text()
        body = script[script.index("PAIRED_MAIL_NAMES ="):script.index("SIGNAL_MAILBOX_NAMES =")]
        env = {}
        exec(compile(ast.parse(body), "paired-mail-diagnostic-names", "exec"), env)
        self.assertEqual(env["PAIRED_MAIL_NAMES"], SMOKE["NAMES"] | {"current-phase","guest-exit-status",
                         "host-state-before.json","host-state-after.json","paired-mail-supply.json"})
        self.assertTrue(all("/" not in name and name.endswith(".json") for name in SMOKE["NAMES"]))
        for name in ("run-alpha-topology-vm.sh","kvm-alpha-topology.sh"):
            out = subprocess.check_output(["sh", HERE/name, "--preview","--scenario","paired-mail"],text=True)
            self.assertIn("Stalwart", out)

    def test_early_and_normal_console_collection_exclude_private_native_scenarios(self):
        script = (HERE/"run-alpha-topology-vm.sh").read_text()
        function = script[script.index("copy_vm_console() {"):script.index("\ncleanup() {")]
        self.assertIn('copy_vm_console "$RUN_DIRECTORY/console.log"', script)
        self.assertIn('copy_vm_console "$CONSOLE"', script)
        self.assertNotIn("vm-console.log", script.replace(function, ""))
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            console = out/"console"
            console.write_bytes(b"private-serial-sentinel")
            for scenario in ("signal-backup","signal-backup-fragments","signal-mailbox","paired-mail","content-mailbox"):
                subprocess.run(["sh","-eu","-c",function+'\nscenario=$1; output_directory=$2; decoder_mode=historical-v1; copy_vm_console "$3"',
                                "sh",scenario,out,console],check=True)
                copy = out/"vm-console.log"
                if scenario == "content-mailbox":
                    self.assertEqual(copy.read_bytes(), console.read_bytes())
                else:
                    self.assertFalse(copy.exists())

    def test_receiver_cannot_mount_the_sender_or_the_provider_stores(self):
        bundle, private, cli, control = map(Path, ("/fixture/runtime","/worker","/immutable/cli","/run/control.sock"))
        for stage in ("send","receive"):
            args = list(map(str, SANDBOX["command"](bundle,private,stage,cli,control)))
            self.assertIn("--unshare-all", args)
            self.assertNotIn("--share-net", args)
            self.assertEqual(args[-1], stage)
            binds = {(args[i+1],args[i+2]):args[i] for i,a in enumerate(args) if a in ("--bind","--ro-bind")}
            self.assertIn(("/worker/providers/b","/tmp/r/providers/b"), binds)
            self.assertEqual(("/worker/providers/a","/tmp/r/providers/a") in binds, stage == "send")
            self.assertEqual(binds[("/run/control.sock","/trial/core/agent.sock")], "--ro-bind")
            self.assertEqual(binds[("/immutable/cli","/trial/core/volparossa")], "--ro-bind")
            self.assertNotIn("/worker/providers", {source for source,_ in binds})

    def test_runtime_cannot_extract_a_link_or_parent_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name,kind in (("../escape",tarfile.REGTYPE),("bin/node",tarfile.SYMTYPE)):
                file = root/"test.tar.gz"
                with tarfile.open(file,"w:gz") as archive:
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    archive.addfile(info,io.BytesIO())
                with self.assertRaisesRegex(ValueError,"invalid runtime entry"):
                    SUPPLY["inspect_runtime"](file,root/"runtime")
            self.assertFalse((root/"escape").exists())

    def test_mail_sources_include_the_actual_jmap_importer_and_sealer(self):
        sources = SUPPLY["PINS"]["source_files"]
        self.assertTrue({"integration/peer-mail/accept.py","integration/peer-mail/import-mime.mjs",
                         "extensions/volparossa-mail-host/jmap.mjs","integration/signal-mail/deposit.py",
                         "packaging/systemd/initialize-owner.py"}.issubset(sources))
        for sha in sources.values():
            self.assertRegex(sha,r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
