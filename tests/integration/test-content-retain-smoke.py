#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert parser/lifecycle regressions; no claim of real remote availability."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-retain-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))
wire = BASE["wire"]


def signed(key, kind, payload):
    return wire({1: wire({1: 1, 2: bytes.fromhex(key), 3: 1000, 4: 1800,
        5: b"n" * 32, 6: kind, 7: hashlib.sha256(payload).digest(), 8: payload}), 2: b"s" * 64})


def exchange(operation, provider="22" * 32, original=b"public original fixture manifest", nonce=99):
    publisher = "11" * 32
    challenge = signed(provider, 1, wire({1: bytes([nonce]) * 32}))
    request = {1: hashlib.sha256(challenge).digest(), 2: bytes.fromhex(provider), 4: original}
    if operation == 2:
        request[3] = operation
    authorization = signed(publisher, 2, wire(request))
    payload = {1: hashlib.sha256(authorization).digest(), 2: hashlib.sha256(challenge).digest(),
        3: bytes.fromhex(provider), 4: bytes.fromhex(publisher), 6: 2,
        7: hashlib.sha256(original).digest(), 8: bytes.fromhex(CHECK["C"]["SHA"]),
        9: CHECK["C"]["BYTES"], 10: CHECK["C"]["UNIQUE_CHUNKS"], 11: 3000}
    if operation == 2:
        payload[5] = operation
    receipt = signed(provider, 3, wire(payload))
    record = dict(operation="deposit" if operation == 1 else "inspect", checked_at=1001,
        original=dict(verified_at=1001, handoff_complete=True,
                      challenge_hex=challenge.hex(), authorization_hex=authorization.hex(), receipt_hex=receipt.hex()))
    return record, provider, publisher, original, 3000


def fixture():
    data = BASE["fixture"]()
    keys = dict(relay3="55" * 32, relay4="22" * 32, relay5="33" * 32)
    data["expected_peers"]["relay3"] = BASE["peer"](keys["relay3"])
    data["layout"].update(provider_nodes=list(keys), provider_keys=keys)
    content = b"synthetic public manifest payload"
    original = wire({1: wire({1: 1, 2: bytes.fromhex("11" * 32), 3: 900, 4: 3000,
        5: b"n" * 32, 6: 1, 7: hashlib.sha256(content).digest(), 8: content}), 2: b"s" * 64})
    digest = hashlib.sha256(original).hexdigest()
    data["publish"]["manifest_id"] = data["layout"]["manifest_id"] = digest
    enrollment = dict(copies=2, max_seconds=1600, max_upload_bytes=CHECK["C"]["BYTES"] * 4,
                      discovery_batch=16)
    enrollment_bytes = json.dumps(enrollment).encode()

    def snapshot(which):
        initial = which == 1
        holders = [keys["relay4"], keys["relay5"]] if initial else [keys["relay5"], keys["relay3"]]
        observations = {}
        for i, key in enumerate(holders):
            record = exchange(1, key, original, which * 10 + i)[0]
            record.update(sequence=which * 2 + i, outcome="complete")
            observations[key] = record
        if not initial:
            observations[keys["relay4"]] = dict(sequence=5, outcome="unavailable", original=None,
                                                operation="inspect", checked_at=1001)
        state = dict(version=1, enrollment_sha256=hashlib.sha256(enrollment_bytes).hexdigest(),
            started_at=1000, deadline=2600, uploads_reserved_bytes=CHECK["C"]["BYTES"] * (2 if initial else 3),
            confirmed_holders=holders, completed_polls=which, pending=None, last_observed=1001,
            attempt_sequence=10 * which, observations=observations,
            last_outcome="stopped" if which == 3 else "maintained")
        state_bytes = json.dumps(state).encode()
        status = dict(state_sha256=hashlib.sha256(state_bytes).hexdigest(), manifest_id=digest,
            original_expiry_unix_seconds=3000, confirmed_holders=holders,
            future_availability_guaranteed=False, maintenance_while_owner_offline=False)
        raw = {"enrollment.json": enrollment_bytes, "original.manifest": original,
               "state.json": state_bytes, "status.json": json.dumps(status).encode()}
        return dict(state=state, status=status, enrollment=enrollment,
            raw={name: dict(hex=value.hex(), sha256=hashlib.sha256(value).hexdigest()) for name, value in raw.items()})

    data.update(automatic_provider_selection=True, initial=snapshot(1), replacement=snapshot(2), final_state=snapshot(3),
        stopped=dict(operation="content_retain", last_outcome="stopped", maintenance_while_owner_offline=False),
        withdrawal=dict(provider_key=keys["relay4"], withdrawn_unix_seconds=1001, receipt=dict(serving=False)),
        process=dict(pid=123, start_ticks=500, exit_status=0, term_sent=True, reaped=True, forced_kill=False,
                     started_unix_ms=1000000, ended_unix_ms=1001000, executable_verified=True, provider_keys_supplied=False),
        fetch_started_unix_ms=1002000)
    data["providers"]["relay3"] = copy.deepcopy(data["providers"]["relay4"])
    data["fetch"].update(manifest_id=digest, peer_bytes=CHECK["C"]["UNIQUE_BYTES"],
        provider_peer_ids=[data["expected_peers"][n] for n in ("relay3", "relay5")])
    data["phases"]["initial"] = data["phases"].pop("deposit")
    data["phases"]["replacement"] = data["phases"].pop("inspect")
    addresses = CHECK["C"]["SHARED"]["PUBLIC_IPS"]
    control = "relay2"
    for phase in data["phases"].values():
        phase["privacy"]["exit"]["provider_application"]["relay3"] = copy.deepcopy(
            phase["privacy"]["exit"]["provider_application"]["relay4"])
        capture = phase["control_privacy"]
        stats = next(iter(capture["interface_statistics"].values()))
        capture.update(interfaces=["ac0", "ac1", "ac2"],
            content_control_pairs={f"ac{i}": [addresses[control], addresses[n]] for i, n in enumerate(keys)},
            content_control_packets={f"ac{i}": dict(inbound=5, outbound=5) for i in range(3)},
            interface_statistics={f"ac{i}": copy.deepcopy(stats) for i in range(3)},
            observed_frames=stats["observed_frames"] * 3)
    data["control_routes"] = {node: {"out": [dict(dev=f"ac{i}", gateway=f"10.241.{83+i}.2",
        prefsrc=addresses[control], dst=addresses[node])], "back": [dict(dev=f"ap{i}",
        gateway=f"10.241.{83+i}.1", prefsrc=addresses[node], dst=addresses[control])]}
        for i, node in enumerate(keys)}
    data["early_control_filter"] = dict(nftables=[dict(rule=dict(chain=chain,
        table="vpa_content_adaptive_client_control", family="inet", expr=[
            dict(match=dict(op="==", left=dict(meta=dict(key=field)), right=dict(set=["cr3", "cr4", "cr5"]))),
            dict(match=dict(op="==", left=dict(payload=dict(protocol="udp", field=port)), right=41000)),
            dict(counter=dict(packets=0, bytes=0)), {"drop": None}]))
        for chain, field in (("input", "iifname"), ("output", "oifname")) for port in ("sport", "dport")])
    return data


class AutomaticCustody(unittest.TestCase):
    def test_early_failed_owner_reaped_and_private_cleanup_still_attempted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "bin/content-custody-smoke.py").write_text("# inert marker\n")
            script = '''
. "$1"
WORK=$2
CUSTODY_AUTOMATIC=yes
optional_json_evidence() { printf 'null\\n'; }
content_custody_retain_private() { printf '{"user_directory_removed":true}\\n'; }
sh -c 'exit 7' &
CUSTODY_OWNER_PID=$!
sleep 0.1
code=0
content_custody_cleanup || code=$?
[ "$code" = 1 ] && [ -z "$CUSTODY_OWNER_PID" ] || exit 1
jq -e '.exit_status == 7 and .term_sent == false and .reaped == true' "$WORK/content-custody-process.json"
jq -e '.user_directory_removed == true' "$WORK/content-custody-private-cleanup.json"
'''
            result = subprocess.run(["sh", "-c", script, "sh", str(HERE / "content-custody-smoke.sh"), str(root)],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_automatic_chain_and_narrow_mutations(self):
        function = CHECK["validate_evidence"]
        # Parser fixture signatures are deliberately fake; real evidence always uses OpenSSL.
        with patch.dict(function.__globals__, verify_signature=lambda *_: None):
            data = fixture()
            function(data)
            mutations = (
                lambda value: value["process"].update(reaped=False),
                lambda value: value["process"].update(provider_keys_supplied=True),
                lambda value: value["process"].update(exit_status=1),
                lambda value: value["source_removed"].update(source_cache_removed=False),
                lambda value: value["fetch"].update(peer_bytes=1),
                lambda value: value["withdrawal"].update(provider_key="33" * 32),
                lambda value: value["final_state"]["enrollment"].update(copies=1),
                lambda value: value["phases"]["replacement"]["privacy"]["client"].update(direct_client_exit_packets=1),
                lambda value: value["control_routes"]["relay3"]["out"][0].update(dev="cr3"),
            )
            for mutation in mutations:
                changed = copy.deepcopy(data)
                mutation(changed)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    function(changed)

    def test_canonical_deposit_omits_default_and_inspect_encodes_two(self):
        function = CHECK["exchange"]
        with patch.dict(function.__globals__, verify_signature=lambda *_: None):
            for operation in (1, 2):
                args = exchange(operation)
                request, challenge = function(*args)
                self.assertEqual(request, hashlib.sha256(bytes.fromhex(args[0]["original"]["authorization_hex"])).hexdigest())
                self.assertEqual(challenge, hashlib.sha256(bytes.fromhex(args[0]["original"]["challenge_hex"])).hexdigest())

    def test_substituted_original_or_provider_and_expired_exchange_rejected(self):
        function = CHECK["exchange"]
        with patch.dict(function.__globals__, verify_signature=lambda *_: None):
            for change in ("provider", "original", "handoff", "time"):
                args = list(copy.deepcopy(exchange(1)))
                if change == "provider":
                    args[1] = "33" * 32
                elif change == "original":
                    args[3] += b"changed"
                elif change == "handoff":
                    args[0]["original"]["handoff_complete"] = False
                else:
                    args[0]["original"]["verified_at"] = 2000
                    args[0]["checked_at"] = 2000
                with self.subTest(change=change), self.assertRaises(ValueError):
                    function(*args)

    def test_invalid_real_signature_is_not_accepted(self):
        with self.assertRaises(ValueError):
            CHECK["verify_signature"](b"public test", b"s" * 64, b"p" * 32, CHECK["DOMAIN"])

    def test_automatic_cleanup_keeps_unrecognized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "custody-user"
            root.mkdir(mode=0o700)
            owner = root / "retain-owner"
            owner.mkdir(mode=0o700)
            CHECK["C"]["create_private"](owner / "unexpected", b"must remain")
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root)
            self.assertEqual((owner / "unexpected").read_bytes(), b"must remain")

    def test_owned_snapshot_and_owner_cleanup_are_bounded_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "custody-user"
            root.mkdir(mode=0o700)
            owner = root / "retain-owner"
            owner.mkdir(mode=0o700)
            for name in CHECK["FILES"]:
                CHECK["C"]["create_private"](owner / name, b"public fixture")
            CHECK["C"]["create_private"](root / "initial-observation.json", b"public fixture")
            self.assertTrue(CHECK["cleanup"](root)["user_directory_removed"])
            self.assertTrue(CHECK["cleanup"](root)["user_directory_removed"])


if __name__ == "__main__":
    unittest.main()
