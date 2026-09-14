#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic parser/gate tests only; real signed network custody requires the VM run."""

import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-custody-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))


def number(value):
    result = bytearray()
    while value >= 128:
        result.append(value & 127 | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def wire(values):
    return b"".join(number(key << 3 | (2 if isinstance(value, bytes) else 0))
                    + (number(len(value)) + value if isinstance(value, bytes) else number(value))
                    for key, value in sorted(values.items()))


def signed_shape(key, operation, state, nonce, explicit_default=False):
    values = {1: bytes([nonce]) * 32, 2: bytes([nonce + 20]) * 32, 3: bytes.fromhex(key),
              4: bytes.fromhex("11" * 32), 7: bytes.fromhex("44" * 32),
              8: bytes.fromhex(CHECK["SHA"]), 9: CHECK["BYTES"], 10: CHECK["UNIQUE_CHUNKS"], 11: 3000}
    if operation != 1 or explicit_default:
        values[5] = operation
    if state != 1:
        values[6] = state
    payload = wire(values)
    body = wire({1: 1, 2: bytes.fromhex(key), 3: 1000, 4: 1800, 5: b"n" * 32,
                 6: 3, 7: hashlib.sha256(payload).digest(), 8: payload})
    # Intentionally not a valid signature: the checker checks binding, not crypto.
    return wire({1: body, 2: b"s" * 64}).hex()


def peer(key):
    value, output = int.from_bytes(bytes.fromhex("002408011220" + key), "big"), ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while value:
        value, digit = divmod(value, 58)
        output = alphabet[digit] + output
    return "1" + output


def fixture():
    base = BASE["fixture"]()
    peers, keys = base["expected_peers"], dict(relay4="22" * 32, relay5="33" * 32)
    peers.update({node: peer(key) for node, key in keys.items()})
    phases = {name: copy.deepcopy(base["cases"]["complete"]) for name in ("deposit", "inspect", "fetch")}
    for name, phase in phases.items():
        phase["control_privacy"] = phase.pop("control")
        phase["gates"] = dict(event_baseline_unix_ms=1000, exit_mptcp_tls_completed=dict(deposit=4, inspect=2, fetch=1)[name])
    context = phases["deposit"]["selected_route"]["route_context_id"]
    data = dict(success=True, expected_peers=peers,
        input=dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], chunks=9, unique_chunks=5,
                   unique_bytes=CHECK["UNIQUE_BYTES"], explicit_public_fixture=True),
        publish=dict(operation="offline_content_publish", network_publication=False,
                     bytes=CHECK["BYTES"], chunks=9, publisher_key_hex="11" * 32, expires_unix_seconds=3000),
        layout=dict(provider_nodes=list(keys), provider_keys=keys, control_relay_peer_id=peers["relay2"],
                    route_context_id=context, manifest_id="44" * 32),
        providers={node: dict(public=dict(identity_public_key_hex=key),
            empty=dict(serving=True, replication_enabled=True, publications=0, replica_publications=0),
            restored=dict(serving=True, replication_enabled=True, publications=1, replica_publications=1),
            restart=dict(node=node, pid_before=100, pid_after=101, cache_before="1:2", cache_after="1:2",
                         namespace_identity="3:4", executable_verified=True, automatic_reopen=True),
            stop=dict(serving=False)) for node, key in keys.items()},
        source_removed=dict(source_cache_removed=True, source_input_removed=True,
                            publisher_identity_retained=True, original_manifest_retained=True),
        output=dict(path="/fixture/output.bin", bytes=CHECK["BYTES"], sha256=CHECK["SHA"], output_mode="0600",
                    source_cache_removed=True, source_input_removed=True),
        fetch=dict(operation="named_content_download", name="disposable-public-custody", revision=1,
            publisher_key="11" * 32, manifest_id="44" * 32, publication_expires_unix_seconds=3000,
            bytes=CHECK["BYTES"], sha256=CHECK["SHA"], chunks=9, providers_used=2,
            provider_peer_ids=[peers[node] for node in keys], peer_bytes=CHECK["BYTES"],
            control_relay_peer_id=peers["relay2"], origin_authenticated=False, globally_latest=False,
            local_delivery=True, ownership_changed=False, output_mode="0600", local_output="/fixture/output.bin",
            cache="/fixture/fresh-cache"),
        isolation=dict(user_uid=985, agent_uid=986, control_gid=987, agent_gid=986,
            cache_mode="0700", output_mode="0600", agent_mount_positive_control=True,
            agent_cannot_read_user_state=True, client_cannot_read_provider_stores=True,
            user_cannot_read_agent_cache=True, fresh_consumer_cache=True),
        private_cleanup=dict(identity_removed=True, passphrase_removed=True, source_removed=True,
                             output_removed=True, user_directory_removed=True), phases=phases)
    for index, (name, operation, state) in enumerate((("missing", 2, 1), ("deposit", 1, 2), ("inspect", 2, 2))):
        data[name] = dict(operation="content_custody_deposit" if operation == 1 else "content_custody_inspect",
            manifest_id="44" * 32, publisher_key_hex="11" * 32, object_bytes=CHECK["BYTES"],
            original_expiry_unix_seconds=3000, requested_providers=2, failed_providers=0,
            confirmed_complete_providers=2 if state == 2 else 0, complete=state == 2,
            private_keys_transferred=False, direct_provider_dial=False, origin_authenticated=False,
            future_availability_guaranteed=False,
            observations=[dict(provider_key_hex=key, agent_handoff_complete=True, error=None,
                state="complete" if state == 2 else "missing", signed_receipt_hex=signed_shape(key, operation, state, index * 2 + j + 1),
                original_expiry_unix_seconds=3000, object_bytes=CHECK["BYTES"], unique_chunks=5)
                for j, key in enumerate(keys.values())])
    return data


class CustodyEvidence(unittest.TestCase):
    def test_bound_receipts_restarts_reassembly_and_captures_are_required(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        mutations = (
            lambda value: value["providers"]["relay4"]["restart"].update(pid_after=100),
            lambda value: value["providers"]["relay5"]["restart"].update(cache_after="1:3"),
            lambda value: value["source_removed"].update(source_cache_removed=False),
            lambda value: value["inspect"]["observations"][0].update(original_expiry_unix_seconds=3001),
            lambda value: value["deposit"]["observations"][0].update(agent_handoff_complete=False),
            lambda value: value["fetch"].update(sha256="00" * 32),
            lambda value: value["phases"]["fetch"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda value: value["phases"]["deposit"]["privacy"]["exit"].update(packet_socket_drops=1),
            lambda value: value["private_cleanup"].update(identity_removed=False),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                invalid = copy.deepcopy(valid)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    CHECK["validate_evidence"](invalid)

    def test_receipt_canonical_shape_and_original_expiry(self):
        args = ("22" * 32, "11" * 32, "44" * 32, 3000, 1, 2)
        valid = signed_shape("22" * 32, 1, 2, 1)
        CHECK["receipt"](valid, *args)
        for encoded in (valid + "1001", signed_shape("22" * 32, 1, 2, 1, True), "808000"):
            with self.assertRaises(ValueError):
                CHECK["receipt"](encoded, *args)
        with self.assertRaises(ValueError):
            CHECK["receipt"](valid, *args[:3], 3001, *args[4:])
        with self.assertRaises(ValueError):
            CHECK["receipt"](valid, *args[:5], 1)

    def test_exact_owned_source_cleanup_reassembly_and_idempotence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "custody-user"
            root.mkdir(mode=0o700)
            CHECK["initialize"](str(root))
            for name in ("identity.key", "manifest.bin"):
                CHECK["create_private"](root / name, b"fixture")
            cache = root / "source-cache"
            cache.mkdir(mode=0o700)
            for name in (".volparossa-owner-v1", ".volparossa-index-v1", "aa" * 32):
                CHECK["create_private"](cache / name, b"fixture")
            removed = CHECK["remove_source"](root)
            self.assertTrue(all(removed.values()))
            CHECK["create_private"](root / "output.bin", CHECK["FIXTURE"])
            self.assertEqual(CHECK["output"](str(root))["sha256"], CHECK["SHA"])
            self.assertEqual(CHECK["cleanup"](str(root)), CHECK["cleanup"](str(root)))
            self.assertFalse(root.exists())

    def test_cleanup_refuses_external_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "custody-user"
            root.mkdir(mode=0o700)
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"must survive")
            (root / "input.bin").symlink_to(outside)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertEqual(outside.read_bytes(), b"must survive")


if __name__ == "__main__":
    unittest.main()
