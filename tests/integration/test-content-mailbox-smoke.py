#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic gate tests only; real mailbox signatures and transport require the KVM run."""

import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-mailbox-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))


def number(value):
    result = bytearray()
    while value >= 128:
        result.append(value & 127 | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def wire(fields):
    return b"".join(number(key << 3 | (2 if isinstance(value, bytes) else 0))
                    + (number(len(value)) + value if isinstance(value, bytes) else number(value))
                    for key, value in sorted(fields.items()))


def receipt(key, op, message=None, length=0):
    fields = {1: bytes([op]) * 31 + bytes.fromhex(key)[:1], 2: b"g" * 32, 3: op, 6: 2000}
    if message:
        fields[5] = bytes.fromhex(message)
    if length:
        fields[8] = length
    if op == 5:
        fields[7] = 1
    payload = wire(fields)
    body = wire({1: 1, 2: bytes.fromhex(key), 3: 1000, 4: 1120, 5: b"n" * 32,
                 6: 4, 7: hashlib.sha256(payload).digest(), 8: payload})
    return wire({1: body, 2: b"s" * 64}).hex()


def peer(key):
    data = bytes.fromhex("002408011220" + key)
    value, output = int.from_bytes(data, "big"), ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while value:
        value, digit = divmod(value, 58)
        output = alphabet[digit] + output
    return "1" + output


def fixture():
    base = BASE["fixture"]()
    keys = dict(relay4="22" * 32, relay5="33" * 32)
    message, ciphertext = "44" * 32, CHECK["BYTES"] + 57
    peers = base["expected_peers"]
    peers.update({node: peer(key) for node, key in keys.items()})
    phases = {}
    for index, name in enumerate(("send", "receive")):
        phase = copy.deepcopy(base["cases"]["complete"])
        phase["selected_route"]["route_context_id"] = "ab"[index] * 32
        for path in phase["selected_route"]["paths"]:
            path["route_context_id"] = "ab"[index] * 32
        phase["privacy"]["exit"]["provider_application"]["relay4"]["response_payload_bytes"] = ciphertext + 1000
        phase["control_relay_peer_id"] = peers["relay2"]
        phase["gates"] = dict(event_baseline_unix_ms=1000, exit_mptcp_tls_completed=(4, 7)[index],
                               exact_provider_lookups=(4, 7)[index])
        phases[name] = phase
    receive = dict(operation="mailbox_receive", messages_discovered=1, messages_delivered=1,
                   sender_manifest_supplied=False, directory_mode="0700", output_mode="0600",
                   acknowledged_providers_per_message=2, listed_providers=2, degraded=False,
                   acknowledgement_receipts=[dict(message_id=message,
                       receipts=[receipt(k, 5, message) for k in keys.values()])])
    empty = dict(receive, messages_discovered=0, messages_delivered=0, acknowledgement_receipts=[])
    return dict(provider_nodes=list(keys), provider_keys=keys, expected_peers=peers,
        providers={n: dict(node=n, pid=800 + i, cache_inode=123, cache_mode="700",
                           serve=dict(serving=True, replication_enabled=False)) for i, n in enumerate(keys)},
        identities=dict(owner="11" * 32, sender="55" * 32),
        invite=dict(operation="mailbox_invite", owner_key_hex="11" * 32, private_key_exported=False,
                    registered_providers=0, mailbox_id="66" * 32),
        enroll=dict(operation="mailbox_enroll", registered_providers=2, mailbox_id="66" * 32,
                    message_capacity_reserved=False, storage_receipts=[receipt(k, 1) for k in keys.values()]),
        send=dict(operation="mailbox_send", confirmed_providers=2, retained_providers=2,
                  already_acknowledged_providers=0, plaintext_uploaded=False,
                  message_id=message, ciphertext_bytes=ciphertext,
                  storage_receipts=[receipt(k, 2, message, ciphertext) for k in keys.values()]),
        receive=receive, receive_empty=empty,
        output=dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], opaque_filename=message,
                    file_mode="0600", directory_mode="0700", empty_directory_entries=0,
                    sender_application_exited=True, sender_keys_and_input_removed_before_receive=True,
                    sender_manifest_removed_before_receive=True, no_manifest_or_message_id_argument=True,
                    agent_mount_positive_control=True, agent_cannot_read_user_state=True,
                    client_cannot_read_provider_stores=True),
        restart=dict(provider_node="relay5", stop=dict(serving=False), reopen=dict(serving=True),
                     listener_absent_between=True, cache_inode_before=123, cache_inode_after=123,
                     cache_mode="0700", reuse_cache=True), phases=phases,
        sender_route_disconnected=True, receiver_route_disconnected=True,
        provider_stop={n: dict(serving=False) for n in keys},
        private_cleanup=dict(sender_secrets_removed=True, owner_secrets_removed=True, plaintext_outputs_removed=True))


class MailboxEvidence(unittest.TestCase):
    def test_exact_receipts_restart_privacy_and_cleanup_are_required(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        mutations = (
            lambda v: v["send"].update(retained_providers=1),
            lambda v: v["send"].update(already_acknowledged_providers=1),
            lambda v: v["receive"].update(sender_manifest_supplied=True),
            lambda v: v["receive"]["acknowledgement_receipts"][0]["receipts"].pop(),
            lambda v: v["receive_empty"].update(messages_delivered=1),
            lambda v: v["restart"].update(cache_inode_after=124),
            lambda v: v["provider_keys"].update(relay4="ff" * 32),
            lambda v: v["phases"]["receive"]["privacy"]["exit"].update(outbound_client_discovery_attempt_packets=1),
            lambda v: v["phases"]["send"]["privacy"]["client"]["interface_statistics"]["physical"].update(packet_socket_drops=1),
            lambda v: v["private_cleanup"].update(owner_secrets_removed=False),
        )
        for mutate in mutations:
            value = copy.deepcopy(valid)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                CHECK["validate_evidence"](value)

    def test_plaintext_is_exact_private_and_opaque(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            received, empty = root / "received", root / "empty"
            received.mkdir(mode=0o700)
            empty.mkdir(mode=0o700)
            target = received / ("44" * 32)
            CHECK["input_file"](target)
            output = CHECK["output_file"](received, empty)
            self.assertEqual(output["sha256"], CHECK["SHA"])
            target.chmod(0o644)
            with self.assertRaises(ValueError):
                CHECK["output_file"](received, empty)


if __name__ == "__main__":
    unittest.main()
