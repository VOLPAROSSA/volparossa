#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Checker/cleanup tests plus opt-in real CLI compatibility; no live network proof here."""

import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import secrets
import subprocess
import tempfile
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))


def fixture():
    publication = dict(publisher_removed=True, publisher_private_key_persisted=False,
                       publisher_hex="1" * 64, object_sha256="2" * 64,
                       bytes=2097275, chunks=9, replica_a_chunks=5, replica_b_chunks=4)
    phases = []
    for index, replica in enumerate("ab"):
        pid = 100 + index
        count, size = ((5, 1048699), (4, 1048576))[index]
        paths = [dict(route_context_id=str(index + 1) * 32, path_id=slot + 1,
                      relay_peer_id=f"peer{slot}", exit_peer_id="exit-peer") for slot in range(2)]
        slots = [dict(relay_peer_id=f"peer{slot}", relay_node=f"relay{slot}") for slot in range(2)]
        privacy = {role: dict(capture_role=role, truncated=False, packet_socket_drops=0,
                             observed_frames=100, expected_link_down_notifications=0,
                             unexpected_outer_packets=0, direct_client_exit_packets=0,
                             internet_destination_outer_packets=0, client_public_packets=0,
                             outbound_client_discovery_attempt_packets=0,
                             client_leg_wireguard_data_datagrams=100,
                             exit_leg_wireguard_data_datagrams=100)
                   for role in CHECK["ROLES"]}
        captures = {role: dict(capture_role=role, truncated=False, observed_frames=100,
                              benchmark_relay_nodes=["relay0", "relay1"],
                              relay1_wireguard_data_datagrams=100, relay2_wireguard_data_datagrams=100,
                              direct_client_exit_packets=0, destination_request_segments=50,
                              destination_response_segments=100) for role in ("client", "exit")}
        phases.append({
            "provider": dict(replica=replica, pid=pid, listen=CHECK["DESTINATION"],
                             source=dict(ip="47.163.4.1", port=32100 + index),
                             chunks_sent=count, bytes_sent=size, missing=(4, 0)[index]),
            "consumer": dict(pid=200 + index, chunks_received=count, bytes_received=size,
                             missing=(4, 0)[index], cached_chunks=(5, 9)[index], complete=bool(index),
                             output_bytes=(0, 2097275)[index],
                             object_sha256=(None, publication["object_sha256"])[index]),
            "selected_route": dict(transport="mptcp", route_context_id=str(index + 1) * 32,
                                   paths=paths, benchmark_slots=slots),
            "protected_gates": dict(serving_pid=pid, publisher_process_exited_before_fetch=True,
                                    event_baseline_unix_ms=1000, ingress_completed=True,
                                    exit_mptcp_tls_open_completed=True),
            "privacy": privacy,
            "application_captures": captures,
        })
    return dict(
        success=True, publication=publication, phases=phases,
        reconstructed_object=dict(bytes=2097275, sha256=publication["object_sha256"],
                                  client_cache_initially_absent=True,
                                  client_cannot_read_replica_stores=True,
                                  publisher_process_exited_before_fetch=True))


def private_fixture():
    value = fixture()
    # Synthetic envelope overhead, not a cryptographic or live network proof.
    value["publication"]["bytes"] += 80
    value["publication"]["recipient_encrypted"] = True
    value["reconstructed_object"]["bytes"] += 80
    value["phases"][0]["provider"]["bytes_sent"] += 80
    value["phases"][0]["consumer"]["bytes_received"] += 80
    value["phases"][1]["consumer"]["output_bytes"] += 80
    value["private_message"] = dict(
        recipient=dict(recipient_public_key_hex="3" * 64, identity_public_key_hex="4" * 64,
                       operation="message_recipient_key", profile="volparossa/message-recipient/v1",
                       private_key_exported=False, network_publication=False),
        recipient_isolation=dict(recipient_uid=1001, provider_uid=1002,
                                 private_directory_mode="0700", encrypted_identity_mode="0600",
                                 passphrase_mode="0600", identity_created_by_normal_cli=True,
                                 identity_storage="encrypted_identity_store",
                                 raw_recipient_private_key_file=False,
                                 key_owned_by_recipient=True, key_unreadable_by_provider=True,
                                 passphrase_unreadable_by_provider=True),
        decryption=dict(plaintext_bytes=2097275, plaintext_sha256=CHECK["FIXTURE_PLAINTEXT_SHA256"],
                        wrong_recipient_rejected=True, wrong_recipient_output_absent=True,
                        no_clobber_verified=True, encrypted_identities_unchanged=True, normal_cli_open=True),
        cli_result=dict(operation="offline_private_message_open", network_retrieval=False, bytes=2097275),
        plaintext_output=dict(plaintext_bytes=2097275, plaintext_sha256=CHECK["FIXTURE_PLAINTEXT_SHA256"],
                              private_output_mode="0600", private_output_owned_by_recipient=True),
        temporary_cleanup=dict(encrypted_identities_removed=True, passphrase_removed=True,
                               plaintext_removed=True, private_directory_removed=True))
    imported = dict(operation="content_import", manifest_id="a" * 64, ciphertext_bytes=2097332,
                    chunks=9, cache="/user/source", agent_cache="/agent/cache", complete=True,
                    network_transfer=False, ownership_changed=False,
                    recipient_decryption_performed=False, private_keys_transferred=False,
                    ciphertext_format_verified=True)
    exported = {**imported, "operation": "content_export", "cache": "/user/new-cache"}
    value["private_message"]["local_handoff"] = dict(
        isolation=dict(user_uid=1001, agent_uid=1002, control_gid=1003, agent_gid=1002,
                       agent_cannot_read_user_cache_or_secrets=True, user_cannot_read_agent_cache=True,
                       all_cache_modes="0700", private_output_mode="0600", identities_unchanged=True,
                       plaintext_sha256=CHECK["FIXTURE_PLAINTEXT_SHA256"], local_only=True),
        publication=dict(operation="offline_private_message_publish", network_publication=False,
                         ciphertext_bytes=2097332, chunks=9, publisher_key_hex="b" * 64),
        **{"import": imported, "export": exported,
           "open": dict(operation="offline_private_message_open", bytes=2097275, network_retrieval=False)},
        status_before=dict(serving=False, publications=0), status_after=dict(serving=False, publications=0))
    public_import = {key: item for key, item in imported.items() if key != "ciphertext_bytes"}
    public_import.update(content_bytes=2097275, public_content=True, ciphertext_format_verified=False,
                         origin_authenticated=False)
    value["private_message"]["local_public_handoff"] = dict(
        isolation=dict(user_uid=1001, agent_uid=1002, control_gid=1003, agent_gid=1002,
                       agent_cannot_read_user_cache=True, user_cannot_read_agent_cache=True,
                       all_cache_modes="0700", output_mode="0600", identity_unchanged=True,
                       default_public_import_rejected=True, default_destination_absent=True,
                       sha256=CHECK["FIXTURE_PLAINTEXT_SHA256"], local_only=True, explicit_public_fixture=True),
        publication=dict(operation="offline_content_publish", network_publication=False,
                         bytes=2097275, chunks=9, publisher_key_hex="b" * 64),
        **{"import": public_import,
           "export": {**public_import, "operation": "content_export", "cache": "/user/new-public"},
           "assemble": dict(operation="offline_content_assemble", bytes=2097275,
                            publisher_key_hex="b" * 64, network_retrieval=False)},
        status_after=dict(serving=False, publications=0))
    value["private_message"]["network_publication"] = network_publication_fixture()
    return value


def network_publication_fixture():
    # Reuse synthetic path facts only; this is not a live network acceptance result.
    base = runpy.run_path(str(Path(__file__).with_name("test-content-provider-smoke.py")))["fixture"]()
    ordinary = base["ordinary_publication"]
    size = CHECK["OBJECT_BYTES"] + 57
    imported = dict(operation="content_import", manifest_id="e" * 64, complete=True,
                    ciphertext_bytes=size, chunks=9, cache="/user/source", agent_cache="/agent/relay4/cache",
                    ciphertext_format_verified=True, ownership_changed=False, network_transfer=False,
                    recipient_decryption_performed=False, private_keys_transferred=False)
    output = dict(provider_node="relay4", ciphertext_bytes=size, ciphertext_sha256="f" * 64,
                  plaintext_bytes=CHECK["OBJECT_BYTES"], plaintext_sha256=CHECK["FIXTURE_PLAINTEXT_SHA256"],
                  route_context_id="a" * 32, user_uid=1001, agent_uid=1002, control_gid=1003, agent_gid=1002,
                  cache_modes="0700", output_mode="0600", sender_identity_unchanged_before_removal=True,
                  sender_removed_before_fetch=True, agent_cannot_read_sender_state=True,
                  client_mount_positive_control=True, client_mount_cannot_read_provider_cache=True,
                  user_cannot_read_agent_caches=True,
                  fresh_destination_cache=True, wrong_recipient_rejected=True, wrong_recipient_output_absent=True,
                  no_clobber_verified=True, recipient_identities_unchanged=True,
                  recipient_key_independently_supplied=True, mailbox_claimed=False)
    return dict(
        publish=dict(operation="offline_private_message_publish", publisher_key_hex="2" * 64,
                     network_publication=False, ciphertext_bytes=size, chunks=9, cache="/user/source"),
        **{"import": imported, "export": dict(imported, operation="content_export",
                                               cache="/user/received", agent_cache="/agent/client/cache")},
        fetch=dict(ordinary["fetch"], bytes=size, peer_bytes=size),
        serve=dict(serving=True, publications=1), stop=dict(serving=False, publications=0),
        open=dict(operation="offline_private_message_open", network_retrieval=False, bytes=CHECK["OBJECT_BYTES"]),
        output=output, sender_cleanup=dict(encrypted_sender_identity_removed=True, sender_passphrase_removed=True,
            sender_input_removed=True, sender_private_directory_removed=True),
        expected_peers=ordinary["expected_peers"], layout=ordinary["layout"],
        selected_route=ordinary["selected_route"], privacy=ordinary["privacy"],
        control_privacy=base["control_underlay"]["capture"])


class EvidenceContract(unittest.TestCase):
    def test_normal_cli_identity_opens_existing_private_seed(self):
        binary_directory = os.environ.get("VOLPAROSSA_TEST_BIN_DIR")
        if not binary_directory:
            self.skipTest("set VOLPAROSSA_TEST_BIN_DIR for the real local CLI compatibility proof")
        cli = str(Path(binary_directory, "volparossa").resolve(strict=True))
        seed = str(Path(binary_directory, "examples/content-acceptance-fixture").resolve(strict=True))
        with tempfile.TemporaryDirectory(prefix=".content-message-cli-", dir=Path(__file__).resolve().parents[2]) as temporary:
            root = Path(temporary)
            passphrase = root / "passphrase"
            with os.fdopen(os.open(passphrase, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                output.write(secrets.token_urlsafe(48).encode("ascii"))

            def run(*arguments, success=True):
                result = subprocess.run([cli, *map(str, arguments)], capture_output=True, timeout=30)
                self.assertEqual(result.returncode == 0, success, result.stderr.decode(errors="replace"))
                return result

            identities = [root / name for name in ("identity.key", "wrong-identity.key")]
            for identity in identities:
                run("init", "--identity", identity, "--passphrase-file", passphrase)
                self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            encrypted = [identity.read_bytes() for identity in identities]
            recipient = json.loads(run("content", "recipient-key", "--identity", identities[0],
                                       "--passphrase-file", passphrase).stdout)
            self.assertFalse(recipient["private_key_exported"])
            publication = root / "publication"
            subprocess.run([seed, "seed-private", str(publication), recipient["recipient_public_key_hex"]],
                           check=True, capture_output=True, timeout=30)
            metadata = json.loads((publication / "publication.json").read_text())
            self.assertTrue(metadata["publisher_removed"] and metadata["recipient_encrypted"])
            self.assertEqual((metadata["chunks"], metadata["replica_a_chunks"], metadata["replica_b_chunks"]), (9, 5, 4))
            output_path = root / "message.bin"

            def open_message(identity, output, success):
                return run("content", "open-message", "--identity", identity, "--passphrase-file", passphrase,
                           "--manifest", publication / "manifest.bin", "--sender-key", metadata["publisher_hex"],
                           "--cache", publication / "replica-a", "--cache", publication / "replica-b",
                           "--output", output, success=success)

            wrong = root / "wrong-message.bin"
            open_message(identities[1], wrong, False)
            self.assertFalse(wrong.exists())
            result = json.loads(open_message(identities[0], output_path, True).stdout)
            self.assertEqual(result["operation"], "offline_private_message_open")
            self.assertEqual(result["bytes"], CHECK["OBJECT_BYTES"])
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
            plaintext = output_path.read_bytes()
            self.assertEqual(hashlib.sha256(plaintext).hexdigest(), CHECK["FIXTURE_PLAINTEXT_SHA256"])
            open_message(identities[0], output_path, False)
            self.assertEqual(output_path.read_bytes(), plaintext)
            self.assertEqual([identity.read_bytes() for identity in identities], encrypted)

    def test_private_transfer_is_distinct_from_public_content(self):
        value = private_fixture()
        CHECK["validate_transfer"](value, True)
        with self.assertRaises(ValueError):
            CHECK["validate_transfer"](value)
        with self.assertRaises(ValueError):
            CHECK["validate_transfer"](fixture(), True)
        report = dict(report_kind="volparossa-native-private-content-network", source_revision="a" * 40,
                      success=True, runner_exit_status=0, transfer=value,
                      cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
                      full_alpha_acceptance_claimed=False, distinct_provider_nodes_claimed=False,
                      provider_discovery_claimed=False, https_authentication_claimed=False,
                      normal_recipient_cli_claimed=True, encrypted_identity_store_claimed=True,
                      normal_publisher_cli_claimed=True, local_private_cache_handoff_claimed=True,
                      local_public_cache_handoff_claimed=True,
                      network_publisher_runtime_claimed=True, mailbox_runtime_claimed=False,
                      full_c07_claimed=False)
        CHECK["validate_report"](report, "a" * 40, True)
        for claim in ("normal_recipient_cli_claimed", "encrypted_identity_store_claimed",
                      "normal_publisher_cli_claimed", "local_private_cache_handoff_claimed",
                      "local_public_cache_handoff_claimed",
                      "network_publisher_runtime_claimed", "mailbox_runtime_claimed", "full_c07_claimed"):
            wrong = copy.deepcopy(report)
            wrong[claim] = not wrong[claim]
            with self.assertRaises(ValueError):
                CHECK["validate_report"](wrong, "a" * 40, True)

    def test_private_handoff_requires_real_account_boundary_and_complete_transfer(self):
        for key, field, value in (
            ("isolation", "agent_uid", 1001), ("isolation", "control_gid", 1002),
            ("isolation", "agent_cannot_read_user_cache_or_secrets", False),
            ("import", "complete", False), ("export", "private_keys_transferred", True),
            ("export", "manifest_id", "c" * 64), ("export", "ciphertext_bytes", 1),
            ("open", "bytes", 1), ("status_after", "serving", True),
        ):
            with self.subTest(key=key, field=field):
                handoff = private_fixture()["private_message"]["local_handoff"]
                handoff[key][field] = value
                with self.assertRaises(ValueError):
                    CHECK["validate_private_handoff"](handoff)

    def test_public_handoff_requires_opt_in_isolation_and_honest_native_scope(self):
        for key, field, value in (
            ("isolation", "agent_uid", 1001), ("isolation", "default_public_import_rejected", False),
            ("isolation", "agent_cannot_read_user_cache", False), ("import", "complete", False),
            ("export", "manifest_id", "c" * 64), ("export", "content_bytes", 1),
            ("export", "origin_authenticated", True), ("export", "ciphertext_format_verified", True),
            ("export", "ciphertext_bytes", 2097275), ("assemble", "bytes", 1),
            ("status_after", "serving", True),
        ):
            with self.subTest(key=key, field=field):
                handoff = private_fixture()["private_message"]["local_public_handoff"]
                handoff[key][field] = value
                with self.assertRaises(ValueError):
                    CHECK["validate_public_handoff"](handoff)

    def test_normal_private_network_publication_requires_real_paths_sender_removal_and_exact_ciphertext(self):
        CHECK["validate_message_publication"](network_publication_fixture())
        for key, field, value in (
            ("output", "sender_removed_before_fetch", False),
            ("output", "recipient_key_independently_supplied", False),
            ("output", "wrong_recipient_rejected", False),
            ("output", "client_mount_positive_control", False),
            ("output", "client_mount_cannot_read_provider_cache", False),
            ("output", "user_uid", 1002), ("output", "no_clobber_verified", False),
            ("sender_cleanup", "encrypted_sender_identity_removed", False),
            ("fetch", "peer_bytes", 0), ("fetch", "provider_peer_ids", ["peer-client"]),
            ("export", "ciphertext_format_verified", False), ("export", "manifest_id", "c" * 64),
            ("export", "agent_cache", "/agent/relay4/cache"), ("stop", "serving", True),
        ):
            with self.subTest(key=key, field=field):
                value_under_test = network_publication_fixture()
                value_under_test[key][field] = value
                with self.assertRaises(ValueError):
                    CHECK["validate_message_publication"](value_under_test)
        for role, counter in (("relay0", "exit_leg_wireguard_data_datagrams"),
                              ("client", "direct_client_exit_packets")):
            value_under_test = network_publication_fixture()
            value_under_test["privacy"][role][counter] = 0 if role == "relay0" else 1
            with self.assertRaises(ValueError):
                CHECK["validate_message_publication"](value_under_test)

    def test_message_publication_builder_reads_actual_named_cli_and_capture_artifacts(self):
        value = network_publication_fixture()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name, suffix in (("publish", "publish"), ("import", "import"), ("serve", "serve"),
                    ("fetch", "fetch"), ("export", "export"), ("open", "open"), ("stop", "stop"),
                    ("output", "object"), ("sender_cleanup", "sender-cleanup"),
                    ("layout", "layout"), ("selected_route", "live-selection")):
                (work / f"content-message-publication-{suffix}.json").write_text(json.dumps(value[name]))
            for role, capture in value["privacy"].items():
                (work / f"content-message-publication-privacy-{role}.json").write_text(json.dumps(capture))
            (work / "content-provider-message-control-privacy.json").write_text(json.dumps(value["control_privacy"]))
            (work / "a01-expected-peers.json").write_text(json.dumps(value["expected_peers"]))
            self.assertEqual(CHECK["build_message_publication"](work), value)

    def test_private_isolation_decryption_and_cleanup_are_required(self):
        for label, mutation in (
            ("plaintext stored as ciphertext", lambda value: value["publication"].update(bytes=2097275)),
            ("oversized envelope", lambda value: value["publication"].update(bytes=2098300)),
            ("unsealed publication", lambda value: value["publication"].update(recipient_encrypted=False)),
            ("provider can read key", lambda value: value["private_message"]["recipient_isolation"].update(key_unreadable_by_provider=False)),
            ("public identity file mode", lambda value: value["private_message"]["recipient_isolation"].update(encrypted_identity_mode="0644")),
            ("provider reads passphrase", lambda value: value["private_message"]["recipient_isolation"].update(passphrase_unreadable_by_provider=False)),
            ("raw recipient key", lambda value: value["private_message"]["recipient_isolation"].update(raw_recipient_private_key_file=True)),
            ("fixture-only identity", lambda value: value["private_message"]["recipient_isolation"].update(identity_created_by_normal_cli=False)),
            ("shared UID", lambda value: value["private_message"]["recipient_isolation"].update(provider_uid=1001)),
            ("wrong recipient succeeds", lambda value: value["private_message"]["decryption"].update(wrong_recipient_rejected=False)),
            ("wrong plaintext", lambda value: value["private_message"]["plaintext_output"].update(plaintext_sha256="f" * 64)),
            ("plaintext world-readable", lambda value: value["private_message"]["plaintext_output"].update(private_output_mode="0644")),
            ("fixture-only opening", lambda value: value["private_message"]["decryption"].update(normal_cli_open=False)),
            ("output overwritten", lambda value: value["private_message"]["decryption"].update(no_clobber_verified=False)),
            ("identity changed", lambda value: value["private_message"]["decryption"].update(encrypted_identities_unchanged=False)),
            ("wrong output retained", lambda value: value["private_message"]["decryption"].update(wrong_recipient_output_absent=False)),
            ("key retained", lambda value: value["private_message"]["temporary_cleanup"].update(encrypted_identities_removed=False)),
            ("passphrase retained", lambda value: value["private_message"]["temporary_cleanup"].update(passphrase_removed=False)),
            ("plaintext retained", lambda value: value["private_message"]["temporary_cleanup"].update(plaintext_removed=False)),
        ):
            with self.subTest(label=label):
                wrong = private_fixture()
                mutation(wrong)
                with self.assertRaises(ValueError):
                    CHECK["validate_transfer"](wrong, True)

    def test_scoped_good_report(self):
        report = dict(report_kind="volparossa-native-content-network", source_revision="a" * 40,
                      success=True, runner_exit_status=0, transfer=fixture(),
                      cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
                      full_alpha_acceptance_claimed=False, distinct_provider_nodes_claimed=False,
                      provider_discovery_claimed=False, https_authentication_claimed=False)
        CHECK["validate_report"](report, "a" * 40)
        for mutation in (
            lambda value: value.update(source_revision="c" * 40),
            lambda value: value.update(https_authentication_claimed=True),
            lambda value: value.update(distinct_provider_nodes_claimed=True),
            lambda value: value["cleanup"].update(remaining_owned_objects=1),
            lambda value: value["host_state"].update(after_sha256="c" * 64),
        ):
            wrong = copy.deepcopy(report)
            mutation(wrong)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](wrong, "a" * 40)

    def test_substituted_or_incomplete_proofs_fail(self):
        for label, mutation in (
            ("publisher online", lambda value: value["publication"].update(publisher_removed=False)),
            ("local shortcut", lambda value: value["reconstructed_object"].update(client_cannot_read_replica_stores=False)),
            ("wrong object", lambda value: value["reconstructed_object"].update(sha256="f" * 64)),
            ("missing replica", lambda value: value["phases"].pop()),
            ("first already complete", lambda value: value["phases"][0]["consumer"].update(complete=True)),
            ("second downloaded all", lambda value: value["phases"][1]["consumer"].update(chunks_received=9)),
            ("direct source", lambda value: value["phases"][0]["provider"]["source"].update(ip="43.159.1.1")),
            ("wrong destination", lambda value: value["phases"][0]["provider"].update(listen=dict(ip="47.163.4.2", port=80))),
            ("substituted provider process", lambda value: value["phases"][0]["provider"].update(pid=999)),
            ("ordinary TCP", lambda value: value["phases"][0]["selected_route"].update(transport="tcp")),
            ("no TLS proof", lambda value: value["phases"][0]["protected_gates"].update(exit_mptcp_tls_open_completed=False)),
            ("missing leg", lambda value: value["phases"][1]["privacy"]["relay0"].update(exit_leg_wireguard_data_datagrams=0)),
            ("capture loss", lambda value: value["phases"][1]["privacy"]["relay1"].update(packet_socket_drops=1)),
            ("capture truncated", lambda value: value["phases"][1]["privacy"]["client"].update(truncated=True)),
            ("direct Client Exit", lambda value: value["phases"][1]["privacy"]["client"].update(direct_client_exit_packets=1)),
            ("Relay destination leak", lambda value: value["phases"][1]["privacy"]["relay0"].update(internet_destination_outer_packets=1)),
            ("Exit sees Client", lambda value: value["phases"][1]["privacy"]["exit"].update(client_public_packets=1)),
            ("missing destination bytes", lambda value: value["phases"][1]["application_captures"]["exit"].update(destination_response_segments=0)),
        ):
            with self.subTest(label=label):
                wrong = fixture()
                mutation(wrong)
                with self.assertRaises(ValueError):
                    CHECK["validate_transfer"](wrong)

    def test_private_cleanup_is_exact_and_idempotent(self):
        script = str(Path(__file__).with_name("content-network-smoke.sh").resolve())
        sender_script = str(Path(__file__).with_name("content-message-publication-smoke.sh").resolve())
        with tempfile.TemporaryDirectory(prefix="volparossa-content-private-cleanup-") as temporary:
            work = Path(temporary)
            private = work / "client-fixtures/content/private"
            private.mkdir(parents=True, mode=0o700)
            for name in ("identity.key", "wrong-identity.key", "passphrase", "message.bin", "wrong-message.bin",
                         "network-message.bin", "network-wrong-message.bin"):
                path = private / name
                path.write_bytes(b"public non-secret cleanup fixture")
                path.chmod(0o600)
            sender = work / "client-fixtures/message-publication/private"
            sender.mkdir(parents=True, mode=0o700)
            for name in ("identity.key", "passphrase", "input.bin"):
                path = sender / name
                path.write_bytes(b"public non-secret sender cleanup fixture")
                path.chmod(0o600)
            unrelated = work / "unrelated.txt"
            unrelated.write_text("preserve", encoding="ascii")
            environment = dict(os.environ, WORK=str(work), WORKER_UID=str(os.getuid()),
                               WORKER_GID=str(os.getgid()))
            for _ in range(2):
                subprocess.run(["sh", "-eu", "-c", '. "$1"; . "$2"; content_network_private_cleanup',
                                "sh", script, sender_script],
                               env=environment, check=True, timeout=5, capture_output=True)
            self.assertFalse(private.exists())
            self.assertFalse(sender.exists())
            self.assertEqual(unrelated.read_text(encoding="ascii"), "preserve")
            self.assertEqual(json.loads((work / "content-private-cleanup.json").read_text()),
                             dict(encrypted_identities_removed=True, passphrase_removed=True,
                                  plaintext_removed=True, private_directory_removed=True))


if __name__ == "__main__":
    unittest.main()
