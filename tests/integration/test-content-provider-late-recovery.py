#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic late-recovery gates, not a live DHT/datapath proof."""
import copy
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-provider-late-recovery.py"))
ADAPTIVE = runpy.run_path(str(HERE / "test-content-provider-adaptive-smoke.py"))


def gate_fixture():
    table = CHECK["TABLE"]
    return dict(nftables=[dict(metainfo={}), dict(table=dict(family="inet", name=table)),
        dict(chain=dict(family="inet", table=table, name="input", type="filter", hook="input", prio=-30, policy="accept")),
        dict(rule=dict(family="inet", table=table, chain="input", expr=[
            dict(match=dict(op="==", left=dict(meta=dict(key="iifname")), right="r4x")),
            *[dict(match=dict(op="==", left=dict(payload=dict(protocol="ip", field=field)), right=address))
                for field, address in (("saddr", "46.162.3.1"), ("daddr", "49.165.5.1"))],
            dict(match=dict(op="==", left=dict(payload=dict(protocol="tcp", field="dport")), right=18080)),
            dict(counter=dict(packets=1, bytes=60)), {"drop": None}]))])


def fixture(control_node="relay2"):
    value = ADAPTIVE["fixture"](control_node)
    for key in ("https", "control_filter", "provider_payload_overlap_ns"): value.pop(key)
    value.update(schema_version=2, concurrent_provider_overlap_claimed=False, previous_context="b"*32, gate=gate_fixture())
    value["publication"] = dict(report_kind="volparossa-content-late-provider-seed", bytes=CHECK["BYTES"], chunks=9,
        object_sha256=CHECK["SHA"], name="disposable-late-native-publication", publisher_hex="3"*64, manifest_id="f"*64,
        publisher_removed=True, publisher_private_key_persisted=False, recipient_encrypted=False,
        replica_a_chunks=5, replica_b_chunks=4, replica_a_bytes=1048699, replica_b_bytes=1048576,
        created_unix_seconds=1000, expires_unix_seconds=4600)
    for route in (value["selected_before"], value["selected_route"]):
        route["route_context_id"] = "c"*32
        for item in route["paths"]: item["route_context_id"] = "c"*32
    nodes, peers = CHECK["NODES"], value["expected_peers"]
    value["layout"]["provider_nodes"] = list(nodes)
    value["fetch"].update(bytes=CHECK["BYTES"], chunks=9, providers_used=2, peer_bytes=CHECK["BYTES"],
        provider_peer_ids=[peers[node] for node in nodes])
    value["providers"].pop("relay3")
    for role, capture in value["privacy"].items():
        for node, counts in capture["provider_application"].items():
            counts.update(request_packets=100 if role == "exit" and node in nodes else 0,
                response_packets=100 if role == "exit" and node in nodes else 0,
                response_payload_bytes=1100000 if role == "exit" and node in nodes else 0)
    addresses = CHECK["BASE"]["PUBLIC_IPS"]
    control = value["control_underlay"]["capture"]
    control.update(interfaces=["lc0", "lc1"], observed_frames=40,
        content_control_pairs={f"lc{i}": [addresses[control_node], addresses[node]] for i, node in enumerate(nodes)},
        content_control_packets={f"lc{i}": dict(inbound=10, outbound=10) for i in range(2)},
        interface_statistics={f"lc{i}": dict(intake_stopped=True, observed_frames=20, packet_socket_packets=20,
            packet_socket_drops=0) for i in range(2)})
    value["control_underlay"]["routes"] = {node: dict(
        out=[dict(dev=f"lc{i}", gateway=f"10.241.{86+i}.2", prefsrc=addresses[control_node], dst=addresses[node])],
        back=[dict(dev=f"lp{i}", gateway=f"10.241.{86+i}.1", prefsrc=addresses[node], dst=addresses[control_node])])
        for i, node in enumerate(nodes)}
    def row(event, when): return dict(event=event, unix_ms=when)
    events = CHECK["EVENTS"]
    value["first_snapshot"] = dict(client=[row(events[1], 1002), row(events[0], 1002)],
        broker=[row(events[3], 1001), row(events[4], 1001)])
    value["final_snapshot"] = copy.deepcopy(value["first_snapshot"])
    value["final_snapshot"]["client"] += [row(events[1], 2000), row(events[0], 2000)]
    value["final_snapshot"]["broker"] += [row(events[3], 1900), row(events[4], 1901), row(events[4], 1901)]
    value["output"] = dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], event_baseline_unix_ms=1000,
        gate_started_ns=1_000_000_000, fetch_started_ns=1_100_000_000, first_snapshot_observed_ns=2_000_000_000,
        late_activation_started_ns=2_100_000_000, late_activation_acknowledged_ns=2_200_000_000,
        gate_released_ns=2_300_000_000, fetch_completed_ns=5_000_000_000,
        cold_cache=True, consumer_provider_hints=False, origin_fallback=False)
    value["run_cleanup"] = dict(fetch_reaped=True, gate_removed=True, operation_completed=True)
    value["cleanup"] = dict(route_disconnected=True, active_contexts=0, paths_empty=True,
        client_output_removed=True, client_manifest_removed=True, client_mount_isolated=True)
    value["readiness"] = dict(schema_version=1, kind="content-provider-late-readiness", success=True,
        scope="warm-control-plane-cold-content-cache", started_ns=100_000_000, completed_ns=500_000_000,
        event_baseline_unix_ms=800, completed_unix_ms=999, route_context_id="c"*32,
        manifest_id=value["publication"]["manifest_id"], control_relay_peer_id=value["layout"]["control_relay_peer_id"],
        attempts=[dict(started_ns=200_000_000, completed_ns=400_000_000, failure=None,
            response=dict(schema_version=1, kind="content-provider-discovery-readiness",
                control_relay_peer_id=value["layout"]["control_relay_peer_id"],
                providers=[dict(peer_id=peers["relay4"], offer_expires_unix_seconds=4600)]))],
        checks=dict(route_unchanged=True, b_not_serving=True, cold_cache=True, children_reaped=True), failure=None,
        events=dict(client=[row(events[1], 900), row(events[0], 900)], broker=[row(events[3], 850), row(events[4], 899)]))
    return value


def raw_files(value):
    prefix = CHECK["PREFIX"]
    files = {f"{prefix}-{suffix}.json": value[key] for key, suffix in (("publication", "publication"), ("layout", "layout"),
        ("status_before", "status-before"), ("status_after", "status-after"), ("fetch", "fetch"), ("output", "object"),
        ("selected_before", "selection"), ("selected_route", "live-selection"), ("cleanup", "cleanup"),
        ("first_snapshot", "first-snapshot"), ("final_snapshot", "final-snapshot"), ("gate", "gate-installed"),
        ("run_cleanup", "run-cleanup"), ("readiness", "readiness"))}
    files["a01-expected-peers.json"] = value["expected_peers"]
    broker = next(node for node in ("relay0", "relay1", "relay2")
        if value["expected_peers"][node] == value["layout"]["control_relay_peer_id"])
    files["content-provider-adaptive-selection.json"] = ADAPTIVE["fixture"](broker)["selected_before"]
    files[f"{prefix}-final-status.txt"] = "connected: false\nactive contexts: 0\n"
    files[f"{prefix}-final-paths.txt"] = ""
    for node, records in value["providers"].items():
        for operation, record in records.items(): files[f"{prefix}-{node}-{operation}.json"] = record
    for role, capture in value["privacy"].items(): files[f"{prefix}-privacy-{role}.json"] = capture
    files[f"{prefix}-control-privacy.json"] = value["control_underlay"]["capture"]
    for node, routes in value["control_underlay"]["routes"].items():
        for direction, route in routes.items(): files[f"{prefix}-control-{node}-{direction}.json"] = route
    return files


def disjoint_snapshot_fixture():
    value = fixture()
    # The broker records generic verified-offer events, not peer identifiers.
    # Keep the two actual suppliers and complementary payload proof, but model
    # only one offer in each completed snapshot: first {A}, then {B}, not {A,B}.
    value["final_snapshot"]["broker"].pop()
    return value


class LateRecovery(unittest.TestCase):
    def test_configuration_is_client_only_and_preparation_precedes_unchanged_gate(self):
        root = HERE.joinpath('kvm-alpha-topology.sh').read_text()
        block = root.split('if [ "$scenario" = content-provider ] && [ "$node" = client ]; then', 1)[1].split('\n        fi', 1)[0]
        self.assertIn('interface: cr0', block); self.assertIn('interface: cr2', block)
        self.assertNotIn('content_contribution:', block)
        self.assertIn('write_config client null false false', root)
        shell = HERE.joinpath('content-provider-late-recovery.sh').read_text()
        self.assertLess(shell.index('wait_observer "$PROVIDER_CONTROL_PID"'), shell.index('.py" prepare'))
        self.assertLess(shell.index('.py" prepare'), shell.index('.py" run'))
        self.assertEqual(CHECK['GATE_NS'], 6_000_000_000)
        self.assertEqual(CHECK['PREPARE_NS'], 30_000_000_000)

    def test_readiness_is_current_only_and_cannot_be_claimed_from_old_evidence(self):
        current = fixture(); CHECK["validate"](current)
        historical = copy.deepcopy(current); historical["schema_version"] = 1; historical.pop("readiness")
        CHECK["validate"](historical, historical=True)
        with self.assertRaises(ValueError): CHECK["validate"](historical)
        with self.assertRaises(ValueError): CHECK["validate"](current, historical=True)
        mutations = [(('readiness', 'success'), False), (('readiness', 'events'), dict(client=[], broker=[])),
            (('readiness', 'attempts'), current['readiness']['attempts']*3),
            (('readiness', 'completed_unix_ms'), current['output']['event_baseline_unix_ms']),
            (('readiness', 'checks', 'cold_cache'), False), (('readiness', 'checks', 'children_reaped'), False),
            (('readiness', 'route_context_id'), '0'*32), (('readiness', 'manifest_id'), '0'*64),
            (('readiness', 'attempts', 0, 'response', 'providers', 0, 'peer_id'), 'wrong-provider'),
            (('readiness', 'attempts', 0, 'response', 'providers', 0, 'offer_expires_unix_seconds'), 0)]
        for keys, changed in mutations:
            with self.subTest(keys=keys):
                value = copy.deepcopy(current); target = value
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = changed
                with self.assertRaises(ValueError): CHECK['validate'](value)

    def test_actual_preparation_is_bounded_separate_cold_and_retains_failed_rounds(self):
        for case in ('ready', 'empty-then-ready', 'both-empty', 'timeout', 'second-error', 'wrong-broker',
                     'wrong-provider', 'early-b', 'changed-route', 'warm-cache'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); value = fixture(); clock = [1_000_000_000]
                value['selected_before']['exact_selected_exit'] = value['expected_peers']['exit']
                binary = work/'volparossa'; binary.touch()
                executable = work/'content-acceptance-fixture'; executable.touch()
                native = work/'state-client/content-late-recovery'; native.mkdir(parents=True)
                for name, item in (("publication", value["publication"]), ("layout", value["layout"]),
                        ("selection", value["selected_before"]), ("peers", value["expected_peers"])):
                    CHECK['write'](CHECK['path'](work, name), item)
                calls, responses, deadlines = [], [], []
                def request(_work, tool, args, deadline):
                    self.assertEqual(tool, executable); self.assertEqual(len(args), 3)
                    self.assertEqual(args[-1], value['publication']['publisher_hex'])
                    self.assertNotIn(value['expected_peers']['relay4'], args)
                    calls.append('discover'); deadlines.append(deadline); clock[0] += 1_000_000_000
                    if case == 'timeout':
                        clock[0] = deadline; raise subprocess.TimeoutExpired(['private-socket'], 30)
                    if case == 'second-error' and len(calls) == 2: raise CHECK['FixtureCommandError'](1)
                    reply = copy.deepcopy(value['readiness']['attempts'][0]['response'])
                    if case in ('both-empty', 'empty-then-ready', 'second-error') and (len(calls) == 1 or case == 'both-empty'):
                        reply['providers'] = []
                    if case == 'wrong-broker': reply['control_relay_peer_id'] = 'wrong'
                    if case == 'wrong-provider': reply['providers'][0]['peer_id'] = 'wrong'
                    responses.append(reply)
                    return reply
                def command(args, deadline, _input=None):
                    deadlines.append(deadline); clock[0] += 1_000_000
                    self.assertLess(clock[0], deadline)
                    if args[-1] == 'paths':
                        context = '0'*32 if case == 'changed-route' else value['selected_before']['route_context_id']
                        return ''.join(f"context={context} path={p['path_id']} relay={p['relay_peer_id']} "
                            f"exit={value['selected_before']['exact_selected_exit']} state=1 rtt_us=1 bytes=0 acked_transport_bytes=0\n"
                            for p in value['selected_before']['paths']).encode()
                    if args[-2:] == ['content', 'status']:
                        if 'runtime-relay5' in args[2]: return json.dumps(dict(serving=case == 'early-b', publications=0)).encode()
                        return json.dumps(dict(control_relay_peer_id=value['layout']['control_relay_peer_id'])).encode()
                    self.assertEqual(args[-3:], ['logs', '--limit', '400'])
                    codes = []
                    for reply in responses:
                        if 'runtime-client' in args[2]:
                            codes.extend([CHECK['EVENTS'][1] if reply['providers'] else CHECK['EVENTS'][2], CHECK['EVENTS'][0]])
                        else:
                            codes.append(CHECK['EVENTS'][3])
                            if reply['providers']: codes.append(CHECK['EVENTS'][4])
                    return ''.join(f"{2001+i} INFO event={code}\n" for i, code in enumerate(codes)).encode()
                if case == 'warm-cache': (native/'cache').mkdir()
                with patch.dict(CHECK['prepare'].__globals__, guest=lambda work: None, readiness_request=request, command=command), \
                        patch.object(CHECK['time'], 'monotonic_ns', side_effect=lambda: clock[0]), \
                        patch.object(CHECK['time'], 'time_ns', side_effect=lambda: 1_000_000_000+clock[0]), \
                        patch.object(CHECK['time'], 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0]+int(seconds*1e9))):
                    if case in ('ready', 'empty-then-ready'): CHECK['prepare'](work, binary, executable)
                    else:
                        with self.assertRaises((ValueError, subprocess.TimeoutExpired)): CHECK['prepare'](work, binary, executable)
                record = CHECK['read'](CHECK['path'](work, 'readiness'))
                CHECK['validate_readiness'](record, value['publication'], value['layout'], value['selected_before'],
                    value['expected_peers'], successful=False)
                self.assertLessEqual(len(calls), 2); self.assertEqual(set(deadlines), {31_000_000_000})
                self.assertEqual(record['success'], case in ('ready', 'empty-then-ready'))
                self.assertNotIn('private-socket', json.dumps(record))
                self.assertFalse(CHECK['path'](work, 'gate', 'state').exists())
                if case == 'empty-then-ready':
                    self.assertEqual(record['attempts'][0]['response']['providers'], [])
                    self.assertEqual(CHECK['count'](record['events']['client'], CHECK['EVENTS'][2]), 1)
                if case == 'second-error':
                    self.assertEqual(len(record['attempts']), 2)
                    self.assertEqual(record['attempts'][1]['failure']['category'], 'command-failed')
                    self.assertEqual(CHECK['count'](record['events']['client'], CHECK['EVENTS'][2]), 1)

    def test_readiness_timeout_kills_reaps_and_closes_exact_child_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); calls = []; clock = [1_000_000_000]
            class Process:
                pid = 1234
                returncode = None
                stdout = io.BytesIO()
                def communicate(self, timeout):
                    self.timeout = timeout; raise subprocess.TimeoutExpired(['private'], timeout)
                def poll(self): return self.returncode
                def kill(self): calls.append('kill')
                def wait(self, timeout): calls.append('reap'); self.returncode = -9
            process = Process()
            def identity(pid):
                clock[0] += 10_000_000_000
                return dict(pid=pid, start_ticks=2)
            with patch.object(CHECK['subprocess'], 'Popen', return_value=process), \
                    patch.object(CHECK['time'], 'monotonic_ns', side_effect=lambda: clock[0]), \
                    patch.dict(CHECK['readiness_request'].__globals__, process_identity=identity):
                with self.assertRaises(subprocess.TimeoutExpired): CHECK['readiness_request'](work, Path('/inert'), [],
                    CHECK['time'].monotonic_ns()+30_000_000_000)
            self.assertEqual(calls, ['kill', 'reap']); self.assertTrue(process.stdout.closed)
            self.assertEqual(process.timeout, 20, 'setup time cannot extend the original deadline')

    def test_exact_late_phase_is_independent_of_payload_overlap(self):
        for broker in ("relay0", "relay1", "relay2"):
            value = fixture(broker)
            value["privacy"]["exit"]["provider_payload_timing"] = {"enabled": False}
            CHECK["validate"](value)
        self.assertNotEqual(CHECK["SHA"], CHECK["BASE"]["SHA"])

    def test_disjoint_first_a_then_b_snapshots_do_not_require_a_repeated_offer(self):
        value = disjoint_snapshot_fixture()
        self.assertEqual(CHECK["count"](value["first_snapshot"]["broker"], CHECK["EVENTS"][4]), 1)
        self.assertEqual(CHECK["count"](value["final_snapshot"]["broker"], CHECK["EVENTS"][4]), 2)
        self.assertEqual(CHECK["count"](value["final_snapshot"]["broker"], CHECK["EVENTS"][3]), 2)
        self.assertEqual(CHECK["count"](value["final_snapshot"]["client"], CHECK["EVENTS"][0]), 2)
        CHECK["validate"](value)

    def test_two_completed_snapshots_with_only_one_verified_offer_still_fail(self):
        value = disjoint_snapshot_fixture()
        self.assertEqual(value["final_snapshot"]["broker"].pop()["event"], CHECK["EVENTS"][4])
        self.assertEqual(CHECK["count"](value["final_snapshot"]["broker"], CHECK["EVENTS"][4]), 1)
        with self.assertRaisesRegex(ValueError, "bounded genuine rediscovery not proven"):
            CHECK["validate"](value)

    def test_two_offers_still_require_actual_late_b_and_complementary_delivery(self):
        original = disjoint_snapshot_fixture()
        mutations = [
            (("fetch", "provider_peer_ids"), [original["expected_peers"]["relay4"]]*2),
            (("privacy", "exit", "provider_application", "relay5", "response_payload_bytes"), 0),
            (("providers", "relay5", "serve", "serving"), False),
            (("output", "sha256"), "0"*64),
            (("output", "late_activation_started_ns"), 1),
            (("output", "fetch_completed_ns"), 400_000_000_000),
        ]
        for keys, changed in mutations:
            with self.subTest(keys=keys):
                value = copy.deepcopy(original); target = value
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = changed
                with self.assertRaises(ValueError): CHECK["validate"](value)

    def test_rejects_no_rediscovery_early_b_warm_cache_unprotected_paths_and_bad_cleanup(self):
        mutations = [(("first_snapshot", "broker"), []), (("final_snapshot", "client"), fixture()["first_snapshot"]["client"]),
            (("output", "cold_cache"), False), (("output", "consumer_provider_hints"), True),
            (("output", "origin_fallback"), True), (("output", "late_activation_started_ns"), 1),
            (("output", "gate_released_ns"), 8_000_000_000), (("output", "fetch_completed_ns"), 400_000_000_000),
            (("fetch", "providers_used"), 1), (("fetch", "origin_body_bytes"), 1),
            (("privacy", "client", "direct_client_exit_packets"), 1),
            (("run_cleanup", "gate_removed"), False), (("cleanup", "client_mount_isolated"), False),
            (("providers", "relay5", "before", "serving"), True), (("publication", "object_sha256"), CHECK["BASE"]["SHA"])]
        for keys, changed in mutations:
            with self.subTest(keys=keys):
                value = fixture(); target = value
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = changed
                with self.assertRaises(ValueError): CHECK["validate"](value)

    def test_gate_can_only_drop_exact_exit_to_a_tcp_content_not_udp_discovery(self):
        CHECK["validate_gate"](gate_fixture())
        for keys, changed in [(("nftables", 2, "chain", "hook"), "output"),
                (("nftables", 3, "rule", "expr", 0, "match", "right"), "underlay"),
                (("nftables", 3, "rule", "expr", 3, "match", "right"), 41000),
                (("nftables", 3, "rule", "expr", 3, "match", "left", "payload", "protocol"), "udp")]:
            value = gate_fixture(); target = value
            for key in keys[:-1]: target = target[key]
            target[keys[-1]] = changed
            with self.assertRaises(ValueError): CHECK["validate_gate"](value)

    def test_gate_rules_separate_nested_blocks_and_pass_read_only_nft_parser(self):
        rules = CHECK["gate_rules"]()
        self.assertTrue(rules.endswith(b"counter drop; }\n}\n"))
        nft = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
        if nft is None: self.skipTest("nft userspace parser is not installed")
        broken = rules.replace(b"counter drop; }\n}\n", b"counter drop; } }\n")
        def parse(raw):
            # Check-only never commits a rule. An unprivileged host may refuse
            # netlink initialization after parsing; that is not installed-gate proof.
            return subprocess.run([nft, "--check", "--file", "-"], input=raw,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        before, after = parse(broken), parse(rules)
        self.assertNotEqual(before.returncode, 0)
        self.assertIn(b"syntax error", before.stderr)
        self.assertNotIn(b"syntax error", after.stderr)
        if after.returncode:
            self.assertEqual(after.stderr.strip(), b"netlink: Error: cache initialization failed: Operation not permitted")

    def test_failure_evidence_is_closed_and_never_exports_exception_or_command_text(self):
        cases = ((CHECK["FixtureCommandError"](2), "command-failed", 2),
            (subprocess.TimeoutExpired(["private-command"], 2, stderr=b"secret"), "timeout", None),
            (InterruptedError("secret"), "interrupted", None), (OSError("secret"), "os-error", None),
            (ValueError("secret"), "invalid-evidence", None))
        for error, category, code in cases:
            value = CHECK["failure_evidence"]("gate-install", error)
            self.assertEqual(value, dict(schema_version=1, kind="content-provider-late-recovery-failure",
                success=False, stage="gate-install", category=category, command_exit_code=code))
            self.assertNotIn("secret", json.dumps(value)); self.assertNotIn("private-command", json.dumps(value))
        original = CHECK["failure_evidence"]("gate-install", CHECK["FixtureCommandError"](2))
        for field, changed in (("schema_version", True), ("success", True), ("stage", "arbitrary-path"),
                ("category", "raw-error"), ("command_exit_code", True), ("command_exit_code", 0),
                ("command_exit_code", 256), ("command_exit_code", -256), ("stderr", "secret")):
            value = {**original, field: changed}
            with self.assertRaises(ValueError): CHECK["validate_failure"](value)
        with patch.object(CHECK["subprocess"], "run", return_value=SimpleNamespace(returncode=2, stdout=b"secret")):
            with self.assertRaises(CHECK["FixtureCommandError"]) as caught:
                CHECK["command"](["unused-inert-command"], CHECK["time"].monotonic_ns() + 1_000_000_000)
        self.assertEqual(caught.exception.returncode, 2)
        self.assertNotIn("secret", str(caught.exception))

    def test_log_snapshots_are_bounded_and_ignore_preexisting_or_noncontent_events(self):
        raw = b"1000 INFO event=CONTENT_DISCOVERY_COMPLETED\n1001 INFO event=CONTENT_DISCOVERY_RECEIVED_OFFERS\n"
        self.assertEqual(CHECK["event_rows"](raw, 1000), [dict(unix_ms=1001, event="CONTENT_DISCOVERY_RECEIVED_OFFERS")])
        self.assertEqual(CHECK["event_rows"](b"1001 INFO event=OTHER_EVENT\n", 1000), [])
        with self.assertRaises(ValueError): CHECK["event_rows"](b"1001 INFO event=OTHER_EVENT\n"*400, 1000)
        with self.assertRaises(ValueError): CHECK["event_rows"](b"x"*(CHECK["LIMIT"]+1), 1000)

    def test_cleanup_releases_gate_before_process_ownership_check_and_attempts_both(self):
        events = []
        def process(_work, suffix="fetch"): events.append(suffix); raise ValueError("replaced")
        with patch.dict(CHECK["cleanup"].__globals__, stop_fetch=process, remove_gate=lambda work: events.append("gate")):
            with self.assertRaises(ValueError): CHECK["cleanup"](Path("/not-an-actual-guest"))
        self.assertEqual(events, ["gate", "fetch", "readiness-process"])
        events.clear()
        def gate(_work): events.append("gate"); raise ValueError("gate failed")
        with patch.dict(CHECK["cleanup"].__globals__, stop_fetch=lambda work, suffix="fetch": events.append(suffix), remove_gate=gate):
            with self.assertRaises(ValueError): CHECK["cleanup"](Path("/not-an-actual-guest"))
        self.assertEqual(events, ["gate", "fetch", "readiness-process"])
        with tempfile.TemporaryDirectory() as temporary: CHECK["cleanup"](Path(temporary))

    def test_coordinator_activates_b_only_after_snapshot_and_always_releases_owned_gate(self):
        for failure in (None, "gate-install", "gate-inspect", "snapshot", "activation"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); native = work / "state-client/content-late-recovery"; native.mkdir(parents=True)
                binary = work / "volparossa"; binary.touch()
                value, calls, clock = fixture(), [], [1_000_000_000]
                for name, contents in (("layout", value["layout"]), ("peers", value["expected_peers"]),
                        ("publication", value["publication"])):
                    CHECK["write"](CHECK["path"](work, name), contents)
                class Process:
                    pid = 77
                    returncode = None
                    def poll(self): return self.returncode
                    def wait(self, timeout):
                        calls.append("fetch-wait")
                        if self.returncode is None:
                            (native / "object.bin").write_bytes(b"x"*CHECK["BYTES"])
                            self.returncode = 0
                        return self.returncode
                    def terminate(self): calls.append("fetch-terminate"); self.returncode = -15
                    def kill(self): calls.append("fetch-kill"); self.returncode = -9
                process = Process()
                def spawn(args, **kwargs):
                    calls.append("fetch-start")
                    self.assertNotIn("--provider", args); self.assertNotIn("--bind", args)
                    self.assertFalse(any("peer-" in arg or "volparossa.test" in arg for arg in args))
                    kwargs["stdout"].write(json.dumps(value["fetch"]).encode())
                    return process
                def now(): clock[0] += 100_000_000; return clock[0]
                def execute(args, deadline, input_data=None):
                    if args[-2:] == ["list", "tables"]: return b'{"nftables":[]}'
                    if args[-2:] == ["-f", "-"]:
                        calls.append("gate-install")
                        if failure == "gate-install": raise CHECK["FixtureCommandError"](2)
                        return b""
                    if "list" in args and "table" in args:
                        if failure == "gate-inspect": raise ValueError("secret malformed gate")
                        return json.dumps(gate_fixture()).encode()
                    if "delete" in args: calls.append("gate-release"); return b""
                    if "logs" in args:
                        label = "client" if "runtime-client" in args[2] else "broker"
                        calls.append("snapshot-"+label)
                        if failure == "snapshot": return b""
                        snapshot = value["final_snapshot"] if process.returncode == 0 else value["first_snapshot"]
                        return "".join(f"{row['unix_ms']} INFO event={row['event']}\n" for row in snapshot[label]).encode()
                    if "serve" in args:
                        calls.append("activate-b")
                        self.assertLess(calls.index("snapshot-client"), calls.index("activate-b"))
                        self.assertLess(calls.index("snapshot-broker"), calls.index("activate-b"))
                        if failure == "activation": raise ValueError("registration failed")
                        return json.dumps(value["providers"]["relay5"]["serve"]).encode()
                    self.fail(f"unexpected command {args}")
                def release(_work, **_kwargs):
                    calls.append("cleanup-gate")
                    diagnostic = CHECK["path"](work, "failure")
                    self.assertEqual(diagnostic.exists(), failure is not None)
                    if failure:
                        record = CHECK["read"](diagnostic); CHECK["validate_failure"](record)
                        stage = {"snapshot": "first-snapshot", "activation": "activate-b"}.get(failure, failure)
                        self.assertEqual(record["stage"], stage)
                        self.assertEqual(record["command_exit_code"], 2 if failure == "gate-install" else None)
                        self.assertNotIn("secret", diagnostic.read_text())
                with patch.dict(CHECK["run"].__globals__, guest=lambda work: None,
                        checked_readiness=lambda *args: value["readiness"],
                        namespace=lambda work: dict(name="va-00000000-r4", identity="1:2"), command=execute,
                        process_identity=lambda pid: dict(pid=pid, start_ticks=100),
                        remove_gate=release), \
                        patch.object(CHECK["subprocess"], "Popen", side_effect=spawn), \
                        patch.object(CHECK["time"], "monotonic_ns", side_effect=now), \
                        patch.object(CHECK["time"], "time_ns", return_value=1_000_000_000), \
                        patch.object(CHECK["time"], "sleep"):
                    if failure:
                        with self.assertRaises(ValueError): CHECK["run"](work, binary, "va-00000000-r4")
                    else: CHECK["run"](work, binary, "va-00000000-r4")
                self.assertIn("cleanup-gate", calls)
                if failure in ("gate-install", "gate-inspect"):
                    self.assertNotIn("fetch-start", calls)
                else: self.assertIsNotNone(process.returncode)
                cleanup = CHECK["read"](CHECK["path"](work, "run-cleanup"))
                self.assertEqual(cleanup, dict(fetch_reaped=True, gate_removed=True, operation_completed=failure is None))
                if failure == "snapshot": self.assertNotIn("activate-b", calls)
                elif failure is None:
                    self.assertLess(calls.index("activate-b"), calls.index("gate-release"))
                    self.assertLess(calls.index("gate-release"), calls.index("fetch-wait"))
                if failure in ("snapshot", "activation"):
                    self.assertLess(calls.index("cleanup-gate"), calls.index("fetch-terminate"))

    def test_one_absolute_gate_deadline_accepts_late_discovery_but_not_slow_activation_or_release(self):
        for case in ("discovery-5.09s", "discovery-expired", "activation-expired", "release-expired"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); native = work / "state-client/content-late-recovery"; native.mkdir(parents=True)
                binary = work / "volparossa"; binary.touch()
                value, calls, clock = fixture(), [], [1_000_000_000]
                gate_started, fetch_started, deadlines = [], [], []
                for name, contents in (("layout", value["layout"]), ("peers", value["expected_peers"]),
                        ("publication", value["publication"])):
                    CHECK["write"](CHECK["path"](work, name), contents)
                class Process:
                    pid = 77
                    returncode = None
                    def poll(self): return self.returncode
                    def wait(child, timeout):
                        calls.append("fetch-wait")
                        if child.returncode is not None:
                            self.assertEqual(timeout, 2)
                            return child.returncode
                        self.assertAlmostEqual(timeout, (fetch_started[0]+300_000_000_000-clock[0])/1e9)
                        clock[0] += 100_000_000
                        (native / "object.bin").write_bytes(
                            b"".join(bytes([16+i])*262144 for i in range(8)) + bytes([25])*123)
                        child.returncode = 0
                        return 0
                    def terminate(child): calls.append("fetch-terminate"); child.returncode = -15
                    def kill(child): calls.append("fetch-kill"); child.returncode = -9
                process = Process()
                def spawn(*args, **kwargs):
                    fetch_started.append(clock[0]); calls.append("fetch-start")
                    return process
                def advance(seconds): clock[0] += round(seconds*1e9)
                def execute(args, **kwargs):
                    # Exercise real command(): every subprocess receives only its
                    # remaining absolute budget, capped at two seconds.
                    duration, output = 0.005, b""
                    if args[-2:] == ["list", "tables"]: output = b'{"nftables":[]}'
                    elif args[-2:] == ["-f", "-"]:
                        gate_started.append(clock[0]); calls.append("gate-install")
                    elif "list" in args and "table" in args: output = json.dumps(gate_fixture()).encode()
                    elif "logs" in args:
                        label = "client" if "runtime-client" in args[2] else "broker"
                        if process.returncode == 0: snapshot = value["final_snapshot"]
                        elif case != "discovery-expired" and clock[0] >= fetch_started[0]+5_090_000_000:
                            snapshot = value["first_snapshot"]
                        else: snapshot = dict(client=[], broker=value["first_snapshot"]["broker"])
                        output = "".join(f"{row['unix_ms']} INFO event={row['event']}\n" for row in snapshot[label]).encode()
                    elif "serve" in args:
                        calls.append("activate-b")
                        duration = 1.0 if case == "activation-expired" else 0.1
                        output = json.dumps(value["providers"]["relay5"]["serve"]).encode()
                    elif "delete" in args:
                        calls.append("gate-release")
                        duration = 1.0 if case == "release-expired" else 0.01
                    else: self.fail(f"unexpected command {args}")
                    if gate_started and process.returncode is None:
                        deadline = gate_started[0]+CHECK["GATE_NS"]
                        self.assertGreater(kwargs["timeout"], 0)
                        self.assertLessEqual(kwargs["timeout"], min(2, (deadline-clock[0])/1e9))
                        deadlines.append(deadline)
                    if duration > kwargs["timeout"]:
                        advance(kwargs["timeout"])
                        raise subprocess.TimeoutExpired(args, kwargs["timeout"])
                    advance(duration)
                    return SimpleNamespace(returncode=0, stdout=output)
                def release(_work, **_kwargs):
                    calls.append("cleanup-gate")
                    self.assertLessEqual(clock[0], gate_started[0]+CHECK["GATE_NS"]+20_000_000)
                    if case != "discovery-5.09s": self.assertTrue(CHECK["path"](work, "failure").exists())
                with patch.dict(CHECK["run"].__globals__, guest=lambda work: None,
                        checked_readiness=lambda *args: value["readiness"],
                        namespace=lambda work: dict(name="va-00000000-r4", identity="1:2"),
                        process_identity=lambda pid: dict(pid=pid, start_ticks=100), remove_gate=release), \
                        patch.object(CHECK["subprocess"], "run", side_effect=execute), \
                        patch.object(CHECK["subprocess"], "Popen", side_effect=spawn), \
                        patch.object(CHECK["time"], "monotonic_ns", side_effect=lambda: clock[0]), \
                        patch.object(CHECK["time"], "time_ns", return_value=1_000_000_000), \
                        patch.object(CHECK["time"], "sleep", side_effect=advance):
                    if case == "discovery-5.09s": CHECK["run"](work, binary, "va-00000000-r4")
                    else:
                        with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                            CHECK["run"](work, binary, "va-00000000-r4")
                self.assertEqual(set(deadlines), {gate_started[0]+6_000_000_000})
                cleanup = CHECK["read"](CHECK["path"](work, "run-cleanup"))
                self.assertEqual(cleanup, dict(fetch_reaped=True, gate_removed=True,
                    operation_completed=case == "discovery-5.09s"))
                if case == "discovery-5.09s":
                    output = CHECK["read"](CHECK["path"](work, "object"))
                    self.assertGreaterEqual(output["first_snapshot_observed_ns"]-output["fetch_started_ns"], 5_090_000_000)
                    self.assertLessEqual(output["gate_released_ns"]-output["gate_started_ns"], 6_000_000_000)
                    value["output"] = output; CHECK["validate"](value)
                else:
                    failure = CHECK["read"](CHECK["path"](work, "failure")); CHECK["validate_failure"](failure)
                    self.assertEqual(failure["stage"], {"discovery-expired": "first-snapshot",
                        "activation-expired": "activate-b", "release-expired": "gate-release"}[case])
                    self.assertFalse(CHECK["path"](work, "object").exists())
                    self.assertLess(calls.index("cleanup-gate"), calls.index("fetch-terminate"))
                if case == "discovery-expired": self.assertNotIn("activate-b", calls)
                if case == "activation-expired": self.assertNotIn("gate-release", calls)

    def test_builder_requires_exact_original_snapshots_and_disconnected_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); expected = fixture()
            for name, value in raw_files(expected).items():
                (work / name).write_text(value if isinstance(value, str) else json.dumps(value))
            self.assertEqual(CHECK["build_evidence"](work), expected)
            (work / f"{CHECK['PREFIX']}-final-paths.txt").write_text("active path\n")
            with self.assertRaises(ValueError): CHECK["build_evidence"](work)


if __name__ == "__main__": unittest.main()
