#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure proof-validator regression fixtures; never opens network sockets."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("local_fixture", Path(__file__).with_name("local-link-smoke.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fixture = module.fixture
run_id = "1" * 32
peers = {node: f"peer-{node}" for node in module.INTERFACES}
records = {"a01-expected-peers.json": peers, "mpquic-units.json": []}
for index, node in enumerate(module.INTERFACES):
    roles = {"client": True, "relay": True, "exit": node != "client"}
    for stage in ("before", "after"):
        records[f"local-link-node-{node}-{stage}.json"] = {"agent_pid": index + 100, "roles": roles}
    for mode in ("client", "exit"):
        if (node, mode) != ("client", "exit"):
            records["mpquic-units.json"].append({"node": node, "mode": mode,
                "main_pid": len(records["mpquic-units.json"]) + 1000, "socket_verified": True})
    records[f"local-link-capture-{node}.json"] = {
        "wireguard_edges": {"10.241.10.1>10.241.10.2": 4, "42.158.0.1>46.162.3.1": 4,
                            "10.241.10.2>10.241.10.1": 4, "10.241.12.1>10.241.12.2": 4},
        "destination_requests": {name: 4 for name in module.FLOWS},
        "destination_responses": {name: 4 for name in module.FLOWS}, "truncated": False,
        "packet_socket_drops": 0, "direct_client_exit_packets": 0, "plaintext_leaks": 0}
for stage in ("before", "after"):
    records[f"local-link-addresses-{stage}.json"] = [
        {"ifname": "cr0", "addr_info": [{"local": "10.241.10.1"}]},
        {"ifname": "cr2", "addr_info": [{"local": "10.241.12.1"}]}]
    records[f"local-link-routes-{stage}.json"] = [{"dst": "10.241.10.0/30", "dev": "cr0"},
        {"dst": "10.241.12.0/30", "dev": "cr2"},
        {"dst": "10.241.31.2", "type": "unreachable"}]
echoes = {}
for name, flow in module.FLOWS.items():
    payload = fixture.payload_for(run_id, name)
    digest = hashlib.sha256(payload).hexdigest()
    records[f"local-link-app/{name}.json"] = {"success": True, "datagrams": 3,
        "destination": list(fixture.DESTINATION), "sent_sha256": digest, "response_sha256": digest,
        "sent_bytes": len(payload), "response_bytes": len(payload),
        "first_echo_ns": 100, "last_echo_ns": 3_000_000_100}
    echoes[name] = {"sha256": digest, "bytes": len(payload), "datagrams": 3,
                    "source_ips": [flow["uplink"]]}
records["local-link-app/server.json"] = {"destination": list(fixture.DESTINATION), "flows": echoes}
path = f"context={'2' * 32} path=1 relay=peer-relay0 exit=peer-exit state=3 rtt_us=1 bytes=0\n"
contribution_path = f"context={'3' * 32} path=1 relay=peer-client exit=peer-relay2 state=3 rtt_us=1 bytes=0\n"

with tempfile.TemporaryDirectory(prefix="volparossa-local-link-contract-") as temporary:
    directory = Path(temporary)
    (directory / "local-link-app").mkdir()
    def evaluate(data, selected_path=path, selected_contribution=contribution_path):
        for name, value in data.items():
            fixture.write_json(directory / name, value)
        (directory / "local-link-paths-client.txt").write_text(selected_path, encoding="ascii")
        (directory / "local-link-paths-relay0.txt").write_text(selected_contribution, encoding="ascii")
        return module.build_evidence(directory, run_id)
    result = evaluate(records)
    assert result["success"] and len(result["flows"]) == 2
    assert result["flows"][0]["path_evidence"]["client_relay_scope"] == "DirectLocalLan"
    assert result["contribution_witness"]["node"] == "client"
    assert result["contribution_witness"]["consuming_context"] != result["contribution_witness"]["relaying_context"]
    def rejected(name, mutation):
        changed = copy.deepcopy(records)
        mutation(changed)
        try:
            evaluate(changed)
        except ValueError:
            return
        raise AssertionError("accepted invalid local-link evidence: " + name)
    rejected("public address", lambda data: data["local-link-addresses-after.json"][0]["addr_info"].append({"local": "8.8.8.8"}))
    rejected("Internet default", lambda data: data["local-link-routes-after.json"].append({"dst": "default", "dev": "cr0"}))
    rejected("client Exit enabled", lambda data: data["local-link-node-client-after.json"]["roles"].update(exit=True))
    rejected("daemon replaced", lambda data: data["local-link-node-client-after.json"].update(agent_pid=1))
    rejected("wrong echo", lambda data: data["local-link-app/client.json"].update(response_sha256="bad"))
    rejected("wrong Exit source", lambda data: data["local-link-app/server.json"]["flows"]["client"].update(source_ips=["10.241.10.1"]))
    rejected("missing LAN WG leg", lambda data: data["local-link-capture-client.json"].update(wireguard_edges={}))
    rejected("missing WAN WG leg", lambda data: data["local-link-capture-exit.json"].update(wireguard_edges={}))
    rejected("missing contribution LAN leg", lambda data: data["local-link-capture-client.json"]["wireguard_edges"].pop("10.241.12.1>10.241.12.2"))
    rejected("contribution Exit source", lambda data: data["local-link-app/server.json"]["flows"]["relay0"].update(source_ips=["10.241.31.1"]))
    rejected("nonconcurrent contribution", lambda data: data["local-link-app/relay0.json"].update(first_echo_ns=3_000_000_000))
    for field in ("truncated", "packet_socket_drops", "direct_client_exit_packets", "plaintext_leaks"):
        rejected(field, lambda data, field=field: data["local-link-capture-client.json"].update({field: 1}))
    for invalid in (path.replace("state=3", "state=2"), path.replace("peer-relay0", "peer-client")):
        try:
            evaluate(records, invalid)
        except ValueError:
            continue
        raise AssertionError("accepted inactive or wrong relay path")
    for invalid in (contribution_path.replace("peer-client", "peer-exit"),
                    contribution_path.replace("3" * 32, "2" * 32)):
        try:
            evaluate(records, path, invalid)
        except ValueError:
            continue
        raise AssertionError("accepted missing actual local-only relay contribution")

print("Local-link pure evidence contract passed; no live datapath claim")
