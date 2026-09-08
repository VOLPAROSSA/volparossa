#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate observed MeshOwner backend evidence; never imply an overlay or physical-radio proof."""

import hashlib
import json
from pathlib import Path
import sys


def event(path, prefix):
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise ValueError("bounded mesh log exceeded")
    values = [json.loads(line[len(prefix):]) for line in raw.decode().splitlines()
              if line.startswith(prefix)]
    if len(values) != 1:
        raise ValueError(f"expected one {prefix.strip()} event in {path.name}")
    return values[0]


def payload_hash(response):
    data = b"".join(sequence.to_bytes(4, "big") + bytes([0xb9 if response else 0x63]) * 1020
                    for sequence in range(128))
    return hashlib.sha256(data).hexdigest()


def admission_evidence(log, node):
    """Require the real setter/readback before bytes, on the same affine kernel owner."""
    admission = event(log, "MESH_ADMISSION ")
    if (admission.get("role") != node["role"]
            or type(admission.get("ifindex")) is not int
            or admission["ifindex"] != node["ifindex"]
            or admission.get("zero_readback") is not True
            or type(admission.get("final_maximum_peers")) is not int
            or admission["final_maximum_peers"] != 2
            or admission.get("established_preserved") is not True):
        raise ValueError("owned mesh admission/readback or retained ESTAB peer evidence failed")
    # event() already bounds the immutable test log and requires each event exactly once.
    # The Rust event follows both exact-owner readbacks and retained-original-peer checks;
    # MESH_RESULT then proves actual bidirectional payload/counters on those retained links.
    prefixes = ("MESH_ADMISSION ", "MESH_RESULT ", "MESH_REMOVED ")
    ordered = [prefix for line in log.read_text().splitlines()
               for prefix in prefixes if line.startswith(prefix)]
    if ordered != list(prefixes):
        raise ValueError("mesh admission must precede payload and exact-owner retirement")
    return admission


def evidence(directory):
    nodes = []
    for role in ("a", "b"):
        log = directory / f"mesh-{role}.log"
        node = event(log, "MESH_RESULT ")
        retired = event(log, "MESH_REMOVED ")
        expected_name = "vw" + ("51" if role == "a" else "52") * 6 + "5"
        if (node["role"] != role or node["interface"] != expected_name
                or node["ifindex"] <= 0 or node["wiphy"] < 0
                or node["joined"] is not True or node["established"] is not True
                or node["sent_bytes"] != 131072 or node["received_bytes"] != 131072
                or node["sent_sha256"] != payload_hash(role == "b")
                or node["received_sha256"] != payload_hash(role != "b")
                or any(node[field] <= 0 for field in (
                    "rx_bytes_delta", "tx_bytes_delta", "rx_packets_delta", "tx_packets_delta"))
                or retired != {"role": role, "idempotent": True}):
            raise ValueError("actual mesh payload, peering, counters or retirement evidence failed")
        node["admission"] = admission_evidence(log, node)
        nodes.append(node)
    crash = event(directory / "mesh-crash.log", "MESH_CRASH_READY ")
    if crash["interface"] != "vw5353535353535" or crash["ifindex"] <= 0:
        raise ValueError("socket-loss object was not the exact owned interface")
    if nodes[0]["wiphy"] == nodes[1]["wiphy"]:
        raise ValueError("two actual radios required")
    return nodes


def build(directory, revision, status, normal, socket_loss, unchanged, remaining):
    report = {
        "report_kind": "volparossa-wifi-mesh-kernel-backend",
        "source_revision": revision,
        "success": False,
        "simulation": "mac80211_hwsim",
        "kernel": "6.12.107+deb13-amd64",
        "frequency_mhz": 2412,
        "open_layer2": True,
        "sae_claimed": False,
        "physical_radio_proven": False,
        "bandwidth_claimed": False,
        "full_agent_overlay_proven": False,
        "admission_setter_readback_proven": False,
        "nodes": [],
        "socket_loss_cleanup": socket_loss == "yes",
        "cleanup": {"complete": remaining == 0, "remaining_owned_objects": remaining,
                    "namespace_baseline_restored": normal == "yes" and socket_loss == "yes"},
        "host_state": {"captured": True, "unchanged": unchanged == "yes"},
    }
    try:
        report["nodes"] = evidence(directory)
        if status != 0 or normal != "yes" or socket_loss != "yes" or unchanged != "yes" or remaining != 0:
            raise ValueError("mesh fixture or exact cleanup did not complete")
        report["admission_setter_readback_proven"] = True
        report["success"] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["observed_blocker"] = str(error)[:512]
    return report


if __name__ == "__main__":
    output, revision, status, normal, socket_loss, unchanged, remaining = sys.argv[1:]
    directory = Path(output)
    result = build(directory, revision, int(status), normal, socket_loss, unchanged, int(remaining))
    (directory / "wifi-mesh-smoke.json").write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit(0 if result["success"] else 1)
