#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Physical Mail traffic for two independent Clients, their selected relays and primary Exit."""
import importlib.util
import ipaddress
from pathlib import Path
import re
import socket
import sys

spec = importlib.util.spec_from_file_location("paired_mail_packet_engine",
    Path(__file__).with_name("content-replication-capture.py"))
ENGINE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ENGINE)

RELAYS = ("relay0", "relay1", "relay2")
CUSTODIANS = ("relay3", "relay5")
PUBLIC = {**ENGINE.PUBLIC, "relay3": ENGINE.LEARNER_IP}
ACTIVE = {"enroll": "relay4", "send": "client", "receive": "relay4"}
INTERFACES = {
    "client": ("underlay", "cb1", "cb2", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5"),
    "relay4": ("underlay", "r4c", "r4b1", "r4b2", "r4x", "ar0", "ar1", "ar2"),
    "exit": ("underlay", "xd", "xr0", "xr1", "xr2", "xr3", "xr4", "xr5"),
}
PROVIDER_FIELDS = ("request_packets", "response_packets", "response_payload_bytes")
EXTRA = ("underlay_control_attempt_packets", *(f"{node}_{field}" for node in CUSTODIANS for field in PROVIDER_FIELDS))


def require(value, message):
    if not value:
        raise ValueError(message)


def layout(phase):
    require(phase in ACTIVE, "unknown paired Mail phase")
    return {"phase": "paired-mail-peer-" + phase, "relays": {node: PUBLIC[node] for node in RELAYS}}


def check_layout(value):
    require(value in [layout(phase) for phase in ACTIVE], "unexpected paired Mail physical topology")


def role_node(layout, role):
    require(role in INTERFACES, "unexpected paired Mail capture role")
    return role


def classify(layout, role, protocol, src, sport, dst, dport, payload, iface, *, frame=None):
    pair = {src, dst}
    if any(pair == {PUBLIC[client], PUBLIC["exit"]} for client in ("client", "relay4")):
        return {"forbidden_packets": 1, "direct_client_exit_packets": 1}
    source, destination = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version != destination.version:
        return {"forbidden_packets": 1, "malformed_packets": 1}
    if source.version == 6:
        if ((source.is_link_local or source.is_unspecified) and (destination.is_link_local or dst.startswith("ff02:"))
                and protocol == socket.IPPROTO_ICMPV6 and payload and payload[0] in (130, 131, 132, 133, 134, 135, 136, 143)):
            return {"neighbor_packets": 1}
        if source.is_link_local and dst == "ff02::fb" and protocol == socket.IPPROTO_UDP and sport and dport == 5353:
            return {"mdns_packets": 1, "control_packets": 1}
        return {"forbidden_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport and dport and 41000 in (sport, dport):
        if ENGINE.exact_control_pair(role, iface, src, dst):
            return {"control_packets": 1}
        if (iface == "underlay" and sport == dport == 41000 and src == PUBLIC[role]
                and dst in ENGINE.LEARNER_UNROUTED_CONTROL.get(role, {"51.167.7.1"})):
            return {"control_packets": 1, "underlay_control_attempt_packets": 1}
    if protocol == socket.IPPROTO_ICMP and ENGINE.exact_control_port_unreachable(role, iface, src, dst, payload):
        return {"control_packets": 1, "control_port_unreachable_packets": 1}
    if (protocol == socket.IPPROTO_UDP and sport and dport == 5353 and dst == "224.0.0.251"
            and src in ENGINE.MDNS_INTERFACE_ADDRESSES.get((role, iface), ())):
        return {"mdns_packets": 1, "control_packets": 1}
    for node in CUSTODIANS:
        address = PUBLIC[node]
        if address in pair and pair.intersection({PUBLIC["client"], PUBLIC["relay4"]}):
            return {"forbidden_packets": 1, "direct_provider_packets": 1}
        if protocol != socket.IPPROTO_TCP or role != "exit" or iface != "xr" + node[-1]:
            continue
        if src == PUBLIC["exit"] and dst == address and sport and dport == 18080:
            return {f"{node}_request_packets": 1}
        if src == address and dst == PUBLIC["exit"] and sport == 18080 and dport:
            return {f"{node}_response_packets": 1, f"{node}_response_payload_bytes": len(payload)}
    if protocol == socket.IPPROTO_UDP and sport and dport:
        for index, relay in enumerate(RELAYS):
            physical = {"client": "cr", "relay4": "ar", "exit": "xr"}[role] + str(index)
            if iface != physical or pair != {PUBLIC[role], PUBLIC[relay]}:
                continue
            shape = ENGINE.wireguard_shape(payload, len(payload))
            if shape in ("handshake", "keepalive"):
                return {f"wireguard_{shape}_packets": 1}
            if shape == "data":
                leg = "exit_leg" if role == "exit" else "client_leg"
                return {f"{leg}_wireguard_data_datagrams": 1, f"{leg}_wireguard_data_bytes": len(payload),
                    f"{relay}_{leg}_wireguard_data_datagrams": 1}
    return {"forbidden_packets": 1}


# The engine instance is private to this profile; its packet intake, bounds and
# final drained kernel statistics are shared with the original replication trial.
ENGINE.role_node, ENGINE.validate_layout, ENGINE.classify = role_node, check_layout, classify
ENGINE.COUNTERS += EXTRA


def validate(captures, selected_route, expected_peers, packet_bytes, *, phase):
    current = layout(phase)
    require(set(captures) == set(INTERFACES) and type(packet_bytes) is int and 0 < packet_bytes <= 8388608,
        "incomplete paired Mail receive capture")
    participants = (*RELAYS, *CUSTODIANS, "client", "relay4", "exit")
    require(all(isinstance(expected_peers[n], str) and expected_peers[n] for n in participants)
        and len({expected_peers[n] for n in participants}) == len(participants), "Mail network identities overlap")
    paths, slots = selected_route["paths"], selected_route["benchmark_slots"]
    context = selected_route["route_context_id"]
    require(selected_route["transport"] == "mptcp" and re.fullmatch(r"[0-9a-f]{32}", context)
        and context != "0" * 32 and len(paths) == len(slots) == 2, "missing live receive route")
    selected = {slot["relay_node"] for slot in slots}
    require(len(selected) == 2 and selected <= set(RELAYS) and all(
        slot["relay_peer_id"] == expected_peers[slot["relay_node"]] == path["relay_peer_id"]
        and path["route_context_id"] == context and path["exit_peer_id"] == expected_peers["exit"]
        for slot, path in zip(slots, paths, strict=True)), "receive route roles changed")
    for role, record in captures.items():
        require(type(record["schema_version"]) is int and record["schema_version"] == 1 and record["phase"] == current["phase"]
            and record["capture_role"] == record["node"] == role and record["complete"] is True
            and record["truncated"] is False and record["interfaces"] == list(INTERFACES[role])
            and all(type(record[k]) is int and record[k] == 0 for k in (
                "malformed_packets", "forbidden_packets", "direct_provider_packets", "direct_client_exit_packets", "packet_socket_drops")),
            "unverified paired Mail physical boundary")
        rows = record["interface_statistics"]
        require(set(rows) == set(INTERFACES[role]) and all(
            row["drained"] is True and row["intake_stopped"] is True and row["packet_socket_drops"] == row["forbidden_packets"] == 0
            and type(row["observed_frames"]) is int and 0 <= row["observed_frames"] == row["packet_socket_packets"]
            and 4194304 <= row["receive_buffer_bytes"] <= 8388608 for row in rows.values())
            and type(record["observed_frames"]) is int
            and 0 <= record["observed_frames"] == sum(row["observed_frames"] for row in rows.values()) <= ENGINE.MAX_FRAMES,
            "receive-side packet sockets did not drain completely")
        leg = "exit_leg" if role == "exit" else "client_leg"
        active = role in (ACTIVE[phase], "exit")
        minimum = 1 if phase == "enroll" else 17
        for node in RELAYS:
            count = record[f"{node}_{leg}_wireguard_data_datagrams"]
            require(type(count) is int and (count >= minimum if active and node in selected else count == 0),
                "selected receive legs lack physical traffic")
        require(all(type(record[f"{n}_{k}"]) is int and record[f"{n}_{k}"] >= 0 for n in CUSTODIANS for k in PROVIDER_FIELDS),
            "invalid Mail custodian measurement")
        require(sum(record[f"{n}_{leg}_wireguard_data_datagrams"] for n in RELAYS)
            <= record["observed_frames"], "protected packet count exceeds capture")
        require(sum(record[f"{n}_{k}"] for n in CUSTODIANS for k in ("request_packets", "response_packets"))
            <= record["observed_frames"], "provider packets exceed capture")
    for role in ("client", "relay4"):
        require(all(captures[role][f"{n}_{k}"] == 0 for n in CUSTODIANS for k in PROVIDER_FIELDS),
            "provider application traffic bypassed the Exit")
    exit_node = captures["exit"]
    require(all(exit_node[f"{n}_request_packets"] > (16 if phase == "send" else 0)
        and exit_node[f"{n}_response_packets"] > 0 for n in CUSTODIANS),
        "both independent Mail custodians must exchange traffic with the Exit")
    if phase == "receive":
        require(max(exit_node[f"{n}_response_payload_bytes"] for n in CUSTODIANS) >= packet_bytes,
            "encrypted Mail return missing at the Exit")


def main(args):
    require(len(args) == 5 and args[0] == "capture" and args[1] in ACTIVE and args[2] in INTERFACES,
        "usage: capture PHASE ROLE OUTPUT READY")
    phase, role, output, ready = args[1:]
    ENGINE.capture(layout(phase), output, ready, role, list(INTERFACES[role]))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit("paired Mail physical capture failed")
