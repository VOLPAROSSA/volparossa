#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only IPv6 preflight for the two disposable private-DNS VM scenarios.

No socket/query, route, sysctl, interface, firewall or resolver change is made.
The fixed route lookup sends no packets. A present route is NOT Internet proof.
"""
import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
import re
import selectors
import subprocess
import time

SCENARIOS = ("dns-cache", "reciprocity-private-dns")
# A-root's published IPv6 endpoint; the versioned selector, not runner addresses,
# is retained in evidence. Never resolve this name through the runner's DNS.
ROOT_IPV6 = "2001:503:ba3e::2:30"
ADDRESS_COMMAND = ("ip", "-j", "-6", "address", "show")
ROUTE_COMMAND = ("ip", "-j", "-6", "route", "get", ROOT_IPV6)
MAX_BYTES = 65536
MAX_SECONDS = 2


@dataclass
class Probe:
    code: int | None = None
    output: bytes = b""
    error: bytes = b""
    failure: str | None = None


def read_command(command):
    """Bound both subprocess time and collected bytes; never print raw output."""
    process = None
    result = Probe()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        buffers = {"output": bytearray(), "error": bytearray()}
        deadline = time.monotonic() + MAX_SECONDS
        with selectors.DefaultSelector() as readable:
            readable.register(process.stdout, selectors.EVENT_READ, "output")
            readable.register(process.stderr, selectors.EVENT_READ, "error")
            while readable.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result.failure = "timeout"
                    return result
                for key, _events in readable.select(timeout=remaining):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        readable.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(data)
                    if sum(map(len, buffers.values())) > MAX_BYTES:
                        result.failure = "output_limit"
                        return result
            process.wait(timeout=max(.001, deadline - time.monotonic()))
        result.code = process.returncode
        result.output, result.error = bytes(buffers["output"]), bytes(buffers["error"])
    except FileNotFoundError:
        result.failure = "tool_unavailable"
    except subprocess.TimeoutExpired:
        result.failure = "timeout"
    except (OSError, ValueError, subprocess.SubprocessError):
        result.failure = "probe_error"
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                result.failure = "cleanup_unconfirmed"
            process.stdout.close()
            process.stderr.close()
    return result


def parse_json(probe):
    if probe.failure is not None or probe.code != 0 or probe.error.strip() \
            or len(probe.output) > MAX_BYTES:
        raise ValueError("unusable read-only probe")
    value = json.loads(probe.output.decode("utf-8", errors="strict"))
    if not isinstance(value, list) or len(value) > 256:
        raise ValueError("unexpected probe shape")
    return value


def usable_global(address):
    value = ipaddress.IPv6Address(address)
    return value.is_global and not value.is_multicast and not value.is_unspecified


def address_observation(probe):
    try:
        found = False
        for link in parse_json(probe):
            records = link["addr_info"]
            if not isinstance(records, list) or len(records) > 128:
                raise ValueError("address bound")
            for record in records:
                if record["family"] != "inet6":
                    raise ValueError("unexpected address family")
                valid = usable_global(record["local"])
                if record.get("scope") == "global" and valid \
                        and not record.get("tentative", False) and not record.get("dadfailed", False):
                    found = True
        return dict(read_ok=True, has_global_address=found, status="parsed")
    except (ValueError, UnicodeError, TypeError, KeyError):
        return dict(read_ok=False, has_global_address=None, status=probe.failure or "invalid_result")


def route_observation(probe):
    # iproute2 exits 2 for the kernel's explicit ENETUNREACH. Generic errors,
    # malformed/empty JSON and unsupported tools must never mean "no route".
    if probe.failure is None and probe.code == 2 and not probe.output.strip() \
            and probe.error.strip() == b"RTNETLINK answers: Network is unreachable":
        return dict(state="absent", has_global_source=None, status="kernel_enetunreach")
    try:
        rows = parse_json(probe)
        if len(rows) != 1:
            raise ValueError("route count")
        row = rows[0]
        destination = row["dst"].removesuffix("/128")
        if ipaddress.IPv6Address(destination) != ipaddress.IPv6Address(ROOT_IPV6) \
                or row.get("type", "unicast") != "unicast" or not isinstance(row.get("dev"), str) \
                or not row["dev"] or len(row["dev"]) > 64:
            raise ValueError("route scope")
        source = row.get("prefsrc", row.get("src"))
        return dict(state="present", has_global_source=usable_global(source) if source is not None else None,
                    status="parsed_unicast_route")
    except (ValueError, UnicodeError, TypeError, KeyError, AttributeError):
        return dict(state="unknown", has_global_source=None, status=probe.failure or "invalid_result")


def make_report(addresses, route, scenario, revision):
    if scenario not in SCENARIOS or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("fixed scenario and revision required")
    address_state, route_state = address_observation(addresses), route_observation(route)
    known = address_state["read_ok"] and route_state["state"] in ("present", "absent")
    ipv6 = route_state["state"] == "present" if known else None
    reason = ("runner_ipv6_route_present_reachability_unverified" if ipv6 is True else
              "runner_ipv6_route_absent_to_fixed_root" if ipv6 is False else "runner_ipv6_probe_unknown")
    return dict(schema=1, report_kind="volparossa-qemu-outer-uplink", source_revision=revision,
        scenario=scenario, preflight_complete=known, reason=reason, outer_ipv6=ipv6,
        qemu_option=("ipv6=on" if ipv6 else "ipv6=off") if known else None,
        observations=dict(addresses=address_state, route=route_state),
        probe=dict(root_selector="a-root-v6-v1", address_command="ip-json-ipv6-address-show",
                   route_command="ip-json-ipv6-route-get-fixed-root", max_seconds_each=MAX_SECONDS,
                   max_bytes_each=MAX_BYTES, runner_uid_matches_qemu=True),
        external_reachability_proven=False, network_traffic_sent=False, host_network_modified=False,
        product_ipv6_changed=False, overlay_ipv6_changed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("revision")
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.revision):
        raise SystemExit(77)
    report = make_report(read_command(ADDRESS_COMMAND), read_command(ROUTE_COMMAND), args.scenario, args.revision)
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 4096:
        raise SystemExit(70)
    print(encoded)
    raise SystemExit(0 if report["preflight_complete"] else 77)


if __name__ == "__main__":
    main()
