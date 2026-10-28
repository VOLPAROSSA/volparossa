#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded host diagnostics and a separate, narrow configuration checkpoint.

The two IPv6 pure functions reuse VOLPAROSSA Map 8a227709, hosted.py blob
d7e8015f8a0aa26e946e97890adb1259c43167fa, with only the snapshot docstring adapted.
Provenance and exact upstream renderer commits are in THIRD_PARTY_LICENSES.md.
No route bytes, addresses, device names, hostname or raw kernel build text leave
this module. Supported identity is a reviewed compatibility assumption, never
Ubuntu vendor-lineage verification or running-kernel source attestation.
"""
import hashlib
import os
from pathlib import Path
import re

IPV6_ROUTE_BYTES = 1024**2
IPV6_ROUTE_ROWS = 4096
IPV6_ROUTE_RENDERER_PROFILES = {
    "linux-6.8-native-seq-v1": r"6\.8\.0-[0-9]{1,6}-(?:generic|azure)",
    "linux-6.17-azure-native-seq-v1": r"6\.17\.0-[0-9]{1,6}-azure",
    "linux-7.0-azure-native-seq-v1": r"7\.0\.0-[0-9]{1,6}-azure",
}
FILES = {"ipv4_routes": "/proc/net/route", "ipv6_routes": "/proc/net/ipv6_route", "resolver": "/etc/resolv.conf"}
FILE_BYTES = 1024**2


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ipv6_route_snapshot(raw):
    """Hash one bounded proc snapshot; only the reference-count bytes are split.

    Layout: reviewed Linux v6.8/v6.17/v7.0 ipv6_route_native_seq_show, byte-identical.
    These fingerprints are not acceptance. Legacy diagnostics never waive raw
    equality; the separate configuration checkpoint preserves raw truth while
    checking its explicitly versioned, narrower configuration policy.
    Empty tables are valid. Duplicate rows and their order remain significant.
    """
    require(type(raw) is bytes and len(raw) <= IPV6_ROUTE_BYTES, "IPV6_ROUTE_BYTES")
    metadata = dict(schema=1, error=None, non_refcount=None, reference_metadata=None, row_count=None)
    snapshot = dict(raw=digest(raw), metadata=metadata)
    try:
        rows = raw.splitlines(keepends=True)
        require(len(rows) <= IPV6_ROUTE_ROWS, "IPV6_ROUTE_ROW_BOUND")
        non_refcount, references = [], []
        layout = (rb"[0-9a-f]{32} ([0-9a-f]{2}) [0-9a-f]{32} ([0-9a-f]{2}) "
                  rb"[0-9a-f]{32} [0-9a-f]{8} (?P<reference>[0-9a-f]{8}) "
                  rb"[0-9a-f]{8} [0-9a-f]{8} (?P<device> *[A-Za-z0-9_.-]{0,15})\n")
        for row in rows:
            match = re.fullmatch(layout, row)
            require(match is not None, "IPV6_ROUTE_ROW_SHAPE")
            require(all(int(match[index], 16) <= 128 for index in (1, 2)), "IPV6_ROUTE_ROW_SHAPE")
            device = match["device"].lstrip(b" ")
            require(device not in (b".", b"..") and match["device"] == device.rjust(8, b" "),
                    "IPV6_ROUTE_ROW_SHAPE")
            start, end = match.span("reference")
            non_refcount.append(row[:start] + row[end:])
            references.append(match["reference"] + b"\n")
        metadata.update(non_refcount=digest(b"".join(non_refcount)),
                        reference_metadata=digest(b"".join(references)), row_count=len(rows))
    except ValueError as error:
        # Fixed internal codes only; preserve the raw fingerprint on row rejection.
        metadata["error"] = "IPV6_ROUTE_ROW_BOUND" if str(error) == "IPV6_ROUTE_ROW_BOUND" else "IPV6_ROUTE_ROW_SHAPE"
    return snapshot


def ipv6_route_comparison(before, after):
    """Closed fingerprints only; rejected parses never become valid baselines."""
    def fingerprint(value, bound):
        return (type(value) is dict and set(value) == {"bytes", "sha256"}
                and type(value["bytes"]) is int and 0 <= value["bytes"] <= bound
                and type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)
    for value in (before, after):
        require(type(value) is dict and set(value) == {"raw", "metadata"}
                and fingerprint(value["raw"], IPV6_ROUTE_BYTES), "IPV6_ROUTE_METADATA_SHAPE")
        meta = value["metadata"]
        require(type(meta) is dict and set(meta) == {"schema", "error", "non_refcount", "reference_metadata", "row_count"}
                and type(meta["schema"]) is int and meta["schema"] == 1, "IPV6_ROUTE_METADATA_SHAPE")
        if meta["error"] is not None:
            require(type(meta["error"]) is str and meta["error"] in ("IPV6_ROUTE_ROW_BOUND", "IPV6_ROUTE_ROW_SHAPE")
                    and all(meta[key] is None for key in ("non_refcount", "reference_metadata", "row_count")),
                    "IPV6_ROUTE_METADATA_SHAPE")
        else:
            require(type(meta["row_count"]) is int and 0 <= meta["row_count"] <= IPV6_ROUTE_ROWS
                    and fingerprint(meta["non_refcount"], IPV6_ROUTE_BYTES)
                    and fingerprint(meta["reference_metadata"], IPV6_ROUTE_ROWS * 9)
                    and meta["reference_metadata"]["bytes"] == meta["row_count"] * 9
                    and meta["non_refcount"]["bytes"] + meta["row_count"] * 8 == value["raw"]["bytes"],
                    "IPV6_ROUTE_METADATA_SHAPE")
    raw_changed = before["raw"] != after["raw"]
    valid = before["metadata"]["error"] is None and after["metadata"]["error"] is None
    fields = {key + "_changed": before["metadata"][key] != after["metadata"][key] if valid else None
              for key in ("non_refcount", "reference_metadata", "row_count")}
    require(not valid or raw_changed or not any(fields.values()), "IPV6_ROUTE_METADATA_SHAPE")
    classification = ("PARSE_REJECTED" if not valid else "NON_REFCOUNT_DIFFERENCE"
        if fields["non_refcount_changed"] or fields["row_count_changed"] else "REFERENCE_METADATA_ONLY"
        if fields["reference_metadata_changed"] else "RAW_DIFFERENCE" if raw_changed else "UNCHANGED")
    return dict(classification=classification, raw_changed=raw_changed, metadata_valid=valid, **fields)


def fingerprint(value, bound):
    return (type(value) is dict and set(value) == {"bytes", "sha256"}
        and type(value["bytes"]) is int and 0 <= value["bytes"] <= bound
        and type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)


def renderer():
    """One uname capture. Never select hostname; hash bounded free-form version text."""
    value = dict(state="unavailable", profile=None, kernel=None, error="KERNEL_CAPTURE_FAILED")
    try:
        identity = os.uname()
        fields = {key:getattr(identity, key) for key in ("sysname", "release", "version", "machine")}
        require(all(type(fields[key]) is str and 0 < len(fields[key]) <= bound
            and re.fullmatch(r"[ -~]+", fields[key])
            for key,bound in (("sysname",16),("release",128),("version",256),("machine",32))), "KERNEL_IDENTITY_INVALID")
        kernel = {key:fields[key] for key in ("sysname", "release", "machine")}
        kernel["version_sha256"] = hashlib.sha256(fields["version"].encode("ascii")).hexdigest()
        profile = next((name for name,pattern in IPV6_ROUTE_RENDERER_PROFILES.items()
            if fields["sysname"] == "Linux" and fields["machine"] == "x86_64"
            and re.fullmatch(pattern, fields["release"])), None)
        value.update(state="supported" if profile else "unsupported", profile=profile,
            kernel=kernel, error=None if profile else "KERNEL_PROFILE_UNSUPPORTED")
    except (OSError,AttributeError,TypeError,ValueError) as error:
        if type(error) is ValueError and str(error) == "KERNEL_IDENTITY_INVALID":
            value["error"] = "KERNEL_IDENTITY_INVALID"
    return value


def validate_renderer(value):
    require(type(value) is dict and set(value) == {"state","profile","kernel","error"}, "HOST_METADATA_INVALID")
    if value["state"] == "unavailable":
        require(value["profile"] is None and value["kernel"] is None
            and value["error"] in ("KERNEL_CAPTURE_FAILED","KERNEL_IDENTITY_INVALID"), "HOST_METADATA_INVALID")
        return
    require(value["state"] in ("supported","unsupported"), "HOST_METADATA_INVALID")
    kernel = value["kernel"]
    require(type(kernel) is dict and set(kernel) == {"sysname","release","machine","version_sha256"}
        and all(type(kernel[key]) is str and 0 < len(kernel[key]) <= bound
            and re.fullmatch(r"[ -~]+",kernel[key])
            for key,bound in (("sysname",16),("release",128),("machine",32)))
        and type(kernel["version_sha256"]) is str and re.fullmatch("[0-9a-f]{64}",kernel["version_sha256"]), "HOST_METADATA_INVALID")
    expected = next((name for name,pattern in IPV6_ROUTE_RENDERER_PROFILES.items()
        if kernel["sysname"] == "Linux" and kernel["machine"] == "x86_64"
        and re.fullmatch(pattern,kernel["release"])),None)
    require(value["profile"] == expected and value["state"] == ("supported" if expected else "unsupported")
        and value["error"] == (None if expected else "KERNEL_PROFILE_UNSUPPORTED"), "HOST_METADATA_INVALID")


def capture():
    """One bounded read of each fixed file; neither retries nor partial fingerprints."""
    snapshot = dict(schema=1, files={}, renderer=renderer(), ipv6=None)
    for label,name in FILES.items():
        record = dict(state="unavailable", error="READ_FAILED", fingerprint=None)
        try:
            with Path(name).open("rb") as stream:
                raw = stream.read(FILE_BYTES + 1)
            if type(raw) is not bytes or len(raw) > FILE_BYTES:
                record["error"] = "READ_BOUND"
            else:
                record.update(state="observed", error=None, fingerprint=digest(raw))
                if label == "ipv6_routes":
                    snapshot["ipv6"] = ipv6_route_snapshot(raw)
        except OSError:
            pass  # Closed capture failure; never persist the OS error or its path operands.
        snapshot["files"][label] = record
    return snapshot


def validate(snapshot):
    require(type(snapshot) is dict and set(snapshot) == {"schema","files","renderer","ipv6"}
        and type(snapshot["schema"]) is int and snapshot["schema"] == 1
        and type(snapshot["files"]) is dict and set(snapshot["files"]) == set(FILES), "HOST_METADATA_INVALID")
    validate_renderer(snapshot["renderer"])
    for record in snapshot["files"].values():
        require(type(record) is dict and set(record) == {"state","error","fingerprint"}, "HOST_METADATA_INVALID")
        if record["state"] == "observed":
            require(record["error"] is None and fingerprint(record["fingerprint"],FILE_BYTES), "HOST_METADATA_INVALID")
        else:
            require(record["state"] == "unavailable" and record["error"] in ("READ_FAILED","READ_BOUND")
                and record["fingerprint"] is None, "HOST_METADATA_INVALID")
    ipv6_record = snapshot["files"]["ipv6_routes"]
    if ipv6_record["state"] == "observed":
        ipv6_route_comparison(snapshot["ipv6"],snapshot["ipv6"])
        require(snapshot["ipv6"]["raw"] == ipv6_record["fingerprint"], "HOST_METADATA_INVALID")
    else:
        require(snapshot["ipv6"] is None, "HOST_METADATA_INVALID")


def complete(snapshot):
    validate(snapshot)
    return all(record["state"] == "observed" for record in snapshot["files"].values())


def hashes(snapshot):
    """Legacy fixed-path SHA dictionary; unavailable files never become an empty digest."""
    validate(snapshot)
    return {name:(snapshot["files"][label]["fingerprint"]["sha256"]
        if snapshot["files"][label]["state"] == "observed" else None) for label,name in FILES.items()}


def compare(before, after):
    """Legacy diagnostics grant no configuration or trial acceptance."""
    value = dict(schema=1, diagnostic_only=True, acceptance_evidence=False,
        classification="METADATA_REJECTED", raw_equal=None,
        changed={label:None for label in FILES}, renderer_equal=None, ipv6=None)
    try:
        validate(before); validate(after)
    except (ValueError,TypeError,KeyError):
        return value
    value["changed"] = {label:(left["fingerprint"] != right["fingerprint"]
        if left["state"] == right["state"] == "observed" else None)
        for label in FILES for left,right in [(before["files"][label],after["files"][label])]}
    if not complete(before) or not complete(after):
        value["classification"] = "CAPTURE_UNAVAILABLE"
        return value
    value["raw_equal"] = not any(value["changed"].values())
    left,right = before["renderer"],after["renderer"]
    value["renderer_equal"] = left == right
    if left["state"] != "supported" or right["state"] != "supported":
        value["classification"] = "RENDERER_UNSUPPORTED"
    elif left != right:
        value["classification"] = "KERNEL_IDENTITY_DIFFERENCE"
    else:
        value["ipv6"] = ipv6_route_comparison(before["ipv6"],after["ipv6"])
        value["classification"] = ("OTHER_COMPONENT_DIFFERENCE"
            if value["changed"]["ipv4_routes"] or value["changed"]["resolver"]
            else value["ipv6"]["classification"])
    return value


def configuration_checkpoint(before, after):
    """Derive eligibility from captures, never from a supplied diagnostic classification.

    This checks only the two captured route/resolver configurations. It establishes
    no firewall, leak, transient-state, route-lineage or kernel-attestation claim.
    Trial acceptance additionally requires the controller's terminal cleanup gate.
    """
    result = dict(version=1, mode="supported_ipv6_reference_metadata_v1",
                  eligible=False, classification="REJECTED", raw_equal=None)
    try:
        for snapshot in (before, after):
            validate(snapshot)
            require(complete(snapshot), "CONFIG_CAPTURE_UNAVAILABLE")
            require(snapshot["renderer"]["state"] == "supported", "CONFIG_RENDERER_UNSUPPORTED")
            meta = snapshot["ipv6"]["metadata"]
            require(meta["error"] is None, "CONFIG_PARSE_REJECTED")
            rows = meta["row_count"]
            size = snapshot["ipv6"]["raw"]["bytes"]
            # The validated renderer emits 150 bytes per row, plus 0..7 bytes
            # when the device name exceeds its minimum eight-character field.
            require(rows * 150 <= size <= rows * 157, "CONFIG_LENGTH_INVALID")
            fingerprints = [record["fingerprint"] for record in snapshot["files"].values()]
            fingerprints += [meta["non_refcount"], meta["reference_metadata"]]
            require(all(value["bytes"] != 0 or value == digest(b"") for value in fingerprints),
                    "CONFIG_EMPTY_HASH_INVALID")
        require(before["renderer"] == after["renderer"], "CONFIG_RENDERER_CHANGED")
        require(all(before["files"][name]["fingerprint"] == after["files"][name]["fingerprint"]
                    for name in ("ipv4_routes", "resolver")), "CONFIG_OTHER_CHANGED")
        left, right = before["ipv6"], after["ipv6"]
        require(left["metadata"]["non_refcount"] == right["metadata"]["non_refcount"]
                and left["metadata"]["row_count"] == right["metadata"]["row_count"], "CONFIG_ROUTES_CHANGED")
        raw_equal = left["raw"] == right["raw"]
        references_equal = left["metadata"]["reference_metadata"] == right["metadata"]["reference_metadata"]
        require(raw_equal == references_equal, "CONFIG_RAW_INCONSISTENT")
        result.update(eligible=True, raw_equal=raw_equal,
                      classification="UNCHANGED" if raw_equal else "REFERENCE_METADATA_ONLY")
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        pass  # A closed rejection contains no input, paths, addresses or exception strings.
    return result
