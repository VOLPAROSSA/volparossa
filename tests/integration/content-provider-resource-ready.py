#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded guest-fixture PSI precondition, never worker admission or transfer proof.

The production budget still checks current PSI, cgroup-constrained memory and
descriptor capacity itself. Cold-cache I/O may reintroduce pressure after this
precondition; the unchanged overlap checks must then fail normally.
"""
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

THRESHOLDS = {"cpu": 20.0, "memory": 1.0, "io": 10.0}
MAX_SOURCE_BYTES = 16 * 1024
DEADLINE_NS = 30_000_000_000
INTERVAL_NS = 1_000_000_000
REQUIRED = 3
MAX_SAMPLES = DEADLINE_NS // INTERVAL_NS
STATES = {"below_threshold", "pressured", "unavailable"}
SCOPE = {"guest_global_psi": True, "memory_capacity_checked": False,
         "fd_capacity_checked": False, "cgroup_capacity_checked": False,
         "worker_capacity_proven": False, "production_policy_overridden": False}
OUTPUTS = {"native": "content-provider-adaptive-resource-ready.json",
           "https": "content-provider-adaptive-https-resource-ready.json",
           "pressure": "content-provider-pressure-resource-ready.json"}


def require(condition):
    if not condition:
        raise ValueError("invalid resource readiness evidence")


def read_bounded(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_SOURCE_BYTES)
        # Proc files normally report size zero; bound actual reads independently.
        chunks = []
        size = 0
        while size <= MAX_SOURCE_BYTES:
            raw = os.read(descriptor, MAX_SOURCE_BYTES + 1 - size)
            if not raw:
                break
            chunks.append(raw)
            size += len(raw)
        require(size <= MAX_SOURCE_BYTES)
        return b"".join(chunks).decode("utf-8", errors="strict")
    finally:
        os.close(descriptor)


def average(text):
    # Match the production source and first `some avg10` field, not `full`/avg60.
    line = next((line for line in text.splitlines() if line.startswith("some ")), None)
    require(line is not None)
    field = next((field[6:] for field in line.split() if field.startswith("avg10=")), None)
    require(field is not None)
    require(re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", field) is not None)
    value = float(field)
    require(math.isfinite(value) and 0.0 <= value <= 100.0)
    return value


def observe(reader=read_bounded):
    result = {}
    for kind, threshold in THRESHOLDS.items():
        try:
            value = average(reader(Path("/proc/pressure") / kind))
            result[kind] = "pressured" if value >= threshold else "below_threshold"
        except (OSError, ValueError, UnicodeError):
            result[kind] = "unavailable"
    return result


def validate_observation(observation):
    require(type(observation) is dict and observation.keys() == THRESHOLDS.keys())
    require(all(type(value) is str and value in STATES for value in observation.values()))


def validate(receipt):
    require(type(receipt) is dict and receipt.keys() == {
        "schema_version", "kind", "phase", "scope", "status", "deadline_ms",
        "sample_interval_ms", "required_consecutive", "samples", "consecutive",
        "elapsed_ms", "last_observation"})
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1)
    require(receipt["kind"] == "content-provider-psi-readiness")
    require(type(receipt["phase"]) is str and receipt["phase"] in OUTPUTS)
    require(type(receipt["status"]) is str and receipt["status"] in {"ready", "timeout", "unavailable"})
    scope = receipt["scope"]
    require(type(scope) is dict and scope == SCOPE and all(type(value) is bool for value in scope.values()))
    for key, expected in (("deadline_ms", 30000), ("sample_interval_ms", 1000), ("required_consecutive", REQUIRED)):
        require(type(receipt[key]) is int and receipt[key] == expected)
    for key, maximum in (("samples", MAX_SAMPLES), ("consecutive", REQUIRED), ("elapsed_ms", 2**64 - 1)):
        require(type(receipt[key]) is int and 0 <= receipt[key] <= maximum)
    samples, consecutive = receipt["samples"], receipt["consecutive"]
    require(consecutive <= samples)
    require(receipt["elapsed_ms"] >= max(0, samples - 1) * 1000)
    observation = receipt["last_observation"]
    if observation is None:
        require(samples == 0)
    else:
        validate_observation(observation)
        require(samples > 0)
    if receipt["status"] == "ready":
        require(consecutive == REQUIRED and (REQUIRED - 1) * 1000 <= receipt["elapsed_ms"] < 30000)
        require(all(value == "below_threshold" for value in observation.values()))
    elif receipt["status"] == "timeout":
        require(receipt["elapsed_ms"] >= 30000 and consecutive < REQUIRED)
    else:
        require(observation is not None and "unavailable" in observation.values() and consecutive == 0)
        require(receipt["elapsed_ms"] < 30000)
    return receipt


def wait_ready(phase, *, sampler=observe, clock=time.monotonic_ns, sleeper=time.sleep):
    require(phase in OUTPUTS)
    start = clock()
    deadline = start + DEADLINE_NS
    samples = consecutive = 0
    now = start
    observation = None
    status = "timeout"
    while samples < MAX_SAMPLES:
        sample_start = clock()
        now = sample_start
        if sample_start >= deadline:
            break
        observation = sampler()
        validate_observation(observation)
        samples += 1
        now = clock()
        if now >= deadline:
            break
        if "unavailable" in observation.values():
            consecutive = 0
            status = "unavailable"
            break
        consecutive = consecutive + 1 if all(value == "below_threshold" for value in observation.values()) else 0
        if consecutive == REQUIRED:
            status = "ready"
            break
        # Re-check the same absolute deadline after early/interrupted sleeps.
        next_sample = min(sample_start + INTERVAL_NS, deadline)
        while now < next_sample:
            sleeper((next_sample - now) / 1_000_000_000)
            now = clock()
    elapsed_ms = (now - start) // 1_000_000
    return validate(dict(schema_version=1, kind="content-provider-psi-readiness", phase=phase,
                         scope=dict(SCOPE), status=status, deadline_ms=30000, sample_interval_ms=1000,
                         required_consecutive=REQUIRED, samples=samples, consecutive=consecutive,
                         elapsed_ms=elapsed_ms, last_observation=observation))


def run(work, phase, *, waiter=wait_ready):
    require(phase in OUTPUTS and work.is_absolute() and work.resolve() == work)
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        # Never overwrite a prior trial's receipt, including dangling symlinks.
        name = OUTPUTS[phase]
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("readiness receipt already exists")
        receipt = validate(waiter(phase))
        require(receipt["phase"] == phase)
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        require(len(raw) <= 2048)
        output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
        with os.fdopen(output, "wb") as stream:
            stream.write(raw)
        return receipt["status"] == "ready"
    finally:
        os.close(directory)


def main():
    try:
        require(len(sys.argv) == 3)
        return 0 if run(Path(sys.argv[1]), sys.argv[2]) else 1
    except (OSError, ValueError, UnicodeError):
        # Never export raw proc text, paths or exception details.
        print("CONTENT_PROVIDER_RESOURCE_READINESS_INVALID", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
