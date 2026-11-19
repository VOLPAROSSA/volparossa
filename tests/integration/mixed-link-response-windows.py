#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Join real HTTP/3 receive intervals, Exit path choices and Client wire counters on one guest clock."""
import json
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def record(directory, case, samples):
    def read(name):
        return json.loads((directory / f"mixed-link-{case}-{name}.json").read_bytes())
    client, destination, capture = (read(name) for name in ("client", "destination", "client-capture"))
    start, end = client["response_first_byte_unix_us"], client["response_complete_unix_us"]
    delivery = client["response_duration_ns"] / 1000
    require(client["case"] == destination["case"] == "mixed-" + case
            and client["response_sha256"] == destination["response_sha256"]
            and client["response_bytes"] == destination["response_bytes"] == 33554432, "invalid measured payload")
    # A guest wall-clock jump cannot silently select samples from another phase.
    # The throughput gate continues to use the monotonic application duration.
    require(start < end and abs(end-start-delivery) <= 100000, "unstable guest wall clock")
    snapshots = capture["response_received_samples"]
    require(2 <= len(snapshots) <= 202 and all(a["unix_us"] <= b["unix_us"] for a,b in zip(snapshots,snapshots[1:]))
            and snapshots[0]["unix_us"] <= start and snapshots[-1]["unix_us"] >= end, "incomplete marker capture")
    names = ("relay1_received_bytes","relay2_received_bytes")
    for i,name in enumerate(names,1):
        require(snapshots[-1][name] == capture["after_marker"][f"relay{i}_received_wireguard_data_bytes"]
                and all(0 <= a[name] <= b[name] for a,b in zip(snapshots,snapshots[1:])), "counter discontinuity")
    selected = [s for s in samples if start <= s["unix_us"] <= end]
    require(len(selected) <= 64 and all(a["sample"] < b["sample"] for a,b in zip(selected,selected[1:])),
            "response spans multiple scheduler sessions")
    quarters = []
    for i in range(4):
        low,high = start+(end-start)*i//4,start+(end-start)*(i+1)//4
        inside = [v for v in snapshots if low <= v["unix_us"] <= high]
        choices = [v for v in selected if low <= v["unix_us"] and (v["unix_us"] < high or (i == 3 and v["unix_us"] == high))]
        counts = {}
        for s in choices:
            if s["has_selected"]:
                p=str(s["selected_path"]);counts[p]=counts.get(p,0)+1
        span = None
        if len(inside) >= 2:
            span = {k: inside[-1][k]-inside[0][k] for k in names}
            span.update(start_unix_us=inside[0]["unix_us"],end_unix_us=inside[-1]["unix_us"])
        quarters.append(dict(start_unix_us=low,end_unix_us=high,scheduler_samples=len(choices),
                             selected_path_samples=counts,observed_wire_bytes=span))
    return dict(first_body_unix_us=start,complete_unix_us=end,response_duration_ns=client["response_duration_ns"],
                scheduler_samples_in_response=len(selected),observation_quarters=quarters)


def analyze(directory):
    data=[]
    with (directory/"mpquic-exit.log").open() as stream:
        for line in stream:
            if line.startswith("NATIVE_EDT_SAMPLE "):
                data.append(json.loads(line.split(" ",1)[1]))
                require(len(data) <= 1024, "oversized native diagnostic")
    records={case:record(directory,case,data) for case in ("single","aggregate")}
    require(records["single"]["complete_unix_us"] < records["aggregate"]["first_body_unix_us"],"overlapping independent flows")
    return dict(schema_version=1,source="guest HTTP/3 receive clock, Exit EDT and independently observed Client WireGuard bytes",
                records=records)


if __name__ == "__main__":
    try:
        print(json.dumps(analyze(Path(sys.argv[1])), sort_keys=True, indent=2))
    except (KeyError,OSError,TypeError,ValueError):
        sys.exit("Mixed-link response observations incomplete")
