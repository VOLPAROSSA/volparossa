#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable B-broker-only CPU PSI floor, never a measurement of actual load."""
import hashlib
import copy
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time

TARGET = "/proc/pressure/cpu"
METHOD = "private-broker-cpu-pressure-floor-v1"


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(pid):
    value = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(value[0] not in ("Z", "X"), "pressure owner is no longer live")
    return dict(pid=pid, start_ticks=int(value[19]))


def live(member):
    try:
        return identity(member["pid"]) == member
    except (OSError, ValueError):
        return False


def inode(path):
    info = Path(path).stat()
    return [info.st_dev, info.st_ino]


def namespace(pid):
    return os.readlink(f"/proc/{pid}/ns/mnt")


def work_path_shape(work):
    # kvm-alpha-topology.sh creates /opt/va.<32 lowercase UUID hex>.<mktemp suffix>.
    return work.parent == Path("/opt") and re.fullmatch(
        r"va\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", work.name) is not None


def guard(work):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
        and subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and work_path_shape(work)
        and work.resolve() == work and work.stat().st_uid == 0,
        "pressure injection requires the original disposable root-owned KVM work area")


def pressure_text(raw):
    """100 is max(real CPU some.avg10, 100) for every valid kernel percentage."""
    require(0 < len(raw) <= 4096, "CPU pressure text bound")
    text = raw.decode("ascii")
    matches = list(re.finditer(r"(?m)^some avg10=([0-9]+\.[0-9]+)( avg60=[0-9.]+ avg300=[0-9.]+ total=[0-9]+)$", text))
    require(len(matches) == 1 and 0 <= float(matches[0][1]) <= 100, "invalid kernel CPU pressure")
    start, end = matches[0].span(1)
    return (text[:start] + "100.00" + text[end:]).encode("ascii")


def covering_mounts(raw):
    require(len(raw) <= 1048576, "mountinfo bound")
    entries = []
    for line in raw.decode("ascii").splitlines():
        left, right = line.split(" - ", 1)
        parts = left.split(); trailing = right.split()
        require(len(parts) >= 6 and len(trailing) >= 3, "invalid mountinfo")
        target = parts[4]
        if target == "/" or TARGET == target or TARGET.startswith(target.rstrip("/") + "/"):
            require(not any(flag.startswith("shared:") for flag in parts[6:]),
                "CPU covering mount could propagate to another namespace")
            entries.append(dict(id=int(parts[0]), parent=int(parts[1]), root=parts[3],
                target=target, options=parts[5], propagation=parts[6:], filesystem=trailing[0]))
    require(entries and any(item["target"] == "/proc" and item["filesystem"] == "proc" for item in entries),
        "missing private proc mount")
    return entries


def view(member):
    require(live(member), "broker identity changed")
    pid = member["pid"]
    result = dict(process=member, namespace=namespace(pid),
        cpu_inode=inode(f"/proc/{pid}/root{TARGET}"),
        mounts=covering_mounts(Path(f"/proc/{pid}/mountinfo").read_bytes()))
    require(live(member), "broker changed during mount observation")
    return result


def check_isolation(guest, brokers, slow):
    require(slow in brokers and len(brokers) >= 2, "missing original broker cohort")
    selected = brokers[slow]["namespace"]
    require(selected != guest["namespace"] and all(selected != item["namespace"]
        for name, item in brokers.items() if name != slow), "B does not own a distinct mount namespace")
    require(not any(item["target"] == TARGET for item in brokers[slow]["mounts"]),
        "CPU pressure already has a dedicated mount")


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= 65536, "pressure record bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def load(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, "unsafe pressure record")
        return json.loads(stream.read(65537))


def unchanged(plan):
    require(namespace(1) == plan["guest"]["namespace"] and inode(TARGET) == plan["guest"]["cpu_inode"],
        "guest CPU pressure mount changed")
    for name, original in plan["brokers"].items():
        if name != plan["slow"]:
            current = view(original["process"])
            require(current == original, "another broker's pressure mount changed")


def with_namespace(plan, operation):
    member = plan["brokers"][plan["slow"]]["process"]
    require(live(member), "original B broker is no longer live")
    descriptor = os.open(f"/proc/{member['pid']}/ns/mnt", os.O_RDONLY)
    try:
        require(live(member) and os.readlink(f"/proc/self/fd/{descriptor}") == plan["brokers"][plan["slow"]]["namespace"],
            "original private B namespace changed")
        return operation(descriptor)
    finally:
        os.close(descriptor)


def invoke(descriptor, *arguments, extra_fds=()):
    subprocess.run(["nsenter", f"--mount=/proc/self/fd/{descriptor}", "--", *arguments],
        check=True, timeout=10, stdin=subprocess.DEVNULL, pass_fds=(descriptor, *extra_fds))


def install(work, brokers, slow):
    guard(work)
    # Verify root's namespace, not merely its view of PID 1's proc tree.
    require(namespace(os.getpid()) == namespace(1), "observer is outside the guest root namespace")
    guest = dict(namespace=namespace(1), cpu_inode=inode(TARGET))
    actual = {}
    for name in ("relay3", "relay4", "relay5"):
        unit = f"volparossa-alpha-compute@{name}.service"
        state = subprocess.check_output(["systemctl", "show", "--property=LoadState", "--value", unit], text=True).strip()
        if state == "not-found":
            continue
        require(state == "loaded", "unexpected disposable broker unit state")
        pid = int(subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
            unit], text=True).strip())
        if pid:
            actual[name] = identity(pid)
    require(actual == brokers, "the recorded cohort does not cover every disposable peer broker")
    observed = {name: view(member) for name, member in brokers.items()}
    check_isolation(guest, observed, slow)
    directory = work / "agent-ready-dag-pressure"
    directory.mkdir(mode=0o700)
    source = directory / "cpu"
    raw = Path(f"/proc/{brokers[slow]['pid']}/root{TARGET}").read_bytes()
    injected = pressure_text(raw)
    descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(injected); stream.flush(); os.fsync(stream.fileno())
    plan = dict(version=1, method=METHOD, floor_percent=100, real_load_claimed=False,
        slow=slow, guest=guest, brokers=observed, source_inode=inode(source),
        original_text_hex=raw.hex(), injected_text_hex=injected.hex(), injected_sha256=digest(injected),
        boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
    # Written before any mount; the existing cleanup hook can recover partial setup.
    save(work / "agent-ready-dag-pressure-plan.json", plan)
    print("Disposable guest only: bind a labelled CPU PSI 100% floor onto B's already-private /proc/pressure/cpu; no shared-mount changes.", flush=True)
    def bind(namespace_fd):
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(inode(f"/proc/self/fd/{source_fd}") == plan["source_inode"], "pressure source replaced")
            invoke(namespace_fd, "mount", "--bind", f"/proc/self/fd/{source_fd}", TARGET, extra_fds=(source_fd,))
            invoke(namespace_fd, "mount", "-o", "remount,bind,ro", TARGET)
        finally:
            os.close(source_fd)
    with_namespace(plan, bind)
    installed = inspect(work, plan)
    save(work / "agent-ready-dag-pressure-installed.json", installed)
    return dict(plan=plan, installed=installed)


def inspect(work, plan):
    guard(work); unchanged(plan)
    selected = view(plan["brokers"][plan["slow"]]["process"])
    exact = [entry for entry in selected["mounts"] if entry["target"] == TARGET]
    require(len(exact) == 1 and "ro" in exact[0]["options"].split(",")
        and selected["namespace"] == plan["brokers"][plan["slow"]]["namespace"]
        and selected["cpu_inode"] == plan["source_inode"], "original exact private CPU floor is not active")
    raw = Path(f"/proc/{selected['process']['pid']}/root{TARGET}").read_bytes()
    require(raw.hex() == plan["injected_text_hex"] and digest(raw) == plan["injected_sha256"], "CPU floor bytes changed")
    saved = work / "agent-ready-dag-pressure-installed.json"
    if saved.exists():
        require(selected == load(saved)["broker"], "recorded CPU mount identity changed")
    return dict(broker=selected, other_brokers_unchanged=True, guest_unchanged=True,
        boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))


def release(work, cleanup=False):
    guard(work)
    path = work / "agent-ready-dag-pressure-plan.json"
    if not path.exists():
        return None
    plan = load(path); restored_path = work / "agent-ready-dag-pressure-restored.json"
    if restored_path.exists():
        member = plan["brokers"][plan["slow"]]["process"]
        require(not (work / "agent-ready-dag-pressure").exists(), "restored pressure source reappeared")
        if live(member):
            require(view(member) == plan["brokers"][plan["slow"]], "restored CPU mount changed")
        return load(restored_path)
    member = plan["brokers"][plan["slow"]]["process"]
    if not live(member):
        require(cleanup, "B disappeared before its exact pressure mount could be restored")
        processes = list(Path("/proc").glob("[0-9]*"))
        require(len(processes) <= 8192, "namespace disappearance scan bound")
        for proc in processes:
            try:
                present = namespace(int(proc.name))
            except FileNotFoundError:
                continue
            require(present != plan["brokers"][plan["slow"]]["namespace"], "original CPU mount namespace still has an owner")
        source = work / "agent-ready-dag-pressure/cpu"
        require(inode(source) == plan["source_inode"], "refusing to remove another pressure source")
        source.unlink(); source.parent.rmdir()
        result = dict(disposition="original_broker_and_namespace_gone", source_removed=True,
            boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        save(restored_path, result)
        return result
    current = view(member); original = plan["brokers"][plan["slow"]]
    unmount_started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if current["cpu_inode"] == plan["source_inode"]:
        exact = [entry for entry in current["mounts"] if entry["target"] == TARGET]
        require(len(exact) == 1 and current["namespace"] == original["namespace"], "refusing to unmount another CPU mount")
        saved = work / "agent-ready-dag-pressure-installed.json"
        if saved.exists():
            require(current == load(saved)["broker"], "refusing to unmount a replaced CPU mount")
        print("Disposable guest only: unmount the exact recorded B-only CPU floor; restore real kernel PSI and the normal quiet hold.", flush=True)
        with_namespace(plan, lambda fd: invoke(fd, "umount", "--", TARGET))
    else:
        require(current == original, "partial pressure setup changed an unrelated mount")
    restored = view(member); unchanged(plan)
    require(restored == original, "original kernel CPU pressure inode/mount was not restored")
    raw = Path(f"/proc/{member['pid']}/root{TARGET}").read_bytes()
    pressure_text(raw)  # Validate a real PSI sample, never replace it with synthetic quiet.
    result = dict(broker=restored, real_pressure_hex=raw.hex(), real_pressure_sha256=digest(raw),
        other_brokers_unchanged=True, guest_unchanged=True, source_removed=True,
        unmount_started_boottime_ns=unmount_started,
        boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
    source = work / "agent-ready-dag-pressure/cpu"
    require(inode(source) == plan["source_inode"], "refusing to remove another floor file")
    source.unlink(); source.parent.rmdir()
    save(restored_path, result)
    return result


def validate(pressure, held, restored):
    plan, installed = pressure["plan"], pressure["installed"]
    require(plan["version"] == 1 and plan["method"] == METHOD and plan["floor_percent"] == 100
        and plan["real_load_claimed"] is False, "unlabelled pressure injection")
    check_isolation(plan["guest"], plan["brokers"], plan["slow"])
    require(held["broker"] == installed["broker"] and plan["source_inode"] != plan["guest"]["cpu_inode"]
        and plan["source_inode"] != plan["brokers"][plan["slow"]]["cpu_inode"], "CPU floor mount identity changed")
    original = bytes.fromhex(plan["original_text_hex"]); raw = bytes.fromhex(plan["injected_text_hex"])
    require(pressure_text(original) == raw and digest(raw) == plan["injected_sha256"], "wrong CPU floor source")
    for item in (installed, held):
        require(item["guest_unchanged"] is True and item["other_brokers_unchanged"] is True
            and item["broker"]["process"] == plan["brokers"][plan["slow"]]["process"]
            and item["broker"]["namespace"] == plan["brokers"][plan["slow"]]["namespace"]
            and item["broker"]["cpu_inode"] == plan["source_inode"], "private CPU floor identity differs")
        mounts = item["broker"]["mounts"]
        require(sum(entry["target"] == TARGET for entry in mounts) == 1
            and all(not any(flag.startswith("shared:") for flag in entry["propagation"]) for entry in mounts)
            and any(entry["target"] == TARGET and "ro" in entry["options"].split(",") for entry in mounts),
            "CPU floor mount was not readonly/private")
    raw = bytes.fromhex(restored["real_pressure_hex"]); pressure_text(raw)
    require(restored["broker"] == plan["brokers"][plan["slow"]]
        and restored["real_pressure_sha256"] == digest(raw) and restored["guest_unchanged"] is True
        and restored["other_brokers_unchanged"] is True and restored["source_removed"] is True
        and plan["boottime_ns"] <= installed["boottime_ns"] <= held["boottime_ns"]
            < restored["unmount_started_boottime_ns"] <= restored["boottime_ns"],
        "kernel CPU pressure was not exactly restored after C")


def self_test():
    run_id = "0123456789abcdef" * 2
    for suffix in ("abc123", "ABCdef", "09azAZ"):
        assert work_path_shape(Path(f"/opt/va.{run_id}.{suffix}"))
    for invalid in (
        f"/tmp/va.{run_id}.abc123", f"opt/va.{run_id}.abc123",
        f"/opt/nested/va.{run_id}.abc123", f"/opt/../opt/va.{run_id}.abc123",
        "/opt/va.abc123", f"/opt/va.{run_id}",
        f"/opt/va.{run_id[:-1]}.abc123", f"/opt/va.{run_id}0.abc123",
        f"/opt/va.{run_id.upper()}.abc123", f"/opt/va.{run_id}.abc12",
        f"/opt/va.{run_id}.abc1234", f"/opt/va.{run_id}.abc_12",
        f"/opt/va.{run_id}.abc123\n", f"/opt/va.{run_id}.abc.12",
    ):
        assert not work_path_shape(Path(invalid)), invalid
    raw = b"some avg10=6.21 avg60=4.10 avg300=3.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
    assert pressure_text(raw) == raw.replace(b"avg10=6.21", b"avg10=100.00")
    mounts = b"1 0 0:1 / / rw - ext4 /dev/x rw\n2 1 0:2 / /proc rw master:1 - proc proc rw\n"
    assert len(covering_mounts(mounts)) == 2
    for invalid in (raw.replace(b"6.21", b"100.01"), raw.replace(b"some", b"unknown"), b"", raw + raw):
        try: pressure_text(invalid)
        except ValueError: pass
        else: raise AssertionError("invalid PSI accepted")
    for invalid in (mounts.replace(b"master:1", b"shared:2 master:1"), mounts.replace(b"rw - ext4", b"rw shared:1 - ext4")):
        try: covering_mounts(invalid)
        except ValueError: pass
        else: raise AssertionError("propagating mount accepted")
    base = dict(namespace="mnt:[2]", mounts=covering_mounts(mounts))
    check_isolation(dict(namespace="mnt:[1]"), dict(a=dict(base, namespace="mnt:[3]"), b=base), "b")
    for guest, other in (("mnt:[2]", "mnt:[3]"), ("mnt:[1]", "mnt:[2]")):
        try: check_isolation(dict(namespace=guest), dict(a=dict(base, namespace=other), b=base), "b")
        except ValueError: pass
        else: raise AssertionError("shared broker namespace accepted")
    original = dict(base, process=dict(pid=12, start_ticks=5), cpu_inode=[3, 4])
    source_inode = [9, 10]
    mounted = dict(original, cpu_inode=source_inode, mounts=original["mounts"] + [dict(id=3, parent=2,
        root="/cpu", target=TARGET, options="ro", propagation=[], filesystem="ext4")])
    plan = dict(version=1, method=METHOD, floor_percent=100, real_load_claimed=False, slow="b",
        guest=dict(namespace="mnt:[1]", cpu_inode=[3, 4]), brokers=dict(b=original,
            a=dict(original, namespace="mnt:[3]", process=dict(pid=11, start_ticks=4))),
        source_inode=source_inode, original_text_hex=raw.hex(), injected_text_hex=pressure_text(raw).hex(),
        injected_sha256=digest(pressure_text(raw)), boottime_ns=1)
    installed = dict(broker=mounted, other_brokers_unchanged=True, guest_unchanged=True, boottime_ns=2)
    held = dict(installed, boottime_ns=3)
    restored = dict(broker=original, real_pressure_hex=raw.hex(), real_pressure_sha256=digest(raw),
        other_brokers_unchanged=True, guest_unchanged=True, source_removed=True,
        unmount_started_boottime_ns=4, boottime_ns=5)
    proof = dict(plan=plan, installed=installed)
    validate(proof, held, restored)
    mutations = (
        lambda p,h,r:p["plan"].update(real_load_claimed=True),
        lambda p,h,r:p["plan"].update(floor_percent=20),
        lambda p,h,r:p["plan"].update(injected_sha256="0"*64),
        lambda p,h,r:h["broker"].update(namespace="mnt:[1]"),
        lambda p,h,r:h["broker"].update(cpu_inode=[20,21]),
        lambda p,h,r:h["broker"]["mounts"][-1].update(propagation=["shared:1"]),
        lambda p,h,r:h["broker"]["mounts"][-1].update(options="rw"),
        lambda p,h,r:r.update(guest_unchanged=False),
        lambda p,h,r:r.update(source_removed=False),
        lambda p,h,r:r.update(real_pressure_sha256="0"*64),
        lambda p,h,r:r.update(unmount_started_boottime_ns=3))
    for mutate in mutations:
        candidate, current, final = copy.deepcopy(proof), copy.deepcopy(held), copy.deepcopy(restored)
        mutate(candidate, current, final)
        try: validate(candidate, current, final)
        except ValueError: pass
        else: raise AssertionError("invalid floor identity/restoration accepted")
    print("ready-DAG work-path/pressure/isolation/restoration controls PASS (3 valid paths, 33 negatives); no mount or namespace execution")
    return proof, held, restored


if __name__ == "__main__":
    require(sys.argv[1:] == ["self-test"], "only the pure self-test is directly executable")
    self_test()
