#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite, diagnostic-only KVM observations for the disposable Android owner.

Callers must first establish the existing hosted identity. Numeric identities,
device metadata and groups remain in memory or in the owner's private baseline;
only comparisons and fixed access/error categories may leave that boundary.
No ACL changes, sudo, VM creation, ioctl, device IO or privilege changes.
"""
import errno
import grp
import os
import pwd
import re
import stat
import struct

PREFIX = "VOLPAROSSA_ANDROID_KVM_OBSERVATION "
NAME = "weather-android-kvm-observation.json"
DEVICE = "/dev/kvm"
STATES = frozenset(("character", "missing", "symlink", "other", "unavailable"))
OPEN = frozenset(("opened", "eacces", "eperm", "enoent", "enodev", "ebusy", "other",
    "not_attempted", "device_changed"))
BOOLS = ("root_owned", "real_read", "real_write", "effective_read", "effective_write")
COMPARISONS = ("same_identity", "same_groups", "same_device", "same_mode", "same_device_owner")
ACL_BOOLS = ("private_primary_group", "named_group_read", "named_group_write", "mask_read", "mask_write")


def require(condition):
    if not condition: raise ValueError("KVM_OBSERVATION_REJECTED")


def identity(value):
    require(type(value) is dict and set(value) == {"core_commit", "weather_commit", "run_id", "run_attempt"})
    require(all(type(value[k]) is str and re.fullmatch("[0-9a-f]{40}", value[k])
        for k in ("core_commit", "weather_commit")))
    require(all(type(value[k]) is str and re.fullmatch("[1-9][0-9]{0,19}", value[k])
        for k in ("run_id", "run_attempt")))


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_rdev, info.st_mode, info.st_uid, info.st_gid]


def private_primary_group():
    """Admit only the ordinary runner's existing, otherwise unused primary group.

    This is inspection, not group membership modification. Ambiguous NSS data
    fails closed. The numeric result is private input to the fixed ACL command.
    """
    uid, gid = os.getuid(), os.getgid()
    require(uid > 0 and gid > 0 and os.getresuid() == (uid,) * 3 and os.getresgid() == (gid,) * 3)
    device = os.lstat(DEVICE)
    require(stat.S_ISCHR(device.st_mode) and device.st_uid == 0)
    account, group, accounts, groups = pwd.getpwuid(uid), grp.getgrgid(gid), pwd.getpwall(), grp.getgrall()
    require(account.pw_uid == uid and account.pw_gid == gid and group.gr_gid == gid
        and type(account.pw_name) is str and account.pw_name
        and type(group.gr_name) is str and group.gr_name
        and len(group.gr_mem) <= 256 and set(group.gr_mem) <= {account.pw_name}
        and 1 <= len(accounts) <= 4096 and 1 <= len(groups) <= 4096)
    same_group = [entry for entry in accounts if entry.pw_gid == gid]
    require(len(same_group) == 1 and same_group[0].pw_uid == uid and same_group[0].pw_name == account.pw_name)
    aliases = [entry for entry in groups if entry.gr_gid == gid]
    require(len(aliases) == 1 and aliases[0].gr_name == group.gr_name and aliases[0].gr_mem == group.gr_mem)
    return gid


def grant_primary_group():
    """Refuse any existing extended ACL before setfacl can recompute its mask.

    With only the basic mode ACL, adding one named group cannot unmask other
    named users/groups. Existing ACLs are not rewritten or simplified here.
    """
    gid = private_primary_group()
    before = os.lstat(DEVICE)
    require(stat.S_ISCHR(before.st_mode) and before.st_uid == 0)
    try:
        os.getxattr(DEVICE, "system.posix_acl_access", follow_symlinks=False)
    except OSError as error:
        require(error.errno == errno.ENODATA and metadata(before) == metadata(os.lstat(DEVICE)))
        return gid
    raise ValueError("KVM_EXTENDED_ACL_REJECTED")


def acl_projection(raw, gid):
    """Decode Linux's bounded POSIX ACL xattr, retaining no IDs or ACL text.

    The format is linux/posix_acl_xattr.h: version 2, followed by <tag,perm,id>.
    Require a complete, unambiguous access ACL before reporting group rights.
    """
    require(type(raw) is bytes and 4 <= len(raw) <= 8192 and (len(raw) - 4) % 8 == 0
        and struct.unpack_from("<I", raw)[0] == 2)
    entries = {}
    for tag, permissions, identifier in struct.iter_unpack("<HHI", raw[4:]):
        require(tag in (1, 2, 4, 8, 16, 32) and permissions <= 7
            and ((identifier == 0xffffffff) is (tag in (1, 4, 16, 32)))
            and (tag, identifier) not in entries)
        entries[tag, identifier] = permissions
    require(all((tag, 0xffffffff) in entries for tag in (1, 4, 16, 32)))
    group, mask = entries.get((8, gid), 0), entries[16, 0xffffffff]
    return dict(named_group_read=bool(group & 4), named_group_write=bool(group & 2),
        mask_read=bool(mask & 4), mask_write=bool(mask & 2))


def group_acl():
    """Diagnostic-only read of the exact device's current named-group grant."""
    result = dict(state="unavailable", **dict.fromkeys(ACL_BOOLS))
    try:
        gid = private_primary_group()
        result["private_primary_group"] = True
        before = os.lstat(DEVICE)
        raw = os.getxattr(DEVICE, "system.posix_acl_access", follow_symlinks=False)
        require(metadata(before) == metadata(os.lstat(DEVICE)))
        result.update(acl_projection(raw, gid)); result["state"] = "observed"
    except (KeyError, ValueError, TypeError, struct.error): result["state"] = "rejected"
    except OSError as error:
        if error.errno == errno.ENODATA: result["state"] = "absent"
    return validate_acl(result)


def validate_acl(value):
    require(type(value) is dict and set(value) == {"state", *ACL_BOOLS}
        and value["state"] in ("observed", "absent", "rejected", "unavailable"))
    require(all(value[key] is None or type(value[key]) is bool for key in ACL_BOOLS))
    if value["state"] == "observed": require(all(type(value[key]) is bool for key in ACL_BOOLS))
    return value


def group_usable(value):
    validate_acl(value)
    return value["state"] == "observed" and all(value[key] is True for key in ACL_BOOLS)


def snapshot():
    """Private result. Open/close checks permission only; never read/write/ioctl."""
    value = dict(credentials=None, groups=None, device=None, state="unavailable",
        open_result="not_attempted", **dict.fromkeys(BOOLS))
    try:
        value["credentials"] = [*os.getresuid(), *os.getresgid()]
        groups = sorted(set(os.getgroups()))
        if len(groups) <= 256: value["groups"] = groups
    except OSError: pass
    try:
        info = os.lstat(DEVICE)
        value["device"] = metadata(info)
        value["state"] = ("character" if stat.S_ISCHR(info.st_mode) else
            "symlink" if stat.S_ISLNK(info.st_mode) else "other")
        value["root_owned"] = info.st_uid == 0
    except FileNotFoundError:
        value["state"] = "missing"
        return value
    except OSError:
        return value
    # A changed/symlink/non-device target is not opened, even for diagnostics.
    if value["state"] != "character" or not value["root_owned"]: return value
    for key, mode, effective in (("real_read", os.R_OK, False), ("real_write", os.W_OK, False),
            ("effective_read", os.R_OK, True), ("effective_write", os.W_OK, True)):
        try: value[key] = os.access(DEVICE, mode, effective_ids=effective, follow_symlinks=False)
        except (OSError, NotImplementedError): pass
    descriptor = None
    try:
        descriptor = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        current = metadata(os.fstat(descriptor))
        value["open_result"] = "opened" if current == value["device"] else "device_changed"
    except OSError as error:
        value["open_result"] = {errno.EACCES: "eacces", errno.EPERM: "eperm", errno.ENOENT: "enoent",
            errno.ENODEV: "enodev", errno.EBUSY: "ebusy"}.get(error.errno, "other")
    finally:
        if descriptor is not None:
            try: os.close(descriptor)
            except OSError: value["open_result"] = "other"
    return value


def validate_private(value):
    require(type(value) is dict and set(value) == {"credentials", "groups", "device", "state", "open_result", *BOOLS})
    require(type(value["state"]) is str and value["state"] in STATES
        and type(value["open_result"]) is str and value["open_result"] in OPEN)
    for key in BOOLS: require(value[key] is None or type(value[key]) is bool)
    for key, maximum, length in (("credentials", 2**32 - 1, 6), ("device", 2**64 - 1, 6), ("groups", 2**32 - 1, None)):
        row = value[key]
        require(row is None or type(row) is list and len(row) <= 256
            and (length is None or len(row) == length)
            and all(type(item) is int and 0 <= item <= maximum for item in row))
    if value["groups"] is not None: require(value["groups"] == sorted(set(value["groups"])))
    return value


def project(value, baseline=None):
    validate_private(value)
    if baseline is not None: validate_private(baseline)
    def compare(key, indices=None):
        left, right = value[key], None if baseline is None else baseline[key]
        if left is None or right is None: return None
        return left == right if indices is None else all(left[i] == right[i] for i in indices)
    return validate_projection(dict(state=value["state"], open_result=value["open_result"],
        **{key: value[key] for key in BOOLS}, same_identity=compare("credentials"),
        same_groups=compare("groups"), same_device=compare("device", (0, 1, 2)),
        same_mode=compare("device", (3,)), same_device_owner=compare("device", (4, 5))))


def validate_projection(value):
    require(type(value) is dict and set(value) == {"state", "open_result", *BOOLS, *COMPARISONS})
    require(type(value["state"]) is str and value["state"] in STATES
        and type(value["open_result"]) is str and value["open_result"] in OPEN)
    for key in (*BOOLS, *COMPARISONS): require(value[key] is None or type(value[key]) is bool)
    return value


def usable(value):
    validate_private(value)
    return value["credentials"] is not None and value["groups"] is not None \
        and value["state"] == "character" and value["open_result"] == "opened" and all(value[k] is True for k in BOOLS)


def baseline_record(selected_identity, value):
    identity(selected_identity); validate_private(value)
    return dict(schema=1, kind="weather-android-private-kvm-baseline", identity=selected_identity, snapshot=value)


def baseline(value, selected_identity):
    identity(selected_identity)
    require(type(value) is dict and set(value) == {"schema", "kind", "identity", "snapshot"})
    require(type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "weather-android-private-kvm-baseline" and value["identity"] == selected_identity)
    return validate_private(value["snapshot"])


def continuity_baseline_record(selected_identity, value, acl):
    identity(selected_identity); validate_private(value); validate_acl(acl)
    require(usable(value) and group_usable(acl))
    return dict(schema=1, kind="weather-android-private-kvm-continuity", identity=selected_identity,
        snapshot=value, acl=acl)


def continuity_baseline(value, selected_identity):
    require(type(value) is dict and set(value) == {"schema", "kind", "identity", "snapshot", "acl"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "weather-android-private-kvm-continuity" and value["identity"] == selected_identity)
    require(value == continuity_baseline_record(selected_identity, value["snapshot"], value["acl"]))
    return value


def native_record(selected_identity, before, initial, baseline_state, at_failure=None):
    return validate_native(dict(schema=1, kind="weather-android-native-kvm-observation", identity=selected_identity,
        baseline_state=baseline_state, before_main=project(before, initial),
        at_kvm_guard_failure=None if at_failure is None else project(at_failure, initial),
        diagnostic_only=True, joined_core_acceptance=False))


def validate_native(value):
    require(type(value) is dict and set(value) == {"schema", "kind", "identity", "baseline_state",
        "before_main", "at_kvm_guard_failure", "diagnostic_only", "joined_core_acceptance"})
    require(type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "weather-android-native-kvm-observation")
    identity(value["identity"])
    require(value["baseline_state"] in ("available", "absent", "rejected")
        and value["diagnostic_only"] is True and value["joined_core_acceptance"] is False)
    validate_projection(value["before_main"])
    if value["at_kvm_guard_failure"] is not None: validate_projection(value["at_kvm_guard_failure"])
    if value["baseline_state"] != "available":
        for point in (value["before_main"], value["at_kvm_guard_failure"]):
            if point is not None: require(all(point[key] is None for key in COMPARISONS))
    return value


def receipt(selected_identity, phase, before, native_state="absent", native=None):
    return validate_receipt(dict(schema=1, kind="weather-android-kvm-observation", identity=selected_identity,
        phase=phase, owner_before_publication=project(before, before),
        native=dict(state=native_state, record=native), diagnostic_only=True,
        joined_core_acceptance=False, physical_device=False, production_authority=False))


def continuity_receipt(selected_identity, current, acl, baseline_state, initial=None,
        native_state="absent", native=None, *, phase="owner"):
    """Schema 2 binds the actual pre-QEMU baseline, never a self-comparison."""
    identity(selected_identity); validate_acl(acl)
    if initial is not None: continuity_baseline(initial, selected_identity)
    snapshot = None if initial is None else initial["snapshot"]
    result = dict(schema=2, kind="weather-android-kvm-observation", identity=selected_identity, phase=phase,
        baseline_state=baseline_state, before_qemu=None if snapshot is None else project(snapshot),
        acl_before_qemu=None if initial is None else initial["acl"],
        owner_before_publication=project(current, snapshot), acl_before_publication=acl,
        native=dict(state=native_state, record=native), diagnostic_only=True,
        joined_core_acceptance=False, physical_device=False, production_authority=False)
    return validate_receipt(result)


def validate_receipt(value):
    fields = {"schema", "kind", "identity", "phase", "owner_before_publication", "native",
        "diagnostic_only", "joined_core_acceptance", "physical_device", "production_authority"}
    require(type(value) is dict and type(value.get("schema")) is int and value["schema"] in (1, 2))
    if value["schema"] == 2:
        fields |= {"baseline_state", "before_qemu", "acl_before_qemu", "acl_before_publication"}
    require(set(value) == fields and value["kind"] == "weather-android-kvm-observation")
    identity(value["identity"]); require(value["phase"] in ("preflight", "owner"))
    require(value["diagnostic_only"] is True and all(value[k] is False
        for k in ("joined_core_acceptance", "physical_device", "production_authority")))
    validate_projection(value["owner_before_publication"])
    if value["schema"] == 2:
        require(value["baseline_state"] in ("available", "absent", "rejected"))
        if value["phase"] == "preflight":
            require(value["baseline_state"] == "absent" and value["native"] == dict(state="absent", record=None))
        validate_acl(value["acl_before_publication"])
        if value["baseline_state"] == "available":
            validate_projection(value["before_qemu"]); validate_acl(value["acl_before_qemu"])
            require(value["before_qemu"]["state"] == "character" and value["before_qemu"]["open_result"] == "opened"
                and all(value["before_qemu"][key] is True for key in BOOLS)
                and all(value["before_qemu"][key] is None for key in COMPARISONS)
                and group_usable(value["acl_before_qemu"]))
        else:
            require(value["before_qemu"] is None and value["acl_before_qemu"] is None
                and all(value["owner_before_publication"][key] is None for key in COMPARISONS))
    row = value["native"]
    require(type(row) is dict and set(row) == {"state", "record"}
        and row["state"] in ("available", "absent", "rejected"))
    if row["state"] == "available":
        validate_native(row["record"]); require(row["record"]["identity"] == value["identity"])
    else: require(row["record"] is None)
    return value
