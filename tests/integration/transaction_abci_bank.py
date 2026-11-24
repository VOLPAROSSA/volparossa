# SPDX-License-Identifier: GPL-3.0-only
"""Use the real Bank owner interface from a separate unprivileged, offline process."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat

OWNER_UID = 21004
SOURCE = Path(__file__).with_name("transaction-abci-bank-revision")


def source_revision():
    revision = SOURCE.read_text().strip()
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("invalid_bank_source")
    return revision


def stage_binary(source, destination, expected_sha, owner_uid):
    """Copy a bounded ordinary file once. Only the verified root-owned copy can execute."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as input_file:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != owner_uid or metadata.st_mode & 0o022
                or not 0 < metadata.st_size <= 32 * 1024 * 1024):
            raise ValueError("bank_binary_input")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        with destination.open("xb") as output:
            while remaining:
                block = input_file.read(min(remaining, 65536))
                if not block:
                    raise ValueError("bank_binary_length")
                output.write(block)
                digest.update(block)
                remaining -= len(block)
            if input_file.read(1) or digest.hexdigest() != expected_sha:
                raise ValueError("bank_binary_digest")
            os.fchmod(output.fileno(), 0o555)


class Owner:
    def __init__(self, work, ledger, checked, require):
        self.root = work / "bank-owner"
        self.binary = work / "bin/ordered_authorizer"
        self.ledger = ledger
        self.checked = checked
        self.require = require
        try:
            pwd.getpwuid(OWNER_UID)
        except KeyError:
            pass
        else:
            require(False, "bank_owner_uid_in_use")
        self.root.mkdir(mode=0o700)
        os.chown(self.root, OWNER_UID, OWNER_UID)
        genesis = (work / "node0/app.json").read_bytes()
        require(self.command("init", (), genesis) == b"ready\n", "bank_owner_genesis")

    def command(self, action, arguments, data=None):
        # The owner receives only the public genesis or an explicitly supplied TEST seed over stdin.
        return self.checked(["unshare", "--net", "--", "setpriv", "--reuid", str(OWNER_UID), "--regid",
                             str(OWNER_UID), "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                             "--bounding-set=-all", "--no-new-privs", "--", str(self.binary), action,
                             str(self.root), self.ledger, *arguments], input_bytes=data)

    def prepare(self, action, operation, start, end, terms, seed):
        value = self.command(action, (operation, str(start), str(end), *terms), seed)
        self.require(0 < len(value) <= 4096, "bank_command_length")
        return value

    def replay(self, operation, original):
        value = self.command("replay", (operation,))
        self.require(value == original, "bank_reopened_bytes_changed")
        return value


def valid_cancellation(observed, replay):
    if not isinstance(observed, dict) or set(observed) != {"released_units", "receipts", "reopened_sha256", "retry_height"}:
        return False
    receipts = observed["receipts"]
    if not isinstance(receipts, list) or len(receipts) != 2:
        return False
    fields = {"operation_id", "reservation_id", "command_sha256", "sequence", "state", "consensus_certificate"}
    if any(not isinstance(r, dict) or set(r) != fields for r in receipts):
        return False
    reserve, cancel = receipts
    return (all(isinstance(r[f], str) and re.fullmatch("[a-f0-9]{64}", r[f]) for r in receipts
                for f in ("operation_id", "reservation_id", "command_sha256"))
            and observed["released_units"] == 10 and [r["sequence"] for r in receipts] == [3, 4]
            and reserve["state"] == "Reserved" and cancel["state"] == "Cancelled"
            and reserve["operation_id"] == reserve["reservation_id"] == cancel["reservation_id"] != cancel["operation_id"]
            and reserve["command_sha256"] != cancel["command_sha256"] == observed["reopened_sha256"]
            and all(r["consensus_certificate"] is False for r in receipts)
            and type(observed["retry_height"]) is int
            and replay["retry_start_height"] < observed["retry_height"] < replay["height"])


def validate_receipt(receipt, expected_sha, checks):
    if not isinstance(receipt, dict) or set(receipt) != {"source_revision", "authorizer_sha256",
            "genesis_ledger", "seed_removed", "reserve_sha256", "commit_sha256", "reopened_without_seed", "cancellation"}:
        return False
    keys = ["genesis_ledger", "reserve_sha256", "commit_sha256"]
    return (bool(re.fullmatch("[a-f0-9]{64}", expected_sha))
            and receipt["source_revision"] == source_revision() and receipt["authorizer_sha256"] == expected_sha
            and receipt["seed_removed"] is True and receipt["reopened_without_seed"] is True
            and valid_cancellation(receipt["cancellation"], checks["crash_replay"])
            and all(isinstance(receipt[k], str) and re.fullmatch("[0-9a-f]{64}", receipt[k]) for k in keys)
            and checks["startup"].get("bank_genesis_ledger") == receipt["genesis_ledger"]
            and receipt["reserve_sha256"] != receipt["commit_sha256"]
            and checks["commit"].get("bank_command_sha256") == [receipt["reserve_sha256"], receipt["commit_sha256"]]
            and checks["crash_replay"].get("bank_command_sha256") == checks["commit"]["bank_command_sha256"])
