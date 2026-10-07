#!/usr/bin/env python3
"""Guest-only real four-validator Comet/ABCI TEST trial, never financial settlement.

The default is an inert plan. Execution requires the existing disposable KVM
guest, explicit flags and source-built binaries. All network objects live in
new owned namespaces; there is no link to the guest's original namespace.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

COMET_COMMIT = "0880b4d378f347ab16e54ec677ff50d803f37d62"
GO_VERSION = "go1.27.1"
GO_SHA256 = "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"
GO_LICENSE_SHA256 = "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
TEST_UNIT = "volparossa.test.unit.v1"
TRIAL_SECONDS = 480
RPC_LIMIT = 262144
NODE_COUNT = 4
NODES = tuple(f"10.77.0.{10 + n}" for n in range(NODE_COUNT))
UIDS = tuple(21000 + n for n in range(NODE_COUNT))
PHASES = ("setup", "startup", "signed_conflict", "commit", "partition_3_1",
          "rejoin_3_1", "partition_2_2", "rejoin_2_2", "crash_replay", "cleanup")


class TrialFailure(Exception):
    """Closed diagnostic: never interpolate subprocess output or private paths."""


def require(condition, code):
    if not condition:
        raise TrialFailure(code)


def checked(argv, *, timeout=15, input_bytes=None, uid=None):
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                               user=uid, group=uid, extra_groups=[] if uid is not None else None)
    output = bytearray()
    oversized = threading.Event()
    def drain():
        with process.stdout:
            while chunk := process.stdout.read(4096):
                available = RPC_LIMIT - len(output)
                output.extend(chunk[:available])
                if len(chunk) > available:
                    oversized.set()
    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        if input_bytes is not None:
            require(len(input_bytes) <= 16384, "command_input_limit")
            process.stdin.write(input_bytes)
            process.stdin.close()
        process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        reader.join(timeout=3)
    require(not reader.is_alive(), "command_reader_leak")
    require(process.returncode == 0, "command_failed")
    require(not oversized.is_set(), "command_output_limit")
    return bytes(output)


def atomic_json(path, value, uid=None):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if uid is not None:
        os.chown(path, uid, uid)


def plan():
    return {
        "unit": "TEST", "execute_default": False, "validators": NODE_COUNT,
        "source_built_comet": COMET_COMMIT, "compiler": GO_VERSION,
        "trial_seconds": TRIAL_SECONDS,
        "changes": ["five new guest-only network namespaces",
                    "four veth pairs and one bridge entirely inside those namespaces",
                    "temporary bridge-family nft partition rules inside the switch namespace",
                    "eight supervised processes with private synthetic keys and stores",
                    "remove every owned namespace, process and synthetic key after trial"],
        "does_not_prove": ["Byzantine equivocation", "independent devices",
                           "VOLPAROSSA overlay transport", "confidential validators",
                           "real money or securities", "independently verified light-client finality"],
    }


def guarded_guest():
    require(os.geteuid() == 0, "guest_root_required")
    require(os.uname().nodename == "volparossa-alpha", "wrong_guest")
    require(checked(["systemd-detect-virt"]).strip() == b"kvm", "wrong_virtualization")
    release = Path("/etc/os-release").read_text()
    require(re.search(r'^ID=debian$', release, re.M) is not None
            and re.search(r'^VERSION_ID="?13"?$', release, re.M) is not None, "wrong_os")
    require(Path.cwd().resolve() == Path("/home/vpci/source"), "wrong_source_directory")
    for uid in UIDS:
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise TrialFailure("synthetic_uid_collision")


def namespace_names(prefix):
    require(re.fullmatch(r"vptx-[0-9a-f]{12}", prefix) is not None, "namespace_name")
    return [prefix + "-switch"] + [prefix + f"-n{n}" for n in range(NODE_COUNT)]


def network_plan(prefix):
    """Pure typed commands: not one address or link is added to the parent namespace."""
    switch, *nodes = namespace_names(prefix)
    commands = [["ip", "netns", "add", name] for name in [switch, *nodes]]
    commands += [["ip", "-n", switch, "link", "set", "lo", "up"],
                 ["ip", "-n", switch, "link", "add", "br0", "type", "bridge"],
                 ["ip", "-n", switch, "addr", "add", "10.77.0.1/24", "dev", "br0"],
                 ["ip", "-n", switch, "link", "set", "br0", "up"]]
    for n, node in enumerate(nodes):
        commands += [
            ["ip", "-n", switch, "link", "add", f"p{n}", "type", "veth", "peer", "name", "e0", "netns", node],
            ["ip", "-n", switch, "link", "set", f"p{n}", "master", "br0"],
            ["ip", "-n", switch, "link", "set", f"p{n}", "up"],
            ["ip", "-n", node, "link", "set", "lo", "up"],
            ["ip", "-n", node, "addr", "add", NODES[n] + "/24", "dev", "e0"],
            ["ip", "-n", node, "link", "set", "e0", "up"],
        ]
    return commands


def parent_snapshot():
    values = {}
    for label, command in (
        ("addresses", ["ip", "-j", "address"]),
        ("routes4", ["ip", "-j", "-4", "route", "show", "table", "all"]),
        ("routes6", ["ip", "-j", "-6", "route", "show", "table", "all"]),
        ("rules4", ["ip", "-j", "-4", "rule"]),
        ("rules6", ["ip", "-j", "-6", "rule"]),
        ("firewall", ["nft", "-j", "list", "ruleset"]),
        ("namespaces", ["ip", "netns", "list"]),
    ):
        values[label] = hashlib.sha256(checked(command)).hexdigest()
    values["dns"] = hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()
    values["sysctls"] = hashlib.sha256(b"".join(Path(p).read_bytes() for p in (
        "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"))).hexdigest()
    return values


def replace_toml(text, section, key, value):
    """Replace exactly one existing upstream key, no loose/global substitutions."""
    current, found, output = "", 0, []
    for line in text.splitlines():
        match = re.fullmatch(r"\[([^\[\]]+)\]", line.strip())
        if match:
            current = match[1]
        if current == section and re.match(r"^" + re.escape(key) + r"\s*=", line):
            line = f"{key} = {json.dumps(value, separators=(',', ':'))}"
            found += 1
        output.append(line)
    require(found == 1, "upstream_config_contract")
    return "\n".join(output) + "\n"


def partition_rules(left, right):
    require(set(left).isdisjoint(right) and set(left) | set(right) == set(range(4)), "partition_membership")
    require(left and right, "partition_membership")
    def addresses(group):
        return "{ " + ", ".join(NODES[n] for n in sorted(group)) + " }"
    # Both directions and all packets: established connections cannot bypass the cut.
    return ("table bridge vptx { chain cut { type filter hook forward priority -200; policy accept;\n"
            f"ip saddr {addresses(left)} ip daddr {addresses(right)} counter drop\n"
            f"ip saddr {addresses(right)} ip daddr {addresses(left)} counter drop\n"
            "} }\n").encode()


def rpc(node, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}, separators=(",", ":")).encode()
    request = urllib.request.Request(f"http://{NODES[node]}:26657", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
    # Explicit empty proxy map: caller environment cannot route synthetic commands elsewhere.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        data = response.read(RPC_LIMIT + 1)
    require(len(data) <= RPC_LIMIT, "rpc_output_limit")
    result = json.loads(data)
    require(result.get("id") == 1 and result.get("jsonrpc") == "2.0", "rpc_envelope")
    require("error" not in result and isinstance(result.get("result"), dict), "rpc_error")
    return result["result"]


def query(node, path, data=b""):
    response = rpc(node, "abci_query", {"path": path, "data": data.hex(), "prove": False})["response"]
    require(response.get("code", 0) == 0, "abci_query_rejected")
    raw = base64.b64decode(response["value"], validate=True)
    require(len(raw) <= 16384, "abci_query_limit")
    return json.loads(raw)


def info(node):
    value = query(node, "/test/info")
    require(value.get("unit") == TEST_UNIT and value.get("consensus_certificate") is False, "info_contract")
    require(type(value.get("height")) is int and value["height"] >= 0, "info_height")
    for field in ("app_hash", "ledger_id"):
        require(re.fullmatch(r"[0-9a-f]{64}", value.get(field, "")) is not None, "info_digest")
    return value


def balance(node, key):
    value = query(node, "/test/balance", bytes.fromhex(key))
    require(set(value) == {"available_units", "reserved_units"}
            and all(type(v) is int and v >= 0 for v in value.values()), "balance_contract")
    return value


class Trial:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work)
        self.processes = {}
        self.phase = "setup"
        self.end = time.monotonic() + TRIAL_SECONDS
        self.report = {"schema": 1, "unit": "TEST", "comet_source": COMET_COMMIT,
                       "compiler": GO_VERSION, "acceptance": False, "checkpoints": {},
                       "scope": plan()["does_not_prove"], "phase": "setup"}

    def remaining(self, cap=60):
        remaining = self.end - time.monotonic()
        require(remaining > 0, "trial_deadline")
        return min(cap, remaining)

    def alive(self):
        require(len(self.processes) == 8, "process_count")
        require(all(p.poll() is None for p in self.processes.values()), "child_exited")

    def wait(self, predicate, cap=60):
        end = time.monotonic() + self.remaining(cap)
        while time.monotonic() < end:
            self.alive()
            try:
                result = predicate()
                if result:
                    return result
            except (urllib.error.URLError, TimeoutError, ConnectionError, KeyError,
                    json.JSONDecodeError, TrialFailure):
                pass
            time.sleep(0.25)
        raise TrialFailure("observation_deadline")

    def checkpoint(self, phase, **evidence):
        require(phase in PHASES, "phase")
        self.report["checkpoints"][phase] = evidence

    def launch(self, n, kind):
        private = self.work / f"node{n}"
        if kind == "app":
            command = [self.args.adapter, "serve", "--config", str(private / "app.json"),
                       "--store", str(private / "ordered"), "--socket", str(private / "app.sock")]
        else:
            command = [self.args.comet, "start", "--home", str(private)]
        command = ["ip", "netns", "exec", namespace_names(self.args.namespace)[n + 1],
                   "setpriv", "--reuid", str(UIDS[n]), "--regid", str(UIDS[n]),
                   "--clear-groups", "--", *command]
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                       "HOME": str(private), "GOMAXPROCS": "1", "GOMEMLIMIT": "128MiB"}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment,
                                   cwd=private, start_new_session=True, umask=0o077)
        self.processes[(n, kind)] = process

    def stop(self, n, kind, crash=False):
        process = self.processes.pop((n, kind))
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL if crash else signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)

    def setup(self):
        require(self.work.parent == Path("/var/tmp") and self.work.resolve() == self.work
                and re.fullmatch(r"vptx-[A-Za-z0-9_]+", self.work.name) is not None
                and self.work.stat().st_uid == 0 and stat.S_IMODE(self.work.stat().st_mode) == 0o700
                and sorted(path.name for path in self.work.iterdir()) == ["bin"], "private_work_root")
        require(Path(self.args.comet) == self.work / "bin/cometbft"
                and Path(self.args.adapter) == self.work / "bin/volparossa-transaction-abci", "private_executables")
        checked([self.args.comet, "testnet", "--v", "4", "--n", "0", "--o", str(self.work),
                 "--initial-height", "1", "--populate-persistent-peers=false"], timeout=20)
        # Generated upstream private keys use the upstream crypto CSPRNG. Account keys
        # are separate new Ed25519 seeds from the same upstream generator, not validators.
        account_home = self.work / "account-keygen"
        checked([self.args.comet, "testnet", "--v", "2", "--n", "0", "--o", str(account_home),
                 "--populate-persistent-peers=false"], timeout=20)
        accounts = []
        for n in range(2):
            key = json.loads((account_home / f"node{n}/config/priv_validator_key.json").read_text())
            public = base64.b64decode(key["pub_key"]["value"], validate=True)
            secret = base64.b64decode(key["priv_key"]["value"], validate=True)
            require(len(public) == 32 and len(secret) == 64 and secret[32:] == public, "upstream_ed25519_key")
            accounts.append({"public_key": public.hex(), "units": 100 if n == 0 else 0})
            if n == 0:
                with (self.work / "payer.seed").open("xb") as output:
                    os.chmod(output.name, 0o600)
                    output.write(secret[:32])
        self.payer, self.recipient = [account["public_key"] for account in accounts]
        genesis = json.loads((self.work / "node0/config/genesis.json").read_text())
        seconds = int(time.time())
        chain = "volparossa-test-" + secrets.token_hex(12)
        validators = []
        peer_ids = []
        for n in range(4):
            key = json.loads((self.work / f"node{n}/config/priv_validator_key.json").read_text())
            public = base64.b64decode(key["pub_key"]["value"], validate=True)
            require(len(public) == 32, "validator_key")
            validators.append(public.hex())
            peer_id = checked([self.args.comet, "show-node-id", "--home", str(self.work / f"node{n}")]).decode().strip()
            require(re.fullmatch(r"[0-9a-f]{40}", peer_id) is not None, "peer_identity")
            peer_ids.append(peer_id)
        require(len(set(validators)) == 4 and not set(validators) & {self.payer, self.recipient}, "key_independence")
        app = {"version": 1, "chain_id": chain, "seconds": seconds, "nanos": 0,
               "validators": validators, "accounts": accounts}
        genesis.update(chain_id=chain, initial_height="1", app_state=app,
                       genesis_time=datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       app_hash="")
        for validator in genesis["validators"]:
            validator["power"] = "10"
        genesis["consensus_params"] = {
            "block": {"max_bytes": "98304", "max_gas": "-1"},
            "evidence": {"max_age_num_blocks": "1000", "max_age_duration": "86400000000000", "max_bytes": "8192"},
            "validator": {"pub_key_types": ["ed25519"]}, "version": {"app": "1"},
            "abci": {"vote_extensions_enable_height": "0"}, "authority": {"authority": ""},
        }
        for n in range(4):
            private = self.work / f"node{n}"
            config = private / "config/config.toml"
            text = config.read_text()
            settings = [
                ("", "proxy_app", "unix://" + str(private / "app.sock")),
                ("", "log_level", "error"), ("", "abci", "socket"),
                ("rpc", "laddr", "tcp://" + NODES[n] + ":26657"),
                ("rpc", "max_open_connections", 16), ("rpc", "max_body_bytes", 16384),
                ("rpc", "unsafe", False), ("rpc", "pprof_laddr", ""),
                ("p2p", "laddr", "tcp://" + NODES[n] + ":26656"),
                ("p2p", "external_address", NODES[n] + ":26656"),
                ("p2p", "persistent_peers", ",".join(f"{peer_ids[k]}@{NODES[k]}:26656" for k in range(4) if k != n)),
                ("p2p", "persistent_peers_max_dial_period", "1s"),
                ("p2p", "pex", False), ("p2p", "addr_book_strict", False),
                ("p2p", "allow_duplicate_ip", False),
                ("p2p", "max_num_inbound_peers", 4), ("p2p", "max_num_outbound_peers", 4),
                ("p2p.libp2p", "enabled", False),
                ("mempool", "size", 128), ("mempool", "max_txs_bytes", 524288),
                ("mempool", "max_tx_bytes", 4096), ("mempool", "cache_size", 256),
                ("consensus", "timeout_commit", "500ms"),
                ("consensus", "create_empty_blocks", True),
                ("consensus", "create_empty_blocks_interval", "1s"),
                ("statesync", "enable", False), ("storage", "discard_abci_responses", False),
            ]
            for section, key, value in settings:
                text = replace_toml(text, section, key, value)
            config.write_text(text)
            (private / "config/genesis.json").write_text(json.dumps(genesis, separators=(",", ":")))
            atomic_json(private / "app.json", app)
            for parent, dirs, files in os.walk(private):
                os.chmod(parent, 0o700)
                os.chown(parent, UIDS[n], UIDS[n])
                for file in files:
                    path = Path(parent) / file
                    os.chmod(path, 0o600)
                    os.chown(path, UIDS[n], UIDS[n])
        # Only traversal of the common temporary root is allowed; every node is private.
        os.chmod(self.work, 0o711)
        self.checkpoint("setup", validators=4, independent_stores=4, private_sockets=4,
                        genesis_sha256=hashlib.sha256(json.dumps(genesis, sort_keys=True).encode()).hexdigest())

    def converged(self, min_height=1):
        # Compare the same committed block height across all nodes, not racing tip hashes.
        if any(int(rpc(n, "status")["sync_info"]["latest_block_height"]) < min_height for n in range(4)):
            return False
        states = [info(n) for n in range(4)]
        height = min(state["height"] for state in states)
        if height < min_height:
            return False
        headers = [rpc(n, "block", {"height": str(height)}) for n in range(4)]
        hashes = [h["block_id"]["hash"] for h in headers]
        apps = [h["block"]["header"]["app_hash"] for h in headers]
        require(len(set(hashes)) == 1 and len(set(apps)) == 1, "divergent_committed_block")
        require(len({state["ledger_id"] for state in states}) == 1, "divergent_ledger")
        return {"height": height, "block_hash": hashes[0], "header_app_hash": apps[0]}

    def sign(self, action, operation, **options):
        command = [self.args.adapter, "sign-" + action, "--ledger", self.ledger,
                   "--secret-key", str(self.work / "payer.seed"), "--operation", operation,
                   "--valid-from", str(int(time.time()) - 5), "--expires", str(int(time.time()) + 240)]
        for key, value in options.items():
            command += ["--" + key.replace("_", "-"), str(value)]
        value = checked(command).strip().decode("ascii")
        require(re.fullmatch(r"[0-9a-f]{2,8192}", value) is not None and len(value) % 2 == 0, "signed_command_contract")
        return bytes.fromhex(value)

    def broadcast(self, node, command):
        result = rpc(node, "broadcast_tx_sync", {"tx": base64.b64encode(command).decode()})
        require(result.get("code", 0) == 0, "check_tx_rejected")

    def tx_result(self, command):
        result = rpc(0, "tx", {"hash": base64.b64encode(hashlib.sha256(command).digest()).decode(), "prove": False})
        require(base64.b64decode(result["tx"], validate=True) == command, "transaction_bytes_changed")
        require(int(result["height"]) > 0, "transaction_not_committed")
        return result

    def balances(self, available, reserved, recipient):
        return all(balance(n, self.payer) == {"available_units": available, "reserved_units": reserved}
                   and balance(n, self.recipient) == {"available_units": recipient, "reserved_units": 0}
                   for n in range(4))

    def same_receipts(self, originals):
        return all(query(n, "/test/operation", bytes.fromhex(receipt["operation_id"])) == receipt
                   for n in range(4) for receipt in originals)

    def committed_retries_after(self, commands, start):
        """Observe actual new block inclusion/results, never an old tx-index hit."""
        found = {}
        cursor = start + 1
        def observe():
            nonlocal cursor
            tip = int(rpc(0, "status")["sync_info"]["latest_block_height"])
            require(tip - start <= 256, "retry_block_budget")
            while cursor <= tip:
                block = rpc(0, "block", {"height": str(cursor)})["block"]
                results = rpc(0, "block_results", {"height": str(cursor)})
                require(int(block["header"]["height"]) == cursor and int(results["height"]) == cursor,
                        "retry_block_position")
                transactions = [base64.b64decode(value, validate=True) for value in (block["data"]["txs"] or [])]
                outcomes = results["txs_results"] or []
                require(len(transactions) == len(outcomes), "retry_block_results")
                for command, outcome in zip(transactions, outcomes):
                    if command in commands:
                        require(outcome.get("code", 0) == 0, "retry_execution_rejected")
                        require(base64.b64decode(outcome["data"], validate=True) == hashlib.sha256(command).digest(),
                                "retry_command_digest")
                        found[command] = cursor
                cursor += 1
            return [found[command] for command in commands] if len(found) == len(commands) else False
        return self.wait(observe)

    def cut(self, left, right):
        checked(["nft", "-f", "-"], input_bytes=partition_rules(left, right))

    def heal(self):
        data = json.loads(checked(["nft", "-j", "list", "table", "bridge", "vptx"]))
        counters = [expr["counter"]["packets"] for item in data["nftables"]
                    for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
        require(len(counters) == 2 and all(type(count) is int and count > 0 for count in counters),
                "partition_no_packet_evidence")
        checked(["nft", "delete", "table", "bridge", "vptx"])
        return counters

    def observe_stable(self, members, seconds=8):
        start = [info(n)["height"] for n in members]
        began = time.monotonic()
        end = began + self.remaining(seconds)
        samples = 0
        while time.monotonic() < end:
            self.alive()
            require([info(n)["height"] for n in members] == start, "partition_unexpected_commit")
            samples += 1
            time.sleep(0.25)
        elapsed = time.monotonic() - began
        require(samples >= 8 and elapsed >= seconds, "partition_missing_coverage")
        return {"heights": start, "samples": samples, "observation_seconds": round(elapsed, 3)}

    def run(self):
        self.setup()
        self.phase = "startup"
        for n in range(4):
            self.launch(n, "app")
        deadline = time.monotonic() + self.remaining(10)
        while not all((self.work / f"node{n}/app.sock").is_socket() for n in range(4)):
            require(time.monotonic() < deadline, "app_startup_deadline")
            require(all(p.poll() is None for p in self.processes.values()), "app_startup_failed")
            time.sleep(0.1)
        for n in range(4):
            self.launch(n, "comet")
        self.checkpoint("startup", **self.wait(lambda: self.converged(2)))
        self.ledger = info(0)["ledger_id"]
        self.phase = "signed_conflict"
        operations = [secrets.token_hex(32), secrets.token_hex(32)]
        commands = [self.sign("reserve", op, recipient=self.recipient, units=70) for op in operations]
        for n, command in enumerate(commands):
            self.broadcast(n, command)
        results = self.wait(lambda: [self.tx_result(command) for command in commands])
        # Protobuf JSON may omit an integer zero, but never accept an unknown code.
        codes = [result["tx_result"].get("code", 0) for result in results]
        require(sorted(codes) == [0, 7], "conflicting_spends_not_exclusive")
        self.wait(lambda: self.balances(30, 70, 0))
        winner = codes.index(0)
        operation = query(0, "/test/operation", bytes.fromhex(operations[winner]))
        require(operation["state"] == "Reserved" and operation["consensus_certificate"] is False, "reservation_receipt")
        self.checkpoint("signed_conflict", result_codes=codes, conserved_units=100,
                        **self.wait(lambda: self.converged(max(int(result["height"]) for result in results) + 1)))
        self.phase = "commit"
        commit_operation = secrets.token_hex(32)
        commit = self.sign("commit", commit_operation, reservation=operation["reservation_id"])
        self.broadcast(0, commit)
        committed = self.wait(lambda: self.tx_result(commit))
        require(committed["tx_result"].get("code", 0) == 0, "commit_rejected")
        self.wait(lambda: self.balances(30, 0, 70))
        commit_receipt = query(0, "/test/operation", bytes.fromhex(commit_operation))
        require(commit_receipt["state"] == "Committed" and commit_receipt["consensus_certificate"] is False
                and operation["command_sha256"] == hashlib.sha256(commands[winner]).hexdigest()
                and commit_receipt["command_sha256"] == hashlib.sha256(commit).hexdigest(), "original_receipts")
        original_receipts = [operation, commit_receipt]
        self.wait(lambda: self.same_receipts(original_receipts))
        self.checkpoint("commit", debited_units=70, credited_units=70, conserved_units=100,
                        **self.wait(lambda: self.converged(int(committed["height"]) + 1)))
        self.phase = "partition_3_1"
        self.cut([0, 1, 2], [3])
        # Allow at most an already signed in-flight block to drain; then observe exact stability.
        time.sleep(3)
        minority = info(3)["height"]
        majority_before = [info(n)["height"] for n in [0, 1, 2]]
        majority = max(majority_before)
        stable = self.observe_stable([3])
        progressed = self.wait(lambda: min(info(n)["height"] for n in [0, 1, 2]) >= majority + 3)
        require(progressed and info(3)["height"] == minority, "three_one_progress")
        majority_after = [info(n)["height"] for n in [0, 1, 2]]
        self.checkpoint("partition_3_1", majority_progress_blocks_at_least=3,
                        majority_heights_before=majority_before, majority_heights_after=majority_after,
                        drop_packets=self.heal(), all_processes_alive=True, **stable)
        self.phase = "rejoin_3_1"
        self.checkpoint("rejoin_3_1", **self.wait(lambda: self.converged(max(majority_after) + 1)))
        self.phase = "partition_2_2"
        self.cut([0, 1], [2, 3])
        time.sleep(3)
        stable = self.observe_stable([0, 1, 2, 3])
        stop_height = max(stable["heights"])
        self.checkpoint("partition_2_2", drop_packets=self.heal(), all_processes_alive=True, **stable)
        self.phase = "rejoin_2_2"
        self.checkpoint("rejoin_2_2", **self.wait(lambda: self.converged(stop_height + 2)))
        self.phase = "crash_replay"
        # Actual post-commit process crash. Not equivocation, nor a pre-commit failpoint.
        before = info(3)["height"]
        self.stop(3, "comet", crash=True)
        self.stop(3, "app", crash=True)
        stale = self.work / "node3/app.sock"
        if stale.exists() or stale.is_symlink():
            metadata = stale.lstat()
            require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == UIDS[3], "unexpected_socket_replacement")
            stale.unlink()
        self.launch(3, "app")
        deadline = time.monotonic() + self.remaining(10)
        while not stale.is_socket():
            require(time.monotonic() < deadline, "restart_socket_deadline")
            time.sleep(0.1)
        self.launch(3, "comet")
        self.wait(lambda: self.converged(before + 2))
        self.wait(lambda: self.balances(30, 0, 70))
        self.wait(lambda: self.same_receipts(original_receipts))
        # A cache rejection or old tx-index entry is not execution proof. Both
        # original byte strings must occur in actual new committed blocks.
        retry_commands = [commands[winner], commit]
        retry_start = max(int(rpc(n, "status")["sync_info"]["latest_block_height"]) for n in range(4))
        for command in retry_commands:
            self.broadcast(3, command)
        retry_heights = self.committed_retries_after(retry_commands, retry_start)
        converged = self.wait(lambda: self.converged(max(max(retry_heights) + 1, before + 4)))
        self.wait(lambda: self.balances(30, 0, 70))
        self.wait(lambda: self.same_receipts(original_receipts))
        self.checkpoint("crash_replay", crashed_node=3, post_commit_restart=True,
                        height_before_restart=before,
                        retry_start_height=retry_start, retry_committed_heights=retry_heights,
                        retry_result_codes=[0, 0], unchanged_balances=True, unchanged_receipts=True,
                        original_receipt_sequences=[receipt["sequence"] for receipt in original_receipts],
                        second_abci_execution_proven=True, **converged)
        self.report["acceptance"] = True

    def finish(self):
        errors = False
        self.report["children_before_cleanup"] = [
            {"node": node, "kind": kind, "exit_status": process.poll()}
            for (node, kind), process in sorted(self.processes.items())
        ]
        for node, kind in list(self.processes):
            try:
                self.stop(node, kind)
            except (OSError, subprocess.TimeoutExpired):
                errors = True
        self.report["phase"] = self.phase
        self.report["processes_reaped"] = not errors and not self.processes
        if errors:
            self.report["acceptance"] = False


def run_inside(args):
    trial = Trial(args)
    try:
        trial.run()
    except (TrialFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        trial.report["failure"] = str(error) if isinstance(error, TrialFailure) else "fixture_contract_failure"
    finally:
        trial.finish()
        atomic_json(Path(args.output) / "transaction-abci-inner.json", trial.report)
    return 0 if trial.report["acceptance"] else 1


def execute(args):
    guarded_guest()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit or "") is not None, "source_commit")
    for path in (args.comet, args.adapter):
        require(path and Path(path).is_absolute() and Path(path).is_file() and not Path(path).is_symlink(), "binary_path")
    require(args.build_receipt is not None, "build_receipt_required")
    build = json.loads(Path(args.build_receipt).read_text())
    verify_build(build, args.expected_commit, Path(args.comet), Path(args.adapter))
    output = Path(args.output)
    require(output.is_dir() and not output.is_symlink() and not list(output.iterdir()), "output_directory")
    before = parent_snapshot()
    prefix = "vptx-" + secrets.token_hex(6)
    work = Path(tempfile.mkdtemp(prefix="vptx-", dir="/var/tmp"))
    process = None
    failure = None
    cleanup_ok = True
    owned_names = []
    try:
        # The guest vpci home may be mode0700. Do not weaken it: put verified
        # executable copies in the disposable fixture root for synthetic UIDs.
        (work / "bin").mkdir(mode=0o755)
        os.chmod(work / "bin", 0o755)
        for attribute, name in (("comet", "cometbft"), ("adapter", "volparossa-transaction-abci")):
            destination = work / "bin" / name
            shutil.copyfile(getattr(args, attribute), destination)
            os.chmod(destination, 0o755)
            setattr(args, attribute, str(destination))
        verify_build(build, args.expected_commit, Path(args.comet), Path(args.adapter))
        existing_names = {line.split()[0] for line in checked(["ip", "netns", "list"]).decode().splitlines()}
        require(not existing_names.intersection(namespace_names(prefix)), "namespace_collision")
        for command in network_plan(prefix):
            if command[:3] == ["ip", "netns", "add"]:
                # Record the attempted exact new name so partial ip-netns setup is
                # also cleaned. Existing names were checked before any mutation.
                owned_names.append(command[3])
            checked(command)
        command = ["ip", "netns", "exec", namespace_names(prefix)[0], sys.executable,
                   str(Path(__file__).resolve()), "--inside", "--namespace", prefix,
                   "--work", str(work), "--output", str(output),
                   "--comet", args.comet, "--adapter", args.adapter]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        process.wait(timeout=TRIAL_SECONDS + 30)
        require(process.returncode == 0, "trial_failed")
    except (TrialFailure, OSError, subprocess.SubprocessError) as error:
        failure = str(error) if isinstance(error, TrialFailure) else "supervisor_failure"
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        # Enumerate each exact owned namespace, terminate every surviving member,
        # then delete only those exact names. Never infer cleanup from child exit.
        for name in reversed(owned_names):
            try:
                present = checked(["ip", "netns", "list"]).decode().splitlines()
                if name not in [line.split()[0] for line in present]:
                    continue
                for pid in checked(["ip", "netns", "pids", name]).decode().split():
                    require(pid.isdecimal() and int(pid) > 1, "cleanup_pid")
                    try:
                        handle = os.pidfd_open(int(pid))
                        try:
                            require(os.stat(f"/proc/{pid}/ns/net").st_ino == os.stat(f"/run/netns/{name}").st_ino,
                                    "cleanup_process_namespace")
                            signal.pidfd_send_signal(handle, signal.SIGKILL)
                        finally:
                            os.close(handle)
                    except ProcessLookupError:
                        pass
                for _ in range(20):
                    if not checked(["ip", "netns", "pids", name]).strip():
                        break
                    time.sleep(0.1)
                require(not checked(["ip", "netns", "pids", name]).strip(), "namespace_process_leak")
                checked(["ip", "netns", "delete", name])
            except (TrialFailure, OSError, subprocess.SubprocessError):
                cleanup_ok = False
        require(work.parent == Path("/var/tmp") and re.fullmatch(r"vptx-[A-Za-z0-9_]+", work.name) is not None
                and not work.is_symlink(), "cleanup_work_target")
        if work.exists():
            shutil.rmtree(work)
    after = parent_snapshot()
    receipt_path = output / "transaction-abci-inner.json"
    inner = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {"acceptance": False}
    receipt = {"schema": 1, "source_commit": args.expected_commit, "comet_source": COMET_COMMIT,
               "acceptance": failure is None and inner_complete(inner) and cleanup_ok and before == after,
               "parent_before": before, "parent_after": after, "parent_unchanged": before == after,
               "owned_namespaces_removed": cleanup_ok, "private_keys_removed": not work.exists(),
               "failure": failure, "scope": plan()["does_not_prove"]}
    atomic_json(output / "transaction-abci-acceptance.json", receipt)
    return 0 if receipt["acceptance"] else 1


def inner_complete(value):
    return (value.get("schema") == 1 and value.get("unit") == "TEST"
            and value.get("comet_source") == COMET_COMMIT
            and value.get("compiler") == GO_VERSION and value.get("acceptance") is True
            and value.get("processes_reaped") is True and "failure" not in value
            and value.get("phase") == "crash_replay"
            and set(value.get("checkpoints", {})) == set(PHASES) - {"cleanup"})


def verify_build(build, revision, comet, adapter):
    require(build.get("schema") == 1 and build.get("source_commit") == revision
            and build.get("comet_source") == COMET_COMMIT and build.get("compiler") == GO_VERSION
            and build.get("compiler_archive_sha256") == GO_SHA256
            and build.get("compiler_license_sha256") == GO_LICENSE_SHA256
            and build.get("source_built_engine") is True and build.get("compiler_auto_upgrade") is False,
            "build_provenance")
    for name, path in (("comet", comet), ("adapter", adapter)):
        with path.open("rb") as stream:
            require(build.get(name + "_sha256") == hashlib.file_digest(stream, "sha256").hexdigest(), "binary_digest")
    for name in ("go_mod_sha256", "go_sum_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", build.get(name, "")) is not None, "module_digest")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--comet")
    parser.add_argument("--adapter")
    parser.add_argument("--output")
    parser.add_argument("--build-receipt")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--namespace", help=argparse.SUPPRESS)
    parser.add_argument("--work", help=argparse.SUPPRESS)
    return parser.parse_args()


def main():
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise TrialFailure("interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    args = parse_args()
    if args.inside:
        guarded_guest()
        namespace_names(args.namespace)
        # An internal flag is not enough: verify we are actually in the named switch namespace.
        require(checked(["ip", "netns", "identify", str(os.getpid())]).decode().strip()
                == namespace_names(args.namespace)[0], "wrong_namespace")
        return run_inside(args)
    print(json.dumps(plan(), sort_keys=True))
    if not args.execute:
        return 0
    require(args.yes, "explicit_confirmation_required")
    return execute(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (TrialFailure, OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("transaction_abci_fixture_failed", file=sys.stderr)
        raise SystemExit(1)
