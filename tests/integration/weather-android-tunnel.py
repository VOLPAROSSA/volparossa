#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded API-only doorway from the Android sandbox to a disposable core VM.

The host owns the SSH identity outside the socket-only directory exposed to the
Android sandbox. The guest connects as the weather worker, never as root. This
transports original HTTP responses; it supplies neither weather data nor core
acceptance evidence. The joined runner must still verify custody and captures.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import runpy
import selectors
import select
import signal
import socket
import stat
import subprocess
import sys
import time

ROUTES = ("/api/volparossa/forecast", "/api/volparossa/air-quality")
ORIGIN = "http://127.0.0.1:43210"
MAX_REQUEST = 4096
MAX_RESPONSE = 256 * 1024 + 8192
EXCHANGE_SECONDS = 190
MAX_REQUESTS = 6
GUEST_STATE = Path("/run/volparossa-weather-android/endpoint.json")
GUEST_HELPER = "/usr/local/libexec/volparossa-weather-android-tunnel.py"
PREFIX = "VOLPAROSSA_WEATHER_ANDROID_TUNNEL_DIAGNOSTIC "
MAX_DIAGNOSTIC_BYTES = 4096  # Includes the UTF-8 marker and final LF.
PHASES = frozenset(("admission", "listen", "accept", "request-read", "request-limit", "exchange-spawn",
    "exchange-write", "exchange-read", "exchange-client", "exchange-join", "exchange-deadline",
    "exchange-protocol", "response-observe", "response-send", "hold-open", "exchange-cleanup", "socket-cleanup"))
REASONS = {
    "deadline": frozenset(("accept", "request-read", "exchange-read", "exchange-join", "exchange-deadline",
        "response-send", "hold-open")),
    "interrupted": PHASES | {None},
    "request-rejected": frozenset(("request-read", "request-limit")),
    "client-disconnected": frozenset(("exchange-client", "response-send")),
    "extra-request": frozenset(("exchange-client", "hold-open")),
    "child-failed": frozenset(("exchange-join",)),
    "response-bound": frozenset(("exchange-read",)),
    "response-rejected": frozenset(("exchange-protocol", "response-observe")),
    "cleanup-failed": frozenset(("exchange-cleanup", "socket-cleanup")),
    "io-error": PHASES | {None},
    "guard-rejected": frozenset(("admission", "listen", "exchange-spawn", "exchange-write")),
}
HTTP_STATUSES = frozenset(("200", "400", "403", "404", "405", "408", "429", "500", "502", "503", "504",
    "other", "invalid"))
PRODUCTS = dict(zip(ROUTES, ("weather", "air_quality")))


class TunnelInterrupted(Exception):
    """Do not let selectors interpret cancellation as a retryable EINTR."""


def require(value):
    if not value:
        raise ValueError("weather_android_tunnel_rejected")


def validate_diagnostic(value):
    """Failure-only observations; neither raw HTTP nor guest cleanup authority."""
    require(type(value) is dict and set(value) == {"schema", "kind", "success", "joined_core_acceptance", "primary", "cleanup"})
    require(type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "weather-android-tunnel-diagnostic"
        and value["success"] is False and value["joined_core_acceptance"] is False)
    facts = value["primary"]
    require(type(facts) is dict and set(facts) == {"phase", "reason", "product", "ordinal", "completed",
        "requests", "ssh_status", "http_status"})
    phase, reason, product, ordinal = (facts[key] for key in ("phase", "reason", "product", "ordinal"))
    require(phase is None or type(phase) is str and phase in PHASES)
    require(reason is None or type(reason) is str and reason in REASONS and phase in REASONS[reason])
    require(product is None or type(product) is str and product in PRODUCTS.values())
    counts = facts["requests"]
    require(type(counts) is dict and set(counts) == set(PRODUCTS.values())
        and all(type(count) is int and 0 <= count <= 3 for count in counts.values()))
    require(type(facts["completed"]) is int and 0 <= facts["completed"] <= sum(counts.values()) <= MAX_REQUESTS)
    require(ordinal is None or type(ordinal) is int and 1 <= ordinal <= 3
        and product is not None and ordinal == counts[product])
    if product is None: require(ordinal is None)
    if phase in {None, "admission", "listen", "accept", "request-read", "hold-open"}:
        require(product is None and ordinal is None)
    if phase == "request-limit": require(product is not None and ordinal is None)
    active = {"exchange-spawn", "exchange-write", "exchange-read", "exchange-client", "exchange-join",
        "exchange-deadline", "exchange-protocol", "response-observe", "response-send", "exchange-cleanup"}
    if phase in active: require(product is not None and ordinal is not None)
    if phase in {None, "admission", "listen"}: require(sum(counts.values()) == 0 and facts["completed"] == 0)
    if phase in {"accept", "request-read", "request-limit", "hold-open"}:
        require(facts["completed"] == sum(counts.values()))
    if phase in active - {"response-send", "exchange-cleanup"}:
        require(facts["completed"] + 1 == sum(counts.values()))
    if phase == "hold-open": require(facts["completed"] == MAX_REQUESTS)
    status = facts["ssh_status"]
    require(status is None or type(status) is int and -255 <= status <= 255)
    if status is not None:
        require(phase in {"exchange-join", "exchange-deadline", "exchange-protocol", "response-observe",
            "response-send", "exchange-cleanup", "socket-cleanup"})
    if reason == "child-failed": require(status is not None and status != 0)
    if phase in {"exchange-deadline", "exchange-protocol", "response-observe", "response-send"}:
        require(status == 0 and type(status) is int)
    http = facts["http_status"]
    require(http is None or type(http) is str and http in HTTP_STATUSES)
    if http is not None:
        require(phase in {"exchange-join", "exchange-deadline", "exchange-protocol", "response-observe",
            "response-send", "exchange-cleanup", "socket-cleanup"})
    cleanup = value["cleanup"]
    require(type(cleanup) is dict and set(cleanup) == {"exchange_child_joined", "socket_removed"}
        and all(item is None or type(item) is bool for item in cleanup.values()))
    encoded = PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    require(len(encoded.encode("utf-8")) <= MAX_DIAGNOSTIC_BYTES)
    return value


class TunnelDiagnostic:
    """Snapshot the first failure before retirement, with no exception text.

    Requests count only quota-admitted attempts; completed counts the original
    successful send/deadline completions, not merely bytes sent. ordinal names
    the current admitted attempt, not a retry. Reasons describe the observed
    decision, not an inferred malicious client or remote root cause.
    Cleanup flags refer only to this exchange group and this socket inode.
    """
    def __init__(self):
        self.active = False
        self.facts = dict(phase=None, reason=None, product=None, ordinal=None, completed=0,
            requests=dict.fromkeys(PRODUCTS.values(), 0), ssh_status=None, http_status=None)
        self.primary = None
        self.cleanup = dict(exchange_child_joined=None, socket_removed=None)

    def phase(self, phase):
        self.facts["phase"] = phase

    def next_request(self, phase):
        self.facts.update(phase=phase, product=None, ordinal=None, ssh_status=None, http_status=None)
        self.cleanup["exchange_child_joined"] = None

    def selected(self, route):
        self.facts.update(product=PRODUCTS[route], ordinal=None)

    def admitted(self, route, ordinal):
        product = PRODUCTS[route]
        self.facts["requests"][product] = ordinal
        self.facts.update(product=product, ordinal=ordinal)

    def completed(self, count):
        self.facts["completed"] = count

    def child_started(self):
        self.cleanup["exchange_child_joined"] = False

    def child_status(self, status):
        self.facts["ssh_status"] = status if type(status) is int and -255 <= status <= 255 else None

    def http(self, raw):
        # Inspect only the fixed status prefix. Never retain reason phrases,
        # headers, a URL, body, hash, exception text or remote identity.
        prefix = bytes(raw[:13])
        status = "invalid"
        if len(prefix) == 13 and prefix.startswith(b"HTTP/1.1 ") and prefix[12:] == b" " and prefix[9:12].isdigit():
            number = prefix[9:12].decode("ascii")
            status = number if number in HTTP_STATUSES else "other"
        self.facts["http_status"] = status

    def cleaned(self, key, value):
        self.cleanup[key] = value

    def capture(self, error):
        if self.primary is not None: return
        phase, reason = self.facts["phase"], None
        if phase in {"exchange-cleanup", "socket-cleanup"}: reason = "cleanup-failed"
        elif isinstance(error, TunnelInterrupted): reason = "interrupted"
        elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)): reason = "deadline"
        elif isinstance(error, BrokenPipeError) and phase in {"exchange-client", "response-send"}:
            reason = "client-disconnected"
        elif isinstance(error, OSError): reason = "io-error"
        elif isinstance(error, ValueError):
            reason = {"request-read": "request-rejected", "request-limit": "request-rejected",
                "exchange-client": "extra-request", "hold-open": "extra-request", "exchange-read": "response-bound",
                "exchange-join": "child-failed", "exchange-protocol": "response-rejected",
                "response-observe": "response-rejected"}.get(phase, "guard-rejected")
        if reason is not None and phase not in REASONS[reason]: reason = None
        self.primary = {**self.facts, "requests": dict(self.facts["requests"]), "reason": reason}

    def record(self):
        require(self.primary is not None)
        return validate_diagnostic(dict(schema=1, kind="weather-android-tunnel-diagnostic", success=False,
            joined_core_acceptance=False, primary=self.primary, cleanup=dict(self.cleanup)))


def observe(diagnostic, method, *args):
    # A broken optional observation cannot change the original failure or skip
    # cleanup. No clocks, process polls or external reads are performed here.
    if diagnostic is not None:
        try: getattr(diagnostic, method)(*args)
        except (AttributeError, OSError, ValueError, KeyError, TypeError, RecursionError): pass


def emit_diagnostic(diagnostic):
    if diagnostic is None or not diagnostic.active: return
    try:
        value = diagnostic.record()
        print(PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    except (AttributeError, OSError, ValueError, KeyError, TypeError, RecursionError): pass


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.fspath(path.resolve(strict=True)))
    require(not path.is_symlink())
    return path


def owned(path, kind, mode, uid=None):
    path = canonical(path)
    info = path.lstat()
    require(kind(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
            and info.st_uid == (os.geteuid() if uid is None else uid))
    return info


def request_path(raw):
    """Admit one bodyless fixed GET; never forward caller headers or credentials."""
    require(type(raw) is bytes and len(raw) <= MAX_REQUEST and raw.endswith(b"\r\n\r\n"))
    lines = raw.decode("ascii").split("\r\n")
    require(len(lines) >= 4 and lines[-2:] == ["", ""])
    parts = lines[0].split(" ")
    require(len(parts) == 3 and parts[0] == "GET" and parts[1] in ROUTES and parts[2] == "HTTP/1.1")
    headers = {}
    for line in lines[1:-2]:
        require(":" in line and not line.startswith((" ", "\t")))
        name, value = line.split(":", 1)
        require(name and name == name.strip() and name.isascii())
        name = name.lower()
        require(name not in headers and all(c.isalnum() or c == "-" for c in name))
        require(all(32 <= ord(c) < 127 or c == "\t" for c in value))
        headers[name] = value.strip()
    require(headers.get("host") == "127.0.0.1:43210"
            and headers.get("origin") == ORIGIN
            and not set(headers) & {"authorization", "cookie", "proxy-authorization", "transfer-encoding", "expect"})
    require("content-length" not in headers or headers["content-length"] == "0")
    return parts[1]


def canonical_request(path):
    require(path in ROUTES)
    return (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n"
            f"Origin: {ORIGIN}\r\nConnection: close\r\n\r\n").encode("ascii")


def ssh_command(key, hosts):
    for path in (key, hosts):
        owned(path, stat.S_ISREG, 0o600)
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", "22223", "-i", str(key),
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(hosts),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "vpci@127.0.0.1", "/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", GUEST_HELPER, "guest"]


def group_alive(group):
    # Only process-group membership/state is read. No argv, environment or
    # unrelated process metadata is retained. Zombies cannot hold descriptors.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and fields[0] not in ("Z", "X"):
                return True
        except FileNotFoundError:
            continue
    return False


def stop_child(child):
    # A reaped leader does not establish that its stdout-holding descendants
    # have stopped. The session/group was created and is owned by this exchange.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if group_alive(child.pid):
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
        until = time.monotonic() + 2
        while group_alive(child.pid) and time.monotonic() < until:
            time.sleep(0.02)
    child.wait(timeout=2)
    require(not group_alive(child.pid))


def exchange(command, request, deadline, *, client=None, diagnostic=None):
    """Own one SSH process group; bound output before collecting it."""
    observe(diagnostic, "phase", "exchange-spawn")
    require(request == canonical_request(request_path(request)))
    require(deadline > time.monotonic())
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    try:
        observe(diagnostic, "child_started")
        observe(diagnostic, "phase", "exchange-write")
        child.stdin.write(request)
        child.stdin.close()
        child.stdin = None
        response = bytearray()
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ, "upstream")
            if client is not None:
                ready.register(client, selectors.EVENT_READ, "client")
            while True:
                observe(diagnostic, "phase", "exchange-read")
                remaining = deadline - time.monotonic()
                events = ready.select(max(0, remaining))
                if remaining <= 0 or not events:
                    raise TimeoutError("weather_android_tunnel_deadline")
                if any(key.data == "client" for key, _ in events):
                    observe(diagnostic, "phase", "exchange-client")
                    # A bodyless, single-request caller has no further bytes to
                    # send. EOF is cancellation; extra bytes are a protocol error.
                    if not client.recv(1, socket.MSG_PEEK):
                        raise BrokenPipeError("weather_android_tunnel_cancelled")
                    raise ValueError("weather_android_tunnel_extra_request_data")
                chunk = os.read(child.stdout.fileno(), min(65536, MAX_RESPONSE + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                require(len(response) <= MAX_RESPONSE)
        observe(diagnostic, "phase", "exchange-join")
        observe(diagnostic, "http", response)
        status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        observe(diagnostic, "child_status", status)
        require(status == 0)
        observe(diagnostic, "phase", "exchange-deadline")
        if time.monotonic() >= deadline:
            raise TimeoutError("weather_android_tunnel_deadline")
        observe(diagnostic, "phase", "exchange-protocol")
        require(response.startswith(b"HTTP/1.1 ") and b"\r\n\r\n" in response)
        return bytes(response)
    except BaseException as error:
        observe(diagnostic, "capture", error)
        raise
    finally:
        try:
            observe(diagnostic, "phase", "exchange-cleanup")
            stop_child(child)
            observe(diagnostic, "cleaned", "exchange_child_joined", True)
        except BaseException as error:
            observe(diagnostic, "capture", error)
            raise
        finally:
            if child.stdin is not None:
                child.stdin.close()
            child.stdout.close()


def receive_request(connection, deadline):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        connection.settimeout(max(0.001, min(3, deadline - time.monotonic())))
        chunk = connection.recv(min(1024, MAX_REQUEST + 1 - len(request)))
        require(chunk)
        request.extend(chunk)
        require(time.monotonic() < deadline and len(request) <= MAX_REQUEST)
    return canonical_request(request_path(bytes(request)))


def same_socket(path, identity):
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISSOCK(current.st_mode) and current.st_uid == os.geteuid()
            and (current.st_dev, current.st_ino) == identity)


def serve(path, command, lifetime=480, *, notify=None, hold_open=False, observe_responses=False, diagnostic=None):
    observe(diagnostic, "phase", "listen")
    require(type(lifetime) is int and 1 <= lifetime <= 480)
    require(type(hold_open) is bool)
    require(type(observe_responses) is bool)
    # Only the host observes response hashes. The installed, fixed-name guest
    # helper stays standalone and needs no extra root-staged Python modules.
    response_observer = runpy.run_path(str(Path(__file__).with_name("weather-android-evidence.py")))["response_observation"] \
        if observe_responses else None
    path = Path(path)
    parent_info = owned(path.parent, stat.S_ISDIR, 0o700)
    require(path.is_absolute() and path.name == "core-api.sock" and len(os.fsencode(path)) < 104)
    require(not path.exists() and not path.is_symlink())
    require(not list(path.parent.iterdir()))
    deadline = time.monotonic() + lifetime
    counts = {route: 0 for route in ROUTES}
    identity = None
    result = dict(schema=1, kind="weather-android-api-tunnel", completed=0, requests=counts,
                  original_response_bytes=True, joined_core_acceptance=False, cleanup_confirmed=False)
    if observe_responses:
        result.update(schema=6, responses=[])
    previous_umask = os.umask(0o077)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))  # Exclusive bind; never unlink a pre-existing name.
        info = path.lstat()
        identity = (info.st_dev, info.st_ino)
        observe(diagnostic, "cleaned", "socket_removed", False)
        os.chmod(path, 0o600)
        owned(path, stat.S_ISSOCK, 0o600)
        server.listen(1)
        if notify:
            notify()
        while result["completed"] < MAX_REQUESTS:
            observe(diagnostic, "next_request", "accept")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("weather_android_tunnel_lifetime")
            server.settimeout(remaining)
            connection, _ = server.accept()
            with connection:
                observe(diagnostic, "phase", "request-read")
                request = receive_request(connection, min(deadline, time.monotonic() + 3))
                route = request_path(request)
                observe(diagnostic, "phase", "request-limit")
                observe(diagnostic, "selected", route)
                require(counts[route] < 3)
                counts[route] += 1
                observe(diagnostic, "admitted", route, counts[route])
                response = exchange(command, request, min(deadline, time.monotonic() + EXCHANGE_SECONDS),
                                    client=connection, diagnostic=diagnostic)
                observe(diagnostic, "phase", "response-observe")
                observation = response_observer(route, counts[route], response) if response_observer is not None else None
                observe(diagnostic, "phase", "response-send")
                connection.settimeout(max(0.001, min(5, deadline - time.monotonic())))
                connection.sendall(response)
                if time.monotonic() >= deadline:
                    raise TimeoutError("weather_android_tunnel_deadline")
                result["completed"] += 1
                observe(diagnostic, "completed", result["completed"])
                if observe_responses:
                    result["responses"].append(observation)
        require(set(counts.values()) == {3})
        if hold_open:
            observe(diagnostic, "next_request", "hold-open")
            # Keep the same inode available for the Android runner's final
            # identity check. The owner sends TERM only after joining that run.
            server.settimeout(max(0.001, deadline - time.monotonic()))
            unexpected, _ = server.accept()
            unexpected.close()
            raise ValueError("weather_android_tunnel_extra_request")
        return result
    except TunnelInterrupted as error:
        if hold_open and result["completed"] == MAX_REQUESTS:
            return result
        observe(diagnostic, "capture", error)
        raise
    except BaseException as error:
        observe(diagnostic, "capture", error)
        raise
    finally:
        observe(diagnostic, "phase", "socket-cleanup")
        try:
            server.close()
            os.umask(previous_umask)
            try:
                current_parent = owned(path.parent, stat.S_ISDIR, 0o700)
                parent_unchanged = ((current_parent.st_dev, current_parent.st_ino)
                                    == (parent_info.st_dev, parent_info.st_ino))
            except (OSError, ValueError):
                parent_unchanged = False
            if identity is not None and parent_unchanged and same_socket(path, identity):
                path.unlink()
                result["cleanup_confirmed"] = True
                observe(diagnostic, "cleaned", "socket_removed", True)
        except BaseException as error:
            observe(diagnostic, "capture", error)
            raise
        # A renamed/replaced path is not proof that our original name vanished.
        # Preserve the replacement and report uncertainty rather than delete it.


def read_until_eof(source, limit, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as ready:
        ready.register(source, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not ready.select(remaining):
                raise TimeoutError("weather_android_tunnel_deadline")
            chunk = os.read(source.fileno(), min(1024, limit + 1 - len(data)))
            if not chunk:
                if time.monotonic() >= deadline:
                    raise TimeoutError("weather_android_tunnel_deadline")
                return bytes(data)
            data.extend(chunk)
            require(len(data) <= limit)


def forward_response(upstream, sink, deadline):
    """Stop upstream work when the SSH response reader disappears."""
    watch = select.poll()
    watch.register(upstream, select.POLLIN | select.POLLERR | select.POLLHUP)
    watch.register(sink, select.POLLERR | select.POLLHUP)
    total = 0
    descriptor = sink.fileno()
    blocking = os.get_blocking(descriptor)
    os.set_blocking(descriptor, False)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("weather_android_tunnel_deadline")
            events = watch.poll(max(1, min(1000, int(remaining * 1000))))
            if any(fd == descriptor for fd, _ in events):
                raise BrokenPipeError("weather_android_tunnel_cancelled")
            if not events:
                continue
            upstream.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = upstream.recv(min(65536, MAX_RESPONSE + 1 - total))
            if time.monotonic() >= deadline:
                raise TimeoutError("weather_android_tunnel_deadline")
            if not chunk:
                return
            total += len(chunk)
            require(total <= MAX_RESPONSE)
            pending = memoryview(chunk)
            with selectors.DefaultSelector() as writable:
                writable.register(descriptor, selectors.EVENT_WRITE)
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not writable.select(remaining):
                        raise TimeoutError("weather_android_tunnel_deadline")
                    try:
                        count = os.write(descriptor, pending)
                    except BlockingIOError:
                        continue
                    require(count > 0)
                    pending = pending[count:]
    finally:
        os.set_blocking(descriptor, blocking)


def guest():
    require(sys.platform == "linux" and os.geteuid() == 0)
    owned(GUEST_STATE.parent, stat.S_ISDIR, 0o700, 0)
    info = owned(GUEST_STATE, stat.S_ISREG, 0o600, 0)
    require(info.st_size <= 2048 and info.st_nlink == 1)
    state = json.loads(GUEST_STATE.read_bytes())
    require(type(state) is dict and set(state) == {"schema", "socket", "control_gid", "expires_at"})
    require(type(state["schema"]) is int and state["schema"] == 1)
    group, expiry = state["control_gid"], state["expires_at"]
    require(type(group) is int and 1 <= group <= 65535
            and type(expiry) is int and 0 < expiry - time.time() <= 840)
    path = canonical(state["socket"])
    require(path.name == "core-api.sock" and len(os.fsencode(path)) < 104)
    owned(path.parent, stat.S_ISDIR, 0o700, 985)
    owned(path, stat.S_ISSOCK, 0o600, 985)
    # The fixed root-owned endpoint contains no arbitrary executable or account.
    # Drop all supplementary groups and both saved identities before any data IO.
    os.setgroups([])
    os.setresgid(group, group, group)
    os.setresuid(985, 985, 985)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(38, 1, 0, 0, 0) == 0)  # PR_SET_NO_NEW_PRIVS
    require(os.getresuid() == (985, 985, 985) and os.getgroups() == [])
    deadline = min(time.monotonic() + EXCHANGE_SECONDS, time.monotonic() + expiry - time.time())
    request = read_until_eof(sys.stdin.buffer, MAX_REQUEST, min(deadline, time.monotonic() + 3))
    require(request == canonical_request(request_path(request)))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
        upstream.settimeout(max(0.001, deadline - time.monotonic()))
        upstream.connect(str(path))
        upstream.sendall(request)
        forward_response(upstream, sys.stdout.buffer, deadline)


def main(diagnostic=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("guest")
    host = commands.add_parser("host")
    host.add_argument("--socket", required=True, type=Path)
    host.add_argument("--ssh-key", required=True, type=Path)
    host.add_argument("--known-hosts", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "guest":
        guest()
        return
    if diagnostic is not None: diagnostic.active = True
    observe(diagnostic, "phase", "admission")
    require(os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa"
            and os.environ.get("GITHUB_WORKFLOW") == "Weather Android protected core delivery")
    # Android sees only the socket parent; neither credentials nor other files.
    require(args.socket.parent.resolve() not in (args.ssh_key.parent.resolve(), args.known_hosts.parent.resolve()))
    result = serve(args.socket, ssh_command(args.ssh_key, args.known_hosts), hold_open=True, observe_responses=True,
        diagnostic=diagnostic)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_number, _frame):
        raise TunnelInterrupted("weather_android_tunnel_interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    diagnostic = TunnelDiagnostic()
    try:
        main(diagnostic)
    except (OSError, ValueError, TunnelInterrupted, subprocess.SubprocessError) as error:
        observe(diagnostic, "capture", error)
        emit_diagnostic(diagnostic)
        print("weather_android_tunnel_failed", file=sys.stderr)
        raise SystemExit(1) from None
