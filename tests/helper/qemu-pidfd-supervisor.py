#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Identity-bound, fail-closed lifecycle supervisor for one QEMU process."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import math
import os
import signal
import stat
import sys
import time
from dataclasses import dataclass
from typing import Callable, NoReturn, Sequence


PROTOCOL = "volparossa-qemu-pidfd-supervisor-v3"
PR_SET_PDEATHSIG = 1
POLL_SECONDS = 0.02
MAX_TIMEOUT_SECONDS = 300.0
MAX_STDERR_BYTES = 917_504
STDERR_READ_BYTES = 65_536
MAX_STDERR_DRAIN_BYTES_PER_POLL = 262_144
MAX_FINAL_STDERR_DRAIN_BYTES = 8_388_608
MAX_QMP_MESSAGE_BYTES = 65_536
MAX_QMP_RECORD_BYTES = 65_536
MAX_QMP_EVENTS = 64
MAX_QMP_STREAM_BYTES = 8_388_608
QMP_READ_BYTES = 65_536
MAX_QMP_DRAIN_BYTES_PER_POLL = 262_144
MAX_FINAL_QMP_DRAIN_BYTES = 8_388_608
QMP_EOF_GRACE_SECONDS = 1.0
QMP_CAPABILITIES_ID = "volparossa-capabilities"
QMP_CONT_ID = "volparossa-cont"
QMP_CAPABILITIES_COMMAND = (
    b'{"execute":"qmp_capabilities","id":"volparossa-capabilities"}\r\n'
)
QMP_CONT_COMMAND = b'{"execute":"cont","id":"volparossa-cont"}\r\n'
QMP_EVENT_NAMES = frozenset(("GUEST_PANICKED", "RESET", "SHUTDOWN", "STOP"))
QMP_SHUTDOWN_CAUSES = frozenset(
    (
        "guest-panic",
        "guest-reset",
        "guest-shutdown",
        "host-error",
        "host-qmp-quit",
        "host-qmp-system-reset",
        "host-signal",
        "host-ui",
        "none",
        "snapshot-load",
        "subsystem-reset",
    )
)
QMP_GUEST_PANIC_ACTIONS = frozenset(("pause", "poweroff", "run"))
PRIVATE_KEY_BEGIN = b"-----BEGIN "
PRIVATE_KEY_END = b"PRIVATE KEY-----"
REDACTED_STDERR = b"[stderr suppressed: private-key marker detected]\n"

EX_USAGE = 64
EX_DATAERR = 65
EX_UNAVAILABLE = 69
EX_SOFTWARE = 70
EX_OSERR = 71
_shutdown_signal: int | None = None
_libc = ctypes.CDLL(None, use_errno=True)
_libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.prctl.restype = ctypes.c_int


class SupervisorError(Exception):
    """A bounded, non-secret error suitable for standard error."""


class UsageError(SupervisorError):
    """Invalid command-line input."""


class ProtocolError(SupervisorError):
    """Invalid control-directory state."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        # argparse errors can echo attacker-controlled argument values. Keep the
        # diagnostic deliberately generic because workflow environments may
        # contain credentials in accidentally supplied arguments.
        raise UsageError("invalid command line")


@dataclass(frozen=True)
class Configuration:
    control_directory: str
    command: tuple[str, ...]
    grace_seconds: float
    term_seconds: float
    kill_seconds: float
    ack_timeout_seconds: float
    qmp_stdio: bool
    qmp_timeout_seconds: float


@dataclass(frozen=True)
class ChildOutcome:
    exit_code: int | None
    exit_signal: int | None


def _canonical_qmp_record(
    events: list[dict[str, object]],
    truncated: bool,
    failed: bool,
) -> bytes:
    return (
        json.dumps(
            {
                "events": events,
                "protocol": PROTOCOL,
                "state": "failed" if failed else "final",
                "truncated": truncated,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _allowlisted_qmp_value(value: object, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "unavailable"


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _finite_json_float(value: str) -> float:
    decoded = float(value)
    if not math.isfinite(decoded):
        raise ValueError("non-finite JSON number")
    return decoded


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


class QmpChannel:
    """A bounded QMP stdio state machine that never retains raw guest data."""

    def __init__(self, read_descriptor: int, write_descriptor: int) -> None:
        self._read_descriptor = read_descriptor
        self._write_descriptor = write_descriptor
        self._buffer = bytearray()
        self._events: list[dict[str, object]] = []
        self._events_truncated = False
        self._greeting_seen = False
        self._responses: set[str] = set()
        self._expected_response: str | None = None
        self._capabilities_enabled = False
        self._stream_bytes = 0
        self._failure: SupervisorError | None = None
        self._finalized = False

    @property
    def greeting_seen(self) -> bool:
        return self._greeting_seen

    def response_seen(self, response_id: str) -> bool:
        return response_id in self._responses

    @property
    def output_closed(self) -> bool:
        return self._read_descriptor < 0

    @property
    def event_record(self) -> bytes:
        if not self._finalized:
            raise SupervisorError("QMP events requested before finalization")
        return _canonical_qmp_record(
            self._events,
            self._events_truncated,
            self._failure is not None,
        )

    def close(self) -> None:
        for attribute in ("_read_descriptor", "_write_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, attribute, -1)

    def fail_if_invalid(self) -> None:
        if self._failure is not None:
            raise self._failure

    def mark_failed(self, message: str) -> None:
        self._fail(message)

    def _send(self, command: bytes, response_id: str) -> None:
        self.fail_if_invalid()
        if self._finalized or self._write_descriptor < 0:
            raise SupervisorError("QMP command channel is unavailable")
        if self._expected_response is not None:
            raise SupervisorError("QMP command response is still pending")
        self._expected_response = response_id
        view = memoryview(command)
        try:
            while view:
                written = os.write(self._write_descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short QMP command write")
                view = view[written:]
        except (BrokenPipeError, OSError) as error:
            self._fail("QMP command could not be sent")
            raise SupervisorError("QMP command could not be sent") from error

    def send_capabilities(self) -> None:
        if not self._greeting_seen or self._responses:
            raise SupervisorError("QMP capabilities command is out of order")
        self._send(QMP_CAPABILITIES_COMMAND, QMP_CAPABILITIES_ID)

    def send_cont(self) -> None:
        if QMP_CAPABILITIES_ID not in self._responses or QMP_CONT_ID in self._responses:
            raise SupervisorError("QMP cont command is out of order")
        self._send(QMP_CONT_COMMAND, QMP_CONT_ID)

    def _fail(self, message: str) -> None:
        if self._failure is None:
            self._failure = SupervisorError(message)
        self._buffer.clear()

    def _append_event(self, message: dict[str, object]) -> None:
        event_name = message.get("event")
        if event_name not in QMP_EVENT_NAMES:
            return
        event: dict[str, object] = {"event": event_name}
        data = message.get("data")
        if event_name in ("RESET", "SHUTDOWN"):
            if not isinstance(data, dict) or not {"guest", "reason"} <= set(data):
                self._fail("QMP reset or shutdown event data is invalid")
                return
            guest = data.get("guest")
            if not isinstance(guest, bool) or not isinstance(data.get("reason"), str):
                self._fail("QMP reset or shutdown event fields are invalid")
                return
            event["guest"] = guest
            event["reason"] = _allowlisted_qmp_value(
                data.get("reason"), QMP_SHUTDOWN_CAUSES
            )
        elif event_name == "GUEST_PANICKED":
            if (
                not isinstance(data, dict)
                or "action" not in data
                or not isinstance(data.get("action"), str)
            ):
                self._fail("QMP guest panic event data is invalid")
                return
            event["action"] = _allowlisted_qmp_value(
                data.get("action"), QMP_GUEST_PANIC_ACTIONS
            )
        if len(self._events) == MAX_QMP_EVENTS:
            self._events_truncated = True
            self._fail("QMP event count exceeds its hard limit")
            return
        self._events.append(event)

    def _valid_greeting(self, value: object) -> bool:
        if not isinstance(value, dict) or not {"capabilities", "version"} <= set(value):
            return False
        capabilities = value.get("capabilities")
        version = value.get("version")
        if not isinstance(capabilities, list) or not all(
            isinstance(capability, str) for capability in capabilities
        ):
            return False
        if not isinstance(version, dict) or not {"package", "qemu"} <= set(version):
            return False
        package = version.get("package")
        qemu = version.get("qemu")
        return (
            isinstance(package, str)
            and isinstance(qemu, dict)
            and {"major", "micro", "minor"} <= set(qemu)
            and all(
                isinstance(qemu.get(component), int)
                and not isinstance(qemu.get(component), bool)
                and 0 <= qemu[component] <= 2_147_483_647
                for component in ("major", "micro", "minor")
            )
        )

    def _consume_message(self, encoded: bytes) -> None:
        try:
            decoded = encoded.decode("ascii")
            message = json.loads(
                decoded,
                object_pairs_hook=_object_without_duplicate_keys,
                parse_constant=_reject_json_constant,
                parse_float=_finite_json_float,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
            self._fail("QMP emitted invalid JSON")
            return
        if not isinstance(message, dict):
            self._fail("QMP emitted a non-object message")
            return
        if "event" in message:
            if not self._capabilities_enabled:
                self._fail("QMP emitted an event before capabilities negotiation")
                return
            if (
                any(
                    discriminator in message
                    for discriminator in ("QMP", "error", "id", "return")
                )
                or "timestamp" not in message
                or not isinstance(message.get("event"), str)
                or not self._valid_timestamp(message.get("timestamp"))
                or ("data" in message and not isinstance(message.get("data"), dict))
            ):
                self._fail("QMP emitted an invalid event")
                return
            self._append_event(message)
            return
        if "QMP" in message:
            if (
                any(
                    discriminator in message
                    for discriminator in ("error", "event", "id", "return")
                )
                or self._greeting_seen
                or self._responses
                or not self._valid_greeting(message.get("QMP"))
            ):
                self._fail("QMP greeting is invalid or duplicated")
                return
            self._greeting_seen = True
            return
        response_id = message.get("id")
        if (
            self._expected_response is None
            or response_id != self._expected_response
            or any(discriminator in message for discriminator in ("QMP", "event"))
            or ("return" not in message and "error" not in message)
        ):
            self._fail("QMP emitted an unexpected response")
            return
        if response_id in self._responses:
            self._fail("QMP emitted a duplicate response")
            return
        if (
            "error" in message
            or not isinstance(message.get("return"), dict)
        ):
            self._fail("QMP rejected a fixed command")
            return
        self._responses.add(response_id)
        self._expected_response = None
        if response_id == QMP_CAPABILITIES_ID:
            self._capabilities_enabled = True

    def _valid_timestamp(self, value: object) -> bool:
        if not isinstance(value, dict) or not {"microseconds", "seconds"} <= set(value):
            return False
        seconds = value.get("seconds")
        microseconds = value.get("microseconds")
        if (
            not isinstance(seconds, int)
            or isinstance(seconds, bool)
            or not isinstance(microseconds, int)
            or isinstance(microseconds, bool)
        ):
            return False
        return (seconds == -1 and microseconds == -1) or (
            seconds >= 0 and 0 <= microseconds < 1_000_000
        )

    def _consume(self, chunk: bytes) -> None:
        self._stream_bytes += len(chunk)
        if self._stream_bytes > MAX_QMP_STREAM_BYTES:
            self._fail("QMP stream exceeds its lifetime size limit")
        if self._failure is not None:
            return
        self._buffer.extend(chunk)
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                if len(self._buffer) > MAX_QMP_MESSAGE_BYTES:
                    self._fail("QMP message exceeds its hard size limit")
                return
            if newline > MAX_QMP_MESSAGE_BYTES:
                self._fail("QMP message exceeds its hard size limit")
                return
            if newline == 0 or self._buffer[newline - 1] != 13:
                self._fail("QMP message is not terminated by exact CRLF")
                return
            encoded = bytes(self._buffer[: newline - 1])
            del self._buffer[: newline + 1]
            if not encoded:
                self._fail("QMP emitted an empty message")
                return
            self._consume_message(encoded)
            if self._failure is not None:
                return

    def drain(self, maximum_bytes: int) -> bool:
        if self._read_descriptor < 0:
            return True
        drained = 0
        while drained < maximum_bytes:
            try:
                chunk = os.read(self._read_descriptor, QMP_READ_BYTES)
            except BlockingIOError:
                return False
            except InterruptedError:
                continue
            except OSError:
                self._fail("QMP output cannot be drained")
                os.close(self._read_descriptor)
                self._read_descriptor = -1
                return True
            if not chunk:
                os.close(self._read_descriptor)
                self._read_descriptor = -1
                if self._buffer:
                    self._fail("QMP output ended with a partial message")
                return True
            drained += len(chunk)
            self._consume(chunk)
        return False

    def finalize(self) -> None:
        if self._finalized:
            return
        if self._write_descriptor >= 0:
            os.close(self._write_descriptor)
            self._write_descriptor = -1
        reached_eof = self.drain(MAX_FINAL_QMP_DRAIN_BYTES)
        if not reached_eof and self._read_descriptor >= 0:
            os.close(self._read_descriptor)
            self._read_descriptor = -1
            self._fail("QMP output did not close after child exit")
        self._finalized = True


class ControlDirectory:
    """A validated directory held open to prevent path substitution."""

    def __init__(self, path: str) -> None:
        if not os.path.isabs(path):
            raise ProtocolError("control directory must be absolute")
        normalized = os.path.normpath(path)
        if normalized != path or os.path.realpath(path) != path:
            raise ProtocolError("control directory path is not canonical")

        try:
            before = os.lstat(path)
        except OSError as error:
            raise ProtocolError("control directory is unavailable") from error
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ProtocolError("control directory is not a real directory")
        if before.st_uid != os.geteuid():
            raise ProtocolError("control directory owner is invalid")
        if stat.S_IMODE(before.st_mode) != 0o700:
            raise ProtocolError("control directory mode must be 0700")

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ProtocolError("control directory cannot be opened safely") from error

        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            os.close(descriptor)
            raise ProtocolError("control directory identity changed")
        self._descriptor = descriptor

        try:
            for name in ("ready", "stop", "qmp", "stderr", "status", "ack"):
                if self._entry_exists(name):
                    raise ProtocolError("control protocol file already exists")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._descriptor = -1

    def __enter__(self) -> "ControlDirectory":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _entry_exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise ProtocolError("control protocol file cannot be inspected") from error
        return True

    def input_exists(self, name: str) -> bool:
        try:
            metadata = os.stat(
                name,
                dir_fd=self._descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        except OSError as error:
            raise ProtocolError("control input cannot be inspected") from error

        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise ProtocolError("control input is not an empty private regular file")
        return True

    def write_bytes(self, name: str, value: bytes) -> None:
        if name not in ("ready", "qmp", "stderr", "status"):
            raise ProtocolError("control output name is invalid")
        maximum_bytes = MAX_QMP_RECORD_BYTES if name == "qmp" else MAX_STDERR_BYTES
        if len(value) > maximum_bytes:
            raise ProtocolError("control output exceeds its hard size limit")
        temporary_name = f".{name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=self._descriptor,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(value)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short control-file write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                name,
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
            )
            os.fsync(self._descriptor)
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=self._descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            raise ProtocolError("control output cannot be published atomically") from error

    def write_json(self, name: str, value: dict[str, object]) -> None:
        encoded = (
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
        self.write_bytes(name, encoded)


class ChildHandle:
    def __init__(
        self,
        process_id: int,
        pidfd: int,
        stderr_read: int,
        qmp: QmpChannel | None,
    ) -> None:
        self._process_id = process_id
        self._pidfd = pidfd
        self._stderr_read = stderr_read
        self._stderr_tail = bytearray()
        self._stderr_scan_tail = b""
        self._stderr_saw_private_key_begin = False
        self._stderr_contains_private_key_marker = False
        self._stderr_finalized = False
        self._outcome: ChildOutcome | None = None
        self._qmp = qmp
        self._qmp_eof_observed_at: float | None = None

    @property
    def outcome(self) -> ChildOutcome | None:
        return self._outcome

    @property
    def stderr_tail(self) -> bytes:
        if not self._stderr_finalized:
            raise SupervisorError("child stderr requested before finalization")
        if self._stderr_contains_private_key_marker:
            return REDACTED_STDERR
        return bytes(self._stderr_tail)

    @property
    def qmp(self) -> QmpChannel | None:
        return self._qmp

    @property
    def qmp_event_record(self) -> bytes:
        if self._qmp is None:
            raise SupervisorError("QMP events requested when QMP is disabled")
        return self._qmp.event_record

    def close(self) -> None:
        if self._pidfd >= 0:
            os.close(self._pidfd)
            self._pidfd = -1
        if self._stderr_read >= 0:
            os.close(self._stderr_read)
            self._stderr_read = -1
        if self._qmp is not None:
            self._qmp.close()

    def _drain_stderr(self, maximum_bytes: int) -> bool:
        if self._stderr_read < 0:
            return True
        drained = 0
        while drained < maximum_bytes:
            try:
                chunk = os.read(self._stderr_read, STDERR_READ_BYTES)
            except BlockingIOError:
                return False
            except InterruptedError:
                continue
            except OSError as error:
                raise SupervisorError("child stderr cannot be drained") from error
            if not chunk:
                os.close(self._stderr_read)
                self._stderr_read = -1
                return True
            drained += len(chunk)
            self._scan_stderr(chunk)
            self._stderr_tail.extend(chunk)
            excess = len(self._stderr_tail) - MAX_STDERR_BYTES
            if excess > 0:
                del self._stderr_tail[:excess]
        return False

    def _scan_stderr(self, chunk: bytes) -> None:
        combined = self._stderr_scan_tail + chunk
        search_from = 0
        if not self._stderr_saw_private_key_begin:
            begin_at = combined.find(PRIVATE_KEY_BEGIN)
            if begin_at >= 0:
                self._stderr_saw_private_key_begin = True
                search_from = begin_at + len(PRIVATE_KEY_BEGIN)
        if self._stderr_saw_private_key_begin and PRIVATE_KEY_END in combined[search_from:]:
            self._stderr_contains_private_key_marker = True
        carry_bytes = max(len(PRIVATE_KEY_BEGIN), len(PRIVATE_KEY_END)) - 1
        self._stderr_scan_tail = combined[-carry_bytes:]

    def _finalize_stderr(self) -> None:
        if self._stderr_finalized:
            return
        reached_eof = self._drain_stderr(MAX_FINAL_STDERR_DRAIN_BYTES)
        if not reached_eof and self._stderr_read >= 0:
            os.close(self._stderr_read)
            self._stderr_read = -1
        self._stderr_finalized = True
        if not reached_eof:
            raise SupervisorError("child stderr did not close after child exit")

    def poll(self, check_qmp_error: bool = True) -> ChildOutcome | None:
        if self._outcome is not None:
            if check_qmp_error and self._qmp is not None:
                self._qmp.fail_if_invalid()
            return self._outcome
        self._drain_stderr(MAX_STDERR_DRAIN_BYTES_PER_POLL)
        qmp_reached_eof = False
        if self._qmp is not None:
            qmp_reached_eof = self._qmp.drain(MAX_QMP_DRAIN_BYTES_PER_POLL)
            if qmp_reached_eof and self._qmp_eof_observed_at is None:
                self._qmp_eof_observed_at = time.monotonic()
            if check_qmp_error:
                self._qmp.fail_if_invalid()
        try:
            waited_process, wait_status = os.waitpid(self._process_id, os.WNOHANG)
        except ChildProcessError as error:
            raise SupervisorError("child reaping state is invalid") from error
        if waited_process == 0:
            if (
                qmp_reached_eof
                and self._qmp is not None
                and self._qmp_eof_observed_at is not None
                and time.monotonic() - self._qmp_eof_observed_at
                >= QMP_EOF_GRACE_SECONDS
            ):
                self._qmp.mark_failed("QMP output closed while the child was live")
                if check_qmp_error:
                    self._qmp.fail_if_invalid()
            return None
        if os.WIFEXITED(wait_status):
            self._outcome = ChildOutcome(os.WEXITSTATUS(wait_status), None)
        elif os.WIFSIGNALED(wait_status):
            self._outcome = ChildOutcome(None, os.WTERMSIG(wait_status))
        else:
            raise SupervisorError("child produced an unsupported wait status")
        try:
            self._finalize_stderr()
        finally:
            if self._qmp is not None:
                self._qmp.finalize()
        if check_qmp_error and self._qmp is not None:
            self._qmp.fail_if_invalid()
        return self._outcome

    def send(self, signal_number: int) -> bool:
        if self.poll(check_qmp_error=False) is not None:
            return False
        try:
            signal.pidfd_send_signal(self._pidfd, signal_number, None, 0)
        except ProcessLookupError:
            return False
        except OSError as error:
            raise SupervisorError("pidfd signal delivery failed") from error
        return True


def _parse_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(seconds) or seconds < 0.0 or seconds > MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"must be finite and between 0 and {MAX_TIMEOUT_SECONDS:g}"
        )
    return seconds


def parse_arguments(arguments: Sequence[str]) -> Configuration:
    parser = SafeArgumentParser(
        description="Supervise one QEMU process using Linux pidfds.",
        allow_abbrev=False,
    )
    parser.add_argument("--grace-seconds", type=_parse_seconds, default=5.0)
    parser.add_argument("--term-seconds", type=_parse_seconds, default=5.0)
    parser.add_argument("--kill-seconds", type=_parse_seconds, default=5.0)
    parser.add_argument("--ack-timeout-seconds", type=_parse_seconds, default=30.0)
    parser.add_argument("--qmp-stdio", action="store_true")
    parser.add_argument("--qmp-timeout-seconds", type=_parse_seconds, default=10.0)
    parser.add_argument("control_directory")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    namespace = parser.parse_args(arguments)
    command = tuple(namespace.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command or not command[0]:
        raise UsageError("COMMAND is required after --")
    if namespace.ack_timeout_seconds == 0.0:
        raise UsageError("--ack-timeout-seconds must be greater than zero")
    if namespace.kill_seconds == 0.0:
        raise UsageError("--kill-seconds must be greater than zero")
    if namespace.qmp_stdio and namespace.qmp_timeout_seconds == 0.0:
        raise UsageError("--qmp-timeout-seconds must be greater than zero")
    return Configuration(
        control_directory=namespace.control_directory,
        command=command,
        grace_seconds=namespace.grace_seconds,
        term_seconds=namespace.term_seconds,
        kill_seconds=namespace.kill_seconds,
        ack_timeout_seconds=namespace.ack_timeout_seconds,
        qmp_stdio=namespace.qmp_stdio,
        qmp_timeout_seconds=namespace.qmp_timeout_seconds,
    )


def _require_linux_pidfds() -> None:
    if not sys.platform.startswith("linux"):
        raise SupervisorError("Linux is required")
    if not callable(getattr(os, "pidfd_open", None)) or not callable(
        getattr(signal, "pidfd_send_signal", None)
    ):
        raise SupervisorError("Python pidfd support is required")


def _close_inherited_file_descriptors() -> None:
    null_descriptor = -1
    try:
        null_descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        if null_descriptor == 0:
            os.set_inheritable(0, True)
        else:
            os.dup2(null_descriptor, 0, inheritable=True)
    except OSError as error:
        raise SupervisorError("standard input cannot be isolated") from error
    finally:
        if null_descriptor > 0:
            os.close(null_descriptor)

    try:
        descriptors = tuple(int(name) for name in os.listdir("/proc/self/fd"))
    except (OSError, ValueError) as error:
        raise SupervisorError("open file descriptors cannot be enumerated safely") from error
    for descriptor in descriptors:
        if descriptor <= 2:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise SupervisorError("inherited file descriptor cannot be closed") from error


def _set_parent_death_signal(signal_number: int) -> None:
    result = _libc.prctl(PR_SET_PDEATHSIG, signal_number, 0, 0, 0)
    if result != 0:
        error_number = ctypes.get_errno()
        raise SupervisorError("PR_SET_PDEATHSIG failed") from OSError(error_number)


def _record_shutdown_signal(signal_number: int, _frame: object) -> None:
    global _shutdown_signal
    if _shutdown_signal is None:
        _shutdown_signal = signal_number


def _arm_supervisor_parent_death_signal() -> int:
    global _shutdown_signal
    _shutdown_signal = None
    original_parent = os.getppid()
    if original_parent <= 1:
        raise SupervisorError("supervisor has no live parent")
    for signal_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, _record_shutdown_signal)
    _set_parent_death_signal(signal.SIGTERM)
    if os.getppid() != original_parent:
        _shutdown_signal = signal.SIGTERM
    return original_parent


def _child_exec(
    supervisor_process_id: int,
    gate_read: int,
    gate_write: int,
    stderr_read: int,
    stderr_write: int,
    qmp_command_read: int,
    qmp_command_write: int,
    qmp_response_read: int,
    qmp_response_write: int,
    command: tuple[str, ...],
) -> NoReturn:
    try:
        os.close(gate_write)
        os.close(stderr_read)
        if qmp_command_write >= 0:
            os.close(qmp_command_write)
        if qmp_response_read >= 0:
            os.close(qmp_response_read)
        _set_parent_death_signal(signal.SIGKILL)
        if os.getppid() != supervisor_process_id:
            os._exit(125)
        while True:
            try:
                release = os.read(gate_read, 1)
                break
            except InterruptedError:
                continue
        os.close(gate_read)
        if release != b"1" or os.getppid() != supervisor_process_id:
            os._exit(125)
        os.dup2(stderr_write, 2, inheritable=True)
        if stderr_write != 2:
            os.close(stderr_write)
        if qmp_command_read >= 0 and qmp_response_write >= 0:
            os.dup2(qmp_command_read, 0, inheritable=True)
            os.dup2(qmp_response_write, 1, inheritable=True)
            if qmp_command_read != 0:
                os.close(qmp_command_read)
            if qmp_response_write != 1:
                os.close(qmp_response_write)
        child_environment = {
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
        }
        os.execvpe(command[0], command, child_environment)
    except BaseException:
        os._exit(126)


def _wait_for_outcome(
    handle: ChildHandle,
    seconds: float,
    check_qmp_error: bool = True,
) -> ChildOutcome | None:
    deadline = time.monotonic() + seconds
    while True:
        outcome = handle.poll(check_qmp_error=check_qmp_error)
        if outcome is not None:
            return outcome
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return None
        time.sleep(min(POLL_SECONDS, remaining))


def _wait_for_unbound_child(process_id: int, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            waited_process, _wait_status = os.waitpid(process_id, os.WNOHANG)
        except ChildProcessError:
            return
        if waited_process == process_id:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise SupervisorError("unbound fork child could not be reaped")
        time.sleep(min(POLL_SECONDS, remaining))


def _owner_is_live(original_parent: int) -> bool:
    return _shutdown_signal is None and os.getppid() == original_parent


def _launch_child(
    command: tuple[str, ...],
    original_parent: int,
    qmp_stdio: bool,
) -> ChildHandle:
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    stderr_read = -1
    stderr_write = -1
    qmp_command_read = -1
    qmp_command_write = -1
    qmp_response_read = -1
    qmp_response_write = -1
    try:
        stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(stderr_read, False)
        if qmp_stdio:
            qmp_command_read, qmp_command_write = os.pipe2(os.O_CLOEXEC)
            qmp_response_read, qmp_response_write = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(qmp_response_read, False)
    except OSError as error:
        os.close(gate_read)
        os.close(gate_write)
        if stderr_read >= 0:
            os.close(stderr_read)
        if stderr_write >= 0:
            os.close(stderr_write)
        for descriptor in (
            qmp_command_read,
            qmp_command_write,
            qmp_response_read,
            qmp_response_write,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        raise SupervisorError("child private pipe setup failed") from error
    supervisor_process_id = os.getpid()
    try:
        process_id = os.fork()
    except OSError as error:
        os.close(gate_read)
        os.close(gate_write)
        os.close(stderr_read)
        os.close(stderr_write)
        for descriptor in (
            qmp_command_read,
            qmp_command_write,
            qmp_response_read,
            qmp_response_write,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        raise SupervisorError("child fork failed") from error

    if process_id == 0:
        _child_exec(
            supervisor_process_id,
            gate_read,
            gate_write,
            stderr_read,
            stderr_write,
            qmp_command_read,
            qmp_command_write,
            qmp_response_read,
            qmp_response_write,
            command,
        )

    os.close(gate_read)
    os.close(stderr_write)
    if qmp_command_read >= 0:
        os.close(qmp_command_read)
    if qmp_response_write >= 0:
        os.close(qmp_response_write)
    try:
        pidfd = os.pidfd_open(process_id, 0)
    except OSError as error:
        os.close(gate_write)
        os.close(stderr_read)
        if qmp_command_write >= 0:
            os.close(qmp_command_write)
        if qmp_response_read >= 0:
            os.close(qmp_response_read)
        _wait_for_unbound_child(process_id, 2.0)
        raise SupervisorError("pidfd binding failed") from error

    qmp = (
        QmpChannel(qmp_response_read, qmp_command_write)
        if qmp_stdio
        else None
    )
    try:
        if not _owner_is_live(original_parent):
            raise SupervisorError("owner disappeared before child release")
        while True:
            try:
                written = os.write(gate_write, b"1")
                break
            except InterruptedError:
                continue
        if written != 1:
            raise SupervisorError("child release failed")
        if not _owner_is_live(original_parent):
            raise SupervisorError("owner disappeared during child release")
    except BaseException:
        os.close(gate_write)
        handle = ChildHandle(process_id, pidfd, stderr_read, qmp)
        try:
            handle.send(signal.SIGKILL)
            if _wait_for_outcome(handle, 2.0) is None:
                raise SupervisorError("released child could not be reaped")
        finally:
            handle.close()
        raise
    os.close(gate_write)
    return ChildHandle(process_id, pidfd, stderr_read, qmp)


def _wait_for_qmp_state(
    handle: ChildHandle,
    qmp: QmpChannel,
    control: ControlDirectory,
    original_parent: int,
    deadline: float,
    predicate: Callable[[], bool],
) -> None:
    while True:
        outcome = handle.poll(check_qmp_error=False)
        qmp.fail_if_invalid()
        if outcome is not None:
            raise SupervisorError("QMP child exited during handshake")
        if qmp.output_closed:
            raise SupervisorError("QMP output closed during handshake")
        trigger = _trigger(control, original_parent)
        if trigger is not None:
            raise SupervisorError("QMP handshake was interrupted")
        if predicate():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise SupervisorError("QMP handshake timed out")
        time.sleep(min(POLL_SECONDS, remaining))


def _initialize_qmp(
    handle: ChildHandle,
    control: ControlDirectory,
    original_parent: int,
    timeout_seconds: float,
) -> None:
    qmp = handle.qmp
    if qmp is None:
        raise SupervisorError("QMP initialization requested without QMP")
    deadline = time.monotonic() + timeout_seconds
    try:
        _wait_for_qmp_state(
            handle,
            qmp,
            control,
            original_parent,
            deadline,
            lambda: qmp.greeting_seen,
        )
        qmp.send_capabilities()
        _wait_for_qmp_state(
            handle,
            qmp,
            control,
            original_parent,
            deadline,
            lambda: qmp.response_seen(QMP_CAPABILITIES_ID),
        )
        qmp.send_cont()
        _wait_for_qmp_state(
            handle,
            qmp,
            control,
            original_parent,
            deadline,
            lambda: qmp.response_seen(QMP_CONT_ID),
        )
    except BaseException:
        qmp.mark_failed("QMP handshake failed")
        raise


def _trigger(
    control: ControlDirectory,
    original_parent: int,
) -> str | None:
    if control.input_exists("ack"):
        raise ProtocolError("ack appeared before status")
    if control.input_exists("stop"):
        return "stop-requested"
    if os.getppid() != original_parent:
        return "parent-death"
    if _shutdown_signal is not None:
        return "supervisor-signal"
    return None


def _terminate_child(
    handle: ChildHandle,
    grace_seconds: float,
    term_seconds: float,
    kill_seconds: float,
) -> tuple[ChildOutcome, str]:
    outcome = _wait_for_outcome(handle, grace_seconds)
    if outcome is not None:
        return outcome, "none"

    termination = "none"
    if handle.send(signal.SIGTERM):
        termination = "term"
    outcome = _wait_for_outcome(handle, term_seconds)
    if outcome is not None:
        return outcome, termination

    if handle.send(signal.SIGKILL):
        termination = "kill"
    outcome = _wait_for_outcome(handle, kill_seconds)
    if outcome is None:
        raise SupervisorError("child did not exit after SIGKILL")
    return outcome, termination


def _monitor_child(
    handle: ChildHandle,
    control: ControlDirectory,
    original_parent: int,
    configuration: Configuration,
) -> tuple[ChildOutcome, str, str]:
    while True:
        outcome = handle.poll()
        if outcome is not None:
            return outcome, "child-exit", "none"
        trigger = _trigger(control, original_parent)
        if trigger is not None:
            outcome, termination = _terminate_child(
                handle,
                configuration.grace_seconds,
                configuration.term_seconds,
                configuration.kill_seconds,
            )
            return outcome, trigger, termination
        time.sleep(POLL_SECONDS)


def _wait_for_ack(control: ControlDirectory, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        if control.input_exists("ack"):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return False
        time.sleep(min(POLL_SECONDS, remaining))


def _publish_status(
    control: ControlDirectory,
    outcome: ChildOutcome,
    trigger: str,
    termination: str,
) -> None:
    control.write_json(
        "status",
        {
            "exit_code": outcome.exit_code,
            "exit_signal": outcome.exit_signal,
            "protocol": PROTOCOL,
            "state": "exited",
            "termination": termination,
            "trigger": trigger,
        },
    )


def _publish_failure_status(control: ControlDirectory) -> None:
    control.write_json(
        "status",
        {
            "error": "supervisor-failure",
            "protocol": PROTOCOL,
            "state": "failed",
        },
    )


def _publish_stderr(
    control: ControlDirectory,
    handle: ChildHandle | None,
) -> None:
    stderr_tail = b"" if handle is None else handle.stderr_tail
    control.write_bytes("stderr", stderr_tail)


def _publish_qmp(
    control: ControlDirectory,
    handle: ChildHandle | None,
    enabled: bool,
) -> None:
    if not enabled:
        return
    if handle is None:
        event_record = _canonical_qmp_record([], False, True)
    else:
        event_record = handle.qmp_event_record
    control.write_bytes("qmp", event_record)


def _emergency_reap(handle: ChildHandle, kill_seconds: float) -> None:
    if handle.outcome is not None:
        return
    handle.send(signal.SIGKILL)
    if _wait_for_outcome(handle, kill_seconds, check_qmp_error=False) is None:
        raise SupervisorError("emergency child reaping did not complete")


def supervise(configuration: Configuration) -> int:
    _close_inherited_file_descriptors()
    with ControlDirectory(configuration.control_directory) as control:
        handle: ChildHandle | None = None
        qmp_published = False
        stderr_published = False
        status_published = False
        try:
            _require_linux_pidfds()
            original_parent = _arm_supervisor_parent_death_signal()
            handle = _launch_child(
                configuration.command,
                original_parent,
                configuration.qmp_stdio,
            )
            if configuration.qmp_stdio:
                _initialize_qmp(
                    handle,
                    control,
                    original_parent,
                    configuration.qmp_timeout_seconds,
                )
            control.write_json(
                "ready",
                {"protocol": PROTOCOL, "state": "ready"},
            )
            try:
                outcome, trigger, termination = _monitor_child(
                    handle,
                    control,
                    original_parent,
                    configuration,
                )
            except ProtocolError:
                outcome, termination = _terminate_child(
                    handle,
                    0.0,
                    configuration.term_seconds,
                    configuration.kill_seconds,
                )
                trigger = "control-error"
            _publish_qmp(control, handle, configuration.qmp_stdio)
            qmp_published = configuration.qmp_stdio
            _publish_stderr(control, handle)
            stderr_published = True
            _publish_status(control, outcome, trigger, termination)
            status_published = True
            if not _wait_for_ack(control, configuration.ack_timeout_seconds):
                raise SupervisorError("acknowledgement timeout")
            return 0 if trigger != "control-error" else EX_DATAERR
        except (OSError, ProtocolError, SupervisorError):
            if handle is not None:
                _emergency_reap(handle, configuration.kill_seconds)
            if not qmp_published:
                _publish_qmp(control, handle, configuration.qmp_stdio)
                qmp_published = configuration.qmp_stdio
            if not stderr_published:
                _publish_stderr(control, handle)
                stderr_published = True
            if not status_published:
                _publish_failure_status(control)
                status_published = True
                if not _wait_for_ack(control, configuration.ack_timeout_seconds):
                    raise SupervisorError(
                        "acknowledgement timeout after supervisor failure"
                    )
            raise
        finally:
            if handle is not None:
                try:
                    _emergency_reap(handle, configuration.kill_seconds)
                finally:
                    handle.close()


def main(arguments: Sequence[str]) -> int:
    try:
        configuration = parse_arguments(arguments)
    except UsageError as error:
        print(f"usage error: {error}", file=sys.stderr)
        return EX_USAGE
    try:
        return supervise(configuration)
    except ProtocolError as error:
        print(f"control protocol error: {error}", file=sys.stderr)
        return EX_DATAERR
    except SupervisorError as error:
        print(f"supervisor error: {error}", file=sys.stderr)
        return EX_UNAVAILABLE
    except OSError:
        print("supervisor error: operating-system operation failed", file=sys.stderr)
        return EX_OSERR
    except BaseException:
        print("supervisor error: unexpected internal failure", file=sys.stderr)
        return EX_SOFTWARE


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
