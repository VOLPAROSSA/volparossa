# SPDX-License-Identifier: GPL-3.0-only
"""Connection-owned RAM lifetime, selected only by the fixed core supervisor.

No listener, session token, file-cache export or cross-owner lookup exists here.
Each turn still performs the full original source/GGUF/input validation. The
parent independently owns admission, pressure, deadlines and joined cleanup.
"""
import contextlib
import math
import os
import resource
import select
import sys
import time

MAX_TASK_SECONDS = 2400
MAX_IDLE_SECONDS = 300
MAX_REQUESTS = 128


class Runtime:
    def __init__(self, worker):
        self.worker = worker
        native = sys.modules.get("volparossa_llama_cpu")
        worker.require(native is not None, "NATIVE_BACKEND_MODULE_UNAVAILABLE")
        self.model = native.RetainedModel()
        self.loaded, self.loaded_tokenizer, self.threads = None, None, None

    def backend(self, threads, session):
        self.worker.require(self.threads is None or self.threads == threads, "NATIVE_SESSION_MODEL_CHANGED")
        if self.loaded is None:
            self.loaded = self.worker.load_backend(threads, session)
            self.threads = threads
        session.check()
        return self.loaded

    def tokenizer(self, transformers, root):
        if self.loaded_tokenizer is None:
            self.loaded_tokenizer = transformers.AutoTokenizer.from_pretrained(
                str(root), local_files_only=True, trust_remote_code=False, use_fast=True)
        return self.loaded_tokenizer

    def close(self):
        try:
            self.model.close()
        finally:
            self.loaded_tokenizer, self.loaded = None, None


def turn_cpu_limit(request, require):
    """New lifetime only: retain the old per-turn allowance and fixed task hard cap.

    SIGXCPU keeps its default terminating disposition. Parent /proc observation
    checks the same turn delta; neither path guesses unknown CPU consumption.
    """
    usage = resource.getrusage(resource.RUSAGE_SELF)
    consumed = usage.ru_utime + usage.ru_stime
    require(math.isfinite(consumed) and consumed >= 0, "NATIVE_SESSION_CPU_OBSERVATION")
    hard = MAX_TASK_SECONDS * request["threads"]
    _soft, actual_hard = resource.getrlimit(resource.RLIMIT_CPU)
    require(actual_hard == hard and consumed < hard, "NATIVE_SESSION_CPU_BOUND")
    allowance = request["max_seconds"] * request["threads"]
    resource.setrlimit(resource.RLIMIT_CPU, (min(hard, math.ceil(consumed) + allowance), hard))


def read_frame(frames, deadline, worker, *, eof=False):
    while True:
        worker.require(not worker.is_stopping(), "JOB_CANCELLED")
        worker.require(time.monotonic() < deadline, "NATIVE_SESSION_DEADLINE")
        raw = frames.take(worker.MAX_REQUEST, "INVALID_REQUEST_FRAME")
        if raw is not None:
            return worker.parse_json(raw)
        if not select.select([frames.descriptor], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
            continue
        try:
            block = os.read(frames.descriptor, min(4096, worker.MAX_REQUEST - len(frames.pending)))
        except BlockingIOError:
            continue
        if not block:
            worker.require(eof and not frames.pending, "OWNER_CONTROL_CLOSED")
            return None
        frames.pending.extend(block)


def settle_turn(session, deadline, worker):
    # Controls written just before result observation belong to the old request,
    # never to the next turn. No further model work happens in this handshake.
    while True:
        value = read_frame(session.frames, deadline, worker)
        if value == {"version": 1, "id": session.request["id"], "kind": "native_turn_finish"}:
            worker.require(type(value["version"]) is int, "INVALID_NATIVE_SESSION_FINISH")
            break
        raw = worker.json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        worker.require(len(raw) <= worker.MAX_CONTROL_LINE, "INVALID_CONTROL_FRAME")
        session.accept_control(raw)
    worker.emit({"version": 1, "id": session.request["id"], "kind": "native_turn_idle"})


def run(first, frames, worker):
    runtime, session, request = Runtime(worker), None, first
    started, turn, seen = time.monotonic(), 0, set()
    binding = tuple(first[key] for key in ("model_profile", "inference_backend", "native_backend_sha256", "threads", "max_seconds"))
    try:
        while request is not None:
            turn += 1
            worker.require(turn <= MAX_REQUESTS and request["native_session"]["turn"] == turn
                           and request["id"] not in seen, "INVALID_NATIVE_SESSION_SEQUENCE")
            seen.add(request["id"])
            worker.require(binding == tuple(request[key] for key in
                           ("model_profile", "inference_backend", "native_backend_sha256", "threads", "max_seconds")),
                           "NATIVE_SESSION_MODEL_CHANGED")
            worker.require(time.monotonic() < started + MAX_TASK_SECONDS, "NATIVE_SESSION_DEADLINE")
            turn_cpu_limit(request, worker.require)
            session = worker.Session(request, frames)
            with open(os.devnull, "w", encoding="ascii") as quiet:
                with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                    result = worker.execute_job(request, session, native_session=runtime)
            worker.emit(result)
            settle_turn(session, min(started + MAX_TASK_SECONDS, session.started + request["max_seconds"]), worker)
            # Drop the complete request/result; retained private tokens/KV have a
            # separate explicit lifetime. This does not claim secure RAM erasure.
            session, result = None, None
            # The parent owns the exact 300-second idle boundary and closes this
            # pipe. A second independently started idle clock must not race its
            # joined close into an erroneous failed turn. The task backstop is
            # still finite here and the parent's earlier deadline always wins.
            value = read_frame(frames, started + MAX_TASK_SECONDS, worker, eof=True)
            request = None if value is None else worker.validate_request(value)
            worker.require(request is None or "native_session" in request, "INVALID_NATIVE_SESSION")
        return 0
    except worker.JobError as error:
        code = str(error)
    except (FileNotFoundError, NotADirectoryError):
        code = "JOB_INPUT_NOT_FOUND"
    except PermissionError:
        code = "JOB_PATH_PERMISSION_DENIED"
    except MemoryError:
        code = "JOB_MEMORY_EXHAUSTED"
    except ImportError:
        code = "BACKEND_IMPORT_FAILED"
    except Exception:
        code = "BACKEND_EXECUTION_FAILED"
    finally:
        runtime.close()
    failure = {"version": 1, "id": request["id"] if request is not None else first["id"],
               "kind": "result", "status": "error", "code": code,
               "elapsed_ms": session.elapsed() if session is not None else 0}
    if session is not None:
        failure["owner_control"] = session.owner_stats()
    worker.emit(failure)
    return 1
