#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit source-only builder. No downloads, package installs or model execution.

Input must be the clean original commit; outputs are always a new directory.
The resulting build.json is provenance, not independent installation authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time

SOURCE = "7fe450e19305b828c199d602c23a8337aaa1f03b"
ORIGIN = "https://github.com/ggml-org/llama.cpp.git"
KIND = "llama_cpp_bf16_v1"
HERE = Path(__file__).resolve().parent
LIBRARY = "libvolparossa_llama_cpu.so"
ALLOWED_NEEDED = {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "ld-linux-x86-64.so.2"}
CHECK_TARGETS = ("vp-native-abi-smoke", "vp-native-bf16-tensors", "vp-upstream-tensor-tests")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(path):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "NATIVE_REGULAR_FILE_REQUIRED")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return {"bytes": meta.st_size, "sha256": result.hexdigest()}


def command(args, cwd=None, timeout=30):
    return subprocess.run(args, cwd=cwd, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout).stdout


def verify_source(source):
    require(source.is_absolute() and not source.is_symlink() and source.is_dir(), "NATIVE_SOURCE_PATH")
    require(command(["git", "rev-parse", "HEAD"], source).decode().strip() == SOURCE, "NATIVE_SOURCE_PIN")
    require(command(["git", "remote", "get-url", "origin"], source).decode().strip() == ORIGIN,
            "NATIVE_SOURCE_ORIGIN")
    require(not command(["git", "status", "--porcelain", "--untracked-files=all"], source),
            "NATIVE_SOURCE_DIRTY")
    return command(["git", "rev-parse", "HEAD^{tree}"], source).decode().strip()


def dependencies(raw):
    require(not re.search(r"\((?:RPATH|RUNPATH)\)", raw), "NATIVE_DYNAMIC_SEARCH_PATH")
    names = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", raw)
    require(names and len(names) == len(set(names)) and set(names) <= ALLOWED_NEEDED,
            "NATIVE_UNAPPROVED_DYNAMIC_DEPENDENCY")
    return sorted(names)


def write_json(path, value):
    with path.open("x", encoding="ascii") as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_build(args, log, env, timeout):
    process = subprocess.Popen(["nice", "-n", "19", *args], stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
    try:
        require(process.wait(timeout=timeout) == 0, "NATIVE_SOURCE_BUILD_FAILED")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def build(source, output, execute=False, checks=False, sanitize=False):
    tree = verify_source(source)
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "NATIVE_FRESH_OUTPUT")
    require(not output.is_relative_to(source) and not source.is_relative_to(output), "NATIVE_SOURCE_OUTPUT_OVERLAP")
    for tool in ("cmake", "c++", "cc", "readelf", "nice"):
        require(shutil.which(tool), "NATIVE_BUILD_TOOL_MISSING")
    require(not sanitize or checks, "NATIVE_SANITIZER_REQUIRES_CHECKS")
    plan = {"kind": KIND, "source_commit": SOURCE, "source_tree": tree,
            "sanitizers": sanitize, "provisionable": not sanitize,
            "jobs": 2, "models_loaded": False, "downloads": False, "install": False}
    if not execute:
        return plan
    output.mkdir(mode=0o700)
    started = time.monotonic()
    env = dict(os.environ)
    # Avoid inherited compiler/linker/pkgconfig overrides or arbitrary preload code.
    for key in list(env):
        if key.startswith(("LD_", "CMAKE_")) or key in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS", "CPATH", "LIBRARY_PATH", "PKG_CONFIG_PATH"):
            env.pop(key)
    epoch = command(["git", "show", "-s", "--format=%ct", SOURCE], source).decode().strip()
    require(re.fullmatch(r"[0-9]{10}", epoch), "NATIVE_SOURCE_TIMESTAMP")
    env.update(SOURCE_DATE_EPOCH=epoch, CMAKE_BUILD_PARALLEL_LEVEL="2")
    commands = [
        ["cmake", "-S", str(HERE / "native-cpu"), "-B", str(output / "build"),
         "-DVP_LLAMA_SOURCE=" + str(source), "-DCMAKE_BUILD_TYPE=Release",
         "-DVP_NATIVE_TESTS=" + ("ON" if checks else "OFF"),
         "-DVP_NATIVE_SANITIZE=" + ("ON" if sanitize else "OFF")],
        ["cmake", "--build", str(output / "build"), "--target", "volparossa_llama_cpu",
         *(CHECK_TARGETS if checks else []), "--parallel", "2"],
    ]
    with (output / "build.log").open("xb") as log:
        for args in commands:
            remaining = 1800 - (time.monotonic() - started)
            require(remaining > 0, "NATIVE_BUILD_DEADLINE")
            run_build(args, log, env, remaining)
    require(verify_source(source) == tree, "NATIVE_SOURCE_CHANGED")
    candidates = list((output / "build").rglob(LIBRARY))
    require(len(candidates) == 1, "NATIVE_LIBRARY_OUTPUT")
    library = output / LIBRARY
    shutil.copyfile(candidates[0], library)
    library.chmod(0o444)
    dynamic = command(["readelf", "--dynamic", str(library)]).decode("ascii")
    if sanitize:
        require(not re.search(r"\((?:RPATH|RUNPATH)\)", dynamic), "NATIVE_DYNAMIC_SEARCH_PATH")
        needed = sorted(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic))
        require(set(needed) <= ALLOWED_NEEDED | {"libasan.so.8", "libubsan.so.1"}, "NATIVE_SANITIZER_DEPENDENCIES")
    else:
        needed = dependencies(dynamic)
    if checks:
        check_env = dict(env, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        with (output / "checks.log").open("xb") as log:
            for target in CHECK_TARGETS:
                matches = list((output / "build").rglob(target))
                require(len(matches) == 1 and matches[0].is_file(), "NATIVE_CHECK_TARGET")
                run_build([str(matches[0])], log, check_env, min(120, 1800 - (time.monotonic() - started)))
    licenses = output / "licenses"
    licenses.mkdir(mode=0o700)
    # Preserve all tracked notices, not only the top-level MIT declaration.
    tracked = command(["git", "ls-files", "-z"], source).decode().split("\0")
    for name in tracked:
        if name and ("LICENSE" in Path(name).name.upper() or "COPYING" in Path(name).name.upper()
                     or "NOTICE" in Path(name).name.upper()):
            original = source / name
            if original.is_file() and not original.is_symlink():
                target = licenses / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(original, target)
                target.chmod(0o444)
    runtime_archives = {}
    for compiler, name in (("c++", "libstdc++.a"), ("cc", "libgcc.a"), ("cc", "libgcc_eh.a")):
        path = Path(command([compiler, "-print-file-name=" + name]).decode().strip()).resolve(strict=True)
        runtime_archives[name] = digest(path)
    compiler_major = command(["c++", "-dumpversion"]).decode().strip()
    require(re.fullmatch(r"[0-9]{1,2}", compiler_major), "NATIVE_TOOLCHAIN_NOTICE")
    runtime_notice = Path("/usr/share/doc") / ("gcc-" + compiler_major + "-base") / "copyright"
    require(runtime_notice.is_file(), "NATIVE_TOOLCHAIN_NOTICE")
    shutil.copyfile(runtime_notice, licenses / "GCC-runtime-copyright")
    (licenses / "GCC-runtime-copyright").chmod(0o444)
    report = dict(plan, version=1, abi_version=1, library={"path": LIBRARY, **digest(library)},
                  dynamic_dependencies=needed, cpu="avx2_fma_f16c", quantization=False,
                  checks=list(CHECK_TARGETS) if checks else [],
                  known_upstream_sanitizer_failure={
                      "scope": "all_type_synthetic_tensor_test", "kind": "ubsan_misaligned_load",
                      "source": "ggml/src/ggml-cpu/arch/x86/quants.c:590",
                      "function": "ggml_vec_dot_q1_0_q8_0", "original_log_bytes": 412,
                      "original_log_sha256": "37e07701e4f9a7fadbee0876f77d7eb034192e951a4cd2da572606255bf84f08"},
                  static_runtime_archives=runtime_archives, runtime_notice=digest(runtime_notice),
                  wrapper_sources={name: digest(HERE / "native-cpu" / name)
                                   for name in ("CMakeLists.txt", "adapter.h", "adapter.cpp")},
                  tool_versions={tool: command([tool, "--version"]).decode().splitlines()[0]
                                 for tool in ("cmake", "c++", "cc")})
    write_json(output / "build.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--checks", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.source, args.output, args.execute, args.checks, args.sanitize), sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError):
        parser.exit(1, "NATIVE_CPU_BUILD_FAILED\n")


if __name__ == "__main__":
    main()
