#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit source-only builder. No downloads, package installs or model execution.

Input must be the clean original commit; outputs are always a new directory.
The resulting build.json is provenance, not independent installation authority.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time

import llama_cpu as native

SOURCE = "7fe450e19305b828c199d602c23a8337aaa1f03b"
ORIGIN = "https://github.com/ggml-org/llama.cpp.git"
KIND = "llama_cpp_bf16_v1"
HERE = Path(__file__).resolve().parent
LIBRARY = "libvolparossa_llama_cpu.so"
ALLOWED_NEEDED = {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "ld-linux-x86-64.so.2"}
CHECK_TARGETS = ("vp-native-abi-smoke", "vp-native-loader-validation", "vp-native-bf16-tensors",
                 "vp-native-output-constraint", "vp-native-session", "vp-upstream-tensor-tests")
WRAPPER_FILES = ("CMakeLists.txt", "adapter.h", "adapter.cpp", "bounded-tensor-validation.patch",
                 "output-constraint.h", "output-constraint.cpp", "session-state.h", "q1-aligned-load.patch")


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
    tree = command(["git", "rev-parse", "HEAD^{tree}"], source).decode().strip()
    require(tree == native.SOURCE_TREE, "NATIVE_SOURCE_TREE")
    return tree


def patched_loader(source):
    """Only one exact upstream file is transformed; source is never modified."""
    original = source / "src/llama-model-loader.cpp"
    require(digest(original)["sha256"] == native.LOADER_ORIGINAL_SHA, "NATIVE_LOADER_ORIGINAL")
    patch_path = HERE / "native-cpu/bounded-tensor-validation.patch"
    require(digest(patch_path)["sha256"] == native.LOADER_PATCH_SHA, "NATIVE_LOADER_PATCH")
    before = original.read_text(encoding="utf-8")
    require(before.count("std::async(std::launch::async,") == 2, "NATIVE_LOADER_LAUNCH_SHAPE")
    after = before.replace("std::async(std::launch::async,", "std::async(std::launch::deferred,")
    old = "    for (auto & future : validation_result) {\n        auto result = future.get();"
    new = ("    for (auto & future : validation_result) {\n"
           "        // Complete validation stays on this execution thread; poll owner cancellation\n"
           "        // between tensors without exposing data or acknowledging pause while loading.\n"
           "        if (progress_callback && !progress_callback((float) size_done / size_data, progress_callback_user_data)) {\n"
           "            return false;\n        }\n        auto result = future.get();")
    require(after.count(old) == 1, "NATIVE_LOADER_JOIN_SHAPE")
    after = after.replace(old, new)
    patch = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                     fromfile="a/src/llama-model-loader.cpp", tofile="b/src/llama-model-loader.cpp"))
    require(patch.encode() == patch_path.read_bytes(), "NATIVE_LOADER_PATCH_SHAPE")
    result = after.encode("utf-8")
    require(hashlib.sha256(result).hexdigest() == native.LOADER_EFFECTIVE_SHA, "NATIVE_LOADER_EFFECTIVE")
    return result


def stage_loader(source, output):
    data = patched_loader(source)
    overlay = output / "loader-overlay"
    overlay.mkdir(mode=0o700)
    target = overlay / "llama-model-loader.cpp"
    with target.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o444)
    return target


def verify_loader_compilation(output, loader):
    path = output / "build/compile_commands.json"
    require(digest(path)["bytes"] <= 16 * 1024 * 1024, "NATIVE_COMPILE_DATABASE_BOUND")
    entries = json.loads(path.read_bytes())
    require(type(entries) is list and 1 <= len(entries) <= 4096, "NATIVE_COMPILE_DATABASE_SHAPE")
    matches = [Path(row["file"]) for row in entries if Path(row["file"]).name == loader.name]
    require(matches == [loader] and not loader.is_symlink()
            and digest(loader)["sha256"] == native.LOADER_EFFECTIVE_SHA, "NATIVE_COMPILED_LOADER")


def patched_cpu(source):
    """Copy Q1 bytes into aligned scalar storage; preserve all arithmetic."""
    original = source / native.CPU_ORIGINAL_PATH
    require(digest(original)["sha256"] == native.CPU_ORIGINAL_SHA, "NATIVE_CPU_ORIGINAL")
    patch_path = HERE / "native-cpu/q1-aligned-load.patch"
    require(digest(patch_path)["sha256"] == native.CPU_PATCH_SHA, "NATIVE_CPU_PATCH")
    before = original.read_text(encoding="utf-8")
    old = "        const uint32_t * GGML_RESTRICT qs32 = (const uint32_t *) x[ib].qs;\n"
    new = "        uint32_t qs32[4];\n        memcpy(qs32, x[ib].qs, sizeof(qs32));\n"
    require(before.count(old) == 1, "NATIVE_CPU_LOAD_SHAPE")
    after = before.replace(old, new)
    patch = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                     fromfile="a/" + native.CPU_ORIGINAL_PATH, tofile="b/" + native.CPU_ORIGINAL_PATH))
    require(patch.encode() == patch_path.read_bytes(), "NATIVE_CPU_PATCH_SHAPE")
    result = after.encode("utf-8")
    require(hashlib.sha256(result).hexdigest() == native.CPU_EFFECTIVE_SHA, "NATIVE_CPU_EFFECTIVE")
    return result


def stage_cpu(source, output):
    data = patched_cpu(source)
    overlay = output / "cpu-overlay"
    overlay.mkdir(mode=0o700)
    target = overlay / "quants.c"
    with target.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o444)
    return target


def verify_cpu_compilation(output, source):
    path = output / "build/compile_commands.json"
    require(digest(path)["bytes"] <= 16 * 1024 * 1024, "NATIVE_COMPILE_DATABASE_BOUND")
    entries = json.loads(path.read_bytes())
    require(type(entries) is list and 1 <= len(entries) <= 4096, "NATIVE_COMPILE_DATABASE_SHAPE")
    staged = output / "cpu-overlay/quants.c"
    files = [Path(row["file"]).resolve() if Path(row["file"]).is_absolute()
             else (Path(row["directory"]) / row["file"]).resolve() for row in entries]
    require(files.count(staged.resolve()) == 1 and (source / native.CPU_ORIGINAL_PATH).resolve() not in files
            and not staged.is_symlink() and digest(staged)["sha256"] == native.CPU_EFFECTIVE_SHA,
            "NATIVE_COMPILED_CPU")
    entry = entries[files.index(staged.resolve())]
    require(type(entry.get("command")) is str, "NATIVE_COMPILED_CPU_TARGET")
    command = shlex.split(entry["command"])
    require(command.count("-o") == 1 and command.index("-o") + 1 < len(command),
            "NATIVE_COMPILED_CPU_TARGET")
    target = Path(command[command.index("-o") + 1]).parts
    require(any(target[i:i + 2] == ("CMakeFiles", "ggml-cpu.dir") for i in range(len(target) - 1)),
            "NATIVE_COMPILED_CPU_TARGET")
    require(command.count("-c") == 1 and command.index("-c") + 1 < len(command),
            "NATIVE_COMPILED_CPU_COMMAND")
    compiled = Path(command[command.index("-c") + 1])
    require(Path(entry["directory"]).is_absolute(), "NATIVE_COMPILED_CPU_COMMAND")
    if not compiled.is_absolute():
        compiled = Path(entry["directory"]) / compiled
    require(compiled.resolve() == staged.resolve(), "NATIVE_COMPILED_CPU_COMMAND")


def stage_loader_checks(loader):
    """Source-derived toy check: actual launch/join statements, never a model."""
    require(digest(loader)["sha256"] == native.LOADER_EFFECTIVE_SHA, "NATIVE_LOADER_EFFECTIVE")
    source = loader.read_text(encoding="utf-8")
    launches = re.findall(r"validation_result\.emplace_back\(std::async\(std::launch::deferred,[\s\S]*?\}\)\);", source)
    require(len(launches) == 2, "NATIVE_LOADER_CHECK_SHAPE")
    start = source.index("    // check validation results\n")
    end = source.index("    // check if this is the last call and do final cleanup\n", start)
    fragments = dict(mapped=launches[0], host=launches[1], join=source[start:end])
    for name, fragment in fragments.items():
        path = loader.parent / ("validation-" + name + ".inc")
        with path.open("x", encoding="utf-8") as stream:
            stream.write(fragment + "\n")
        path.chmod(0o444)


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
    patched_loader(source)
    patched_cpu(source)
    plan = {"kind": KIND, "source_commit": SOURCE, "source_tree": tree,
            "output_constraints": [native.OUTPUT_CONSTRAINT],
            "native_sessions": [native.NATIVE_SESSION],
            "sanitizers": sanitize, "provisionable": not sanitize,
            "source_overlay": native.loader_provenance(),
            "cpu_source_overlay": native.cpu_provenance(),
            "jobs": 2, "models_loaded": False, "downloads": False, "install": False}
    if not execute:
        return plan
    wrapper_sources = {name: digest(HERE / "native-cpu" / name) for name in WRAPPER_FILES}
    output.mkdir(mode=0o700)
    loader = stage_loader(source, output)
    cpu = stage_cpu(source, output)
    if checks:
        stage_loader_checks(loader)
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
         "-DVP_LLAMA_MODEL_LOADER=" + str(loader), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
         "-DVP_LLAMA_CPU_QUANTS=" + str(cpu),
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
    require(wrapper_sources == {name: digest(HERE / "native-cpu" / name) for name in WRAPPER_FILES},
            "NATIVE_WRAPPER_CHANGED_DURING_BUILD")
    verify_loader_compilation(output, loader)
    verify_cpu_compilation(output, source)
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
                log.write(("NATIVE_CHECK_BEGIN " + target + "\n").encode("ascii"))
                log.flush()
                run_build([str(matches[0])], log, check_env, min(120, 1800 - (time.monotonic() - started)))
                log.write(("NATIVE_CHECK_PASS " + target + "\n").encode("ascii"))
                log.flush()
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
    report = dict(plan, version=4, abi_version=1, library={"path": LIBRARY, **digest(library)},
                  upstream_original_unchanged=True, loader_compile_source_verified=True,
                  cpu_compile_source_verified=True,
                  dynamic_dependencies=needed, cpu="avx2_fma_f16c", quantization=False,
                  checks=list(CHECK_TARGETS) if checks else [],
                  historical_unpatched_sanitizer_failure={
                      "scope": "all_type_synthetic_tensor_test", "kind": "ubsan_misaligned_load",
                      "source": "ggml/src/ggml-cpu/arch/x86/quants.c:590",
                      "function": "ggml_vec_dot_q1_0_q8_0", "original_log_bytes": 412,
                      "original_log_sha256": "37e07701e4f9a7fadbee0876f77d7eb034192e951a4cd2da572606255bf84f08"},
                  static_runtime_archives=runtime_archives, runtime_notice=digest(runtime_notice),
                  wrapper_sources=wrapper_sources,
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
