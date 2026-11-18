#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Freeze exact reviewed Weather/UI/runtime inputs; never execute captured files.

The separately retained manifest hash authorizes transfer, not runtime execution.
Outputs live outside this immutable tree. The enclosing VM supplies the separately
verified core binary; no mutable package install or data download occurs here.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tarfile

B = runpy.run_path(str(Path(__file__).with_name("browser-filter-bundle.py")))
KIND = "volparossa-weather-client-inputs"
WEATHER = "volparossa-weather/"
BROWSER = "volparossa-browser/"
STAGE = BROWSER + "build/firefox-esr-smoke-v3/"
UI_STAGE = WEATHER + "build/drizzli-volparossa/"
STATIC = UI_STAGE + "build/"
NODE_SHA = "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"
DECODER_SHA = "3a3b64581e6922db4287445f217f993f6967dea5fcc45ff66944b0bc883408f4"
PIN_SHA = "f136020562a6ff0d2a83b948189c31f839afb8a00ea87565469f38640fb0dc86"
BUILD_SHA = "5bcb6d58b34e5b45647feae836bfd086ff0adce0e30487430f5c50941f579827"
PROVEN_BRIDGE_MODULES = frozenset(("src/provider-http.mjs", "src/provider-core.mjs", "src/core-cache.mjs"))
PROVEN_BROWSER_HELPERS = frozenset(("scripts/smoke_compute_model.py", "scripts/smoke_privacy.py", "scripts/stage_firefox.py"))
PROVEN_RUNTIME_FILES = frozenset(("firefox-esr", "libxul.so", "omni.ja", "browser/omni.ja"))
PROVEN_WEATHER_MODULES = frozenset(("src/forecast.mjs", "src/provider.mjs"))
RUNTIME_FILES = frozenset(name for name in B["RUNTIME_FILES"] if not name.startswith("distribution/"))
WEATHER_FILES = frozenset(("LICENSE", "src/forecast.mjs", "src/ecmwf.mjs", "src/core-cache.mjs",
    "src/provider.mjs", "src/provider-core.mjs", "src/provider-http.mjs", "scripts/forecast.mjs",
    "scripts/serve-provider.mjs", "scripts/build_eccodes.py", "third_party/eccodes-sources.json",
    "build/eccodes/build-receipt.json", "integrations/drizzli/upstream.json",
    "integrations/drizzli/upstream.patch", "integrations/drizzli/browser-smoke.json",
    "integrations/drizzli/smoke_browser.py", "integrations/drizzli/smoke_core_browser.py",
    "integrations/drizzli/prepare-core-browser.mjs",
    "third_party/eccodes/licenses/eccodes/LICENSE", "third_party/eccodes/licenses/eccodes/NOTICE",
    "third_party/eccodes/licenses/ecbuild/LICENSE", "third_party/eccodes/licenses/ecbuild/NOTICE",
    "third_party/eccodes/licenses/ecbuild/COPYING", "third_party/eccodes/licenses/libaec/LICENSE.txt",
    "third_party/eccodes/licenses/expected/COPYING"))
BROWSER_FILES = frozenset(("defaults/privacy.json", "scripts/smoke_compute_model.py",
    "scripts/smoke_privacy.py", "scripts/stage_firefox.py"))
CLIENT_FILES = frozenset(("LICENSE", *("src/lib/services/volparossa/" + name + ".mjs"
    for name in ("client", "provider", "forecast"))))
FIXED = frozenset({*(WEATHER + name for name in WEATHER_FILES),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES),
    *(UI_STAGE + name for name in CLIENT_FILES), "runtime/node", "decoder/grib_ls"})
# Version 1 remains the exact frozen temperature/wind input contract. Version 2
# selects the separate precipitation/particulate runner. Input eligibility does
# not constitute evidence that either runtime has completed a live proof.
AQ_MODULES = frozenset(("src/air-quality.mjs", "src/air-quality-provider.mjs"))
OVERLAY_FILES = frozenset(("src/lib/services/volparossa/client.mjs",
    "src/lib/services/volparossa/client.d.mts", "src/lib/services/volparossa-mode.ts",
    "src/routes/weather/week/VolparossaForecast.svelte", "src/routes/weather/week/VolparossaWeek.svelte",
    "src/routes/weather/week/VolparossaAirQuality.svelte"))
FIXTURE_MODULES = frozenset(("tests/fixtures.mjs", "tests/air-quality-fixtures.mjs", "src/ecmwf.mjs"))
NOAA_MODULES = frozenset(("src/noaa-gefs.mjs", "src/air-quality.mjs", "src/core-cache.mjs", "scripts/air-quality.mjs"))
ECMWF_MODULES = frozenset(("src/ecmwf.mjs", "src/forecast.mjs", "src/provider.mjs", "scripts/forecast.mjs"))
WEATHER_FILES_V2 = (WEATHER_FILES - {"integrations/drizzli/browser-smoke.json"}) | AQ_MODULES | NOAA_MODULES | FIXTURE_MODULES | {
    "src/air-quality-core.mjs", "third_party/noaa-gefs.json", "third_party/noaa-gefs-smoke.json",
    "third_party/ecmwf-precipitation-smoke.json",
    "integrations/drizzli/air-quality-browser-smoke.json", "integrations/drizzli/browser-fixture.mjs",
    *("integrations/drizzli/overlay/" + name for name in OVERLAY_FILES)}
CLIENT_FILES_V2 = CLIENT_FILES | OVERLAY_FILES | {"LICENSE.VOLPAROSSA",
    *("src/lib/services/volparossa/" + Path(name).name for name in AQ_MODULES)}
FIXED_V2 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V2),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES),
    *(UI_STAGE + name for name in CLIENT_FILES_V2), "runtime/node", "decoder/grib_ls"})
# A distinct consumer profile, not a relaxation or reinterpretation of v1/v2.
UI_STAGE_V3 = WEATHER + "build/overmorrow-app/"
STATIC_V3 = WEATHER + "build/overmorrow-web/"
OVERMORROW_OVERLAY = frozenset(("lib/api_key.dart", "lib/volparossa/products.dart",
    "lib/volparossa/profile.dart", "lib/volparossa/provider.dart", "lib/volparossa/views.dart",
    "test/volparossa_products_test.dart", "test/volparossa_provider_test.dart",
    "test/volparossa_ui_test.dart", "web/flutter_bootstrap.js"))
OVERMORROW_BRIDGE = PROVEN_BRIDGE_MODULES | PROVEN_WEATHER_MODULES | AQ_MODULES | {"src/air-quality-core.mjs"}
OVERMORROW_FIXTURE = FIXTURE_MODULES | {"integrations/overmorrow/test-fixtures.mjs", "integrations/drizzli/browser-fixture.mjs"}
OVERMORROW_PROOF = "integrations/overmorrow/browser-proof.json"
OVERMORROW_FILES = frozenset(("upstream.json", "upstream.patch", "build-verification.json", "deploy.py",
    "smoke_browser.py", "smoke_core_browser.py", "prepare_core_browser.mjs", "browser-fixture.mjs", "test-fixtures.mjs"))
WEATHER_FILES_V3 = frozenset({*(name for name in WEATHER_FILES_V2 if not name.startswith("integrations/")),
    *("integrations/drizzli/" + name for name in ("smoke_browser.py", "smoke_core_browser.py",
                                                 "prepare-core-browser.mjs", "browser-fixture.mjs")),
    *("integrations/overmorrow/" + name for name in OVERMORROW_FILES),
    *("integrations/overmorrow/overlay/" + name for name in OVERMORROW_OVERLAY), OVERMORROW_PROOF})
CLIENT_FILES_V3 = OVERMORROW_OVERLAY | {"LICENSE", "LICENSE.VOLPAROSSA", "pubspec.lock"}
FIXED_V3 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V3),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES),
    *(UI_STAGE_V3 + name for name in CLIENT_FILES_V3), "runtime/node", "decoder/grib_ls"})
STATIC_REQUIRED_V3 = frozenset(("index.html", "version.json", "flutter.js", "main.dart.js", "favicon.png",
    "manifest.json", "flutter_bootstrap.js", "canvaskit/canvaskit.js", "canvaskit/canvaskit.wasm",
    "canvaskit/chromium/canvaskit.js", "canvaskit/chromium/canvaskit.wasm", "assets/NOTICES",
    "assets/AssetManifest.bin", "LICENSE.txt", "LICENSE.VOLPAROSSA.txt"))
STATIC_ASSET_EXTENSIONS_V3 = frozenset((".png", ".jpg", ".jpeg", ".webp", ".svg", ".ttf", ".otf",
    ".woff", ".woff2", ".json", ".bin", ".frag"))
# Public hosted Drizz.li has a separate reviewed admission, never a relaxation of
# the historical machine-derived runtime or its decoder/source proofs.
ADMISSION_V4 = Path(__file__).with_name("weather-public-drizzli-v4.json")
DECODER_SHA_V4 = "d99425a1b44fe11b9ff77918310bc1b1a2114957558481bd705851e314a59930"
BUILD_SHA_V4 = "1c9b10e294189ffc0fd5a2064c4e436f691aa4e50cd0eea258e7976740ac17e4"
RUNTIME_FILES_V4 = RUNTIME_FILES - {"browser/defaults/syspref/firefox-esr.js",
    "browser/extensions/langpack-nl@firefox-esr.mozilla.org.xpi"}
HOSTED_PROOF = "integrations/drizzli/hosted-browser-proof.json"
HOSTED_PREFIX = "integrations/drizzli/hosted-proof/"
HOSTED_PROOFS = {HOSTED_PROOF: "drizzli-hosted-browser-ci/report.json",
    **{HOSTED_PREFIX + name + ".json": "hosted-clients-ci/" + name + ".json" for name in
       ("build", "result", "cleanup", "baseline", "steps", "preflight-acquire", "preflight-compile", "preflight-browser")},
    HOSTED_PREFIX + "runtime-provenance.json": "hosted-client-runtime/provenance.json",
    HOSTED_PREFIX + "packages.txt": "hosted-client-packages.txt"}
ABI_LOGS = frozenset(("elf.log", "sandbox.log", "version.log", "decode-first.log", "decode-last.log"))
DECODER_LICENSES = frozenset(("ecbuild-source/LICENSE", "ecbuild-source/NOTICE", "ecbuild-source/COPYING",
    "libaec-source/LICENSE.txt", "eccodes-source/LICENSE", "eccodes-source/NOTICE", "eccodes-source/COPYING",
    "eccodes-source/third_party/expected/COPYING"))
WEATHER_FILES_V4 = frozenset({*(name for name in WEATHER_FILES_V2 if not name.startswith("third_party/eccodes/licenses/")
    and name not in {"build/eccodes/build-receipt.json", "third_party/noaa-gefs-smoke.json",
        "third_party/ecmwf-precipitation-smoke.json", "integrations/drizzli/air-quality-browser-smoke.json"}),
    "scripts/prepare_hosted_decoder.py", "scripts/prepare_hosted_runtime.py",
    "third_party/hosted-runtime-inputs.json", "third_party/hosted-runtime-npm.json"})
CLIENT_FILES_V4 = CLIENT_FILES_V2 | {"package-lock.json",
    "volparossa-build-plugins/message-format.LICENSE", "volparossa-build-plugins/m-function-matcher.LICENSE"}
FIXED_V4 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V4),
    *(WEATHER + name for name in HOSTED_PROOFS),
    WEATHER + HOSTED_PREFIX + "decoder-build.json", WEATHER + HOSTED_PREFIX + "decoder-abi.json",
    *(WEATHER + HOSTED_PREFIX + "decoder-abi/" + name for name in ABI_LOGS),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES_V4),
    *(UI_STAGE + name for name in CLIENT_FILES_V4), *("decoder/licenses/" + name for name in DECODER_LICENSES),
    "runtime/node", "runtime/node.LICENSE", "runtime/firefox-copyright", "decoder/grib_ls", "decoder/probe.grib2"})
# Public CanvasKit uses its own reviewed record. Missing real hosted evidence
# leaves this profile closed; no synthetic fixture is written as admission.
ADMISSION_V5 = Path(__file__).with_name("weather-public-overmorrow-v5.json")
HOSTED_OVERMORROW_PROOF = "integrations/overmorrow/hosted-browser-proof.json"
HOSTED_OVERMORROW_TABLE = "integrations/overmorrow/hosted-table-proof.json"
HOSTED_OVERMORROW_PREFIX = "integrations/overmorrow/hosted-proof/"
HISTORICAL_OVERMORROW_DRIVER = HOSTED_OVERMORROW_PREFIX + "historical-smoke_core_browser_v3.py"
HOSTED_OVERMORROW_PROOFS = {
    HOSTED_OVERMORROW_PROOF: "overmorrow-hosted-browser-ci/report.json",
    HOSTED_OVERMORROW_TABLE: "overmorrow-hosted-table-ci/report.json",
    **{HOSTED_OVERMORROW_PREFIX + name + ".json": "hosted-overmorrow-ci/" + name + ".json" for name in
       ("build", "result", "cleanup", "baseline", "steps", "deployment", "sdk-binding", "system-tools",
        "tool-state-acquired", "tool-state-final",
        "preflight-acquire", "preflight-compile", "preflight-browser", "preflight-table-browser")},
    HOSTED_OVERMORROW_PREFIX + "runtime-provenance.json": "hosted-client-runtime/provenance.json",
    HOSTED_OVERMORROW_PREFIX + "sdk-provenance.json": "hosted-flutter-sdk/provenance.json",
    HOSTED_OVERMORROW_PREFIX + "packages.txt": "hosted-overmorrow-packages.txt"}
WEATHER_FILES_V5 = frozenset({*(name for name in WEATHER_FILES_V4 if not name.startswith("integrations/")),
    *("integrations/drizzli/" + name for name in ("smoke_browser.py", "smoke_core_browser.py",
                                                 "prepare-core-browser.mjs", "browser-fixture.mjs")),
    *("integrations/overmorrow/" + name for name in (OVERMORROW_FILES - {"build-verification.json"}) |
        {"smoke_table_browser.py", "table-fixture.mjs"}),
    *("integrations/overmorrow/overlay/" + name for name in OVERMORROW_OVERLAY),
    "scripts/prepare_hosted_flutter.py", "tests/precipitation-fixtures.mjs"})
FIXED_V5 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V5),
    *(WEATHER + name for name in HOSTED_OVERMORROW_PROOFS), WEATHER + HISTORICAL_OVERMORROW_DRIVER,
    WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-build.json", WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-abi.json",
    *(WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-abi/" + name for name in ABI_LOGS),
    *(BROWSER + name for name in BROWSER_FILES), *(STAGE + name for name in RUNTIME_FILES_V4),
    *(UI_STAGE_V3 + name for name in CLIENT_FILES_V3), *("decoder/licenses/" + name for name in DECODER_LICENSES),
    "runtime/node", "runtime/node.LICENSE", "runtime/firefox-copyright", "decoder/grib_ls", "decoder/probe.grib2"})
# Android executes outside the core VM. Its guest bundle contains only the
# production API/acquisition modules and the independently proven decoder.
# No browser, APK, SDK, fixture provider or prior UI success is guest authority.
ADMISSION_V6 = Path(__file__).with_name("weather-public-android-v6.json")
ANDROID_PREFIX = "integrations/overmorrow/android-core-inputs/"
WEATHER_FILES_V6 = frozenset({"LICENSE", "src/ecmwf.mjs", "src/forecast.mjs", "src/provider.mjs",
    "src/noaa-gefs.mjs", "src/air-quality.mjs", "src/air-quality-provider.mjs", "src/air-quality-core.mjs",
    "src/core-cache.mjs", "src/provider-core.mjs", "src/provider-http.mjs", "src/android-proof-receipts.mjs",
    "scripts/forecast.mjs", "scripts/air-quality.mjs", "scripts/serve-provider.mjs",
    "scripts/build_eccodes.py", "scripts/prepare_hosted_decoder.py", "third_party/eccodes-sources.json",
    "third_party/noaa-gefs.json", "third_party/hosted-runtime-inputs.json"})
FIXED_V6 = frozenset({*(WEATHER + name for name in WEATHER_FILES_V6),
    WEATHER + ANDROID_PREFIX + "decoder-build.json", WEATHER + ANDROID_PREFIX + "decoder-abi.json",
    *(WEATHER + ANDROID_PREFIX + "decoder-abi/" + name for name in ABI_LOGS),
    *("decoder/licenses/" + name for name in DECODER_LICENSES),
    "runtime/node", "runtime/node.LICENSE", "decoder/grib_ls", "decoder/probe.grib2"})
EXECUTABLES = frozenset({"runtime/node", "decoder/grib_ls", *(STAGE + name for name in
    ("firefox-esr", "firefox-bin", "crashhelper", "crashreporter", "glxtest", "vaapitest", "pingsender"))})
MAX_FILES = 512
MAX_MANIFEST = 128 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 2 * 1024 * 1024
MAX_STATIC = 32 * 1024 * 1024
require, hex64, encode = B["require"], B["hex64"], B["encode"]
fingerprint, open_checked, identity = B["fingerprint"], B["open_checked"], B["identity"]
header, read_exact, new_path = B["header"], B["read_exact"], B["new_path"]


def decoder_sha(version):
    require(type(version) is int and version in (1, 2, 3, 4, 5, 6))
    return DECODER_SHA_V4 if version in (4, 5, 6) else DECODER_SHA


def pin_sha(version):
    decoder_sha(version)
    return PIN_SHA


def build_sha(version):
    decoder_sha(version)
    return BUILD_SHA_V4 if version in (4, 5, 6) else BUILD_SHA


def build_source(version):
    decoder_sha(version)
    return "scripts/prepare_hosted_decoder.py" if version in (4, 5, 6) else "scripts/build_eccodes.py"


def mode(name):
    return 0o500 if name in EXECUTABLES else 0o400


def bound(name):
    if name.startswith(STAGE) or name in ("runtime/node", "decoder/grib_ls"):
        return MAX_FILE
    return 8 * 1024 * 1024 if name.startswith((STATIC, STATIC_V3)) else 1024 * 1024


def static_name(name, version=1):
    if version == 6:
        return False
    prefix = STATIC_V3 if version in (3, 5) else STATIC
    safe = name.startswith(prefix) and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}", part)
        and part not in (".", "..") for part in name[len(prefix):].split("/"))
    if not safe or version not in (3, 5):
        return safe
    relative = name[len(prefix):]
    return (relative in STATIC_REQUIRED_V3
        or relative.startswith("assets/") and Path(relative).suffix in STATIC_ASSET_EXTENSIONS_V3
        or relative.startswith("icons/") and Path(relative).suffix == ".png")


def manifest(raw, expected):
    require(hex64(expected) and 0 < len(raw) <= MAX_MANIFEST and hashlib.sha256(raw).hexdigest() == expected)
    value = json.loads(raw, object_pairs_hook=B["unique_pairs"])
    require(type(value) is dict and set(value) == {"version", "kind", "files"}
        and type(value["version"]) is int and value["version"] in (1, 2, 3, 4, 5, 6) and value["kind"] == KIND
        and type(value["files"]) is dict
        and 1 <= len(value["files"]) <= MAX_FILES and encode(value) == raw)
    version = value["version"]
    fixed = {1: FIXED, 2: FIXED_V2, 3: FIXED_V3, 4: FIXED_V4, 5: FIXED_V5, 6: FIXED_V6}[version]
    prefix = STATIC_V3 if version in (3, 5) else STATIC
    required_static = set() if version == 6 else (STATIC_REQUIRED_V3 if version in (3, 5) else {"index.html"})
    require(fixed <= set(value["files"]) and all(name in fixed or static_name(name, version) for name in value["files"])
        and {prefix + name for name in required_static} <= set(value["files"]))
    total = static_bytes = 0
    for name, item in value["files"].items():
        require(type(item) is dict and set(item) == {"bytes", "mode", "sha256"}
            and type(item["bytes"]) is int and 0 < item["bytes"] <= bound(name)
            and type(item["mode"]) is int and item["mode"] == mode(name) and hex64(item["sha256"]))
        total += item["bytes"]
        static_bytes += item["bytes"] if name.startswith(prefix) else 0
    require(total <= MAX_TOTAL and static_bytes <= MAX_STATIC)
    for name, expected_sha in (("runtime/node", NODE_SHA), ("decoder/grib_ls", decoder_sha(version)),
            (WEATHER + "third_party/eccodes-sources.json", pin_sha(version)), (WEATHER + build_source(version), build_sha(version))):
        require(value["files"][name]["sha256"] == expected_sha)
    if version == 4:
        # A caller's manifest hash only identifies transferred bytes. The exact
        # reviewed public/source inventory remains independent runtime authority.
        require({name: {key: item[key] for key in ("bytes", "sha256")} for name, item in value["files"].items()}
            == public_admission()["files"])
    elif version == 5:
        require({name: {key: item[key] for key in ("bytes", "sha256")} for name, item in value["files"].items()}
            == public_overmorrow_admission()["files"])
    elif version == 6:
        require({name: {key: item[key] for key in ("bytes", "sha256")} for name, item in value["files"].items()}
            == public_android_admission()["files"])
    return value


def inventory(root, *, exact=None, normalized=False):
    B["canonical"](root)
    files, pending, count = {}, [root], 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o7022)
        if normalized:
            require(stat.S_IMODE(info.st_mode) == 0o500)
        with os.scandir(directory) as children:
            for child in children:
                count += 1
                require(count <= MAX_FILES * 4)
                path = Path(child.path)
                relative = str(path.relative_to(root))
                require(len(path.relative_to(root).parts) <= 20)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(child.is_file(follow_symlinks=False))
                    files[relative] = path
                    require(len(files) <= MAX_FILES)
    if exact is not None:
        require(set(files) == set(exact))
        require(B["directories"](files) == {str(path.relative_to(root)) for path in root.rglob("*") if path.is_dir()})
    return files


def small_json(path):
    source, info = open_checked(path, 1024 * 1024)
    with source:
        raw = source.read(1024 * 1024 + 1)
        require(len(raw) == info.st_size and identity(os.fstat(source.fileno())) == identity(info))
    return json.loads(raw, object_pairs_hook=B["unique_pairs"])


def validate_public_admission(value, version=4):
    """Reviewed source data, not a user-supplied execution grant or release key."""
    require(type(version) is int and version in (4, 5))
    fixed, prefix = (FIXED_V4, STATIC) if version == 4 else (FIXED_V5, STATIC_V3)
    require(type(value) is dict and set(value) == {"schema", "kind", "scope", "sources", "artifacts", "files"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == ("volparossa-weather-public-drizzli-admission" if version == 4
                              else "volparossa-weather-public-overmorrow-admission")
        and value["scope"] == "disposable-joined-weather-only")
    require(type(value["sources"]) is dict and set(value["sources"]) == {"weather", "browser"})
    for item in value["sources"].values():
        require(type(item) is dict and set(item) == {"commit"} and type(item["commit"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", item["commit"]) is not None)
    require(type(value["artifacts"]) is dict and set(value["artifacts"]) == {"assets", "proof", "decoder", "abi"})
    for name, item in value["artifacts"].items():
        require(type(item) is dict and set(item) == {"repository", "run_id", "commit", "id", "name", "sha256", "bytes"}
            and item["repository"] == ("VOLPAROSSA/volparossa" if name == "abi" else "VOLPAROSSA/volparossa-weather")
            and type(item["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", item["commit"]) is not None
            and type(item["name"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", item["name"]) is not None
            and all(type(item[key]) is int and 0 < item[key] < 2**53 for key in ("run_id", "id", "bytes"))
            and hex64(item["sha256"]))
    require(all(value["artifacts"]["assets"][key] == value["artifacts"]["proof"][key]
        for key in ("repository", "run_id", "commit")))
    files = value["files"]
    required_static = {"index.html"} if version == 4 else STATIC_REQUIRED_V3
    require(type(files) is dict and len(fixed) < len(files) <= MAX_FILES
        and fixed <= set(files) and {prefix + name for name in required_static} <= set(files)
        and all(name in fixed or static_name(name, version) for name in files))
    for name, item in files.items():
        require(type(item) is dict and set(item) == {"bytes", "sha256"}
            and type(item["bytes"]) is int and 0 < item["bytes"] <= bound(name) and hex64(item["sha256"]))
    require(sum(item["bytes"] for item in files.values()) <= MAX_TOTAL
        and sum(item["bytes"] for name, item in files.items() if name.startswith(prefix)) <= MAX_STATIC)
    for name, digest in (("runtime/node", NODE_SHA), ("decoder/grib_ls", DECODER_SHA_V4),
            (WEATHER + "third_party/eccodes-sources.json", PIN_SHA),
            (WEATHER + "scripts/prepare_hosted_decoder.py", BUILD_SHA_V4)):
        require(files[name]["sha256"] == digest)
    return value


def public_admission():
    return validate_public_admission(small_json(ADMISSION_V4))


def public_overmorrow_admission():
    return validate_public_admission(small_json(ADMISSION_V5), 5)


def validate_android_admission(value):
    """Reviewed disposable Android/core inputs, never successful runtime evidence."""
    require(type(value) is dict and set(value) == {"schema", "kind", "scope", "sources", "artifacts", "files"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "volparossa-weather-public-android-admission"
        and value["scope"] == "disposable-joined-android-core-only"
        and type(value["sources"]) is dict and set(value["sources"]) == {"weather"})
    source = value["sources"]["weather"]
    require(type(source) is dict and set(source) == {"commit"} and type(source["commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None)
    require(type(value["artifacts"]) is dict and set(value["artifacts"]) == {"decoder", "abi"})
    for name, item in value["artifacts"].items():
        require(type(item) is dict and set(item) == {"repository", "run_id", "commit", "id", "name", "sha256", "bytes"}
            and item["repository"] == ("VOLPAROSSA/volparossa" if name == "abi" else "VOLPAROSSA/volparossa-weather")
            and type(item["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", item["commit"]) is not None
            and type(item["name"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,160}", item["name"]) is not None
            and all(type(item[key]) is int and 0 < item[key] < 2**53 for key in ("run_id", "id", "bytes"))
            and hex64(item["sha256"]))
    files = value["files"]
    require(type(files) is dict and set(files) == FIXED_V6)
    for name, item in files.items():
        require(type(item) is dict and set(item) == {"bytes", "sha256"}
            and type(item["bytes"]) is int and 0 < item["bytes"] <= bound(name) and hex64(item["sha256"]))
    require(sum(item["bytes"] for item in files.values()) <= MAX_TOTAL)
    for name, digest in (("runtime/node", NODE_SHA), ("decoder/grib_ls", DECODER_SHA_V4),
            (WEATHER + "third_party/eccodes-sources.json", PIN_SHA),
            (WEATHER + "scripts/prepare_hosted_decoder.py", BUILD_SHA_V4)):
        require(files[name]["sha256"] == digest)
    return value


def public_android_admission():
    return validate_android_admission(small_json(ADMISSION_V6))


def proven_hashes(value, names):
    # A truncated retained map must not silently skip a source-binding check.
    require(type(value) is dict and set(value) == set(names) and all(hex64(digest) for digest in value.values()))
    return value


def source_proof(weather, browser, ui, stage, selected, version=1):
    """Check retained build provenance; do not run either project's validators."""
    require(type(version) is int and version in (1, 2))
    proof = small_json(weather / ("integrations/drizzli/browser-smoke.json" if version == 1
                                 else "integrations/drizzli/air-quality-browser-smoke.json"))
    upstream = small_json(weather / "integrations/drizzli/upstream.json")
    require(proof["passed"] is True and proof["scope"]["synthetic_weather"] is True
        and proof["scope"]["core_executed"] is False)
    hashes = {name[len(STATIC):]: item["sha256"] for name, item in selected.items() if name.startswith(STATIC)}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(digest == proof["source"]["built_tree_sha256"] and len(hashes) == proof["source"]["built_files"]
        and sum(item["bytes"] for name, item in selected.items() if name.startswith(STATIC)) == proof["source"]["built_bytes"])
    require(proof["source"]["upstream"] == upstream["commit"] and proof["source"]["tree"] == upstream["tree"]
        and selected[UI_STAGE + "LICENSE"]["sha256"] == upstream["license_sha256"]
        and selected[WEATHER + "integrations/drizzli/upstream.patch"]["sha256"]
            == upstream["upstream_patch_sha256"] == proof["source"]["patch_sha256"]
        and selected[WEATHER + "integrations/drizzli/smoke_browser.py"]["sha256"] == proof["source"]["driver_sha256"])
    module_names = PROVEN_WEATHER_MODULES | (AQ_MODULES if version == 2 else set())
    weather_modules = proven_hashes(upstream["weather_modules"], module_names)
    require(weather_modules == proven_hashes(proof["source"]["weather_modules"], module_names))
    for module, expected_sha in weather_modules.items():
        digest = selected[WEATHER + module]["sha256"]
        require(digest == selected[UI_STAGE + "src/lib/services/volparossa/" + Path(module).name]["sha256"]
            == expected_sha)
    overlay = proof["source"]["overlay_sha256"]
    if version == 2:
        overlay = proven_hashes(overlay, OVERLAY_FILES)
    require(selected[UI_STAGE + "src/lib/services/volparossa/client.mjs"]["sha256"]
        == overlay["src/lib/services/volparossa/client.mjs"])
    bridge_names = PROVEN_BRIDGE_MODULES | ({"src/air-quality-core.mjs"} if version == 2 else set())
    for relative, digest in proven_hashes(proof["source"]["bridge_modules"], bridge_names).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    for relative, digest in proven_hashes(proof["source"]["browser_helpers"], PROVEN_BROWSER_HELPERS).items():
        require(selected[BROWSER + relative]["sha256"] == digest)
    metadata = small_json(stage / "volparossa-staging.json")
    runtime = proven_hashes(metadata["runtime_sha256"], PROVEN_RUNTIME_FILES)
    require(runtime == proven_hashes(proof["runtime"]["sha256"], PROVEN_RUNTIME_FILES)
        and metadata["defaults_sha256"] == selected[BROWSER + "defaults/privacy.json"]["sha256"]
        and metadata["autoconfig_sha256"] == selected[STAGE + "volparossa.cfg"]["sha256"])
    for relative, digest in runtime.items():
        require(selected[STAGE + relative]["sha256"] == digest)
    decoder_proof(weather)
    if version == 2:
        extended_source_proof(weather, selected, proof)


def decoder_proof(weather):
    build = small_json(weather / "build/eccodes/build-receipt.json")
    require(build["compiled"] is True and build["embedded_definitions"] is True
        and build["required_environment"] == {} and build["source_pin_sha256"] == PIN_SHA
        and build["build_script_sha256"] == BUILD_SHA and build["original_sources_unchanged"] is True)
    require(type(build["artifacts"]) is list and 1 <= len(build["artifacts"]) <= 16)
    artifacts = {}
    for item in build["artifacts"]:
        require(type(item) is dict and set(item) == {"path", "bytes", "sha256"}
            and type(item["path"]) is str and len(item["path"]) <= 256 and item["path"] not in artifacts
            and type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_FILE and hex64(item["sha256"]))
        artifacts[item["path"]] = item
    require(artifacts.get("build/eccodes/eccodes-build/bin/grib_ls")
        == dict(path="build/eccodes/eccodes-build/bin/grib_ls", bytes=31328216, sha256=DECODER_SHA))


def extended_source_proof(weather, selected, proof):
    """Bind separate historical source/UI proofs, never infer joined delivery."""
    require(proof["phase"] == "complete" and proof["scenario"] == "precipitation"
        and proof["air_quality_scenario"] is True and proof["wrapper_outcome"] == "completed"
        and proof["scope"]["synthetic_air_quality"] is True
        and proof["scope"]["actual_drizzli_ui"] is True and proof["scope"]["actual_http_bridge"] is True
        and proof["scope"]["overlay_proven"] is False and proof["scope"]["upstream_origin_proven"] is False
        and proof["runtime"]["node_sha256"] == NODE_SHA)
    for group, names in (("cleanup", ("browser_exited", "fixture_exited", "private_profile_removed",
                                     "normal_browser_stop", "normal_fixture_stop")),
                         ("outer_cleanup", ("namespace_wrapper_exited", "private_profile_removed", "host_netns_unchanged"))):
        require(all(proof[group][name] is True for name in names))
    for name in ("precipitation_native_windows", "precipitation_missing_zero_small_amount", "precipitation_no_hourly_rate",
                 "air_quality_is_separate_product", "air_quality_native_times", "air_quality_missing_zero_concentrations",
                 "air_quality_not_aqi_or_observations", "actual_refresh", "no_external_resources",
                 "weather_failure_preserves_air_quality", "weather_expiry_preserves_air_quality",
                 "aq_unavailable_weather_preserved", "aq_stale_weather_preserved", "air_quality_expiry_preserves_weather"):
        require(proof["checks"][name] is True)
    for name in ("precipitation", "air_quality"):
        initial = proof["checks"][name + "_initial_dom_sha256"]
        require(hex64(initial) and initial == proof["checks"][name + "_refresh_dom_sha256"])
    for name in ("provider_requests", "air_quality_provider_requests"):
        require(type(proof["checks"][name]) is int and proof["checks"][name] == 11)
    for relative, digest in proven_hashes(proof["source"]["overlay_sha256"], OVERLAY_FILES).items():
        require(selected[WEATHER + "integrations/drizzli/overlay/" + relative]["sha256"]
            == selected[UI_STAGE + relative]["sha256"] == digest)
    for relative, digest in proven_hashes(proof["source"]["fixture_modules"], FIXTURE_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    require(selected[WEATHER + "integrations/drizzli/browser-fixture.mjs"]["sha256"] == proof["source"]["fixture_sha256"]
        and selected[UI_STAGE + "LICENSE.VOLPAROSSA"]["sha256"] == selected[WEATHER + "LICENSE"]["sha256"])
    noaa = small_json(weather / "third_party/noaa-gefs-smoke.json")
    require(type(noaa["version"]) is int and noaa["version"] == 1
        and noaa["kind"] == "direct-noaa-native-particulate-forecast" and noaa["success"] is True
        and noaa["origin"] == "https://noaa-gefs-pds.s3.amazonaws.com"
        and noaa["node_sha256"] == NODE_SHA and noaa["decoder_sha256"] == DECODER_SHA
        and noaa["scope"]["actual_origin_acquisition"] is True
        and noaa["scope"]["actual_pinned_native_decoder"] is True
        and all(noaa["scope"][key] is False for key in ("core_executed", "overlay_proven", "browser_executed", "accuracy_proven")))
    for relative, digest in proven_hashes(noaa["source_modules"], NOAA_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)
    ecmwf = small_json(weather / "third_party/ecmwf-precipitation-smoke.json")
    require(type(ecmwf["version"]) is int and ecmwf["version"] == 1
        and ecmwf["kind"] == "direct-ecmwf-native-precipitation-forecast" and ecmwf["success"] is True
        and ecmwf["source"] == "https://data.ecmwf.int/forecasts"
        and ecmwf["node_sha256"] == NODE_SHA and ecmwf["decoder_sha256"] == DECODER_SHA
        and ecmwf["native_accumulation_windows_preserved"] is True and ecmwf["hourly_rates_inferred"] is False
        and ecmwf["core_overlay_roundtrip_proven"] is False and ecmwf["browser_execution_proven"] is False)
    for relative, digest in proven_hashes(ecmwf["source_modules"], ECMWF_MODULES).items():
        require(selected[WEATHER + relative]["sha256"] == digest)


def overmorrow_source_proof(weather, stage, selected, proof_path):
    """Bind the current real UI proof. Origin receipts remain historical only.

This does not assert that the current acquisition wrappers have run against
origins: the joined runner must acquire and validate new products itself.
Neither historical receipt is changed or used as current-wrapper authority.
"""
    proof = small_json(proof_path)
    pin = small_json(weather / "integrations/overmorrow/upstream.json")
    build = small_json(weather / "integrations/overmorrow/build-verification.json")
    require(type(proof["schema"]) is int and proof["schema"] == 1 and proof["passed"] is True
        and proof["phase"] == "complete" and proof["wrapper_outcome"] == "completed")
    scope = dict(actual_overmorrow_ui=True, actual_http_bridge=True, synthetic_weather=True,
        synthetic_air_quality=True, core_executed=False, overlay_proven=False,
        upstream_origin_proven=False, native_mobile_proven=False)
    require(proof["scope"] == scope and all(type(value) is bool for value in proof["scope"].values()))
    for group, names in (("cleanup", ("browser_exited", "fixture_exited", "private_profile_removed",
                                     "normal_browser_stop", "normal_fixture_stop")),
                         ("outer_cleanup", ("namespace_wrapper_exited", "private_profile_removed", "host_netns_unchanged"))):
        require(set(proof[group]) == set(names) and all(proof[group][name] is True for name in names))
    checks = proof["checks"]
    for name in ("actual_canvas_and_semantics", "independent_native_timelines", "native_values_visible",
                 "no_fabricated_current_or_aqi", "fixed_public_area", "source_attribution", "actual_refresh",
                 "weather_failure_and_stale_preserve_air_quality", "weather_idle_expiry_without_request",
                 "air_quality_failure_and_stale_preserve_weather", "air_quality_idle_expiry_without_request",
                 "existing_aq_detail_without_new_request", "same_origin_loaded_resources"):
        require(checks[name] is True)
    for name in ("provider_requests", "air_quality_provider_requests"):
        require(type(checks[name]) is int and checks[name] == 10)
    require(all(hex64(checks[name]) for name in ("initial_semantics_sha256", "final_semantics_sha256")))
    source = proof["source"]
    require(set(source) == {"upstream", "tree", "patch_sha256", "overlay_sha256", "deployed_tree_sha256",
        "deployed_files", "deployed_bytes", "bridge_modules", "fixture_modules", "browser_helpers",
        "isolation_helper_sha256", "driver_sha256", "fixture_sha256"})
    require(source["upstream"] == pin["commit"] == build["upstream_commit"]
        and source["tree"] == pin["tree"] and source["patch_sha256"] == pin["upstream_patch_sha256"]
        == build["upstream_patch_sha256"] == selected[WEATHER + "integrations/overmorrow/upstream.patch"]["sha256"]
        and selected[UI_STAGE_V3 + "LICENSE"]["sha256"] == pin["license_sha256"]
        == selected[STATIC_V3 + "LICENSE.txt"]["sha256"]
        and selected[UI_STAGE_V3 + "pubspec.lock"]["sha256"] == pin["pubspec_lock_sha256"] == build["pubspec_lock_sha256"]
        and selected[UI_STAGE_V3 + "LICENSE.VOLPAROSSA"]["sha256"] == selected[WEATHER + "LICENSE"]["sha256"]
        == selected[STATIC_V3 + "LICENSE.VOLPAROSSA.txt"]["sha256"])
    for relative, digest in proven_hashes(source["overlay_sha256"], OVERMORROW_OVERLAY).items():
        require(selected[WEATHER + "integrations/overmorrow/overlay/" + relative]["sha256"]
            == selected[UI_STAGE_V3 + relative]["sha256"] == digest)
    for group, names, prefix in (("bridge_modules", OVERMORROW_BRIDGE, WEATHER),
            ("fixture_modules", OVERMORROW_FIXTURE, WEATHER),
            ("browser_helpers", PROVEN_BROWSER_HELPERS, BROWSER)):
        for relative, digest in proven_hashes(source[group], names).items():
            require(selected[prefix + relative]["sha256"] == digest)
    for field, relative in (("isolation_helper_sha256", "integrations/drizzli/smoke_browser.py"),
            ("driver_sha256", "integrations/overmorrow/smoke_browser.py"),
            ("fixture_sha256", "integrations/overmorrow/browser-fixture.mjs")):
        require(hex64(source[field]) and selected[WEATHER + relative]["sha256"] == source[field])
    hashes = {name[len(STATIC_V3):]: item["sha256"] for name, item in selected.items() if name.startswith(STATIC_V3)}
    tree_sha = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    deployment = build["deployment"]
    require(tree_sha == source["deployed_tree_sha256"] == deployment["tree_sha256"]
        and type(source["deployed_files"]) is int and source["deployed_files"] == len(hashes) == deployment["files"]
        and type(source["deployed_bytes"]) is int and source["deployed_bytes"] == deployment["bytes"]
        == sum(item["bytes"] for name, item in selected.items() if name.startswith(STATIC_V3))
        and deployment["static_profile"] == "flutter-canvaskit")
    for field, name in (("main_js_sha256", "main.dart.js"), ("bootstrap_sha256", "flutter_bootstrap.js"),
                        ("notices_sha256", "assets/NOTICES")):
        require(deployment[field] == hashes[name])
    require(type(build["schema"]) is int and build["schema"] == 1 and build["actual_release_web_build"] is True
        and build["profile"] == "VOLPAROSSA_WEATHER=true" and build["flutter"] == pin["flutter"]
        and build["flutter_commit"] == pin["flutter_commit"] and build["synthetic_products"] is True
        and build["browser_interaction_verified"] is True and build["core_delivery_verified"] is False
        and build["native_android_ios_verified"] is False and build["forecast_accuracy_verified"] is False
        and build["browser_trial"]["passed"] is True
        and build["browser_trial"]["report_sha256"] == selected[WEATHER + OVERMORROW_PROOF]["sha256"]
        and build["request_lifecycle"]["provider_source_sha256"] == source["overlay_sha256"]["lib/volparossa/provider.dart"]
        and build["request_lifecycle"]["cold_core_delivery_verified"] is False)
    metadata = small_json(stage / "volparossa-staging.json")
    runtime = proven_hashes(metadata["runtime_sha256"], PROVEN_RUNTIME_FILES)
    require(runtime == proven_hashes(proof["runtime"]["sha256"], PROVEN_RUNTIME_FILES)
        and proof["runtime"]["node_sha256"] == NODE_SHA
        and metadata["defaults_sha256"] == selected[BROWSER + "defaults/privacy.json"]["sha256"]
        and metadata["autoconfig_sha256"] == selected[STAGE + "volparossa.cfg"]["sha256"])
    for relative, digest in runtime.items():
        require(selected[STAGE + relative]["sha256"] == digest)
    decoder_proof(weather)
    # Retain known separate historical source evidence without claiming its
    # hashes describe these current wrappers (notably the newer NOAA cleanup).
    for filename, kind, group in (("noaa-gefs-smoke.json", "direct-noaa-native-particulate-forecast", NOAA_MODULES),
                                 ("ecmwf-precipitation-smoke.json", "direct-ecmwf-native-precipitation-forecast", ECMWF_MODULES)):
        historical = small_json(weather / "third_party" / filename)
        require(type(historical["version"]) is int and historical["version"] == 1 and historical["kind"] == kind
            and historical["success"] is True and historical["node_sha256"] == NODE_SHA
            and historical["decoder_sha256"] == DECODER_SHA)
        proven_hashes(historical["source_modules"], group)
        if filename.startswith("noaa"):
            require(historical["origin"] == "https://noaa-gefs-pds.s3.amazonaws.com"
                and historical["scope"]["actual_origin_acquisition"] is True
                and historical["scope"]["actual_pinned_native_decoder"] is True
                and all(historical["scope"][key] is False for key in
                        ("core_executed", "overlay_proven", "browser_executed", "accuracy_proven")))
        else:
            require(historical["source"] == "https://data.ecmwf.int/forecasts"
                and historical["native_accumulation_windows_preserved"] is True
                and historical["hourly_rates_inferred"] is False
                and historical["core_overlay_roundtrip_proven"] is False
                and historical["browser_execution_proven"] is False)


def capture(weather, ui, browser, stage, node, archive, version=1):
    require(type(version) is int and version in (1, 2))
    for root in (weather, ui, browser, stage):
        B["canonical"](root)
    inventory(stage, exact=RUNTIME_FILES)
    sources = {**{WEATHER + name: weather / name for name in (WEATHER_FILES if version == 1 else WEATHER_FILES_V2)},
        **{BROWSER + name: browser / name for name in BROWSER_FILES},
        **{STAGE + name: stage / name for name in RUNTIME_FILES},
        **{UI_STAGE + name: ui / name for name in (CLIENT_FILES if version == 1 else CLIENT_FILES_V2)},
        **{STATIC + name: path for name, path in inventory(ui / "build").items()},
        "runtime/node": node, "decoder/grib_ls": weather / "build/eccodes/eccodes-build/bin/grib_ls"}
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    for name in EXECUTABLES:
        require(sources[name].stat().st_mode & 0o100)
    raw = encode(dict(version=version, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    source_proof(weather, browser, ui, stage, selected, version)
    return write_archive(sources, selected, raw, expected, archive)


def capture_v3(weather, ui, static_root, browser, stage, node, proof, archive):
    for root in (weather, ui, static_root, browser, stage):
        B["canonical"](root)
    inventory(stage, exact=RUNTIME_FILES)
    require(set(inventory(weather / "integrations/overmorrow/overlay")) == OVERMORROW_OVERLAY)
    sources = {**{WEATHER + name: weather / name for name in WEATHER_FILES_V3 if name != OVERMORROW_PROOF},
        WEATHER + OVERMORROW_PROOF: proof,
        **{BROWSER + name: browser / name for name in BROWSER_FILES},
        **{STAGE + name: stage / name for name in RUNTIME_FILES},
        **{UI_STAGE_V3 + name: ui / name for name in CLIENT_FILES_V3},
        **{STATIC_V3 + name: path for name, path in inventory(static_root).items()},
        "runtime/node": node, "decoder/grib_ls": weather / "build/eccodes/eccodes-build/bin/grib_ls"}
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    for name in EXECUTABLES:
        require(sources[name].stat().st_mode & 0o100)
    raw = encode(dict(version=3, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    overmorrow_source_proof(weather, stage, selected, proof)
    return dict(**write_archive(sources, selected, raw, expected, archive),
        historical_source_proofs_only=True, current_origin_acquisition_proven=False, joined_delivery_proven=False)


def public_sources(weather, browser, assets, proof, decoder, abi):
    """Map only public artifact members and reviewed source, with no execution."""
    for root in (weather, browser, assets, proof, decoder, abi):
        B["canonical"](root)
    stage = assets / "hosted-browser-source/build/firefox-hosted-ci"
    ui = assets / "drizzli-hosted-ci"
    inventory(stage, exact=RUNTIME_FILES_V4)
    sources = {**{WEATHER + name: weather / name for name in WEATHER_FILES_V4},
        **{BROWSER + name: browser / name for name in BROWSER_FILES},
        **{STAGE + name: stage / name for name in RUNTIME_FILES_V4},
        **{WEATHER + name: proof / relative for name, relative in HOSTED_PROOFS.items()},
        **{STATIC + name: path for name, path in inventory(ui / "build").items()},
        **{"decoder/licenses/" + name: decoder / name for name in DECODER_LICENSES},
        **{WEATHER + HOSTED_PREFIX + "decoder-abi/" + name: abi / name for name in ABI_LOGS},
        WEATHER + HOSTED_PREFIX + "decoder-abi.json": abi / "report.json",
        WEATHER + HOSTED_PREFIX + "decoder-build.json": decoder / "hosted-build-receipt.json",
        "decoder/grib_ls": decoder / "eccodes-build/bin/grib_ls", "decoder/probe.grib2": decoder / "probe.grib2",
        "runtime/node": assets / "hosted-client-runtime/node/bin/node",
        "runtime/node.LICENSE": assets / "hosted-client-runtime/node/LICENSE",
        "runtime/firefox-copyright": assets / "hosted-client-runtime/licenses/firefox-copyright"}
    # The public assets intentionally omit the checkout/node_modules. The
    # unchanged synthetic report hashes bind these source copies to its build.
    for name in CLIENT_FILES_V4:
        sources[UI_STAGE + name] = (weather / "integrations/drizzli/overlay" / name if name in OVERLAY_FILES
            else weather / "src" / Path(name).name if name.startswith("src/lib/services/volparossa/")
            else ui / name)
    return sources


def public_source_proof(sources, selected, admission):
    """Separate immutable inner UI, outer lifecycle, build and ABI evidence.

    No historic source receipt claims current origin acquisition. New joined
    consumers are pinned by the admission inventory, not retrospectively by the
    old synthetic UI report's driver hash.
    """
    read = lambda name: small_json(sources[name])
    proof = read(WEATHER + HOSTED_PROOF)
    build = read(WEATHER + HOSTED_PREFIX + "build.json")
    outer = read(WEATHER + HOSTED_PREFIX + "result.json")
    cleanup = read(WEATHER + HOSTED_PREFIX + "cleanup.json")
    upstream = read(WEATHER + "integrations/drizzli/upstream.json")
    scope = dict(actual_drizzli_ui=True, actual_http_bridge=True, synthetic_weather=True,
        synthetic_air_quality=True, core_executed=False, overlay_proven=False, upstream_origin_proven=False)
    require(type(proof["schema"]) is int and proof["schema"] == 1 and proof["passed"] is True
        and proof["phase"] == "complete" and proof["scope"] == scope
        and all(type(item) is bool for item in proof["scope"].values())
        and proof["scenario"] == "precipitation" and proof["air_quality_scenario"] is True
        and "outer_cleanup" not in proof and "wrapper_outcome" not in proof
        and proof["browser_process_exit_code"] == 0)
    for key in ("browser_exited", "fixture_exited", "private_profile_removed", "normal_browser_stop",
                "normal_fixture_stop", "startup_stderr_drained"):
        require(proof["cleanup"][key] is True)
    require(outer["schema"] == 1 and outer["kind"] == "hosted-client-build-and-synthetic-ui"
        and outer["phase"] == "complete" and outer["success"] is True and outer["policy_cleanup_complete"] is True
        and outer["weather_commit"] == admission["artifacts"]["proof"]["commit"] == build["weather_commit"]
        and outer["browser_commit"] == admission["sources"]["browser"]["commit"] == build["browser_commit"]
        and all(outer[key] is False for key in ("origin_acquisition", "core_delivery", "production_authority"))
        and all(outer[key] is True for key in ("synthetic_weather", "synthetic_air_quality"))
        and set(outer["outer_cleanup"]) == {"host_netns_unchanged", "private_profile_removed", "process_drain_confirmed"}
        and all(item is True for item in outer["outer_cleanup"].values()))
    require(cleanup["schema"] == 1 and cleanup["kind"] == "hosted-clients-sandbox-cleanup"
        and all(cleanup[key] is True for key in ("complete", "process_drain_confirmed", "profile_removed",
                                               "restriction_unchanged", "staging_removed")))
    require(build["schema"] == 1 and build["kind"] == "hosted-drizzli-build" and build["source"] == proof["source"]
        and build["browser_report_sha256"] == selected[WEATHER + HOSTED_PROOF]["sha256"]
        and all(build[key] is True for key in ("actual_synthetic_ui", "compiled_networkless", "copyright_notices_preserved"))
        and all(build[key] is False for key in ("core_delivery", "weather_origin", "dependency_lifecycle_scripts", "mutable_assets_prehook"))
        and build["lock_sha256"] == selected[UI_STAGE + "package-lock.json"]["sha256"])
    source = proof["source"]
    require(source["upstream"] == upstream["commit"] == build["upstream_commit"] and source["tree"] == upstream["tree"]
        and source["patch_sha256"] == upstream["upstream_patch_sha256"]
        == selected[WEATHER + "integrations/drizzli/upstream.patch"]["sha256"]
        and source["browser_revision"] == admission["sources"]["browser"]["commit"]
        and selected[UI_STAGE + "LICENSE"]["sha256"] == upstream["license_sha256"]
        and selected[UI_STAGE + "LICENSE.VOLPAROSSA"]["sha256"] == selected[WEATHER + "LICENSE"]["sha256"])
    for field, names, prefix in (("weather_modules", PROVEN_WEATHER_MODULES | AQ_MODULES, WEATHER),
            ("bridge_modules", PROVEN_BRIDGE_MODULES | {"src/air-quality-core.mjs"}, WEATHER),
            ("fixture_modules", FIXTURE_MODULES, WEATHER), ("browser_helpers", PROVEN_BROWSER_HELPERS, BROWSER),
            ("overlay_sha256", OVERLAY_FILES, WEATHER + "integrations/drizzli/overlay/")):
        for name, digest in proven_hashes(source[field], names).items():
            require(selected[prefix + name]["sha256"] == digest)
            if field == "weather_modules":
                require(selected[UI_STAGE + "src/lib/services/volparossa/" + Path(name).name]["sha256"] == digest)
            if field == "overlay_sha256":
                require(selected[UI_STAGE + name]["sha256"] == digest)
    for field, name in (("driver_sha256", "smoke_browser.py"), ("fixture_sha256", "browser-fixture.mjs")):
        require(source[field] == selected[WEATHER + "integrations/drizzli/" + name]["sha256"])
    hashes = {name[len(STATIC):]: item["sha256"] for name, item in selected.items() if name.startswith(STATIC)}
    require(hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == source["built_tree_sha256"] and len(hashes) == source["built_files"]
        and sum(selected[STATIC + name]["bytes"] for name in hashes) == source["built_bytes"])
    for name in ("precipitation_native_windows", "precipitation_missing_zero_small_amount", "precipitation_no_hourly_rate",
            "air_quality_is_separate_product", "air_quality_native_times", "air_quality_missing_zero_concentrations",
            "air_quality_not_aqi_or_observations", "actual_refresh", "no_external_resources",
            "weather_failure_preserves_air_quality", "weather_expiry_preserves_air_quality",
            "aq_unavailable_weather_preserved", "aq_stale_weather_preserved", "air_quality_expiry_preserves_weather"):
        require(proof["checks"][name] is True)
    for name in ("precipitation", "air_quality"):
        require(hex64(proof["checks"][name + "_initial_dom_sha256"])
            and proof["checks"][name + "_initial_dom_sha256"] == proof["checks"][name + "_refresh_dom_sha256"])
    require(proof["checks"]["provider_requests"] == proof["checks"]["air_quality_provider_requests"] == 11)
    staging = read(STAGE + "volparossa-staging.json")
    require(proof["runtime"]["node_sha256"] == NODE_SHA
        and proven_hashes(staging["runtime_sha256"], PROVEN_RUNTIME_FILES)
        == proven_hashes(proof["runtime"]["sha256"], PROVEN_RUNTIME_FILES)
        and staging["defaults_sha256"] == selected[BROWSER + "defaults/privacy.json"]["sha256"]
        and staging["autoconfig_sha256"] == selected[STAGE + "volparossa.cfg"]["sha256"])
    for name, digest in proof["runtime"]["sha256"].items():
        require(selected[STAGE + name]["sha256"] == digest)
    provenance = read(WEATHER + HOSTED_PREFIX + "runtime-provenance.json")
    require(build["runtime"]["provenance_sha256"] == selected[WEATHER + HOSTED_PREFIX + "runtime-provenance.json"]["sha256"]
        and provenance["scope"]["runtime_executed"] is False and provenance["scope"]["expected_runtime_hashes_verified"] is True
        and provenance["pin_sha256"] == selected[WEATHER + "third_party/hosted-runtime-inputs.json"]["sha256"]
        and provenance["npm"]["pin_sha256"] == selected[WEATHER + "third_party/hosted-runtime-npm.json"]["sha256"]
        and provenance["preparer_sha256"] == selected[WEATHER + "scripts/prepare_hosted_runtime.py"]["sha256"])
    public_decoder_proof(read, selected, admission)


def public_decoder_proof(read, selected, admission, prefix=HOSTED_PREFIX):
    build = read(WEATHER + prefix + "decoder-build.json")
    abi = read(WEATHER + prefix + "decoder-abi.json")
    require(build["compiled"] is True and build["tests_passed"] is True
        and build["recipe_sha256"] == BUILD_SHA_V4 and build["source_pin_sha256"] == PIN_SHA
        and build["source_helper_sha256"] == selected[WEATHER + "scripts/build_eccodes.py"]["sha256"]
        and build["tests"]["version"] is True and build["tests"]["ccsds_nonconstant_nearest_points"] is True
        and build["scope"]["decoder_authorized"] is False and build["scope"]["debian13_abi_proven"] is False
        and build["scope"]["network_during_build"] is False and build["scope"]["original_sources_unchanged"] is True)
    artifacts = {item["path"]: {key: item[key] for key in ("bytes", "sha256")} for item in build["artifacts"]}
    for name, original in (("decoder/grib_ls", "eccodes-build/bin/grib_ls"), ("decoder/probe.grib2", "probe.grib2")):
        require(artifacts[original] == {key: selected[name][key] for key in ("bytes", "sha256")})
    require(abi["schema_version"] == 1 and abi["kind"] == "weather-decoder-abi" and abi["success"] is True
        and abi["phase"] == "complete" and abi["blocker"] is None
        and abi["source_commit"] == admission["artifacts"]["abi"]["commit"]
        and abi["weather_commit"] == admission["artifacts"]["decoder"]["commit"]
        and abi["scope"]["disposable_abi_test_only"] is True
        and all(abi["scope"][key] is False for key in ("production_decoder_authorized", "origin_acquisition_proven",
                                                     "core_delivery_proven", "browser_proven"))
        and all(abi["checks"][key] is True for key in ("elf_inspected", "first_point", "inputs_verified", "last_point",
                                                      "relocated_lone_decoder", "sandbox_isolated", "version"))
        and abi["cleanup"] == dict(process_drain_confirmed=True, scratch_removed=True))
    for name in ABI_LOGS:
        item = selected[WEATHER + prefix + "decoder-abi/" + name]
        require(abi["logs"][name] == dict(bytes=item["bytes"], sha256=item["sha256"], exit_status=0))


def capture_v4(weather, browser, assets, proof, decoder, abi, archive):
    admission = public_admission()
    sources = public_sources(weather, browser, assets, proof, decoder, abi)
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    # Artifact download services discard executable mode. Normalized mode is
    # authorized by the fixed profile; executable bytes are never run here.
    raw = encode(dict(version=4, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    public_source_proof(sources, selected, admission)
    return dict(**write_archive(sources, selected, raw, expected, archive),
        synthetic_ui_proven=True, current_origin_acquisition_proven=False, joined_delivery_proven=False)


def public_overmorrow_sources(weather, historical_weather, browser, assets, proof, decoder, abi):
    """No SDK/cache/npm tree, host preferences or rewritten historical report."""
    for root in (weather, historical_weather, browser, assets, proof, decoder, abi):
        B["canonical"](root)
    stage = assets / "hosted-browser-source/build/firefox-hosted-ci"
    ui = assets / "overmorrow-hosted-ci"
    inventory(stage, exact=RUNTIME_FILES_V4)
    require(set(inventory(weather / "integrations/overmorrow/overlay")) == OVERMORROW_OVERLAY)
    sources = {**{WEATHER + name: weather / name for name in WEATHER_FILES_V5},
        **{BROWSER + name: browser / name for name in BROWSER_FILES},
        **{STAGE + name: stage / name for name in RUNTIME_FILES_V4},
        **{WEATHER + name: proof / relative for name, relative in HOSTED_OVERMORROW_PROOFS.items()},
        **{STATIC_V3 + name: path for name, path in inventory(assets / "overmorrow-hosted-web-ci").items()},
        **{"decoder/licenses/" + name: decoder / name for name in DECODER_LICENSES},
        **{WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-abi/" + name: abi / name for name in ABI_LOGS},
        WEATHER + HISTORICAL_OVERMORROW_DRIVER: historical_weather / "integrations/overmorrow/smoke_core_browser.py",
        WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-abi.json": abi / "report.json",
        WEATHER + HOSTED_OVERMORROW_PREFIX + "decoder-build.json": decoder / "hosted-build-receipt.json",
        "decoder/grib_ls": decoder / "eccodes-build/bin/grib_ls", "decoder/probe.grib2": decoder / "probe.grib2",
        "runtime/node": assets / "hosted-client-runtime/node/bin/node",
        "runtime/node.LICENSE": assets / "hosted-client-runtime/node/LICENSE",
        "runtime/firefox-copyright": assets / "hosted-client-runtime/licenses/firefox-copyright"}
    for name in CLIENT_FILES_V3:
        sources[UI_STAGE_V3 + name] = (weather / "integrations/overmorrow/overlay" / name
                                     if name in OVERMORROW_OVERLAY else ui / name)
    return sources


def table_contract(raw):
    """Historical Python is data only. Compare the complete table-check closure."""
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    fields = {"HEADERS", "SOURCE_FIELDS", "TABLES_JS", "require", "canonical", "digest",
              "number_equal", "snapshot", "observed_products"}
    result = {}
    for node in ast.parse(raw.decode("utf-8")).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.asname or alias.name.split(".")[0] for alias in node.names]
        else:
            names = [child.id for child in ast.walk(node)
                     if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)]
        for name in names:
            if name in fields:
                require(name not in result)
                result[name] = ast.dump(node, include_attributes=False)
    require(set(result) == fields)
    return result


def matching_table_contract(sources, selected):
    contracts = []
    for name in (HISTORICAL_OVERMORROW_DRIVER, "integrations/overmorrow/smoke_core_browser.py"):
        name = WEATHER + name
        source, info = open_checked(sources[name], 65536)
        with source:
            raw = source.read(65537)
            require(len(raw) == info.st_size and identity(os.fstat(source.fileno())) == identity(info)
                and hashlib.sha256(raw).hexdigest() == selected[name]["sha256"])
        contracts.append(table_contract(raw))
    require(contracts[0] == contracts[1])


def tool_state_receipt(value):
    """Bound generated metadata, never expose it as original SDK/runtime input."""
    require(type(value) is dict and set(value) == {"schema", "kind", "files", "bytes",
        "stored_outside_sdk", "original_mountpoint_empty"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == "hosted-flutter-tool-state"
        and value["stored_outside_sdk"] is True and value["original_mountpoint_empty"] is True
        and type(value["files"]) is dict and len(value["files"]) <= 64
        and type(value["bytes"]) is int and 0 <= value["bytes"] <= 16 * 1024**2)
    total = 0
    for name, item in value["files"].items():
        require(type(name) is str and 0 < len(name) <= 256 and len(name.split("/")) <= 4
            and re.fullmatch(r"[A-Za-z0-9._/-]+", name) is not None
            and all(part not in ("", ".", "..") for part in name.split("/")))
        require(type(item) is dict and set(item) == {"bytes", "sha256"}
            and type(item["bytes"]) is int and 0 <= item["bytes"] <= 2 * 1024**2 and hex64(item["sha256"]))
        total += item["bytes"]
    require(total == value["bytes"])
    return value


def public_overmorrow_source_proof(sources, selected, admission):
    """Bind original synthetic UI/tables to their build, not to new consumers."""
    read = lambda name: small_json(sources[name])
    prefix = WEATHER + HOSTED_OVERMORROW_PREFIX
    proof = read(WEATHER + HOSTED_OVERMORROW_PROOF)
    table = read(WEATHER + HOSTED_OVERMORROW_TABLE)
    build, outer, cleanup = (read(prefix + name + ".json") for name in ("build", "result", "cleanup"))
    pin = read(WEATHER + "integrations/overmorrow/upstream.json")
    deployment = read(prefix + "deployment.json")
    # Both original phase receipts are frozen independently. State may evolve
    # during tests/build; only the final receipt is the build's final binding.
    tool_state_receipt(read(prefix + "tool-state-acquired.json"))
    final_tool_state = tool_state_receipt(read(prefix + "tool-state-final.json"))
    scope = dict(actual_overmorrow_ui=True, actual_http_bridge=True, synthetic_weather=True,
        synthetic_air_quality=True, core_executed=False, overlay_proven=False,
        upstream_origin_proven=False, native_mobile_proven=False)
    table_scope = dict(scope, ordered_table_contract=True, joined_delivery_proven=False,
                      cold_transfer_proven=False, origin_acquisition_proven=False)
    cleanup_names = {"browser_exited", "fixture_exited", "private_profile_removed",
                     "normal_browser_stop", "normal_fixture_stop"}
    for report, expected_scope in ((proof, scope), (table, table_scope)):
        require(type(report["schema"]) is int and report["schema"] == 1 and report["passed"] is True
            and report["phase"] == "complete" and report["scope"] == expected_scope
            and all(type(item) is bool for item in report["scope"].values())
            and "outer_cleanup" not in report and "wrapper_outcome" not in report
            and set(report["cleanup"]) == cleanup_names and all(report["cleanup"][key] is True for key in cleanup_names))
    require(type(outer["schema"]) is int and outer["schema"] == 1
        and outer["kind"] == "hosted-overmorrow-build-and-synthetic-ui" and outer["phase"] == "complete"
        and outer["success"] is True and outer["policy_cleanup_complete"] is True
        and outer["weather_commit"] == admission["artifacts"]["proof"]["commit"] == build["weather_commit"]
        and outer["browser_commit"] == admission["sources"]["browser"]["commit"] == build["browser_commit"]
        and all(outer[key] is False for key in ("origin_acquisition", "core_delivery", "native_mobile", "production_authority"))
        and all(outer[key] is True for key in ("synthetic_weather", "synthetic_air_quality"))
        and set(outer["outer_cleanup"]) == {"host_netns_unchanged", "private_profile_removed",
                                          "private_table_profile_removed", "process_drain_confirmed"}
        and all(item is True for item in outer["outer_cleanup"].values()))
    require(type(cleanup["schema"]) is int and cleanup["schema"] == 1
        and cleanup["kind"] == "hosted-overmorrow-sandbox-cleanup"
        and all(cleanup[key] is True for key in ("complete", "process_drain_confirmed", "profile_removed",
                                               "restriction_unchanged", "staging_removed")))
    require(type(build["schema"]) is int and build["schema"] == 1 and build["kind"] == "hosted-overmorrow-build"
        and all(build[key] is True for key in ("actual_synthetic_ui", "actual_synthetic_tables", "compiled_networkless",
            "locked_dependencies", "copyright_notices_preserved", "sdk_executed_in_disposable_sandbox"))
        and all(build[key] is False for key in ("core_delivery", "weather_origin", "native_mobile"))
        and type(build["flutter_tests"]) is int and build["flutter_tests"] == 23
        and set(build["reports"]) == {"ui", "table"}
        and build["reports"]["ui"] == dict(sha256=selected[WEATHER + HOSTED_OVERMORROW_PROOF]["sha256"], source=proof["source"])
        and build["reports"]["table"] == dict(sha256=selected[WEATHER + HOSTED_OVERMORROW_TABLE]["sha256"], source=table["source"])
        and build["deployment_sha256"] == selected[prefix + "deployment.json"]["sha256"]
        and build["system_tools"] == read(prefix + "system-tools.json")
        and tool_state_receipt(build["tool_state"]) == final_tool_state)
    source = proof["source"]
    source_keys = {"upstream", "tree", "patch_sha256", "overlay_sha256", "deployed_tree_sha256",
        "deployed_files", "deployed_bytes", "bridge_modules", "fixture_modules", "browser_helpers",
        "isolation_helper_sha256", "driver_sha256", "fixture_sha256"}
    table_keys = {"table_wrapper_sha256", "table_fixture_sha256", "exact_v3_verifier_sha256", "extra_synthetic_modules"}
    require(set(source) == source_keys and set(table["source"]) == source_keys | table_keys
        and {key: table["source"][key] for key in source_keys} == source
        and source["upstream"] == pin["commit"] == build["upstream_commit"] and source["tree"] == pin["tree"]
        and source["patch_sha256"] == pin["upstream_patch_sha256"]
        == selected[WEATHER + "integrations/overmorrow/upstream.patch"]["sha256"]
        and selected[UI_STAGE_V3 + "LICENSE"]["sha256"] == pin["license_sha256"] == selected[STATIC_V3 + "LICENSE.txt"]["sha256"]
        and selected[UI_STAGE_V3 + "pubspec.lock"]["sha256"] == pin["pubspec_lock_sha256"] == build["lock_sha256"]
        and selected[UI_STAGE_V3 + "LICENSE.VOLPAROSSA"]["sha256"] == selected[WEATHER + "LICENSE"]["sha256"]
        == selected[STATIC_V3 + "LICENSE.VOLPAROSSA.txt"]["sha256"])
    for group, names, source_prefix in (("overlay_sha256", OVERMORROW_OVERLAY, WEATHER + "integrations/overmorrow/overlay/"),
            ("bridge_modules", OVERMORROW_BRIDGE, WEATHER), ("fixture_modules", OVERMORROW_FIXTURE, WEATHER),
            ("browser_helpers", PROVEN_BROWSER_HELPERS, BROWSER)):
        for name, digest in proven_hashes(source[group], names).items():
            require(selected[source_prefix + name]["sha256"] == digest)
            if group == "overlay_sha256": require(selected[UI_STAGE_V3 + name]["sha256"] == digest)
    for field, name in (("isolation_helper_sha256", "integrations/drizzli/smoke_browser.py"),
            ("driver_sha256", "integrations/overmorrow/smoke_browser.py"),
            ("fixture_sha256", "integrations/overmorrow/browser-fixture.mjs")):
        require(source[field] == selected[WEATHER + name]["sha256"])
    for field, name in (("table_wrapper_sha256", "integrations/overmorrow/smoke_table_browser.py"),
            ("table_fixture_sha256", "integrations/overmorrow/table-fixture.mjs"),
            ("exact_v3_verifier_sha256", HISTORICAL_OVERMORROW_DRIVER)):
        require(table["source"][field] == selected[WEATHER + name]["sha256"])
    for name, digest in proven_hashes(table["source"]["extra_synthetic_modules"], {"tests/precipitation-fixtures.mjs"}).items():
        require(selected[WEATHER + name]["sha256"] == digest)
    hashes = {name[len(STATIC_V3):]: item["sha256"] for name, item in selected.items() if name.startswith(STATIC_V3)}
    require(hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == source["deployed_tree_sha256"] == deployment["tree_sha256"]
        and type(source["deployed_files"]) is int and source["deployed_files"] == len(hashes) == deployment["files"]
        and type(source["deployed_bytes"]) is int and source["deployed_bytes"] == deployment["bytes"]
        == sum(selected[STATIC_V3 + name]["bytes"] for name in hashes)
        and deployment["asset_sha256"] == hashes and deployment["static_profile"] == "flutter-canvaskit")
    for name in ("actual_canvas_and_semantics", "independent_native_timelines", "native_values_visible",
            "no_fabricated_current_or_aqi", "fixed_public_area", "source_attribution", "actual_refresh",
            "weather_failure_and_stale_preserve_air_quality", "weather_idle_expiry_without_request",
            "air_quality_failure_and_stale_preserve_weather", "air_quality_idle_expiry_without_request",
            "existing_aq_detail_without_new_request", "same_origin_loaded_resources"):
        require(proof["checks"][name] is True)
    for name in ("provider_requests", "air_quality_provider_requests"):
        require(type(proof["checks"][name]) is int and proof["checks"][name] == 10)
    require(all(hex64(proof["checks"][name]) for name in ("initial_semantics_sha256", "final_semantics_sha256")))
    require(table["kind"] == "overmorrow-synthetic-native-table-contract")
    for name in ("exact_current_v3_extractor", "exact_current_v3_observed_products", "same_origin_loaded_resources",
            "actual_pointer_refresh", "exact_captured_response_bodies", "ordered_four_weather_five_air_quality_rows",
            "native_missing_calm_zero_and_precipitation_windows"):
        require(table["checks"][name] is True)
    for name in ("weather_requests", "air_quality_requests"):
        require(type(table["checks"][name]) is int and table["checks"][name] == 2)
    require(type(table["table_phases"]) is list and len(table["table_phases"]) == 2)
    for index, row in enumerate(table["table_phases"], 1):
        require(row["phase"] == ("initial_tables" if index == 1 else "refreshed_tables")
            and row["row_counts"] == dict(weather=4, air_quality=5)
            and all(type(value) is int for value in row["row_counts"].values())
            and type(row["browser_requests_each"]) is int and type(row["provider_requests_each"]) is int
            and row["browser_requests_each"] == row["provider_requests_each"] == index
            and row["exact_ordered_rows_and_metadata"] is True and hex64(row["display_sha256"]))
        proven_hashes(row["response_sha256"], {"weather", "air_quality"})
    staging = read(STAGE + "volparossa-staging.json")
    runtime = proven_hashes(staging["runtime_sha256"], PROVEN_RUNTIME_FILES)
    for report in (proof, table):
        require(proven_hashes(report["runtime"]["sha256"], PROVEN_RUNTIME_FILES) == runtime
            and report["runtime"]["node_sha256"] == NODE_SHA)
    require(staging["defaults_sha256"] == selected[BROWSER + "defaults/privacy.json"]["sha256"]
        and staging["autoconfig_sha256"] == selected[STAGE + "volparossa.cfg"]["sha256"])
    for name, digest in runtime.items(): require(selected[STAGE + name]["sha256"] == digest)
    provenance = read(prefix + "runtime-provenance.json")
    require(build["runtime"]["provenance_sha256"] == selected[prefix + "runtime-provenance.json"]["sha256"]
        and provenance["scope"]["runtime_executed"] is False and provenance["scope"]["expected_runtime_hashes_verified"] is True
        and provenance["pin_sha256"] == selected[WEATHER + "third_party/hosted-runtime-inputs.json"]["sha256"]
        and provenance["npm"]["pin_sha256"] == selected[WEATHER + "third_party/hosted-runtime-npm.json"]["sha256"]
        and provenance["preparer_sha256"] == selected[WEATHER + "scripts/prepare_hosted_runtime.py"]["sha256"])
    sdk, binding = read(prefix + "sdk-provenance.json"), read(prefix + "sdk-binding.json")
    require(sdk["schema"] == binding["schema"] == 1 and sdk["kind"] == "hosted-flutter-sdk-materialization"
        and sdk["pin_sha256"] == selected[WEATHER + "integrations/overmorrow/upstream.json"]["sha256"]
        and sdk["preparer_sha256"] == selected[WEATHER + "scripts/prepare_hosted_flutter.py"]["sha256"]
        and sdk["input"]["version"] == pin["flutter"] and sdk["input"]["commit"] == pin["flutter_commit"] == build["flutter_commit"]
        and sdk["input"]["sha256"] == pin["flutter_archive_sha256"]
        and sdk["scope"] == dict(runtime_executed=False, current_update_authority=False, host_installed=False,
            expected_sdk_hashes_verified=True, licenses_preserved=True)
        and all(type(flag) is bool for flag in sdk["scope"].values())
        and binding == build["sdk_materialization"] == build["sdk_final_binding"]
        and binding["provenance_sha256"] == selected[prefix + "sdk-provenance.json"]["sha256"]
        and binding["runtime_executed"] is False
        and all(binding[key] == sdk[key] for key in ("input", "sdk_files", "files", "bytes", "inventory_sha256")))
    require(hex64(sdk["inventory_sha256"]) and type(sdk["files"]) is int and 1 <= sdk["files"] <= 25000
        and type(sdk["bytes"]) is int and 0 < sdk["bytes"] <= 3 * 1024**3)
    proven_hashes(sdk["sdk_files"], {"bin/cache/dart-sdk/bin/dart", "bin/cache/flutter_tools.snapshot"})
    public_decoder_proof(read, selected, admission, HOSTED_OVERMORROW_PREFIX)
    matching_table_contract(sources, selected)


def capture_v5(weather, historical_weather, browser, assets, proof, decoder, abi, archive):
    admission = public_overmorrow_admission()
    sources = public_overmorrow_sources(weather, historical_weather, browser, assets, proof, decoder, abi)
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    raw = encode(dict(version=5, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    public_overmorrow_source_proof(sources, selected, admission)
    return dict(**write_archive(sources, selected, raw, expected, archive), synthetic_ui_proven=True,
        synthetic_native_tables_proven=True, current_origin_acquisition_proven=False, joined_delivery_proven=False)


def android_sources(weather, node_root, decoder, abi):
    # No discovery outside these explicit roots; selecting a source is not
    # execution. Every member must match the separate checked-in admission.
    return {**{WEATHER + name: weather / name for name in WEATHER_FILES_V6},
        **{"decoder/licenses/" + name: decoder / name for name in DECODER_LICENSES},
        **{WEATHER + ANDROID_PREFIX + "decoder-abi/" + name: abi / name for name in ABI_LOGS},
        WEATHER + ANDROID_PREFIX + "decoder-abi.json": abi / "report.json",
        WEATHER + ANDROID_PREFIX + "decoder-build.json": decoder / "hosted-build-receipt.json",
        "decoder/grib_ls": decoder / "eccodes-build/bin/grib_ls", "decoder/probe.grib2": decoder / "probe.grib2",
        "runtime/node": node_root / "bin/node", "runtime/node.LICENSE": node_root / "LICENSE"}


def capture_v6(weather, node_root, decoder, abi, archive):
    admission = public_android_admission()
    sources = android_sources(weather, node_root, decoder, abi)
    selected = {name: dict(**fingerprint(path, bound(name)), mode=mode(name)) for name, path in sorted(sources.items())}
    raw = encode(dict(version=6, kind=KIND, files=selected)); expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    public_decoder_proof(lambda name: small_json(sources[name]), selected, admission, ANDROID_PREFIX)
    return dict(**write_archive(sources, selected, raw, expected, archive),
        current_origin_acquisition_proven=False, native_android_proven=False, joined_delivery_proven=False)


def write_archive(sources, selected, raw, expected, archive):
    new_path(archive)
    with os.fdopen(os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        for name in ("INPUTS.json", *sorted(selected)):
            item = selected.get(name, dict(bytes=len(raw), mode=0o400, sha256=expected))
            output.write(header(name, item["bytes"], item["mode"]))
            source, before = (io.BytesIO(raw), None) if name == "INPUTS.json" else open_checked(sources[name], item["bytes"])
            with source:
                digest, remaining = hashlib.sha256(), item["bytes"]
                while remaining:
                    chunk = source.read(min(65536, remaining)); require(bool(chunk))
                    output.write(chunk); digest.update(chunk); remaining -= len(chunk)
                require(not source.read(1) and digest.hexdigest() == item["sha256"])
                if before is not None:
                    require(identity(os.fstat(source.fileno())) == identity(before))
            output.write(b"\0" * (-item["bytes"] % 512))
        output.write(b"\0" * 1024); output.flush(); os.fsync(output.fileno())
    return checked_archive(archive, expected)


def checked_archive(archive, expected, root=None, *, runtime=False, report_version=False):
    source, before = open_checked(archive, MAX_ARCHIVE)
    with source:
        require(before.st_size % 512 == 0)
        first = read_exact(source, 512)
        item = tarfile.TarInfo.frombuf(first, "utf-8", "strict")
        require(item.name == "INPUTS.json" and item.type == tarfile.REGTYPE and 0 < item.size <= MAX_MANIFEST
            and first == header("INPUTS.json", item.size, 0o400))
        raw = read_exact(source, item.size)
        require(read_exact(source, -item.size % 512) == b"\0" * (-item.size % 512))
        selected = manifest(raw, expected)
        # Only profiles with explicit joined-runtime dispatch may execute.
        # V6 uses the separate owned Android runner, not an older browser UI.
        # Admitting exact inputs is never evidence that execution passed.
        require(not runtime or selected["version"] in (1, 2, 3, 4, 5, 6))
        if root is not None:
            new_path(root); root.mkdir(mode=0o700)
        for name, record in sorted(selected["files"].items()):
            require(read_exact(source, 512) == header(name, record["bytes"], record["mode"]))
            target = None
            try:
                if root is not None:
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    target = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
                digest, remaining = hashlib.sha256(), record["bytes"]
                while remaining:
                    chunk = read_exact(source, min(65536, remaining)); digest.update(chunk); remaining -= len(chunk)
                    if target is not None: target.write(chunk)
                require(digest.hexdigest() == record["sha256"])
                require(read_exact(source, -record["bytes"] % 512) == b"\0" * (-record["bytes"] % 512))
                if target is not None:
                    target.flush(); os.fchmod(target.fileno(), record["mode"])
            finally:
                if target is not None: target.close()
        require(read_exact(source, 1024) == b"\0" * 1024 and not source.read(1))
        require(identity(os.fstat(source.fileno())) == identity(before))
        source.seek(0); archive_sha = hashlib.file_digest(source, "sha256").hexdigest()
        require(identity(os.fstat(source.fileno())) == identity(before))
    if root is not None:
        with os.fdopen(os.open(root / "INPUTS.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), "wb") as output:
            output.write(raw)
        for directory in sorted([root, *(p for p in root.rglob("*") if p.is_dir())], key=lambda p: len(p.parts), reverse=True):
            directory.chmod(0o500)
    return dict(manifest_sha256=expected, archive_sha256=archive_sha, files=len(selected["files"]),
        bytes=sum(item["bytes"] for item in selected["files"].values()),
        **({"bundle_version": selected["version"]} if report_version else {}))


def verify_tree(root, expected):
    source, info = open_checked(root / "INPUTS.json", MAX_MANIFEST, normalized=0o400)
    with source:
        raw = source.read(MAX_MANIFEST + 1); require(identity(os.fstat(source.fileno())) == identity(info))
    selected = manifest(raw, expected)
    inventory(root, exact=set(selected["files"]) | {"INPUTS.json"}, normalized=True)
    for name, item in selected["files"].items():
        require(fingerprint(root / name, item["bytes"], normalized=item["mode"])
            == {key: item[key] for key in ("bytes", "sha256")})
    return dict(manifest_sha256=expected, files=len(selected["files"]), runtime_executed=False)


def _android_worker_info(path, maximum=None, mode=0o500):
    B["canonical"](path)
    info = path.lstat()
    require(info.st_uid == 985 and stat.S_IMODE(info.st_mode) == mode)
    if maximum is None:
        require(stat.S_ISDIR(info.st_mode))
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    return info


def _android_worker_file(path, maximum, mode, *, retain=False):
    before = _android_worker_info(path, maximum, mode)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(descriptor)) == identity(before))
        digest, remaining, chunks = hashlib.sha256(), before.st_size, []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            require(bool(chunk)); digest.update(chunk); remaining -= len(chunk)
            if retain: chunks.append(chunk)
        require(not os.read(descriptor, 1)
            and identity(os.fstat(descriptor)) == identity(before)
            and identity(path.lstat()) == identity(before))
        B["canonical"](path)
        return dict(bytes=before.st_size, sha256=digest.hexdigest()), b"".join(chunks), before
    finally:
        os.close(descriptor)


def verify_android_worker_tree(root, expected):
    """Root verifies only the fixed profile-6 tree owned by guest worker 985.

    The ordinary caller-owned verifier remains unchanged. No process identity,
    ownership or permission is changed, and captured source is never executed.
    """
    require(os.geteuid() == 0)
    _, raw, manifest_info = _android_worker_file(root / "INPUTS.json", MAX_MANIFEST, 0o400, retain=True)
    selected = manifest(raw, expected)
    require(selected["version"] == 6)
    files, directories, pending, count = {}, {}, [root], 0
    while pending:
        directory = pending.pop()
        directories[directory] = _android_worker_info(directory)
        with os.scandir(directory) as children:
            for child in children:
                count += 1; require(count <= MAX_FILES * 4)
                path = Path(child.path)
                require(len(path.relative_to(root).parts) <= 20)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(child.is_file(follow_symlinks=False))
                    files[str(path.relative_to(root))] = path
                    require(len(files) <= MAX_FILES)
        require(identity(directory.lstat()) == identity(directories[directory]))
    require(set(files) == set(selected["files"]) | {"INPUTS.json"})
    require({str(path.relative_to(root)) for path in directories if path != root} == B["directories"](files))
    observed = {root / "INPUTS.json": manifest_info}
    for name, item in selected["files"].items():
        fingerprint, _, observed[files[name]] = _android_worker_file(files[name], item["bytes"], item["mode"])
        require(fingerprint == {key: item[key] for key in ("bytes", "sha256")})
    for path, before in (*directories.items(), *observed.items()):
        require(identity(path.lstat()) == identity(before))
        B["canonical"](path)
    return dict(manifest_sha256=expected, files=len(selected["files"]), runtime_executed=False)


def main():
    action, *args = sys.argv[1:]
    if action in ("capture", "capture-v2") and len(args) == 6:
        result = capture(*map(Path, args), version=2 if action == "capture-v2" else 1)
    elif action == "capture-v3" and len(args) == 8:
        result = capture_v3(*map(Path, args))
    elif action == "capture-v4" and len(args) == 7:
        result = capture_v4(*map(Path, args))
    elif action == "capture-v5" and len(args) == 8:
        result = capture_v5(*map(Path, args))
    elif action == "capture-v6" and len(args) == 5:
        result = capture_v6(*map(Path, args))
    elif action == "verify-runtime" and len(args) == 2:
        result = checked_archive(Path(args[0]), args[1], runtime=True)
    elif action == "runtime-version" and len(args) == 2:
        # Dispatch only after checking every member and the complete archive.
        # Identifying a valid input profile does not authorize its execution.
        result = checked_archive(Path(args[0]), args[1], report_version=True)
    elif action == "unpack" and len(args) == 3:
        result = checked_archive(Path(args[0]), args[2], Path(args[1]))
    elif action in ("verify", "verify-tree") and len(args) == 2:
        result = (checked_archive if action == "verify" else verify_tree)(Path(args[0]), args[1])
    else:
        raise ValueError("weather_client_bundle_rejected")
    print(json.dumps(dict(version=1, action=action, **(result | {"runtime_executed": False})), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, tarfile.TarError, UnicodeError):
        print('{"runtime_executed":false,"failure":"weather_client_bundle_rejected"}')
        raise SystemExit(1)
