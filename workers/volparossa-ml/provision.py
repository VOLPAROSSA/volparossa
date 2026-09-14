#!/usr/bin/env python3
"""Explicit, guest-only provisioning. Preview never creates files or uses the network.

Original wheels, licenses and model card stay under the new private root. This
is an operator-invoked development tool, not an agent auto-download mechanism.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import venv
import zipfile


HERE = Path(__file__).resolve().parent
MODEL_ID = "HuggingFaceTB/SmolLM2-135M-Instruct"
REVISION = "83212e1e2b3cfd6958f3707877bb878945dea8ee"
RESERVE_BYTES = 64 * 1024 * 1024
ALLOWED_HOSTS = frozenset({
    "files.pythonhosted.org", "download.pytorch.org", "download-r2.pytorch.org",
    "huggingface.co", "us.aws.cdn.hf.co", "cdn-lfs.huggingface.co",
    "cas-bridge.xethub.hf.co",
})


class ProvisionError(Exception):
    """A fail-closed provisioning refusal; an existing destination is never reused."""


def require(condition, message):
    if not condition:
        raise ProvisionError(message)


def official_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment,
            "unapproved artifact URL/redirect")
    return url


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        official_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def load_pins():
    pins = json.loads((HERE / "model-pins.json").read_text())
    require(pins["format_version"] == 1
            and pins["platform"] == "cpython-3.13-linux-x86_64"
            and pins["model_id"] == MODEL_ID and pins["revision"] == REVISION,
            "unsupported provisioning pin format/model")
    require(len(pins["files"]) == 8 and len(pins["wheels"]) == 38,
            "unexpected artifact set")
    for group in (pins["files"], pins["wheels"]):
        names = set()
        for item in group:
            name = item["path"]
            require(re.fullmatch(r"[A-Za-z0-9_.+\-]+", name) and name not in names,
                    "invalid/duplicate artifact filename")
            names.add(name)
            require(type(item["bytes"]) is int and 0 < item["bytes"] < 300_000_000,
                    "invalid artifact size")
            require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "invalid SHA256")
            official_url(item["url"])
            require(urllib.parse.unquote(urllib.parse.urlsplit(item["url"]).path)
                    .endswith("/" + name), "artifact URL/filename mismatch")
    for item in pins["files"]:
        require(item["url"] == f"https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{item['path']}",
                "model URL is not revision-pinned")
    for item in pins["wheels"]:
        require(item["path"].endswith(".whl"), "source distributions are forbidden")
        expected_host = "download.pytorch.org" if item["name"] == "torch" else "files.pythonhosted.org"
        require(urllib.parse.urlsplit(item["url"]).hostname == expected_host,
                "wheel is not from the selected official distribution")
        require(not any(word in item["name"] for word in ("nvidia", "cuda", "triton")),
                "GPU package is outside the CPU runtime")
    lock = (HERE / "requirements.lock").read_text()
    actual = [line for line in lock.splitlines() if line and not line.startswith("#")]
    expected = [f"{x['name']}=={x['version']} --hash=sha256:{x['sha256']}" for x in pins["wheels"]]
    require(actual == expected, "requirements.lock does not exactly match artifact pins")
    return pins


def download_total(pins):
    return sum(item["bytes"] for group in (pins["files"], pins["wheels"]) for item in group)


def execution_root(args):
    require(args.yes and args.disposable_guest,
            "execution requires --yes --disposable-guest")
    require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 13)
            and platform.system() == "Linux" and platform.machine() == "x86_64",
            "execution requires CPython 3.13 on Linux x86_64")
    require(args.root is not None and args.budget_bytes is not None,
            "execution requires --root NEW_ABSOLUTE_PATH --budget-bytes N")
    root = Path(args.root)
    require(root.is_absolute() and len(root.parts) >= 3 and root == root.resolve(),
            "root must be absolute, explicit and have no symlink components")
    require(not root.exists() and not root.is_symlink(), "root must not already exist")
    require(root.parent.is_dir() and root.parent.stat().st_uid == os.getuid(),
            "root parent must exist and belong to the invoking user")
    require(root not in (Path.home(), HERE) and not HERE.is_relative_to(root),
            "a home or workspace ancestor cannot be the installation root")
    guest = subprocess.run(["/usr/bin/systemd-detect-virt", "--vm"],
                           capture_output=True, text=True, timeout=10, check=False)
    is_vm = guest.returncode == 0 and guest.stdout.strip() in ("kvm", "qemu")
    ci_root = os.environ.get("RUNNER_TEMP", "")
    is_hosted_ci = (os.environ.get("GITHUB_ACTIONS") == "true"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("RUNNER_OS") == "Linux"
                    and bool(ci_root) and root.is_relative_to(Path(ci_root).resolve()))
    require(is_vm or is_hosted_ci,
            "not an explicitly acknowledged disposable KVM/QEMU or GitHub-hosted CI root")
    return root, "kvm/qemu" if is_vm else "github-hosted-ci"


def download(item, target, opener, deadline):
    """Only the pinned bytes may reach disk; no weight/wheel import happens here."""
    digest = hashlib.sha256()
    remaining = item["bytes"]
    created = False
    require(time.monotonic() < deadline, "provisioning deadline expired")
    request = urllib.request.Request(official_url(item["url"]),
                                     headers={"User-Agent": "VOLPAROSSA-explicit-provision/1"})
    try:
        with opener.open(request, timeout=30) as response, target.open("xb") as output:
            created = True
            official_url(response.url)
            length = response.headers.get("Content-Length")
            require(length is None or int(length) == remaining, "download size header mismatch")
            while remaining:
                require(time.monotonic() < deadline, "provisioning deadline expired")
                block = response.read(min(1024 * 1024, remaining))
                require(block, "truncated artifact")
                remaining -= len(block)
                output.write(block)
                digest.update(block)
            require(not response.read(1), "artifact exceeds pinned size")
            require(digest.hexdigest() == item["sha256"], "artifact SHA256 mismatch")
        target.chmod(0o600)
    except BaseException:
        # Only this newly created file is eligible; leave the private root for diagnosis.
        if created and target.is_file() and not target.is_symlink():
            target.unlink()
        raise


def wheel_expanded_bytes(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) <= 100_000, "excessive wheel entry count")
        names = set()
        for entry in entries:
            parts = PurePosixPath(entry.filename)
            require(not parts.is_absolute() and ".." not in parts.parts
                    and "\\" not in entry.filename and entry.filename not in names,
                    "unsafe/duplicate wheel entry")
            require(not stat.S_ISLNK(entry.external_attr >> 16), "wheel symlink is forbidden")
            names.add(entry.filename)
        return sum(entry.file_size for entry in entries)


# Executed only by the new private venv, with the verified pinned pip wheel on
# sys.path. Its vendored packaging evaluates the exact target markers/specifiers
# from actual downloaded wheel METADATA, before installing any runtime package.
CHECK_WHEEL_GRAPH = r'''
import email, json, pathlib, sys, zipfile
sys.path.insert(0, sys.argv[1])
from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.specifiers import SpecifierSet
from pip._vendor.packaging.tags import sys_tags
from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
from pip._vendor.packaging.version import Version
pins=json.loads(pathlib.Path(sys.argv[2]).read_text())
wheelhouse=pathlib.Path(sys.argv[3]); env=default_environment(); env['extra']=''
versions={canonicalize_name(x['name']):Version(x['version']) for x in pins['wheels']}
for item in pins['wheels']:
    name,version,_,tags=parse_wheel_filename(item['path'])
    assert tags.intersection(sys_tags()), ('wrong platform',item['path'])
    assert canonicalize_name(item['name'])==name and versions[name]==version
    with zipfile.ZipFile(wheelhouse/item['path']) as archive:
        members=[x for x in archive.namelist() if x.endswith('.dist-info/METADATA')]
        assert len(members)==1
        meta=email.message_from_bytes(archive.read(members[0]))
    assert canonicalize_name(meta['Name'])==name and Version(meta['Version'])==version
    assert Version(env['python_full_version']) in SpecifierSet(meta.get('Requires-Python',''))
    for raw in meta.get_all('Requires-Dist',[]):
        req=Requirement(raw)
        if req.marker is not None and not req.marker.evaluate(env): continue
        assert not req.url and not req.extras, ('unexpected dependency form',raw)
        dependency=canonicalize_name(req.name)
        assert dependency in versions and versions[dependency] in req.specifier, (name,raw)
print('PINNED_WHEEL_GRAPH_OK')
'''

RUN_PINNED_PIP = (
    "import runpy,sys;sys.path.insert(0,sys.argv[1]);"
    "sys.argv=['pip']+sys.argv[2:];runpy.run_module('pip',run_name='__main__')"
)


def run_checked(command, environment, root, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "provisioning deadline expired")
    subprocess.run(command, env=environment, cwd=root, check=True, timeout=remaining)


def execute(args, pins):
    root, guest_kind = execution_root(args)
    total = download_total(pins)
    require(args.budget_bytes >= total + RESERVE_BYTES, "budget cannot hold pinned downloads")
    require(shutil.disk_usage(root.parent).free >= args.budget_bytes,
            "free disk space is below the explicit budget")
    previous_umask = os.umask(0o077)
    try:
        root.mkdir(mode=0o700)  # Exclusive new root, never an existing cache/install.
        model = root / "model"
        wheels = root / "wheels"
        temporary = root / "tmp"
        for directory in (model, wheels, temporary, root / "cache"):
            directory.mkdir(mode=0o700)
        (root / "model-pins.json").write_bytes((HERE / "model-pins.json").read_bytes())
        (root / "requirements.lock").write_bytes((HERE / "requirements.lock").read_bytes())
        deadline = time.monotonic() + args.timeout_seconds
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), OfficialRedirect())
        for group, directory in ((pins["wheels"], wheels), (pins["files"], model)):
            for item in group:
                print(json.dumps({"downloading": item["path"], "bytes": item["bytes"]}), flush=True)
                download(item, directory / item["path"], opener, deadline)
        expanded = sum(wheel_expanded_bytes(wheels / x["path"]) for x in pins["wheels"])
        # Original wheels remain for license/provenance. No bytecode compilation;
        # the reserve covers venv metadata/scripts and bounded pip temporaries.
        require(total + expanded + RESERVE_BYTES <= args.budget_bytes,
                "verified wheel expansion exceeds explicit disk budget")
        runtime = root / "venv"
        venv.EnvBuilder(with_pip=False, symlinks=True).create(runtime)
        runtime.chmod(0o700)
        python = str(runtime / "bin/python3")
        pip_wheel = str(wheels / next(x["path"] for x in pins["wheels"] if x["name"] == "pip"))
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(temporary),
            "HF_HOME": str(root / "cache"), "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
            "HF_HUB_DISABLE_XET": "1", "DO_NOT_TRACK": "1", "CUDA_VISIBLE_DEVICES": "",
        }
        run_checked([python, "-I", "-B", "-c", CHECK_WHEEL_GRAPH, pip_wheel,
                     str(root / "model-pins.json"), str(wheels)], environment, root, deadline)
        run_checked([python, "-I", "-B", "-c", RUN_PINNED_PIP, pip_wheel,
                     "--isolated", "--disable-pip-version-check", "install", "--no-index",
                     "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-compile",
                     "--no-cache-dir", "--find-links", str(wheels),
                     "--requirement", str(root / "requirements.lock")], environment, root, deadline)
        run_checked([python, "-I", "-B", "-m", "pip", "--isolated",
                     "--disable-pip-version-check", "check"], environment, root, deadline)
        run_checked([python, "-I", "-B", "-c",
                     "import torch,transformers,peft;"
                     "assert torch.__version__=='2.14.0+cpu' and torch.version.cuda is None;"
                     "assert transformers.__version__=='5.16.1' and peft.__version__=='0.20.0';"
                     "print('OFFLINE_CPU_RUNTIME_IMPORT_OK')"], environment, root, deadline)
        report = {
            "format_version": 1, "success": True, "guest": guest_kind,
            "runtime_root": str(runtime), "model_root": str(model),
            "model_id": MODEL_ID, "revision": REVISION,
            "download_bytes": total, "wheel_expanded_bytes": expanded,
            "budget_bytes": args.budget_bytes, "installed_wheels": len(pins["wheels"]),
            "model_pins_sha256": hashlib.sha256((root / "model-pins.json").read_bytes()).hexdigest(),
            "requirements_sha256": hashlib.sha256((root / "requirements.lock").read_bytes()).hexdigest(),
            "training_performed": False, "runtime_autofetch_enabled": False,
        }
        (root / "provision-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)
    except BaseException:
        print(f"Provisioning incomplete; only the new private root may contain files: {root}", file=sys.stderr)
        raise
    finally:
        os.umask(previous_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preview", action="store_true", help="default: no writes or network")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--disposable-guest", action="store_true")
    parser.add_argument("--root", help="new private absolute guest directory; must not exist")
    parser.add_argument("--budget-bytes", type=int, help="maximum downloads plus expanded runtime")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    try:
        require(1 <= args.timeout_seconds <= 3600, "timeout must be 1..3600 seconds")
        pins = load_pins()
        plan = {
            "mode": "execute" if args.execute else "preview", "root": args.root,
            "model_id": MODEL_ID, "revision": REVISION, "wheel_count": len(pins["wheels"]),
            "download_bytes": download_total(pins), "budget_bytes": args.budget_bytes,
            "disk_budget_includes": "retained downloads + verified wheel expansion + 64MiB reserve",
            "changes": "new private root only: venv/, model/, wheels/, tmp/, cache/, pin files and report",
            "host_install": False, "training": False,
            "execute_requires": "--execute --yes --disposable-guest --root NEW_PATH --budget-bytes N; disposable KVM/QEMU or GitHub-hosted CI",
        }
        print(json.dumps(plan, indent=2), flush=True)
        if args.execute:
            execute(args, pins)
        return 0
    except (ProvisionError, OSError, ValueError, KeyError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"Provisioning refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
