#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source upload sibling; reuse the unchanged guest-only Cloud provisioner."""
import json
from pathlib import Path
import re
import runpy

HERE = Path(__file__).resolve().parent
PIN_PATH = HERE / "cloud-private-upload-pins.json"
BASE = runpy.run_path(str(HERE / "cloud-private-file-provision.py"))
FILES = BASE["FILES"] | frozenset(("src/owner-uploads.mjs", "scripts/upload_lock.py",
                                  "scripts/smoke_owner_upload_ui.py"))


def configured():
    pins = json.loads(PIN_PATH.read_text())
    # Deliberately fail closed until the reviewed product commit is available.
    # A working tree hash or the historical read-only revision is not upload proof.
    BASE["require"](type(pins.get("revision")) is str
        and re.fullmatch(r"[0-9a-f]{40}", pins["revision"])
        and pins["revision"] != "0" * 40 and set(pins.get("files", {})) == FILES)
    state = BASE["load_pins"].__globals__
    state.update(PINS=PIN_PATH, REVISION=pins["revision"], FILES=FILES)
    BASE["load_pins"]()
    return state


if __name__ == "__main__":
    configured()["main"]()
