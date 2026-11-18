#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source upload sibling; reuse the unchanged guest-only Cloud provisioner."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
PIN_PATH = HERE / "cloud-private-upload-pins-paired.json"
BASE = runpy.run_path(str(HERE / "cloud-private-file-provision.py"))
FILES = BASE["FILES"] | frozenset(("src/owner-uploads.mjs", "scripts/upload_lock.py",
                                  "scripts/smoke_owner_upload_ui.py", "src/storage-maintenance.mjs",
                                  "src/storage-upload-maintenance.mjs"))


def configured():
    state = BASE["load_pins"].__globals__
    state.update(PINS=PIN_PATH, REVISION="178592a3881d49f839f7716a154f7ef446ecbda5", FILES=FILES)
    BASE["load_pins"]()
    return state


if __name__ == "__main__":
    configured()["main"]()
