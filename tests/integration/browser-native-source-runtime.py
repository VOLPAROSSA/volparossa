# SPDX-License-Identifier: GPL-3.0-only
"""Runtime binding used by the ordinary-tab driver inside a fresh native bundle."""
from browser_native_shared import FIREFOX_REVISION, GUEST_ROOT, digest, require, validate

# Both native builds expose the SHA of their original compilation receipt.
# The shared validator authenticates this file before the driver starts Firefox.
BASE_RECEIPT_SHA = digest(GUEST_ROOT / "provenance/build-result.json")
