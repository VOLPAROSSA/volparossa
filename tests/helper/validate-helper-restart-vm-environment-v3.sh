#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$here/validate-helper-vm-environment-v3.py" restart "$@"
