# GPSD source and notice authority

`pins.json` fixes Debian trixie source version **3.25-5+deb13u2**, all four input
sizes/SHA256 values, the ordered eleven-patch quilt series and three Ubuntu
support-package hashes. No source snapshot, archive, binary or local modification
of GPSD is carried here. The source-only provenance inspection downloaded no
native binaries and executed no downloaded source.

The Debian source hashes were checked through a valid installed Debian archive
keyring -> trixie InRelease -> Sources.xz -> exact gpsd source stanza chain on
2026-10-28. Metadata hashes and the retained local evidence receipt digest are
recorded; `debian-source-entry.txt` preserves the exact primary stanza. The hosted
builder treats these reviewed fixed hashes as authority, not a moving mirror index.
The upstream release-3.25 tag points to 8501f01b257b226b9ad34190628e23838babadff;
neither its signature nor the detached tar signature was independently verified.
The authenticated Debian archive chain instead binds the actual tar bytes.

Use the complete Debian patch series, including CVE-2025-67268, CVE-2025-67269,
CVE-2026-58459 and CVE-2026-60122. The builder preserves original source-file
notices and applies only this pinned Debian series; bare upstream 3.25 is rejected.

COPYING is the unchanged upstream BSD-2-Clause notice. `debian-copyright` is the
unchanged complete Debian inventory, including ISC and IBM exceptions.
`file-notices.json` preserves original notice blocks for the invoked client/test
helpers and exceptional library files, with original source-file hashes.
GPSD is not relabeled as GPL; the VOLPAROSSA driver scripts remain GPL-3.0-only.
Privately extracted build-support packages retain their own packaged copyright
files and are not included in the evidence artifact or product distribution.

Primary origins:

- https://deb.debian.org/debian/pool/main/g/gpsd/
- https://packages.debian.org/source/trixie/gpsd
- https://gitlab.com/gpsd/gpsd/-/tags/release-3.25
- https://archive.ubuntu.com/ubuntu/dists/noble/universe/binary-amd64/Packages.gz
- https://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz

Support-package hashes came from the two primary Ubuntu HTTPS package indexes;
their index digests are recorded. No claim of an independently verified Ubuntu
archive signature is made. The reviewed exact package hashes are checked before
extraction/execution, and their Python-only dependency closure uses the runner's
existing system Python without changing the system package database or libc.
