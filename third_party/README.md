# Native third-party sources

`upstream.lock.json` is the authoritative, machine-readable source and patch
lock for the native MPQUIC component. Normal verification and builds perform
no network access. Source retrieval is a separate, explicit operation:

~~~sh
native/volparossa-mpquic/scripts/fetch-upstream.sh --yes
~~~

The fetcher checks each full commit, Git tree, origin, tag, parent gitlink, and
tracked-worktree state while reconstructing the exact mqvpn submodule layout.
It does not modify a locked source tree. Existing checkouts that differ from
the lock are rejected.

`verify-upstream.sh` additionally compares the verbatim license and NOTICE
copies, verifies the exact bundled Wintun `wintun.h`, `LICENSE`, and `README.md`
hashes, and verifies both local patch hashes. `build-upstream.sh` then exports
each locked tree with `git archive` into the ignored native build staging
directory. Only those exports receive the two reviewed patches:

| Target | Patch | SHA-256 |
|---|---|---|
| mqvpn | `patches/volparossa-mqvpn.patch` | `dfeffe71a9db187a700a078f0f9f427a57f7eb69bfae2ba1b974a556bd22719d` |
| xquic | `patches/volparossa-xquic.patch` | `acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b` |

The builder runs `git apply --check` before applying each patch and refuses a
hash mismatch. It compiles from source; unchecked prebuilt binaries are not
accepted.

License and notice copies live in `third_party/licenses/` and remain verbatim
from the locked revisions, including `wintun-MIT.txt`. mqvpn selects MIT from
Wintun's `GPL-2.0 OR MIT` offer. Its userspace header is a Windows-only bundled
source input: it is not compiled or linked on Debian, and no Wintun DLL is
bundled, downloaded, or loaded at runtime. Source checkouts under
`third_party/src/` and exported build trees under
`native/volparossa-mpquic/build/` remain untracked.

The audit records unresolved capabilities as `false`. The patches close SPKI
pinning, explicit peer-tuple binding, honest path-metric, server session
correlation, credential-retirement, and caller-supplied TLS-secret-path seams.
The mqvpn server now accepts bounded in-memory PEM identity and uses sealed
anonymous Linux memfds for its synchronous xquic import. Native API version 4
implements bounded request-driven reverse polling, a nonzero local association identifier
validated at the mqvpn boundary, separate multipath-at-least-two versus
single-path-exactly-one modes without downgrade, and route-scoped auth/TLS
material with a bounded expiry. It also consumes exactly one request-bound UDP
descriptor for `AddPath`; native never creates or binds a path socket. Versions
1, 2, 3, and unknown versions fail closed. The local identifier does not change
the RFC 9484 zero IP Datagram wire Context ID. SCM_RIGHTS correlation and a
same-session namespace cookie do not prove privileged-helper origin, so
production path adoption remains blocked until that provenance is authenticated.

Still unresolved are trusted helper-origin proof for client path descriptors,
the unique delivered-payload metric, the operational exit listener plus
helper/agent-to-native TLS-material and namespace-FD lifecycle,
exact VOLPAROSSA EDT scheduler, real reverse-dataplane topology, end-to-end
dynamic path removal/failover, and the full disposable namespace acceptance
suite. No source lock, patch, binary, or unit-test result is itself
evidence that the required VOLPAROSSA dataplane exists.
