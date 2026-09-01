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
hashes, and verifies all local patch hashes. `build-upstream.sh` then exports
each locked tree with `git archive` into the ignored native build staging
directory. Only those exports receive the reviewed patches:

| Target | Patch | SHA-256 |
|---|---|---|
| mqvpn | `patches/volparossa-mqvpn.patch` | `91885f49781c5fc38f9d1822c2b98ffec135fc939c769b678acccd7de48fa887` |
| mqvpn | `patches/volparossa-mqvpn-exit-paths.patch` | `da22508590dd066852344ac685cb1fc53dfdfaebaed16353ae53f8675f7e1427` |
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
anonymous Linux memfds for its synchronous xquic import. The patched server
also honours multipath=false, bounds app-accepted/pre-H3 QUIC connections by
the validated MaxClients limit, and can pin all UDP ingress and egress to one
exact canonical caller-supplied peer. Each H3 connection can claim only one
lifetime-affine CONNECT-IP session; duplicate bodies and Datagram stream IDs
cannot borrow the primary assignment, and all close/destroy paths share
idempotent session cleanup. Raw lifecycle tests prove both N/N+1 admission and
unsupported-ALPN pre-H3 cleanup release capacity for reuse. The patch
intentionally leaves VOLPAROSSA's
separate `MaxClients=1` product setting as a wrapper/runtime configuration
non-goal instead of hard-coding it into general-purpose upstream mqvpn. Native API version 6
implements role-specific preflight, a fresh per-process-start instance, exact request-digest
correlation, bounded request-driven reverse polling, and separate multipath-at-least-two versus
single-path-exactly-one modes without downgrade, and route-scoped auth/TLS
material plus signed reservation/finalize, commitment, certificate and process-instance scope with
a bounded expiry. It consumes one operation-bound UDP descriptor
for `AddPath` and one listener-shaped descriptor for `StartExitSession`; Rust and
the dormant C runtime check its current tuple/flags, but not helper origin,
assigned-address state, or network namespace. The dormant C runtime closes that
descriptor before failing closed. Versions
1 through 5 and unknown versions fail closed. The process instance does not change
the RFC 9484 zero IP Datagram wire Context ID. SCM_RIGHTS proves request correlation;
only active client `AddPath` checks a same-session namespace cookie. Native converts accepted
wall expiry to BOOTTIME and uses a bounded process-local reservation/finalize ledger with no live
eviction, but does not verify the signed bundle or retain that ledger across restart. Production
path adoption remains blocked until separate role service identities, helper provenance, the exact
namespace and product-pool assignment are authenticated and durably bound. The current same-UID
socket is not attestation or authentication against an explicitly untrusted agent.

Still unresolved are trusted helper-origin proof for client path descriptors,
the unique delivered-payload metric, the operational exit listener plus
helper/agent-to-native TLS-material and namespace-FD lifecycle,
exact VOLPAROSSA EDT scheduler, real reverse-dataplane topology, end-to-end
dynamic path removal/failover, and the full disposable namespace acceptance
suite. No source lock, patch, binary, or unit-test result is itself
evidence that the required VOLPAROSSA dataplane exists.
