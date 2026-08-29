# Testing and acceptance

Unit tests establish parser and state-machine properties; they do not establish dataplane privacy or
multipath. Real dataplane claims require a disposable Debian 13 network-namespace topology,
independent kernel/native counters, packet captures, fault injection, cleanup, and a machine-readable
acceptance report.

## Unprivileged quality gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --locked --offline --all-targets -- -D warnings
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
```
The dependency script verifies exact crates.io archives, reviewed local
security changes, unchanged license files, complete vendor-tree hashes, and
the locked root and standalone fuzz feature graphs before running cargo-deny's
license/ban/source checks and no-fetch `cargo-audit >= 0.22.1` scans of both
lockfiles. It records the local RustSec database commit. Debian's cargo-deny
0.18.3 rejects CVSS 4.0 vectors; a successful licenses/bans/sources subset
alone does not replace the advisory gate. See `third_party/rust/README.md` for
the narrowly scoped local backports, single-backend Yamux hardening, and
scanner exemptions.

The package-license regression proves all three reviewed path overrides and
the exact `yamux 0.13.10` release-tag license fallback enter the distributable
notices while workspace and arbitrary path packages do not.

Focused unit/property tests cover canonical protobuf, all eighteen signed
control payloads, signatures/key binding, replay/TTL/skew, advertisements, two-hop forwarding,
direct datapath-relay framing, policy normalization/thresholds, peerstore privacy,
selection/diversity/capacity, reservation expiry and exact retries, route contexts/LRU,
helper/native/local frames, configuration, MPTCP netlink, WireGuard plans, schedulers, and
idempotent cleanup planning. These tests are not dataplane or privacy evidence.

`volparossa-discovery/tests/reservation_rpc.rs` establishes authenticated Noise/Yamux connections
among three real libp2p swarms over process-local MemoryTransport. It proves a client cannot send an
exit request directly to the exit, then carries the same canonical wrapper client -> control relay
-> exit and the signed response back. Its probe case proves
`/volparossa/datapath-relay/4` framing while the production handler returns a received
fail-closed `Unavailable` without exposing a fake probe event.

Discovery unit tests prove `/volparossa/advertisement/4` canonical bounds and reject request
versions 1, 2, 3, and future values plus the retired direct-reservation v2 identifiers. Protocol,
reservation, exit, and relay tests cover fresh session identities, hold/permit/finalize/grant/
confirmation/receipt binding, exact successful retries, replay/expiry, capacity rollback, and
removal of permanent client Peer ID fields. Test-only exact evidence verifiers do not make a real
probe producer.

The production agent route state machine is not yet proven end to end. The no-argument production
helper can execute at most one live Client context at a time, containing exactly one Client-role
WireGuard lease, through Bind, Prepare and Destroy. Activate, Commit, Probe, transport acquisition, real two-leg probing,
client ingress, and live relay/exit publication remain fail closed. The unprivileged tests above
create no WireGuard device or host route; the separate disposable gate below confines its network
fixtures to private namespaces and does not satisfy an acceptance case without retained exact-main
evidence.

## Helper-boundary evidence

The helper identity and production IPC boundary has a separate, narrower live gate:

```sh
just build-helper-live-worker-identity-proof
sudo just test-helper-live-worker-identity-proof
```

Build as the ordinary workspace user, then execute only as root inside a disposable Debian 13
amd64 virtual machine with PID 1 systemd v257. The execute path refuses containers, a dirty or
changing worktree, unsupported hosts, missing artifacts, and an occupied host
`/run/volparossa`. Preview remains the safe default.

Successful execution writes exactly one canonical JSON document to stdout; plans and diagnostics
go to stderr. `tests/helper/helper-boundary-evidence-v1.schema.json` is the structural contract and
`tests/helper/validate-helper-boundary-evidence-v1.sh` enforces stricter semantics, exact ordered
PASS checks, distinct systemd invocation IDs, two worker descriptors before retirement, exact
not-found unit retirement, zero production descriptors during the live run, argumentless
production startup, clean retirement, separate observed source/artifact bookends, and equal
digests for the exact enumerated host-state records at two fences. The report is published only after its
root-owned stage has been removed. `tests/helper/test-helper-boundary-evidence-v1.sh` supplies a
canonical fixture and adversarial malformed or internally inconsistent false-PASS mutations. The
standalone validator checks the report contract, not the authenticity of an arbitrary report file;
the gate also does not infer that a pre-existing binary was built from the observed commit. Retained
evidence must therefore include the trusted disposable-VM job which first builds both binaries as
an unprivileged user from that clean checkout and then runs the fixed producer without changing it.

The production phase now runs one closed functional-client-lease probe as the staged agent. The
root hook creates one fixed dummy underlay only inside the transient unit's `PrivateNetwork`
namespace, then the probe registers an exact tag-35 intent and prepares one Client-role lease. At a
fixed root-owned FIFO READY barrier, the hook independently observes one direct helper child with
the expected executable, dedicated UID/GID and separate network namespace. That namespace must
contain only loopback and one UP WireGuard interface with the exact ownership-marker prefix, one
global `/128`, a non-zero public key and listen port, no peer, and no firewall mark. The probe
validates exact response correlation, opaque non-zero handles, the fixed `DirectAssigned` underlay
address and the helper-returned kernel proof; the external observation deliberately does not print
or independently byte-compare endpoint or key material.

After one fixed release byte, the probe requires exact Destroy followed by an idempotent
`existed=false` Destroy, then performs a second Prepare/Destroy cycle under the same helper runtime
with a distinct context, handles and public key. The hook finally requires zero helper children,
no WireGuard object in the retained first-worker namespace, no helper descriptor retaining that
namespace or any foreign worker network namespace, an empty systemd descriptor store, and a
private network satisfying the fixed exact-one-loopback/no-default-route cleanup predicate after
removing the dummy fixture. These checks prove a live, reusable, peerless Client lease and normal process-owned
cleanup only. They do not prove activation, a peer handshake, routing, transport, a tunnel,
crash/restart cleanup, package behavior, or a datapath.

The guest does not wrap that complete root producer in one 1 MiB file-size limit: the reviewed
helper and IPC-probe binaries are legitimately larger. Instead, each source must be one non-empty,
workspace-owned executable regular file with one hard link and a size of at most 128 MiB. Each is
copied separately under an exact 128 MiB `RLIMIT_FSIZE`, with source identity, metadata, and digest
fenced before and after the root-only staged copy. Only after both copies pass does the producer set
its own soft and hard file-size limit to 1 MiB and verify it before copying the at-most-1-MiB hook,
creating account/capture files, or starting either unit. The fixed path never raises that limit.
Both transient units independently retain `LimitFSIZE=1048576`; this bounds their writes even if
the producer exits.

The resolver state fence does not treat every non-root owner below `/run` as trusted. It accepts the
service owner pair only for the two fixed `systemd-resolved` files below the exact
`/run/systemd/resolve` runtime directory, after binding that pair to one active, running service
invocation and to the real/effective/saved/filesystem credentials of its current process. The
pinned genericcloud proof further requires the exact root-owned Debian `/etc/resolv.conf` symlink.
The authority record, runtime-directory identity, resolver object, canonical target metadata and
content digest are all bookended; only their private joined digest enters the before/after host
state comparison. Fixed rejection labels may identify the failed predicate but never print
resolver bytes, DNS/search values, raw metadata, process IDs, invocation IDs or digests.

The firewall fence treats canonical `nft --json list ruleset` output as the `nf_tables` authority,
including rules reached through `iptables-nft`; it does not infer a legacy backend from whichever
generic iptables alternative happens to be selected. Legacy IPv4 and IPv6 `x_tables` state is
classified only through `/proc/self/net/ip_tables_names` and
`/proc/self/net/ip6_tables_names`: the proc entry may be absent, present but empty, or present with a
bounded table inventory. Only the last case executes the fixed absolute
`/usr/sbin/iptables-legacy-save -M /bin/false` or
`/usr/sbin/ip6tables-legacy-save -M /bin/false` producer exactly twice. Both normalized dumps, both
inventory observations, and the nft JSON observations bracketing them must be identical or the gate
fails closed. Raw inventories and rule dumps remain in validated private capture files and are
removed; the comparison retains only SHA-256 digests and diagnostics use fixed labels. Equal
before/after records establish stability at those fences, not continuous firewall stability during
the interval.

The shared private-capture predicate validates the numeric regular-file type plus exact owner,
mode and single-link metadata, independently of file length. Successful commands, probe stderr and
validator streams may legitimately be zero bytes; where content has a semantic contract, callers
assert empty, non-empty or canonical content separately. The ownership lock's bytes have no
semantic meaning. Contract tests pin both zero-length acceptance and rejection of a wrong owner,
wrong mode, symlink or additional hard link.

The report carries those non-claims in its exact `scope` object: it is evidence only for the helper
boundary and does not claim package behavior, restart recovery, `CleanupOwned`, a VPN datapath, or
any A01--A15 result. AV1-09 remains Open until
the exact committed gate passes on the required clean disposable VM and its report is retained.

### Manual non-retained branch smoke and retained main-branch VM evidence

`.github/workflows/helper-boundary-evidence.yml` is intentionally manual. Start it with
**Actions -> Helper boundary evidence -> Run workflow** and select one branch. Exact
`refs/heads/main` selects `retained-main`: the job checks out that exact revision without persisted
GitHub credentials, binds the VM runner and report to `GITHUB_SHA`, revalidates the bounded output
on the host, and uploads the allowlisted artifacts. A canonical non-main `refs/heads/*` selects
`non-retained-pr-smoke`: the same exact branch/SHA disposable KVM proof and its environment/report
validation run. On PASS every proof file is discarded and the output directory must be empty; the
workflow uploads neither branch PASS artifacts nor branch failure diagnostics. This is manual branch selection, not an
automatic `pull_request` trigger and not support for `refs/pull/*`. Only a retained exact-main PASS
can count as AV1-09 evidence or change the alpha score.

If the guest proof fails in branch-smoke mode, the runner may emit only one fixed allowlisted failure
category (or `unclassified`) to job stderr. For `worker-launch-status` only, it may additionally emit
one fixed structural classification of launch binding, terminal state and payload-free helper stage.
It does not print or upload the proof diagnostic file.

The job first verifies the exact canonical bytes and complete object in
`tests/helper/debian13-amd64-image-v1.json`, and only then reads its HTTPS URL, filename, and
SHA-512. The recorded SHA-512 was manually reviewed against the upstream Debian cloud-image
`SHA512SUMS` file. That per-build checksum file has no detached Debian signature, so the manifest
deliberately calls this a reviewed Debian genericcloud image rather than cryptographically
attested upstream provenance. The download is size-, redirect-, connection-, and wall-time-bounded,
is verified before use, and is rehashed after VM use. The job invokes the fixed VM driver through
an exact process-scoped KVM authority boundary. In outline, with each value first validated and the
runner path made canonical and absolute, that boundary is:

```sh
proof_mode_flag=--retained-main
source_ref=refs/heads/main
runner_uid=$(id -u)
kvm_gid=$(stat -Lc '%g' /dev/kvm)
kvm_identity=$(stat -Lc '%d:%i:%t:%T:%F' /dev/kvm)
runner_path="$(pwd -P)/tests/helper/run-helper-boundary-evidence-vm.sh"
sudo -n -- /usr/bin/setpriv \
  --reuid "$runner_uid" \
  --regid "$kvm_gid" \
  --clear-groups \
  --inh-caps=-all \
  --ambient-caps=-all \
  --bounding-set=-all \
  --no-new-privs \
  --reset-env \
  -- \
  "$runner_path" \
  --execute \
  --yes \
  "$proof_mode_flag" \
  --image "$VOLPAROSSA_VM_IMAGE" \
  --output "$VOLPAROSSA_EVIDENCE_OUTPUT" \
  --expected-commit "$GITHUB_SHA" \
  --expected-source-ref "$source_ref" \
  --expected-host-uid "$runner_uid" \
  --expected-kvm-gid "$kvm_gid" \
  --expected-kvm-identity "$kvm_identity"
```

For a non-main smoke, the workflow substitutes `--non-retained-pr-smoke` and the exact selected
`refs/heads/<branch>` value. Execute mode requires exactly one proof mode and one matching canonical
source ref; `main` can never select the non-retained mode.

The driver uses two KVM boots of one disposable overlay. In the first boot, fixed provisioning
commands use unrestricted egress for `apt` and `cargo fetch`; no destination allowlist is claimed.
It then powers off.
The second boot uses QEMU user networking with `restrict=on`, proves that external HTTPS is denied,
and builds with `cargo --locked --offline` before running the fixed root proof. The host injects and
pins a fresh Ed25519 guest host key before the first SSH probe; it never uses SSH trust-on-first-use.
An identity-bound pidfd supervisor owns each QEMU lifetime, and byte-oriented collectors actively
cap and drain the VM console and command output.

In `retained-main` mode, the host revalidates a successful canonical report, its SHA-256, and the
exact PASS-only environment record including the commit, image, guest versions, KVM, restricted
network mode, and report hash crosslink. A successful retained artifact contains only the report,
report hash, bounded environment record, VM console, and proof stderr, for 90 days. A caught
VM/proof failure may retain only its
bounded environment diagnostic, console, and proof stderr for diagnosis; before the guest proof,
that stderr file may instead contain the canonical supervisor status and a private rolling tail of
QEMU stderr. The identity-bound supervisor continuously drains the supervised stream, retains at
most 896 KiB, and publishes the finalized tail before status; it never applies a file-size limit to
QEMU or its writable disk. It scans every drained byte across read boundaries and replaces the tail
with a fixed redaction notice if a PEM/OpenSSH private-key marker appeared, including before
retained-tail bytes. A writer inherited by an unexpected descendant cannot make finalization
unbounded: that lifecycle fails closed. A failed run cannot publish a report or report hash. The
guest's seven network JSON normalizers also require exact document and entry shapes, preserve
IPv4/IPv6 route and rule provenance explicitly, and suppress parser stderr. Malformed captured
network state therefore reaches the retained diagnostic only as a fixed failure label, never as a
data-dependent JSON excerpt; the unprivileged contract exercises that boundary with a sentinel.
The upload uses an exact allowlist and never includes either ephemeral SSH key, the cloud-init seed,
base image, source archive, or writable VM disk. Every candidate retained file is also rejected if it
contains a private-key marker. Uncertain cleanup removes both the finalized stderr and an exact
private `.stderr.<pid>.tmp` left by an interrupted atomic publication; malformed names, links, or
metadata fail cleanup closed instead of being followed.

The standard GitHub-hosted runner is disposable and is not promised to expose nested KVM. On that
ephemeral CI host only, the workflow uses `sudo` to install the fixed Ubuntu packages. It does not
change `/dev/kvm` ownership, mode, group membership, or ACL. Before any KVM process it records the
device identity and the complete numeric ACL, requires the root-owned device's original group to
have effective `rw-` access, and validates the fixed root-owned `/usr/bin/setpriv` executable.
Exactly two launches receive process-scoped KVM authority: the KVM preflight and the absolute
repository runner. Both use the device GID as their primary GID while clearing supplementary groups
and inheritable, ambient, and bounding capabilities, enabling `no_new_privs`, and resetting the
environment.

The runner refuses host root and never invokes host `sudo`. Its execute mode requires the expected
host UID, KVM GID, and device identity. At startup and immediately before each of the two QEMU
boots, it requires all four `/proc/self/status` UID fields to equal the original runner UID, all
four GID fields to equal the KVM device GID, an empty supplementary-group set, zero `CapInh`,
`CapPrm`, `CapEff`, `CapBnd`, and `CapAmb`, and `NoNewPrivs: 1`. It also rechecks the exact character
device identity, root ownership, device GID, and readable/writable access. The preflight exercises
KVM twice inside one process-scoped authority across `udevadm settle`, with a running virtual CPU
each time, and then compares the ACL byte-for-byte with the original snapshot. A one-open ACL
lifetime therefore cannot produce a false pass. The workflow repeats the device-identity and
numeric-ACL comparison before the PASS artifact can be uploaded. It never falls back to TCG. A
missing stable group-readable KVM device is an infrastructure failure, not negative helper-boundary
evidence. Equally, a completed job does not change the alpha score unless the selected post-merge
`main` revision produces a host-revalidated `PASS`, the exact artifact is retained, and the
unchanged host KVM-state gate succeeds.

Fuzz targets are required for every externally controlled parser: all eighteen signed v4 control
payloads, advertisement-v4, exit-forwarding-v4, datapath-relay-v4, policy manifests, local/helper/
native control frames, `OPEN_TCP`, UDP authorization, TLS ClientHello, QUIC
Initial/classification, peerlinks, and configuration. Inputs must reach the 512 KiB frame boundary
and at least one byte beyond it. Corpora contain only synthetic metadata. Enforce allocation,
recursion, field, list, frame, timeout, peer, session, buffer, and replay-cache bounds. Parser
compilation or a short smoke run is not evidence of sustained fuzzing.

The A0 regression tests for tags 17 and 18 are likewise not sustained fuzz evidence; their
request, receipt, wrapper, and nested-envelope parsers remain under this open fuzzing requirement.

## Privileged topology safety contract

The topology runs only in disposable Linux namespaces connected by veth pairs. It may create
temporary namespace-scoped nftables rules, routes, addresses, WireGuard devices, MPTCP endpoints,
and `tc netem` limits. The runner must:

1. print exact proposed names, veths, address ranges, tables/marks, rules, and limits;
2. reject collisions and non-Debian/non-Linux prerequisites;
3. capture host route/rule, DNS, nftables, link, and namespace state before changes;
4. ask for confirmation unless a clearly named CI-only opt-in is set;
5. trap exit, error, INT, TERM, and HUP and call idempotent scoped cleanup;
6. avoid host sysctl, DNS, default-route, firewall, VPN, and physical-interface changes;
7. capture the same host state afterward and fail on any unrelated delta.

Never run a root script whose targets contain unresolved variables, globs, broad prefixes, or the
host namespace. Diagnostic `ip`, `wg`, `nft`, `ss`, `tcpdump`, and `tc` output is allowed in tests;
product behavior uses netlink/UAPI.

## Required nodes and links

The single command topology contains a client, two replaceable bootstrap peers, at least six relays,
two exits, allowed and denied TCP/UDP/HTTP3 destinations, independent operator/ASN/prefix
metadata, constrained paths, NAT cases, and a policy signer/fixture boundary. Each physical leg has a
distinct veth/network, and packet captures occur inside relevant namespaces, never on an unrelated
host interface.

## Acceptance cases

| ID | Required evidence |
|---|---|
| A01 | Discovery and advertisement/selection continue after either bootstrap contact is removed. |
| A02 | A real TCP download has at least two `IPPROTO_MPTCP` subflows through different relays, both with increasing data counters. |
| A03 | Constrained MPTCP paths aggregate beyond the measured capacity of one path. |
| A04 | Removing an active MPTCP relay does not terminate the application flow. |
| A05 | UDP echo uses one relay and packet/routing evidence proves no direct client-exit path. |
| A06 | Browser HTTP/3 inside MASQUE uses one genuine MPQUIC connection with at least two unique-byte-carrying relay paths. |
| A07 | Removing one MPQUIC relay avoids unnecessary inner-QUIC interruption and no downgrade/direct route occurs. |
| A08 | An allowed test domain/protocol/port succeeds. |
| A09 | Unlisted domain, raw IP, SNI mismatch/missing SNI, and forbidden port all fail closed. |
| A10 | ECH or otherwise unverifiable destination identity fails closed. |
| A11 | Relay capture shows only client/relay/exit overlay traffic, not the Internet destination in the routed outer layer. |
| A12 | Exit-namespace packet capture sees incoming control/datapath relays rather than the client's public address or direct connection. |
| A13 | Client packet capture plus routes prove no direct client-exit control or dataplane path. |
| A14 | Forced agent/helper/native crashes followed by cleanup remove all owned namespaces, links, routes, MP paths, sockets, and rules. |
| A15 | Original host routes, DNS, firewall, links, sysctls, and VPN state are unchanged after the run. |

An acceptance case passes only when its evidence is automatically checked. A configured interface,
handshake, signature, service-state transition, or scheduler decision without unique delivered bytes
does not count as a data-carrying path. A12 and A13 specifically require packet-capture evidence;
unit tests, route plans, and the absence of a direct-exit method cannot substitute for those
captures.

## Machine-readable report

Every acceptance invocation emits exactly one JSON document on standard output. Human explanation
goes to standard error. The normative structural contract is
`tests/integration/acceptance-report.schema.json`; the repository also provides the stricter semantic
validator `tests/integration/validate-report.sh`.

Every report lists A01 through A15 exactly once. A case can be `PASS` only with one or more
content-addressed evidence objects. An overall `PASS` additionally requires an attempted and
completed full-suite execution on Debian 13 amd64, complete source/time provenance, a created
topology, captured and unchanged host state, complete cleanup, zero remaining owned objects, and
all fifteen cases passing. MPTCP selects A02-A04/A14/A15 and MPQUIC selects A06-A07/A14/A15; a
successful subset remains overall `BLOCKED` with `PARTIAL_SUITE` because it is not full acceptance.

Evidence paths use bounded ASCII components below the report directory. The validator rejects
report or evidence symlinks, rehashes every readable regular evidence file, and compares its actual
SHA-256 with the report. A14 cannot pass without separate agent, helper, native, and owned-object
cleanup checks. A15 cannot pass unless fixed before/after evidence entries bind to present, equal
host-state digests. A case cannot pass or fail before a topology exists, and missing post-attempt
host or cleanup state is an `ERROR`, not a successful or merely blocked result.

The current default commands are safe previews:

```sh
just test-integration
just test-netns
just test-mptcp
just test-mpquic
just benchmark
```

An execute request must additionally include the explicit `--yes` acknowledgement after the
printed plan. Omitting or duplicating that acknowledgement is an argument error and cannot reach a
mutating path. The acknowledgement is not proof of safety: the fixed supervisor, environment gate,
ownership checks, teardown, and host-state comparison must all still succeed.

The acceptance and benchmark drivers required to exercise real datapaths are not present yet. The
production probe producer, helper backend, agent route orchestration, and client ingress are also
blocked. Consequently these commands intentionally emit `overall: "BLOCKED"`, mark unexecuted work
`SKIPPED` with a reason, and exit 77. Exit 64 denotes invalid arguments and 69 denotes a missing
local report prerequisite. Exit 77 is not a passing or successful acceptance result.

The Rust report-model tests compile the normative Draft 2020-12 schema and validate full, MPTCP,
and MPQUIC model reports against it. `tests/integration/test-harness.sh` is unprivileged and
exercises argument parsing, strict semantic and artifact validation, `--only mptcp|mpquic`
selection, false-PASS refusals, fail-closed execution requests, and non-mutation previews with
command shims. The root-capable topology entry point contains no dormant network mutator, refuses
arbitrary commands and standalone cleanup, and only prints the fixed future lifecycle plan.

The lifecycle protocol is separate from the acceptance result. Before its five bounded, canonical
frames, the outer sends one bounded canonical `LAUNCH_CONTEXT` transport-provisioning record over
a dedicated inherited unnamed channel. It contains only the random run ID, the three original-host
namespace identities, and the fixed topology-specification digest. It is not a lifecycle frame,
cannot authorize topology mutation, and malformed, missing, duplicated, or prematurely closed
provisioning never reaches `GO`. A separate inherited bidirectional channel then carries the five lifecycle
frames in one strict order. `BOOTSTRAP_READY` is an
attestation that the fixed inner worker must construct only after directly measuring that it is PID
1 in different network, mount, and PID
namespaces, with private mounts, the enumerated read-only pre-`GO` network baseline, handlers, and
the parent-death chain established before network-topology mutation. The outer independently
compares the three namespace identities with
its original host identities. Only then may it send the affine `GO` authorization. The current
early slice reaches that barrier and permits only one bounded private-`/run` root-and-slot,
two-transient-nsfs-pin, two-veth, four-address, exact counted parent-FORWARD-policy, link-activation,
endpoint-route, four-permanent-neighbour, and fixed run-bound ICMPv4 echo transaction. It proves one
exact request/reply, exact `1/60`, `1/60`, `0/0` request/reply/drop counters, and matching
one-RX/one-TX 74-byte link telemetry on all four veth ends before explicit reverse neighbour
removal, deletion-only link teardown, and exact policy retirement; it does
not claim that the remaining configured topology lifecycle is implemented.
`TOPOLOGY_READY` attests to the run ID, fixed topology-specification digest, exact two run-bound
namespace identities, and the completed probe, all directly observed by that worker. The outer then
sends `STOP`; `FINISHED` must bind the SHA-256 of the exact `TOPOLOGY_READY` bytes and report
attempted cleanup. The outer independently reaps the complete sandbox and constructs the acceptance
report. EOF before `GO` explicitly means that no topology mutation was authorized; fixed pre-`GO`
bootstrap operations such as namespace creation, ID mapping, and private mounts may already have
occurred and must still be contained and reaped. EOF afterward requires cleanup. Missing,
malformed, reordered, duplicated, contradictory, or differently bound records fail closed. These
transient attestations are not A14 evidence and cannot themselves make any A01-A15 case pass.

After a real lifecycle-only run, normal teardown still leaves A14 `SKIPPED` with
`FORCED_CRASH_NOT_EXECUTED`. A15 alone may be `PASS` when two privacy-safe outer fingerprint
manifests are present, content-addressed, and exactly equal after the complete sandbox process tree
has been reaped. All selected datapath cases remain `SKIPPED` with `LIFECYCLE_ONLY`, so the report
and process result remain `BLOCKED`/77. The current blocked entry point has not produced that
evidence yet.

The test-only `volparossa-netns-runner` now owns an initial, deliberately early post-`GO`
containment slice. Its only transient topology is two otherwise-pristine network namespaces, their
kernel-default loopback/rules, their nsfs mounts, two fixed veth pairs, four fixed `/30` IPv4
addresses, four active link ends, two exact static `/32` endpoint routes, four exact affine
`NUD_PERMANENT` IPv4 neighbours, the exact kernel-created qdisc and route side effects, and one
run-bound generation-2 `inet` table containing the sole fixed
parent-FORWARD policy. While that policy is exact, the runner conditionally establishes
namespace-local IPv4 forwarding in PID 1's disposable parent network namespace and restores the
exact original record before policy retirement; the outer host setting remains unchanged. The
runner emits exactly one 40-byte raw ICMPv4 echo request from endpoint A, receives one exact
60-byte reply, proves the two accepts at one packet/60 bytes each and the terminal drop at zero,
and joins that evidence to one RX and one TX 74-byte Ethernet frame on every veth end. This proves
only that fixed run-bound exchange and its bounded teardown; it does not prove packet absence,
packet-capture privacy, a general VPN datapath, topology readiness, `TOPOLOGY_READY`, A14, A15, or
acceptance. It re-executes only
`/proc/self/exe`,
once as the fixed launcher and once as namespace PID 1, with a distinct private selector for each role. It
clears both child environments, fences unrelated inherited descriptors, and uses three separate
unnamed descriptor-free `SOCK_SEQPACKET` outer-to-launcher channels plus one launcher-to-PID-1
bootstrap channel; the lifecycle endpoint is transferred affinely to PID 1. Exactly one
`LAUNCH_CONTEXT` is provisioned within a fixed child-side timeout. The launcher binds kernel peer
PID/UID/GID on all three outer channels to its live parent, requires the parent's executable inode
to match its own, accepts only the exact outer `--run` invocation, and installs a verified
parent-death `SIGKILL` before isolation. A launcher-selector invocation without that exact parent
contract, and a PID-1-selector invocation without its required namespace and channel contract, are
rejected.

The single-task launcher performs one direct `unshare` of anonymous user, mount, network, and
pending child PID namespaces. Before any child exists, the outer retains a pidfd and anchored
`/proc/<pid>` directory, pins the exact user, mount, network, and current PID namespace descriptors,
requires an empty child set, and proves that the existing `pid_for_children` magic link is in the
kernel-defined uninstantiated state. Only then does it write `deny` to `setgroups` and one exact
`0 <outer-id> 1` extent to each ID map; both sides independently read back those mappings and the
stable partial namespace set. The launcher then emits `MAPPINGS_VERIFIED`, but cannot spawn PID 1
yet. The outer repeats its anchored mapping readback and returns the affine `MAPPINGS_PINNED`
proceed record; EOF instead retires the launcher before a PID-namespace child can exist.

After that barrier the launcher makes exactly one second fixed `/proc/self/exe` invocation, which
becomes PID 1 in the pending namespace and remains blocked on a new private bootstrap channel. The
launcher and PID 1 perform an affine, run-bound provision, parent-death, liveness, execution,
private-mount, and EOF exchange. PID 1 independently requires PID 1/PPID 0, one task, mapped-root
credentials, the exact inherited namespace set, an empty environment, cwd `/`, and an armed
parent-death `SIGKILL`. The outer upgrades its launcher namespace pins only after the child exists
and independently proves the exact executable/selector, PID/PPID/nesting, mappings, namespaces,
empty descendant set, and sole launcher-child relation. Only after the outer returns its run- and
PID-bound `PID1_PINNED` acknowledgement does PID 1 recursively make the inherited mount tree
private. It then uses the descriptor-based Linux mount API to attach a 16 MiB, 4096-inode,
mode-0700 tmpfs at `/run` with `nosuid,nodev,noexec`, followed by a separately instantiated procfs
at `/proc` with the same hardening flags. No caller-selected path, mount option, command, or
fallback is accepted.

Linux 6.12 supports tmpfs `noswap`, but deliberately rejects changing swapability from this
unprivileged user-namespace boundary. This slice therefore proves that `/run` remains empty and
places no key, credential, or token material there. Future filesystem-backed secret material stays
forbidden until the runner can independently prove a non-swappable store without broadening the
unprivileged supervisor boundary.

PID 1 binds the visible mount IDs to a bounded mountinfo parse, requires every inherited mount to
have no propagation relationship, proves `/run` is the new bounded empty tmpfs, and proves that
private procfs exposes exactly PID/task set `{1}` with no child. It retains root, `/run`, and `/proc`
descriptors and repeats that proof after the outer acknowledgement and immediately before exit.
The outer independently reads the still-live PID through its pre-mount pidfd and anchored host
`/proc/<pid>` directory, matches visible `statx` mount IDs to mountinfo, checks tmpfs type, capacity,
inode bound, mode and mapped ownership, and matches `/proc/1/ns/pid` to the retained PID namespace.
Only then is `PRIVATE_MOUNTS_VERIFIED` returned.

Before any child or fallback-reaper thread exists, the outer requires exact default inherited
HUP/INT/TERM actions, a waitable default CHLD action, and an empty inherited signal mask. It then
blocks exactly HUP, INT, TERM and CHLD and owns a nonblocking close-on-exec `signalfd`.
PID 1 inherits that exact mask and, before reporting private-mount readiness, installs fixed real
HUP/INT/TERM emergency handlers. Normal delivery remains synchronous through `signalfd`; an
unexpectedly unblocked managed signal can only make the emergency handler call `_exit(128 +
signal)`. The outer binds its independent readback to the retained pidfd and anchored proc
directory: `SigBlk` is exactly `0000000000014003`, managed bits are absent from `SigIgn`, `SigPnd`
and `ShdPnd`, and `SigCgt` is exactly `0000000000004443`. That caught set is the `0x4003` managed
mask plus the `0x0440` process-start SIGBUS/SIGSEGV stack-overflow baseline of the repository-pinned
Rust 1.85.0 runtime on Debian 13 amd64, not a Linux ABI constant; the audited UAPI separately reads
back the exact managed handler addresses, flags and masks.

After `PRIVATE_MOUNTS_VERIFIED`, PID 1 directly proves the enumerated read-only pre-`GO` network
baseline, repeats its mount/runtime/signal proofs, and emits one canonical `BOOTSTRAP_READY` over
the affinely transferred lifecycle endpoint. The frame is bound to the run and PID 1's measured
network, mount, and PID namespace identities. The outer parses that actual frame, requires all
three identities to match its retained PID-1 namespace pins, repeats the live mount and signal
proofs, and accepts the frame through the strict outer lifecycle state. Only then does it send
one canonical `GO`. PID 1 consumes the resulting affine `MutationAuthorization` and immediately
revalidates the complete pristine network baseline before the first filesystem mutation. The
production ownership transition operates only through retained directory descriptors: it creates
exactly `/run/netns` and `/run/volparossa-netns-runner/<run_id>` at mode 0700 plus two run-derived,
empty namespace slots at mode 0000. It proves their exact entry set and retained identities. One
fixed PID-1 task then creates distinct network namespaces A and B, restoring its exact parent
network namespace after each excursion. Audited `open_tree` and `move_mount` calls publish each as
an exact run-derived nsfs pin. The runtime proves their type, owning user namespace, distinct
object and mount identities, visible read-only-pin joinability, and the hidden-slot/visible-pin
dual view. Its active mountinfo proof is the exact original bounded baseline plus exactly two
known mount-ID/path/nsfs/no-propagation additions beneath the private `/run` mount; it is not an
independent assertion about every possible nsfs root or option field. A read-only visitor joins
each visible pin, runs the complete pristine RTNL, IPv4-forwarding, and zero-nftables-table proof,
and restores the exact parent after each visit. PID 1 then sends exactly two `RTM_NEWLINK` requests
with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Each request derives its parent name from
the run ID, fixes MTU 1500, TXQLEN 1000, and one TX/RX queue on both ends, and places peer `eth0`
directly in the exact retained target namespace through `IFLA_NET_NS_FD`; there is no
create-then-move fallback. The affine owner retains the target nsfs identity plus the exact fresh
parent/peer indices. Independent bounded snapshots then require parent `lo+vpa*+vpb*`, endpoint A
`lo+eth0`, and endpoint B `lo+eth0`, with exact veth type, down flags, peer relations, namespace
lineage, link attributes, unique locally administered MACs, exact zero fresh-link statistics and
ifmap, unchanged non-link state, IPv4-forwarding record, qdisc state, and empty nftables baseline.
PID 1 then borrows that pair owner into one affine `AuthorizedIpv4Addresses` sub-transaction and
sends exactly four `RTM_NEWADDR` requests with
`NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Every address, `/30` prefix, interface
label/index, namespace identity, scope, permanent lifetime, and rollback target is derived from
retained authority: parent A `10.241.1.1/30`, endpoint A `10.241.1.2/30`, parent B
`10.241.2.1/30`, and endpoint B `10.241.2.2/30`. All four veth ends initially remain down.
Independent parent/A/B snapshots admit exactly those four address records and the four
kernel-created local-table `/32` routes coupled to them, while requiring every other route and
RTNL object, qdisc observation, IPv4-forwarding record, and nftables baseline to remain unchanged.
PID 1 then sends four separate bounded `RTM_NEWLINK` requests that change only IPv6
address-generation mode to `none`; ACK/readback is followed by a separate exact four-end proof
barrier. Before any link-up request, PID 1 derives one policy expectation only from the retained
run and canonical A/B veth lineage. One generation-pinned atomic `NETLINK_NETFILTER` transaction
installs a run-derived `inet vpl_<run_id>` table, one `filter` base chain named `forward` at the
`inet` forward hook with priority 0 and policy drop, one exact IPv4 ICMP echo-request accept rule
from endpoint A (`10.241.1.2`) to endpoint B (`10.241.2.2`), and only its exact reverse echo-reply
accept rule. Fresh full-ruleset observation proves exactly that semantic state at generation 2.
With that policy active and all four ends still down at IPv6 addrgen mode `none`, PID 1 uses its
retained private-proc descriptor to establish canonical `1\n` in the fixed parent
`/proc/sys/net/ipv4/ip_forward` record. It requests exactly one bounded two-byte write when the
retained original is `0\n`; an original `1\n` is freshly re-read and adopted without a write. It
next activates all four ends with separate link-up requests. Exact converged parent/A/B
observations require carrier-up `noqueue` links, no IPv6 addresses, four local `/32`, four
connected `/30`, four high-broadcast `/32`, and four local-table IPv6 `ff00::/8` multicast routes.
Only temporary stable kernel snapshots may be retried inside the same two-second absolute
deadline; the final verifier remains exact. Those admitted routes remain kernel side effects.
The generation-2 policy is freshly re-proved across each topology transition. PID 1 freshly
reverifies the complete active state and sends exactly two bounded raw
`RTM_NEWROUTE` requests: endpoint A `10.241.2.2/32 via 10.241.1.1 dev eth0` and endpoint B
`10.241.1.2/32 via 10.241.2.1 dev eth0`. Both use
`NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`; the route header is exactly `AF_INET` `/32`,
main, `RTPROT_STATIC`, universe, unicast, flags zero, and the attributes are exactly
`RTA_TABLE=254`, `RTA_DST`, `RTA_GATEWAY`, and `RTA_OIF`. Retained namespace and pair authority
canonically supplies every value. Exact parent/A/B observations require an unchanged parent and
exactly the corresponding authorized route in each endpoint. A non-exact sibling or extra object
fails closed, and any possibly sent request retains deletion-bound authority even after an
ambiguous ACK/readback. PID 1 next installs exactly four affine `NUD_PERMANENT` IPv4 neighbours in
canonical parent A/B then endpoint A/B order. Parent records map each fixed endpoint address to its
endpoint MAC; endpoint records map each fixed parent gateway to its parent MAC. Exact semantic
parent/A/B observations require precisely those four records, `NDA_PROBES=0`, zero proxy-neighbour
records, and no other configuration delta. The complete `NDA_CACHEINFO` structure is validated,
but only its volatile telemetry values are excluded from snapshot equality. Every other field,
attribute, flag, length, namespace, interface, address, and MAC remains exact. The generation-2
policy and all three zero counters are re-proved around installation. With those neighbours still
armed, PID 1 consumes zero-counter authority and prepares one nonblocking close-on-exec raw ICMPv4
socket in endpoint A, bound to `eth0` and `10.241.1.2`, connected to `10.241.2.2`, and enabled for
`IP_PKTINFO`. One `sendmsg`, with no retry, emits an exact 40-byte request: identifier is the first
two canonical run-ID ASCII bytes interpreted big-endian, sequence is one, and payload is the full
32-byte canonical ASCII run ID. Before the absolute deadline, one bounded `recvmsg` must return an
exact 60-byte IPv4 reply with matching source, destination, receive interface, `IP_PKTINFO`, IPv4
and ICMP checksums, identifier, sequence, and full payload. The socket closes before two identical,
complete, generation-bracketed policy observations require the request-accept, reply-accept, and
terminal-drop counters at exactly `packets/bytes=1/60`, `1/60`, and `0/0`. Fresh semantic parent,
endpoint-A, and endpoint-B RTNL observations then require every veth end at exactly one RX and one
TX packet and 74 RX and TX bytes, with every other parsed 32- and 64-bit link-statistic field zero.
Routes, addresses, qdiscs, permanent neighbours, zero probes, and zero proxy-neighbour records must
remain exact. PID 1 then explicitly removes neighbours in reverse endpoint B/A then parent B/A
order, reconciles each possibly sent deletion to exact absence, proves restoration of the exact
routed snapshot without changing the post-echo link telemetry, and re-proves the exact
`1/60`, `1/60`, `0/0` counter profile. No `RTM_DELROUTE` request or encoder exists. After consuming
the reply/counter/telemetry proof and downgrading the policy to counter-agnostic cleanup authority,
PID 1 directly deletes veth B followed by A as the sole route-removal mechanism. Once a link request
may have been sent, teardown
never tries to restore link-down/EUI-64 state and never runs ordinary per-address rollback. Both
route owners and every lower address and pair owner remain armed. After direct veth B/A deletion,
PID 1 restores the exact retained original parent `ip_forward` record while the exact structural
generation-2 policy remains under counter-agnostic cleanup authority: an original `0\n` causes one
bounded two-byte restore write, while an
original `1\n` requires no write. It then proves all three namespaces byte-exactly equal to the
retained enumerated network baselines for the restored phase. PID 1 deletes only the freshly
observed table handle with a generation-pinned atomic transaction and requires a fresh complete
ruleset observation to prove semantic emptiness at generation 3. The final network proof binds the
restored RTNL, proc, and endpoint state to that generation-3 nftables result. A prevalidated
infallible retirement barrier disarms the route, address, and pair owners only after those final
proofs. This restoration claim covers only the fixed `ip_forward` record. Linux may reset related
per-device IPv4 configuration when forwarding changes; those other devconf values are not
exhaustively enumerated here, and their complete removal relies on destruction of the disposable
parent network namespace after its last reference closes. This slice does not separately observe
that destruction.
It ensures every detached-clone and transient visible-pin
descriptor is closed before ordinarily unmounting nsfs B then A with `UMOUNT_NOFOLLOW`, proves the
hidden empty slots and original mountinfo baseline are restored, and then rolls back slot B, slot A,
the per-run directory, the workspace root, and the netns root. Required directory `fsync` barriers
make every completed removal explicit. The proof removes every owned mount and link plus every
transaction-retained descriptor reference; it relies on kernel reference counting rather than
claiming to observe namespace destruction after the last reference closes.

After restoring the affine `PristineRun` state, PID 1 repeats its network, mount, runtime, and
signal proofs and sends one internal canonical `MUTATION_ROLLBACK_COMPLETE` record through the
launcher. The outer accepts and run/PID-binds it, then independently proves that the private
`/run` is empty again. Only then does the outer send exact TERM through the retained PID-1 pidfd.
PID 1 must consume that actual `signalfd` record and return one canonical run-, PID- and
signal-bound `MANAGED_SIGNAL_OBSERVED` through the launcher, which forwards the host-PID-bound
`PID1_SIGNAL_OBSERVED`. Once the outer accepts that observation and repeats the live signal proof,
it closes the lifecycle channel. Because `GO` was consumed, both lifecycle states require that EOF
to mean `CleanupRequired`; it can no longer mean `NoTopologyMutationAuthorized`. PID 1 then repeats
its proofs, exits 77, and is exactly reaped by the launcher and outer. Failure before the internal
rollback checkpoint proves bounded process containment only, not completed mutation rollback.

That fixed readiness baseline contains exactly one down `lo` link at ifindex 1 with loopback-only
flags, MTU 65536, transmit queue length 1000, `noop` qdisc, default link mode and group, zero
address/broadcast/promiscuity/all-multicast/protocol-down state, IPv6 EUI-64 address-generation
mode, GSO segment limit 65535, and GSO/GRO plus IPv4 GSO/GRO size limits 65536. It has no link
relationship, alias, alternate name, link-info, or attached XDP program. It
contains no addresses, routes, ordinary or proxy neighbours, nexthop objects, or unexpected qdisc
records. Its
routing-policy database is exactly IPv4 priorities 0/local, 32766/main, and 32767/default plus
IPv6 priorities 0/local and 32766/main. Each complete observation reads the fixed namespace-local
`/proc/sys/net/ipv4/ip_forward` record through the retained private-proc descriptor, accepts only
canonical `0\n` or `1\n`, and binds both the procfs object identity and value across the RTNL
snapshot. This readiness observation does not write the record; the later `GO`-authorized,
policy-bound transition described above may conditionally do so. A bounded read-only
`NETLINK_NETFILTER` sequence
requires generation 1 immediately before and after complete table, chain, rule, set, object, and
flowtable dumps, all of which must be empty. PID 1 repeats the complete observation immediately
before the authorized write and again after root/slot rollback; every pinned component must match,
while retained mount, runtime, and signal proofs bracket both barriers.

The production raw-`NFNETLINK` writer and strict observer implement the exact lifecycle forward
policy: one run-derived `inet vpl_<run_id>` table, one `filter` base chain named
`forward` at the `inet` forward hook with priority 0 and policy drop, and exactly three ordered
rules. The first matches only the IPv4 ICMP echo-request tuple from endpoint A (`10.241.1.2`) to
endpoint B (`10.241.2.2`) and places one inline counter immediately before `accept`; the second
matches only its exact reverse echo reply and likewise places one inline counter immediately before
`accept`; the third is unconditional and places one inline counter immediately before `drop`.
Before packet authority is consumed, every fresh complete active-policy observation requires each
of the three typed counters to be exactly `packets=0` and `bytes=0`. The one-way fixed-ICMP counter
phase can never regain zero-counter authority. After the sole socket closes, it can advance only
through two identical complete generation-bracketed observations with request/reply/drop
packets/bytes exactly `1/60`, `1/60`, and `0/0`; later teardown retains counter-agnostic deletion
authority only. The policy's only mutations are the bounded generation-pinned atomic
install transaction and the later handle-only table deletion; strict capped ACK binding and fresh
full-ruleset reconciliation cover every possibly sent request. Disposable namespace tests exercise
the production writer and prove the complete observed lineage from empty generation 1, through that
exact policy at generation 2, back to a semantically empty ruleset at generation 3. They record
canonical `0\n` or `1\n` before mutation and prove the value is byte-identical afterward. Extra or
altered tables, chains, rules, expressions, counter values, hooks, policies, tuples, verdicts, ACKs,
handles, or generations fail closed. Counter updates do not advance the nftables generation ID, so
an isolated observation alone would not prove stability or packet absence. The integrated proof
instead brackets one affine send authority with an exact reply, two matching post-close counter
observations, and exact four-veth link telemetry. That proves the one fixed exchange, not absence of
other packets, packet-capture privacy, a general VPN datapath, topology readiness, or acceptance.

The readiness observation does not claim that forwarding is disabled and makes no pre-`GO`
forwarding-setting request. A separate fixed proc writer can target only the descriptor-pinned
parent-namespace `ip_forward` record, accepts only canonical `0\n` or `1\n`, performs at most one
two-byte write per transition, and returns affine reconciliation authority after a possibly written
request. After a possibly written enable, any stable result other than the exact enabled target,
including the original value, stays indeterminate and aborts fail closed. It has no general sysctl
surface. Neither proof claims that every firewall/netfilter
facility is empty.
Qdisc records are enumerated so an ingress/`clsact` hook cannot hide behind link qdisc name
`noop`; traffic-control classes, filters, and chains are not separately catalogued because this
slice admits no non-baseline qdisc on which they could attach. Other netconf, address-label,
neighbour-table parameter, conntrack, ipset,
NFQUEUE/NFLOG, legacy-xtables, and independent-hook state is outside it. A read-only GET or the
fixed writers may cause ordinary kernel module loading. The runner has no general sysctl or
general nftables mutation API: it can change only the fixed forwarding record and install or retire
only the exact policy above. A later topology driver must pin every additional setting it relies on
or extend this proof before any additional packet class is sent.

The strict positive outer bootstrap exchange is `NAMESPACES_CREATED`, `MAPPINGS_INSTALLED`,
`MAPPINGS_VERIFIED`, `MAPPINGS_PINNED`, `PID1_SPAWNED`, `PID1_PINNED`, `PRIVATE_MOUNTS_READY`,
`PRIVATE_MOUNTS_VERIFIED`, `MUTATION_ROLLBACK_COMPLETE`, `PID1_SIGNAL_OBSERVED`, and
`PID1_REAPED`. The exclusive mount-policy branch substitutes `PRIVATE_MOUNTS_UNAVAILABLE` for the
two positive mount records. Only `EPERM` or `EACCES` from an exact fixed mount-UAPI operation may
take that branch; malformed state, missing targets, unsupported APIs, invalid options, resource
failures, and failed readback remain internal errors. Other fixed
kernel-policy denials return separate honest `BLOCKED` outcomes when required parent, namespace,
mapping, or outer PID-1 proof is unavailable, without fallback. A pre-isolation parent-proof or
namespace-policy denial uses a bounded two-channel half-close handshake: the launcher advertises
both EOFs but cannot exit until the outer acknowledges the control EOF, so early `SIGCHLD` never
races the admitted blocked result. Only the outer-owned containment deadline bounds that wait; the
launcher cannot time itself out before acknowledgement. If the outer PID-1 pin is
unavailable after spawn, the launcher sends one run-bound `ABORT_BEFORE_PRIVATE_MOUNTS` record to
PID 1, proves lifecycle EOF, and reaps it without issuing a mount instruction. A generic green CI
job may therefore prove only fail-closed behaviour; the complete positive path requires the
explicit `BlockedAfterFixedIcmpEchoTeardown` outcome on the Debian 13 acceptance host:

The portable unit suite runs the live RTNL and read-only NFNETLINK collectors plus adversarial
wire/parser and RTNL link/object cases when unprivileged user/network namespaces are available.
Disposable live cases install both `clsact` and `ingress` qdiscs through bounded RTNETLINK and
prove that the collector sees and rejects them. A separate disposable live round trip installs one
fixed `/30` address on a down veth, proves its exact address record and kernel-created local-table
`/32` route, removes it, and requires byte-exact restoration of the retained down-veth snapshot.
Another disposable round trip sets addrgen mode `none`, activates both ends, retains the exact
carrier/qdisc/address/route requirements through bounded convergence, directly deletes the pair,
and requires byte-exact parent and endpoint restoration.
The exact endpoint-route cases prove canonical request encoding, strict route decoding,
both-pair/namespace lineage, fail-closed sibling classification, and deletion-bound ownership.
The exact permanent-neighbour cases prove canonical `RTM_NEWNEIGH`/`RTM_DELNEIGH` encoding,
four-entry affine ownership, parent A/B then endpoint A/B installation, endpoint B/A then parent
B/A removal, strict namespace/route/address/MAC lineage, exact `NUD_PERMANENT` state, zero probes,
zero proxy neighbours, and fail-closed reconciliation after every possibly sent request. Semantic
snapshot equality validates the complete neighbour record and excludes only the four volatile
`NDA_CACHEINFO` telemetry values; malformed, duplicate, unknown, or conflicting records are fatal.
The live production-policy round trip installs the exact three-rule, zero-counter generation-2
ruleset in a disposable namespace, deletes only its observed table handle, proves semantic-empty
generation 3, and verifies the inherited canonical forwarding value unchanged. That isolated
fixture deliberately sends no packet and makes no counter-stability claim. Separate parser,
checksum, socket-contract, single-send, timeout, reply, full-run-ID-binding, counter-profile, and
link-statistic tests cover the fixed ICMP components. The dedicated lifecycle gate below is the
positive integration that joins those production components into one real request/reply proof.
Separate fixed-writer tests use a distinct disposable network namespace to establish `0\n`, perform
a real `0\n` to `1\n` to `0\n` round trip, and restore that namespace's initial value. Synthetic
descriptor-backed tests prove that an inherited `1\n` takes the no-write enable and restore path.
Together with the production lifecycle gate these cover both conditional branches without changing
the development host, but they are not a claim that two separately forced initial values traversed
the complete PID-1 lifecycle.
These portable cases treat only the exact util-linux `EPERM` forms for an unavailable `unshare` or
UID/GID-map write as an environmental skip; every other spawn, child, parser, or proof failure
remains fatal. Such a skip is not readiness evidence and cannot replace the dedicated gate.

```sh
just test-netns-fixed-icmp-echo-proof
```

That opt-in gate requires an unprivileged Debian 13 amd64 host with unprivileged user namespaces
enabled, zero inherited, permitted, effective, and ambient capability sets, and `no_new_privs`. It
also requires Debian's `iproute2` (`ip` and `tc`) and `jq` packages for a read-only, canonical outer
configuration fingerprint. A dedicated ephemeral VM is required for authoritative acceptance, but
the gate itself proves only that its immediate host is a VM; CI job provenance must establish that
the VM was dedicated and ephemeral. A bare-metal development host may supply an additional local
proof because the runner remains inside disposable namespaces and the gate compares its outer
namespace and mount table plus canonical stable link fields, addresses without expiring lifetimes,
IPv4/IPv6 routes and policy rules, nexthops, qdiscs without counters, IPv4 `ip_forward`, IPv6
`all/default` forwarding, and `/etc/resolv.conf` object/target identity plus content before and
after. It deliberately excludes
volatile carrier/operstate, neighbour state, counters, address lifetimes, and resolver-daemon
caches. The unprivileged gate does not escalate and cannot authoritatively read host
nftables/legacy-firewall state or VPN-private peer/key state. This is useful rollback evidence, not
A14, A15, or acceptance evidence. A container on an Ubuntu runner does not supply the required
Debian-host kernel evidence, and a privileged container would test a different privilege boundary.
The gate executes a private, owner-only copy of the fixed-target build artifact.

The earlier `just test-netns-permanent-neighbour-proof`,
`just test-netns-counted-forward-policy-proof`,
`just test-netns-ipv4-forwarding-runtime-proof`,
`just test-netns-forward-policy-teardown-proof`,
`just test-netns-endpoint-route-teardown-proof`,
`just test-netns-link-activation-teardown-proof`,
`just test-netns-ipv4-address-rollback-proof`,
`just test-netns-veth-rollback-proof`, `just test-netns-live-nsfs-proof`,
`just test-netns-authorized-private-run-proof`, and `just test-netns-bootstrap-ready-proof` recipes
remain compatibility entry points, but the command above is the canonical name for the deepest
currently implemented proof. A successful gate still expects the runner's honest
`BlockedAfterFixedIcmpEchoTeardown` result and exit status 77: the fixed echo and rollback are
proved, but no lifecycle `TOPOLOGY_READY`, A14, A15, or acceptance result is emitted.

The runner retains exact-child and namespace-FD ownership through a bounded synchronous reap
attempt. Normal reaping retains the pidfd and exact `Child` ownership; every forced `SIGKILL` after
admission targets that pidfd, including timeout and fallback-reaper paths. Pidfd acquisition is
mandatory; if it fails, the private channels close, `SIGKILL` is attempted against the still-owned
unreaped child, and that child is synchronously waited/reaped before the pidfd error returns. The
public `--run` entry requires exactly one initial task, and any non-default `SIGCHLD` handler or
`SA_NOCLDWAIT` is rejected before any channel, permit, reaper thread, or child is created. If a
later synchronous reap attempt cannot complete, ownership transfers to a process-local fallback
reaper instead of being silently detached; that rare fallback is not claimed as post-exit cleanup
or A14 evidence. The current positive `--run` path requires post-`GO` EOF to classify as
`CleanupRequired`, proves repeated exact PID-1 and outer-launcher reaping plus unchanged outer
namespace, mount-table, canonical link/address/route/rule/nexthop/qdisc, IPv4 `ip_forward`, IPv6
`all/default` forwarding, and resolver-file observations, and honestly returns
`BlockedAfterFixedIcmpEchoTeardown`/77. That outcome additionally proves the complete
private-mount barrier, exact RTNL state, descriptor-pinned IPv4-forwarding baseline, zero nftables
tables bracketed by unchanged generation 1, one real pinned `BOOTSTRAP_READY`, canonical `GO`,
affine `MutationAuthorization`, the descriptor-relative root/slot transaction, two live pristine
nsfs pins, and two exactly proven down-veth pairs, each created through one atomic `RTM_NEWLINK`
request. It also proves the four fixed `/30` addresses and exactly four kernel-created local-table
`/32` routes while every veth end remains down, the all-addrgen-NONE barrier, the atomic exact
generation-2 counted parent-FORWARD policy installed before activation, exact carrier-up activation
and
kernel-owned qdisc/route side effects, both exact static endpoint routes and their strict parent/A/B
observation, exactly four affine permanent IPv4 neighbours installed parent A/B then endpoint A/B,
their semantic proof with zero probes and zero proxy neighbours, one no-retry 40-byte raw ICMPv4
request from endpoint A and one exact 60-byte reply bound to the full canonical run ID, two identical
post-socket-close counter observations at request/reply/drop `1/60`, `1/60`, `0/0`, and exact
one-RX/one-TX plus 74-byte RX/TX telemetry on every veth end. It further proves explicit reverse
neighbour removal endpoint B/A then parent B/A back to the exact routed state without changing that
telemetry, a final exact counter-profile reproof, conversion to counter-agnostic cleanup authority,
direct veth B/A deletion, and parent/endpoint restoration
under generation 2 after exact restoration of the retained parent `ip_forward` record, handle-only
policy deletion, semantic-empty generation 3, final
parent/endpoint reproof before route/address/pair owner retirement, and the nsfs ordinary reverse
unmount, internal `MUTATION_ROLLBACK_COMPLETE` checkpoint, independent empty-`/run` verification,
and fixed pidfd-to-PID1-signalfd TERM observation described above. It conditionally writes only the
disposable parent namespace's fixed forwarding record, restores that exact original record, leaves
the outer host setting byte-identical, and creates no manifest. This proves the one fixed run-bound
echo and its joined reply/counter/link evidence. It does not prove packet absence, packet-capture
privacy, a general VPN datapath, an ownership manifest, topology readiness, `TOPOLOGY_READY`,
forced-crash cleanup, A14, A15, or acceptance evidence. At supervised IPC
boundaries, managed
outer HUP/INT/TERM events take
priority over pending protocol records and trigger bounded exact-launcher containment. The live
gate does not yet prove external-signal handling throughout every reap/report phase, a forced
parent-death/crash chain, a general descendant reaper, or A14 cleanup. Command/environment shims
prove that the runner invokes no namespace or networking utility. It still has no general
root-filesystem or supplementary-group isolation, `TOPOLOGY_READY`, `STOP`, `FINISHED`, configured
dataplane-topology mutation, crash-cleanup evidence, acceptance report, or A01-A15 result.
`BOOTSTRAP_READY` remains readiness evidence; this `GO` authorizes only the bounded private-root,
two-pin, two-veth, four-address, exact counted forward-policy, conditional forwarding enable/restore,
link-activation, endpoint-route, permanent-neighbour, fixed-ICMP, and policy teardown transaction, and the
rollback checkpoint is not A14 cleanup or acceptance evidence.
The dedicated-host proof also does not claim hostile same-UID sender provenance from the
`signalfd_siginfo` metadata; it proves that the retained pidfd send is followed by the exact
quiescent TERM observation within this fixed supervisor.

Privileged topology execution stays blocked until that fixed reviewed supervisor additionally owns
lifecycle setup and evidence finalization, complete process-tree containment, network-object
ownership, and teardown as one operation.
It may not accept a caller-selected command, executable, backend, timeout, cleanup prefix, or
network-object name.

Run-scoped names derive from one 128-bit lowercase hexadecimal run ID. The production ownership and
namespace modules and the `PristineRun`, `AuthorizedPrivateRun`, `AuthorizedNamespacePins`,
`AuthorizedVethPairs`, `AuthorizedIpv4Addresses`, `AuthorizedIpv4AddrgenNone`,
`AuthorizedActivatedTopology`, `AuthorizedEndpointRoutes`, `AuthorizedPermanentNeighbours`, and
`AuthorizedDeletedTopology` typestates are active in the runner.
Separate affine forwarding authorities distinguish the original, enabled, exactly restored, and
indeterminate record states; lower-owner retirement and policy deletion cannot cross an enabled or
unclassified forwarding state.
After consuming
`MutationAuthorization`, it uses only the retained private-`/run` descriptor to create the fixed
mode-0700 roots `/run/netns` and `/run/volparossa-netns-runner/<run_id>` plus exactly two
run-derived mode-0000 empty slots. It retains and rechecks their identities and exact entry sets.
A provisional containment guard exists immediately after every exclusive creation. In the fixed
one-PID-1-task, trusted-launcher model, an inotify witness rejects delete, move, and recreate
activity across the inherently non-atomic `mkdirat`-to-open handoff. A retained descriptor plus
that exact handoff observation permits only a scoped cleanup attempt; immediately before unlink,
the guard revalidates the descriptor, path, parent, and object shape. If the new directory cannot
be pinned unambiguously, the runner leaves the name untouched, fails closed, and
relies on destruction of its disposable mount namespace rather than risking deletion of a
replacement. Only a fully pinned and journalled layout can advance to the namespace transition.
That transition publishes exactly two live nsfs pins, visits each through its visible read-only
descriptor, creates and proves exactly two fixed down-veth pairs, installs and proves the four fixed
IPv4 addresses and their four kernel-created local-table routes while every end remains down,
proves the all-NONE barrier, installs the exact generation-2 policy, conditionally establishes
parent-namespace IPv4 forwarding, and proves the carrier-up
barrier plus both endpoint routes with exact qdisc/route side effects. It installs and semantically
proves the four exact permanent neighbours, performs and proves the sole run-bound ICMPv4 echo,
joins the exact reply to matching `1/60`, `1/60`, `0/0` counters and four-veth 74-byte telemetry,
then explicitly removes the neighbours in reverse back to the routed barrier without changing that
telemetry. After one final counter-profile reproof it downgrades policy authority and directly
deletes veth B then A. It restores the exact original forwarding
record, proves all three network namespaces pristine
for the enumerated restored phase under generation 2, deletes the policy by its observed handle,
proves semantic-empty generation 3, repeats the final network proof, retires the
lower owners, and ordinarily unmounts nsfs B then A,
and proves its exact mountinfo baseline before the success path reverses slot B, slot A, the per-run
directory, the workspace root, and the netns root, including directory `fsync`. Inotify and
compare-before-unlink
are not a race-free deletion
primitive against a hostile mapped-same-UID process with a previously opened writable directory
descriptor. That actor is explicitly outside this disposable runner's proof; a production helper
must instead provide root-owned exclusive mutation authority. This transaction neither creates
nor publishes an ownership manifest.

The future private ownership-manifest contract remains a mode-0600, owner-bound, bounded and
canonically sorted record of exact namespace names and unique nonzero device/inode pairs. Its
reader/classifier and atomic publication machine remain `cfg(test)`-only. Temporary-directory
regressions require initially empty mode-0700 roots, exact entry sets, descriptor and nonzero
`statx` mount identities, two mode-0000 empty slots, an exclusive mode-0600 `ownership.pending`,
exact bounded double readback, file sync, `RENAME_NOREPLACE`, directory sync, and an immediate
manifest pin. Failure injection at every modeled stage/publication boundary exercises reverse,
identity-scoped unlink of only the synthetic regular files created by that invocation.
`tests/netns/test-lifecycle-contract.sh` exercises the manifest decision logic without creating a
namespace or invoking a networking command.

Those publication tests deliberately use synthetic device/inode records and one tempfile actor;
they do not prove a live namespace, hostile same-UID concurrency safety, safe production namespace
teardown, topology/probe readiness, cleanup, A14, or A15. Separately, the runtime transaction
proves its own two transient live nsfs pins, two fixed veth pairs, four fixed IPv4 addresses,
their exact active qdisc/route side effects, four exact affine permanent neighbours with explicit
reverse removal, one exact fixed run-bound ICMPv4 echo with joined reply/counter/link evidence, one
generation-2 parent-FORWARD policy that transitions affinely from exact-zero authority through the
exact `1/60`, `1/60`, `0/0` profile to counter-agnostic cleanup authority,
conditional enable/restore of the fixed parent `ip_forward` record, and
deletion-only link teardown plus handle-only policy retirement with pre-retirement pristine and
semantic-empty generation-3 proofs inside the fixed one-PID-1-task, trusted-launcher model, but
production still has no manifest writer or configured topology lifecycle. The unmount target is
retained parent at `/proc/thread-self/fd/<fd>/<leaf>` and is identity-checked before unmount; the
intervening lookup is
not a race-free primitive against an excluded hostile mapped-same-UID actor. A production helper
must provide root-owned exclusive mutation authority and retain rollback authority across any
future ownership-manifest integration.

The V1 lifecycle specification digest also pins the two namespace and underlay-interface name
formulas, two isolated `/30` networks, two exact host routes, absence of default routes and host
links, namespace-local forwarding, an nftables forward policy of drop, the exact counted IPv4 ICMP
request/reply tuples needed by the one-shot probe, and the unconditional counted terminal drop.
Changing that topology requires an explicit
contract/digest change rather than an implicit worker variation.

## Native and performance gates

Native mqvpn/xquic runs its pinned upstream tests, warnings-as-errors build where feasible, ASan/
UBSan, and Valgrind. Interoperability fixes are patches recorded in `THIRD_PARTY_LICENSES.md`.

Benchmarks cover one/four relays; TCP/MPTCP and QUIC/MPQUIC; RTT spread, loss, jitter, capacity,
WireGuard overhead, setup/discovery/failover; CPU, memory, context switches; and net user versus
physical tunnel data. Benchmark results never substitute for functional/privacy acceptance.

The blocked preview reports are harness evidence only. They do not satisfy A01–A15, native
interoperability, fuzzing, performance, privacy, cleanup, or real-network acceptance.
