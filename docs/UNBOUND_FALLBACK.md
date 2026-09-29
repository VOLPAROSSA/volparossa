# Exit-side Unbound fallback

The development default is now the bounded private Unbound worker. This default/package
integration is a candidate pending its source-exact installation and reciprocal-role proof;
the earlier native and cache results below retain their narrower scopes. No host DNS,
routes, firewall, resolver service or trust anchors are changed automatically.

## Private packaged worker candidate

The private mode removes the listener altogether:

```yaml
dns_cache:
  enabled: true
  upstream: null
  fallback:
    mode: unbound_private
```

This starts the fixed source-built `/usr/libexec/volparossa-dns-worker` only when
an authorized Exit lookup needs fallback. The worker communicates through
inherited pipes, retains the existing agent UID, and performs real libunbound
recursion/validation. No new UID exemption, root operation, DNS listener, helper
command or resolver service is added. Local applications cannot submit requests
to an agent-owned public DNS socket because this backend has none. Missing
binary/library/anchors, DNSSEC bogus, timeout and unavailable answers never fall
through to the OS resolver. An unconfirmed child cleanup quarantines the backend.

The core package now requires its exact-version `volparossa-private-dns-worker` companion.
That companion includes this executable and requires `libunbound8` >= 1.26.1 plus
`dns-root-data`, without a dependency back to the core or the standalone Unbound daemon.
Build the companion only in a provisioned Debian 13 environment using
`sh packaging/build-private-dns-worker-deb.sh --build`; preview is non-writing.
Building requires `libunbound-dev`, pkg-config, a C compiler and CMake.
An effective Exit using private Unbound rejects absent/unsafe worker or root-anchor files
at agent startup as `DNS_PRIVATE_WORKER_UNAVAILABLE`; no configuration parsing
performs filesystem access and no missing companion silently enables OS fallback.
All-off and local-only nodes do not require or probe the worker during inert startup.
Changing effective roles already requires restart, where the Exit asset check applies.
The worker reads only the fixed Debian root hints and trust anchor; it does not
load `resolv.conf`, `hosts`, arbitrary configuration, or private path arguments.
Updating distribution trust anchors remains an operator/package responsibility.

The new disposable package proof installs the source-built companion and stages the same
guest development binaries through the normal Debian package layout. It checks actual
roles-off startup, missing-worker rejection by the installed agent, and the ordinary
install/upgrade/remove lifecycle. A separate resolver probe inherits the shipped agent
sandbox and must perform real DNSSEC resolution; its explicit executable/one-shot fixture
deviations do not prove a full agent DNS query or a release build. Both original package
reports and the independent native resolver report are retained. Live results are pending.

Private lookups still use an unexpired, independently verified shared-proof RAM
answer first. On a miss, [bounded sequential source selection](#private-worker-unbound_private)
uses recent source timings to choose a peer attempt or private recursion within
the original five-second deadline. At most two native
children may run; the last 500 ms is reserved for exact child termination/reaping.
No successful or negative result is returned before that child's successful wait.
The native `secure` verdict alone is recorded as `PrivateUnbound { dnssec_secure }`,
not as a shareable proof or a wire AD assertion. The version-2 worker also supplies
its raw answer and related DNSKEY/DS packets to the existing independent built-in-root
verifier. Successful verification yields `UpstreamValidated`, retained under the current
policy for local reuse and existing peer proof serving. Rebinding checks, exact address
pinning and route expiry remain enforced. Each resolution has a fresh process; its native
context lives only across that lookup's bounded evidence exchanges. A persistent native
cache or a guarantee of the fastest source for every question is not claimed.

See [the native boundary and versioned pipe protocol](../native/volparossa-dns-worker/README.md)
and [opt-in configuration](../config/examples/unbound-private-exit.yaml).
Native compilation against the hash-checked Debian library passes. Nine focused
version-2 protocol, independent-proof, source-choice and owned inert-process checks
pass. They include seeded proof collection without a repeated address lookup, rejection
of forged signatures despite AD, and child cleanup after cancellation/timeout. These
local checks do not prove the new native proof-cache path in a real deployment.
All 19 focused DNS tests, strict UDP all-target/all-feature Clippy, formatting and
four version-2 guest-report checks also pass.
Those earlier local checks do not by themselves prove the new packaged default.

### Cache selection and configuration migration

`dns_cache.enabled: false` disables proof retention, local proof reuse, peer lookup,
peer proof serving and publication. It does **not** disable the selected resolver or
silently switch it to the OS. Private Unbound then performs only the primary validated
lookup, with the same deadline and child cleanup, without collecting extra shared proof.

An explicit `fallback: { mode: system }` remains an opt-out. Existing custom `upstream`
configurations now require that explicit mode; an ambiguous custom upstream with the
private default fails configuration validation with a migration hint. Operator-owned
configuration files are not silently rewritten. Four configuration checks, three agent
startup-selection checks and three cache-disabled resolver checks pass locally.

## Opt in only to an already-protected endpoint

```yaml
dns_cache:
  enabled: true
  upstream: null
  fallback:
    mode: unbound
    endpoint: "127.0.0.1:5335"
```

The endpoint must be loopback, above port 1024, in the agent's network namespace. A separate
`upstream` is rejected in this mode. The example is also available as
[`config/examples/unbound-exit.yaml`](../config/examples/unbound-exit.yaml).
Configuration validation does not prove that a listener exists or that it is Unbound. This is
an explicitly operator-trusted service, not an authenticated remote resolver discovery mechanism.

The same resolver serves the Exit's protected DNS, TCP hostname lookup and UDP/MPQUIC address
pinning. Clients still send policy-authorized queries through their protected one-relay route;
they do not invoke this fallback locally. Route relays remain excluded from peer DNS requests.
Cache-serving peers remain cache-only: a peer miss does not trigger their own recursion.

## Lookup and provenance

### Explicit loopback endpoint (`unbound`)

This existing mode retains its fixed bounded order:

1. Unexpired, independently verified RAM answer under the current policy.
2. Independently verified peer proof, with the existing 500 ms peer budget.
3. Positive DNSSEC-proof collection from the configured Unbound endpoint, at most 3 seconds.
4. A bounded TCP DNS query to that **same** endpoint, using the remainder of the common 5-second deadline.

Only the independent built-in-root verifier can put an answer into the shared proof cache.
Unbound's AD flag is recorded as `TrustedUnbound { authenticated_data }`, not relabelled as
independent DNSSEC evidence. Unsigned answers and supported CNAME chains may be used as trusted
local fallback results, but are not advertised or shared. The existing aggregate fallback counter
includes these responses without retaining names, addresses or query history.

The fallback sends checking-enabled requests. SERVFAIL, including DNSSEC validation failure,
malformed/truncated responses, timeout and unavailable service fail closed: **no OS fallback**.
NXDOMAIN and family-specific NODATA become correlated negative replies in protected DNS; no
negative proof, SOA lifetime or AD flag is invented. Other egress consumers fail when no permitted
address exists. CNAME chains are bounded to eight aliases; a positive response uses the lowest
actual CNAME/address TTL. Public-address filtering and exact destination pinning still apply.

### Private worker (`unbound_private`)

The independently verified RAM proof cache remains first. On a miss, the private
mode keeps just two aggregate moving-average durations and two scheduling
deadlines in RAM: no additional names, addresses, policy or peer identifiers, and
no persistent timing history. A recently faster validated peer is preferred;
otherwise private Unbound starts immediately. The timings include complete peer
fetch/independent validation/retention, or native worker execution and reaping.

A cold peer attempt gets 50 ms. With a measured Unbound duration, the peer budget
is that duration minus a small margin, bounded to 20–500 ms and the original
resolution deadline. A miss, invalid proof or timeout triggers a 30-second peer
cooldown and then private fallback. Occasional alternate-source comparisons use
one actual authorized request, at most once per 30 seconds; they are not background
queries or a race of simultaneous sources. A peer attempt is ended or dropped
before the fallback worker is polled. This selects from recent observations, not
knowledge of which source will be fastest for every individual question.

Every peer attempt still requires complete route-peer exclusions and the current
policy scope. DNSSEC validation, immutable proof/first-seen TTL bounds and address
pinning are unchanged. A private worker now seeds the independent proof collector
with the original raw address answer and retains one native context for the related
DNSKEY/DS requests. Raw messages are bounded to 4 KiB and 32 exchanges; no unrelated
address query, extra worker, listener or deadline is introduced. Query-start timestamps
conservatively bound TTLs. Only the independently verified result becomes shareable;
unsigned or unsupported answers retain their non-shareable native provenance. Neither
a fast answer nor the native secure verdict substitutes for a transferable proof.
The original five-second deadline, 500 ms cleanup reserve, two-worker limit,
quarantine and prohibition of OS fallback remain intact.

The focused sequential-choice test and strict UDP all-target/all-feature Clippy
pass. The controlled test covers peer timeout/drop before fallback, bypass during
cooldown, a later successful peer probe without a worker, and exclusion-scope
enforcement. It is not recursive DNS or a live-network speed comparison; the
separate guest preflight below retains its own evidence boundary.

## Unbound operating requirements

Choose explicitly between direct recursion and forwarding. With direct recursion, omit a root
`forward-zone`; with forwarding, name the operator's trusted forwarder and keep
`forward-first: no` so failure does not silently switch to recursion. For TLS forwarding, use
certificate validation and an authentication name. See the official
[Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#forward-zone-options).

For a provisioned instance, preserve DNSSEC validation and its managed root anchor; use
`val-permissive-mode: no`, `cache-min-ttl: 0`, and `serve-expired: no`. These prevent accepting
bogus data or deliberately extending ordinary cache lifetimes. Keep query/reply/validation logs
off, verbosity at 0, and do not enable dnstap, persistent cachedb, or EDNS client-subnet sharing.
Bound memory/query concurrency and retain QNAME minimisation. These settings are documented in
the [Debian 13 Unbound manual](https://manpages.debian.org/trixie/unbound/unbound.conf.5.en.html);
trust-anchor setup is described in the [official setup guide](https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/configuration.html#set-up-trust-anchor-enable-dnssec).

**Loopback is not sufficient isolation.** Existing Client ingress exempts the permanent agent
UID, not an arbitrary `unbound` account. A stock daemon under another UID may have its own
recursion captured by the node's Client route. Conversely, simply moving it to the exempt UID
and exposing a loopback listener could give local applications an unprotected DNS escape.
This change adds neither exemption nor firewall bypass. An operator must supply the protected
Exit-side service boundary before using this option on a reciprocal node.

The intended packaged default requires the private worker above to pass a
simultaneous Client+Exit datapath proof. Until then the default stays `system`.
No `resolv.conf` replacement, systemd-resolved change, or automatic package/service activation is
part of this feature.

## Evidence boundary

The existing `dns-cache` KVM scenario now also invokes a separate
`private-unbound-proof` preflight. It source-builds the real worker inside the
disposable Debian 13 guest against the exact SHA-checked Debian packages recorded
in `THIRD_PARTY_LICENSES.md`. A public Rust `ExitResolver` example checks actual
native verdicts for `iana.org`, `neverssl.com` (only passes if actually unsigned)
and the deliberately broken `dnssec-failed.org` test described by
[ICANN](https://www.icann.org/dns-resolvers-checking-current-trust-anchors).
No alternative trust anchor, forged secure verdict or fixed positive reply is
used. A private guest mount namespace supplies an OS-positive `/etc/hosts`
sentinel: private bogus/timeout must fail despite that tempting fallback.
An observer stops only the probe's own native child via pidfd and checks exact
PID/start disappearance while the caller remains alive, for both timeout and
caller cancellation. The extra report retains worker/anchor digests and the
actual package version. Dependency or public-DNS availability failure fails the
preflight; it is not a skipped PASS.

`private-unbound-proof.json` is **additional**, not a replacement for existing
C05 protected peer/cache evidence. It explicitly sets
`normal_client_route_proven` and `reciprocal_client_exit_proven` to false. The version-2
candidate additionally requires a genuine native signed lookup to produce independent
shareable proof and a subsequent local-cache answer. This is still distinct from a
live peer receiving that proof; a passing new guest artifact is required.
Only the disposable VM installs these dependencies or performs the live queries.

The [first live run on `9aa777fd`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36594857358)
**failed**, with all 137 original exported files retained. Its native worker actually resolves
the signed test name with `dnssec_secure=true` (3,601 ms, TTL 3,595 s) and the unsigned test
name with `dnssec_secure=false` (3,624 ms, TTL 56 s), despite the OS-positive sentinel.
The bogus case produces `PROBE_BOGUS_NO_RESULT`; its typed Rust failure was not retained, so
timeout versus another failure is not established. Native timeout/cancel cases were not reached.
The original C05 phase separately obtains one independently validated upstream answer, then
fails `DNS_CACHE_CAPTURE_INCOMPLETE`; this is not completed peer/local-cache evidence.
Its packet observers failed with a `frame` keyword mismatch at the shared capture adapter;
the candidate fixes that interface and passes five focused DNS capture/report checks.
The original failed artifact is unchanged, and that fix alone proves no live C05 result.
Guest hosts and final host-state bytes remain unchanged, and topology cleanup completes.
Original ZIP SHA-256: `10e197cc29b4598a90962e92026f2fbd24c075833e2b223b1238840a282921e7`.
These partial observations are real resolver evidence, not a passing full fallback/deployment proof.

The [version-2 run on `6aaa5c95`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36598970370)
also **fails overall**. Its separate protected DNS-cache report now passes: real A/AAAA
upstream validation, peer retrieval, local reuse and unsigned fallback, with drained privacy
captures, complete cleanup and unchanged guest host state. The exact-source report checker
and a rebuild from the original raw evidence both pass. This does not prove Unbound supplied
those shared packets: that existing C05 fixture uses its separately verified upstream.

The native preflight returns an unsigned answer in 2,192 ms and proves exact native-child
reaping on timeout (4,501 ms) and caller cancellation (1,502 ms), while the caller remains
alive. Its signed and deliberately bogus questions instead return `Unavailable` at 4,502 ms
and 4,501 ms. Neither a validated signed answer nor a native `Bogus` verdict was obtained;
these deadline results are not relabelled as those missing proofs. The raw worker response
and recursive packet progress were not retained, so the particular upstream delay is unknown.
The original 276-file artifact remains unchanged (ZIP SHA-256
`dac9505dd913fbeac4f30ca15a6772e4504cc94e0a24fc3068d4de16073d45b1`).
Native proof-cache linkage and simultaneous reciprocal deployment remain incomplete;
the default is still `system`.
The follow-up preflight retains all five original gates. Only after a signed or bogus case
returns `Unavailable`, it may run one separate 30-second native timing diagnostic per failed
case. These fixed-question guest-only observations retain no raw packet or log, have their
own bounded child cleanup, and explicitly cannot count as acceptance or extend the normal
five-second resolution budget. Six focused report/protocol checks pass; timing results are
recorded below.

The [diagnostic run on `84be45ac`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36602822670)
still **fails overall**, but now proves the signed private-worker-to-local-cache linkage:
the native lookup returns in 3,297 ms, the original answer validates independently against
the built-in roots, and policy-bound local reuse does not extend its TTL. The unsigned answer
returns in 3,611 ms, remains unshared, and timeout/cancel reaping passes again. The deliberately
bogus name instead returns `Unavailable` at 4,502 ms. Its separate fresh native diagnostic
also produces no complete reply within 30,032 ms and is killed/reaped; extending the caller's
budget is therefore not a demonstrated fix. No actual native `Bogus` verdict is claimed.
The separate protected C05 report passes again but uses its own upstream, not these native
answers. Guest hosts, topology cleanup and byte-identical guest-parent network snapshots pass.
The original 298-file artifact is unchanged, ZIP SHA-256
`b568467b21f7644a17c1f713f1782316a6ccf744ff03a77dafa82cde416031ff`.
Native-to-peer distribution and reciprocal deployment remain unproved; `system` remains the
default pending those integration steps.

The next private-DNS VM fixture also checks the runner's IPv6 address/route information
without sending packets. Only an explicit kernel `ENETUNREACH` for the fixed root selector
disables IPv6 on QEMU's outer user network; unknown observations stop before VM launch.
A present route keeps that option enabled but does not establish Internet reachability.
The bounded, sanitized decision is retained as `qemu-outer-uplink.json`. Other scenarios,
product IPv6, internal WireGuard paths and all acceptance gates remain unchanged. Five pure
decision checks pass. This fixture candidate is not evidence of the original runner's
IPv6 state or a demonstrated correction of the signed/bogus failures.

The [IPv6-observed run on `4930f8e9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36605711028)
now **passes all five native preflight cases** with the exact same native worker hash as
`84be45ac`: signed recursion plus independent proof/local reuse in 1,436 ms, unsigned recursion
in 440 ms, a real `Bogus` verdict in 937 ms, timeout reaping in 4,501 ms and caller-cancel
reaping in 1,503 ms. The runner actually reports no IPv6 route to the fixed root selector,
so only QEMU outer IPv6 is disabled; product and internal-overlay IPv6 are unchanged.
The exact-source native report checker passes and no extended diagnostic is needed.
This supports the outer-uplink explanation without changing validation or resolution budgets.

The workflow still **fails overall**, now in the separate protected C05 phase at
`dns-cache-warm-a-aaaa` / `DNS_CACHE_NORMAL_ROUTE_UNAVAILABLE`. That route failure is not
relabelled as a native validation failure or a successful combined deployment. The original
167-file artifact is retained, ZIP SHA-256
`52cab14a548df4c1ca48405a4cbd8ba6ddf2494efbf6022fc259922f3c0d82ba`.
Cleanup completes and guest-parent snapshots are byte-identical.

The new `reciprocity-private-dns` scenario is an executable candidate, not a live PASS.
It retains the same four all-role agents and concurrent native UDP flows from the reciprocal
fixture, then requires an ordinary protected application lookup to use the actually selected
Exit's private worker and a second lookup to reuse independently validated local proof.
Four owned guest-only TAPs supply independent DNS uplinks; DROP-only containment prevents
fixture addresses or forwarded sessions from escaping over those TAPs. It adds no product
firewall exemption and changes neither the developer host nor the VM parent's networking.
Separate drained packet captures, exact worker ownership, original UDP lifetimes, TAP/process
cleanup and unchanged host state remain mandatory. Five focused inert fixture tests and the
static wrapper contract pass; no real reciprocal private-DNS result is claimed yet.

Its [first live run on `4930f8e9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36605721961)
fails during topology setup, before any reciprocal DNS lookup: the owned slirp uplink reports
`cannot pivot_root to /tmp` / `create_sandbox failed`. Sandbox and seccomp are not disabled
to bypass this result. Original 16-file artifact ZIP SHA-256:
`74796b2199c6f7cf767c8f412a61cc789cf35578444a11c2948d03e0af3c030d`.
The uplink/topology cleanup and unchanged guest-parent state pass; the deployment gate stays open.

The [mount-isolated run on `71d0567d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36609662468)
gets all four sandboxed uplinks and concurrent native UDP contexts running, but still **fails**
with `PRIVATE_DNS_SUBPROCESS_TIMEOUT`. The fixture's first protected-DNS connect command hits
its 20-second subprocess limit while admission reports the preselection owner busy; the Client
then reports `CONNECT_DNS_ROUTE_READY` just after that boundary. No application DNS question
or private resolver child is observed in this run. This is not proof of reciprocal DNS reuse.
The candidate gives only that ordinary connect operation its existing 75-second caller budget;
it does not extend the product's signed flow lifetime or count an expired UDP window as passing.
The complete 147-file original artifact is retained, ZIP SHA-256
`c1b5f3f0a692b4ef32d4bc5dca052e60c746eecb3f2c185126197c0a63b6017c`.
Uplink/topology cleanup passes with zero leftovers and byte-identical host snapshots.

The [bounded-reuse run on `859c9e90`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36613320245)
**passes the complete C05 workflow**, including both unchanged exact-source report checkers.
All five native private-Unbound cases pass: independently validated signed recursion/local
reuse (673 ms), unsigned recursion (821 ms), a real Bogus verdict (2,312 ms), timeout reaping
(4,500 ms) and cancellation reaping (1,503 ms). The separate protected-network phases prove
A/AAAA delivery on the same actual application socket and route, independently verified
proof fetched by a different Exit, non-shareable unsigned fallback, and local reuse after
the original proof-serving Exit is actually stopped. Group retirement, capture completeness,
privacy checks, zero owned leftovers and byte-identical host state all pass. The 275-file
original artifact is retained, ZIP SHA-256
`389b25478906eb89a058359b01a8fe09f9637c59797bd8022c396be28d710111`.
The C05 peer proof and live native-worker preflight are separate checks, not one claim that
every production reciprocal deployment is now ready. That run did not switch the default;
the current default/package candidate is described above.

The [reciprocal run on the same source](https://github.com/VOLPAROSSA/volparossa/actions/runs/36613323557)
still **fails**. Its real protected warm lookup takes 1,610 ms through the selected Exit's
unprivileged private worker; the same socket's local-cache repeat takes 3 ms, with no new
worker, exact upstream/local metric increments and cumulative response bytes 42 then 84.
It subsequently times out while reading route status during idle cleanup. Additionally,
the preserved Exit captures contain two unparsed TAP frames in the warm phase and one
unrecognized mDNS source in the local phase. Three incoming DNS response packets, but no
outgoing DNS requests, also cross the local-phase boundary; their individual provenance is
not proved. These capture errors are not silently accepted as a privacy PASS. Some completed
pre-cleanup observations were not checkpointed in the failed report and are not invented.
All four original echo applications report success; final fixture cleanup and host-state
comparison pass, but the complete combined gate remains open. Original 169-file artifact
ZIP SHA-256: `a27b2a97d4b04ff501b85852069bdad26c0340c4779f7fc74efb54b2e06b734b`.

The [next reciprocal run on `383b8117`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36617479438)
also remains **failed**, now at capture validation. Its checkpoints retain an 819-ms genuine
private-Unbound answer and a 25-ms same-socket local-cache answer, one original worker/no new
worker, unchanged four-node agent identities and UDP contexts, and a post-DNS echo on each
original flow. Natural retirement is observed through 404 completed status reads, no status
timeouts and eventual absence of the owned DNS context; final phase retirement fields were
not serialized before validation failed and are not fabricated. Seven captures have no
malformed/forbidden packets; the warm Exit capture rejects one ARP reply from the exact
private gateway to its TAP with `tap_arp_shape`. Its length/raw bytes were not exported, so
the precise length/padding cause cannot be read back from that artifact. Final cleanup and
unchanged host state pass. All 169 originals are retained (ZIP SHA-256
`8b57f4e81b79ff6b9b2de23a3ad8c31f2d09a92f04d00d36b92477e1a741891f`).

The current capture candidate admits the exact 64-byte, zero-padded gateway ARP reply
emitted by the pinned Debian libslirp implementation, retaining the exact TAP, endpoint,
hardware/protocol and MAC bindings. It does not relax IP/DNS capture rules. Six targeted
capture checks and nineteen shared capture checks pass. The older frame's length was not
retained, so identifying that historical failure as this specific padding case remains an
inference; a new source-exact reciprocal run is still required.

### Bounded protected DNS connection reuse

The Client can now keep a successful UDP DNS association for subsequent questions about
the **same canonical name**, from the same application source and original resolver tuple,
under the same policy and selected Relay/Exit. For example, A and AAAA need not create two
separate routes. Only one question is outstanding; responses must match its transaction ID
and complete question. Name, application, resolver or policy changes require a new ordinary
route. TCP DNS retains its one-shot behavior.

Reuse never refreshes signed authorization: the original expiry, a 30-second idle bound and
a maximum of 16 sequential questions all apply. The Client owns idle retirement even without
another application request. The Exit also accepts only bounded questions for the original
signed name, and invalid correlation or resolution fails closed. No browsing history is stored.

Three targeted Rust checks cover A/AAAA correlation, changed owners/policy and unextended
expiry/request limits. The C05 fixture now keeps a real application socket open for each
A/AAAA pair and observes actual cumulative bytes on that same route, with separate captures
and source counters. Explicit retirement still separates Exit changes and the offline-cache
phase. The source-exact C05 run at `859c9e90` above now passes this sequence; the original
failed route-selection runs remain failed.

The reciprocal fixture likewise keeps one real UDP socket for its warm A lookup and
subsequent A cache hit. PID, socket cookie, source port, sequence and cumulative route
bytes must agree across separate capture/metric phases. Both answers and the unchanged
four-node agent/UDP-context snapshots must precede an actual final echo on every original
flow. One natural 30-second DNS-association retirement is then observed outside that
concurrent window, without extending signed authorization or disconnecting the other flow.

The next reciprocal candidate moves remote/helper retirement confirmation outside the
route-state mutex. Status remains responsive while the exact cleanup owner is retained;
only that owner's confirmed success can publish Idle. The original cleanup deadline is
unchanged. Fixture checkpoints now retain completed observations before a later failure,
and a timed-out status read remains unknown rather than proving route absence. Capture
decoding admits only canonical ARP between this fixture's exact private TAP endpoints on
that TAP, and preserves the existing Exit mDNS aliases. Locally observed inbound recursive
responses remain counted as unattributed residual packets: a cache-hit phase must still
have zero outgoing recursive queries, an exact local-cache counter increment and no new
native worker. These source fixes do not retrospectively identify the rejected packets or
the exact retirement owner in the failed `859c9e90` run.

The new responsiveness test and four existing disconnect/cancellation/quarantine checks
pass, as do strict agent Clippy, formatting, eleven reciprocal-fixture checks (the
separate privileged mount probe is opt-in), four exact-TAP capture checks and nineteen
shared-capture regressions. They establish the local correction, not a completed new
four-role live acceptance run.

Focused tests cover configuration rejection, bounded CNAME/TTL/provenance parsing, malformed and
negative responses, rebinding rejection, and an actual framed TCP backend in a disposable test
namespace. That backend uses controlled DNS responses, **not an executed Unbound daemon**.
On 2026-09-29, both configuration tests and all ten focused DNS tests pass, including the
isolated TCP exchange. Strict Clippy passes for the affected config, UDP and agent crates
with all targets/features. Reproduce with `cargo test -p volparossa-config -p volparossa-udp
--lib dns`; this does not install Unbound or change the host resolver.
Those focused checks alone do not prove deployed Unbound validation, private listener
ownership, reciprocal-role routing, fastest-source choice, or the complete fallback feature.

The genuine-Unbound signed/unsigned/bogus and timeout/cancellation preflight plus protected
C05 cache sequence now have the separate live evidence above. The combined four-role private
Unbound route, remaining CNAME/NXDOMAIN/expiry cases and fastest-source selection still need
their relevant evidence. The full fallback request remains incomplete; the default backend
has not been switched on the strength of these partial results.
