# Exit-side Unbound fallback

When a permitted DNS answer is not available from a valid network cache, the selected
**Exit** must still resolve the name. Unbound provides that fallback. It does not move
DNS resolution back onto the client's ordinary Internet connection or turn cache peers
into public recursive resolvers.

The development default in this source is **`unbound_private`**: a short-lived,
Exit-owned worker with private pipes and no DNS listener. This is defined by
[the configuration default](../../crates/volparossa-config/src/dns_cache.rs) and selected by
[the agent's resolver setup](../../crates/volparossa-agent/src/dns_fallback.rs).
Choosing a default does not enable participation. No host DNS, routes, firewall,
resolver service or trust anchors are changed automatically.

## Resolver choices

| Mode | Where a cache miss is resolved | What the operator must know |
| --- | --- | --- |
| `unbound_private` — default | Packaged worker using libunbound, owned by the Exit agent | An enabled Exit requires the worker and trust-anchor assets. No DNS listener is opened. |
| `unbound` — explicit choice | An operator-provisioned Unbound endpoint on a high loopback port | The endpoint needs real isolation; loopback alone is not access control. |
| `system` — explicit opt-out | The existing operating-system resolver backend | This is a deliberate configuration choice, never an automatic fallback after Unbound fails. |

Caching and fallback are separate choices. Setting `dns_cache.enabled: false` disables
proof retention and peer sharing, **not** the selected resolver. Custom `upstream`
configuration requires explicit `system` mode; it cannot silently replace private Unbound.

## How resolution works

1. The client sends a policy-authorized question through its protected relay/exit route.
2. The Exit first reuses an unexpired, independently verified local proof if one exists.
3. On a miss, it uses a bounded peer attempt or the selected fallback. Private mode
   chooses their order from recent timings; it does not promise the fastest source for
   every question.
4. The answer is checked and tied to the permitted destination. Only independently
   verified DNSSEC proof can enter the shared cache. A native “secure” verdict or an
   endpoint's AD flag alone is not a transferable proof.
5. Expired, invalid or unavailable results are not repaired by silently switching to the
   OS resolver. Owned native workers must be stopped and reaped before cleanup succeeds.

A peer serves only proof it already has: a peer-cache miss does not start recursion there.
Unsigned answers may be usable under the selected trusted fallback, but they are not
promoted into independently verified shared answers.

## Evidence boundary

Retained source-bound results establish different parts of the implementation:

- [Reciprocal private resolution and local reuse](#reciprocal-private-resolution-and-local-reuse-pass):
  the scoped `c2e21c6c` trial exercises a real protected lookup while the four participating
  agents retain their existing flows. Its complete receipt is in the archive.
- [Development-package and cache integration](#complete-development-package-and-cache-pass):
  `138787d1`, run [36719475479](https://github.com/VOLPAROSSA/volparossa/actions/runs/36719475479),
  passes the protected cache sequence, five native Unbound cases, installed resolver
  sandbox and package install/upgrade/remove lifecycle. The separate `c5ac8331` repeat
  includes the MPTCP-refill composition; PR169 merged as `3d9b0d6fc618`.

Neither result proves a release build, every later combined revision, a full installed-agent
DNS-query path or globally fastest source selection. Follow
[the DNS integration checkpoint](../IMPLEMENTATION_STATUS.md#latest-dns-integration-checkpoint)
for remaining integration work. Earlier failures stay failed in the
[retained history](#retained-trials-and-development-history); their “still system” and
“not yet in main” statements apply to the revisions described there, not this source.

<a id="complete-development-package-and-cache-pass"></a>

<a id="private-packaged-worker-candidate"></a>

## Private packaged worker

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

See [the native boundary and versioned pipe protocol](../../native/volparossa-dns-worker/README.md)
and [opt-in configuration](../../config/examples/unbound-private-exit.yaml).

### Cache selection and configuration migration

`dns_cache.enabled: false` disables proof retention, local proof reuse, peer lookup,
peer proof serving and publication. It does **not** disable the selected resolver or
silently switch it to the OS. Private Unbound then performs only the primary validated
lookup, with the same deadline and child cleanup, without collecting extra shared proof.

An explicit `fallback: { mode: system }` remains an opt-out. Existing custom `upstream`
configurations now require that explicit mode; an ambiguous custom upstream with the
private default fails configuration validation with a migration hint. Operator-owned
configuration files are not silently rewritten.

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
[`config/examples/unbound-exit.yaml`](../../config/examples/unbound-exit.yaml).
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

The configured development default is `unbound_private`, not the standalone loopback
service described in this section. An effective Exit needs the packaged worker assets;
roles-off and local-only startup do not require or start that worker.

The private packaged default has the scoped simultaneous Client+Exit datapath
and development-package proofs summarized above. Explicit `mode: system` remains an opt-out.

No `resolv.conf` replacement, systemd-resolved change, or automatic package/service activation is
part of this feature.

## Retained trials and development history

<a id="early-package-and-protocol-checks"></a>
<a id="reciprocal-private-resolution-and-local-reuse-pass"></a>
<a id="integrated-repeat-after-mptcp-refill"></a>
<a id="connection-reuse-development-record"></a>

Earlier package/protocol failures, reciprocal-role proof, MPTCP-refill composition and
connection-reuse trials remain in the [development archive](../archive/network-architecture-notes-20261026.txt).
Their original run IDs, sources, hashes and limitations are retained; they are not
current configuration instructions or authorization for host DNS changes.
