# Exit-side Unbound fallback

This slice adds a bounded resolver backend, not an installed resolver service or a completed
reciprocal Client+Exit deployment. Existing configurations retain the system-resolver fallback.
No host DNS, routes, firewall, services or trust anchors are changed automatically.

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

The separate opt-in `volparossa-private-dns-worker` companion package includes
this executable and requires `libunbound8` >= 1.26.1 plus `dns-root-data`; it does
**not** require the standalone Unbound daemon. The core package and its existing
Ubuntu-hosted package-build job retain their previous dependencies. Build the
companion only in a provisioned Debian 13 environment using
`sh packaging/build-private-dns-worker-deb.sh --build`; preview is non-writing.
Building requires `libunbound-dev`, pkg-config, a C compiler and CMake.
Explicit private configuration rejects absent/unsafe worker or root-anchor files
at agent startup as `DNS_PRIVATE_WORKER_UNAVAILABLE`; no configuration parsing
performs filesystem access and no missing companion silently enables OS fallback.
The worker reads only the fixed Debian root hints and trust anchor; it does not
load `resolv.conf`, `hosts`, arbitrary configuration, or private path arguments.
Updating distribution trust anchors remains an operator/package responsibility.

Private lookup order is independently verified RAM cache → bounded peer lookup →
private recursion within the original five-second deadline. At most two native
children may run; the last 500 ms is reserved for exact child termination/reaping.
No successful or negative result is returned before that child's successful wait.
The native `secure` verdict is recorded as `PrivateUnbound { dnssec_secure }`,
not as a shareable proof or a wire AD assertion. Rebinding checks, exact address
pinning and route expiry remain enforced. Each query has a fresh process: a
persistent libunbound cache, adaptive fastest-source selection, and independent
proof extraction through the private worker are **not** claimed by this slice.

See [the native boundary and versioned pipe protocol](../native/volparossa-dns-worker/README.md)
and [opt-in configuration](../config/examples/unbound-private-exit.yaml).
Native compilation against the hash-checked Debian library passes. Three focused
protocol/real inert-process lifecycle tests and the strict private configuration
test pass, together with affected-crate all-target Clippy. They do not prove recursive DNS or a deployed
reciprocal Client+Exit path. The default stays `system` until the disposable
real-resolver/privacy/cleanup proof below passes.

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

The existing bounded order is retained:

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

This slice does not yet race a slower peer against Unbound or learn which source is fastest.
It retains existing deadlines, rather than claiming adaptive fastest-answer selection.

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

Focused tests cover configuration rejection, bounded CNAME/TTL/provenance parsing, malformed and
negative responses, rebinding rejection, and an actual framed TCP backend in a disposable test
namespace. That backend uses controlled DNS responses, **not an executed Unbound daemon**.
On 2026-09-29, both configuration tests and all ten focused DNS tests pass, including the
isolated TCP exchange. Strict Clippy passes for the affected config, UDP and agent crates
with all targets/features. Reproduce with `cargo test -p volparossa-config -p volparossa-udp
--lib dns`; this does not install Unbound or change the host resolver.
They do not prove deployed Unbound validation, private listener ownership, reciprocal-role
routing, fastest-source choice, or the complete requested fallback feature.

A subsequent disposable integration must run genuine Unbound, exercise signed/unsigned/bogus,
CNAME/NXDOMAIN/expiry cases, exclude unprotected Client queries, retain privacy captures and prove
cleanup plus unchanged host state. Documentation must retain this incomplete status until that
evidence exists.
