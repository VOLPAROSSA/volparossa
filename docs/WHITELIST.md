# Threshold-signed destination whitelist

VOLPAROSSA exits are policy-enforcing proxies, never open proxies. Every enabled exit and selecting
client must validate the same canonical, versioned manifest and exact hash. Missing, expired,
ambiguous, mismatched, or insufficiently signed policy fails closed.

## Trust model

Production defaults require three unique valid Ed25519 signatures from five configured production
maintainers. Maintainer keys are trust anchors supplied with/configured by the product, not learned
from DHT popularity, bootstrap peers, or exits. Development keys are explicitly labeled and rejected
in production mode. Private maintainer keys never belong in this repository or product
configuration.

The manifest contains schema/protocol version, monotonic policy version, validity interval,
maintainer set/environment, exact domains, label-safe wildcard domains, exact IPs, exact TCP/UDP
ports, and signatures. It is canonicalized before hashing/signing. Duplicate maintainers,
signatures, destinations, or permissions are rejected.

## Matching rules

- Exact domain `example.org` matches only that normalized IDNA ASCII hostname.
- Wildcard `*.example.org` matches one or more complete labels below the suffix, not the apex and
  never a string suffix such as `badexample.org`.
- A wildcard must have a meaningful multi-label suffix; TLD-wide patterns are invalid.
- A domain rule never authorizes a raw IP, even if DNS once returned it.
- An IP rule authorizes exactly one IPv4 or IPv6 address; no implicit CIDR or adjacent addresses.
- Every permission is one exact transport and non-zero destination port.
- Redirects, destination changes, protocol changes, and new DNS answers require a fresh decision.

## Flow enforcement

The exit resolves the approved hostname through its protected DNS path, validates returned address
types, and pins selected addresses to the short-lived flow/session. TCP authorization, resolved IP,
port, policy hash, and visible TLS ClientHello SNI must agree. UDP authorization also pins the exact
destination tuple and idle timeout. QUIC/UDP 443 requires strict Initial/TLS verification of the
hostname. Shared CDN IPs do not broaden authorization to other hostnames.

ECH hides information required by v1 enforcement. When ECH or another condition makes destination
identity unverifiable, production policy rejects the flow; it does not fall back to IP-only, raw
UDP, another port, arbitrary DNS, or a direct connection.

## Distribution and activation

Nodes may advertise a policy capability key and exact version/hash so compatible exits can be found,
and signed policy bytes may be distributed through decentralized peers. Distribution does not grant
trust. Activation occurs only after canonical decoding, threshold verification against the local
trust store, environment checks, time/skew/lifetime bounds, semantic validation, and monotonic
rollback prevention.

An existing route context remains pinned to its policy/exit for established flows. Policy expiry or
replacement blocks new flows and causes bounded drain/reselection; it must not silently move an
established flow to another exit.

## Limits and diagnostics

The current policy crate bounds signed manifests to 512 KiB, bodies to 448 KiB, maintainers and
signatures to 32, destinations to 4096, permissions per destination to 64, total permissions to
16384, input domains to 1024 bytes, and canonical domain names to 253 bytes. Production defaults
also bound lifetime to seven days and accepted future clock skew to 60 seconds.

Rejections use stable reason codes. Durable logs must not include full requested hostnames, resolved
destination IPs, DNS responses, or payloads. Test fixtures may use only reserved domains/addresses.

## Operations

Validate a candidate without activating it:

```sh
volparossa policy verify /path/to/manifest
```

Inspect only public active metadata:

```sh
volparossa policy status
```

These commands are release requirements; consult [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)
before assuming they exist or enforce traffic. Required denials include unlisted domains, raw IP,
wrong port, SNI mismatch/missing SNI, ECH/unverifiable QUIC, rebinding, stale/rollback policy, and
insufficient or development signatures.
