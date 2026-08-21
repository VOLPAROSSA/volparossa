# Security policy

VOLPAROSSA handles routing, cryptographic keys, policy decisions, and privileged network state.
Security reports are welcome, but this development repository is not yet suitable for protecting
real user traffic. No released version is currently designated as supported.

## Reporting a vulnerability

Use the repository host's private security-advisory feature when one is available. If the project
is mirrored somewhere without a private channel, open a minimal issue asking a maintainer to
establish private contact; do not include exploit details, identities, keys, packet captures, or
private destinations in that issue. The project has not published a separate security email or PGP
key, so documentation must not invent one.

Include, where safe:

- affected revision and Debian/kernel version;
- whether the issue crosses the agent/helper privilege boundary;
- the smallest reproducible input or namespace topology;
- expected versus observed fail-closed behaviour;
- whether secrets or forbidden destination metadata reached logs or disk;
- a suggested stable diagnostic code, if relevant.

Never test against volunteer nodes or third-party destinations without explicit permission. Use
only disposable network namespaces and test keys. Do not attach real identity stores or policy
maintainer private keys.

## Response principles

Maintainers should acknowledge privately, reproduce without changing the reporter's host network,
assess affected revisions, prepare tests and a fix, and coordinate disclosure. A security fix is not
complete until regression tests cover failure and cleanup paths. We do not promise a response SLA
while the project has no formal security team.

## Security invariants

Reports are especially important when they show any of the following:

- a normal direct client-to-exit dataplane route;
- relay Internet egress, relay host access, or cross-route forwarding;
- unsigned, expired, replayed, oversized, or version-confused control input being accepted;
- a policy, hostname, SNI, ECH, DNS, raw-IP, or destination-port fail-open;
- ordinary TCP or single-path QUIC being reported as multipath;
- helper acceptance of free-form commands, paths, interface names, or firewall expressions;
- secret keys or browsing destinations persisted or logged contrary to policy;
- crash cleanup affecting unrelated host state or leaving a leak route.

The full adversary analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
