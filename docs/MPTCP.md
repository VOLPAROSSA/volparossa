# TCP over Linux MPTCP

VOLPAROSSA does not implement multipath TCP in user space and never calls ordinary TCP “MPTCP.” The
required transport is a Linux socket explicitly created with `IPPROTO_MPTCP` (protocol 262). Failure
to create or use that protocol is fatal; there is no silent `IPPROTO_TCP` fallback.

## Data path

The client namespace transparently redirects an application TCP flow to a streaming proxy. Before
data flows, the client sends a signed, expiring `OPEN_TCP` authorization for a canonical hostname,
exact port, route context, flow, ephemeral client, and policy hash. The proxy's byte stream is
protected with TLS 1.3 from client to exit, over kernel MPTCP. The application's own TLS, if present,
remains unchanged inside that stream.

The exit verifies authorization and active policy, resolves and pins the hostname, checks that any
visible ClientHello SNI agrees, opens the approved destination socket, and streams with bounded
buffers/backpressure. It must not buffer a whole response or reinterpret application bytes.

## Path-manager backend

`MptcpPathManagerBackend` is the reusable abstraction. Debian 13's kernel generic-netlink
`mptcp_pm` family is the required default backend. It registers only selected WireGuard overlay
source addresses and bounds accepted `ADD_ADDR` and additional subflows. The Linux kernel remains
responsible for scheduling, congestion control, retransmission, reassembly, and connection state.

An mptcpd backend may be added only after a reproducible Debian 13 kernel-backend limitation is
documented. mptcpd is therefore not a default runtime dependency and must not mask a broken kernel
integration.

## Path rules

Each subflow must bind to a selected WireGuard path whose outer route contains exactly one unique
relay and the same exit. Route-policy rules prevent an MPTCP subflow from choosing the physical
interface or a direct exit route. An address is removed before its WireGuard path is destroyed.
Established flows remain pinned to the exit chosen for their context.

## Required evidence

Configuration, socket construction, a netlink encoder, or `ss` showing an MPTCP connection is not
enough. The disposable topology must prove:

- the socket protocol is MPTCP and ordinary fallback is rejected;
- at least two subflows use different relay namespaces/interfaces;
- packet/byte counters show both subflows carried real application data;
- constrained paths aggregate beyond one path where topology permits;
- killing a relay preserves the application flow on another subflow;
- captures show no direct client-exit dataplane and no relay-visible Internet destination;
- cleanup removes endpoints, interfaces, routes, rules, and namespaces without host changes.

Until acceptance checks A02–A04 pass, the MPTCP dataplane remains incomplete regardless of unit-test
coverage. See [TESTING.md](TESTING.md).
