# Direct local links and capability-based contribution

Agreed functional-development scope, 2026-09-05. This document describes work to integrate,
not completed functionality. The initial executable target remains Debian 13 amd64.

Every consuming node contributes what its available connections can provide. A node with an
independent usable Internet uplink offers policy-limited exit service as well as relay service.
A node without one contributes direct local connectivity and forwarding; it does not invent
an Internet uplink or recursively advertise the overlay itself as independent exit capacity.
Installation remains dormant until participation is configured.

## Datapath

Direct means a local **underlay** between peers, not a Client-to-Exit bypass. Each overlay path
still has exactly one relay and a separate exit, with end-to-end protected Client--Exit payloads.
Different parallel paths use different relays. Local link-layer mesh forwarding, if used, is
not an additional decrypting VOLPAROSSA relay role. A reachable participant with actual Internet
access is still necessary to reach external Internet destinations.

The first vertical slice is an existing Ethernet/local Wi-Fi link from a client without a
default route to a contributing relay, followed by the existing authenticated route to an exit.
It must carry real application data and retain no-direct-exit and policy enforcement. Next,
multiple selected paths can bind to distinct local and Internet interfaces in the same route.
Actual radio link creation follows behind the same underlay interface rather than a separate
VPN implementation.

An authenticated on-link peer needs scoped provenance: local interface, address family,
locally observed peer address, and route ownership must agree. Private addresses are not made
globally routable by relaxing the common public-IP predicate. Local peers do not receive
fabricated public ASNs or fake diverse public prefixes. Advertisements and capacity indexes
must distinguish independently reachable Internet service from local-only contribution.

The initial implementation uses signed `DirectLocalLan` scope, per-lease helper underlay binding
and exact read-only kernel route checks. The executable IPv4 fixture now requires the offline
node to consume through one WAN-capable Relay while simultaneously contributing as another
Client's Relay, with a private Exit-facing link to an independently connected Exit. Neither flow
may connect its Client directly to its Exit. LocalOnly selection uses an absent ASN and a real
authenticated LAN prefix; two unknown origins do not count as independent paths. The Exit's
signed observation preserves the local scope instead of pretending the address is public.
Focused checks and the evidence parser pass, but this two-flow fixture has not yet passed live.
ULA classification and kernel route parsing have focused coverage, not live IPv6 transfer
evidence. Automatic radio setup also remains unfinished; no hidden public-IP fallback is used.

## Sharing capacity

Configured limits remain hard ceilings, not evidence of unused bandwidth. The sharing controller
must observe owner traffic and link load, reduce contributed traffic promptly when the owner
needs the connection, and increase sharing only while spare capacity is available. Physical
uplink and Wi-Fi airtime are shared resources: counting the same bottleneck twice does not
create capacity. Scheduling must consider shared link/uplink origins as well as relay identity.
Owner-priority enforcement needs a live competing-traffic demonstration; a reservation ledger
or an advertised free-Mbps value alone is not completion evidence.

The first upload implementation has an explicit `sharing` configuration: one actual egress
interface, operator-known total usable upload, and one aggregate contribution ceiling. The
unprivileged agent installs its daemon-long typed helper owner before advertising participation,
checks the real queues, and retires them at shutdown. Disconnecting a Client route does not
remove contribution scheduling. Relay/Exit WireGuard traffic and actual TCP/UDP Exit payload
sockets use the contribution class; ordinary priority-zero owner traffic has queue precedence.
These are scheduling hints, not a security identity for arbitrary local applications.

Real disposable-veth traffic and engine-to-kernel lifecycle checks pass: two contribution
sources share one cap, owner upload takes priority, contribution recovers, and exact cleanup
restores the original queue. The [production-node upload run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989126592)
at `21aa8f21` also passed with real protected Exit traffic and competing node-owned upload:
5.430 Mbps contributed when idle, zero contribution while the owner received 11.996 Mbps of the
12-Mbps uplink, and 7.377 Mbps contribution after owner load stopped. The same protected UDP
route delivered exact application echoes before and after that load, all observers lost zero
packets and detected no plaintext/direct-exit leaks, and cleanup restored the original network
state. This proves upload queue behavior, not application goodput or arbitrary-link speed.
General UDP now pipelines bounded sends/replies; bounded FQ-CoDel separates contributed flows
under the unchanged owner-priority and rate caps. Supported software
`mq` and ordinary default `fq_codel` roots are restored exactly; custom options, classifiers and
unsupported/offloaded geometry are refused before mutation. It is not automatic bandwidth estimation, download-bottleneck control,
Wi-Fi airtime management or local/WAN throughput aggregation.

## Explicit Debian Wi-Fi mesh runtime

The first radio implementation is open-L2 802.11s on a new helper-owned interface. It is disabled
by default and requires explicit acknowledgement of that open local link layer. VOLPAROSSA's
authenticated control transport and two-leg/end-to-end overlay protections remain required;
this mode does not implement SAE or add protection for other services exposed by the host on a LAN.

Configuration supplies an existing wireless parent, common mesh ID, explicit 20-MHz frequency,
nonconflicting private host address/prefix and at most 32 neighbors. The helper verifies actual
hardware, regulatory and active-interface coexistence before creating the separate interface;
it does not retune an existing connection or change rfkill. Only the new interface receives the
connected address. No Internet default route, DNS setting, mesh forwarding or portal is installed.
The exact socket-owned interface is inspected throughout the daemon lifetime and removed at
shutdown. Route-only cleanup does not remove it. Listeners and local bootstrap dials start after
the mesh address exists. Compatible physical radios still need a real association/transfer test;
pure validation and ownership tests are not that evidence. The
[disposable hwsim backend run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989125353)
has now passed real kernel peering, 128-KiB transfers in both directions with matching hashes,
station counters and normal/crash cleanup on two simulated radios. Full agent/discovery/overlay
composition on that radio underlay still needs its own functional proof.

The shipped configuration keeps `wifi_mesh.enabled` false. An operator configuring a disposable
pair can select the same `mesh_id` and `frequency_mhz` on both peers, distinct `local_address`
values in the same private prefix, and each machine's own `parent_interface`. Enabling it also
requires `acknowledge_open_underlay: true` and explicit participation roles. Configuration/role
changes require a controlled daemon restart; this is not automatic discovery of usable radios,
address allocation or channel selection. Do not enable it on an active host until the separate
radio proof has passed for the intended environment.

## Practical boundaries and completion evidence

Wi-Fi mesh/P2P modes and simultaneous association depend on hardware, driver, firmware and
channel combinations. Linux exposes supported capabilities through
[nl80211/iw](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html);
[wpa_supplicant's P2P interface](https://w1.fi/wpa_supplicant/devel/p2p.html) provides discovery
and group lifecycle operations. Existing LAN connectivity can be developed first without assuming every
radio supports the later direct mode. Phone operation needs its own platform implementation
and cannot be claimed from a Debian veth test.

Functional demonstrations are: local-only discovery with no Internet bootstrap; real two-leg
Internet traffic for an offline client; concurrent local plus independent Internet paths;
uplink loss/recovery without recursive egress; and owner-priority sharing under load. Real
Wi-Fi setup needs a compatible-radio demonstration in addition to disposable virtual Ethernet
tests. All development-host routes, DNS, firewall and Wi-Fi configuration remain untouched.
