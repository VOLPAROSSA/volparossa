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

## Sharing capacity

Configured limits remain hard ceilings, not evidence of unused bandwidth. The sharing controller
must observe owner traffic and link load, reduce contributed traffic promptly when the owner
needs the connection, and increase sharing only while spare capacity is available. Physical
uplink and Wi-Fi airtime are shared resources: counting the same bottleneck twice does not
create capacity. Scheduling must consider shared link/uplink origins as well as relay identity.
Owner-priority enforcement needs a live competing-traffic demonstration; a reservation ledger
or an advertised free-Mbps value alone is not completion evidence.

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
