# Common questions

[Documentation](README.md) · [Project overview](../README.md) · [Applications](applications/APPLICATIONS.md)

## Can I use this as my everyday network or backup service

Not yet as a supported product. There are real development milestones, but the expanded
alpha, application integrations and release qualification are unfinished. The first core
target is Debian 13 amd64. Phone and other application-platform targets do not mean that
the complete service already works on those devices.

Keep independent copies of important data and do not route sensitive traffic through an
unqualified build. Start with the [development summary](../README.md#development-status),
then the [operations guide](development/OPERATIONS.md) if you want to investigate a development setup.

## Is this a VPN or a new Internet

Protected network transport is the foundation. The wider DICN design adds cooperative
caching, private storage and shared computation. It uses local links and existing Internet
connectivity; it does not create connectivity where there are no reachable peers or uplinks.

The goal is participant-operated infrastructure without a mandatory central service class,
not an immediate replacement for every Internet protocol or application backend.

## Does multipath mean more than two relays in a row

No. Each normal protected path is **client → one relay → exit → destination**.
Two WireGuard links make it a *two-leg* path. *Multipath* means several such paths in parallel,
using different relays and the same exit. Direct local Wi-Fi/Ethernet describes how a peer
is reached; it does not remove the relay/exit privacy boundary.

The design admits useful additional connections within available resources and transport
limits. More connections sharing one radio or uplink do not automatically add bandwidth.
[Route architecture](architecture/ARCHITECTURE.md) · [Local links](network/LOCAL_LINK_NETWORK.md)

## Can I participate without my own Internet subscription

That is part of the design: reach a participating neighbor over a supported local link,
then use protected routes to an authorized exit with independent Internet access.
Somewhere along the route an actual uplink is still required.

Contribution follows available capabilities. Consumers provide relay service; independently
connected nodes also provide policy-limited exit service. Local-only nodes do not pretend to
have an independent exit. Installation leaves roles off until participation is explicitly
configured. Simulated-radio trials do not prove support for every physical Wi-Fi device.

## Does one gigabyte of backup require two gigabytes of contribution

With the current two-copy policy, **a 1 GB encrypted archive consumes approximately 2 GB
remotely, plus charged overhead**. You contribute that amount of usable space for others.
The two gigabytes already include both copies; it is not three. Your original local file
does not count as space contributed to others.

Fragments are spread among providers, with two copies of each fragment. Older full-archive
backups remain recoverable. Automatic reciprocal accounting and safe reduction of contributed
capacity are unfinished; lowering your usage must not delete someone else's live data.
[Storage details](services/PRIVATE_STORAGE.md)

## Can storage peers read or classify my files

Storage accepts application-encrypted data; the owner retains recovery keys. Peers hold opaque
fragments, not readable photos, messages or backups. That also means peers cannot reliably
classify the original files simply by examining ciphertext.

The intended immune system combines appropriate checks before encryption, controlled admission
and resource use, and evidence-led abuse responses without distributing private files or keys.
A modified uploader can evade local checks. Hashes, a signature or an AI judgment do not prove
legality, and an unverified accusation must not authorize deletion of another person's backup.
The complete private-content abuse mechanism remains in development; no decryption backdoor
or guarantee of an illegal-content-free network is claimed.

## Is all HTTPS traffic cached and shared

No. Supported modes authenticate eligible public content using original publisher/origin
authority, then verify retrieved chunks. They do not intercept TLS, share logged-in/private
responses or trust a peer's hash as proof of what a website published.

The aim is to use peers when they help and fall back to an authorized origin when appropriate.
Current support does not cover arbitrary browser HTTPS traffic.
[Cache design](services/CONTENT_NETWORK_PROPOSAL.md) · [HTTPS download modes](development/OPERATIONS.md#https-checksum-file-downloads)

## Is the AI only local and does more hardware make it smarter

The intended architecture is **network cooperation and shared learning**, not isolated local
assistants. Real public peer tasks and model exchange exist. Protected execution of private
work on another node remains unfinished: transport encryption alone cannot hide input from
the operator executing a model. Local private inference is a fallback, not the end goal.

More participants can add resources and diversity, but intelligence, latency and throughput
are different measurements. Actual small-model runs still make mistakes. Improvements must
be measured rather than inferred from node count or training activity. Model labels such as
135M, 360M and 1.7B refer to approximate parameter counts, not a quality score or the number
of agents. [Compute design and evidence](services/DECENTRALIZED_AGENTS.md)

## Does the immune system inspect everything or assign moral scores

No. It is intended to review **agents, artifacts and scoped decisions**, not score people.
The seven virtues are a values framework for reasoning, not a list of keywords to block.
The current destination/port whitelist does not classify every page behind a hostname or
make encrypted traffic readable. Mutual review, authority, correction and privacy protection
remain separate requirements. [Principles](../README.md#governed-by-7-virtues) · [Policy](privacy/WHITELIST.md)

## Where should I report an idea or a problem

Use the [repository issues](https://github.com/VOLPAROSSA/volparossa/issues) for ordinary bugs,
documentation problems and feature proposals. Include the relevant revision and expected
behavior; do not publish keys, personal data or raw private traffic.

For vulnerabilities, follow [SECURITY.md](../SECURITY.md). For implementation work, read
[CONTRIBUTING.md](../CONTRIBUTING.md) and the [documentation guide](README.md).
