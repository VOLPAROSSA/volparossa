# Network trial records

For the current checkpoints and open work, see the [implementation status](../IMPLEMENTATION_STATUS.md).

## F04 — helperacceptatie en integratie geslaagd — 2026-10-27

[PR349](https://github.com/VOLPAROSSA/volparossa/pull/349) is op 27 oktober 2026
gemerged als `edf569300acbdf5e7715b5192ffbb293235b15ab` en bevat de minimale
beveiligingsroute en de gerichte helpercorrecties. De mergegegevens zijn op
5 november 2026 opnieuw gecontroleerd; dit is geen nieuwe runtimeproef. De oorspronkelijke
[F04-evidence en failures](https://github.com/VOLPAROSSA/volparossa/blob/ff2df276bc50a395dbcfa2d11b515c51fe0ee340/docs/IMPLEMENTATION_STATUS.md)
blijven behouden; PR347 is historische basis, geen afzonderlijke integratiekandidaat.

De verkeersblokkade was een fixture-omgevingsfout: een verse private
netwerknamespace begint met ICMP-datagramgroepbereik `1 0`, terwijl de hook bewust
geen `NET_RAW` heeft. Correctie `3a4ef6c9` staat uitsluitend de gevalideerde
agent-GID toe in de twee tijdelijke namespaces die werkelijk ping uitvoeren.
Root-/groep-/capability-/namespacebinding, beginwaarde en readback zijn fataal;
productiecode en capabilities blijven gelijk. De initiële hostnamespace wordt
alleen gelezen; haar pingbereik is aan de bestaande voor/na-vergelijking toegevoegd.

De enige geautoriseerde [Debian13-KVM-proef40542366058](https://github.com/VOLPAROSSA/volparossa/actions/runs/40542366058)
**slaagt** op exact `3a4ef6c9d3499cbe4d71db614194cba14e3a89b6`.
De bestaande Client/Exit/Relay-ping-, handshake-, RX/TX- en relaygroeicontroles,
exacte custody/FD-storecycli, commit/destroy/retry, één geforceerde singleton
CleanupConfirmedExactPresent-restart, cleanup/retirement, hostvergelijking en
VM-/image-/bronfences zijn werkelijk doorlopen. Dit is de bestaande niet-bewaarde
branchproef; geen retained-main-mijlpaal, algemeen restartbewijs of DICN-productacceptatie.
Numerieke bereik-/counterwaarden zijn niet als afzonderlijke artifacts bewaard;
de positieve grens volgt uit de fatale guards en de exact gebonden PASS.

Zes nieuwe private-fixtureregressies, acht diagnosetests, de volledige betrokken
livecontracttest en gerichte syntax/ShellCheck/diffcontroles slagen. Onafhankelijke
bron- en resultaatreview bevestigt de afbakening. Eerdere Quality40487291792,
CodeQL40487286993, dependency/RustSec- en zbus/crypto/DPS-native-evidence blijven
hergebruikt voor hun gecontroleerd gelijke inputs; dit is geen herhaalde audit.
De geïntegreerde kandidaat behoudt de destijds actuele main-documentatie;
de [bestaande PR-controles](https://github.com/VOLPAROSSA/volparossa/pull/349/checks)
blijven bij hun geteste bron horen. De handmatige integratie is voltooid.
Dit bewijst geen nieuwe runtimecompositie en activeert geen productiefunctionaliteit.

## Network baseline and remaining proof

The original [full v1 checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
passes A01–A15 on `482e33d0` with complete privacy captures, real MPTCP aggregation,
path-loss survival, 25 forced crashes/helper restart recovery and zero owned
objects after cleanup. Run 34047766913 and Quality 34047735082 bind that source.
The same-build mixed-link run 34047765944 fails its WAN-only warm-route baseline
with `INGRESS_MPQUIC_DATAGRAM_REJECTED`; it proves no new LAN+WAN gain ratio.
Reciprocal owner-priority download trial 34142685975 at `efc35ac9` passes its one
configured IPv4 bottleneck; arbitrary ISP/Wi-Fi/physical-radio guarantees do not
follow. Local-only configuration alone does not prove offline private-endpoint
routing. All newer shared-service, application and update requirements remain
part of completion.

The full Core candidate at `43b71ac3` produced two identical release packages
on the Ubuntu runner, SHA-256 `0973864d3fdf348fe31f932921400e219aeebba5f85ab17488a44f95379e1d19`.
In Debian 13, the suite no longer indexed the pinned Unbound packages and the
private DNS companion was unavailable to apt. The independent network trial
passed A01–A13 and A15. A14 counted eleven remaining runtime sockets after
the forced crash. The outer host snapshots matched. The acceptance gate
withheld the downloadable package.
[Original run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44447116925) ·
[Guest package error](../development/evidence/alpha-package-44447116925/package-apt.stderr)

On 19 November 2026, Core `9072cce87c77ea8e421b1261cb5e5ade80e758a7` passed
all 15 v1 cases in the twelve-node Debian 13 KVM topology. After the forced
crashes, the guest counted zero remaining owned objects and the before/after
host snapshots matched. The `alpha` workflow built the Core package twice on
one Ubuntu runner and obtained identical bytes. In Debian 13 amd64, the package
trial installed Core 0.1.0 with its matching private DNS worker, started both
Core services, ran `doctor` before and after upgrading, and removed Core. The
upgrade preserved the identity and restarted the active services. Removal
preserved the identity and configuration. The network snapshots matched.
[Acceptance report and original case evidence](../development/evidence/alpha-package-44453914133/acceptance-report.json) ·
[Package lifecycle](../development/evidence/alpha-package-44453914133/package-lifecycle.json) ·
[Workflow run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44453914133)

The installable QA candidate has a GitHub Actions expiry date of 26 November 2026.
The ZIP SHA-256 is `573554dd00c7b946bfd030524293fc1e9615db177047771f25d7647a32d1892d`.
The repository retains both package checksums and the original acceptance evidence.
[Candidate package pair](https://github.com/VOLPAROSSA/volparossa/actions/runs/44453914133/artifacts/14499490074) ·
[Core checksum](../development/evidence/alpha-package-44453914133/volparossa_0.1.0_amd64.deb.sha256) ·
[Worker checksum](../development/evidence/alpha-package-44453914133/volparossa-private-dns-worker_0.1.0_amd64.deb.sha256) ·
[Installation instructions](../../packaging/README.md)

On 19 November 2026, two independent hosted runners each built the Debian
amd64 packages twice from Core `428e28999768f274e61c0267e34db4f671677b2f`.
The Core package (26,104,956 bytes) and private DNS worker (52,796 bytes)
each matched byte for byte across the two downloads. The package builder now
calculates Installed-Size from logical file sizes, so filesystem block allocation
does not change the binary archive. Both Debian 13 KVM runs passed A01–A15,
installed the package pair, preserved the identity across the upgrade and
removed the package. Each guest counted zero remaining test objects and its
before/after host snapshots matched.
[First acceptance](../development/evidence/alpha-package-44530318378/acceptance-report.json) ·
[Second acceptance](../development/evidence/alpha-package-44530323130/acceptance-report.json) ·
[First package lifecycle](../development/evidence/alpha-package-44530318378/package-lifecycle.json) ·
[Second package lifecycle](../development/evidence/alpha-package-44530323130/package-lifecycle.json) ·
[Core SHA-256](../development/evidence/alpha-package-44530323130/volparossa_0.1.0_amd64.deb.sha256) ·
[Worker SHA-256](../development/evidence/alpha-package-44530323130/volparossa-private-dns-worker_0.1.0_amd64.deb.sha256) ·
[First run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530318378) ·
[Second run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530323130) ·
[Download the tested packages](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530323130/artifacts/14537641263)

The combined candidate `009dc5821d1e0d6d498381b9fbf0272ea38e9a5c` includes the Bank signing interface and validator trial. GitHub Actions built the Core and worker packages twice on one runner and compared each pair byte for byte. The twelve-node Debian 13 KVM passed all 15 transport cases. The installation VM started the Core services, preserved the identity through an upgrade and removed the package. Its network state matched before and after installation. The downloaded Core package is 26,105,172 bytes and the worker is 52,824 bytes. The candidate ZIP expires on 26 November 2026.
[Download the tested package pair](https://github.com/VOLPAROSSA/volparossa/actions/runs/44549419011/artifacts/14546019187) · [All fifteen case reports](../development/evidence/alpha-package-44549419011) · [Installation, upgrade and removal](../development/evidence/alpha-package-44549419011/package-lifecycle.json) · [Core checksum](../development/evidence/alpha-package-44549419011/volparossa_0.1.0_amd64.deb.sha256) · [Worker checksum](../development/evidence/alpha-package-44549419011/volparossa-private-dns-worker_0.1.0_amd64.deb.sha256) · [Original run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44549419011)
