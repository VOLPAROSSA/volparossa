# Weather: behoud van historische testinputs (F09)

De zeven oorspronkelijke GitHub Actions-artifacts voor de huidige Weather-admissions
zijn op 23 oktober 2026 lokaal bewaard en op SHA-256, grootte, broncommit en
oorspronkelijke run gecontroleerd. De inputbundels voor v4, v5 en v6 zijn met de
bestaande validators gereconstrueerd. De lokale kopieën blijven controleerbaar na
het vervallen van de GitHub-objecten. **De huidige hosted workflows zijn hiermee
nog niet onafhankelijk van artifactverval. F09 blijft gedeeltelijk open.**

Dit dossier betreft Core `89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1` en de
ongewijzigde admissions. Bewaring geeft geen nieuwe runtime-, release- of
productieautorisatie. De oorspronkelijke mislukte en geslaagde proeven blijven
historisch bewijs met hun oorspronkelijke scope.

## Afhankelijkheden en deadline

Alle tijden hieronder zijn UTC op **26 oktober 2026**. Alle zeven artifacts waren
beschikbaar en niet verlopen bij de geauthenticeerde inventarisatie op 23 oktober.

| Artifact | Inhoud | Oorspronkelijke run | ZIP-bytes | Vervalt |
|---|---|---|---:|---|
| 11732430773 | Decoderprovenance, elf gebonden receipts | Weather 38214736539 | 35.901 | 06:56:04 |
| 11731895956 | Decoder, probe, buildreceipt en licenties | Weather 38214736539 | 14.057.646 | 06:56:05 |
| 11732188075 | Debian 13 ABI-bewijs | Core 38216142236 | 22.790 | 07:09:56 |
| 11735263794 | Drizz.li build-/UI-bewijs | Weather 38224151028 | 125.048 | 08:33:21 |
| 11735448641 | Drizz.li/browser/Node-assets | Weather 38224151028 | 147.157.200 | 08:33:22 |
| 11741385637 | Overmorrow build-/UI-bewijs | Weather 38235992570 | 139.087 | 10:27:50 |
| 11741150955 | Overmorrow/browser/Node-assets | Weather 38235992570 | 157.533.229 | 10:27:51 |

Samen **319.070.901 bytes**. De volledige oorspronkelijke digests staan in
[decoder-ABI-v1](../../tests/helper/weather-decoder-abi-v1.json),
[Drizz.li-v4](../../tests/integration/weather-public-drizzli-v4.json),
[Overmorrow-v5](../../tests/integration/weather-public-overmorrow-v5.json) en
[Android-v6](../../tests/integration/weather-public-android-v6.json).

- `weather-decoder-abi.yml` heeft decoder 11731895956 nodig om de aparte offline
  Debian 13 ABI-proef te beginnen. De zevende provenance-ZIP wordt niet door deze
  workflow gedownload, maar is wel onderdeel van zijn historische admission.
- `weather-products-delivery.yml` heeft decoder, ABI en beide Drizz.li-artifacts
  nodig voor de beschermde tweemodellen-/Drizz.li-proef.
- `weather-overmorrow-delivery.yml` heeft decoder, ABI en beide
  Overmorrow-artifacts nodig voor de beschermde Overmorrow-webproef.
- `weather-android-delivery.yml` heeft decoder en ABI nodig voor de geïnstalleerde
  Android/Core-proef. Het bouwt de app uit de gepinde bron; een later gepubliceerd
  Android-debugartifact is geen input van deze admission.

Deze vier opt-in workflows stoppen na verval bij de download-/metadatacontrole,
vóór de eigenlijke proef. De gewone Quality-bronchecks gebruiken deze downloads
niet. Het verhogen van repositoryretentie verlengt bestaande objecten niet:
[GitHub documenteert dat wijzigingen alleen nieuwe objecten raken](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#configuring-the-retention-period-for-checks-workflow-runs-commit-statuses-artifacts-and-logs-in-your-repository).

## Bewaren en onafhankelijk van GitHub opnieuw controleren

Gebruik een vertrouwde Core-checkout met de vier gereviewde admissions, Python 3
en een reeds geauthenticeerde `gh` voor capture. Installeer hiervoor geen software
op de ontwikkelhost. Kies een expliciete private map buiten de bijgehouden bron:

```sh
umask 077
python3 -B scripts/preserve-weather-artifacts.py capture \
  --store "$PWD/.volparossa-dev/weather-artifact-store"
```

Bewaar de gerapporteerde `manifest_sha256` afzonderlijk, bijvoorbeeld in het
gereviewde taakdossier. De helper selecteert uitsluitend de zeven gereviewde
artifacts. Hij controleert actuele run-/artifactmetadata, inclusief niet-verlopen
status, succesvolle attempt 1, broncommit en exacte ZIP-digest. Reeds aanwezige
`blobs/<sha256>.zip` worden alleen na volledige controle hergebruikt; de
metadatacontrole blijft actueel. De helper uploadt niets en voert geen bewaarde
code uit. Mappen zijn `0700`, bestanden `0600`.

Het gecontroleerde lokale F09-archief heeft manifest SHA-256
`0201e6187e1aa0e0d50dbd1537449cd8b39c59615c97d3cb1eeef4c84b1a6795`.
Deze digest hoort bij precies die capture; een nieuwe capture krijgt eigen
actuele metadata en dus een eigen manifestdigest.

Controleer daarna geheel offline, ook na 26 oktober:

```sh
python3 -B scripts/preserve-weather-artifacts.py verify \
  --store "$PWD/.volparossa-dev/weather-artifact-store" \
  --manifest-sha256 '<afzonderlijk bewaarde SHA-256>'
```

De verifier bindt snapshots aan de checked-in admissions, controleert alle ZIPs
en elf provenance-receipts en weigert afwijkende of onveilige archiefstructuren.
De capturetijd en metadata zijn bewaarde waarnemingen; lokale checksums zijn geen
onafhankelijke GitHub-attestation of vertrouwde tijdstempel. Offline verificatie
verklaart geen actuele beschikbaarheid van een verlopen remote artifact.
De volledige store en de afzonderlijke manifestdigest horen samen in een
goedgekeurde back-up; een tweede map op dezelfde schijf beschermt niet tegen
schijfverlies.

De zeven echte opgeslagen ZIPs zijn ook offline gecontroleerd met een
gesimuleerde klok op 27 oktober 2026, terwijl sockets en subprocessen expliciet
waren geblokkeerd. Dat slaagt met dezelfde manifestdigest en historische scope.
Dit is een test van het gedrag na expiry, geen waarneming uit de toekomst en geen
versoepeling van de live Actions-controles.

De 27 gerichte helpertests slagen, inclusief verkeerde provenance, beschadigde
ZIPs, onveilige paden, FIFO's en afgebroken downloads. De helper beëindigt zijn
downloadproces en ruimt eigen onvolledige outputs op bij SIGTERM/SIGINT.
Na SIGKILL of stroomuitval kan een incomplete store overblijven: bewaar die als
bewijs, gebruik een nieuwe private store en hergebruik uitsluitend opnieuw
gecontroleerde blobs. Een nieuwe capture blijft actuele, niet-verlopen metadata
vereisen; geef een onvolledig manifest nooit achteraf een succesclaim.
Quality voert de nieuwe inerte tests uit. De zes bestaande gerichte Weather-
bundel-/workflowtestsuites slagen eveneens, samen 123 tests.

## Aangetoonde reconstructie

De oorspronkelijke ZIPs, API-metadata, bronexports en resultaten zijn privé
bewaard onder `.volparossa-dev/f09-20261023/` in de bestaande workspace. Zij zijn
niet opgenomen in Git. `source-snapshots.json` bindt 108 geselecteerde bronfiles
aan hun repository, commit, grootte en SHA-256; de bijbehorende commitobjecten
zijn eveneens gecontroleerd. De overige inputs komen uit de zeven exacte ZIPs.

| Profiel | Files | INPUTS-manifest SHA-256 | TAR SHA-256 |
|---|---:|---|---|
| Drizz.li v4 | 216 | `639a332cb70622a8693d598eca0e33f97e03d8ec2b6bffcea8c6e3e85e6c41ed` | `18b14b786d39203362e6d740053cc493f8b3f851b44e1c35a98cf191f5552849` |
| Overmorrow v5 | 208 | `b5486b16bc24ce0013d170e7b558b2ae3b8bb7a6953fbaef9fdfa554acd53ab1` | `f2eb00503d4c538f4bb33b7aeebeb3202a845e3250086077322b565faba1019b` |
| Android v6 | 39 | `8f6d92ecc4f6c05f58511d30754537ac5768b729166119704c3c96fd8ba639f1` | `dd734e4bd5579edf129f81a4bf322efc0e4a28a2dae58a4b10ff705170834b61` |

`weather-client-bundle.py capture-v4`, `capture-v5` en `capture-v6` hebben alle
463 fileverwijzingen gecontroleerd tegen hun oorspronkelijke admissions.
`verify-runtime` en `runtime-version` hebben alle drie archieven onafhankelijk
teruggelezen. Deze commando's inspecteren bytes en voeren de runtimes niet uit.
De afzonderlijke `weather-decoder-abi.py verify-inputs` controleert alle 13
decoderinputs. De behouden Node-bytes uit de webassets voldoen ook aan de v6-pin;
hiervoor was geen aanvullende binaire download nodig.

Een bewaarde bundel kan direct zonder netwerk opnieuw worden gecontroleerd:

```sh
python3 -B tests/integration/weather-client-bundle.py verify-runtime \
  /absolute/private/path/weather-v6.tar \
  8f6d92ecc4f6c05f58511d30754537ac5768b729166119704c3c96fd8ba639f1
```

Bewaar de bijbehorende vertrouwde validatorbron naast het archief. Voor een nieuwe
reconstructie uit ZIPs blijven de exacte bronpinnen nodig:

| Bron | Commit |
|---|---|
| Browser, v4/v5 | `08bac388a0abfd06426bebe8f6fabd0157d2e709` |
| Weather, v4 | `3c8d708040fffac61d0535e961acc8ca9c3337ba` |
| Weather, v5 | `992054c2680e6ef00837b214e7dbd106ba69cc82` |
| Historische Overmorrow-driver | `06672c54a8394e8ab850730a56631808d752c7db` |
| Weather, v6 | `3b90442a9d5be4db73ccf83cba2028364980c3ca` |

Voor de ABI-inputcontrole is een private kopie van exact dezelfde validator en
admission gebruikt. De eerste poging vanuit de bestaande checkout weigerde
terecht de daar groepsschrijfbare admission (`0664`). Die mislukte log is bewaard;
de originele checkoutrechten en de validator zijn ongewijzigd. De identieke
kopie op `0600` slaagt.

## Herbouw en resterend besluit

Bronbouwinstructies bestaan voor de decoder (Weather `7d61077`), Drizz.li
(`397693c`) en Overmorrow (`06672c5`). ecbuild, libaec, ecCodes, client-upstreams,
Node, npm, Firefox en Flutter hebben bron-/runtimepinnen en licentiegegevens.
De originele decoderbuilder verklaart expliciet dat de toolchain niet volledig
hermetisch is en bit-identieke herbouw niet bewezen is. Compiler-/guestversies,
timings, browsermetingen en cleanupreceipts kunnen bij nieuwe uitvoering
verschillen. Daarom levert opnieuw bouwen geen geldig vervangend historisch
bewijs op: nieuwe bytes en receipts vereisen nieuwe, onafhankelijk beoordeelde
admissions. De volledige oorspronkelijke ZIPs behouden is voor deze keten de
kleinste betrouwbare herstelmaatregel.

Voor blijvend hosted gebruik is nog een concreet publicatie-/opslagbesluit nodig.
Aanbevolen: uitsluitend deze zeven ZIPs met minimale provenance bewaren als
immutable testinputarchief binnen de bestaande GitHub-organisatie, bijvoorbeeld
een expliciet als testarchief aangeduide GitHub Release. Een release is een
afzonderlijke publicatiehandeling; er is geen release of opslagdienst aangemaakt.
De oorspronkelijke licenties en notices moeten intact blijven. Publiceer geen
private auditdirectory, tokens, tijdelijke downloadlinks of extra hostbestanden.

Daarna is een afzonderlijk gereviewde archive-admission en gerichte consumer-PR
nodig, met exacte oorspronkelijke bytes/digests, expliciete archiefprovenance en
een geauthenticeerde, duurzame bron. De bestaande Actions-route blijft verlopen
artifacts weigeren; er komt geen automatische mirrorfallback of versoepeling
van oorspronkelijke admissions. De opslag/publicatie wacht op een expliciet
besluit; de consumer-PR en zijn merge zijn nog niet uitgevoerd. Alternatief is
een nieuwe bronbouwketen met nieuwe
onafhankelijke bewijzen, met meer werk en geen herstel van verloren geschiedenis.

F09 kan pas volledig dicht wanneer ook de goedgekeurde hosted inputvoorziening
na de oorspronkelijke vervaldatum werkt. Lokaal bytebehoud en gecontroleerde
reconstructie zijn voltooid; nieuwe runtime-acceptatie is niet geclaimd.
