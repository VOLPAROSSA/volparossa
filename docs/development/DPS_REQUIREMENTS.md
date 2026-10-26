# VOLPAROSSA — Decentralized Positioning System (DPS)

Deze permanente functionele uitbreiding hoort volledig bij [GOAL.md](GOAL.md).
DPS is een herbruikbare, versieerbare corevoorziening boven de bestaande vijf
DICN-lagen, met afzonderlijke platformadapters voor sensoren en radiosystemen.
De [bronversie](DPS_REQUIREMENTS_SOURCE_20261023.md) en de
[ontvangen delen](DPS_GOAL_20261021.md) bewaren provenance; oude model- en
procesinstructies daarin zijn vervangen door de gebruikerswijziging van 2026-10-26
in [AGENTS.md](../../AGENTS.md) en [CODEX_WORKFLOW.md](CODEX_WORKFLOW.md).
[Het serviceontwerp](../services/DPS.md) werkt de eisen uit;
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) bevat voortgang en planning.

## Positionering en sensoren

Onderzoek, ontwerp en implementeer privacybeschermende positionering die waar
technisch mogelijk zelfstandig zonder GPS/GNSS werkt en met satellietpositionering
samenwerkt om nauwkeurigheid, beschikbaarheid, snelheid, efficiëntie en betrouwbaarheid
te verbeteren. Gebruik bestaande, onderbouwde open-source technieken en standaarden
voordat nieuwe algoritmen worden ontwikkeld. Onderzoek:

- GPS, Galileo en andere ondersteunde GNSS-systemen;
- Wi-Fi RTT, Ultra Wideband (UWB), Bluetooth/BLE, andere geschikte lokale radiosignalen
  en directe peer-to-peer-afstandsmetingen;
- inertiële navigatie met versnellingsmeters en gyroscopen, kompas en barometer;
- visual-inertial odometry en geschikte cameratechnieken binnen expliciete camerarechten;
- betrouwbare vaste referentiepunten en positioneringsankers;
- sensorfusie, robuuste schatting, foutcorrectie en offline/lokale werking.

Laat apparaten elkaar helpen met afstandsmetingen en relatieve positionering.
Onderscheid relatieve, absolute geografische en extern gerefereerde posities:
zonder betrouwbare geografische referentie ontstaat geen bewezen absolute wereldpositie.
Bereken een betere of robuustere positie wanneer voldoende betrouwbare, onafhankelijke
gegevens bestaan; toon anders onzekerheid, conflicten en onbetrouwbaarheid.

## GNSS-integriteit en veilige terugval

Ontwikkel een onafhankelijke integriteitscontrole op GNSS-posities. Onderzoek
spoofing, jamming en signaaluitval, onwaarschijnlijke positiesprongen, gemanipuleerde
tijd/positie, onbetrouwbare of gecompromitteerde ankers, valse peerclaims en
gecoördineerde manipulatie door schijnbaar onafhankelijke bronnen. Onderzoek
GNSS-authenticatie, waaronder Galileo OSNMA, waar ontvanger en platform dat ondersteunen.
Authenticatie van navigatieberichten is geen onafhankelijke verificatie van de berekende
positie; een ondertekende locatieclaim bewijst de fysieke locatie niet.

Combineer waar mogelijk fysiek onafhankelijke metingen en controleer hun consistentie.
Meldingen van dezelfde of gecorreleerde bron tellen niet als onafhankelijk bewijs.
Bij vermoeden van manipulatie moet DPS verdachte gegevens isoleren of afwaarderen,
beschikbare onafhankelijke bronnen onderzoeken, bij voldoende bewijs een alternatieve
positie berekenen, onzekerheid en integriteitsstatus melden en veilige terugval of
tijdelijke onbeschikbaarheid ondersteunen. Vervang een verdachte positie niet stilzwijgend
door een onbewezen schatting en overschrijf de OS-locatievoorziening niet ongeautoriseerd.
Anomaliedetectie garandeert geen detectie van alle spoofing- of jammingaanvallen.

## Privacy en gebruikerscontrole

Voer positionering en sensorfusie zoveel mogelijk lokaal uit zonder verplichte deling
van exacte locatie of bewegingsgeschiedenis. Onderzoek tijdelijke, niet onnodig koppelbare
identifiers, dataminimalisatie, korte bewaartermijnen, versleutelde communicatie en
privacybeschermde uitwisseling van noodzakelijke meetgegevens met controleerbare,
expliciete toestemming. Bescherm tegen reconstructie van verplaatsingen, locatieprofilering
en koppeling tussen applicaties of sessies. Onderzoek ook identificatie via afstandsmetingen,
radiosignalen, timing en netwerkmetadata; claim alleen anonimiteit die concrete implementatie
en dreigingsmodel ondersteunen.

Onderscheid ontvangen positioneringshulp van vrijwillig bijdragen van meetgegevens.
Netwerkdeelname is geen toestemming voor locatiepublicatie. Gebruik privélocaties,
routes of bewegingsgeschiedenis niet voor gedeelde AI-training zonder afzonderlijke
geldige toestemming en passende bescherming.

## Kwaliteit, middelen en bewijs

Rapporteer bij een positie geschatte nauwkeurigheid en onzekerheid, beschikbaarheid
en actualiteit, bronherkomst en meettype, integriteitsstatus, bronconflicten,
relatieve/absolute status en berekeningsbeperkingen. Documenteer vertrouwensaannames,
privacyrisico's, foutmodellen, hardwarevereisten en platformbeperkingen.

Onderzoek efficiënte sensorfusie, positiebepaling en foutdetectie. Meet verbeteringen
tegen geschikte GNSS- en andere onafhankelijke referenties. Vergelijk waar mogelijk
positioneringsfout, tijd tot bruikbare positie, beschikbaarheid bij uitval, energie,
CPU/geheugen, netwerkverkeer en weerbaarheid tegen gemanipuleerde metingen.
Meer apparaten of sensoren bewijzen op zichzelf geen betere nauwkeurigheid.
Voorkom onaanvaardbare batterij-, privacy- en resourcekosten door voortdurend scannen
of achtergrondrekenen. DPS is geen gecertificeerd veiligheidskritisch navigatiesysteem;
maak toepassingsgrenzen expliciet.

Begin met begrensde, reproduceerbare proeven voor relatieve positionering, sensorfusie
en GNSS-integriteit, waar mogelijk met onafhankelijke referentiemetingen en gecontroleerde
foutinjectie. Onderscheid simulatie, werkende hardwareproeven en gemeten verbetering.
Geen onbevoegde radioscans, GNSS-verstoring of wijziging van hostnetwerk- of
locatievoorzieningen zonder afzonderlijke toestemming.

## Hergebruik van de vijf infrastructuurlagen

| Laag | DPS-integratie en grens |
| --- | --- |
| Network | Geschikte directe lokale links en toegestane meetcommunicatie; behoud relay-/exitprivacy en normale internetdatapaden. |
| Cache | Alleen geschikte openbare, authentieke en herdistribueerbare referentiegegevens; privélocaties en bewegingen komen niet automatisch in de openbare cache. |
| Storage | Expliciet gekozen private bewaring/synchronisatie via bestaande opslag met het gezamenlijke redundantiebeleid. |
| Compute | Toegestane verwerking, modelverbetering en evaluatie via geschikte gedeelde capaciteit, zonder privélocaties aan onbevoegde peers bloot te stellen. |
| Transaction | Alleen concrete functionele toepassingen onderzoeken; positionering vereist geen financiële deelname of betaling. |

Voorkom dubbele positioneringslogica per applicatie. Scheid sensortoegang van gedeelde
logica en respecteer Linux-, Android-, iOS- en toekomstige platformbeperkingen.

## Applicatie-integraties

Beoordeel iedere bestaande en toekomstige applicatie op daadwerkelijke meerwaarde,
hardware, haalbaarheid, privacy en ontwikkelafhankelijkheden; voeg geen onnodige
locatieafhankelijkheid toe.

| Applicatie | Vereiste of te onderzoeken integratie |
| --- | --- |
| Map | Integreer als alternatieve/aanvullende Organic Maps-locatiebron. Onderzoek nauwkeurigere navigatie, beperkte GNSS-ontvangst, tunnels/binnenomgevingen en manipulatieherkenning. Behoud offline navigatie, zichtbare onzekerheid en private routes/bewegingsgeschiedenis. |
| Weather | Gebruik DPS waar zinvol voor betere lokale informatie en geografische koppeling van toegestane waarnemingen; bescherm locaties en tel dezelfde bron niet als onafhankelijke waarnemingen. |
| Image | Onderzoek optionele locatiebepaling voor foto's/video's binnen bestaande rechten en private opslag; publiceer fotolocaties niet automatisch. |
| Chat | Onderzoek optionele locatie-uitwisseling en lokale positionering met expliciete toestemming, passende versleuteling en bewaartermijnen; behoud Signal Protocol en privacygrenzen. |
| Browser | Onderzoek aanvullende locatie via bestaande platform-/browserrechten; websites en extensies krijgen geen nauwkeurigere locatie dan expliciet toegestaan. |
| Cloud | Alleen waar nodig geautoriseerde private opslag en synchronisatie via de bestaande Storage-layer. |
| Overige | Onderzoek concrete waarde; financiële transacties, identiteiten, stemrechten en autorisaties mogen niet uitsluitend op onbewezen locatieclaims vertrouwen. |

Plan DPS op architecturale afhankelijkheden en systeemwaarde naast de volledige
DICN-ontwikkeling, zonder kritieke integraties automatisch te verdringen. Leg
integratiepunten en verificatiecriteria in de relevante architectuur- en
applicatiedocumentatie vast. Documentatie voltooit de functionaliteit niet.
