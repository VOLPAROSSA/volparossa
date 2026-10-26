<!-- This permanent normative addition is incorporated by GOAL.md. -->
<!-- BEGIN CONSOLIDATED DPS REQUIREMENTS -->
# VOLPAROSSA — Complete DICN Development Goal, Including Decentralized Positioning System (DPS)

Bouw Project VOLPAROSSA zo snel, efficiënt en kwalitatief hoogwaardig mogelijk verder tot een functioneel complete ontwikkel-alpha van het **Decentralized Intelligent Cooperative Network (DICN)**, inclusief alle oorspronkelijke afspraken, latere aanvullingen en de hieronder toegevoegde Decentralized Positioning System-functionaliteit.

Werk autonoom over alle relevante repositories binnen de GitHub-organisatie VOLPAROSSA, met behoud van architecturale samenhang, privacy, veiligheid, betrouwbaarheid en de volledige langetermijnambitie.

## 1. Behoud en consolideer het oorspronkelijke doel

Lees eerst:

- `AGENTS.md` en de relevante repository-instructies.
- `docs/development/GOAL.md`, inclusief het volledige oorspronkelijke doel en alle latere aanvullingen.
- `docs/IMPLEMENTATION_STATUS.md`.
- De bestaande architectuur-, applicatie- en ontwikkelingsdocumentatie.
- De actuele branches, openstaande integraties, tests en technische blokkades.

**Het volledige oorspronkelijke Pursuing Goal blijft onverkort van kracht.**

Alle afgesproken functionaliteit voor de Network-, Cache-, Storage-, Compute- en Transaction-layer blijft behouden, evenals de bestaande applicaties, het gedeelde decentrale AI-netwerk, het immuunsysteem, het waardenkader, de privacyvereisten, autonome softwareontwikkeling en updates.

Behoud ook alle later vastgelegde verduidelijkingen, waaronder Browser, Weather, organisatiebrede efficiëntieverbeteringen en duurzame publieke groei.

Beschouw het oorspronkelijke doel en zijn aanvullingen als één samenhangende ontwikkelopdracht.

Herschrijf of verkort de oorspronkelijke doelstelling niet op een manier die vereisten, nuances of voltooiingscriteria verwijdert.

Behoud de bestaande oorspronkelijke tekst en zijn controleerbare SHA-256-identiteit. Voeg nieuwe afspraken afzonderlijk en traceerbaar toe.

## 2. Nieuwe functionaliteit: Decentralized Positioning System (DPS)

Onderzoek, ontwerp en integreer een gedeeld **Decentralized Positioning System (DPS)** als privacybeschermende positioneringsvoorziening binnen VOLPAROSSA.

DPS moet, waar technisch mogelijk, zelfstandig functioneren zonder GPS/GNSS en daarnaast kunnen samenwerken met bestaande satellietpositionering om nauwkeurigheid, beschikbaarheid, snelheid, efficiëntie en betrouwbaarheid te verbeteren.

Een belangrijke functie is het onafhankelijk controleren van GNSS-posities op fouten, storingen, spoofing en andere vormen van manipulatie.

Wanneer voldoende betrouwbare, onafhankelijke gegevens beschikbaar zijn, moet DPS een betere of robuustere positie kunnen berekenen. Wanneer dat niet mogelijk is, moet het onzekerheid, conflicten en onbetrouwbaarheid zichtbaar maken.

Ontwerp DPS als een **herbruikbare corevoorziening**, niet als een afzonderlijk positioneringssysteem per applicatie.

De bestaande vijf DICN-infrastructuurlagen blijven behouden. DPS benut hun gedeelde mogelijkheden en krijgt een duidelijk afgebakende, versieerbare service-interface.

### 2.1 Zelfstandige en hybride positionering

Onderzoek geschikte bestaande open-source technologieën, standaarden, algoritmen en hardwaremogelijkheden voor:

- GNSS-positionering via GPS, Galileo en andere ondersteunde satellietsystemen.
- Wi-Fi RTT en geschikte draadloze afstandsmetingen.
- Ultra Wideband (UWB).
- Bluetooth/BLE en andere geschikte lokale radiosignalen.
- Directe peer-to-peer-afstandsmetingen.
- Inertiële navigatie met versnellingsmeters en gyroscopen.
- Kompas-, barometer- en andere geschikte sensorgegevens.
- Visual-inertial odometry en andere geschikte cameragebaseerde technieken, uitsluitend binnen expliciete camerarechten.
- Betrouwbare vaste referentiepunten en lokale positioneringsankers.
- Geschikte sensorfusie, robuuste schattingsalgoritmen en foutcorrectie.
- Offline en lokaal werkende positionering.

Gebruik bestaande, goed onderbouwde technologieën waar mogelijk.

Onderzoek hoe apparaten elkaar kunnen helpen met relatieve positionering, afstandsmetingen en het verbeteren van plaatsbepaling.

Maak expliciet onderscheid tussen relatieve posities, absolute geografische posities en posities die afhankelijk zijn van externe referentiepunten.

Een netwerk van apparaten zonder betrouwbare geografische referentie kan niet automatisch een correcte absolute wereldpositie bepalen.

### 2.2 Detectie van GNSS-manipulatie en storingen

Ontwikkel DPS ook als onafhankelijke integriteitscontrole voor satellietpositionering.

Onderzoek bescherming tegen:

- GNSS-spoofing.
- GNSS-jamming en signaaluitval.
- Onwaarschijnlijke positiesprongen.
- Manipulatie van tijd- en positiebepaling.
- Onbetrouwbare of gecompromitteerde positioneringsankers.
- Kwaadwillende peers die valse locatiegegevens aanbieden.
- Gecoördineerde manipulatie door meerdere schijnbaar onafhankelijke bronnen.

Onderzoek geschikte GNSS-authenticatie, waaronder Galileo OSNMA, waar ontvangers en platforms deze ondersteunen.

Maak onderscheid tussen authenticatie van navigatieberichten en onafhankelijke verificatie van de daadwerkelijk berekende positie.

Combineer waar mogelijk fysiek onafhankelijke meetbronnen en controleer hun onderlinge consistentie.

Behandel meerdere meldingen van dezelfde of gecorreleerde bron niet als onafhankelijk bewijs.

Een cryptografisch ondertekende locatieclaim bewijst niet automatisch dat de fysieke locatie correct is.

Wanneer manipulatie wordt vermoed, moet DPS:

1. De verdachte gegevens kunnen isoleren of minder zwaar laten meewegen.
2. Onafhankelijke beschikbare bronnen onderzoeken.
3. Een alternatieve positie berekenen wanneer voldoende betrouwbaar bewijs bestaat.
4. De onzekerheid en integriteitsstatus expliciet rapporteren.
5. Een veilige terugval of tijdelijke onbeschikbaarheid ondersteunen.

Vervang een verdachte GNSS-positie nooit stilzwijgend door een onbewezen schatting.

DPS mag de locatievoorziening van het besturingssysteem niet ongeautoriseerd overschrijven.

Presenteer anomaliedetectie niet als gegarandeerde detectie van alle spoofing- of jammingaanvallen.

### 2.3 Privacy, anonimiteit en gebruikerscontrole

Privacy is een fundamentele ontwerpeis van DPS.

Positionering moet zoveel mogelijk lokaal plaatsvinden, zonder dat gebruikers hun exacte locatie of bewegingsgeschiedenis met het netwerk hoeven te delen.

Onderzoek geschikte privacybeschermende samenwerking, waaronder:

- Lokale sensorfusie en berekening.
- Tijdelijke, niet onnodig koppelbare identifiers.
- Dataminimalisatie en beperkte bewaartermijnen.
- Versleutelde communicatie.
- Privacybeschermde uitwisseling van noodzakelijke meetgegevens.
- Controleerbare en expliciete toestemming.
- Bescherming tegen reconstructie van individuele verplaatsingen.
- Bescherming tegen locatieprofilering en het koppelen van verschillende applicaties of sessies.

Behandel netwerkdeelname niet als toestemming om locatiegegevens te publiceren.

Maak onderscheid tussen het ontvangen van positioneringshulp en het vrijwillig bijdragen van meetgegevens.

Gebruik geen privélocaties, routes of bewegingsgeschiedenis voor gedeelde AI-training zonder afzonderlijke geldige toestemming en passende bescherming.

Onderzoek actief hoe afstandsmetingen, radiosignalen, timing en netwerkmetadata alsnog personen kunnen identificeren.

Noem DPS alleen anoniem voor zover de concrete implementatie en het dreigingsmodel dat daadwerkelijk ondersteunen.

### 2.4 Betrouwbaarheid en kwaliteit

DPS moet naast een positie ook passende kwaliteitsinformatie beschikbaar maken, waaronder:

- Geschatte nauwkeurigheid en onzekerheid.
- Beschikbaarheid en actualiteit.
- Herkomst en type gebruikte meetbronnen.
- Integriteitsstatus.
- Conflicten tussen bronnen.
- Relatieve of absolute positioneringsstatus.
- Relevante beperkingen van de berekening.

Onderzoek efficiënte methoden voor sensorfusie, robuuste foutdetectie en positiebepaling.

Meet daadwerkelijke verbeteringen ten opzichte van geschikte GNSS- en andere referenties.

Vergelijk waar mogelijk:

- Positioneringsfout.
- Tijd tot een bruikbare positie.
- Beschikbaarheid bij uitval.
- Energieverbruik.
- CPU- en geheugengebruik.
- Netwerkverkeer.
- Weerbaarheid tegen gemanipuleerde meetgegevens.

Meer deelnemende apparaten of sensoren betekenen niet automatisch een nauwkeurigere positie.

Voorkom dat DPS door voortdurend radioscannen of achtergrondberekeningen onaanvaardbare batterij-, privacy- of resourcekosten veroorzaakt.

DPS is geen gecertificeerd veiligheidskritisch navigatiesysteem. Maak eventuele toepassingsgrenzen expliciet.

## 3. Integratie in de bestaande DICN-architectuur

Onderzoek hoe DPS de bestaande corevoorzieningen optimaal kan hergebruiken.

**Network-layer:** gebruik geschikte directe lokale verbindingen en toegestane communicatie voor positioneringsmetingen, zonder de bestaande relay-/exitprivacygrenzen of normale internetdatapaden te veranderen.

**Cache-layer:** gebruik uitsluitend geschikte openbare, authentieke en herdistribueerbare referentiegegevens. Privélocaties en bewegingsgegevens horen niet automatisch in de openbare cache.

**Storage-layer:** gebruik de bestaande private opslag voor gegevens die gebruikers expliciet willen bewaren of synchroniseren, met behoud van het gezamenlijke redundantiebeleid.

**Compute-layer:** gebruik geschikte gedeelde rekenmogelijkheden voor toegestane verwerking, modelverbetering en evaluatie, zonder private locatiegegevens aan onbevoegde peers bloot te stellen.

**Transaction-layer:** onderzoek alleen concrete toepassingen wanneer daar een functionele noodzaak voor bestaat. Maak positionering niet afhankelijk van financiële deelname of betalingen.

Voorkom duplicatie van positioneringslogica in afzonderlijke applicaties.

Houd apparaatgebonden sensortoegang gescheiden van de gedeelde positioneringslogica.

Respecteer de platformbeperkingen van Linux, Android, iOS en toekomstige ondersteunde systemen.

## 4. Integratie in VOLPAROSSA-applicaties

Onderzoek voor iedere bestaande en toekomstige applicatie of DPS zinvolle functionaliteit kan toevoegen.

Prioriteer integraties op basis van daadwerkelijke meerwaarde, beschikbare hardware, technische haalbaarheid, privacy en bestaande ontwikkelafhankelijkheden.

### Map
Integreer DPS als alternatieve of aanvullende locatiebron voor Organic Maps. Onderzoek nauwkeurigere navigatie, positionering bij beperkte GNSS-ontvangst, tunnel- en binnenomgevingen, robuustere locatiebepaling en detectie van GNSS-manipulatie. Behoud offline navigatie, maak onzekerheid zichtbaar en voorkom dat routes of bewegingsgeschiedenis automatisch worden gedeeld.

### Weather
Gebruik DPS waar zinvol voor nauwkeurigere lokale weersinformatie en de geografische koppeling van toegestane waarnemingen. Bescherm gebruikerslocaties en voorkom dat meerdere metingen van dezelfde bron als onafhankelijke waarnemingen worden behandeld.

### Image
Onderzoek optionele, privacybeschermende locatiebepaling voor foto's en video's. Bewaar locatiegegevens uitsluitend binnen de bestaande gebruikersrechten en private opslag. Deel geen fotolocaties automatisch met het netwerk.

### Chat
Onderzoek optionele locatie-uitwisseling en lokale positioneringsmogelijkheden, met expliciete toestemming, passende versleuteling en beperkte bewaartermijnen. Behoud het Signal Protocol en bestaande privacygrenzen.

### Browser
Onderzoek DPS als aanvullende locatiebron via bestaande platform- en browserrechten. Voorkom dat websites of extensies nauwkeurigere locatiegegevens verkrijgen dan de gebruiker expliciet heeft toegestaan.

### Cloud
Ondersteun uitsluitend geautoriseerde opslag en synchronisatie van privépositioneringsgegevens, indien nodig. Hergebruik de bestaande Storage-layer.

### Overige applicaties
Onderzoek per applicatie of DPS daadwerkelijk toegevoegde waarde heeft. Voeg geen locatieafhankelijkheid toe wanneer die functioneel niet nodig is. Financiële transacties, identiteiten, stemrechten en autorisaties mogen niet uitsluitend op onbewezen locatieclaims vertrouwen.

### Architectuur en uitvoering
Ontwerp DPS als een gedeelde, versieerbare corevoorziening bovenop de bestaande vijf infrastructuurlagen, met afzonderlijke platformadapters voor sensoren en radiosystemen.

Onderzoek bestaande open-source implementaties en standaarden voordat nieuwe algoritmen worden ontwikkeld.

Leg de vertrouwensaannames, privacyrisico's, foutmodellen, hardwarevereisten en platformbeperkingen vast.

Begin met reproduceerbare, begrensde proeven voor relatieve positionering, sensorfusie en GNSS-integriteitscontrole. Gebruik waar mogelijk onafhankelijke referentiemetingen en gecontroleerde foutinjectie.

Maak onderscheid tussen simulaties, werkende hardwareproeven en werkelijk bewezen positioneringsverbeteringen.

Gebruik geen onbevoegde radioscans, verstoor geen GNSS-signalen en wijzig geen hostnetwerk- of locatievoorzieningen zonder afzonderlijke toestemming.

Integreer DPS in de ontwikkelplanning op basis van architecturale afhankelijkheden en verwachte systeemwaarde. DPS is een blijvende afgesproken uitbreiding, maar hoeft bestaande kritieke integraties niet onmiddellijk te verdringen.

### Hervat het volledige Pursuing Goal
Consolideer deze DPS-uitbreiding als afzonderlijke, traceerbare aanvulling in `docs/development/GOAL.md`, zonder de oorspronkelijke tekst of SHA-256-identiteit te wijzigen.

Werk relevante architectuur- en applicatiedocumentatie bij en leg de benodigde integratiepunten en verificatiecriteria vast.

Behoud alle oorspronkelijke functionaliteit, later afgesproken aanvullingen, actieve branches, openstaande integraties en technische blokkades.

Gebruik Astra Ultra voor architectuur en coördinatie, Sol High voor substantiële implementatie en Luna Medium voor geschikte ondersteunende taken, volgens de reeds geconfigureerde automatische modeldelegatie.

Benut bestaande GitHub Actions efficiënt en behoud de afgesproken kwaliteits-, veiligheids- en privacygrenzen.

Hervat vervolgens autonoom de volledige ontwikkeling van VOLPAROSSA tot een functioneel complete ontwikkel-alpha, inclusief DPS. Bepaal zelfstandig de optimale uitvoeringsvolgorde over alle repositories, rond begonnen integraties doelmatig af en verifieer werkende functionaliteit met reproduceerbare tests.

Maak van DPS geen vervanging van het oorspronkelijke Pursuing Goal en beschouw de documentatie van DPS niet als voltooiing van de functionaliteit.

Controleer na consolidatie expliciet dat de volledige oorspronkelijke doelstelling, alle eerdere aanvullingen en de nieuwe DPS-eisen behouden zijn. Ga daarna verder met de technische ontwikkeling.
<!-- END CONSOLIDATED DPS REQUIREMENTS -->

## Provenance and reading rule

This is the permanent, normative DPS addition incorporated by [GOAL.md](GOAL.md).
Read it together with the complete preserved original objective and every later
clarification there. The [received-source archive](DPS_GOAL_20261021.md) retains
both exact payloads and their SHA-256 identities; no attachment or previous chat
is needed to recover them.

The first source was interrupted inside its final `### Map` subsection. The
user's continuation explicitly completes the text **from the Map integration**.
The text between the markers above therefore joins every byte before that first
`### Map` heading to the entire continuation beginning at `### Map`. Nothing
before Map is rewritten, and Map appears exactly once in the normative text.
The incomplete Map paragraph remains only in the provenance archive; it is not
an additional or competing requirement. The single newline before the closing
marker is a delimiter, not part of the joined payload.

[Service design and acceptance](../services/DPS.md),
[architecture](../architecture/ARCHITECTURE.md) and
[application integration scope](../applications/APPLICATIONS.md) interpret this
addition without reducing it. Current implementation and priorities belong in
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work).
[GOAL_VERIFICATION.md](GOAL_VERIFICATION.md) records the preservation checks and
traceability. Documentation, simulation and implemented hardware functionality
remain separate evidence levels.
