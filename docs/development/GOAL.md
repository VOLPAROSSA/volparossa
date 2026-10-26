# VOLPAROSSA — volledig ontwikkeldoel

Bouw de volledige DICN-ontwikkel-alpha hieronder. Een mijlpaal of huidige
implementatiebeperking verkleint deze scope niet. [AGENTS.md](../../AGENTS.md) en de
[ontwikkelwerkwijze](CODEX_WORKFLOW.md) bepalen de uitvoering;
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) bevat het actuele plan en
bewijs. Lees taakgericht volgens die werkwijze.

Dit document bevat de gezamenlijke functionele eisen, inclusief [DPS](#dps) en
[Studio en hosting](#studio). Technische uitwerking en implementatiebewijs staan
bij de bestaande service-, architectuur- en applicatiedocumentatie. De
[bronversies](../archive/requirements-20261023/README.md) dienen uitsluitend als
provenance, niet als extra leesopdracht of actuele procesinstructie.

## Doel en gedeelde core

Bouw Project VOLPAROSSA zo snel en efficiënt mogelijk tot een functioneel complete ontwikkel-alpha van een DICN — Decentralized Intelligent Cooperative Network. Integreer de vereiste v1-datapaden en alle afgesproken uitbreidingen in grotere, direct bruikbare stukken. Iedere deelnemer draagt verplicht bij naar beschikbare mogelijkheden; exitdienst vereist een eigen bruikbare internetuplink. Financiële deelname staat los van deze wederkerige bijdrage aan het netwerk.
Ontwikkel een herbruikbare core/daemon met versieerbare applicatie-interfaces, die onafhankelijk van geopende applicaties op de achtergrond kan blijven draaien. Laat meerdere geïntegreerde applicaties waar mogelijk dezelfde compatibele service gebruiken, met behoud van gebruikersisolatie. Maak applicatiegebonden en expliciet gekozen systeembrede werking mogelijk. Respecteer de mogelijkheden en beperkingen van ieder ondersteund platform.

## Netwerk en gedeelde cache
Verbind de netwerk-, cache-, storage-, compute- en transactielaag, met duidelijke verantwoordelijkheden en vertrouwensgrenzen. Ondersteun directe lokale verbindingen via wifi en bekabeling naast internetverbindingen, deelname zonder eigen internetuplink en meerdere nuttige parallelle verbindingen en relaypaden. Laat het aantal verbindingen meebewegen met aantoonbare voordelen voor capaciteit, snelheid, stabiliteit en beschikbaarheid, binnen beschikbare apparaatmiddelen.
Behoud de afgesproken relay-/exitprivacygrenzen en echte vereiste MPTCP-, QUIC/MASQUE- en Multipath-QUIC-datapaden. Het normale v1-internetpad blijft client → één relay → exit → bestemming; meerdere parallelle paden gebruiken verschillende relays. Directe lokale verbindingen zijn geen toestemming voor een directe client-naar-exitdataverbinding. Maak onderscheid tussen verbindingen tussen apparaten, parallelle transportpaden en het aantal tussenliggende nodes.
Verspreid geschikte inhoud als verifieerbare fragmenten via de gedeelde cache. Ondersteun opportunistische verspreiding en parallel ophalen zonder het eigen gebruik van deelnemers te hinderen. Verdeel opslag en achtergrondverkeer eerlijk en doelmatig. Gebruik gecontroleerde bronfallback wanneer inhoud ontbreekt, verlopen is of elders sneller beschikbaar is.
Maak geschikte HTTPS-inhoud deelbaar zonder versleuteling, toegangsrechten, authenticiteit of privégegevens te ondermijnen. Presenteer versleuteld doorsturen niet als inhoudelijk cachen. Deel geschikte DNS-antwoorden met behoud van authenticiteit en geldigheid, met Unbound als fallback. Houd openbare caching, privéopslag en berichtenbewaring gescheiden.

<a id="dps"></a>

## Positionering (DPS)

DPS is een herbruikbare, versieerbare corevoorziening boven de bestaande vijf
DICN-lagen, met afzonderlijke platformadapters voor sensoren en radiosystemen.
[Het serviceontwerp](../services/DPS.md) werkt deze eisen uit.

### Positionering en sensoren

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

### GNSS-integriteit en veilige terugval

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

### Privacy en gebruikerscontrole

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

### Kwaliteit, middelen en bewijs

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

### Hergebruik van de vijf infrastructuurlagen

| Laag | DPS-integratie en grens |
| --- | --- |
| Network | Geschikte directe lokale links en toegestane meetcommunicatie; behoud relay-/exitprivacy en normale internetdatapaden. |
| Cache | Alleen geschikte openbare, authentieke en herdistribueerbare referentiegegevens; privélocaties en bewegingen komen niet automatisch in de openbare cache. |
| Storage | Expliciet gekozen private bewaring/synchronisatie via bestaande opslag met het gezamenlijke redundantiebeleid. |
| Compute | Toegestane verwerking, modelverbetering en evaluatie via geschikte gedeelde capaciteit, zonder privélocaties aan onbevoegde peers bloot te stellen. |
| Transaction | Alleen concrete functionele toepassingen onderzoeken; positionering vereist geen financiële deelname of betaling. |

Voorkom dubbele positioneringslogica per applicatie. Scheid sensortoegang van gedeelde
logica en respecteer Linux-, Android-, iOS- en toekomstige platformbeperkingen.

### Applicatie-integraties

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

## Applicaties
Integreer de core in de volgende applicaties, met behoud van hun bestaande bruikbaarheid:
- **volparossa-browser:** Firefox met netwerk-, cache- en decentrale AI-integratie. Gebruik het gedeelde VOLPAROSSA-brein, niet uitsluitend een lokaal model. Lever de afgesproken privacyinstellingen en extensies mee: telemetry, Mozilla-accountfunctionaliteit en gesponsorde links standaard uit; bescherming tegen volgen standaard streng; uBlock Origin, Decentraleyes, Consent-O-Matic en Adaptive Tab Bar Color. De browsergebonden killswitch staat standaard uit, zodat gewone internettoegang als fallback mogelijk blijft; ingeschakeld voorkomt hij die fallback. Dit verandert niet stilzwijgend de beschermingsinstellingen van andere applicaties. Ontwikkel een aanvullende uBlock Origin-filterlijst waarin het netwerk gevonden verbeteringen verzamelt, beoordeelt en gecontroleerd verspreidt. Behoud bestaande filterlijsten en gebruikerskeuzes. Behoud Consent-O-Matic als upstream-extensie zonder VOLPAROSSA-fork; bijdragen aan upstream zijn opt-in. Controleer dat Consent-O-Matic en uBlock Origin goed samenwerken, zonder noodzakelijke websitefuncties te blokkeren of ongewenste toestemming te geven. Laat het immuunsysteem misbruik, onjuiste regels en schadelijke wijzigingen signaleren; maak verspreide wijzigingen controleerbaar, herroepbaar en herstelbaar.
- **volparossa-chat:** Signal met decentrale berichtenaflevering, bellen, videobellen en back-ups. Behoud voor berichten het Signal Protocol, identiteiten en versleuteling. Houd rekening met gekoppelde apparaten en onderscheid volledig decentrale, gemengde en gewone Signal-aflevering.
- **volparossa-mail:** Thunderbird met bestaande accounts en adressen, voorrang voor geschikte VOLPAROSSA-aflevering via het Signal Protocol, decentrale AI en zelfhosting op basis van Stalwart. Ondersteun zowel gewone externe e-mail als VOLPAROSSA-mail, zonder leesbare externe mail aan willekeurige peers bloot te stellen. Maak noodzakelijke externe ontvangstvoorzieningen en hun vertrouwensgrenzen expliciet.
- **volparossa-code:** een open-source code-assistent op basis van OpenCode, met VOLPAROSSA als modelbackend en organisator van de netwerksamenwerking. Hergebruik waar geschikt de bestaande OpenCode-runtime, apps, clients en editor-integraties voor verschillende platforms. Benut agents en subagents voor daadwerkelijk code lezen, wijzigen, controleren en verdelen van werkzaamheden. Netwerksamenwerking is de standaard, ook voor privéprojecten, met ingebouwde bescherming van taakcontext en uitvoering. Behoud expliciete werkruimte- en uitvoeringsrechten, controleerbare wijzigingen en toezicht van het immuunsysteem. Houd modelselectie, peerplanning, resourceverdeling en annulering in de core; bouw geen concurrerende netwerkscheduler in de applicatie.
- **volparossa-image:** Immich voor Android, iPhone/iPad en webbrowsers, met als doel gebruik zonder een eigen permanent ingeschakelde server. Realiseer daarvoor zowel de benodigde backendfuncties als versleutelde decentrale opslag, synchronisatie en herstel. Bescherm privéfoto’s, video’s, locatiegegevens en afgeleide gegevens; maak ze niet automatisch openbaar cache- of trainingsmateriaal.
- **volparossa-map:** Organic Maps met behoud van offline kaarten en navigatie. Ondersteun het delen van verkeersdrukte via VOLPAROSSA, zonder individuele verplaatsingen of volledige locatiegeschiedenis openbaar te maken. Gebruik geschikte netwerk-, cache- en computefuncties voor kaartdistributie en verkeersinformatie, met behoud van bronlicenties, actualiteit en zichtbare onzekerheid.
- **volparossa-weather:** een applicatieonafhankelijke weervoorziening op rechtstreekse openbare modelgegevens, te beginnen met ECMWF, zonder Open-Meteo. Maak aanvullende modellen en waarnemingsbronnen mogelijk waar die aantoonbaar bijdragen. Deel gegevens via de cache en verdeel verwerking en leerwerk over beschikbare netwerkcapaciteit. Ontwikkel gezamenlijke voorspellingen en correcties; meet verbeteringen tegen echte waarnemingen en onafhankelijke evaluatiegegevens. Presenteer meer deelnemers of meer training niet automatisch als betere voorspellingen. Integreer zowel Drizz.li als Overmorrow; neerslag en luchtkwaliteit blijven vereist. Toon ontbrekende bronwaarden als niet beschikbaar, zonder verzonnen waarnemingen of voorspellingen.
- **volparossa-cloud:** OpenCloud met private decentrale bestandsopslag en bruikbaarheid zonder een eigen permanent ingeschakelde server. Realiseer naast bestandsopslag ook de benodigde toegang tot accounts, metadata, mappen, versies, deelrechten en synchronisatie. Onderzoek passende aansluitingen voor zoeken, previews, samenwerking en decentrale AI. Bescherm bestanden én afgeleide privégegevens. Presenteer een back-upconnector of verspreide bestandsopslag niet als een volledig serveronafhankelijke OpenCloud-dienst.
- **volparossa-bank:** een decentrale financiële toepassing voor een gezamenlijk gecoördineerde aandelenportefeuille waarvan de onderliggende stukken eigendom van de participanten zijn. Gebruik **ROIC × FCF-yield**, niet absolute FCF, als uitgangspunt voor de weging; beide invoerwaarden moeten niet-negatief zijn. Leg definities, verslagperioden, waarderingsmomenten, valuta en gegevensherkomst vast. Onderzoek en realiseer interne en externe microtransacties en decentrale prijsvorming die zowel zelfstandig als aanvullend op bestaande systemen kunnen functioneren. Houd rekening met werkelijk geaggregeerd economisch eigendom en toepasselijke concentratie- en meldgrenzen; gebruik geen opsplitsing om eigendom te verhullen. Begin met onderzoek en uitvoerbare simulaties. Echte financiële dienstverlening vereist afzonderlijk vastgestelde bevoegdheden, juridische inrichting en aansluitingen; deelname aan VOLPAROSSA activeert geen beleggingen, financiële accounts of betalingen.
- **volparossa-citizen:** een decentrale toepassing voor voorstellen, beraadslaging en referenda, van gemeentelijk tot mondiaal niveau, die naast bestaande democratische instellingen kan functioneren en daarmee kan samenwerken. Onderzoek geschikte open-source bouwstenen en werk de gekozen opzet uit in uitvoerbare simulaties. Hergebruik de transport-, opslag- en computefuncties van de core; houd specifieke bestuursregels in de toepassing. Ondersteun inclusieve identiteitsregistratie, controleerbare stemgerechtigdheid, geheime stemming en verifieerbare uitkomsten. Onderscheid technische stemuitslagen van daadwerkelijk erkende bestuurlijke of juridische bevoegdheid.

<a id="studio"></a>

### VOLPAROSSA Studio, decentralized hosting and shared AI

Build a fully integrated Silex-based Studio for visual creation, AI assistance,
publication, updates and maintenance through the shared DICN infrastructure,
preserving Silex functionality, portability, security and privacy. Product model
orchestration remains required. [The design](../services/STUDIO_HOSTING.md)
describes the integration contracts.

Geen editoractie of AI-resultaat verleent publicatie-, account-, domein-,
certificaat-, financiële of deploymentbevoegdheid.

#### Shared Core publishing and hosting

Complete and reuse Core content-addressed storage, signed manifests, site packages,
named publications, peer discovery, protected transport, retention and replica management.
Provide website publication and maintenance through suitable independent peers,
including documented availability when the publisher is offline. Implement:

- static websites and associated authorized assets;
- authenticated publisher/site identities, stable names and atomic versioned updates;
- content integrity, publisher authenticity and independent availability verification;
- replica retention, verification, replacement, repair and recovery after peer/publisher loss;
- authorized rollback, expiry, withdrawal and lifecycle management;
- quotas, resource budgets, participant fairness, efficient cache/deduplication and delivery.

Keep content integrity, publisher identity, domain ownership, current-version authority
and availability guarantees distinct. Local caching or successful replication alone
does not prove general hosting. Avoid unnecessary central infrastructure and document
necessary trust anchors and bootstrap dependencies. Prefer completing these existing
facilities over overlapping hosting services.

#### Silex editor and publication workflow

Inspect the current [Studio repository](https://github.com/VOLPAROSSA/volparossa-studio)
and [upstream Silex](https://github.com/silexlabs/Silex): architecture, versions, plugins,
publishing interfaces, desktop implementation, editor APIs and MCP capabilities.
Pin a reproducible, reviewed upstream version. Prefer maintainable adapters, plugins
and upstream-compatible contributions over invasive forks.

Preserve visual editing, responsive design, HTML/CSS export, templates, accessibility
features and normal non-AI operation. Keep output standard and portable, with export
and conventional hosting available; the editor must work before any public deployment.
The user workflow must support creating/importing a site, editing pages, local preview,
validation/preparation, selection of publication identity and hosting mode, explicit
publication authorization, Core publication, actual availability/replica-health monitoring,
and update, restore or withdrawal.

#### Shared AI through supported interfaces

Use the established Core model backend, Compute-layer and agent orchestration for
suitable decentralized model execution, collaboration, scheduling and protected processing.
Investigate Silex's MCP server, OpenCode compatibility, plugin interfaces and AI-ready
desktop architecture; connect through supported MCP/extension mechanisms where suitable.
The user's device must not bound usable intelligence: use cooperating network resources
where permitted and supported. Do not create another AI network or independent
code-assistant runtime inside Studio.

Enable authorized AI assistance for:

- sites/pages from natural-language instructions, layouts, components, styles and responsive design;
- HTML, CSS and JavaScript edits through authorized Silex interfaces;
- text, images and other permitted assets;
- accessibility, semantic structure, metadata, discoverability, translation and localization;
- detection and correction proposals for broken links, layout and accessibility problems;
- explanations and review of proposed changes, updates, maintenance and migration;
- independent suitable subtasks coordinated through the shared agent network.

Protect private sites, unpublished drafts, credentials, customer information, source
code and sensitive content through existing protected computation and explicit rights.
Do not send private content to arbitrary peers or shared training. If suitable protected
execution is unavailable, offer waiting or authorized local fallback without weakening
privacy. Treat model-generated code, external templates, MCP responses and imported
assets as untrusted. Consequential modifications, external publication, account operations
and deployment need explicit authorization; agents may not acquire publication credentials,
enlarge permissions or bypass review/release controls on their own.

#### Static and progressive dynamic hosting

Deliver complete, reliable static hosting first, then progressively implement useful
dynamic functionality as security, execution and durable-state foundations permit.
Research and implement appropriate capabilities for:

- HTML, CSS, JavaScript, fonts, images and other authorized assets;
- versioned manifests, stable identities, decentralized naming/discovery and existing Core delivery;
- custom domains with authenticated domain-to-publication binding, HTTPS and certificate lifecycles;
- publisher-offline availability and authorized deployment, rollback, withdrawal and recovery;
- forms, APIs and dynamic application functionality;
- protected, authorized server-side Compute execution;
- persistent state, databases, sessions and authenticated users;
- separation of public website content and private application data;
- abuse prevention, quotas and service-availability monitoring.

Dynamic hosting requires actual execution, durable state, authorization and suitable
availability guarantees; static replication does not supply them. Evaluate existing
open-source runtimes, databases and protocols without duplicating Core responsibilities.
Introduce a separate general hosting platform only for capabilities that cannot reasonably
fit the established architecture. Preserve conventional browsers and Internet standards;
provide explicit export/conventional hosting alternatives when decentralized hosting is
unavailable or incomplete. Claims of universal availability, censorship resistance,
guaranteed uptime or independence from conventional infrastructure require evidence.

#### Application integrations

Prioritize actual functional value and permission-controlled reuse over unnecessary
dependencies. Keep application business rules in applications and shared infrastructure
in Core.

| Application | Integration and boundary |
| --- | --- |
| Browser | Discover/browse suitable hosted sites through existing Browser/Core integration; preserve ordinary web compatibility, TLS authentication, privacy settings and browser fallback/killswitch behavior. Do not bypass network policy or expose browsing history. |
| Cloud | Investigate private storage/sync of projects, drafts, assets, templates and revision history using existing access control, redundancy, recovery and synchronization. Keep unpublished data separate from public content. |
| Code | Connect source editing, testing, debugging, component creation and technical review to the existing OpenCode integration and shared Core orchestration. |
| Image | Permit explicitly authorized media selection/publication while preserving ownership, licenses, privacy and metadata protection; private photos never become public assets automatically. |
| Mail | Investigate contact forms, notifications and authorized delivery using existing Mail; preserve spam protection, delivery status, authentication and decentralized/external e-mail distinctions. |
| DPS/Map | Investigate optional map/location components only where useful and explicitly authorized; maps must not expose precise locations, movement history or private geographic metadata automatically. |
| Chat, Weather, Citizen, Bank and future apps | Evaluate useful components without granting financial, identity, governance or transaction authority through website components or AI workflows. |

#### Security, privacy and licensing

Treat hosting as security-sensitive shared infrastructure. Protect against unauthorized
publication/modification, publisher impersonation, malicious hosting peers, stale/substituted/
replayed revisions, cross-user/site leakage, malicious HTML/JavaScript/templates/plugins/
dependencies, supply-chain attacks, dynamic-execution abuse, exhaustion/denial of service,
private-draft or credential access, insecure AI code/unauthorized agent actions, incorrect
domain/certificate validation and misleading integrity/availability claims.

Separate editor permissions, AI tools, publication authority, hosting responsibilities
and end-user access. Use independently verifiable publisher identities and authorized
release procedures, least privilege and isolation between unrelated users/sites.
Preserve relay/exit privacy and participant resource budgets.

Investigate Silex's upstream AGPL-3.0-or-later terms, dependencies and the Studio repository's
current license. Comply with integration, modification, distribution and network-service
obligations; retain attribution. Existing GPLv3 repository licensing does not automatically
satisfy an integrated AGPL implementation's obligations.

#### Functional acceptance

Develop coherent end-to-end milestones using representative real processes, separate
identities, actual Core interfaces and appropriate integration tests. Verify all of:

1. Silex creates or imports a representative website.
2. The website can be edited and previewed.
3. The user explicitly authorizes publication.
4. Core produces and validates the signed publication.
5. An independent consumer retrieves and renders the complete site.
6. Suitable retained replicas serve the site after the publisher goes offline, under documented conditions.
7. Authorized updates become visible without mixing incompatible revisions.
8. Unauthorized changes and stale or forged publications are rejected.
9. Failed deployment preserves the previously authorized working version where appropriate.
10. Hosting respects participant resource limits.
11. Shared VOLPAROSSA models/agents perform an authorized, bounded Silex editing task.
12. AI changes can be independently reviewed and tested before publication.
13. Drafts, credentials and sensitive data remain protected.
14. Conventional website export remains functional.
15. Recovery, withdrawal and cleanup behave as documented.

Distinguish component tests, simulated peers, real distributed publication and verified
public availability. HTML export/signed-chunk storage does not complete decentralized
hosting, and a local MCP call alone does not prove decentralized AI integration.

#### Delivery priorities

Build on an audit of verified, partial, missing and blocked Core hosting functionality.
Develop Studio with actual Core contracts, not a disconnected demonstration. Prefer the
least disruptive upstream approach. Establish the publishing contract, complete static
publication, independent retrieval and offline retention, shared AI and useful application
integrations; extend toward dynamic hosting as its foundations become ready. This is
indicative sequencing, not a fixed order. Coordinate with Storage, protected Compute,
DPS, networking and application work; record why higher-priority work is interrupted.
Keep relevant architecture/application documentation, evidence and next steps current;
documentation itself does not satisfy functional acceptance.

## Decentrale participatie en stemregels
Laat het immuunsysteem voorstellen beoordelen vanuit het zevenledige waardenkader en relevante wetgeving, en onderbouwen welke bevoegde groep betrokken is: gemeente, provincie, land, samenwerkingsverband van landen of mondiale bevolking. Maak beoordelingen, jurisdictiekeuzes en procedurele besluiten uitlegbaar en betwistbaar. Behandel voorstellen tot wetswijziging niet automatisch als verboden omdat zij afwijken van bestaande wetgeving.
Onderzoek registratie met paspoorten en andere betrouwbare bewijzen, inclusief meerdere nationaliteiten, documentvernieuwing, mensen zonder paspoort en geboorteregistratie. Voorkom dubbele registraties en stemrechten zonder identiteitsdocumenten, biometrie of politieke voorkeuren openbaar te verspreiden. Maak onderscheid tussen geregistreerd zijn en stemgerechtigd zijn; registratie van een kind geeft een ouder geen extra stem.
Gebruik voor iedere procedure een controleerbaar vastgestelde groep van alle stemgerechtigden, niet uitsluitend deelnemers, accounts of uitgebrachte stemmen. Minimaal één derde steun is nodig om een referendum te starten. Minimaal twee derde vóór betekent aangenomen; minimaal twee derde tegen betekent afgewezen. Alle overige geldige uitslagen zijn onbepaald. Onbepaalde voorstellen kunnen na drie jaar opnieuw in stemming worden gebracht; dit leidt niet automatisch tot een nieuwe stemming. 
Leg procedurele details, waaronder termijnen, hernieuwde ondersteuning en wijzigingen van de stemgerechtigde groep, expliciet vast. Bewijs de werking eerst met synthetische identiteiten en gerichte proeven. Presenteer simulaties niet als bewijs van unieke echte personen, veilige publieke verkiezingen of wettelijke zeggenschap.

## Berichten en private opslag
Realiseer betrouwbare, vertraagde berichtenaflevering via versleutelde bewaring bij peers, zodat verzender en ontvanger niet tegelijk online hoeven te zijn. Dit geldt voor zowel chat als geschikte e-mailaflevering. Onderscheid aangeboden, bewaard en daadwerkelijk afgeleverd; maak fouten en onzekerheid zichtbaar en voorkom stil verlies. Behandel ontbrekende ontvangstbevestiging niet automatisch als mislukte aflevering.
Bouw afzonderlijke, versleutelde decentrale cloudopslag met verspreide fragmenten, redundantie, herstel, vernieuwing en verwijdering. Gebruik één gezamenlijk, door de core beheerd redundantiebeleid voor alle gegevens en applicaties binnen de Storage-layer, geen verschillende beschermingsniveaus per app, gebruiker of bestand. Tijdelijke extra herstelkopieën en compatibiliteit met bestaande archieven mogen daarvan technisch afwijken, met zichtbare kosten en behoud van herstelbaarheid.
Iedere gebruiker biedt minstens evenveel bruikbare opslag als hij elders daadwerkelijk gebruikt, inclusief herstelkopieën en meegerekende overhead. Laat die bijdrage meeschalen met het gebruik. Geef ruimte waarin andermans gegevens staan pas vrij na veilige overdracht of geldige beëindiging van de opslagverplichting. Deel geen privésleutels of leesbare privégegevens met opslagpeers.
Spreid fragmenten over geschikte, voldoende onafhankelijke deelnemers en herstel ontbrekende redundantie wanneer peers verdwijnen. Onderzoek efficiëntere redundantie, waaronder herstelcodes, en pas verbeteringen als gezamenlijk beleid toe wanneer opslagbesparing, beschikbaarheid en herstelkosten dat rechtvaardigen. Behoud compatibiliteit en herstelbaarheid van bestaande gegevens. Maak onderscheid tussen berichten ophalen en bevestigen enerzijds, en niet-verbruikend herstellen van opgeslagen bestanden anderzijds.

## Samenwerkende en lerende intelligentie
Netwerksamenwerking en gezamenlijk leren vormen de standaardarchitectuur, niet een aanvullende functie naast lokale AI. Ontwerp voor flexibele taakverdeling, het combineren van agentresultaten en aantoonbare verbetering van modellen en werkwijzen. Beperk deze mogelijkheden niet onnodig tot wat één apparaat kan uitvoeren. Integreer passende privacybescherming in deze samenwerking en beoordeel technische keuzes gezamenlijk op functionaliteit, kwaliteit, efficiëntie en gegevensbescherming. Maak wezenlijke afwegingen expliciet; verlaag de afgesproken privacy niet stilzwijgend.
Bouw het gedeelde decentrale agent-netwerk als een samenwerkend brein waarvan alle aangesloten applicaties gebruik kunnen maken. Het eigen apparaat is een toegangspunt en draagt bij naar vermogen, maar zijn lokale rekenkracht mag niet de grens vormen aan de bruikbare intelligentie. Maak samenwerking en geschikte netwerkuitvoering de standaard, zodat ook gebruikers met bescheiden apparaten profiteren van modellen en agents die elders rekenen.
Realiseer daadwerkelijk trainen, bestaande agents kopiëren en verder ontwikkelen, modellen uitwisselen en gebruikersopdrachten efficiënt verdelen over beschikbare deelnemers. Verdeel zowel zelfstandige deeltaken als geschikte modelberekeningen wanneer dat functioneel en efficiënt is. Houd rekening met geheugen, rekenkracht, verbindingen, communicatiekosten, beschikbaarheid en de gevoeligheid van gegevens. Gebruik geschikte cache-inhoud én aanvullende toegestane bronnen.
Geef het eigen apparaatgebruik voorrang en voorkom dat achtergrondwerk onaanvaardbare netwerk-, opslag-, geheugen-, energie- of rekenbelasting veroorzaakt. Laat werk zich aanpassen aan beschikbare capaciteit, onderbreken of hervatten waar nodig. Een groot of langdurig gebruikersdoel mag uit meerdere beheersbare deeltaken bestaan; het hoeft niet binnen één lokale uitvoering te passen.
Laat het netwerk zijn modellen, taakverdeling en resourcegebruik voortdurend verbeteren op basis van aantoonbare resultaten. Beoordeel nieuwe of doorgetrainde agents op kwaliteit, efficiëntie en naleving van het waardenkader voordat zij bestaande versies vervangen. Ruim overbodige agentartefacten op zonder benodigde herstelmogelijkheden of lopende werkzaamheden te verliezen.
De ambitie is met groeiende gezamenlijke capaciteit en betere samenwerking te concurreren met centrale AI-platformen en die uiteindelijk mogelijk te overtreffen. Maak onderscheid tussen meer gelijktijdige capaciteit, snellere taakuitvoering en betere intelligentie; bewijs verbeteringen met passende metingen in plaats van ze uit het aantal deelnemers af te leiden.

## Audio, beelden en gesproken interactie
Maak audio- en beeldverwerking onderdeel van dezelfde gedeelde computelaag. Realiseer stapsgewijs het verwerken en begrijpen van beelden en audio, spraakherkenning, spraakgeneratie en natuurlijke gesproken gesprekken. Maak deze mogelijkheden herbruikbaar voor alle passende applicaties.
Laat kwaliteit, reactiesnelheid en efficiëntie verbeteren door gezamenlijk leerwerk en gemeten resultaten, zonder het netwerk of individuele apparaten te overbelasten. Bescherm opnamen, stemgegevens, beelden en afgeleide persoonsgegevens. Gebruik privé-inhoud niet automatisch voor gedeelde training en presenteer synthetische spraak niet misleidend als een echte persoon.

## Autonoom internetgebruik
Laat het gedeelde brein autonoom internetbronnen gebruiken voor gebruikersopdrachten, onderzoek, leren, verbetering en softwareonderhoud, binnen de geldende rechten en beleidsgrenzen. Combineer actuele brongegevens met geschikte cache-inhoud; voorkom onnodige downloads en herhaald werk.
Controleer herkomst, gebruiksrechten, actualiteit en betrouwbaarheid. Respecteer toegangsvoorwaarden, gebruikslimieten en accountbevoegdheden. Behandel websites, documenten en downloads als onbetrouwbare invoer, niet als bevoegdheid om instructies, privacygrenzen of uitvoeringsrechten te wijzigen. Autonoom internetgebruik is geen algemene toestemming om accounts te openen, aankopen te doen, geld te verplaatsen, vertrouwelijke gegevens te publiceren of willekeurige software uit te voeren.

## Beschermde netwerkuitvoering
Realiseer beschermde uitvoering van privétaken op andere nodes als een volwaardige corefunctie, bruikbaar voor alle applicatie-integraties. Bescherm privécode, prompts, documenten, tussenresultaten en uitkomsten niet alleen tijdens transport en opslag, maar ook tegen ongeoorloofde inzage door de beheerder van het uitvoerende apparaat.
Gebruik bestaande, onderbouwde vertrouwelijke-computatietechnieken en verifieer de daadwerkelijke bescherming. Leg vertrouwensaannames, ondersteunde apparaten, beperkingen en prestatiekosten vast. Behandel versleuteld transport, taakfragmentatie, een peersignatuur of een positieve agentbeoordeling op zichzelf niet als bewijs van vertrouwelijke uitvoering.
Verstuur uitsluitend de benodigde taakcontext en geef uitvoerders geen ruimere toegang tot bestanden, sleutels, accounts of hulpmiddelen dan de opdracht vereist. Standaard samenwerking is geen toestemming om privégegevens openbaar te maken, in een publieke cache te plaatsen of voor gedeelde training te gebruiken.
Maak onderscheid tussen leren welke werkwijzen goed presteren en leren van de inhoud van gebruikersgegevens. Gebruik openbare of daarvoor toegestane gegevens en aantoonbaar privacybeschermde leermechanismen. Laat privégegevens niet ongemerkt doorstromen naar gedeelde modellen, trainingspakketten of logs.
Wanneer geschikte beschermde capaciteit ontbreekt, maak dit zichtbaar en bied wachten, een passende beschermde uitvoerder of lokale terugval aan. Verlaag de privacybescherming nooit stilzwijgend. Presenteer lokale terugval niet als voltooiing van de vereiste private netwerksamenwerking.

## Transaction-layer en financieel herstel
Bouw de herbruikbare transactie-infrastructuur in de core, gescheiden van portefeuillebeleid en applicatielogica. Onderzoek geschikte open-source protocollen en bestaande standaarden voordat implementaties worden gekozen. Maak onderscheid tussen opdrachten, autorisatie, reserveringen, interne overdrachten, externe vereffening en definitieve afwikkeling. Voorkom dubbele uitvoering en maak onzekerheid over externe transacties expliciet.
Ondersteun controleerbare eigendoms- en transactieadministratie, zonder een interne registratie op zichzelf gelijk te stellen aan juridisch eigendom van echte aandelen. Houd beleggingswaarde, betaalwaarde, liquiditeit en risico’s zichtbaar uit elkaar. Presenteer een aandelenportefeuille niet als gegarandeerd waardevast spaargeld.
Laat het immuunsysteem helpen fraude, witwassen en misbruik te signaleren en tegen te gaan, met gegevensbescherming en controleerbare bevoegdheden. Geef gewone peers en agentworkers geen onbeperkte toegang tot financiële gegevens, betaalmiddelen of beslissingsmacht over andermans vermogen.
Bouw geautoriseerde correctie- en herstelmechanismen voor foutieve of ongeoorloofde transacties, ook wanneer bedragen binnen het systeem zijn opgesplitst of doorgestuurd. Bewaar de oorspronkelijke transacties en leg correcties afzonderlijk vast. Onderscheid blokkering, intern herstel, externe terugvordering, compensatie en daadwerkelijk terugontvangen waarde.
Voorkom dubbele terugbetaling, fictief herstel en ongemerkt afwentelen van verliezen. Maak tekorten en definitief extern afgewikkelde transacties zichtbaar; beloof geen universele terugdraaibaarheid wanneer geld of eigendomsrechten buiten de zeggenschap van het systeem liggen. Financiële maatregelen vereisen vastgelegde bevoegdheden, onafhankelijke controle en mogelijkheden om fouten te betwisten.

## Waardenkader en immuunsysteem
Laat agents en volledig automatische whitelist-/blacklistbesluitvorming redeneren vanuit de zeven afgesproken deugden — Humilitas, Humanitas, Mansuetudo, Diligentia, Liberalitas, Temperantia en Castitas — en hun tegenpolen: Superbia, Invidia, Ira, Acedia, Avaritia, Gula en Luxuria.
Gebruik dit als overkoepelend waardenkader voor contextuele beoordeling, ook in onvoorziene situaties. Concrete voorbeelden verduidelijken het kader maar vervangen het niet. Houd beoordelingen uitlegbaar en corrigeerbaar; abstracte principes maken misinterpretaties niet onmogelijk.
Gebruik Nederland/EU als gezamenlijke wettelijke basis, aangevuld met toepasselijke lokale exitbeperkingen en relevante regels voor afzonderlijke toepassingen. Maak onderscheid tussen verboden inhoud, contextafhankelijke beoordeling en toegestaan gedrag met eventueel advies.
Laat het wederzijdse immuunsysteem doorwerken in netwerk, cache, storage, compute, transacties, alle applicatie-integraties en softwareonderhoud. Controleer op misbruik, ongeoorloofde handelingen, problematische modellen en onbetrouwbare resultaten, met mogelijkheden voor beperking, herstel en uitsluiting binnen de vastgelegde bevoegdheden.
Laat inhoudelijke beoordeling van privégegevens lokaal of binnen een daarvoor toegelaten beschermde uitvoeringsomgeving plaatsvinden. Deel waar mogelijk alleen noodzakelijke, controleerbare beslis- en uitvoeringsbewijzen, zonder gevoelige inhoud openbaar te maken.
Het immuunsysteem vervangt geen technische toegangscontrole, vertrouwelijkheidsbescherming of wettelijke verantwoordelijkheden. Bescherm privacy en versleuteling; beloof geen volledige inhoudscontrole, foutloze beoordeling, absolute veiligheid of juridische risicoloosheid.

## Autonoom onderhoud en updates
Ontwikkel autonoom onderhoud van de core en alle huidige en toekomstige repositories binnen de GitHub-organisatie VOLPAROSSA. Laat het decentrale brein onderzoek, implementatie, controles en onafhankelijke beoordelingen verdelen.
Publiceer goedgekeurde wijzigingen automatisch via branches, pull requests, toegestane merges en releases, binnen expliciete organisatie- en repositorybevoegdheden. Houd GitHub-publicatierechten en releasebevoegdheden buiten gewone agentworkers. Laat agents niet hun eigen wijzigingen goedkeuren, hun bevoegdheden verruimen of hun beoordelingsvoorwaarden omzeilen.
Realiseer automatische verspreiding en installatie van bevoegde releases voor de geïnstalleerde VOLPAROSSA-componenten op alle clients. Gebruik waar passend het decentrale netwerk voor distributie, maar laat iedere client zelfstandig de releasebevoegdheid, authenticiteit, integriteit, actualiteit en compatibiliteit controleren.
Bouw gefaseerde uitrol, zichtbare status, pauzemogelijkheid en herstel bij mislukking. Behoud instellingen, identiteiten, privégegevens, opgeslagen fragmenten en lopende verplichtingen. Respecteer platformrechten en laat updates zichzelf geen ruimere bevoegdheden geven. Willekeurige peerinhoud, modeluitvoer of een GitHub-commit is op zichzelf geen installatiebevoegdheid.

## Uitvoering en voortgang
Prioriteit is daadwerkelijk werkende functionaliteit. Schrap geen afgesproken functies en presenteer ontbrekende werking niet als voltooid. Werk in grotere, samenhangende gebruiksscenario’s die van begin tot eind uitvoerbaar zijn, met expliciete afhankelijkheden en resterende werkzaamheden.
Gebruik tijdens het bouwen compilatie en gerichte functionele proeven, met behoud van privacygrenzen en bescherming van de ontwikkelhost. Bewijs de essentiële werking van echte datapaden, beschermde netwerkuitvoering, herstel, bevoegdheden, transactieconsistentie en automatische installatie voordat die als functioneel worden beschouwd. Presenteer simulaties, losse componenttests of lokale demonstraties niet als bewijs van een volledig werkende gedistribueerde dienst.
Integreer afgeronde mijlpalen regelmatig in main en ruim volledig geïntegreerde branches op zonder ongepubliceerd werk te verliezen. Beoordeel nieuwe ideeën expliciet op gevolgen voor architectuur, volgorde en resterend werk; laat begonnen integraties niet ongemerkt liggen.
Meet voortgang aan aantoonbaar werkende gebruiksscenario’s. Werk README en overige documentatie gebundeld bij en houd visie, geïmplementeerde werking en resterend werk duidelijk gescheiden. Uitgebreide regressiecontroles, aanvullende hardening, verdere optimalisatie en releasepolish volgen nadat de gewenste functionaliteit is geïntegreerd.

## Prioritering en samenhang
Bepaal en actualiseer zelfstandig de uitvoeringsvolgorde over alle repositories op basis van de actuele implementatie, onderlinge afhankelijkheden en lopende integraties. De volgorde waarin applicaties in dit doel worden genoemd, is geen verplichte bouwvolgorde.
Geef voorrang aan werkzaamheden die gedeelde blokkades wegnemen, architectuurbepalende technische onzekerheden vroeg toetsen of een samenhangend gebruiksscenario aantoonbaar werkend maken. Optimaliseer voor voortgang van het gehele systeem, niet voor afzonderlijke repositories of het aantal wijzigingen.
Ontwikkel benodigde corefuncties samen met concrete applicatie-integraties; wacht niet tot de volledige core gereed is voordat deze in echte gebruiksscenario’s wordt beproefd. Paralleliseer werkzaamheden waar dit zinvol is, zonder versnippering of conflicterende wijzigingen aan gedeelde interfaces.
Bouw voort op het bestaande werk en rond begonnen integraties af waar dat doelmatig is. Wijzig de planning wanneer afhankelijkheden, bevindingen of blokkades dat rechtvaardigen, maar leg kort vast waarom en wat er met het onderbroken werk gebeurt.
Houd een beknopt, actueel uitvoeringsplan bij met de eerstvolgende aantoonbare mijlpalen, betrokken repositories, belangrijkste afhankelijkheden en resterende blokkades. Prioritering verandert de volgorde, niet de afgesproken functionaliteit, privacygrenzen of voltooiingscriteria.

## Organisatiebrede verbetering en publieke groei

Verbeter efficiëntie en kwaliteit in alle VOLPAROSSA-repositories naast de functionele
ontwikkeling. Pak gemeten gedeelde knelpunten aan met samenhangende, omkeerbare
verbeteringen in ontwikkeling, runtimegebruik en onderhoudbaarheid. Behoud werking,
privacy, interoperabiliteit en onafgerond werk. Houd ontwikkel-AI buiten de
productruntime; gebruik standaard publieke hosted runners zonder betaalde diensten
of extra betaalde opslag te activeren. Onderbouw prestatieclaims met metingen.

Duurzame publieke groei omvat vindbaarheid, contributiemogelijkheden, documentatie,
visuele communicatie en voorbereiding op financiering voor de organisatie,
repositories en bestaande website. Behoud onderscheid tussen visie, implementatie
en bewezen werking, en respecteer AI-beleid van financiers. Externe benadering en
financieringsaanvragen vereisen expliciete toestemming. Herstart de lopende
Sponsors-aanvraag niet, wijzig geen financiële/juridische identiteit of DNS/hosting
en ga geen financiële of juridische verplichtingen aan zonder die toestemming.

Bezoekersgerichte verbeteringen aan organisatieprofiel, bestaande website, core-README
en relevante applicatie-README's zijn geautoriseerd via beoordeelbare PR's, passende
controles, toegestane integratie en verificatie van gepubliceerde inhoud. Vertaal
architectuur naar bruikbare voordelen met behoud van identiteit, attributie, volledige
scope en bewijsgrenzen. Dit vervangt de vroegere publicatiestop voor deze afgebakende
wijzigingen; overige benadering, financiering en accountwijzigingen blijven apart
bevoegd. [PUBLIC_GROWTH_20261020.md](PUBLIC_GROWTH_20261020.md) bewaart de onderbouwing.
