# VOLPAROSSA agreed development goal

The complete agreed objective is preserved below in its original Dutch wording.
Use [repository instructions](../../AGENTS.md) for engineering and host-safety rules,
[implementation status](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
for current evidence and dependencies, and the [documentation guide](../README.md)
for the relevant technical contracts. An immediate milestone does not replace this scope.

Source: user attachment `0ba86020-df95-41dc-a519-c58c804ea2c1/goal-objective.md`,
with a local snapshot timestamp of 2026-10-15. The payload between the markers has SHA-256
`2bebaf9e27860115e64f5b93f50cc1e5bc17d34b22c45fe83106d200b86b54c7`.
The newline immediately before the closing marker is a delimiter, not part of the payload.

## Preserved objective

<!-- BEGIN ORIGINAL GOAL -->
Bouw Project VOLPAROSSA zo snel en efficiënt mogelijk tot een functioneel complete ontwikkel-alpha van een DICN — Decentralized Intelligent Cooperative Network. Integreer de vereiste v1-datapaden en alle afgesproken uitbreidingen in grotere, direct bruikbare stukken. Iedere deelnemer draagt verplicht bij naar beschikbare mogelijkheden; exitdienst vereist een eigen bruikbare internetuplink. Financiële deelname staat los van deze wederkerige bijdrage aan het netwerk.
Ontwikkel een herbruikbare core/daemon met versieerbare applicatie-interfaces, die onafhankelijk van geopende applicaties op de achtergrond kan blijven draaien. Laat meerdere geïntegreerde applicaties waar mogelijk dezelfde compatibele service gebruiken, met behoud van gebruikersisolatie. Maak applicatiegebonden en expliciet gekozen systeembrede werking mogelijk. Respecteer de mogelijkheden en beperkingen van ieder ondersteund platform.

### Netwerk en gedeelde cache
Verbind de netwerk-, cache-, storage-, compute- en transactielaag, met duidelijke verantwoordelijkheden en vertrouwensgrenzen. Ondersteun directe lokale verbindingen via wifi en bekabeling naast internetverbindingen, deelname zonder eigen internetuplink en meerdere nuttige parallelle verbindingen en relaypaden. Laat het aantal verbindingen meebewegen met aantoonbare voordelen voor capaciteit, snelheid, stabiliteit en beschikbaarheid, binnen beschikbare apparaatmiddelen.
Behoud de afgesproken relay-/exitprivacygrenzen en echte vereiste MPTCP-, QUIC/MASQUE- en Multipath-QUIC-datapaden. Het normale v1-internetpad blijft client → één relay → exit → bestemming; meerdere parallelle paden gebruiken verschillende relays. Directe lokale verbindingen zijn geen toestemming voor een directe client-naar-exitdataverbinding. Maak onderscheid tussen verbindingen tussen apparaten, parallelle transportpaden en het aantal tussenliggende nodes.
Verspreid geschikte inhoud als verifieerbare fragmenten via de gedeelde cache. Ondersteun opportunistische verspreiding en parallel ophalen zonder het eigen gebruik van deelnemers te hinderen. Verdeel opslag en achtergrondverkeer eerlijk en doelmatig. Gebruik gecontroleerde bronfallback wanneer inhoud ontbreekt, verlopen is of elders sneller beschikbaar is.
Maak geschikte HTTPS-inhoud deelbaar zonder versleuteling, toegangsrechten, authenticiteit of privégegevens te ondermijnen. Presenteer versleuteld doorsturen niet als inhoudelijk cachen. Deel geschikte DNS-antwoorden met behoud van authenticiteit en geldigheid, met Unbound als fallback. Houd openbare caching, privéopslag en berichtenbewaring gescheiden.

### Applicaties
Integreer de core in de volgende applicaties, met behoud van hun bestaande bruikbaarheid:
- **volparossa-browser:** Firefox met netwerk-, cache- en decentrale AI-integratie. Gebruik het gedeelde VOLPAROSSA-brein, niet uitsluitend een lokaal model. Lever de afgesproken privacyinstellingen en extensies mee: telemetry, Mozilla-accountfunctionaliteit en gesponsorde links standaard uit; bescherming tegen volgen standaard streng; uBlock Origin, Decentraleyes, Consent-O-Matic en Adaptive Tab Bar Color. De browsergebonden killswitch staat standaard uit, zodat gewone internettoegang als fallback mogelijk blijft; ingeschakeld voorkomt hij die fallback. Dit verandert niet stilzwijgend de beschermingsinstellingen van andere applicaties. Ontwikkel een aanvullende uBlock Origin-filterlijst waarin het netwerk gevonden verbeteringen verzamelt, beoordeelt en gecontroleerd verspreidt. Behoud bestaande filterlijsten en gebruikerskeuzes. Controleer dat Consent-O-Matic en uBlock Origin goed samenwerken, zonder noodzakelijke websitefuncties te blokkeren of ongewenste toestemming te geven. Laat het immuunsysteem misbruik, onjuiste regels en schadelijke wijzigingen signaleren; maak verspreide wijzigingen controleerbaar, herroepbaar en herstelbaar.
- **volparossa-chat:** Signal met decentrale berichtenaflevering, bellen, videobellen en back-ups. Behoud voor berichten het Signal Protocol, identiteiten en versleuteling. Houd rekening met gekoppelde apparaten en onderscheid volledig decentrale, gemengde en gewone Signal-aflevering.
- **volparossa-mail:** Thunderbird met bestaande accounts en adressen, voorrang voor geschikte VOLPAROSSA-aflevering via het Signal Protocol, decentrale AI en zelfhosting op basis van Stalwart. Ondersteun zowel gewone externe e-mail als VOLPAROSSA-mail, zonder leesbare externe mail aan willekeurige peers bloot te stellen. Maak noodzakelijke externe ontvangstvoorzieningen en hun vertrouwensgrenzen expliciet.
- **volparossa-code:** een open-source code-assistent op basis van OpenCode, met VOLPAROSSA als modelbackend en organisator van de netwerksamenwerking. Hergebruik waar geschikt de bestaande OpenCode-runtime, apps, clients en editor-integraties voor verschillende platforms. Benut agents en subagents voor daadwerkelijk code lezen, wijzigen, controleren en verdelen van werkzaamheden. Netwerksamenwerking is de standaard, ook voor privéprojecten, met ingebouwde bescherming van taakcontext en uitvoering. Behoud expliciete werkruimte- en uitvoeringsrechten, controleerbare wijzigingen en toezicht van het immuunsysteem. Houd modelselectie, peerplanning, resourceverdeling en annulering in de core; bouw geen concurrerende netwerkscheduler in de applicatie.
- **volparossa-image:** Immich voor Android, iPhone/iPad en webbrowsers, met als doel gebruik zonder een eigen permanent ingeschakelde server. Realiseer daarvoor zowel de benodigde backendfuncties als versleutelde decentrale opslag, synchronisatie en herstel. Bescherm privéfoto’s, video’s, locatiegegevens en afgeleide gegevens; maak ze niet automatisch openbaar cache- of trainingsmateriaal.
- **volparossa-map:** Organic Maps met behoud van offline kaarten en navigatie. Ondersteun het delen van verkeersdrukte via VOLPAROSSA, zonder individuele verplaatsingen of volledige locatiegeschiedenis openbaar te maken. Gebruik geschikte netwerk-, cache- en computefuncties voor kaartdistributie en verkeersinformatie, met behoud van bronlicenties, actualiteit en zichtbare onzekerheid.
- **volparossa-weather:** een applicatieonafhankelijke weervoorziening op rechtstreekse openbare modelgegevens, te beginnen met ECMWF, zonder Open-Meteo. Maak aanvullende modellen en waarnemingsbronnen mogelijk waar die aantoonbaar bijdragen. Deel gegevens via de cache en verdeel verwerking en leerwerk over beschikbare netwerkcapaciteit. Ontwikkel gezamenlijke voorspellingen en correcties; meet verbeteringen tegen echte waarnemingen en onafhankelijke evaluatiegegevens. Presenteer meer deelnemers of meer training niet automatisch als betere voorspellingen.
- **volparossa-cloud:** OpenCloud met private decentrale bestandsopslag en bruikbaarheid zonder een eigen permanent ingeschakelde server. Realiseer naast bestandsopslag ook de benodigde toegang tot accounts, metadata, mappen, versies, deelrechten en synchronisatie. Onderzoek passende aansluitingen voor zoeken, previews, samenwerking en decentrale AI. Bescherm bestanden én afgeleide privégegevens. Presenteer een back-upconnector of verspreide bestandsopslag niet als een volledig serveronafhankelijke OpenCloud-dienst.
- **volparossa-bank:** een decentrale financiële toepassing voor een gezamenlijk gecoördineerde aandelenportefeuille waarvan de onderliggende stukken eigendom van de participanten zijn. Gebruik **ROIC × FCF-yield**, niet absolute FCF, als uitgangspunt voor de weging; beide invoerwaarden moeten niet-negatief zijn. Leg definities, verslagperioden, waarderingsmomenten, valuta en gegevensherkomst vast. Onderzoek en realiseer interne en externe microtransacties en decentrale prijsvorming die zowel zelfstandig als aanvullend op bestaande systemen kunnen functioneren. Houd rekening met werkelijk geaggregeerd economisch eigendom en toepasselijke concentratie- en meldgrenzen; gebruik geen opsplitsing om eigendom te verhullen. Begin met onderzoek en uitvoerbare simulaties. Echte financiële dienstverlening vereist afzonderlijk vastgestelde bevoegdheden, juridische inrichting en aansluitingen; deelname aan VOLPAROSSA activeert geen beleggingen, financiële accounts of betalingen.
- **volparossa-citizen:** een decentrale toepassing voor voorstellen, beraadslaging en referenda, van gemeentelijk tot mondiaal niveau, die naast bestaande democratische instellingen kan functioneren en daarmee kan samenwerken. Onderzoek geschikte open-source bouwstenen en werk de gekozen opzet uit in uitvoerbare simulaties. Hergebruik de transport-, opslag- en computefuncties van de core; houd specifieke bestuursregels in de toepassing. Ondersteun inclusieve identiteitsregistratie, controleerbare stemgerechtigdheid, geheime stemming en verifieerbare uitkomsten. Onderscheid technische stemuitslagen van daadwerkelijk erkende bestuurlijke of juridische bevoegdheid.

### Decentrale participatie en stemregels
Laat het immuunsysteem voorstellen beoordelen vanuit het zevenledige waardenkader en relevante wetgeving, en onderbouwen welke bevoegde groep betrokken is: gemeente, provincie, land, samenwerkingsverband van landen of mondiale bevolking. Maak beoordelingen, jurisdictiekeuzes en procedurele besluiten uitlegbaar en betwistbaar. Behandel voorstellen tot wetswijziging niet automatisch als verboden omdat zij afwijken van bestaande wetgeving.
Onderzoek registratie met paspoorten en andere betrouwbare bewijzen, inclusief meerdere nationaliteiten, documentvernieuwing, mensen zonder paspoort en geboorteregistratie. Voorkom dubbele registraties en stemrechten zonder identiteitsdocumenten, biometrie of politieke voorkeuren openbaar te verspreiden. Maak onderscheid tussen geregistreerd zijn en stemgerechtigd zijn; registratie van een kind geeft een ouder geen extra stem.
Gebruik voor iedere procedure een controleerbaar vastgestelde groep van alle stemgerechtigden, niet uitsluitend deelnemers, accounts of uitgebrachte stemmen. Minimaal één derde steun is nodig om een referendum te starten. Minimaal twee derde vóór betekent aangenomen; minimaal twee derde tegen betekent afgewezen. Alle overige geldige uitslagen zijn onbepaald. Onbepaalde voorstellen kunnen na drie jaar opnieuw in stemming worden gebracht; dit leidt niet automatisch tot een nieuwe stemming. 
Leg procedurele details, waaronder termijnen, hernieuwde ondersteuning en wijzigingen van de stemgerechtigde groep, expliciet vast. Bewijs de werking eerst met synthetische identiteiten en gerichte proeven. Presenteer simulaties niet als bewijs van unieke echte personen, veilige publieke verkiezingen of wettelijke zeggenschap.

### Berichten en private opslag
Realiseer betrouwbare, vertraagde berichtenaflevering via versleutelde bewaring bij peers, zodat verzender en ontvanger niet tegelijk online hoeven te zijn. Dit geldt voor zowel chat als geschikte e-mailaflevering. Onderscheid aangeboden, bewaard en daadwerkelijk afgeleverd; maak fouten en onzekerheid zichtbaar en voorkom stil verlies. Behandel ontbrekende ontvangstbevestiging niet automatisch als mislukte aflevering.
Bouw afzonderlijke, versleutelde decentrale cloudopslag met verspreide fragmenten, redundantie, herstel, vernieuwing en verwijdering. Gebruik één gezamenlijk, door de core beheerd redundantiebeleid voor alle gegevens en applicaties binnen de Storage-layer, geen verschillende beschermingsniveaus per app, gebruiker of bestand. Tijdelijke extra herstelkopieën en compatibiliteit met bestaande archieven mogen daarvan technisch afwijken, met zichtbare kosten en behoud van herstelbaarheid.
Iedere gebruiker biedt minstens evenveel bruikbare opslag als hij elders daadwerkelijk gebruikt, inclusief herstelkopieën en meegerekende overhead. Laat die bijdrage meeschalen met het gebruik. Geef ruimte waarin andermans gegevens staan pas vrij na veilige overdracht of geldige beëindiging van de opslagverplichting. Deel geen privésleutels of leesbare privégegevens met opslagpeers.
Spreid fragmenten over geschikte, voldoende onafhankelijke deelnemers en herstel ontbrekende redundantie wanneer peers verdwijnen. Onderzoek efficiëntere redundantie, waaronder herstelcodes, en pas verbeteringen als gezamenlijk beleid toe wanneer opslagbesparing, beschikbaarheid en herstelkosten dat rechtvaardigen. Behoud compatibiliteit en herstelbaarheid van bestaande gegevens. Maak onderscheid tussen berichten ophalen en bevestigen enerzijds, en niet-verbruikend herstellen van opgeslagen bestanden anderzijds.

### Samenwerkende en lerende intelligentie
Netwerksamenwerking en gezamenlijk leren vormen de standaardarchitectuur, niet een aanvullende functie naast lokale AI. Ontwerp voor flexibele taakverdeling, het combineren van agentresultaten en aantoonbare verbetering van modellen en werkwijzen. Beperk deze mogelijkheden niet onnodig tot wat één apparaat kan uitvoeren. Integreer passende privacybescherming in deze samenwerking en beoordeel technische keuzes gezamenlijk op functionaliteit, kwaliteit, efficiëntie en gegevensbescherming. Maak wezenlijke afwegingen expliciet; verlaag de afgesproken privacy niet stilzwijgend.
Bouw het gedeelde decentrale agent-netwerk als een samenwerkend brein waarvan alle aangesloten applicaties gebruik kunnen maken. Het eigen apparaat is een toegangspunt en draagt bij naar vermogen, maar zijn lokale rekenkracht mag niet de grens vormen aan de bruikbare intelligentie. Maak samenwerking en geschikte netwerkuitvoering de standaard, zodat ook gebruikers met bescheiden apparaten profiteren van modellen en agents die elders rekenen.
Realiseer daadwerkelijk trainen, bestaande agents kopiëren en verder ontwikkelen, modellen uitwisselen en gebruikersopdrachten efficiënt verdelen over beschikbare deelnemers. Verdeel zowel zelfstandige deeltaken als geschikte modelberekeningen wanneer dat functioneel en efficiënt is. Houd rekening met geheugen, rekenkracht, verbindingen, communicatiekosten, beschikbaarheid en de gevoeligheid van gegevens. Gebruik geschikte cache-inhoud én aanvullende toegestane bronnen.
Geef het eigen apparaatgebruik voorrang en voorkom dat achtergrondwerk onaanvaardbare netwerk-, opslag-, geheugen-, energie- of rekenbelasting veroorzaakt. Laat werk zich aanpassen aan beschikbare capaciteit, onderbreken of hervatten waar nodig. Een groot of langdurig gebruikersdoel mag uit meerdere beheersbare deeltaken bestaan; het hoeft niet binnen één lokale uitvoering te passen.
Laat het netwerk zijn modellen, taakverdeling en resourcegebruik voortdurend verbeteren op basis van aantoonbare resultaten. Beoordeel nieuwe of doorgetrainde agents op kwaliteit, efficiëntie en naleving van het waardenkader voordat zij bestaande versies vervangen. Ruim overbodige agentartefacten op zonder benodigde herstelmogelijkheden of lopende werkzaamheden te verliezen.
De ambitie is met groeiende gezamenlijke capaciteit en betere samenwerking te concurreren met centrale AI-platformen en die uiteindelijk mogelijk te overtreffen. Maak onderscheid tussen meer gelijktijdige capaciteit, snellere taakuitvoering en betere intelligentie; bewijs verbeteringen met passende metingen in plaats van ze uit het aantal deelnemers af te leiden.

### Audio, beelden en gesproken interactie
Maak audio- en beeldverwerking onderdeel van dezelfde gedeelde computelaag. Realiseer stapsgewijs het verwerken en begrijpen van beelden en audio, spraakherkenning, spraakgeneratie en natuurlijke gesproken gesprekken. Maak deze mogelijkheden herbruikbaar voor alle passende applicaties.
Laat kwaliteit, reactiesnelheid en efficiëntie verbeteren door gezamenlijk leerwerk en gemeten resultaten, zonder het netwerk of individuele apparaten te overbelasten. Bescherm opnamen, stemgegevens, beelden en afgeleide persoonsgegevens. Gebruik privé-inhoud niet automatisch voor gedeelde training en presenteer synthetische spraak niet misleidend als een echte persoon.

### Autonoom internetgebruik
Laat het gedeelde brein autonoom internetbronnen gebruiken voor gebruikersopdrachten, onderzoek, leren, verbetering en softwareonderhoud, binnen de geldende rechten en beleidsgrenzen. Combineer actuele brongegevens met geschikte cache-inhoud; voorkom onnodige downloads en herhaald werk.
Controleer herkomst, gebruiksrechten, actualiteit en betrouwbaarheid. Respecteer toegangsvoorwaarden, gebruikslimieten en accountbevoegdheden. Behandel websites, documenten en downloads als onbetrouwbare invoer, niet als bevoegdheid om instructies, privacygrenzen of uitvoeringsrechten te wijzigen. Autonoom internetgebruik is geen algemene toestemming om accounts te openen, aankopen te doen, geld te verplaatsen, vertrouwelijke gegevens te publiceren of willekeurige software uit te voeren.

### Beschermde netwerkuitvoering
Realiseer beschermde uitvoering van privétaken op andere nodes als een volwaardige corefunctie, bruikbaar voor alle applicatie-integraties. Bescherm privécode, prompts, documenten, tussenresultaten en uitkomsten niet alleen tijdens transport en opslag, maar ook tegen ongeoorloofde inzage door de beheerder van het uitvoerende apparaat.
Gebruik bestaande, onderbouwde vertrouwelijke-computatietechnieken en verifieer de daadwerkelijke bescherming. Leg vertrouwensaannames, ondersteunde apparaten, beperkingen en prestatiekosten vast. Behandel versleuteld transport, taakfragmentatie, een peersignatuur of een positieve agentbeoordeling op zichzelf niet als bewijs van vertrouwelijke uitvoering.
Verstuur uitsluitend de benodigde taakcontext en geef uitvoerders geen ruimere toegang tot bestanden, sleutels, accounts of hulpmiddelen dan de opdracht vereist. Standaard samenwerking is geen toestemming om privégegevens openbaar te maken, in een publieke cache te plaatsen of voor gedeelde training te gebruiken.
Maak onderscheid tussen leren welke werkwijzen goed presteren en leren van de inhoud van gebruikersgegevens. Gebruik openbare of daarvoor toegestane gegevens en aantoonbaar privacybeschermde leermechanismen. Laat privégegevens niet ongemerkt doorstromen naar gedeelde modellen, trainingspakketten of logs.
Wanneer geschikte beschermde capaciteit ontbreekt, maak dit zichtbaar en bied wachten, een passende beschermde uitvoerder of lokale terugval aan. Verlaag de privacybescherming nooit stilzwijgend. Presenteer lokale terugval niet als voltooiing van de vereiste private netwerksamenwerking.

### Transaction-layer en financieel herstel
Bouw de herbruikbare transactie-infrastructuur in de core, gescheiden van portefeuillebeleid en applicatielogica. Onderzoek geschikte open-source protocollen en bestaande standaarden voordat implementaties worden gekozen. Maak onderscheid tussen opdrachten, autorisatie, reserveringen, interne overdrachten, externe vereffening en definitieve afwikkeling. Voorkom dubbele uitvoering en maak onzekerheid over externe transacties expliciet.
Ondersteun controleerbare eigendoms- en transactieadministratie, zonder een interne registratie op zichzelf gelijk te stellen aan juridisch eigendom van echte aandelen. Houd beleggingswaarde, betaalwaarde, liquiditeit en risico’s zichtbaar uit elkaar. Presenteer een aandelenportefeuille niet als gegarandeerd waardevast spaargeld.
Laat het immuunsysteem helpen fraude, witwassen en misbruik te signaleren en tegen te gaan, met gegevensbescherming en controleerbare bevoegdheden. Geef gewone peers en agentworkers geen onbeperkte toegang tot financiële gegevens, betaalmiddelen of beslissingsmacht over andermans vermogen.
Bouw geautoriseerde correctie- en herstelmechanismen voor foutieve of ongeoorloofde transacties, ook wanneer bedragen binnen het systeem zijn opgesplitst of doorgestuurd. Bewaar de oorspronkelijke transacties en leg correcties afzonderlijk vast. Onderscheid blokkering, intern herstel, externe terugvordering, compensatie en daadwerkelijk terugontvangen waarde.
Voorkom dubbele terugbetaling, fictief herstel en ongemerkt afwentelen van verliezen. Maak tekorten en definitief extern afgewikkelde transacties zichtbaar; beloof geen universele terugdraaibaarheid wanneer geld of eigendomsrechten buiten de zeggenschap van het systeem liggen. Financiële maatregelen vereisen vastgelegde bevoegdheden, onafhankelijke controle en mogelijkheden om fouten te betwisten.

### Waardenkader en immuunsysteem
Laat agents en volledig automatische whitelist-/blacklistbesluitvorming redeneren vanuit de zeven afgesproken deugden — Humilitas, Humanitas, Mansuetudo, Diligentia, Liberalitas, Temperantia en Castitas — en hun tegenpolen: Superbia, Invidia, Ira, Acedia, Avaritia, Gula en Luxuria.
Gebruik dit als overkoepelend waardenkader voor contextuele beoordeling, ook in onvoorziene situaties. Concrete voorbeelden verduidelijken het kader maar vervangen het niet. Houd beoordelingen uitlegbaar en corrigeerbaar; abstracte principes maken misinterpretaties niet onmogelijk.
Gebruik Nederland/EU als gezamenlijke wettelijke basis, aangevuld met toepasselijke lokale exitbeperkingen en relevante regels voor afzonderlijke toepassingen. Maak onderscheid tussen verboden inhoud, contextafhankelijke beoordeling en toegestaan gedrag met eventueel advies.
Laat het wederzijdse immuunsysteem doorwerken in netwerk, cache, storage, compute, transacties, alle applicatie-integraties en softwareonderhoud. Controleer op misbruik, ongeoorloofde handelingen, problematische modellen en onbetrouwbare resultaten, met mogelijkheden voor beperking, herstel en uitsluiting binnen de vastgelegde bevoegdheden.
Laat inhoudelijke beoordeling van privégegevens lokaal of binnen een daarvoor toegelaten beschermde uitvoeringsomgeving plaatsvinden. Deel waar mogelijk alleen noodzakelijke, controleerbare beslis- en uitvoeringsbewijzen, zonder gevoelige inhoud openbaar te maken.
Het immuunsysteem vervangt geen technische toegangscontrole, vertrouwelijkheidsbescherming of wettelijke verantwoordelijkheden. Bescherm privacy en versleuteling; beloof geen volledige inhoudscontrole, foutloze beoordeling, absolute veiligheid of juridische risicoloosheid.

### Autonoom onderhoud en updates
Ontwikkel autonoom onderhoud van de core en alle huidige en toekomstige repositories binnen de GitHub-organisatie VOLPAROSSA. Laat het decentrale brein onderzoek, implementatie, controles en onafhankelijke beoordelingen verdelen.
Publiceer goedgekeurde wijzigingen automatisch via branches, pull requests, toegestane merges en releases, binnen expliciete organisatie- en repositorybevoegdheden. Houd GitHub-publicatierechten en releasebevoegdheden buiten gewone agentworkers. Laat agents niet hun eigen wijzigingen goedkeuren, hun bevoegdheden verruimen of hun beoordelingsvoorwaarden omzeilen.
Realiseer automatische verspreiding en installatie van bevoegde releases voor de geïnstalleerde VOLPAROSSA-componenten op alle clients. Gebruik waar passend het decentrale netwerk voor distributie, maar laat iedere client zelfstandig de releasebevoegdheid, authenticiteit, integriteit, actualiteit en compatibiliteit controleren.
Bouw gefaseerde uitrol, zichtbare status, pauzemogelijkheid en herstel bij mislukking. Behoud instellingen, identiteiten, privégegevens, opgeslagen fragmenten en lopende verplichtingen. Respecteer platformrechten en laat updates zichzelf geen ruimere bevoegdheden geven. Willekeurige peerinhoud, modeluitvoer of een GitHub-commit is op zichzelf geen installatiebevoegdheid.

### Uitvoering en voortgang
Prioriteit is daadwerkelijk werkende functionaliteit. Schrap geen afgesproken functies en presenteer ontbrekende werking niet als voltooid. Werk in grotere, samenhangende gebruiksscenario’s die van begin tot eind uitvoerbaar zijn, met expliciete afhankelijkheden en resterende werkzaamheden.
Gebruik tijdens het bouwen compilatie en gerichte functionele proeven, met behoud van privacygrenzen en bescherming van de ontwikkelhost. Bewijs de essentiële werking van echte datapaden, beschermde netwerkuitvoering, herstel, bevoegdheden, transactieconsistentie en automatische installatie voordat die als functioneel worden beschouwd. Presenteer simulaties, losse componenttests of lokale demonstraties niet als bewijs van een volledig werkende gedistribueerde dienst.
Integreer afgeronde mijlpalen regelmatig in main en ruim volledig geïntegreerde branches op zonder ongepubliceerd werk te verliezen. Beoordeel nieuwe ideeën expliciet op gevolgen voor architectuur, volgorde en resterend werk; laat begonnen integraties niet ongemerkt liggen.
Meet voortgang aan aantoonbaar werkende gebruiksscenario’s. Werk README en overige documentatie gebundeld bij en houd visie, geïmplementeerde werking en resterend werk duidelijk gescheiden. Uitgebreide regressiecontroles, aanvullende hardening, verdere optimalisatie en releasepolish volgen nadat de gewenste functionaliteit is geïntegreerd.

### Prioritering en samenhang
Bepaal en actualiseer zelfstandig de uitvoeringsvolgorde over alle repositories op basis van de actuele implementatie, onderlinge afhankelijkheden en lopende integraties. De volgorde waarin applicaties in dit doel worden genoemd, is geen verplichte bouwvolgorde.
Geef voorrang aan werkzaamheden die gedeelde blokkades wegnemen, architectuurbepalende technische onzekerheden vroeg toetsen of een samenhangend gebruiksscenario aantoonbaar werkend maken. Optimaliseer voor voortgang van het gehele systeem, niet voor afzonderlijke repositories of het aantal wijzigingen.
Ontwikkel benodigde corefuncties samen met concrete applicatie-integraties; wacht niet tot de volledige core gereed is voordat deze in echte gebruiksscenario’s wordt beproefd. Paralleliseer werkzaamheden waar dit zinvol is, zonder versnippering of conflicterende wijzigingen aan gedeelde interfaces.
Bouw voort op het bestaande werk en rond begonnen integraties af waar dat doelmatig is. Wijzig de planning wanneer afhankelijkheden, bevindingen of blokkades dat rechtvaardigen, maar leg kort vast waarom en wat er met het onderbroken werk gebeurt.
Houd een beknopt, actueel uitvoeringsplan bij met de eerstvolgende aantoonbare mijlpalen, betrokken repositories, belangrijkste afhankelijkheden en resterende blokkades. Prioritering verandert de volgorde, niet de afgesproken functionaliteit, privacygrenzen of voltooiingscriteria.
<!-- END ORIGINAL GOAL -->

## Later clarifications

These clarifications supplement the preserved objective; they do not replace it.

- Consent-O-Matic remains the upstream extension, without a VOLPAROSSA fork.
  Contributions upstream are opt-in. Keep its cooperation with uBlock Origin and
  the browser's controlled filter-list work within the existing
  [browser requirements](../applications/BROWSER_NETWORK.md) and
  [application scope](../applications/APPLICATIONS.md#browser).
- Weather includes both Drizz.li and Overmorrow integrations. Precipitation and
  air-quality support remain required follow-on functionality, not optional
  omissions. Missing or unavailable source values must stay visibly unavailable;
  never substitute invented observations or forecasts. The
  [Weather application scope](../applications/APPLICATIONS.md#weather) and
  [current execution plan](../IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones)
  retain their implementation and evidence boundaries.

- Organization-wide efficiency and quality optimization (2026-10-20) is explicitly
  authorized alongside the complete goal above. Prioritize measured shared
  bottlenecks and coherent, reversible improvements to development, runtime
  resources and maintainability across all VOLPAROSSA repositories. Preserve
  functionality, privacy, interoperability, active integrations and unfinished
  work. Use Astra/Ultra for principal decisions, bounded Sol/High implementation
  and review, and Luna/Medium support. Verify actual delegation. Keep development
  AI tooling outside the product runtime; use standard public hosted runners
  without enabling paid services or additional paid storage. Performance claims
  require measured evidence. The [execution plan](../IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones)
  retains the current priorities and acceptance boundaries.

- Sustainable public growth (2026-10-20) is authorized across the organization,
  repositories and existing website, alongside the complete technical objective.
  Improve discoverability, contribution paths, documentation, visual communication
  and funding readiness while distinguishing vision, implementation and evidence.
  Keep external outreach and funding applications for explicit approval; do not
  restart the pending Sponsors application, change financial/legal identities,
  alter DNS/hosting or submit financial/legal commitments. Respect funder-specific
  AI policies. The [public-growth record](PUBLIC_GROWTH_20261020.md) preserves the
  audit, priorities, verification, remaining opportunities and roadmap.

- Public messaging implementation (2026-10-21) explicitly authorizes visitor-facing
  improvements to the organization profile, existing website, core README and
  relevant application READMEs, with reviewable PRs, appropriate checks, permitted
  integration and verification of published content. Translate architecture into
  useful human benefits while preserving the complete goal, identity, attribution
  and evidence boundaries. This supersedes the previous milestone's publication
  hold for these scoped changes. Unrelated outreach, funding applications,
  financial commitments and account changes still require separate authorization.


### Decentralized Positioning System addition (2026-10-21)

The complete [DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md) is incorporated here as a
permanent, normative addition to this goal. The preserved original objective and
**every** later clarification above remain in force. Read the full joined DPS
text, not just this navigation summary:

- **Positioning:** investigate and implement useful standalone and hybrid GNSS,
  local radio, ranging and sensor-based positioning, relative and absolute
  estimates, with explicit hardware and platform limits.
- **GNSS integrity:** investigate manipulation and interference, compare
  sufficiently independent observations, represent uncertainty, and distinguish
  inconsistency detection from proof that a position is correct.
- **Privacy and control:** require appropriate permission, precision limits,
  purpose and retention boundaries. Do not automatically share locations, routes,
  photo locations or movement histories, or turn them into public cache/training
  data. Keep private processing within existing protected-execution boundaries.
- **Shared architecture:** build a versioned core service above the existing five
  infrastructure layers, with separate sensor/radio platform adapters. Reuse
  authorized Network, Cache, Storage, Compute and Transaction facilities; DPS is
  not a sixth layer or a payment condition for positioning.
- **Applications:** retain offline Organic Maps navigation and visible uncertainty;
  assess Weather, Image, Chat, Browser, Cloud and other applications on actual
  value. Preserve Signal Protocol, browser/platform permission ceilings, private
  storage, independent weather observations and existing functionality. Unproven
  location claims cannot alone establish financial, identity or voting authority.
- **Verification:** research existing open-source implementations and standards;
  document trust assumptions, faults and resource limits; start with bounded,
  reproducible relative-positioning, fusion and GNSS-integrity trials using
  independent references and controlled fault injection where possible. Keep
  simulation, functioning hardware and measured accuracy improvements distinct.
- **Safety and priorities:** no unauthorized radio scans, GNSS disruption or
  host network/location changes. Schedule DPS by dependencies and system value
  alongside critical integrations; documentation does not complete functionality.

The [dated source archive](DPS_GOAL_20261021.md) preserves both received parts
verbatim. The second part replaces/completes the interrupted Map subsection in
the first; the normative join contains that subsection once. Provenance copies
are not extra requirements or instructions to find a temporary attachment.

### Durable goal and instruction boundaries

This file, its preserved original, every clarification and the incorporated
DPS addition define **agreed functionality**. [AGENTS.md](../../AGENTS.md) defines
engineering, delegation, authority and host-safety rules. The
[implementation ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
records **implemented evidence and the active plan**. A current limitation or
next milestone does not repeal a requirement. Scoped later user amendments
supersede only the earlier terms they explicitly revise; all other terms remain.

Use [PURSUING_GOAL.md](PURSUING_GOAL.md) for the self-contained replacement UI
text and [GOAL_VERIFICATION.md](GOAL_VERIFICATION.md) for reproducible preservation
and completeness checks. A fresh conversation needs only the repository and live
branch/run state; historical attachment paths identify provenance, not dependencies.


### Studio and decentralized hosting addition (2026-10-22)

The entire [STUDIO_HOSTING_REQUIREMENTS.md](STUDIO_HOSTING_REQUIREMENTS.md)
is incorporated as a permanent, normative addition to the complete objective.
It preserves the original goal, every earlier amendment including DPS, all five
infrastructure layers and active integrations. Read its complete ten sections;
this paragraph is navigation, not a substitute or reduced acceptance criterion.

Build shared Core website publishing and hosting through existing signed content,
site packages, names, protected delivery, retention and repair. Integrate Silex as
VOLPAROSSA Studio for portable visual editing, explicit publication, revision and
availability management, and shared decentralized AI through supported adapters
and MCP interfaces. Preserve non-AI editing, private drafts, protected computation,
application permissions, existing relay/exit policy and upstream license obligations.
Static hosting comes first; useful dynamic execution and durable application state
remain required progressive work with their own evidence. Export and conventional
hosting remain explicit alternatives. No editor action or AI result grants publication,
account, domain, certificate, financial or deployment authority.

The [hosting design and audit](../services/STUDIO_HOSTING.md) separates reused
implementation from missing functionality and maps all fifteen acceptance criteria.
The [application scope](../applications/APPLICATIONS.md#studio) and
[execution plan](../IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones)
retain cross-application boundaries and dependency-based priorities. This addition
does not authorize changes to the development host, DNS, accounts or public-site
hosting, and documentation is not functional completion.
