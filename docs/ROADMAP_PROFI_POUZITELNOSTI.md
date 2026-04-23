# Roadmapa profesionalni pouzitelnosti

Tento dokument shrnuje, co zvedne praktickou hodnotu programu vice nez dalsi heuristicke "hadani" a co je realisticky mozne doplnit bez ofenzivnich technik.

## 1. Kde je program dnes slabsi nez Nmap

Aktualni stav je v poradku jako integracni prototyp, ale ne jako plnohodnotny sitovy monitoring:

- inventar je stale dominantne zavisly na Nmap behu,
- chybi autorizovane L2 a Wi-Fi zdroje,
- chybi live flow telemetrie,
- chybi pomaly, credentialed audit konfiguraci a nastaveni,
- chybi dlouhodobe ukladani a trendovani sitoveho chovani.

Proto dnes program nevidi "vic nez Nmap". Realisticka cesta neni nahradit Nmap, ale udelat z nej jednu vrstvu ve vicevrstvem collector stacku.

## 2. Co nejvice zvysi viditelnost site

### 2.1 Asset discovery a topologie

Nejvetsi prinos neprinese dalsi aktivni scan, ale tyto autorizovane zdroje:

- SNMP poller nad switche, routy, firewally a access pointy
- LLDP/CDP/FDP sousedi
- ARP tabulky
- MAC address tables
- DHCP lease exporty
- Wi-Fi controller API

Bez techto zdroju neni korektni tvrdit:

- vsechny access pointy,
- vsechny Wi-Fi klienty,
- fyzickou topologii,
- kam je zarizeni opravdu pripojene.

### 2.2 Live analyza provozu

Pro "antivirus styl" hlidani site je potreba rozdelit vrstvu na:

- IDS/NDR metadata
- flow telemetry
- packet/session retention

Doporuceny stack:

- Suricata pro alerty, TLS/HTTP/DNS/file metadata a oficialni spravu rulesetu
- Zeek pro protocol metadata, `conn.log`, `http.log`, `dns.log`, `ssl.log`, `weird.log`
- ntopng pro live host/flow pohled a behavioralni alerty
- Arkime pro session index a dohledatelny PCAP

### 2.3 Pomalý a presny audit nastaveni

Tady je potreba druha pipeline oddelena od live monitoringu:

- credentialed vulnerability scan
- config collection
- config drift a compliance

Doporucene komponenty:

- Greenbone/OpenVAS pro hlubsi credentialed audit
- NAPALM pro standardizovane getters z network zarǐzeni
- Netmiko nebo scrapli pro vendor-specific SSH read-only sběr
- Wazuh agentless monitoring pro soubory, adresare a konfigurace pres SSH

## 3. Doporucena cilova architektura

### Vrstva A - aktivni inventar

- Nmap jako zakladni discovery a service/version vrstva
- volitelne `httpx` nad potvrzenymi HTTP sluzbami
- volitelne `nuclei` jen nad podepsanymi nebo internimi kontrolovanymi templaty

### Vrstva B - L2/L3/Wi-Fi inventar

- SNMP collector
- LLDP/CDP/FDB/ARP collector
- DHCP lease collector
- Wi-Fi controller connector

### Vrstva C - live monitoring

- Suricata EVE ingest
- Zeek ingest
- ntopng nebo NetFlow/IPFIX ingest
- volitelne Arkime session index

### Vrstva D - hlubsi audit

- Greenbone task orchestration
- credentialed SSH/API config audit
- diff konfiguraci a drift rules

### Vrstva E - inteligence a prioritizace

- NVD
- EPSS
- CISA KEV
- volitelne Vulners
- volitelne CIRCL Vulnerability-Lookup
- volitelne IP/URL reputace

## 4. Co ma smysl implementovat jako dalsi faze v tomto programu

### Faze 1 - aby konecne "videl sit"

1. SNMP modul
   - interface list
   - LLDP/CDP neighbors
   - ARP table
   - MAC table
   - device vendor/model/serial, pokud je dostupny

2. Wi-Fi/controller konektory
   - Meraki Dashboard API
   - UniFi/Omada/Aruba/Meraki podle realneho prostredi
   - AP inventory
   - connected clients
   - SSID/radio/channel/security metadata

3. DHCP a gateway import
   - router/firewall leases
   - DNS cache / resolver logy

Tohle udela vic pro realnou mapu site nez dalsi scan na stanicich.

### Faze 2 - aby "zil" v case

1. Suricata live collector
2. Zeek live collector
3. ntopng / NetFlow / IPFIX collector
4. casove okna, baseline a anomaly engine

Pak pujde delat:

- nove hosty v siti,
- nove otevrene porty,
- zmeny v komunikacnim vzoru,
- dlouhodobe neobvykly odchozi provoz,
- podezrele DNS/TLS/HTTP artefakty.

### Faze 3 - aby presne hodnotil stav zarizeni

1. Greenbone orchestrator
2. read-only config audit konektory
3. compliance pravidla pro sitove prvky
4. diff konfigurace a drift

Pak dostanes druhy rezim:

- "co se zive deje v siti"
- "co je na zarizenich spatne nastaveno"

To jsou dve ruzne discipliny a maji byt oddelene.

## 5. Externi databaze a API

### 5.1 Co program pouziva ted

- NVD CVE API
- lokalni CPE mapovani podle vlastnich pravidel a Nmap evidence
- FIRST EPSS API
- CISA KEV feed
- lokalni demo provider

### 5.2 Co ma vyskou hodnotu doplnit

#### Vulners

Vhodne jako rozsireny provider nad NVD:

- CVE kontext
- exploit references
- vendor advisories
- audit workflow

Pouzit jen jako dalsi zdroj kontextu, ne jako jediny zdroj pravdy.

#### CIRCL Vulnerability-Lookup

Vhodne jako fallback nebo paralelni multi-source lookup:

- vice zdroju nez samotne NVD
- verejne HTTP API
- dumpy

#### AbuseIPDB

Vhodne pro IP reputaci u externich komunikaci:

- check IP
- blacklist feed
- block / network check

Nevhodne jako jediny signal pro blokaci.

#### URLhaus

Vhodne pro:

- zle URL
- malware payload intelligence
- korelaci proxy / DNS / HTTP logu

#### MISP nebo OpenCTI

Vhodne jako lokalni TI bus:

- centralni agregace
- STIX/TAXII / konektory
- interní enrichment vrstva

To je vhodne az ve chvili, kdy budes mit vic feedu a vlastni alerty.

## 6. Doporucene opensource nastroje podle role

### Sitova viditelnost

- Nmap
- LibreNMS
- NAPALM
- Netmiko
- ntopng
- Arkime
- Zeek
- Suricata

### Hlubsi audit

- Greenbone / OpenVAS
- Wazuh agentless monitoring
- `httpx`
- `nuclei`

### Inteligence

- NVD
- EPSS
- CISA KEV
- Vulners
- CIRCL Vulnerability-Lookup
- AbuseIPDB
- URLhaus
- MISP / OpenCTI

## 7. Co je potreba zmenit v samotnem programu

### Dnes

Program je:

- dobry integracni report engine,
- rozumny orchestrator Nmap + enrichment + passive ingest + controlled web checks,
- slusny dashboard nad reportem.

### Aby byl profesionalne pouzitelny

Je potreba pridat:

1. permanentni data store
   - PostgreSQL nebo OpenSearch

2. collector scheduler
   - rychly live loop
   - pomaly audit loop

3. source adapters
   - SNMP
   - LLDP/CDP
   - DHCP
   - Wi-Fi controllers
   - NetFlow/IPFIX
   - Greenbone

4. confidence engine
   - co je potvrzene
   - co je korelace
   - co je jen hint

5. alert policy engine
   - thresholds
   - suppressions
   - maintenance windows
   - deduplikace

6. signed template governance
   - verze templatu
   - podpisy
   - audit trail

## 8. Nejdůležitější praktický zaver

Pokud chces, aby to "videlo co nejvic", neinvestuj dalsi cas do agresivnejsiho scanu z jedne stanice.

Nejvyssi navratnost maji:

1. SNMP + LLDP/CDP + ARP/MAC
2. Wi-Fi controller API
3. Suricata + Zeek + ntopng
4. Greenbone credentialed audit
5. dalsi threat-intel feedy

To je cesta od "wrapperu nad Nmapem" k realne pouzitelnemu sitovemu bezpecnostnimu systemu.

## 9. Odkazy na oficialni zdroje

- NVD Products API: https://nvd.nist.gov/developers/products
- NVD Vulnerabilities API: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV katalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS API: https://api.first.org/data/v1/epss
- Vulners docs: https://docs.vulners.com/
- CIRCL Vulnerability-Lookup: https://vulnerability.circl.lu/
- Zeek quickstart: https://docs.zeek.org/en/master/quickstart.html
- Zeek `conn.log`: https://docs.zeek.org/en/master/reference/logs/conn.html
- Suricata EVE schema: https://docs.suricata.io/en/latest/appendix/eve-schema.html
- Suricata rule management: https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html
- LibreNMS auto-discovery: https://docs.librenms.org/Extensions/Auto-Discovery/
- LibreNMS network map: https://docs.librenms.org/Extensions/Network-Map/
- NAPALM getters: https://napalm.readthedocs.io/en/latest/base.html
- ntopng hosts: https://www.ntop.org/guides/ntopng/basic_concepts/hosts.html
- ntopng flows: https://www.ntop.org/guides/ntopng/user_interface/network_interface/flows/flows.html
- Greenbone python-gvm: https://greenbone.github.io/python-gvm/
- Wazuh agentless monitoring: https://documentation.wazuh.com/current/user-manual/capabilities/agentless-monitoring/how-it-works.html
- ProjectDiscovery `httpx`: https://docs.projectdiscovery.io/opensource/httpx/running
- Nuclei template signing: https://docs.projectdiscovery.io/templates/reference/template-signing
