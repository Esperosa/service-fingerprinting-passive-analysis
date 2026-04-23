# Analýza pipeline a autopilota

## Co program skutečně používá

Aktivní vrstva:
- `nmap` baseline inventář (`-Pn -sV`)
- `nmap` cílený follow-up nad nejasnými nebo zajímavými službami
- `nmap` forenzní follow-up nad prioritními cíli (`banner,http-title,http-headers,ssl-cert,ssh-hostkey,smb-os-discovery`)
- `httpx` pro HTTP/TLS fingerprinting
- `nuclei` nad lokálními řízenými templaty

Pasivní a live vrstva:
- import `Suricata EVE`
- import `Zeek notice/http/conn`
- snapshot `ntopng`
- snapshot `NetFlow/IPFIX`

Autorizovaný kontext:
- `SNMP/LLDP/CDP/ARP/FDB/VLAN` snapshot
- `LibreNMS`
- `Meraki`
- `UniFi`
- `Aruba`
- `Omada`

Auditní vrstva:
- `Greenbone/OpenVAS`
- `Wazuh`
- `NAPALM`
- `Netmiko`
- `scrapli`

Enrichment a intel:
- `NVD` / lokální `demo` provider
- doplňkově `Vulners`
- `CIRCL Vulnerability-Lookup`
- `URLhaus`
- `AbuseIPDB`

## Co bylo mělké a co je teď opravené

Původní běh byl lineární:
1. baseline inventář
2. volitelný follow-up
3. enrichment
4. report

To nestačilo pro opakované zpřesňování a prokazatelnou orchestrace.

Teď je pipeline vícekroková:
1. baseline inventář
2. cílený follow-up identity
3. průběžné score a výběr prioritních cílů
4. forenzní follow-up nad vybranými hosty/porty
5. znovuvýpočet CPE/CVE/web vrstvy nad zpřesněným inventářem
6. korelace pasivních/live/audit/context lane
7. finální report

Nad tím běží `autopilot`, který:
- umí periodické cykly
- automaticky zapíná hlubší ověření
- ukládá samostatný `automation/latest.json`
- dopočítává coverage a identity ratio
- modeluje interní agenty jako auditovatelnou vrstvu:
  - `planner`
  - `inventory`
  - `live-observer`
  - `forensic`
  - `correlator`
  - `intel`

## Důkazní běhy

### Reálný live autopilot

Workspace:
- `workspace_real_autopilot_live`

Hlavní artefakty:
- `workspace_real_autopilot_live/runs/run-20260409145211-1-623bc4f7002b4c17b9769905a694746b/report.json`
- `workspace_real_autopilot_live/automation/latest.json`

Souhrn:
- `21` hostů
- `289` služeb
- `13` web probe záznamů
- `1` potvrzený aktivní web check
- `15` findings
- `3` automatizační kola uvnitř jednoho běhu (`baseline + follow-up + forensic`)
- `tooling_coverage_ratio = 0.86`
- `service_identity_coverage_ratio = 1.00`

Reálně proběhly i surové artefakty:
- `raw/nmap.xml`
- `raw/nmap-followup.xml`
- `raw/nmap-forensic.xml`
- `raw/httpx.jsonl`
- `raw/nuclei.jsonl`

### Full-stack autopilot nad bohatými snapshoty

Workspace:
- `workspace_autopilot_fullstack2`

Hlavní artefakt:
- `workspace_autopilot_fullstack2/automation/latest.json`

Souhrn:
- `cycles_total = 2`
- `tooling_coverage_ratio = 1.00`
- `service_identity_coverage_ratio = 1.00`

Tento běh potvrzuje, že pokud jsou k dispozici live, auditní a context zdroje, autopilot je skutečně zapojí do jedné koordinované pipeline, ne jen jako izolované importy.

## Co teď platí o automatizovaném běhu

- Jednorázový scan už není jediný mechanismus.
- Forenzní zpřesnění je samostatná fáze s vlastním XML artefaktem.
- Coverage se měří podle skutečně vykonaných capability, ne podle toho, zda zrovna vznikl nález.
- Replay běhy nejsou falešně penalizovány za to, že neprovádějí live follow-up.
- Live a auditní zdroje se promítají do lane, findings, triage i automation reportu.
