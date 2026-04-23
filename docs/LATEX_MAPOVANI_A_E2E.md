# Mapování LaTeX požadavků na implementaci

## Co z LaTeXu musí prototyp umět

Z textu bakalářské práce vyplývají zejména tyto závazné body:

1. opakovatelný aktivní inventář hostů a služeb,
2. oddělený enrichment přes veřejná vulnerability data,
3. pasivní import a korelace událostí,
4. jednotný auditovatelný report nad `run_id`,
5. stabilní klíče `host_key` a `service_key`,
6. diff mezi běhy,
7. explicitní přiznání nejistoty,
8. řízené ověřovací scénáře,
9. srozumitelný výstup pro orientaci a priorizaci,
10. důsledné oddělení prototypu od tvrzení o stoprocentní detekci.

## Kde je to v programu

### Aktivní inventář

- `src/nmap.rs`
- `src/report.rs`
- `src/main.rs`

Plní:
- discovery a řízený Nmap běh,
- parsování XML,
- normalizaci do interního modelu,
- stabilní `host_key` / `service_key`.

### Enrichment o zranitelnosti

- `src/cpe.rs`
- `src/vuln.rs`

Plní:
- CPE kandidáty,
- NVD dotazy,
- `freeze/live` režim přes cache,
- CVE/CVSS metadata,
- doplněný exploit kontext přes EPSS a CISA KEV.

### Pasivní část

- `src/passive/*`
- `src/correlation.rs`

Plní:
- import Suricata EVE JSON,
- import Zeek logů,
- normalizaci do jednotného schématu,
- korelaci `ip+port`, `ip-only`, `unmapped`.

### Jednotný report a diff

- `src/model.rs`
- `src/diff.rs`
- `src/storage.rs`
- `src/narrative.rs`

Plní:
- `report.json`,
- `report.md`,
- `report.txt`,
- raw archivaci zdrojů,
- diff mezi běhy,
- auditovatelnou vazbu na zdroje a zjištění.

### Ověření scénářů

- `src/simulation.rs`
- `src/verification.rs`
- `tests/e2e.rs`

Plní:
- deterministické scénáře,
- náhodně generované laboratorní dvojice,
- automatické vyhodnocení očekávání.

### Srozumitelný výstup a UI

- `src/server.rs`
- `ui/index.html`
- `ui/app.js`
- `ui/styles.css`

Plní:
- přehled běhů,
- souhrn,
- topologii host -> služba,
- drilldown na službu,
- findings,
- diff,
- detail CVE,
- detail HTTPX a nuclei.

## Co bylo doplněno nad původní minimum z LaTeXu

Navíc oproti základnímu rozsahu práce je implementováno:

1. `httpx` modul
   - řízený L7 fingerprinting jen nad HTTP službami z inventáře,
   - title, status, server, content type, content length, response time, favicon/hash hints, základní web hints.

2. `nuclei` modul
   - ne nad cizími rozsáhlými šablonami,
   - ale nad lokální kontrolovanou sadou templátů:
     - Basic auth over HTTP,
     - Prometheus metrics exposed,
     - Swagger UI exposed,
     - Directory listing exposed.

3. lokální živá webová laboratoř
   - `scripts/web_lab.py`
   - slouží pro reálný end-to-end běh a viditelné UI demo.

## Co stále není korektní tvrdit

Ani po rozšíření není korektní tvrdit, že prototyp:

- zjistí vše, co je v síti,
- spolehlivě potvrdí každou zranitelnost,
- nahradí SIEM/IDS/VM platformu,
- poskytuje kvantifikovanou přesnost pro libovolné prostředí,
- má plnohodnotný live pasivní sensor s dlouhodobým sběrem.

To je v souladu s LaTeX textem, který výslovně vymezuje řešení jako `proof-of-concept`.

## Reálně ověřený viditelný E2E běh

Na tomto stroji byl ověřen běh nad lokální webovou laboratoří:

- scope: `127.0.0.1/32`
- porty: `18080,18081,18082,18083,18084`
- pipeline:
  - Nmap,
  - HTTPX,
  - nuclei,
  - report,
  - UI server.

Výstup:

- workspace: `workspace_web_lab3`
- run id: `run-20260408064939-1-f232021bf44d44a093ae3bc62bdcd3e3`
- hosty: `1`
- služby: `5`
- HTTPX probe: `5`
- active checks: `4`
- findings: `4`

Detekované kontrolované nálezy:

- `bakula-basic-auth-over-http`
- `bakula-prometheus-metrics-exposed`
- `bakula-swagger-ui-exposed`
- `bakula-directory-listing-exposed`

UI server byl spuštěn nad:

- `http://127.0.0.1:8093/`

## Další doporučený krok

Z hlediska návaznosti na LaTeX je další logický krok:

1. přidat volitelnou archivaci referenčních živých běhů,
2. rozšířit HTTPX vrstvu o řízený TLS fingerprinting a favicon clustering,
3. přidat další lokální nuclei templaty pouze tam, kde mají jasný auditní smysl,
4. nechat heuristické web hints vždy oddělené od vysokojistotních findings.
