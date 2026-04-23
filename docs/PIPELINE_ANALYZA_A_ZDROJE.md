# Pipeline: analýza, limity a doporučené zdroje

## Co pipeline dělá nyní

Aktuální pipeline pracuje ve čtyřech krocích:

1. Aktivní inventář
   - načte Nmap XML nebo spustí Nmap,
   - normalizuje hosty, porty, služby a detekční jistotu.

2. Identita služby
   - převezme přímo nalezené CPE z Nmap,
   - doplní kurátorované mapování z lokálních pravidel,
   - při absenci přesné identity vytvoří jen částečný kandidát a současně nechá ve výstupu identifikační mezeru.

3. Internetový enrichment
   - NVD CVE API pro mapování CVE k CPE,
   - FIRST EPSS API pro pravděpodobnostní priorizaci,
   - CISA KEV feed pro ověření, zda je CVE veřejně doložené jako aktivně zneužívané.

4. Korelace a rozhodování
   - spojí pasivní události se službami,
   - dopočítá skóre a prioritu služby,
   - vytvoří findings a textový report s auditovatelnou evidencí.

## Co bylo doplněno oproti původní verzi

- `exploit_context` u CVE záznamu:
  - EPSS score,
  - EPSS percentile,
  - CISA KEV status a metadata.
- findings navíc rozlišují:
  - běžné vysoké CVSS,
  - známou exploataci v praxi,
  - zvýšený pravděpodobnostní zájem útočníků.
- report JSON, Markdown i text nyní ukazují, jestli je CVE jen v NVD, nebo má i reálnější exploit kontext.
- UI zobrazuje EPSS a KEV přímo v detailu CVE.

## Co pipeline neumí a nemá předstírat

Pipeline neumí "zjistit vše". To není technicky ani metodicky reálné.

Nejde poctivě slíbit:

- přesnou identitu služby bez banneru, verze nebo autentizovaného přístupu,
- úplné zachycení všech hrozeb v síti bez dostatečné senzorové viditelnosti,
- úplný výčet CVE jen z neúplné nebo neurčité identity produktu,
- důkaz kompromitace pouze z CVSS nebo EPSS,
- bezpečné rozhodnutí "jen podle malých náznaků", pokud není zachovaná důkazní stopa.

Správný cíl pipeline je jiný:

- maximalizovat kvalitní kandidáty,
- oddělit jisté závěry od heuristik,
- držet evidenci k původu každého tvrzení,
- priorizovat ruční ověření tam, kde je automatika nejednoznačná.

## Největší praktické slabiny, které zůstávají

1. Neúplná identita služby
   - Pokud Nmap nevrátí produkt nebo verzi, pipeline je správně konzervativní.
   - To snižuje přesnost CPE i CVE enrichmentu.

2. Šum v NVD
   - I po filtrování podle CPE konfigurací může NVD vracet široké množiny CVE pro daný produkt nebo verzi.
   - EPSS a KEV pomáhají s prioritou, ale neřeší samy o sobě falešnou pozitivitu.

3. Pasivní vrstva je stále dávková
   - Importuje Suricata/Zeek logy, ale není to zatím dlouhodobě běžící senzor a streamovací korelace.

4. Chybí aplikační fingerprinting
   - U webových služeb dnes pipeline neprovádí hlubší HTTP/TLS fingerprinting, favicon fingerprinting ani kurátorovanou detekci frameworků.

## Doporučené open-source vrstvy pro další rozvoj

### Vrstvy, které dávají technický smysl

1. `httpx`
   - pro HTTP title, headers, TLS a základní web fingerprinting,
   - vhodné jako navazující krok jen na porty, které aktivní inventář vyhodnotí jako HTTP/HTTPS.

2. `nuclei`
   - pro kurátorované ověření konkrétních slabin po vysokojistotní identifikaci služby,
   - nemá nahrazovat inventář; má být až nad ním.

3. `Suricata`
   - pro síťové alerty a EVE JSON,
   - vhodná pro kontinuální pasivní vrstvu.

4. `Zeek`
   - pro detailní kontext síťového chování a protokolových logů,
   - důležité pro korelaci a auditní vysvětlení findings.

5. `Nmap`
   - zůstává základním aktivním zdrojem identity služby.

### Vrstvy, které přidávat opatrně

1. `masscan` nebo `rustscan`
   - dávají smysl pro rychlé předvýběry, ale bez následné validace mohou zvyšovat šum.

2. fingerprinting přes ML/LLM
   - vhodný jen jako pomocná sumarizační nebo asistenční vrstva,
   - ne jako primární zdroj pravdy pro detekci zranitelnosti.

## Profesionální další kroky

Nejvyšší návratnost mají tyto kroky:

1. Přidat HTTP/TLS fingerprinting vrstvu
   - title, server header, certificate subject/SAN, favicon hash, redirect chain.

2. Zavést řízený online CPE lookup
   - pouze pro služby s produktem a verzí,
   - s přísným skórováním kandidátů,
   - bez automatického přijetí nejednoznačných výsledků.

3. Přidat volitelný `nuclei` krok
   - jen pro služby s vysokou jistotou identity,
   - oddělit evidenci "fingerprint", "advisory match" a "active check".

4. Přidat pasivní TLS fingerprinting
   - JA3/JA4 nebo obdobné signály tam, kde je k dispozici senzor.

5. Oddělit rizikové vrstvy ve skóre
   - identita,
   - exposure,
   - public exploit context,
   - pasivní anomálie,
   - změna mezi běhy.

## Doporučení k LLM

LLM je vhodné použít pouze jako volitelnou vrstvu pro:

- sumarizaci findings,
- přirozený text reportu,
- vysvětlení vztahu mezi více CVE a jednou službou.

LLM není vhodné použít jako zdroj pravdy pro:

- potvrzení verze produktu,
- přiřazení CVE bez doloženého CPE nebo advisory,
- rozhodnutí o kompromitaci,
- automatické tvrzení, že systém "zjistil vše".

## Shrnutí

Největší posun kvality nepřinese agresivnější heuristika, ale lepší evidence:

- přesnější identita služby,
- širší, ale auditovatelný enrichment,
- jasné oddělení jistých a heuristických závěrů,
- lepší priorizace pomocí KEV a EPSS,
- postupné doplnění specializovaných open-source nástrojů na správném místě pipeline.
