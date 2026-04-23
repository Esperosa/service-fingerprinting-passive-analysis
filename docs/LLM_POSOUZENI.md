# Posouzení LLM / LoRA pro Bakula

## Stručný závěr

Pro tento projekt **nedoporučuji stavět detekční logiku na LLM ani na LoRA modelu natrénovaném na "všech zranitelnostech"**.

Doporučuji:

1. **detekci a enrichment ponechat deterministické**:
   - Nmap / strukturované parsery
   - CPE mapování
   - NVD / CVE / advisory zdroje
   - pravidla a findings vrstvu
2. **LLM případně použít jen jako volitelnou prezentační vrstvu**:
   - sumarizace findings
   - vysvětlení dopadu
   - návrh dokumentace
   - vždy pouze nad doloženým JSON reportem a s citacemi na zdroje

## Proč ne LoRA jako hlavní řešení

### 1. Znalost zranitelností rychle zastarává

Vulnerability knowledge base se mění průběžně. Staticky doladěný model by velmi rychle zastarával a musel by se často přeučovat.

### 2. Potřebujeme citovatelný a auditovatelný výstup

U bezpečnostního reportu je důležité doložit:

- z jakého CPE/CVE/advisory tvrzení vznikl závěr,
- jaká byla verze produktu,
- jaká byla míra jistoty,
- odkud pochází zdroj.

LLM bez striktního grounding mechanismu tuto vlastnost spolehlivě negarantuje.

### 3. Detekce není totéž co textové vysvětlení

To, co Bakula potřebuje jako jádro, je:

- přesná identifikace služby,
- korelace,
- aplikabilita CPE/CVE,
- pravidla nad událostmi,
- reprodukovatelný diff.

To jsou primárně strukturované úlohy. LLM se zde hodí spíše až ve vrstvě vysvětlení.

## Co dává větší smysl než LoRA

### Varianta A: deterministická pipeline + šablonovaná dokumentace

To je nyní implementovaný směr:

- `report.json` jako pravda,
- `report.md` a `report.txt` jako deterministický textový převod,
- findings s evidencí a doporučením.

Výhoda:

- plná auditovatelnost,
- minimální halucinace,
- snadná regresní kontrola.

### Varianta B: RAG nad NVD/CVE/advisories

Pokud se má přidat generativní vrstva, doporučený směr je:

- ne fine-tuning nad "všemi zranitelnostmi",
- ale **RAG** nad:
  - NVD
  - CVE Program
  - vendor advisories
  - interní findings JSON

LLM by pak dostal:

- konkrétní `report.json`,
- konkrétní CVE/reference,
- přesně vybrané advisory texty,
- instrukci, že smí tvrdit jen to, co je ve vstupu.

### Varianta C: malé lokální LLM jen pro shrnutí

Lokální model může mít smysl pro:

- české executive summary,
- vysvětlení findings,
- převod do lidsky čitelné dokumentace.

Nesmí však být zdrojem pravdy pro detekci.

## Doporučená cílová architektura

### Bez LLM v jádru

```text
Nmap / Zeek / Suricata
        ->
normalizace
        ->
CPE / CVE / rules / findings
        ->
report.json
        ->
report.md / report.txt / UI
```

### Volitelná LLM vrstva až nad reportem

```text
report.json + references + advisories
        ->
RAG vrstva
        ->
LLM sumarizace
        ->
"human-readable briefing" s citacemi
```

## Praktické doporučení pro tento projekt

Nejlepší další krok není LoRA model na všech CVE, ale:

1. rozšířit deterministic findings,
2. doplnit advisory retrieval,
3. přidat exporty reportů,
4. případně až potom přidat volitelnou LLM summarizační vrstvu.

## Poznámka k výzkumným zjištěním

Empirické studie nad LLM-based vulnerability detection ukazují, že současné LLM detektory mají při projektovém měřítku stále významné limity v recall, false discovery rate a provozní ceně. To je další důvod, proč je vhodné držet detekční pipeline deterministickou a LLM používat až jako nadstavbu pro interpretaci.
