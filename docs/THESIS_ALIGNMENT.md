# Soulad s primarni myslenkou bakalarske prace

Tento dokument shrnuje, zda aktualni program odpovida primarni myslence bakalarske prace:

> fingerprinting sluzeb a pasivni analyza sitoveho provozu pro detekci bezpecnostnich hrozeb v lokalni siti, s jednotnym auditovatelnym reportem a poctivym vymezenim nejistoty.

## Primarni osa bakalarske prace

Z LaTeX textu vyplyva, ze jadro reseni ma byt:

1. opakovatelna aktivni inventarizace hostu a sluzeb,
2. obohaceni pres verejne vulnerability zdroje,
3. pasivni pozorovani vybranych bezpecnostnich jevu,
4. korelace obou vetvi do jednoho reportu,
5. diff mezi behy,
6. overeni na rizenych scenarich,
7. poctive priznani limitu.

Soucasne je v textu prace explicitne uvedeno, ze:

- nejde o univerzalni enterprise platformu,
- nejde o nastroj, ktery "zjisti vse",
- nejde o system, ktery sam potvrzuje zneuzitelnost hostu,
- pasivni cast je omezena viditelnosti senzoru,
- CVE/CPE mapovani slouzi pro priorizaci a dalsi overeni, ne jako definitivni dukaz zranitelnosti.

## Stav programu vuci teto ose

### 1. Aktivni inventar

Splneno.

- `src/nmap.rs`
- `src/report.rs`
- `src/main.rs`

Program umi opakovatelny inventar hostu a sluzeb, stabilni `host_key` a `service_key`, archivaci raw vstupu a diff mezi behy.

### 2. Vulnerability enrichment

Splneno.

- `src/cpe.rs`
- `src/vuln.rs`

Program oddeluje fingerprinting od enrichmentu a uklada zdroj, cas stazeni, kandidaty i nejistotu mapovani.

### 3. Pasivni cast

Splneno v rozsahu bakalarskeho prototypu.

- `src/passive/*`
- `src/correlation.rs`

Program umi import Suricata a Zeek, normalizaci, korelaci `ip+port`, `ip-only`, `unmapped`, a explicitni priznani nizke jistoty.

### 4. Jednotny report

Splneno.

- `src/storage.rs`
- `src/narrative.rs`
- `src/report.rs`

Vznikaji `report.json`, `report.md`, `report.txt`, `manifest.json` a diff.

### 5. Overyovaci scenare

Splneno.

- `src/simulation.rs`
- `src/verification.rs`
- `tests/e2e.rs`

Program umi deterministicke scenare a automaticke vyhodnoceni ocekavani.

### 6. UI a interpretace

Splneno jako pomocna vrstva nad reportem.

- `src/server.rs`
- `ui/*`

UI je nadstavba nad reportem, ne samostatny zdroj pravdy. To je v souladu s bakalarskou praci, kde je hlavnim artefaktem auditovatelny report.

## Co bylo potreba vycistit

Po rozsirovani o platformni a enterprise vrstvu vznikl dojem, ze program smeruje k obecne orchestrace a ze to je hlavni ucel. To neodpovida primarni myslence prace.

Proto bylo upraveno:

- README nyní stavi thesis core pred platformnimi funkcemi,
- dokumentace explicitne oddeluje jadro prototypu od volitelnych provoznich rozsireni,
- spousteci postup pro reprezentativni thesis-aligned beh je uveden samostatne.

## Co je navic oproti bakalarske praci

Nad ramec jadra jsou k dispozici:

- controlled `httpx` a `nuclei` vrstva,
- findings a triage vrstva,
- RBAC a platformni DB,
- Redis broker,
- externi PostgreSQL control-plane backend,
- rolling upgrade policy a cluster metadata.

Tato vrstva neni v rozporu s bakalarskou praci, pokud je interpretovana jako navazujici rozsireni a ne jako nova hlavni osa projektu.

## Zavěr

Aktualni program odpovida primarni myslence bakalarske prace tehdy, kdyz je pouzivan predevsim jako:

- aktivni inventar + vulnerability enrichment + pasivni korelace + jednotny report + overeni scenaru.

Tomuto pouziti odpovida doporuceny beh:

```powershell
cargo run -- demo e2e --workspace .\workspace
cargo run -- overeni spust --workspace .\workspace --scenare .\workspace\simulace --provider demo
cargo run -- server spust --workspace .\workspace
```

Pokud by byl program prezentovan hlavne jako cluster orchestrator nebo univerzalni network manager, s bakalarskou praci by se rozchazel. V aktualnim stavu tomu tak neni; thesis core je zachovano a v dokumentaci je znovu postaveno na prvni misto.
