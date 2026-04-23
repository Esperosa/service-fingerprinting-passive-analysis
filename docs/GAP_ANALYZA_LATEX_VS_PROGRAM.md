# GAP analyza LaTeX specifikace vs. program

Tento soubor shrnuje, co LaTeX dokumentace pozaduje a jak je to pokryto v aktualnim Rust prototypu.

## Shrnuti

- LaTeX popisuje auditovatelny prototyp, ne hotovy bezpecnostni produkt.
- Aktualni program pokryva aktivni inventar, CPE/CVE enrichment, pasivni import, korelaci, diff, findings vrstvu, simulace a automaticke overeni scenaru.
- Zbyvajici mezery se tykaji hlavne produkcniho hardeningu, live sberu, identity/auth vrstvy a hlubsiho CPE/NVD zpracovani.

## Funkcni pozadavky

| Pozadavek z dokumentace | Stav v programu | Poznamka |
|---|---|---|
| Scope, porty, profil behu | Hotovo | `beh spust`, metadata v `report.run` |
| Aktivni inventar hostu a sluzeb | Hotovo | Nmap XML parser + volitelne spusteni realneho Nmap |
| Archiv raw vstupu | Hotovo | `workspace/runs/<run_id>/raw/*` |
| Normalizovany inventar | Hotovo | `report.json` se stabilnimi `host_key` a `service_key` |
| CPE kandidati a prace s nejistotou | Hotovo | `nmap`, `curated`, `partial`, confidence + note |
| CVE/CVSS enrichment z NVD | Hotovo | provider `nvd`, cache, `retrieved_at` |
| Offline/demo enrichment | Hotovo | provider `demo` |
| Freeze rezim | Hotovo | CLI `--freeze` |
| Import Suricata a Zeek | Hotovo | `eve.json`, `notice.log`, `http.log`, `conn.log` |
| Sanitizace pasivnich dat | Hotovo | neuklada payloady ani credentials |
| Korelace `ip+port`, `ip-only`, `unmapped` | Hotovo | explicitne viditelne v reportu |
| Diff mezi behy | Hotovo | `report.diff` |
| Auditovatelny JSON report | Hotovo | schema v `RunReport` |
| Overyovaci scenare a metriky | Hotovo | `simulace generuj` + `overeni spust` + `verification/latest.json` |
| Samostatne interpretovane nalezy | Hotovo | `report.findings` + doporuceni |

## Nefunkcni pozadavky

| Pozadavek z dokumentace | Stav v programu | Poznamka |
|---|---|---|
| Reprodukovatelnost pipeline | Hotovo v ramci prototypu | topologie simulaci je deterministicka podle `seed`, casy jsou relativni k behu kvuli pasivnimu oknu |
| Auditovatelnost a dohledatelnost | Hotovo | raw archiv, metadata behu, cache, findings evidence |
| Minimalizace citlivych dat | Hotovo | zadna hesla, payloady ani tajne klice v reportech |
| Oddeleni externich tajemstvi od kodu | Hotovo | `NVD_API_KEY` z prostredi |
| Transparentnost nejistoty | Hotovo | confidence, method, partial CPE, correlation uncertainty |
| Produkcni nasaditelnost | Castocne | program je produkcne pripraveny jako prototyp, ne jako hotovy viceuzivatelsky system |

## Co bylo proti puvodni demonstracni verzi doplneno

- `report.findings` s typy jako `high_risk_cve_exposure`, `plaintext_management_protocol`, `http_basic_without_tls`, `unexpected_traffic`, `new_exposed_service`.
- `verification/latest.json` a CLI `overeni spust`.
- Manifesty scenaru s automatickymi kontrolami poctu hostu, sluzeb, CVE, udalosti a diff zmen.
- Nahodny generator laboratornich scenaru podle `seed`.
- UI sekce pro nalezy a stav posledniho automatickeho overeni.
- Robustnejsi NVD klient s timeoutem a zakladnim retry/backoff chovanim.

## Co je porad mimo rozsah

- Live packet sensor a dlouhodoby streaming dat.
- Distribuovane planovani skenu, fronty, worker pool.
- Centralni databaze a migrace schemat.
- Autentizace, autorizace a audit uzivatelu v UI.
- TLS terminace a hardening webove vrstvy pro verejne nasazeni.
- Plnohodnotny Vulners provider.
- Hloubkove vyhodnoceni exploitability nad konfiguraci hostu.

## Prakticky zaver

Podle LaTeX dokumentace je aktualni stav poctive dokoncen jako end-to-end prototyp:

1. umi sesbirat data,
2. umi je korelovat,
3. umi je interpretovat do nalezu,
4. umi se otestovat nad simulovanymi scenari,
5. umi vysledky zverejnit pres CLI, JSON a UI.

Neni korektni tvrdit, ze jde o hotovy SOC produkt bez dalsiho hardeningu. Je korektni tvrdit, ze jde o komplexni, otestovany a dal rozsiritelny zaklad implementace podle dokumentace.
