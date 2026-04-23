# Produkcni dotazeni aktualni verze

Tento dokument shrnuje, co bylo doplneno nad puvodni thesis core prototyp tak, aby nasazeni bylo provoznejsi, auditovatelnejsi a blizsi pozadavkum z LaTeX specifikace, aniz by se ztratil hlavni smysl programu.

## Co bylo dotazeno

### 1. Provozni konfigurace

- `bakula.toml` ma jednotny model `AppConfig`
- konfigurace se umi vytvorit i validovat prikazy:
  - `cargo run -- config init --path <soubor>`
  - `cargo run -- config validate --path <soubor>`
- doplneny byly produkcni bloky:
  - `retention.max_runs`
  - `retention.keep_raw`
  - `security.require_api_token`
  - `security.api_token_env`

### 2. Ochrana API

- UI/API server umi bezet v rezimu s povinnym tokenem
- podporovane hlavicky:
  - `Authorization: Bearer <token>`
  - `X-API-Key: <token>`
- UI si umi token vyzadat a znovu pouzit z `localStorage`

### 3. Auditovatelne ulozeni kazdeho behu

Kazdy beh nově obsahuje:

- `report.json`
- `report.md`
- `report.txt`
- `manifest.json`

`manifest.json` obsahuje:

- relativni cesty souboru v run adresari
- velikost souboru
- `SHA-256` hash

Tím je mozne zpetne dokazat, s jakymi artefakty se pracovalo a zda se nezmenily.

### 4. Retencni politika

Po ulozeni runu se uplatni retencni pravidla:

- maximalni pocet runu v `retention.max_runs`
- volitelne odkladani nebo odmazani `raw` artefaktu pres `retention.keep_raw`

To je potreba pro dlouhodobejsi provoz, aby workspace nerostl bez kontroly.

### 5. Serverove provozni endpointy

Vedle stavajicich API jsou k dispozici:

- `/api/health`
- `/api/ready`
- `/api/meta`
- `/api/metrics`

`/api/metrics` vraci Prometheus-friendly metriky pro pocet behu a souhrnove objemy dat.

### 6. Centralni platformni vrstva

Nad thesis core je doplneno:

- centralni SQLite backend pro uzivatele, tokeny, joby a nody,
- RBAC role `admin`, `operator`, `analyst`, `viewer`,
- distribuovana job fronta s lease claimy,
- cluster metadata, quorum policy a rolling upgrade plan,
- oddeleny Redis Streams durable queue broker,
- externi PostgreSQL control-plane backend.

Tato vrstva rozsiruje provozni pouzitelnost, ale nenahrazuje hlavni thesis osu programu.

## Co tim jeste nevzniklo

Aktualni verze je vyrazne provoznejsi nez puvodni prototyp, ale porad z ni poctive neni:

- plne cloud-native orchestracni platforma s automatickym self-healingem,
- runtime Axum server trvale napojeny primo na PostgreSQL bez SQLite fallbacku,
- dlouhodoby multi-senzorovy streaming backend s centralni TSDB,
- multi-tenant prostredi a rozsahle provozni governance,
- nastroj, ktery by nahrazoval SIEM/IDS/VM ekosystem v plnem rozsahu.

## Soulad s bakalarskou praci

Tato vrstva je v souladu s textem bakalarske prace v tom, ze:

- zachovava auditovatelny report a zdrojove artefakty,
- nepretvari heuristiky za jiste vysledky,
- rozviji prototyp smerem k realnejsimu provozu,
- ale netvrdi, ze tim byl prokazan univerzalni enterprise-grade provoz bez dalsi validace.

Primarni myslenka bakalarske prace zustava stejna:

- aktivni inventar,
- vulnerability enrichment,
- pasivni korelace,
- jednotny report,
- overeni na rizenych scenarich.
