# Fingerprinting služeb a pasivní analýza síťového provozu

Veřejná softwarová příloha mé bakalářské práce na FIM UHK. Prototyp v Rustu spojuje aktivní inventář služeb, kontext zranitelností a vybrané pasivní síťové události do nálezů, které lze zpětně prověřit.

**Role:** návrh a implementace prototypu, webového rozhraní, testů a ověření vydaného balíčku.  
**Stack:** Rust, Axum, TypeScript/CSS, Nmap, Suricata, Zeek, CPE/CVE/CVSS.  
**Stav:** akademický prototyp a ověřený release; nejde o nasazený produkční SOC nástroj.

## Co projekt řeší

Samotný seznam otevřených portů nevysvětluje, co na nich běží ani které události se k nim vztahují. Projekt proto skládá několik kroků do jedné kontrolovatelné cesty:

1. Inventář hostů a služeb z aktivního zjišťování.
2. Normalizace služeb a přiřazení CPE a veřejného CVE/CVSS kontextu.
3. Import událostí ze Suricata EVE JSON a logů Zeeku.
4. Korelace událostí k hostům/službám, skórování a triage nálezů.
5. Report s validační stopou a manifestem s kontrolními hashi.

Kód je v `src/`, testy v `tests/`, statické UI v `ui/` a jeho zdroje v `ui-src/`. Podrobnější architektura, workflow a limity jsou v [docs](docs/).

## Jak si projekt ověřit

Před zveřejněním prošly lokálně `cargo fmt --check`, `npm run build:ui`, `npm run test:ui`, `cargo test` a `cargo build --release`. Release [`v0.1.0-thesis`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/releases/tag/v0.1.0-thesis) byl navíc ověřen z balíčku staženého z GitHubu: spuštění EXE, demo E2E běh a odpověď serveru na UI a health endpoint. Přesné kroky a hash balíčku jsou v [protokolu ověření](docs/RELEASE_VERIFICATION_2026-04-23.md).

Při každém pushi a pull requestu běží [CI](.github/workflows/ci.yml): `cargo fmt --check`, `cargo clippy` (informativně), `cargo test` a `npm run build:ui`. Šest unit testů, které čtou lokální neveřejný workspace `workspace_fullstack`, je označeno `#[ignore]`; kde tento workspace existuje, spustí se příkazem `cargo test -- --include-ignored`.

### Rychlý start ze zdrojů

Vyžaduje Rust toolchain a Node.js/npm. Nmap a další externí nástroje jsou potřeba jen pro příslušné volitelné scénáře.

```powershell
npm install
npm run build:ui
cargo test
npm run test:ui
cargo run -- demo e2e --workspace .\workspace
cargo run -- server spust --workspace .\workspace
```

Webové UI se poté otevře na `http://127.0.0.1:8080`.

**Pojmenování:** projekt vznikal pod pracovním názvem *Bakula*. Ten zůstává v technických identifikátorech – crate a binárka `bakula-program`, konfigurace `bakula.toml`, ID šablon `bakula-*` a název ZIP balíčku ve vydání – aby odpovídaly ověřenému release `v0.1.0-thesis` a odkazům v práci. Jde o tentýž projekt.

## Rozsah a bezpečnost

Repozitář obsahuje demo a referenční data pro lokální ověření, ale ne historické soukromé workspaces, lokální logy, build cache ani zdrojové texty bakalářské práce. Aktivní skenování používejte jen v prostředí, ke kterému máte oprávnění; šablony pro webové kontroly jsou v `resources/nuclei-templates/controlled/`.

Tento kořenový URL repozitáře je stabilní odkaz uvedený v příloze práce. Zdrojový kód je pod licencí MIT, viz [LICENSE](LICENSE); externí nástroje mají vlastní licence.
