# Fingerprinting sluzeb a pasivni analyza sitoveho provozu

Tento repozitar je verejna digitalni priloha bakalarske prace na FIM UHK.
Obsahuje zdrojovy kod prototypu pro korelaci aktivniho inventare sitovych
sluzeb, verejneho kontextu zranitelnosti a vybranych pasivnich udalosti.

Pracovni nazev binarky v kodu je `bakula-program`, ale vecny popis projektu je:
fingerprinting sluzeb a pasivni analyza sitoveho provozu pro detekci
bezpecnostnich hrozeb.

## Co repozitar obsahuje

- Rust CLI a server (`src`, `tests`, `Cargo.toml`, `Cargo.lock`).
- Staticke webove UI a zdrojove TypeScript/CSS soubory (`ui`, `ui-src`).
- Kontrolovane `nuclei` sablony pro nedestruktivni webove kontroly.
- Demo a referencni data pro lokalni overeni.
- Referencni workspace pouzity pri overeni prace: `workspace_thesis_verify_current`.
- Dokumentaci k architekture, workflow, overeni a limitum v adresari `docs`.

Repozitar zamerne neobsahuje:

- build cache (`target`, `node_modules`),
- historicke lokalni workspaces a logy,
- binarni soubory `httpx.exe` a `nuclei.exe`,
- ZIP baliky externich nastroju,
- LaTeX zdroje bakalarske prace.

## Overeny stav

Lokalen byly pred publikaci spusteny tyto kontroly:

```powershell
cargo fmt --check
npm run build:ui
npm run test:ui
cargo test
cargo build --release
```

Vysledek: vsechny kontroly prosly.

## Rychly start

Predpoklady:

- Rust toolchain,
- Node.js a npm,
- volitelne Nmap, ProjectDiscovery httpx/nuclei a Ollama.

Instalace zavislosti a build UI:

```powershell
npm install
npm run build:ui
```

Spusteni testu:

```powershell
cargo test
npm run test:ui
```

Ukazkovy E2E beh:

```powershell
cargo run -- demo e2e --workspace .\workspace
cargo run -- server spust --workspace .\workspace
```

Webove UI je potom dostupne na `http://127.0.0.1:8080`.

## Vazba na bakalarskou praci

Prototyp implementuje technicke jadro popsane v praci:

1. aktivni inventar hostu a sluzeb,
2. mapovani sluzeb na CPE,
3. obohaceni o CVE/CVSS kontext,
4. import pasivnich udalosti ze Suricata EVE JSON a Zeek logu,
5. korelaci udalosti na hosty/sluzby,
6. scoring, nalezy, validacni stopy a triage kroky,
7. auditovatelny report a manifest s kontrolnimi hashi.

Verejny URL repozitare:

```text
https://github.com/Esperosa/service-fingerprinting-passive-analysis
```

## Bezpecnostni vymezeni

Nastroj je urcen pouze pro autorizovana laboratorni, skolni nebo vlastni
prostredi. Aktivni skenovani a webove kontroly mohou byt mimo autorizovany
rozsah neeticke nebo protipravni. Pouzivejte vlastni scope a nedestruktivni
profily.

## Licence

Kod je zverejnen jako soucast akademicke prilohy. Podrobnosti jsou v `LICENSE`.
Externi zavislosti a nastroje maji vlastni licence.
