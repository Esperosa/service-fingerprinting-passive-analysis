# Lokální ověření

Tento soubor shrnuje reálně provedené ověření mimo simulovanou laboratoř.

## Ověřený lokální rozsah

- Wi-Fi rozhraní: `192.168.1.116/24`
- výchozí brána: `192.168.1.1`

## Reálně spuštěný síťový scan

Použitý příkaz:

```powershell
cargo run -- beh spust `
  --workspace .\workspace_local `
  --nazev "Lokalni sitovy scan" `
  --scope 192.168.1.116/32,192.168.1.1/32 `
  --ports 53,80,135,139,443,445,2179,3306,8080,9993,64118 `
  --profile opatrny `
  --provider nvd `
  --spustit-nmap
```

## Co ověření odhalilo

1. Reálný Nmap XML obsahoval `DOCTYPE` a `xml-stylesheet`, což původní parser odmítal.
   - opraveno v `src/nmap.rs`
2. Po opravě parseru proběhl běh end-to-end korektně.
3. Reálný scan našel otevřené služby například:
   - `192.168.1.1`: `53/tcp`, `80/tcp`, `443/tcp`, `8080/tcp`
   - `192.168.1.116`: `135/tcp`, `139/tcp`, `445/tcp`, `2179/tcp`, `3306/tcp`, `8080/tcp`, `9993/tcp`, `64118/tcp`
4. U většiny těchto služeb chyběla přesná verze, takže konzervativní NVD enrichment nevytváří CVE nálezy bez opory ve verzi.
5. Místo toho vznikají konzervativní findings typu:
   - `management_surface_exposure`
   - `identification_gap`

## Výsledek po doplnění findings vrstvy

Přepuštění uloženého reálného Nmap XML přes novou pipeline:

```powershell
cargo run -- beh spust `
  --workspace .\workspace_local_review `
  --nazev "Lokalni sitovy scan po analyze" `
  --scope 192.168.1.116/32,192.168.1.1/32 `
  --ports 53,80,135,139,443,445,2179,3306,8080,9993,64118 `
  --nmap-xml .\workspace_local\tmp\nmap-20260407-185745.xml `
  --provider nvd
```

Souhrn:

- hosté: `2`
- portové záznamy: `22`
- CVE: `0`
- události: `0`
- findings: `13`

Interpretace:

- pipeline se nad reálným výstupem chová korektně,
- při absenci přesné verze raději nevymýšlí CVE,
- přesto vytváří prakticky užitečný seznam exponovaných ploch a míst s identifikační mezerou.

## Ověření NVD API

NVD vrstva byla samostatně ověřena nad známým simulovaným vstupem s jednoznačnými CPE:

```powershell
cargo run -- beh spust `
  --workspace .\workspace_real_api2 `
  --nazev "NVD simulace po filtraci" `
  --scope 192.168.56.0/24 `
  --ports 21,22,23,80,443,8080 `
  --nmap-xml .\workspace\simulace\zakladni\nmap.xml `
  --suricata-eve .\workspace\simulace\zakladni\suricata\eve.json `
  --zeek-dir .\workspace\simulace\zakladni\zeek `
  --provider nvd
```

Tím je ověřeno:

- čerpání z NVD API,
- cachování odpovědí,
- retry/timeout chování,
- promítnutí výsledků do reportu a findings vrstvy.

## Důležitý limit

Lokální scan neobsahuje pasivní vstupy ze Suricata/Zeek, takže zde nelze ověřovat korelaci pasivních událostí. Ta je ověřena na simulovaných scénářích v `workspace/verification/latest.json`.
