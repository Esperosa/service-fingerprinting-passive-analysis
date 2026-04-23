# Specifikace a stav

## Cíl

Vytvořit běžící prototyp, který spojí:

1. aktivní inventář hostů a služeb,
2. obohacení o veřejné vulnerability informace,
3. pasivní bezpečnostní události,
4. korelaci a auditovatelný report,
5. UI v češtině.

## Zvolená architektura

- Jádro: Rust
- Rozhraní: CLI + webové UI přes Axum
- Uložení dat: souborový workspace s JSON reporty a raw archivem
- Simulace: generátor vstupů Nmap XML, Suricata EVE JSON a Zeek logů

## Funkční rozsah

- [x] Načtení Nmap XML a normalizace inventáře
- [x] Volitelné spuštění reálného Nmap skenu
- [x] CPE kandidáti z Nmap i kurátorovaných pravidel
- [x] Provider `demo` pro offline testy
- [x] Provider `nvd` pro online dotazy
- [x] Cache dotazů podle CPE
- [x] Režim `freeze`
- [x] Import Suricata alertů
- [x] Import Zeek `notice.log`, `http.log`, `conn.log`
- [x] Heuristika `HTTP Basic bez TLS`
- [x] Heuristika `plaintext protocol`
- [x] Heuristika `unexpected_traffic`
- [x] Korelace `ip+port`, `ip-only`, `unmapped`
- [x] Výpočet priority služby
- [x] Samostatná vrstva nálezů s evidencí a doporučením
- [x] JSON report se souhrnem, hosty, službami, CVE a událostmi
- [x] Diff mezi dvěma běhy
- [x] Webové UI v češtině
- [x] Generátor simulovaného prostředí
- [x] Náhodné scénáře s deterministickou topologií podle `seed`
- [x] Manifesty scénářů a automatické ověření nad sadou běhů

## Otevřená rozšíření mimo první verzi

- [ ] Přesnější CPE matching proti oficiálnímu CPE API
- [ ] Import dalších Zeek logů (`ssl.log`, `dns.log`)
- [ ] Jemnější práce s NVD rate limitingem a retry politikou
- [ ] Uživatelské přihlašování do UI
- [ ] Export HTML/PDF reportu
- [ ] Dlouhodobý live collector místo batch importu logů
- [ ] Pokročilejší pravidla a výjimky pro korelaci

## Zásady poctivosti vůči zadání

- Program netvrdí potvrzenou kompromitaci.
- CVE jsou použita pro priorizaci, ne jako důkaz zneužití.
- Pasivní část neukládá payloady ani credentials.
- Simulace je označená jako simulace a slouží k testům pipeline.
- Produkční připravenost zde znamená poctivě dokončený prototyp s testy a verifikací, ne hotový SOC produkt pro bezobslužné nasazení.
