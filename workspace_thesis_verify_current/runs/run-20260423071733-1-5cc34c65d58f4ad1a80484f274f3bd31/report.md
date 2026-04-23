# Zakladni scenar

## Souhrn

- ID běhu: `run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31`
- Rozsah: 192.168.56.0/24
- Profil: `demo`
- Provider: `demo` (live)
- Hosté: 3
- Služby: 6
- CVE: 6
- Události: 8
- Události bez vazby na inventář: 0
- Nálezy: 17

## Nálezy

### Na službě 192.168.56.30/host-only je zvýšený výskyt timeout/retry provozu [střední / nízká jistota]

- Typ: `connection_timeout_burst`
- Cíl: 192.168.56.30/host-only
- Důvod: Pasivní vrstva zachytila opakované timeouty/retry stavy, které často doprovází přetížení, nestabilní cestu nebo agresivní skenovací vzor.
- Doporučení: Prověřit limity služby, fronty, firewall a transportní retry chování. Pokud jde o útok nebo burst sken, dočasně aplikovat přísnější rate limit a segmentaci.
- Evidence:
  - service_key=192.168.56.30/host-only
  - service_name=host-only
  - product=Korelace pouze na uroven hosta | version=- | port_state=n/a
  - zeek | connection_timeout_burst | ip-only | Spojeni vykazuje timeout/retry tlak (ratio 0.67, timeout_like 2, celkem 3).

### Korelace pro 192.168.56.30/host-only obsahuje události s nižší jistotou [nízká / nízká jistota]

- Typ: `correlation_uncertainty`
- Cíl: 192.168.56.30/host-only
- Důvod: Část událostí byla přiřazena pouze na úrovni hostu nebo zůstala neúplně mapována; to je z metodického hlediska korektní, ale snižuje přesnost závěru.
- Doporučení: Rozšířit viditelnost senzoru, doplnit portový kontext nebo kurátorované korelační výjimky tam, kde je vazba opakovaně nejednoznačná.
- Evidence:
  - unexpected_traffic | ip-only | Pozorovan provoz na port 3306, ktery neni v aktivnim inventari jako otevrena sluzba.
  - connection_timeout_burst | ip-only | Spojeni vykazuje timeout/retry tlak (ratio 0.67, timeout_like 2, celkem 3).
  - packet_rate_spike | ip-only | Pozorovan prudky narust rychlosti paketu (max_pps 6833, max_bps 3333333, timeout_ratio 0.67).
  - service_overload_risk | ip-only | Kombinace vysokych rychlosti, retry a zatizeni ukazuje na riziko pretizeni sluzby (votes 2, max_pps 6833).

### Služba 192.168.56.10/tcp/443 obsahuje zranitelnosti s vysokou prioritou [vysoká / vysoká jistota]

- Typ: `high_risk_cve_exposure`
- Cíl: 192.168.56.10/tcp/443
- Důvod: Nejvyšší nalezené CVSS je 9.8; výstup slouží jako podklad pro priorizaci a další ověření.
- Doporučení: Ověřit skutečnou verzi a konfiguraci služby proti vendor advisory, naplánovat patch nebo kompenzační opatření a případně omezit síťovou expozici.
- Evidence:
  - service_key=192.168.56.10/tcp/443
  - cpe=cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:* | method=nmap | confidence=High
  - CVE-2021-41773 | CVSS 3.1 7.5
  - CVE-2021-42013 | CVSS 3.1 9.8

### Služba 192.168.56.10/tcp/80 obsahuje zranitelnosti s vysokou prioritou [vysoká / vysoká jistota]

- Typ: `high_risk_cve_exposure`
- Cíl: 192.168.56.10/tcp/80
- Důvod: Nejvyšší nalezené CVSS je 9.8; výstup slouží jako podklad pro priorizaci a další ověření.
- Doporučení: Ověřit skutečnou verzi a konfiguraci služby proti vendor advisory, naplánovat patch nebo kompenzační opatření a případně omezit síťovou expozici.
- Evidence:
  - service_key=192.168.56.10/tcp/80
  - cpe=cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:* | method=nmap | confidence=High
  - CVE-2021-41773 | CVSS 3.1 7.5
  - CVE-2021-42013 | CVSS 3.1 9.8

### Služba 192.168.56.30/tcp/22 obsahuje zranitelnosti s vysokou prioritou [střední / vysoká jistota]

- Typ: `high_risk_cve_exposure`
- Cíl: 192.168.56.30/tcp/22
- Důvod: Nejvyšší nalezené CVSS je 8.8; výstup slouží jako podklad pro priorizaci a další ověření.
- Doporučení: Ověřit skutečnou verzi a konfiguraci služby proti vendor advisory, naplánovat patch nebo kompenzační opatření a případně omezit síťovou expozici.
- Evidence:
  - service_key=192.168.56.30/tcp/22
  - cpe=cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:* | method=nmap | confidence=High
  - CVE-2023-38408 | CVSS 3.1 8.8

### Na službě 192.168.56.10/tcp/80 byla pozorována autentizace bez TLS [vysoká / vysoká jistota]

- Typ: `http_basic_without_tls`
- Cíl: 192.168.56.10/tcp/80
- Důvod: Použití HTTP Basic bez šifrovaného kanálu vystavuje přihlašovací údaje odposlechu.
- Doporučení: Vynutit TLS, odstranit Basic autentizaci na HTTP endpointu nebo ji přesunout za reverzní proxy s TLS terminací a silnějším ověřením.
- Evidence:
  - service_key=192.168.56.10/tcp/80
  - service_name=http
  - product=Apache httpd | version=2.4.49 | port_state=open
  - suricata | http_basic_without_tls | ip+port | HTTP Basic credentials over plaintext channel
  - zeek | http_basic_without_tls | ip+port | HTTP pozorovani: /login

### Externí intel vrstva vrátila shodu pro T1040 [nízká / střední jistota]

- Typ: `intel:mitre-att&ck-context`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - https://attack.mitre.org/techniques/T1040/
  - status=analytical-context

### Externí intel vrstva vrátila shodu pro T1049 [nízká / střední jistota]

- Typ: `intel:mitre-att&ck-context`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - https://attack.mitre.org/techniques/T1049/
  - status=analytical-context

### Externí intel vrstva vrátila shodu pro CVE-2021-3618 [nízká / vysoká jistota]

- Typ: `intel:osv.dev`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - https://alpaca-attack.com/
  - https://lists.debian.org/debian-lts-announce/2022/11/msg00031.html
  - https://bugzilla.redhat.com/show_bug.cgi?id=1975623
  - status=referenced

### Externí intel vrstva vrátila shodu pro CVE-2021-41773 [nízká / vysoká jistota]

- Typ: `intel:osv.dev`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-41773
  - https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WS5RVHOIIRECG65ZBTZY7IEJVWQSQPG3/
  - https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-httpd-pathtrv-LAzg68cZ
  - http://www.openwall.com/lists/oss-security/2021/10/07/1
  - https://security.netapp.com/advisory/ntap-20211029-0009/
  - http://www.openwall.com/lists/oss-security/2021/10/08/4
  - http://www.openwall.com/lists/oss-security/2021/10/05/2
  - http://www.openwall.com/lists/oss-security/2021/10/08/6
  - status=referenced

### Externí intel vrstva vrátila shodu pro CVE-2021-42013 [nízká / vysoká jistota]

- Typ: `intel:osv.dev`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-42013
  - http://www.openwall.com/lists/oss-security/2021/10/08/1
  - https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RMIIEFINL6FUIOPD2A3M5XC6DH45Y3CC/
  - http://www.openwall.com/lists/oss-security/2021/10/08/4
  - http://www.openwall.com/lists/oss-security/2021/10/08/5
  - http://www.openwall.com/lists/oss-security/2021/10/08/6
  - http://www.openwall.com/lists/oss-security/2021/10/08/3
  - https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-httpd-pathtrv-LAzg68cZ
  - status=referenced

### Externí intel vrstva vrátila shodu pro CVE-2023-38408 [nízká / vysoká jistota]

- Typ: `intel:osv.dev`
- Cíl: neuvedeno
- Důvod: Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu.
- Doporučení: Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem.
- Evidence:
  - http://www.openwall.com/lists/oss-security/2023/09/22/11
  - https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CEBTJJINE2I3FHAUKKNQWMFGYMLSMWKQ/
  - http://www.openwall.com/lists/oss-security/2023/09/22/9
  - https://lists.debian.org/debian-lts-announce/2023/08/msg00021.html
  - https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RAXVQS6ZYTULFAK3TEJHRLKZALJS3AOU/
  - https://support.apple.com/kb/HT213940
  - https://www.vicarius.io/vsociety/posts/exploring-opensshs-agent-forwarding-rce-cve-2023-38408
  - http://www.openwall.com/lists/oss-security/2023/07/20/2
  - status=referenced

### Na službě 192.168.56.30/host-only byla detekována špička rychlosti paketů [střední / nízká jistota]

- Typ: `packet_rate_spike`
- Cíl: 192.168.56.30/host-only
- Důvod: Detektor zaznamenal neobvykle vysokou packet-rate vůči běžnému průběhu služby; to je praktický signál rizika degradace a nedostupnosti.
- Doporučení: Doplnit limitaci pps/bps, ověřit capacity plán a připravit burst-profil obrany (dočasný shaper, ACL nebo agresivnější WAF/IPS režim).
- Evidence:
  - service_key=192.168.56.30/host-only
  - service_name=host-only
  - product=Korelace pouze na uroven hosta | version=- | port_state=n/a
  - zeek | packet_rate_spike | ip-only | Pozorovan prudky narust rychlosti paketu (max_pps 6833, max_bps 3333333, timeout_ratio 0.67).

### FTP na službě 192.168.56.20/tcp/21 nepoužívá šifrovaný přenos [střední / vysoká jistota]

- Typ: `plaintext_management_protocol`
- Cíl: 192.168.56.20/tcp/21
- Důvod: FTP přenáší řídicí kanál a často i přihlašovací údaje bez šifrování. I když nejde vždy o správu systému, pořád jde o slabý přístupový kanál.
- Doporučení: Přesunout přenos na SFTP nebo FTPS, omezit port 21 jen na nutné zdroje a ověřit, zda se přes službu nepřenáší citlivé údaje.
- Evidence:
  - service_key=192.168.56.20/tcp/21
  - service_name=ftp
  - product=vsftpd | version=3.0.3 | port_state=open

### Telnet na službě 192.168.56.20/tcp/23 nepoužívá šifrovaný přenos [vysoká / vysoká jistota]

- Typ: `plaintext_management_protocol`
- Cíl: 192.168.56.20/tcp/23
- Důvod: Telnet přenáší přihlašovací údaje i správcovské příkazy bez šifrování, takže je v běžné síti citlivý na odposlech a převzetí relace.
- Doporučení: Nahradit Telnet za SSH, zablokovat port 23 mimo nezbytný správcovský segment a ověřit, zda služba není jen zbytková nebo testovací.
- Evidence:
  - service_key=192.168.56.20/tcp/23
  - service_name=telnet
  - product=BusyBox telnetd | version=1.36.1 | port_state=open
  - suricata | plaintext_protocol | ip+port | TELNET plaintext management traffic
  - zeek | plaintext_protocol | ip+port | Telnet management session observed

### Služba 192.168.56.30/host-only vykazuje riziko přetížení a degradace [vysoká / nízká jistota]

- Typ: `service_overload_risk`
- Cíl: 192.168.56.30/host-only
- Důvod: Kombinace timeoutů, rate spike a provozního tlaku indikuje, že služba může být na hraně kapacity nebo pod aktivním tlakem.
- Doporučení: Aktivovat agresivnější ochranu: krátkodobý rate-limit, přísnější ACL/WAF pravidla, priorizace provozu a audit kapacitního stropu.
- Evidence:
  - service_key=192.168.56.30/host-only
  - service_name=host-only
  - product=Korelace pouze na uroven hosta | version=- | port_state=n/a
  - zeek | service_overload_risk | ip-only | Kombinace vysokych rychlosti, retry a zatizeni ukazuje na riziko pretizeni sluzby (votes 2, max_pps 6833).

### Na cíli 192.168.56.30/host-only byl zaznamenán provoz mimo aktivní inventář [nízká / nízká jistota]

- Typ: `unexpected_traffic`
- Cíl: 192.168.56.30/host-only
- Důvod: Pasivní vrstva zaznamenala komunikaci na port nebo službu, které se nepotvrdily aktivním během; může jít o krátkodobou expozici, mezeru ve viditelnosti nebo chybu korelace.
- Doporučení: Ověřit aktivním opakováním, zda služba nebyla dostupná jen krátce, a prověřit topologii senzoru i pravidla filtrace.
- Evidence:
  - service_key=192.168.56.30/host-only
  - service_name=host-only
  - product=Korelace pouze na uroven hosta | version=- | port_state=n/a
  - zeek | unexpected_traffic | ip-only | Pozorovan provoz na port 3306, ktery neni v aktivnim inventari jako otevrena sluzba.

## Doporučené kroky

### Hlubší audit služby 192.168.56.10/tcp/80 [vysoká]

- Typ: `deep-service-review`
- Cíl: 192.168.56.10/tcp/80
- Důvod: Služba kombinuje vysokou prioritu se zjištěními, která zaslouží credentialed nebo detailnější ověření.
- Nástroje: greenbone, httpx, nuclei, config-review
- Evidence:
  - cve=CVE-2021-41773
  - cve=CVE-2021-42013

### Hlubší audit služby 192.168.56.10/tcp/443 [vysoká]

- Typ: `deep-service-review`
- Cíl: 192.168.56.10/tcp/443
- Důvod: Služba kombinuje vysokou prioritu se zjištěními, která zaslouží credentialed nebo detailnější ověření.
- Nástroje: greenbone, httpx, nuclei, config-review
- Evidence:
  - cve=CVE-2021-41773
  - cve=CVE-2021-42013

### Hlubší audit služby 192.168.56.30/tcp/22 [vysoká]

- Typ: `deep-service-review`
- Cíl: 192.168.56.30/tcp/22
- Důvod: Služba kombinuje vysokou prioritu se zjištěními, která zaslouží credentialed nebo detailnější ověření.
- Nástroje: greenbone, httpx, nuclei, config-review
- Evidence:
  - cve=CVE-2023-38408

### Aktivovat agresivnější ochranu proti přetížení [vysoká]

- Typ: `aggressive-mitigation`
- Cíl: 192.168.56.30/host-only
- Důvod: Detekce ukazuje timeouty/rate spike nebo přímé riziko přetížení; bez okamžité mitigace hrozí degradace nebo nedostupnost služby.
- Nástroje: rate-limit, traffic-shaping, waf, firewall
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - packet_rate_spike:192.168.56.30/host-only
  - service_overload_risk:192.168.56.30/host-only

### Ověřit CVE bezpečným důkazním průchodem [vysoká]

- Typ: `spawn-agent:cve-proof-agent`
- Cíl: 192.168.56.10/tcp/443
- Důvod: CVE záznam sám nestačí. Agent má bez destruktivního exploitu spojit CPE, verzi, NVD, KEV, EPSS, CIRCL/OSV, dostupnost služby a případný řízený web check.
- Nástroje: nvd, cisa-kev, first-epss, circl, osv, greenbone, nuclei-controlled
- Evidence:
  - cve=CVE-2021-3618
  - cve=CVE-2021-41773
  - cve=CVE-2021-42013
  - cve=CVE-2023-38408

### Potvrdit riziko nešifrovaného přihlášení [vysoká]

- Typ: `spawn-agent:credential-exposure-validator`
- Cíl: 192.168.56.10/tcp/80
- Důvod: Nešifrovaný protokol je potřeba ověřit proti pasivním důkazům, zdrojům, portům a opakování v čase. Agent nemá číst hesla, ale potvrdit, zda takový provoz skutečně existuje.
- Nástroje: zeek, suricata, pcap-metadata-review, firewall-scope-check
- Evidence:
  - plaintext=192.168.56.10/tcp/80
  - plaintext=192.168.56.20/tcp/21
  - plaintext=192.168.56.20/tcp/23

### Forenzně ověřit podezřelé síťové vzorce [vysoká]

- Typ: `spawn-agent:traffic-pcap-analyst`
- Cíl: 192.168.56.30/host-only
- Důvod: Provozní anomálie potřebuje časový kontext, objemy, směry, timeouty a vazbu na běžné služby. Agent má porovnat flow, Zeek a Suricata důkazy a říct, co je fakt a co hypotéza.
- Nástroje: zeek, suricata, netflow-ipfix, ntopng, baseline-profiler
- Evidence:
  - traffic=connection_timeout_burst target=192.168.56.30/host-only
  - traffic=packet_rate_spike target=192.168.56.30/host-only
  - traffic=service_overload_risk target=192.168.56.30/host-only
  - traffic=unexpected_traffic target=192.168.56.30/host-only

### Spustit rozhodovací forenzní plán [vysoká]

- Typ: `forensic-decision-plan`
- Cíl: 192.168.56.30/host-only
- Důvod: Nálezy nejsou brané jen jako shoda textu. Decision engine z nich skládá hypotézy a chce je potvrdit dalším zdrojem: aktivním follow-upem, pasivní telemetrií nebo autorizovaným kontextem.
- Nástroje: nmap-forensic, zeek, suricata, controller-context
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - high_risk_cve_exposure:192.168.56.10/tcp/443
  - high_risk_cve_exposure:192.168.56.10/tcp/80
  - high_risk_cve_exposure:192.168.56.30/tcp/22
  - http_basic_without_tls:192.168.56.10/tcp/80
  - packet_rate_spike:192.168.56.30/host-only
  - plaintext_management_protocol:192.168.56.20/tcp/21
  - plaintext_management_protocol:192.168.56.20/tcp/23

### Vytvořit agenta pro ověření CVE a exploitability [vysoká]

- Typ: `spawn-agent:vuln-intel-verifier`
- Cíl: 192.168.56.10/tcp/443
- Důvod: U zranitelností nestačí bannerová shoda. Agent má porovnat verzi, CPE, CVE, KEV/EPSS a reálnou síťovou expozici, aby oddělil teoretickou zranitelnost od praktického rizika.
- Nástroje: nvd, cisa-kev, first-epss, circl, osv, vulners-optional, vendor-advisory
- Evidence:
  - high_risk_cve_exposure:192.168.56.10/tcp/443
  - high_risk_cve_exposure:192.168.56.10/tcp/80
  - high_risk_cve_exposure:192.168.56.30/tcp/22

### Vytvořit agenta pro nešifrované přihlášení [vysoká]

- Typ: `spawn-agent:passive-credential-hunter`
- Cíl: 192.168.56.20/tcp/21
- Důvod: Nešifrovaný Telnet nebo FTP je potřeba ověřit v pasivních datech, protože aktivní sken ukáže port, ale pasivní provoz ukáže, jestli přes něj opravdu tečou relace.
- Nástroje: zeek, suricata, pcap-review, firewall
- Evidence:
  - plaintext_management_protocol:192.168.56.20/tcp/21
  - plaintext_management_protocol:192.168.56.20/tcp/23

### Vytvořit agenta pro vzorce provozu [vysoká]

- Typ: `spawn-agent:traffic-forensics`
- Cíl: 192.168.56.30/host-only
- Důvod: U provozních anomálií je důležitý kontext v čase. Agent má porovnat cíle, zdroje, objem, timeouty a vazbu na běžné služby.
- Nástroje: netflow-ipfix, ntopng, zeek, baseline-profiler
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - packet_rate_spike:192.168.56.30/host-only
  - service_overload_risk:192.168.56.30/host-only
  - unexpected_traffic:192.168.56.30/host-only

### Doplnit řízený web pentest pro HTTP služby [střední]

- Typ: `spawn-agent:web-pentest-agent`
- Cíl: 192.168.56.10/tcp/80
- Důvod: Běh vidí HTTP/HTTPS služby, ale nemá potvrzené aktivní web checks. Agent má spustit pouze kontrolované nedestruktivní šablony a uložit přesný důkaz.
- Nástroje: httpx, nuclei-controlled, tls-grab, headers-review
- Evidence:
  - web_targets=2
  - active_checks=0

### Vytvořit agenta pro ověření identity služby [střední]

- Typ: `spawn-agent:identity-verifier`
- Cíl: 192.168.56.30/host-only
- Důvod: Některé závěry mají nižší jistotu nebo chybí přesná identita služby. Agent má doplnit banner, CPE, controller inventář a pasivní relace, aby se nerozhodovalo jen podle hrubé shody.
- Nástroje: nmap-followup, service-banner, controller-context, case-memory
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - correlation_uncertainty:192.168.56.30/host-only
  - intel:mitre-att&ck-context:unknown
  - packet_rate_spike:192.168.56.30/host-only
  - service_overload_risk:192.168.56.30/host-only
  - unexpected_traffic:192.168.56.30/host-only

## Rozhodovací a monitorovací vrstvy

### Agent context-fusion [limited]

- Zdroj: `context-fusion`
- Typ: `automation`
- Souhrn: Context agent sjednotil 3 aktiv a 2 vazeb z autorizovaných zdrojů.
- Evidence:
  - context_activated=false
  - audit_sources=false

### Agent correlator [ok]

- Zdroj: `correlator`
- Typ: `automation`
- Souhrn: Korelační agent navázal 17 nálezů a 13 doporučených kroků.
- Evidence:
  - audit_findings=0

### Agent credential-hunter [ok]

- Zdroj: `credential-hunter`
- Typ: `automation`
- Souhrn: Credential hunter vytvořil ověřovací úkol pro nešifrované přihlášení bez práce s obsahem hesel.
- Evidence:
  - credential_validation=true
  - passive_sources=true

### Agent agent:credential-exposure-validator [spawned]

- Zdroj: `agent:credential-exposure-validator`
- Typ: `automation`
- Souhrn: Dynamický agent credential-exposure-validator vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - plaintext=192.168.56.10/tcp/80
  - plaintext=192.168.56.20/tcp/21
  - plaintext=192.168.56.20/tcp/23
  - source_action=validation:credential-exposure-agent:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:cve-proof-agent [spawned]

- Zdroj: `agent:cve-proof-agent`
- Typ: `automation`
- Souhrn: Dynamický agent cve-proof-agent vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - cve=CVE-2021-3618
  - cve=CVE-2021-41773
  - cve=CVE-2021-42013
  - cve=CVE-2023-38408
  - source_action=validation:cve-proof-agent:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:identity-verifier [spawned]

- Zdroj: `agent:identity-verifier`
- Typ: `automation`
- Souhrn: Dynamický agent identity-verifier vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - correlation_uncertainty:192.168.56.30/host-only
  - intel:mitre-att&ck-context:unknown
  - packet_rate_spike:192.168.56.30/host-only
  - service_overload_risk:192.168.56.30/host-only
  - unexpected_traffic:192.168.56.30/host-only
  - source_action=decision:identity-verifier:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:passive-credential-hunter [spawned]

- Zdroj: `agent:passive-credential-hunter`
- Typ: `automation`
- Souhrn: Dynamický agent passive-credential-hunter vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - plaintext_management_protocol:192.168.56.20/tcp/21
  - plaintext_management_protocol:192.168.56.20/tcp/23
  - source_action=decision:plaintext-passive-hunter:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:traffic-forensics [spawned]

- Zdroj: `agent:traffic-forensics`
- Typ: `automation`
- Souhrn: Dynamický agent traffic-forensics vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - connection_timeout_burst:192.168.56.30/host-only
  - packet_rate_spike:192.168.56.30/host-only
  - service_overload_risk:192.168.56.30/host-only
  - unexpected_traffic:192.168.56.30/host-only
  - source_action=decision:traffic-forensics:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:traffic-pcap-analyst [spawned]

- Zdroj: `agent:traffic-pcap-analyst`
- Typ: `automation`
- Souhrn: Dynamický agent traffic-pcap-analyst vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - traffic=connection_timeout_burst target=192.168.56.30/host-only
  - traffic=packet_rate_spike target=192.168.56.30/host-only
  - traffic=service_overload_risk target=192.168.56.30/host-only
  - traffic=unexpected_traffic target=192.168.56.30/host-only
  - source_action=validation:traffic-forensic-agent:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:vuln-intel-verifier [spawned]

- Zdroj: `agent:vuln-intel-verifier`
- Typ: `automation`
- Souhrn: Dynamický agent vuln-intel-verifier vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - high_risk_cve_exposure:192.168.56.10/tcp/443
  - high_risk_cve_exposure:192.168.56.10/tcp/80
  - high_risk_cve_exposure:192.168.56.30/tcp/22
  - source_action=decision:vuln-intel-verifier:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent agent:web-pentest-agent [spawned]

- Zdroj: `agent:web-pentest-agent`
- Typ: `automation`
- Souhrn: Dynamický agent web-pentest-agent vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol.
- Evidence:
  - web_targets=2
  - active_checks=0
  - source_action=validation:web-pentest-agent:run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31

### Agent followup [limited]

- Zdroj: `followup`
- Typ: `automation`
- Souhrn: Follow-up agent ponechal běh bez druhého průchodu (není potřeba nebo není live režim).
- Evidence:
  - followup=false
  - live_nmap_mode=false

### Agent forensic [pending]

- Zdroj: `forensic`
- Typ: `automation`
- Souhrn: Forenzní agent označil další kandidáty, ale hlubší průchod v tomto běhu neproběhl.
- Evidence:
  - suspicious_targets=3

### Agent intel [ok]

- Zdroj: `intel`
- Typ: `automation`
- Souhrn: Intel agent zpracoval 6 externích matchů, provider demo a veřejný stack používá Vulners jen jako volitelný doplněk.
- Evidence:
  - cves=6
  - sources=MITRE ATT&CK Context|OSV.dev

### Agent inventory [ok]

- Zdroj: `inventory`
- Typ: `automation`
- Souhrn: Inventarizační agent zpracoval 3 hostů a 6 služeb.
- Evidence:
  - followup=false
  - forensic=false

### Agent live-observer [ok]

- Zdroj: `live-observer`
- Typ: `automation`
- Souhrn: Live/pasivní vrstva vidí 2 lane a 8 korelovaných událostí.
- Evidence:
  - passive_sources=true
  - live_sources=true

### Agent planner [ok]

- Zdroj: `planner`
- Typ: `automation`
- Souhrn: Plánovač seřadil 3 prioritních cílů a rozdělil běh do kroků inventář -> zpřesnění -> korelace -> intel.
- Evidence:
  - tooling_coverage_ratio=0.75
  - service_identity_ratio=1.00

### Agent remediation [ok]

- Zdroj: `remediation`
- Typ: `automation`
- Souhrn: Remediation agent převádí ověřené nálezy na 13 doporučených kroků s důkazy.
- Evidence:
  - triage_actions=13
  - validation_ready=true

### Agent reporter [ok]

- Zdroj: `reporter`
- Typ: `automation`
- Souhrn: Report agent sjednotil 7 lane, 17 nálezů a 13 doporučených kroků.
- Evidence:
  - run_id=run-20260423071733-1-5cc34c65d58f4ad1a80484f274f3bd31
  - tooling_coverage=0.75

### Agent traffic-forensics [ok]

- Zdroj: `traffic-forensics`
- Typ: `automation`
- Souhrn: Traffic forensics agent má ověřovací úkol pro provozní anomálii a skládá flow/Zeek/Suricata důkazy.
- Evidence:
  - traffic_forensics=true
  - events=8
  - live_lanes=2

### Agent validation [ok]

- Zdroj: `validation`
- Typ: `automation`
- Souhrn: Validační agent rozpadl nálezy na důkazní matice a bezpečné ověřovací úkoly.
- Evidence:
  - validation_matrix=true
  - ai_context_bridge=true

### Agent web-pentest [ok]

- Zdroj: `web-pentest`
- Typ: `automation`
- Souhrn: Web pentest agent má bezpečnou validační lane nebo aktivní kontrolované checks.
- Evidence:
  - http_targets=true
  - safe_pentest=true
  - aggressive_pentest=false
  - active_web_checks=false

### agent lifecycle [ok]

- Zdroj: `agent-lifecycle`
- Typ: `automation`
- Souhrn: Agent governor vyhodnotil, které role mají běžet, které se mají vytvořit a které je možné nechat vypnuté kvůli slabému signálu.
- Nástroje: scheduler, resource-budget, agent-registry
- Evidence:
  - spawn=vuln-intel-verifier reason=cve-or-exploitability-signal
  - spawn=passive-credential-hunter reason=plaintext-management-protocol
  - spawn=traffic-forensics reason=traffic-pattern-anomaly
  - spawn=identity-verifier reason=low-confidence-or-correlation-gap
  - keep=correlator reason=passive-or-flow-context-present

### decision hypotheses [ok]

- Zdroj: `decision-hypotheses`
- Typ: `automation`
- Souhrn: Decision engine sestavil 9 hypotéz z prioritních nálezů a oddělil ověření od okamžité mitigace.
- Nástroje: nmap-forensic, passive-correlation, case-memory
- Evidence:
  - hypothesis=connection_timeout_burst target=192.168.56.30/host-only
  - hypothesis=high_risk_cve_exposure target=192.168.56.10/tcp/443
  - hypothesis=high_risk_cve_exposure target=192.168.56.10/tcp/80
  - hypothesis=high_risk_cve_exposure target=192.168.56.30/tcp/22
  - hypothesis=http_basic_without_tls target=192.168.56.10/tcp/80
  - hypothesis=packet_rate_spike target=192.168.56.30/host-only

## Hosté a služby

### 192.168.56.10

- Hostname: web-frontend
- Počet služeb: 2

- `192.168.56.10/tcp/80` | http | stav=open | priorita=vysoka | skóre=11.27
  - produkt: Apache httpd 2.4.49
  - CPE: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
  - CVE: CVE-2021-41773 [CVSS 7.5], CVE-2021-42013 [CVSS 9.8]
  - Události: http_basic_without_tls, http_basic_without_tls
- `192.168.56.10/tcp/443` | https | stav=open | priorita=vysoka | skóre=9.8
  - produkt: Apache httpd 2.4.49
  - CPE: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
  - CVE: CVE-2021-41773 [CVSS 7.5], CVE-2021-42013 [CVSS 9.8]
### 192.168.56.20

- Hostname: admin-gateway
- Počet služeb: 2

- `192.168.56.20/tcp/21` | ftp | stav=open | priorita=stredni | skóre=6.5
  - produkt: vsftpd 3.0.3
  - CPE: cpe:2.3:a:vsftpd_project:vsftpd:3.0.3:*:*:*:*:*:*:*
  - CVE: CVE-2021-3618 [CVSS 6.5]
- `192.168.56.20/tcp/23` | telnet | stav=open | priorita=nizka | skóre=0
  - produkt: BusyBox telnetd 1.36.1
  - CPE: cpe:2.3:a:*:busybox_telnetd:1.36.1:*:*:*:*:*:*:*
  - Události: plaintext_protocol, plaintext_protocol
### 192.168.56.30

- Hostname: fileserver
- Počet služeb: 2

- `192.168.56.30/host-only` | host-only | stav=n/a | priorita=nizka | skóre=0
  - produkt: Korelace pouze na uroven hosta 
  - Události: unexpected_traffic, connection_timeout_burst, packet_rate_spike, service_overload_risk
- `192.168.56.30/tcp/22` | ssh | stav=open | priorita=vysoka | skóre=8.8
  - produkt: OpenSSH 8.9
  - CPE: cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*
  - CVE: CVE-2023-38408 [CVSS 8.8]