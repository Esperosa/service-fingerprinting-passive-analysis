# Bezpecne rozsirení sberu a limity

Tento prototyp ma byt podle LaTeX dokumentace obhajitelny jako integracni a analyzni nastroj, ne jako ofenzivni pivoting framework.

## Co je bezpecne a vecne spravne doplnovat

- autorizovany Nmap inventar ve vymezenem scope
- import Suricata a Zeek logu
- `httpx` fingerprinting jen nad sluzbami, ktere uz dolozil inventar
- `nuclei` jen nad kontrolovanymi lokalnimi sablonami a jen nad dolozenymi HTTP endpointy
- obohaceni z verejnych zdroju NVD, CISA KEV, FIRST EPSS
- diff mezi behy a vysvetlovaci vrstvu nad hotovym reportem

## Co v aktualnim modelu chybi a proc

V reportu neni poctive mozne tvrdit:

- access pointy a Wi-Fi klienty
- L2 sousedy a mapovani switch portu
- uplnou fyzickou topologii
- laterální dosah za routovacimi hranami

Duvod je jednoduchy: pro tato tvrzeni chybi autorizovany zdroj dat.

## Jak to rozsirit bez ofenzivnich technik

### Wi-Fi / AP vrstva

- UniFi Network API
- TP-Link Omada Controller API
- Cisco WLC / Meraki dashboard API
- Aruba Central API
- SNMP cteni z AP nebo controlleru

### L2 a fyzicka topologie

- LLDP/CDP tabulky ze switchu
- MAC address table / CAM tabulky
- ARP a DHCP lease exporty
- router nebo firewall API

### Provozni vrstva

- NetFlow/IPFIX/sFlow
- SPAN/TAP zrcadleni do Zeek nebo Suricata
- syslog a asset CMDB export

## Doporuceny princip

1. Nejdřív mit dolozeny asset.
2. Pak k assetu pripojit autorizovany zdroj identity.
3. Teprve potom pustit cileny check nebo enrichment.

To odpovida i implementaci v tomto repozitari: system nehada CVE ani topologii tam, kde pro ne nema oporu.
