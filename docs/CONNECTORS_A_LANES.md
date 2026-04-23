# Connectors a lanes

Aktuálně implementované vrstvy:

- Aktivní inventář: `nmap`
- Web vrstva: `httpx`, `nuclei`
- Pasivní telemetrie: `suricata`, `zeek`
- Autorizované síťové zdroje:
  - `SNMP/LLDP/CDP/ARP/FDB/VLAN` snapshot
  - `LibreNMS` snapshot nebo API
  - `Meraki` snapshot nebo API
  - `UniFi` snapshot nebo API přes zadané endpointy
  - `Aruba Central` snapshot nebo API
  - `Omada` snapshot nebo API přes zadané endpointy
- Live lanes:
  - `ntopng` snapshot
  - `NetFlow/IPFIX` snapshot
- Audit lanes:
  - `Greenbone/OpenVAS` report
  - `Wazuh agentless` report
  - `NAPALM` snapshot
  - `Netmiko` snapshot
  - `scrapli` snapshot
- Vulnerability providers:
  - `NVD`
  - `Vulners` jako doplňkový provider k `NVD`
- Intel feeds:
  - `URLhaus`
  - `AbuseIPDB`
  - `CIRCL Vulnerability-Lookup`

Implementační poznámky:

- `NVD` zůstává primární zdroj CVE/CVSS.
- `Vulners` se používá pro doplňkové reference a advisory kontext.
- `URLhaus` a `AbuseIPDB` vyžadují klíč v prostředí.
- `CIRCL` je veřejný a může běžet bez klíče.
- `UniFi` a `Omada` mají v projektu bezpečnější variantu přes snapshot nebo explicitně zadané API endpointy, protože dostupnost endpointů závisí na konkrétní instalaci/controller verzi.

Užitečné CLI přepínače:

- `--supplement-vulners`
- `--snmp-snapshot`
- `--librenms-snapshot` / `--librenms-base-url`
- `--meraki-snapshot` / `--meraki-network-id`
- `--unifi-snapshot` / `--unifi-devices-url` / `--unifi-clients-url` / `--unifi-links-url`
- `--aruba-snapshot` / `--aruba-base-url` / `--aruba-site-id`
- `--omada-snapshot` / `--omada-devices-url` / `--omada-clients-url` / `--omada-links-url`
- `--ntopng-snapshot`
- `--flow-snapshot`
- `--greenbone-report`
- `--wazuh-report`
- `--napalm-snapshot`
- `--netmiko-snapshot`
- `--scrapli-snapshot`
- `--disable-circl`

Každý běh ukládá raw artefakty do `runs/<run_id>/raw/`.
