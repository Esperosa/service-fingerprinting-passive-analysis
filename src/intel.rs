use std::{collections::BTreeSet, env, time::Duration};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    model::{Confidence, IntelMatch, MonitoringLane, RunReport, Severity},
};

#[derive(Debug, Clone)]
pub struct IntelConfig {
    pub urlhaus_auth_env: String,
    pub abuseipdb_key_env: String,
    pub circl_enabled: bool,
    pub osv_enabled: bool,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
            abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
            circl_enabled: true,
            osv_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSourceCatalog {
    pub source_id: String,
    pub name: String,
    pub cost: String,
    #[serde(default)]
    pub key_env: Option<String>,
    pub enabled_by_default: bool,
    pub purpose: String,
    pub indicators: Vec<String>,
    pub reference_url: String,
}

#[derive(Debug, Deserialize)]
struct UrlhausResponse {
    query_status: String,
    #[serde(default)]
    urlhaus_reference: Option<String>,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbEnvelope {
    data: AbuseIpDbRecord,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbRecord {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u64,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "lastReportedAt")]
    last_reported_at: Option<String>,
    #[serde(rename = "totalReports")]
    total_reports: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(default)]
    url: Option<String>,
}

pub fn public_intel_sources() -> Vec<IntelSourceCatalog> {
    vec![
        source_catalog(
            "nvd",
            "NVD CVE API",
            "free",
            None,
            true,
            "Primární veřejná databáze CVE, CPE a CVSS pro aktivní službový inventář.",
            &["cve", "cpe", "cvss"],
            "https://nvd.nist.gov/developers/vulnerabilities",
        ),
        source_catalog(
            "cisa-kev",
            "CISA Known Exploited Vulnerabilities",
            "free",
            None,
            true,
            "Seznam CVE, které CISA eviduje jako známě zneužívané.",
            &["cve", "kev", "exploitation"],
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ),
        source_catalog(
            "first-epss",
            "FIRST EPSS API",
            "free",
            None,
            true,
            "Pravděpodobnost praktického zneužití CVE podle EPSS skóre.",
            &["cve", "epss"],
            "https://www.first.org/epss/api",
        ),
        source_catalog(
            "circl",
            "CIRCL Vulnerability-Lookup",
            "free",
            None,
            true,
            "Nezávislý CVE kontext, vendor a produktové informace k ověření zranitelností.",
            &["cve", "advisory"],
            "https://vulnerability.circl.lu/",
        ),
        source_catalog(
            "osv",
            "OSV.dev",
            "free",
            None,
            true,
            "Veřejný open-source vulnerability index pro další ověření CVE a advisories.",
            &["cve", "osv", "advisory"],
            "https://google.github.io/osv.dev/api/",
        ),
        source_catalog(
            "mitre-attack",
            "MITRE ATT&CK",
            "free",
            None,
            true,
            "Analytický rámec pro vysvětlení pozorovaných síťových technik bez tvrzení neprokázaného útoku.",
            &["technique", "forensic-context"],
            "https://attack.mitre.org/",
        ),
        source_catalog(
            "urlhaus",
            "URLhaus",
            "free-key-optional",
            Some("URLHAUS_AUTH_KEY"),
            false,
            "Ověření URL a webových indikátorů proti malware URL feedu.",
            &["url", "malware"],
            "https://urlhaus.abuse.ch/api/",
        ),
        source_catalog(
            "abuseipdb",
            "AbuseIPDB",
            "free-key-optional",
            Some("ABUSEIPDB_API_KEY"),
            false,
            "Reputační kontrola veřejných IP adres z pasivních událostí.",
            &["ip", "reputation"],
            "https://docs.abuseipdb.com/",
        ),
        source_catalog(
            "vulners",
            "Vulners",
            "free-key-optional",
            Some("VULNERS_API_KEY"),
            false,
            "Doplňkový exploitability a vulnerability kontext nad NVD/public stackem.",
            &["cve", "exploit", "advisory"],
            "https://vulners.com/docs/api/",
        ),
    ]
}

pub fn collect_intel(report: &RunReport, config: &IntelConfig) -> Result<Vec<IntelMatch>> {
    let client = Client::builder()
        .user_agent("bakula-program/0.1")
        .timeout(Duration::from_secs(15))
        .build()?;

    let mut matches = Vec::new();

    if let Ok(auth_key) = env::var(&config.urlhaus_auth_env) {
        if !auth_key.trim().is_empty() {
            for url in collect_urls(report) {
                append_optional_match(
                    &mut matches,
                    "URLhaus",
                    query_urlhaus(&client, &auth_key, &url),
                );
            }
        }
    }

    if let Ok(api_key) = env::var(&config.abuseipdb_key_env) {
        if !api_key.trim().is_empty() {
            for ip in collect_public_ips(report) {
                append_optional_match(
                    &mut matches,
                    "AbuseIPDB",
                    query_abuseipdb(&client, &api_key, &ip),
                );
            }
        }
    }

    if config.circl_enabled {
        for cve in collect_cves(report) {
            append_optional_match(&mut matches, "CIRCL", query_circl(&client, &cve));
        }
    }

    if config.osv_enabled {
        for cve in collect_cves(report) {
            append_optional_match(&mut matches, "OSV.dev", query_osv(&client, &cve));
        }
    }

    matches.extend(collect_attack_context(report));
    matches.sort_by(|left, right| left.match_id.cmp(&right.match_id));
    matches.dedup_by(|left, right| left.match_id == right.match_id);
    Ok(matches)
}

pub fn build_public_intel_lane(report: &RunReport) -> Option<MonitoringLane> {
    if report.summary.cves_total == 0 && report.intel_matches.is_empty() {
        return None;
    }

    let sources = report
        .intel_matches
        .iter()
        .map(|item| item.source.clone())
        .collect::<BTreeSet<_>>();
    let public_sources = public_intel_sources()
        .into_iter()
        .filter(|item| item.enabled_by_default)
        .map(|item| item.name)
        .collect::<Vec<_>>();
    let mut evidence = vec![
        format!("provider={}", report.run.provider),
        format!("cves={}", report.summary.cves_total),
        format!("intel_matches={}", report.intel_matches.len()),
        format!(
            "sources={}",
            if sources.is_empty() {
                "-".to_string()
            } else {
                sources.iter().cloned().collect::<Vec<_>>().join("|")
            }
        ),
    ];
    evidence.extend(
        public_sources
            .iter()
            .take(8)
            .map(|source| format!("public_source={source}")),
    );

    Some(MonitoringLane {
        lane_id: format!("lane:intel:public-stack:{}", report.run.run_id),
        lane_type: "audit".to_string(),
        source: "public-intel-stack".to_string(),
        title: "Veřejný threat intel stack".to_string(),
        status: if report.intel_matches.is_empty() {
            "limited".to_string()
        } else {
            "ok".to_string()
        },
        summary: if report.intel_matches.is_empty() {
            "Intel agent má CVE kontext, ale žádný veřejný doplňkový match nevrátil data pro tento běh.".to_string()
        } else {
            format!(
                "Intel agent zkřížil zranitelnosti a indikátory přes {} veřejných zdrojů; Vulners je volitelný doplněk.",
                sources.len()
            )
        },
        evidence,
        recommended_tools: vec![
            "nvd".to_string(),
            "cisa-kev".to_string(),
            "first-epss".to_string(),
            "circl".to_string(),
            "osv".to_string(),
            "vulners-optional".to_string(),
        ],
    })
}

fn collect_urls(report: &RunReport) -> BTreeSet<String> {
    let mut urls = BTreeSet::new();
    for service in report.hosts.iter().flat_map(|host| host.services.iter()) {
        if let Some(probe) = &service.web_probe {
            urls.insert(probe.url.clone());
            if let Some(final_url) = &probe.final_url {
                urls.insert(final_url.clone());
            }
        }
        for check in &service.active_checks {
            urls.insert(check.matched_url.clone());
        }
    }
    urls
}

fn collect_public_ips(report: &RunReport) -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    for event in report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.events.iter())
    {
        if let Some(src_ip) = &event.event.src_ip {
            if is_public_ip(src_ip) {
                ips.insert(src_ip.clone());
            }
        }
        if is_public_ip(&event.event.dst_ip) {
            ips.insert(event.event.dst_ip.clone());
        }
    }
    ips
}

fn collect_cves(report: &RunReport) -> BTreeSet<String> {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.cves.iter())
        .map(|item| item.cve_id.clone())
        .collect()
}

fn append_optional_match(
    matches: &mut Vec<IntelMatch>,
    source: &str,
    result: Result<Option<IntelMatch>>,
) {
    match result {
        Ok(Some(item)) => matches.push(item),
        Ok(None) => {}
        Err(error) => eprintln!("Varovani: {source} intel dotaz selhal: {error}"),
    }
}

fn query_urlhaus(client: &Client, auth_key: &str, url: &str) -> Result<Option<IntelMatch>> {
    let response = client
        .post("https://urlhaus-api.abuse.ch/v1/url/")
        .header("Auth-Key", auth_key)
        .form(&[("url", url)])
        .send()?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let payload: UrlhausResponse = response.json()?;
    if payload.query_status != "ok" {
        return Ok(None);
    }
    Ok(Some(IntelMatch {
        match_id: format!("intel:urlhaus:{url}"),
        source: "URLhaus".to_string(),
        indicator_type: "url".to_string(),
        indicator: url.to_string(),
        status: "listed".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        summary: format!(
            "URLhaus eviduje URL jako {}. Tags: {}.",
            payload.threat.unwrap_or_else(|| "malicious".to_string()),
            if payload.tags.is_empty() {
                "-".to_string()
            } else {
                payload.tags.join(", ")
            }
        ),
        references: payload.urlhaus_reference.into_iter().collect(),
        linked_host_key: None,
        linked_service_key: None,
    }))
}

fn query_abuseipdb(client: &Client, api_key: &str, ip: &str) -> Result<Option<IntelMatch>> {
    let response = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", api_key)
        .header("Accept", "application/json")
        .query(&[
            ("ipAddress", ip),
            ("maxAgeInDays", "90"),
            ("verbose", "true"),
        ])
        .send()?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let payload: AbuseIpDbEnvelope = response.json()?;
    if payload.data.abuse_confidence_score == 0 {
        return Ok(None);
    }
    Ok(Some(IntelMatch {
        match_id: format!("intel:abuseipdb:{ip}"),
        source: "AbuseIPDB".to_string(),
        indicator_type: "ip".to_string(),
        indicator: ip.to_string(),
        status: "reported".to_string(),
        severity: if payload.data.abuse_confidence_score >= 75 {
            Severity::High
        } else if payload.data.abuse_confidence_score >= 25 {
            Severity::Medium
        } else {
            Severity::Low
        },
        confidence: Confidence::Medium,
        summary: format!(
            "AbuseIPDB skóre {}. Země {}. Reportů {}. Poslední report {}.",
            payload.data.abuse_confidence_score,
            payload.data.country_code.unwrap_or_else(|| "-".to_string()),
            payload.data.total_reports.unwrap_or_default(),
            payload
                .data
                .last_reported_at
                .unwrap_or_else(|| "-".to_string())
        ),
        references: vec![format!("https://www.abuseipdb.com/check/{ip}")],
        linked_host_key: None,
        linked_service_key: None,
    }))
}

fn query_circl(client: &Client, cve_id: &str) -> Result<Option<IntelMatch>> {
    let response = client
        .get(format!("https://vulnerability.circl.lu/api/cve/{cve_id}"))
        .header("Accept", "application/json")
        .send()?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let payload: serde_json::Value = response.json()?;
    let vendor = payload
        .pointer("/containers/cna/affected/0/vendor")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let product = payload
        .pointer("/containers/cna/affected/0/product")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let title = payload
        .pointer("/containers/cna/title")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            payload
                .pointer("/containers/cna/descriptions/0/value")
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or("Další kontext z CIRCL Vulnerability-Lookup.");
    Ok(Some(IntelMatch {
        match_id: format!("intel:circl:{cve_id}"),
        source: "CIRCL Vulnerability-Lookup".to_string(),
        indicator_type: "cve".to_string(),
        indicator: cve_id.to_string(),
        status: "referenced".to_string(),
        severity: Severity::Low,
        confidence: Confidence::High,
        summary: format!("{title} Vendor: {vendor}. Product: {product}."),
        references: vec![format!("https://vulnerability.circl.lu/vuln/{cve_id}")],
        linked_host_key: None,
        linked_service_key: None,
    }))
}

fn query_osv(client: &Client, cve_id: &str) -> Result<Option<IntelMatch>> {
    let response = client
        .get(format!("https://api.osv.dev/v1/vulns/{cve_id}"))
        .header("Accept", "application/json")
        .send()?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let payload: OsvVulnerability = response.json()?;
    Ok(parse_osv_match(cve_id, payload))
}

fn parse_osv_match(cve_id: &str, payload: OsvVulnerability) -> Option<IntelMatch> {
    if payload.id.trim().is_empty() {
        return None;
    }
    let mut references = payload
        .references
        .iter()
        .filter_map(|reference| reference.url.as_deref())
        .filter(|url| !url.trim().is_empty())
        .take(8)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if references.is_empty() {
        references.push(format!("https://osv.dev/vulnerability/{}", payload.id));
    }
    let alias_hint = if payload.aliases.is_empty() {
        "-".to_string()
    } else {
        payload.aliases.join(", ")
    };
    let description = payload
        .summary
        .or(payload.details)
        .unwrap_or_else(|| "OSV.dev eviduje doplňkový vulnerability kontext.".to_string());
    Some(IntelMatch {
        match_id: format!("intel:osv:{cve_id}"),
        source: "OSV.dev".to_string(),
        indicator_type: "cve".to_string(),
        indicator: cve_id.to_string(),
        status: "referenced".to_string(),
        severity: Severity::Low,
        confidence: Confidence::High,
        summary: format!(
            "{} Aliasy: {}.",
            compact_text(&description, 260),
            alias_hint
        ),
        references,
        linked_host_key: None,
        linked_service_key: None,
    })
}

fn collect_attack_context(report: &RunReport) -> Vec<IntelMatch> {
    let mut matches = Vec::new();
    let has_plaintext = report.findings.iter().any(|finding| {
        matches!(
            finding.finding_type.as_str(),
            "plaintext_management_protocol" | "http_basic_without_tls"
        )
    }) || report_event_types(report).any(|event_type| {
        matches!(
            event_type,
            "plaintext_protocol" | "http_basic_without_tls" | "insecure_auth_possible"
        )
    });
    if has_plaintext {
        matches.push(attack_context_match(
            "T1040",
            "Network Sniffing",
            "Nešifrované přihlášení je potřeba brát jako riziko odposlechu v lokální síti. MITRE technika je tady vysvětlující rámec, ne důkaz, že útok opravdu proběhl.",
            "https://attack.mitre.org/techniques/T1040/",
        ));
    }

    let has_traffic_anomaly = report.findings.iter().any(|finding| {
        matches!(
            finding.finding_type.as_str(),
            "unexpected_traffic"
                | "external_flow_observed"
                | "connection_timeout_burst"
                | "packet_rate_spike"
                | "packet_loss_signal"
                | "service_overload_risk"
                | "inductive_volume_anomaly"
        )
    }) || report_event_types(report).any(|event_type| {
        matches!(
            event_type,
            "unexpected_traffic"
                | "external_flow_observed"
                | "connection_timeout_burst"
                | "packet_rate_spike"
                | "packet_loss_signal"
                | "service_overload_risk"
                | "inductive_volume_anomaly"
        )
    });
    if has_traffic_anomaly {
        matches.push(attack_context_match(
            "T1049",
            "System Network Connections Discovery",
            "Podezřelý síťový vzorec má smysl ověřit přes spojení, cíle, objem a opakování v čase. ATT&CK záznam slouží jen jako forenzní orientace pro další kontrolu.",
            "https://attack.mitre.org/techniques/T1049/",
        ));
    }

    matches
}

fn report_event_types(report: &RunReport) -> impl Iterator<Item = &str> {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.events.iter())
        .map(|event| event.event.event_type.as_str())
}

fn attack_context_match(
    technique_id: &str,
    technique_name: &str,
    summary: &str,
    reference: &str,
) -> IntelMatch {
    IntelMatch {
        match_id: format!("intel:mitre:{technique_id}"),
        source: "MITRE ATT&CK Context".to_string(),
        indicator_type: "technique".to_string(),
        indicator: technique_id.to_string(),
        status: "analytical-context".to_string(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        summary: format!("{technique_id} {technique_name}: {summary}"),
        references: vec![reference.to_string()],
        linked_host_key: None,
        linked_service_key: None,
    }
}

fn compact_text(value: &str, max_chars: usize) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() <= max_chars {
        return normalized;
    }
    let mut output = normalized.chars().take(max_chars).collect::<String>();
    output.push_str("...");
    output
}

fn source_catalog(
    source_id: &str,
    name: &str,
    cost: &str,
    key_env: Option<&str>,
    enabled_by_default: bool,
    purpose: &str,
    indicators: &[&str],
    reference_url: &str,
) -> IntelSourceCatalog {
    IntelSourceCatalog {
        source_id: source_id.to_string(),
        name: name.to_string(),
        cost: cost.to_string(),
        key_env: key_env.map(ToString::to_string),
        enabled_by_default,
        purpose: purpose.to_string(),
        indicators: indicators.iter().map(|item| (*item).to_string()).collect(),
        reference_url: reference_url.to_string(),
    }
}

fn is_public_ip(value: &str) -> bool {
    let Ok(ip) = value.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            !(ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_multicast()
                || ipv4.is_unspecified())
        }
        std::net::IpAddr::V6(ipv6) => {
            !(ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_multicast()
                || ipv6.is_unicast_link_local())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_catalog_includes_public_and_optional_feeds() {
        let sources = public_intel_sources();
        assert!(
            sources
                .iter()
                .any(|item| item.source_id == "nvd" && item.enabled_by_default)
        );
        assert!(
            sources
                .iter()
                .any(|item| item.source_id == "osv" && item.enabled_by_default)
        );
        assert!(
            sources
                .iter()
                .any(|item| item.source_id == "circl" && item.enabled_by_default)
        );
        assert!(sources.iter().any(|item| item.source_id == "vulners"
            && item.key_env.as_deref() == Some("VULNERS_API_KEY")));
    }

    #[test]
    fn osv_payload_is_converted_to_intel_match() {
        let payload = OsvVulnerability {
            id: "CVE-2023-38408".to_string(),
            summary: Some("OpenSSH ssh-agent remote code execution issue".to_string()),
            details: None,
            aliases: vec!["CVE-2023-38408".to_string()],
            references: vec![OsvReference {
                url: Some("https://osv.dev/vulnerability/CVE-2023-38408".to_string()),
            }],
        };
        let item = parse_osv_match("CVE-2023-38408", payload).expect("osv match");
        assert_eq!(item.source, "OSV.dev");
        assert_eq!(item.indicator, "CVE-2023-38408");
        assert!(item.summary.contains("OpenSSH"));
    }
}
