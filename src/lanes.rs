use std::{fs, path::PathBuf};

use serde::Deserialize;

use crate::{
    error::Result,
    model::{Confidence, Finding, HostReport, MonitoringLane, Severity},
};

#[derive(Debug, Clone, Default)]
pub struct LaneConfig {
    pub ntopng_snapshot: Option<PathBuf>,
    pub flow_snapshot: Option<PathBuf>,
    pub greenbone_report: Option<PathBuf>,
    pub wazuh_report: Option<PathBuf>,
    pub napalm_snapshot: Option<PathBuf>,
    pub netmiko_snapshot: Option<PathBuf>,
    pub scrapli_snapshot: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct LaneArtifacts {
    pub ntopng_json: Option<String>,
    pub flow_json: Option<String>,
    pub greenbone_json: Option<String>,
    pub wazuh_json: Option<String>,
    pub napalm_json: Option<String>,
    pub netmiko_json: Option<String>,
    pub scrapli_json: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LaneBundle {
    pub monitoring_lanes: Vec<MonitoringLane>,
    pub findings: Vec<Finding>,
    pub artifacts: LaneArtifacts,
}

#[derive(Debug, Deserialize, Default)]
struct NtopngSnapshot {
    #[serde(default)]
    flows: Vec<FlowRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct FlowSnapshot {
    #[serde(default)]
    records: Vec<FlowRecord>,
}

#[derive(Debug, Deserialize)]
struct FlowRecord {
    src_ip: String,
    dst_ip: String,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    packets: Option<u64>,
    #[serde(default)]
    duration_ms: Option<u64>,
    #[serde(default)]
    duration_s: Option<f64>,
    #[serde(default)]
    timeout_count: Option<u32>,
    #[serde(default)]
    retransmits: Option<u32>,
    #[serde(default)]
    dropped_packets: Option<u64>,
    #[serde(default)]
    device_capacity_pps: Option<u64>,
    #[serde(default)]
    device_capacity_bps: Option<u64>,
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct GreenboneSnapshot {
    #[serde(default)]
    findings: Vec<GreenboneFinding>,
}

#[derive(Debug, Deserialize)]
struct GreenboneFinding {
    id: String,
    name: String,
    host_ip: String,
    #[serde(default)]
    port: Option<u16>,
    severity: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    solution: Option<String>,
    #[serde(default)]
    oid: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct WazuhSnapshot {
    #[serde(default)]
    alerts: Vec<WazuhAlert>,
}

#[derive(Debug, Deserialize)]
struct WazuhAlert {
    id: String,
    level: u8,
    description: String,
    #[serde(default)]
    srcip: Option<String>,
    #[serde(default)]
    dstip: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    agent_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AuditDeviceSnapshot {
    #[serde(default)]
    devices: Vec<AuditDevice>,
}

#[derive(Debug, Deserialize)]
struct AuditDevice {
    hostname: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    issues: Vec<AuditIssue>,
}

#[derive(Debug, Deserialize)]
struct AuditIssue {
    id: String,
    title: String,
    severity: String,
    summary: String,
    #[serde(default)]
    recommendation: Option<String>,
}

pub fn collect_lanes(hosts: &[HostReport], config: &LaneConfig) -> Result<LaneBundle> {
    let mut bundle = LaneBundle::default();

    if let Some(path) = &config.ntopng_snapshot {
        let raw = fs::read_to_string(path)?;
        let snapshot: NtopngSnapshot = serde_json::from_str(&raw)?;
        bundle.artifacts.ntopng_json = Some(raw);
        bundle.monitoring_lanes.push(MonitoringLane {
            lane_id: "lane:live:ntopng".to_string(),
            lane_type: "live".to_string(),
            source: "ntopng".to_string(),
            title: "ntopng live flow telemetry".to_string(),
            status: if snapshot.flows.is_empty() {
                "missing".to_string()
            } else {
                "ok".to_string()
            },
            summary: format!("Toků {}.", snapshot.flows.len()),
            evidence: snapshot
                .flows
                .iter()
                .take(5)
                .map(|flow| {
                    format!(
                        "{} -> {}:{} {}",
                        flow.src_ip,
                        flow.dst_ip,
                        flow.dst_port.unwrap_or_default(),
                        flow.app.clone().unwrap_or_else(|| "-".to_string())
                    )
                })
                .collect(),
            recommended_tools: vec![
                "ntopng".to_string(),
                "suricata".to_string(),
                "zeek".to_string(),
            ],
        });
        bundle
            .findings
            .extend(flow_findings("ntopng", hosts, &snapshot.flows));
    }

    if let Some(path) = &config.flow_snapshot {
        let raw = fs::read_to_string(path)?;
        let snapshot: FlowSnapshot = serde_json::from_str(&raw)?;
        bundle.artifacts.flow_json = Some(raw);
        bundle.monitoring_lanes.push(MonitoringLane {
            lane_id: "lane:live:flow".to_string(),
            lane_type: "live".to_string(),
            source: "netflow-ipfix".to_string(),
            title: "NetFlow / IPFIX".to_string(),
            status: if snapshot.records.is_empty() {
                "missing".to_string()
            } else {
                "ok".to_string()
            },
            summary: format!("Flow záznamů {}.", snapshot.records.len()),
            evidence: snapshot
                .records
                .iter()
                .take(5)
                .map(|flow| {
                    format!(
                        "{} -> {}:{} bytes={}",
                        flow.src_ip,
                        flow.dst_ip,
                        flow.dst_port.unwrap_or_default(),
                        flow.bytes.unwrap_or_default()
                    )
                })
                .collect(),
            recommended_tools: vec![
                "netflow".to_string(),
                "ipfix".to_string(),
                "ntopng".to_string(),
            ],
        });
        bundle
            .findings
            .extend(flow_findings("netflow-ipfix", hosts, &snapshot.records));
    }

    if let Some(path) = &config.greenbone_report {
        let raw = fs::read_to_string(path)?;
        let snapshot: GreenboneSnapshot = serde_json::from_str(&raw)?;
        bundle.artifacts.greenbone_json = Some(raw);
        bundle.monitoring_lanes.push(MonitoringLane {
            lane_id: "lane:audit:greenbone".to_string(),
            lane_type: "audit".to_string(),
            source: "greenbone".to_string(),
            title: "Greenbone / OpenVAS".to_string(),
            status: if snapshot.findings.is_empty() {
                "missing".to_string()
            } else {
                "ok".to_string()
            },
            summary: format!("Auditních nálezů {}.", snapshot.findings.len()),
            evidence: snapshot
                .findings
                .iter()
                .take(5)
                .map(|item| {
                    format!(
                        "{} {}:{} {}",
                        item.name,
                        item.host_ip,
                        item.port.unwrap_or_default(),
                        item.severity
                    )
                })
                .collect(),
            recommended_tools: vec!["greenbone".to_string(), "credentialed-scan".to_string()],
        });
        bundle
            .findings
            .extend(greenbone_findings(hosts, &snapshot.findings));
    }

    if let Some(path) = &config.wazuh_report {
        let raw = fs::read_to_string(path)?;
        let snapshot: WazuhSnapshot = serde_json::from_str(&raw)?;
        bundle.artifacts.wazuh_json = Some(raw);
        bundle.monitoring_lanes.push(MonitoringLane {
            lane_id: "lane:audit:wazuh".to_string(),
            lane_type: "audit".to_string(),
            source: "wazuh".to_string(),
            title: "Wazuh agentless".to_string(),
            status: if snapshot.alerts.is_empty() {
                "missing".to_string()
            } else {
                "ok".to_string()
            },
            summary: format!("Alertů {}.", snapshot.alerts.len()),
            evidence: snapshot
                .alerts
                .iter()
                .take(5)
                .map(|item| format!("level={} {}", item.level, item.description))
                .collect(),
            recommended_tools: vec![
                "wazuh".to_string(),
                "agentless".to_string(),
                "config-review".to_string(),
            ],
        });
        bundle
            .findings
            .extend(wazuh_findings(hosts, &snapshot.alerts));
    }

    if let Some(path) = &config.napalm_snapshot {
        ingest_audit_device_snapshot("napalm", "NAPALM getters", path, &mut bundle)?;
    }
    if let Some(path) = &config.netmiko_snapshot {
        ingest_audit_device_snapshot("netmiko", "Netmiko config audit", path, &mut bundle)?;
    }
    if let Some(path) = &config.scrapli_snapshot {
        ingest_audit_device_snapshot("scrapli", "scrapli config audit", path, &mut bundle)?;
    }

    Ok(bundle)
}

fn ingest_audit_device_snapshot(
    source: &str,
    title: &str,
    path: &PathBuf,
    bundle: &mut LaneBundle,
) -> Result<()> {
    let raw = fs::read_to_string(path)?;
    let snapshot: AuditDeviceSnapshot = serde_json::from_str(&raw)?;
    match source {
        "napalm" => bundle.artifacts.napalm_json = Some(raw),
        "netmiko" => bundle.artifacts.netmiko_json = Some(raw),
        "scrapli" => bundle.artifacts.scrapli_json = Some(raw),
        _ => {}
    }
    bundle.monitoring_lanes.push(MonitoringLane {
        lane_id: format!("lane:audit:{source}"),
        lane_type: "audit".to_string(),
        source: source.to_string(),
        title: title.to_string(),
        status: if snapshot.devices.is_empty() {
            "missing".to_string()
        } else {
            "ok".to_string()
        },
        summary: format!(
            "Zařízení {}, issues {}.",
            snapshot.devices.len(),
            snapshot
                .devices
                .iter()
                .map(|item| item.issues.len())
                .sum::<usize>()
        ),
        evidence: snapshot
            .devices
            .iter()
            .take(5)
            .map(|device| format!("{} issues={}", device.hostname, device.issues.len()))
            .collect(),
        recommended_tools: vec![source.to_string(), "config-audit".to_string()],
    });
    bundle
        .findings
        .extend(audit_issue_findings(source, &snapshot.devices));
    Ok(())
}

fn flow_findings(source: &str, hosts: &[HostReport], flows: &[FlowRecord]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for flow in flows.iter().filter(|flow| is_public_ip(&flow.dst_ip)) {
        let host_key = hosts
            .iter()
            .find(|host| host.ip == flow.src_ip)
            .map(|host| host.host_key.clone());

        let duration_s = flow
            .duration_s
            .or_else(|| flow.duration_ms.map(|value| value as f64 / 1000.0))
            .unwrap_or(0.0);
        let pps = if duration_s > 0.0001 {
            flow.packets.unwrap_or_default() as f64 / duration_s
        } else {
            0.0
        };
        let bps = if duration_s > 0.0001 {
            (flow.bytes.unwrap_or_default() as f64 * 8.0) / duration_s
        } else {
            0.0
        };
        let timeout_count = flow.timeout_count.unwrap_or_default();
        let retransmits = flow.retransmits.unwrap_or_default();
        let dropped_packets = flow.dropped_packets.unwrap_or_default();

        findings.push(Finding {
            finding_id: format!(
                "finding:{source}:flow:{}:{}:{}",
                flow.src_ip,
                flow.dst_ip,
                flow.dst_port.unwrap_or_default()
            ),
            finding_type: "external_flow_observed".to_string(),
            title: format!(
                "Live vrstva zachytila externí tok {} -> {}",
                flow.src_ip, flow.dst_ip
            ),
            severity: if flow.bytes.unwrap_or_default() > 50_000_000 {
                Severity::Medium
            } else {
                Severity::Low
            },
            confidence: Confidence::Medium,
            host_key: host_key.clone(),
            service_key: None,
            rationale:
                "NetFlow/IPFIX nebo ntopng zachytil komunikaci do veřejné sítě. Výstup sám o sobě neznamená kompromitaci, ale doplňuje provozní kontext a kandidáty k ověření."
                    .to_string(),
            evidence: vec![
                format!("src_ip={}", flow.src_ip),
                format!("dst_ip={}", flow.dst_ip),
                format!("dst_port={}", flow.dst_port.unwrap_or_default()),
                flow.protocol
                    .clone()
                    .map(|protocol| format!("protocol={protocol}"))
                    .unwrap_or_else(|| "protocol=-".to_string()),
                format!("bytes={}", flow.bytes.unwrap_or_default()),
                format!("packets={}", flow.packets.unwrap_or_default()),
                format!("pps={pps:.0}"),
                format!("bps={bps:.0}"),
                format!("timeouts={timeout_count}"),
                format!("retransmits={retransmits}"),
                format!("dropped_packets={dropped_packets}"),
                flow.category
                    .clone()
                    .map(|category| format!("category={category}"))
                    .unwrap_or_else(|| "category=-".to_string()),
                flow.url
                    .clone()
                    .map(|url| format!("url={url}"))
                    .unwrap_or_else(|| "url=-".to_string()),
            ],
            recommendation:
                "Prověřit, zda jde o očekávanou komunikaci, případně doplnit reputační a URL intel vrstvu a zachovat auditní stopu pro následné vyšetření."
                    .to_string(),
        });

        if timeout_count >= 3 || retransmits >= 12 {
            findings.push(Finding {
                finding_id: format!(
                    "finding:{source}:flow-timeout:{}:{}:{}",
                    flow.src_ip,
                    flow.dst_ip,
                    flow.dst_port.unwrap_or_default()
                ),
                finding_type: "flow_timeout_pressure".to_string(),
                title: format!(
                    "Flow {} -> {} vykazuje timeout/retry tlak",
                    flow.src_ip, flow.dst_ip
                ),
                severity: if timeout_count >= 6 || retransmits >= 30 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Medium,
                host_key: host_key.clone(),
                service_key: None,
                rationale:
                    "Tok obsahuje zvýšený počet timeoutů/retransmisí, což odpovídá přetížení cesty nebo cílové služby."
                        .to_string(),
                evidence: vec![
                    format!("timeouts={timeout_count}"),
                    format!("retransmits={retransmits}"),
                    format!("pps={pps:.0}"),
                    format!("bps={bps:.0}"),
                ],
                recommendation:
                    "Prověřit limity zařízení na trase, fronty a policy; při potvrzení aktivovat konzervativnější shaping a ochranu proti burstům."
                        .to_string(),
            });
        }

        let pps_capacity_ratio = flow
            .device_capacity_pps
            .map(|cap| if cap == 0 { 0.0 } else { pps / cap as f64 })
            .unwrap_or(0.0);
        let bps_capacity_ratio = flow
            .device_capacity_bps
            .map(|cap| if cap == 0 { 0.0 } else { bps / cap as f64 })
            .unwrap_or(0.0);
        let capacity_ratio = pps_capacity_ratio.max(bps_capacity_ratio);
        if capacity_ratio >= 0.8 || pps >= 2_500.0 || bps >= 35_000_000.0 {
            findings.push(Finding {
                finding_id: format!(
                    "finding:{source}:flow-rate:{}:{}:{}",
                    flow.src_ip,
                    flow.dst_ip,
                    flow.dst_port.unwrap_or_default()
                ),
                finding_type: "flow_packet_rate_pressure".to_string(),
                title: format!(
                    "Flow {} -> {} se blíží kapacitnímu limitu",
                    flow.src_ip, flow.dst_ip
                ),
                severity: if capacity_ratio >= 1.0 || pps >= 5_000.0 || bps >= 80_000_000.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Medium,
                host_key,
                service_key: None,
                rationale:
                    "Rychlost toku je vysoká vůči odhadované kapacitě zařízení nebo překračuje provozní heuristický práh."
                        .to_string(),
                evidence: vec![
                    format!("pps={pps:.0}"),
                    format!("bps={bps:.0}"),
                    format!("capacity_ratio={capacity_ratio:.2}"),
                    format!(
                        "device_capacity_pps={}",
                        flow.device_capacity_pps.unwrap_or_default()
                    ),
                    format!(
                        "device_capacity_bps={}",
                        flow.device_capacity_bps.unwrap_or_default()
                    ),
                ],
                recommendation:
                    "Aplikovat rate-limit a prioritizaci provozu, ověřit kapacitní plán linky/zařízení a připravit agresivnější mitigaci při opakování."
                        .to_string(),
            });
        }
    }

    findings
}

fn greenbone_findings(hosts: &[HostReport], items: &[GreenboneFinding]) -> Vec<Finding> {
    items.iter()
        .map(|item| Finding {
            finding_id: format!("finding:greenbone:{}", item.id),
            finding_type: "greenbone_finding".to_string(),
            title: item.name.clone(),
            severity: severity_from_text(&item.severity),
            confidence: Confidence::High,
            host_key: hosts
                .iter()
                .find(|host| host.ip == item.host_ip)
                .map(|host| host.host_key.clone()),
            service_key: item.port.and_then(|port| {
                hosts.iter().find(|host| host.ip == item.host_ip).and_then(|host| {
                    host.services
                        .iter()
                        .find(|service| service.port == port)
                        .map(|service| service.service_key.clone())
                })
            }),
            rationale: item
                .summary
                .clone()
                .unwrap_or_else(|| "Greenbone audit vrátil explicitní nález.".to_string()),
            evidence: vec![
                format!("host_ip={}", item.host_ip),
                format!("port={}", item.port.unwrap_or_default()),
                item.oid
                    .clone()
                    .map(|oid| format!("oid={oid}"))
                    .unwrap_or_else(|| "oid=-".to_string()),
            ],
            recommendation: item
                .solution
                .clone()
                .unwrap_or_else(|| "Ověřit výsledek credentialed auditu a promítnout mitigaci do konfigurace nebo patchingu.".to_string()),
        })
        .collect()
}

fn wazuh_findings(hosts: &[HostReport], alerts: &[WazuhAlert]) -> Vec<Finding> {
    alerts
        .iter()
        .map(|item| Finding {
            finding_id: format!("finding:wazuh:{}", item.id),
            finding_type: "wazuh_alert".to_string(),
            title: item.description.clone(),
            severity: if item.level >= 10 {
                Severity::High
            } else if item.level >= 6 {
                Severity::Medium
            } else {
                Severity::Low
            },
            confidence: Confidence::Medium,
            host_key: item
                .dstip
                .as_deref()
                .and_then(|ip| hosts.iter().find(|host| host.ip == ip))
                .map(|host| host.host_key.clone()),
            service_key: None,
            rationale: "Wazuh agentless audit vrátil pravidlový alert nad cílovým systémem nebo jeho konfigurací.".to_string(),
            evidence: vec![
                item.rule_id
                    .clone()
                    .map(|id| format!("rule_id={id}"))
                    .unwrap_or_else(|| "rule_id=-".to_string()),
                item.srcip
                    .clone()
                    .map(|ip| format!("src_ip={ip}"))
                    .unwrap_or_else(|| "src_ip=-".to_string()),
                item.dstip
                    .clone()
                    .map(|ip| format!("dst_ip={ip}"))
                    .unwrap_or_else(|| "dst_ip=-".to_string()),
                item.agent_name
                    .clone()
                    .map(|name| format!("agent={name}"))
                    .unwrap_or_else(|| "agent=-".to_string()),
            ],
            recommendation:
                "Prověřit alert proti reálné konfiguraci, potvrdit dopad a zachovat auditní stopu o nápravě."
                    .to_string(),
        })
        .collect()
}

fn audit_issue_findings(source: &str, devices: &[AuditDevice]) -> Vec<Finding> {
    devices
        .iter()
        .flat_map(|device| {
            device.issues.iter().map(move |issue| Finding {
                finding_id: format!("finding:{source}:{}", issue.id),
                finding_type: format!("{source}_config_issue"),
                title: issue.title.clone(),
                severity: severity_from_text(&issue.severity),
                confidence: Confidence::High,
                host_key: device.ip.clone(),
                service_key: None,
                rationale: issue.summary.clone(),
                evidence: vec![
                    format!("device={}", device.hostname),
                    device
                        .ip
                        .clone()
                        .map(|ip| format!("ip={ip}"))
                        .unwrap_or_else(|| "ip=-".to_string()),
                ],
                recommendation: issue.recommendation.clone().unwrap_or_else(|| {
                    "Prověřit konfiguraci zařízení a aplikovat nápravné opatření podle interního standardu.".to_string()
                }),
            })
        })
        .collect()
}

fn severity_from_text(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "high" | "vysoka" => Severity::High,
        "medium" | "stredni" => Severity::Medium,
        _ => Severity::Low,
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
