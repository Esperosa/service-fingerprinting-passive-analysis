use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use uuid::Uuid;

use crate::{
    model::{
        Confidence, CorrelatedEvent, HostReport, InventoryRecord, NetworkAsset, PassiveWindow,
        RunMetadata, RunReport, ServiceReport, SourceMetadata, Summary, TopologyEdge,
    },
    nmap::ParsedInventory,
};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn normalize_inventory(parsed: ParsedInventory) -> Vec<HostReport> {
    parsed
        .hosts
        .into_iter()
        .map(|host| {
            let host_key = host.ip.clone();
            let host_id = format!("host:{}", host.ip);
            let services = host
                .services
                .into_iter()
                .map(|service| {
                    let service_key = format!("{}/{}/{}", host.ip, service.proto, service.port);
                    let service_id = format!("svc:{service_key}");
                    ServiceReport {
                        service_id,
                        service_key,
                        proto: service.proto,
                        port: service.port,
                        port_state: service.port_state,
                        state_reason: service.state_reason,
                        inventory: InventoryRecord {
                            service_name: service
                                .service_name
                                .unwrap_or_else(|| "unknown".to_string()),
                            product: service.product,
                            version: service.version,
                            extrainfo: service.extrainfo,
                            detection_source: service.detection_source,
                            confidence: service.confidence,
                        },
                        cpe: service
                            .cpes
                            .into_iter()
                            .map(|cpe23_uri| crate::model::CpeCandidate {
                                cpe23_uri,
                                method: "nmap".to_string(),
                                confidence: Confidence::High,
                                note: Some("Prevzato primo z Nmap XML.".to_string()),
                            })
                            .collect(),
                        cves: Vec::new(),
                        events: Vec::new(),
                        web_probe: None,
                        active_checks: Vec::new(),
                        score: 0.0,
                        priorita: "nizka".to_string(),
                    }
                })
                .collect();

            HostReport {
                host_id,
                host_key,
                ip: host.ip,
                hostname: host.hostname,
                mac: host.mac,
                vendor: host.vendor,
                services,
            }
        })
        .collect()
}

pub fn infer_network_context_from_hosts(
    hosts: &[HostReport],
) -> (Vec<NetworkAsset>, Vec<TopologyEdge>) {
    if hosts.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut assets = hosts
        .iter()
        .map(|host| {
            let asset_type = infer_asset_type(host);
            let observations = build_host_observations(host, &asset_type);
            NetworkAsset {
                asset_id: format!("nmap:{}", host.host_key),
                asset_type,
                name: host.hostname.clone().unwrap_or_else(|| host.ip.clone()),
                source: "nmap-derived".to_string(),
                confidence: infer_asset_confidence(host),
                ip: Some(host.ip.clone()),
                mac: host.mac.clone(),
                vendor: host.vendor.clone(),
                model: None,
                serial: None,
                status: Some("up".to_string()),
                location: None,
                linked_host_key: Some(host.host_key.clone()),
                observations,
            }
        })
        .collect::<Vec<_>>();

    assets.sort_by(|left, right| left.name.cmp(&right.name));

    let root_asset_id = assets
        .iter()
        .find(|asset| asset.asset_type == "router")
        .or_else(|| assets.iter().find(|asset| asset.asset_type == "switch"))
        .or_else(|| {
            assets
                .iter()
                .find(|asset| asset.asset_type == "access-point")
        })
        .map(|asset| asset.asset_id.clone());
    let access_point_id = assets
        .iter()
        .find(|asset| asset.asset_type == "access-point")
        .map(|asset| asset.asset_id.clone());
    let switch_id = assets
        .iter()
        .find(|asset| asset.asset_type == "switch")
        .map(|asset| asset.asset_id.clone());

    let mut edges = Vec::new();
    if let Some(root_asset_id) = root_asset_id {
        for asset in assets
            .iter()
            .filter(|asset| asset.asset_id != root_asset_id)
        {
            let target = match asset.asset_type.as_str() {
                "wireless-client" => access_point_id
                    .as_ref()
                    .or(Some(&root_asset_id))
                    .cloned()
                    .unwrap_or_else(|| root_asset_id.clone()),
                "endpoint" => switch_id
                    .as_ref()
                    .or(Some(&root_asset_id))
                    .cloned()
                    .unwrap_or_else(|| root_asset_id.clone()),
                _ => root_asset_id.clone(),
            };
            if target == asset.asset_id {
                continue;
            }
            edges.push(TopologyEdge {
                edge_id: format!("nmap-edge:{}::{}", target, asset.asset_id),
                source_asset_id: target.clone(),
                target_asset_id: asset.asset_id.clone(),
                relation: if asset.asset_type == "wireless-client" {
                    "wireless-visibility".to_string()
                } else {
                    "inferred-reachability".to_string()
                },
                source: "nmap-derived".to_string(),
                confidence: if asset.asset_type == "router" || asset.asset_type == "switch" {
                    Confidence::Medium
                } else {
                    Confidence::Low
                },
                details: vec![
                    "odvozeno_z=hostname_mac_vendor".to_string(),
                    format!("cil={}", asset.name),
                ],
            });
        }
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    (assets, edges)
}

fn infer_asset_type(host: &HostReport) -> String {
    let hostname = host.hostname.clone().unwrap_or_default().to_lowercase();
    let vendor = host.vendor.clone().unwrap_or_default().to_lowercase();
    let has_dns = host
        .services
        .iter()
        .any(|service| service.port == 53 && service.port_state == "open");
    let has_web_admin = host.services.iter().any(|service| {
        service.port_state == "open"
            && matches!(service.port, 443 | 8443 | 8080 | 8880 | 8843 | 6789)
    });
    let has_ssh = host
        .services
        .iter()
        .any(|service| service.port == 22 && service.port_state == "open");

    if host.ip.ends_with(".1")
        || hostname.contains("gateway")
        || (hostname.contains("unifi") && (has_dns || has_web_admin))
    {
        return "router".to_string();
    }
    if hostname.contains("usw") || hostname.contains("switch") || hostname.contains("core-sw") {
        return "switch".to_string();
    }
    if hostname.contains("u7")
        || hostname.contains("u6")
        || hostname.contains("uap")
        || hostname.contains("ap")
        || hostname.contains("extender")
        || (vendor.contains("ubiquiti") && has_ssh && !has_dns)
    {
        return "access-point".to_string();
    }
    if hostname.contains("phone")
        || hostname.contains("tablet")
        || hostname.contains("notebook")
        || hostname.contains("iphone")
        || hostname.contains("android")
        || hostname.contains("lenovo")
        || hostname.contains("nothing")
    {
        return "wireless-client".to_string();
    }
    if vendor.contains("ubiquiti") {
        return "network-device".to_string();
    }
    "endpoint".to_string()
}

fn infer_asset_confidence(host: &HostReport) -> Confidence {
    if host.hostname.is_some() && host.vendor.is_some() {
        Confidence::Medium
    } else if host.hostname.is_some() || host.vendor.is_some() {
        Confidence::Low
    } else {
        Confidence::Low
    }
}

fn build_host_observations(host: &HostReport, asset_type: &str) -> Vec<String> {
    let open_ports = host
        .services
        .iter()
        .filter(|service| service.port_state == "open")
        .map(|service| format!("{}/{}", service.port, service.proto))
        .collect::<Vec<_>>();
    let mut observations = Vec::new();
    if !open_ports.is_empty() {
        observations.push(format!("otevrene_porty={}", open_ports.join(",")));
    }
    if let Some(vendor) = &host.vendor {
        observations.push(format!("vendor={vendor}"));
    }
    if let Some(mac) = &host.mac {
        observations.push(format!("mac={mac}"));
    }
    observations.push(format!("typ={asset_type}"));
    observations
}

pub fn determine_passive_window(start: DateTime<Utc>, end: DateTime<Utc>) -> PassiveWindow {
    PassiveWindow {
        start: start - Duration::hours(1),
        end: end + Duration::hours(1),
        time_window_s: 3600,
    }
}

pub fn build_source_metadata(
    nmap_mode: &str,
    nmap_path: &Path,
    nmap_followup_path: Option<&PathBuf>,
    nmap_forensic_path: Option<&PathBuf>,
    suricata_eve: Option<&PathBuf>,
    zeek_dir: Option<&PathBuf>,
    snmp_snapshot: Option<&PathBuf>,
    librenms_snapshot: Option<&PathBuf>,
    librenms_base_url: Option<&str>,
    meraki_snapshot: Option<&PathBuf>,
    meraki_network_id: Option<&str>,
    unifi_snapshot: Option<&PathBuf>,
    aruba_snapshot: Option<&PathBuf>,
    omada_snapshot: Option<&PathBuf>,
    ntopng_snapshot: Option<&PathBuf>,
    flow_snapshot: Option<&PathBuf>,
    greenbone_report: Option<&PathBuf>,
    wazuh_report: Option<&PathBuf>,
    napalm_snapshot: Option<&PathBuf>,
    netmiko_snapshot: Option<&PathBuf>,
    scrapli_snapshot: Option<&PathBuf>,
) -> SourceMetadata {
    SourceMetadata {
        nmap_mode: Some(nmap_mode.to_string()),
        nmap_xml: Some(nmap_path.to_string_lossy().to_string()),
        nmap_followup_xml: nmap_followup_path.map(|path| path.to_string_lossy().to_string()),
        nmap_forensic_xml: nmap_forensic_path.map(|path| path.to_string_lossy().to_string()),
        suricata_eve: suricata_eve.map(|path| path.to_string_lossy().to_string()),
        zeek_dir: zeek_dir.map(|path| path.to_string_lossy().to_string()),
        snmp_snapshot: snmp_snapshot.map(|path| path.to_string_lossy().to_string()),
        librenms_snapshot: librenms_snapshot.map(|path| path.to_string_lossy().to_string()),
        librenms_base_url: librenms_base_url.map(ToString::to_string),
        meraki_snapshot: meraki_snapshot.map(|path| path.to_string_lossy().to_string()),
        meraki_network_id: meraki_network_id.map(ToString::to_string),
        unifi_snapshot: unifi_snapshot.map(|path| path.to_string_lossy().to_string()),
        aruba_snapshot: aruba_snapshot.map(|path| path.to_string_lossy().to_string()),
        omada_snapshot: omada_snapshot.map(|path| path.to_string_lossy().to_string()),
        ntopng_snapshot: ntopng_snapshot.map(|path| path.to_string_lossy().to_string()),
        flow_snapshot: flow_snapshot.map(|path| path.to_string_lossy().to_string()),
        greenbone_report: greenbone_report.map(|path| path.to_string_lossy().to_string()),
        wazuh_report: wazuh_report.map(|path| path.to_string_lossy().to_string()),
        napalm_snapshot: napalm_snapshot.map(|path| path.to_string_lossy().to_string()),
        netmiko_snapshot: netmiko_snapshot.map(|path| path.to_string_lossy().to_string()),
        scrapli_snapshot: scrapli_snapshot.map(|path| path.to_string_lossy().to_string()),
    }
}

pub fn attach_events(
    hosts: &mut [HostReport],
    events: Vec<CorrelatedEvent>,
) -> Vec<CorrelatedEvent> {
    let mut unmapped = Vec::new();

    for event in events {
        if let Some(service_id) = &event.correlation.service_id {
            if let Some(service) = hosts
                .iter_mut()
                .flat_map(|host| host.services.iter_mut())
                .find(|service| &service.service_id == service_id)
            {
                service.events.push(event);
                continue;
            }
        }

        if let Some(host_id) = &event.correlation.host_id {
            if let Some(host) = hosts.iter_mut().find(|host| &host.host_id == host_id) {
                let synthetic_service = host.services.iter_mut().find(|service| service.port == 0);
                if let Some(service) = synthetic_service {
                    service.events.push(event);
                } else {
                    host.services.push(ServiceReport {
                        service_id: format!("svc:{}/host-only", host.host_key),
                        service_key: format!("{}/host-only", host.host_key),
                        proto: "host".to_string(),
                        port: 0,
                        port_state: "n/a".to_string(),
                        state_reason: Some("Kontejner pro host-level udalosti".to_string()),
                        inventory: InventoryRecord {
                            service_name: "host-only".to_string(),
                            product: Some("Korelace pouze na uroven hosta".to_string()),
                            version: None,
                            extrainfo: None,
                            detection_source: "correlation".to_string(),
                            confidence: Confidence::Low,
                        },
                        cpe: Vec::new(),
                        cves: Vec::new(),
                        events: vec![event],
                        web_probe: None,
                        active_checks: Vec::new(),
                        score: 0.0,
                        priorita: "nizka".to_string(),
                    });
                }
                continue;
            }
        }

        unmapped.push(event);
    }

    for host in hosts {
        host.services.sort_by(|left, right| {
            left.port
                .cmp(&right.port)
                .then(left.proto.cmp(&right.proto))
        });
    }

    unmapped.sort_by(|left, right| {
        left.event
            .timestamp
            .cmp(&right.event.timestamp)
            .then(left.event.event_id.cmp(&right.event.event_id))
    });
    unmapped
}

pub fn score_services(hosts: &mut [HostReport]) {
    for service in hosts.iter_mut().flat_map(|host| host.services.iter_mut()) {
        let max_cvss = service
            .cves
            .iter()
            .filter_map(|item| item.cvss.as_ref().map(|cvss| cvss.base_score))
            .fold(0.0_f64, f64::max);
        let max_active_check = service
            .active_checks
            .iter()
            .map(|item| match item.severity {
                crate::model::Severity::High => 8.5,
                crate::model::Severity::Medium => 5.5,
                crate::model::Severity::Low => 2.5,
            })
            .fold(0.0_f64, f64::max);
        let kev_present = service.cves.iter().any(|item| {
            item.exploit_context
                .as_ref()
                .and_then(|context| context.cisa_kev.as_ref())
                .map(|kev| kev.known_exploited)
                .unwrap_or(false)
        });
        let max_epss = service
            .cves
            .iter()
            .filter_map(|item| {
                item.exploit_context
                    .as_ref()
                    .and_then(|context| context.epss.as_ref())
                    .map(|epss| epss.score)
            })
            .fold(0.0_f64, f64::max);
        let cpe_weight = service
            .cpe
            .first()
            .map(|cpe| match cpe.method.as_str() {
                "nmap" => 1.0,
                "curated" => 0.85,
                "partial" => 0.45,
                _ => 0.2,
            })
            .unwrap_or(0.0);
        let id_weight = service.inventory.confidence.weight();
        let passive_bump = if service
            .events
            .iter()
            .any(|event| event.event.severity >= crate::model::Severity::Medium)
        {
            1.15
        } else {
            1.0
        };
        let exploit_floor = if kev_present {
            9.0
        } else if max_epss >= 0.7 {
            7.5
        } else if max_epss >= 0.3 {
            5.0
        } else {
            0.0
        };
        let effective_cvss = max_cvss.max(exploit_floor).max(max_active_check);
        let exploit_bump = if kev_present {
            1.35
        } else if max_epss >= 0.7 {
            1.2
        } else if max_epss >= 0.3 {
            1.1
        } else {
            1.0
        };
        let active_check_bump = if max_active_check >= 8.5 {
            1.25
        } else if max_active_check >= 5.5 {
            1.12
        } else {
            1.0
        };
        service.score = ((effective_cvss * cpe_weight * id_weight)
            * passive_bump
            * exploit_bump
            * active_check_bump
            * 100.0)
            .round()
            / 100.0;
        service.priorita = if service.score >= 7.5 {
            "vysoka".to_string()
        } else if service.score >= 4.0 {
            "stredni".to_string()
        } else {
            "nizka".to_string()
        };
        service
            .cves
            .sort_by(|left, right| left.cve_id.cmp(&right.cve_id));
        service
            .events
            .sort_by(|left, right| left.event.timestamp.cmp(&right.event.timestamp));
    }
}

pub fn build_run_id() -> String {
    let counter = RUN_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(
        "run-{}-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        counter,
        Uuid::new_v4().simple()
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_report(
    run_id: &str,
    nazev: &str,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    scope: Vec<IpNet>,
    ports: Vec<u16>,
    profile: &str,
    provider: &str,
    enrichment_mode: &str,
    passive_window: PassiveWindow,
    sources: SourceMetadata,
    mut hosts: Vec<HostReport>,
    mut unmapped_events: Vec<CorrelatedEvent>,
) -> RunReport {
    hosts.sort_by(|left, right| left.ip.cmp(&right.ip));
    unmapped_events.sort_by(|left, right| {
        left.event
            .timestamp
            .cmp(&right.event.timestamp)
            .then(left.event.event_id.cmp(&right.event.event_id))
    });
    let attached_events_total = hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .map(|service| service.events.len())
        .sum::<usize>();
    let summary = Summary {
        hosts_total: hosts.len(),
        services_total: hosts.iter().map(|host| host.services.len()).sum(),
        cves_total: hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .map(|service| service.cves.len())
            .sum(),
        events_total: attached_events_total + unmapped_events.len(),
        unmapped_events_total: unmapped_events.len(),
        findings_total: 0,
        services_high_priority: hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .filter(|service| service.priorita == "vysoka")
            .count(),
        web_probes_total: hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .filter(|service| service.web_probe.is_some())
            .count(),
        active_checks_total: hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .map(|service| service.active_checks.len())
            .sum(),
        network_assets_total: 0,
        wireless_clients_total: 0,
        topology_edges_total: 0,
        triage_actions_total: 0,
        monitoring_lanes_total: 0,
        live_lanes_total: 0,
        audit_lanes_total: 0,
        intel_matches_total: 0,
        audit_findings_total: 0,
        automation_agents_total: 0,
        automation_rounds_total: 0,
        periodic_cycles_total: 1,
        forensic_targets_total: 0,
        realtime_sources_total: 0,
        service_identity_high_confidence_total: 0,
        service_identity_coverage_ratio: 0.0,
        tooling_coverage_ratio: 0.0,
        mas_parallelism_ratio: 0.0,
        mas_queue_wait_ms_avg: 0.0,
        mas_agent_sla_ratio: 0.0,
        mas_consensus_score: 0.0,
        mas_consensus_state: String::new(),
    };

    RunReport {
        schema_version: "1.0".to_string(),
        run: RunMetadata {
            run_id: run_id.to_string(),
            nazev: nazev.to_string(),
            started_at,
            finished_at,
            scope,
            ports,
            profile: profile.to_string(),
            enrichment_mode: enrichment_mode.to_string(),
            provider: provider.to_string(),
            passive_window,
            sources,
        },
        summary,
        hosts,
        unmapped_events,
        network_assets: Vec::new(),
        topology_edges: Vec::new(),
        monitoring_lanes: Vec::new(),
        intel_matches: Vec::new(),
        findings: Vec::new(),
        triage_actions: Vec::new(),
        diff: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CorrelationInfo, NormalizedEvent, Severity};

    #[test]
    fn attach_events_preserves_unmapped_passive_signal() {
        let mut hosts = Vec::<HostReport>::new();
        let event = sample_unmapped_event("event:unmapped:1");

        let unmapped = attach_events(&mut hosts, vec![event]);

        assert_eq!(unmapped.len(), 1);
        assert_eq!(unmapped[0].correlation.method, "unmapped");
        assert!(hosts.is_empty());
    }

    #[test]
    fn build_report_counts_unmapped_events_in_summary() {
        let started_at = Utc::now();
        let report = build_report(
            "run-test",
            "Test",
            started_at,
            started_at,
            vec!["192.168.56.0/24".parse().expect("scope")],
            vec![80],
            "bezny",
            "demo",
            "freeze",
            determine_passive_window(started_at, started_at),
            SourceMetadata::default(),
            Vec::new(),
            vec![sample_unmapped_event("event:unmapped:2")],
        );

        assert_eq!(report.summary.events_total, 1);
        assert_eq!(report.summary.unmapped_events_total, 1);
        assert_eq!(report.unmapped_events.len(), 1);
    }

    fn sample_unmapped_event(event_id: &str) -> CorrelatedEvent {
        CorrelatedEvent {
            event: NormalizedEvent {
                event_id: event_id.to_string(),
                timestamp: Utc::now(),
                src_ip: Some("192.168.56.200".to_string()),
                dst_ip: "192.168.56.250".to_string(),
                proto: "tcp".to_string(),
                dst_port: Some(8080),
                event_type: "unexpected_traffic".to_string(),
                severity: Severity::Medium,
                source: "test".to_string(),
                rule_id: None,
                message: "pasivni udalost bez aktivniho hosta".to_string(),
                raw_ref: None,
                count: 1,
            },
            correlation: CorrelationInfo {
                method: "unmapped".to_string(),
                confidence: Confidence::Low,
                time_window_s: 3600,
                host_id: None,
                service_id: None,
            },
        }
    }
}
