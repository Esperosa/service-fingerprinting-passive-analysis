use crate::model::{Confidence, RunReport, Severity, TriageAction};

pub fn build_triage_actions(report: &RunReport) -> Vec<TriageAction> {
    let mut actions = Vec::new();

    for service in report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| service.priorita == "vysoka")
    {
        actions.push(TriageAction {
            action_id: format!("triage:service:{}", service.service_key),
            action_type: "deep-service-review".to_string(),
            title: format!("Hlubší audit služby {}", service.service_key),
            priority: Severity::High,
            rationale: "Služba kombinuje vysokou prioritu se zjištěními, která zaslouží credentialed nebo detailnější ověření.".to_string(),
            target_asset_id: None,
            target_service_key: Some(service.service_key.clone()),
            recommended_tools: vec![
                "greenbone".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
                "config-review".to_string(),
            ],
            evidence: service
                .active_checks
                .iter()
                .map(|check| format!("active_check={}", check.template_id))
                .chain(service.cves.iter().map(|cve| format!("cve={}", cve.cve_id)))
                .collect(),
        });
    }

    for asset in report.network_assets.iter().filter(|asset| {
        asset.asset_type == "access-point"
            || asset.asset_type == "switch"
            || asset.asset_type == "firewall"
    }) {
        if asset.linked_host_key.is_none() {
            actions.push(TriageAction {
                action_id: format!("triage:asset-link:{}", asset.asset_id),
                action_type: "inventory-gap".to_string(),
                title: format!("Doplnit vazbu pro asset {}", asset.name),
                priority: Severity::Medium,
                rationale: "Asset je vidět z autorizovaného zdroje, ale není spárovaný s aktivním inventářem hostů.".to_string(),
                target_asset_id: Some(asset.asset_id.clone()),
                target_service_key: None,
                recommended_tools: vec![
                    "snmp".to_string(),
                    "lldp".to_string(),
                    "nmap".to_string(),
                ],
                evidence: vec![
                    format!("source={}", asset.source),
                    format!("confidence={:?}", Confidence::Medium).to_lowercase(),
                ],
            });
        }
    }

    if report.summary.events_total == 0 {
        actions.push(TriageAction {
            action_id: "triage:enable-live-monitoring".to_string(),
            action_type: "monitoring-gap".to_string(),
            title: "Doplnit live monitoring provozu".to_string(),
            priority: Severity::Medium,
            rationale: "Aktuální běh nemá žádné pasivní události, takže nepopisuje skutečné chování provozu v čase.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "suricata".to_string(),
                "zeek".to_string(),
                "ntopng".to_string(),
            ],
            evidence: vec!["events_total=0".to_string()],
        });
    }

    let overload_findings = report
        .findings
        .iter()
        .filter(|item| {
            item.finding_type == "service_overload_risk"
                || item.finding_type == "packet_rate_spike"
                || item.finding_type == "connection_timeout_burst"
        })
        .collect::<Vec<_>>();
    let inductive_findings = report
        .findings
        .iter()
        .filter(|item| item.finding_type == "inductive_volume_anomaly")
        .collect::<Vec<_>>();
    if !overload_findings.is_empty() {
        actions.push(TriageAction {
            action_id: "triage:traffic-overload-mitigation".to_string(),
            action_type: "aggressive-mitigation".to_string(),
            title: "Aktivovat agresivnější ochranu proti přetížení".to_string(),
            priority: Severity::High,
            rationale:
                "Detekce ukazuje timeouty/rate spike nebo přímé riziko přetížení; bez okamžité mitigace hrozí degradace nebo nedostupnost služby."
                    .to_string(),
            target_asset_id: None,
            target_service_key: overload_findings
                .iter()
                .find_map(|item| item.service_key.clone()),
            recommended_tools: vec![
                "rate-limit".to_string(),
                "traffic-shaping".to_string(),
                "waf".to_string(),
                "firewall".to_string(),
            ],
            evidence: overload_findings
                .iter()
                .take(6)
                .map(|item| format!("{}:{}", item.finding_type, item.service_key.clone().unwrap_or_default()))
                .collect(),
        });
    }
    if !inductive_findings.is_empty() {
        actions.push(TriageAction {
            action_id: "triage:inductive-anomaly-review".to_string(),
            action_type: "inductive-review".to_string(),
            title: "Forenzně potvrdit induktivní outlier nálezy".to_string(),
            priority: Severity::High,
            rationale:
                "Nešablonová datová indukce signalizuje netypické chování, které nemusí být pokryté signaturami; vyžaduje rychlé potvrzení proti baseline."
                    .to_string(),
            target_asset_id: None,
            target_service_key: inductive_findings
                .iter()
                .find_map(|item| item.service_key.clone()),
            recommended_tools: vec![
                "pcap-review".to_string(),
                "zeek".to_string(),
                "suricata".to_string(),
                "baseline-profiler".to_string(),
            ],
            evidence: inductive_findings
                .iter()
                .take(6)
                .map(|item| format!("{}:{}", item.finding_type, item.service_key.clone().unwrap_or_default()))
                .collect(),
        });
    }

    if report
        .intel_matches
        .iter()
        .any(|item| item.severity == Severity::High)
    {
        actions.push(TriageAction {
            action_id: "triage:intel-confirmation".to_string(),
            action_type: "intel-confirmation".to_string(),
            title: "Potvrdit indikátory z externích feedů".to_string(),
            priority: Severity::High,
            rationale:
                "Externí reputační nebo IOC feed vrátil vysoce závažnou shodu; ta zvyšuje prioritu ručního potvrzení, ale sama o sobě nenahrazuje lokální důkaz kompromitace."
                    .to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "urlhaus".to_string(),
                "abuseipdb".to_string(),
                "pcap-review".to_string(),
            ],
            evidence: report
                .intel_matches
                .iter()
                .filter(|item| item.severity == Severity::High)
                .take(5)
                .map(|item| format!("{}={}", item.source, item.indicator))
                .collect(),
        });
    }

    if report.summary.live_lanes_total == 0 {
        actions.push(TriageAction {
            action_id: "triage:add-live-lane".to_string(),
            action_type: "visibility-gap".to_string(),
            title: "Doplnit rychlou live pipeline".to_string(),
            priority: Severity::Medium,
            rationale:
                "Běh neobsahuje žádnou live lane nad flow telemetrií, takže neukazuje průběžný obraz provozu v síti."
                    .to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "suricata".to_string(),
                "zeek".to_string(),
                "ntopng".to_string(),
                "ipfix".to_string(),
            ],
            evidence: vec!["live_lanes_total=0".to_string()],
        });
    }

    if report.summary.audit_lanes_total == 0 {
        actions.push(TriageAction {
            action_id: "triage:add-audit-lane".to_string(),
            action_type: "audit-gap".to_string(),
            title: "Doplnit pomalou auditní pipeline".to_string(),
            priority: Severity::Medium,
            rationale:
                "Bez Greenbone/Wazuh/konfigurační auditní lane systém neověřuje credentialed a konfigurační stav zařízení."
                    .to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "greenbone".to_string(),
                "wazuh".to_string(),
                "napalm".to_string(),
                "scrapli".to_string(),
            ],
            evidence: vec!["audit_lanes_total=0".to_string()],
        });
    }

    if report.summary.network_assets_total == 0 {
        actions.push(TriageAction {
            action_id: "triage:add-authorized-network-context".to_string(),
            action_type: "visibility-gap".to_string(),
            title: "Přidat autorizované síťové kontexty".to_string(),
            priority: Severity::Medium,
            rationale: "Bez SNMP/LLDP/Wi-Fi controller dat neuvidí report fyzickou topologii ani bezdrátové klienty.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "snmp".to_string(),
                "lldp".to_string(),
                "meraki".to_string(),
                "librenms".to_string(),
            ],
            evidence: vec!["network_assets_total=0".to_string()],
        });
    }

    actions.sort_by(|left, right| right.priority.cmp(&left.priority));
    actions.dedup_by(|left, right| left.action_id == right.action_id);
    actions
}
