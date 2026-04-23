use std::collections::BTreeSet;

use crate::model::{Finding, MonitoringLane, RunReport, Severity, TriageAction};

#[derive(Debug, Clone)]
pub struct ValidationBundle {
    pub lanes: Vec<MonitoringLane>,
    pub actions: Vec<TriageAction>,
}

pub fn build_validation_bundle(report: &RunReport) -> ValidationBundle {
    let cves = collect_cves(report);
    let exploit_context_total = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.cves.iter())
        .filter(|cve| {
            cve.exploit_context
                .as_ref()
                .is_some_and(|context| context.epss.is_some() || context.cisa_kev.is_some())
        })
        .count();
    let active_checks_total = report.summary.active_checks_total;
    let internal_pentest_checks_total = internal_pentest_checks_total(report);
    let aggressive_pentest_checks_total = aggressive_pentest_checks_total(report);
    let web_targets_total = web_targets_total(report);
    let plaintext = matching_findings(
        report,
        &["plaintext_management_protocol", "http_basic_without_tls"],
    );
    let traffic = matching_findings(
        report,
        &[
            "unexpected_traffic",
            "external_flow_observed",
            "connection_timeout_burst",
            "packet_rate_spike",
            "packet_loss_signal",
            "service_overload_risk",
            "inductive_volume_anomaly",
        ],
    );
    let cve_findings = matching_findings(
        report,
        &[
            "high_risk_cve_exposure",
            "known_exploited_vulnerability",
            "probable_exploitation_interest",
        ],
    );
    let exposed_changes = report
        .diff
        .as_ref()
        .map(|diff| {
            diff.changed_services
                .iter()
                .filter(|item| item.change_type == "nova_sluzba")
                .count()
        })
        .unwrap_or(0);

    let mut lanes = vec![
        validation_matrix_lane(
            report,
            cves.len(),
            exploit_context_total,
            active_checks_total,
            internal_pentest_checks_total,
            aggressive_pentest_checks_total,
            plaintext.len(),
            traffic.len(),
        ),
        safe_pentest_lane(
            report,
            web_targets_total,
            report.summary.web_probes_total,
            active_checks_total,
            internal_pentest_checks_total,
            aggressive_pentest_checks_total,
            cves.len(),
            traffic.len(),
        ),
        ai_context_bridge_lane(report),
    ];

    let mut actions = Vec::new();
    if !cves.is_empty() || !cve_findings.is_empty() {
        actions.push(TriageAction {
            action_id: format!("validation:cve-proof-agent:{}", report.run.run_id),
            action_type: "spawn-agent:cve-proof-agent".to_string(),
            title: "Ověřit CVE bezpečným důkazním průchodem".to_string(),
            priority: Severity::High,
            rationale: "CVE záznam sám nestačí. Agent má bez destruktivního exploitu spojit CPE, verzi, NVD, KEV, EPSS, CIRCL/OSV, dostupnost služby a případný řízený web check.".to_string(),
            target_asset_id: None,
            target_service_key: first_finding_target(&cve_findings),
            recommended_tools: vec![
                "nvd".to_string(),
                "cisa-kev".to_string(),
                "first-epss".to_string(),
                "circl".to_string(),
                "osv".to_string(),
                "greenbone".to_string(),
                "nuclei-controlled".to_string(),
            ],
            evidence: cves.iter().take(8).map(|cve| format!("cve={cve}")).collect(),
        });
    }

    if web_targets_total > 0 && active_checks_total == 0 {
        actions.push(TriageAction {
            action_id: format!("validation:web-pentest-agent:{}", report.run.run_id),
            action_type: "spawn-agent:web-pentest-agent".to_string(),
            title: "Doplnit řízený web pentest pro HTTP služby".to_string(),
            priority: Severity::Medium,
            rationale: "Běh vidí HTTP/HTTPS služby, ale nemá potvrzené aktivní web checks. Agent má spustit pouze kontrolované nedestruktivní šablony a uložit přesný důkaz.".to_string(),
            target_asset_id: None,
            target_service_key: first_web_target(report),
            recommended_tools: vec![
                "httpx".to_string(),
                "nuclei-controlled".to_string(),
                "tls-grab".to_string(),
                "headers-review".to_string(),
            ],
            evidence: vec![
                format!("web_targets={web_targets_total}"),
                format!("active_checks={active_checks_total}"),
            ],
        });
    }

    if !plaintext.is_empty() {
        actions.push(TriageAction {
            action_id: format!("validation:credential-exposure-agent:{}", report.run.run_id),
            action_type: "spawn-agent:credential-exposure-validator".to_string(),
            title: "Potvrdit riziko nešifrovaného přihlášení".to_string(),
            priority: Severity::High,
            rationale: "Nešifrovaný protokol je potřeba ověřit proti pasivním důkazům, zdrojům, portům a opakování v čase. Agent nemá číst hesla, ale potvrdit, zda takový provoz skutečně existuje.".to_string(),
            target_asset_id: None,
            target_service_key: first_finding_target(&plaintext),
            recommended_tools: vec![
                "zeek".to_string(),
                "suricata".to_string(),
                "pcap-metadata-review".to_string(),
                "firewall-scope-check".to_string(),
            ],
            evidence: plaintext
                .iter()
                .take(8)
                .map(|finding| format!("plaintext={}", target_of(finding)))
                .collect(),
        });
    }

    if !traffic.is_empty() {
        actions.push(TriageAction {
            action_id: format!("validation:traffic-forensic-agent:{}", report.run.run_id),
            action_type: "spawn-agent:traffic-pcap-analyst".to_string(),
            title: "Forenzně ověřit podezřelé síťové vzorce".to_string(),
            priority: Severity::High,
            rationale: "Provozní anomálie potřebuje časový kontext, objemy, směry, timeouty a vazbu na běžné služby. Agent má porovnat flow, Zeek a Suricata důkazy a říct, co je fakt a co hypotéza.".to_string(),
            target_asset_id: None,
            target_service_key: first_finding_target(&traffic),
            recommended_tools: vec![
                "zeek".to_string(),
                "suricata".to_string(),
                "netflow-ipfix".to_string(),
                "ntopng".to_string(),
                "baseline-profiler".to_string(),
            ],
            evidence: traffic
                .iter()
                .take(8)
                .map(|finding| format!("traffic={} target={}", finding.finding_type, target_of(finding)))
                .collect(),
        });
    }

    if exposed_changes > 0 {
        actions.push(TriageAction {
            action_id: format!("validation:exposure-retest-agent:{}", report.run.run_id),
            action_type: "spawn-agent:exposure-retest-agent".to_string(),
            title: "Znovu ověřit nově exponované služby".to_string(),
            priority: Severity::Medium,
            rationale: "Nová služba proti baseline může být legitimní změna i riziko. Agent má zopakovat bezpečný aktivní dotaz, zkontrolovat vlastnictví změny a propojit výsledek s pasivním provozem.".to_string(),
            target_asset_id: None,
            target_service_key: report
                .diff
                .as_ref()
                .and_then(|diff| diff.changed_services.first().map(|item| item.service_key.clone())),
            recommended_tools: vec![
                "nmap-followup".to_string(),
                "service-banner".to_string(),
                "controller-context".to_string(),
                "change-review".to_string(),
            ],
            evidence: vec![format!("new_exposed_services={exposed_changes}")],
        });
    }

    if actions.is_empty() {
        actions.push(TriageAction {
            action_id: format!("validation:kill-aggressive-pentest:{}", report.run.run_id),
            action_type: "kill-agent:aggressive-pentest".to_string(),
            title: "Nechat agresivní pentest vypnutý".to_string(),
            priority: Severity::Low,
            rationale: "V běhu není dost silný signál pro invazivnější testování. Bezpečný profil má zůstat u monitoringu, inventáře a opakovaného ověření při novém důkazu.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec!["scheduler".to_string(), "policy-gate".to_string()],
            evidence: vec!["reason=no-validation-target".to_string()],
        });
    }

    lanes.sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    actions.sort_by(|left, right| right.priority.cmp(&left.priority));
    ValidationBundle { lanes, actions }
}

fn validation_matrix_lane(
    report: &RunReport,
    cves_total: usize,
    exploit_context_total: usize,
    active_checks_total: usize,
    internal_pentest_checks_total: usize,
    aggressive_pentest_checks_total: usize,
    plaintext_total: usize,
    traffic_total: usize,
) -> MonitoringLane {
    let validation_score = validation_score(
        cves_total,
        exploit_context_total,
        active_checks_total,
        internal_pentest_checks_total,
        plaintext_total,
        traffic_total,
    );
    MonitoringLane {
        lane_id: format!("lane:validation:matrix:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "validation-matrix".to_string(),
        title: "Důkazní validační matice".to_string(),
        status: if validation_score >= 0.78 {
            "ok"
        } else if validation_score >= 0.52 {
            "limited"
        } else {
            "pending"
        }
        .to_string(),
        summary: format!(
            "Validační vrstva spočítala důkazní skóre {:.0} % z CVE kontextu, interního pentestu, aktivních checků, nešifrovaného přihlášení a provozní forenziky.",
            validation_score * 100.0
        ),
        evidence: vec![
            format!("validation_score={validation_score:.2}"),
            format!("cves={cves_total}"),
            format!("exploit_context={exploit_context_total}"),
            format!("active_checks={active_checks_total}"),
            format!("internal_pentest_checks={internal_pentest_checks_total}"),
            format!("aggressive_pentest_checks={aggressive_pentest_checks_total}"),
            format!("plaintext_findings={plaintext_total}"),
            format!("traffic_findings={traffic_total}"),
        ],
        recommended_tools: vec![
            "nmap".to_string(),
            "bakula-internal-pentest".to_string(),
            "httpx-optional".to_string(),
            "nuclei-controlled-optional".to_string(),
            "zeek".to_string(),
            "suricata".to_string(),
            "greenbone".to_string(),
        ],
    }
}

fn safe_pentest_lane(
    report: &RunReport,
    web_targets_total: usize,
    web_probes_total: usize,
    active_checks_total: usize,
    internal_pentest_checks_total: usize,
    aggressive_pentest_checks_total: usize,
    cves_total: usize,
    traffic_total: usize,
) -> MonitoringLane {
    let has_work = web_targets_total > 0 || cves_total > 0 || traffic_total > 0;
    let active_confirmation =
        web_probes_total > 0 || active_checks_total > 0 || internal_pentest_checks_total > 0;
    MonitoringLane {
        lane_id: format!("lane:validation:safe-pentest:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "safe-pentest-validator".to_string(),
        title: "Bezpečný pentest validátor".to_string(),
        status: if active_confirmation {
            "ok"
        } else if has_work {
            "limited"
        } else {
            "idle"
        }
        .to_string(),
        summary: if active_checks_total > 0 {
            "Program už má aktivní kontrolované checks a může je použít jako přesnější důkaz."
                .to_string()
        } else if internal_pentest_checks_total > 0 {
            "Vestavěný pentest engine potvrdil aktivní důkazy bez závislosti na externích binárkách."
                .to_string()
        } else if web_probes_total > 0 {
            "Program má web fingerprinting jako aktivní důkaz dostupnosti a další checks může navázat na konkrétní odpovědi.".to_string()
        } else if has_work {
            "Program má cíle pro bezpečný pentest, ale v tomto běhu zatím nemá aktivní potvrzení odpovědi cíle.".to_string()
        } else {
            "Program nevidí cíl, který by dával smysl bezpečně pentestovat.".to_string()
        },
        evidence: vec![
            format!("web_targets={web_targets_total}"),
            format!("web_probes={web_probes_total}"),
            format!("active_checks={active_checks_total}"),
            format!("internal_pentest_checks={internal_pentest_checks_total}"),
            format!("aggressive_pentest_checks={aggressive_pentest_checks_total}"),
            format!("cves={cves_total}"),
            format!("traffic_findings={traffic_total}"),
            "policy=non-destructive-authorized".to_string(),
        ],
        recommended_tools: vec![
            "bakula-internal-pentest".to_string(),
            "bakula-tcp-probe".to_string(),
            "bakula-http-prober".to_string(),
            "nmap-safe-scripts".to_string(),
            "greenbone-authenticated".to_string(),
        ],
    }
}

fn validation_score(
    cves_total: usize,
    exploit_context_total: usize,
    active_checks_total: usize,
    internal_pentest_checks_total: usize,
    plaintext_total: usize,
    traffic_total: usize,
) -> f64 {
    let cve_signal = if cves_total == 0 {
        1.0
    } else {
        (exploit_context_total as f64 / cves_total as f64).clamp(0.0, 1.0)
    };
    let active_signal =
        ((active_checks_total + internal_pentest_checks_total) as f64 / 6.0).clamp(0.0, 1.0);
    let passive_signal = ((plaintext_total + traffic_total) as f64 / 8.0).clamp(0.0, 1.0);
    ((cve_signal * 0.42) + (active_signal * 0.34) + (passive_signal * 0.24)).clamp(0.0, 1.0)
}

fn ai_context_bridge_lane(report: &RunReport) -> MonitoringLane {
    MonitoringLane {
        lane_id: format!("lane:validation:ai-context:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "ai-context-bridge".to_string(),
        title: "Dynamický kontext pro Skokyho".to_string(),
        status: "ok".to_string(),
        summary: "AI dostává souhrn běhu, vybraný host/službu/nález, top rizika, agentní lane, doporučené nástroje a zdroje místo pevného statického textu.".to_string(),
        evidence: vec![
            format!("findings={}", report.summary.findings_total),
            format!("lanes={}", report.summary.monitoring_lanes_total),
            format!("intel_matches={}", report.summary.intel_matches_total),
            format!("triage_actions={}", report.summary.triage_actions_total),
        ],
        recommended_tools: vec![
            "ollama".to_string(),
            "context-json".to_string(),
            "selected-node-context".to_string(),
            "evidence-sources".to_string(),
        ],
    }
}

fn collect_cves(report: &RunReport) -> Vec<String> {
    let mut cves = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.cves.iter())
        .map(|cve| cve.cve_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    cves.sort();
    cves
}

fn internal_pentest_checks_total(report: &RunReport) -> usize {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.active_checks.iter())
        .filter(|check| check.source == "bakula-internal-pentest")
        .count()
}

fn aggressive_pentest_checks_total(report: &RunReport) -> usize {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.active_checks.iter())
        .filter(|check| {
            check.source == "bakula-internal-pentest"
                && check.evidence.iter().any(|item| item == "mode=aggressive")
        })
        .count()
}

fn matching_findings<'a>(report: &'a RunReport, types: &[&str]) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| {
            types
                .iter()
                .any(|expected| finding.finding_type == *expected)
        })
        .collect()
}

fn web_targets_total(report: &RunReport) -> usize {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| {
            service.port_state == "open"
                && (service
                    .inventory
                    .service_name
                    .to_ascii_lowercase()
                    .contains("http")
                    || matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880))
        })
        .count()
}

fn first_web_target(report: &RunReport) -> Option<String> {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .find(|service| {
            service.port_state == "open"
                && (service
                    .inventory
                    .service_name
                    .to_ascii_lowercase()
                    .contains("http")
                    || matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880))
        })
        .map(|service| service.service_key.clone())
}

fn first_finding_target(findings: &[&Finding]) -> Option<String> {
    findings
        .iter()
        .find_map(|finding| finding.service_key.clone())
}

fn target_of(finding: &Finding) -> String {
    finding
        .service_key
        .as_deref()
        .or(finding.host_key.as_deref())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::storage::Workspace;

    use super::*;

    #[test]
    fn validation_bundle_adds_safe_pentest_and_context_lanes() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let report = Workspace::open(&workspace)
            .expect("workspace")
            .load_report("run-20260422133515-1-38d015c6d60447f598e4605cf2bf8f0d")
            .expect("report");
        let bundle = build_validation_bundle(&report);
        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "safe-pentest-validator")
        );
        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "ai-context-bridge")
        );
        assert!(
            bundle
                .actions
                .iter()
                .any(|action| action.action_type.starts_with("spawn-agent:"))
        );
    }
}
