use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Result, ai, automation, intel,
    model::{RunReport, Severity},
    storage::Workspace,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionReadinessReport {
    pub generated_at: DateTime<Utc>,
    pub workspace: String,
    pub status: String,
    pub grade: String,
    pub score: f64,
    #[serde(default)]
    pub latest_run_id: Option<String>,
    #[serde(default)]
    pub checks: Vec<ReadinessCheck>,
    #[serde(default)]
    pub blockers: Vec<String>,
    #[serde(default)]
    pub next_steps: Vec<String>,
    #[serde(default)]
    pub commercial_gap_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub check_id: String,
    pub category: String,
    pub label: String,
    pub status: String,
    pub score: f64,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub next_step: String,
}

pub fn assess_workspace(
    workspace_root: &Path,
    auth_required: bool,
) -> Result<ProductionReadinessReport> {
    let workspace = Workspace::open(workspace_root)?;
    let runs = workspace.list_runs()?;
    let latest_run_id = runs.first().map(|run| run.run_id.clone());
    let latest_report = latest_run_id
        .as_deref()
        .map(|run_id| workspace.load_report(run_id))
        .transpose()?;
    let automation_latest = load_automation(workspace_root);
    let verification = load_verification_summary(workspace_root);
    let ai_diagnostic = ai::diagnose();

    let mut checks = Vec::new();
    push_active_inventory(&mut checks, latest_report.as_ref());
    push_vulnerability_enrichment(&mut checks, latest_report.as_ref());
    push_vulners_automation(&mut checks, latest_report.as_ref());
    push_passive_monitoring(&mut checks, latest_report.as_ref());
    push_live_telemetry(&mut checks, latest_report.as_ref());
    push_decision_engine(&mut checks, latest_report.as_ref());
    push_safe_pentest_validation(&mut checks, latest_report.as_ref());
    push_agent_governor(
        &mut checks,
        latest_report.as_ref(),
        automation_latest.as_ref(),
    );
    push_local_ai(&mut checks, &ai_diagnostic);
    push_security(&mut checks, auth_required);
    push_evidence_retention(&mut checks, workspace_root, latest_run_id.as_deref());
    push_verification(&mut checks, verification.as_ref());

    let score = if checks.is_empty() {
        0.0
    } else {
        round_ratio(checks.iter().map(|check| check.score).sum::<f64>() / checks.len() as f64)
    };
    let status = if checks.iter().any(|check| check.status == "fail") {
        "limited"
    } else if score >= 0.92 {
        "professional-ready"
    } else {
        "operational"
    }
    .to_string();
    let grade = if score >= 0.92 {
        "A"
    } else if score >= 0.82 {
        "B"
    } else if score >= 0.68 {
        "C"
    } else {
        "D"
    }
    .to_string();
    let blockers = checks
        .iter()
        .filter(|check| check.status == "fail")
        .map(|check| format!("{}: {}", check.label, check.next_step))
        .collect::<Vec<_>>();
    let next_steps = checks
        .iter()
        .filter(|check| check.status != "pass")
        .map(|check| format!("{}: {}", check.label, check.next_step))
        .take(6)
        .collect::<Vec<_>>();
    let commercial_gap_notes = commercial_gap_notes(&checks);

    Ok(ProductionReadinessReport {
        generated_at: Utc::now(),
        workspace: workspace_root.display().to_string(),
        status,
        grade,
        score,
        latest_run_id,
        checks,
        blockers,
        next_steps,
        commercial_gap_notes,
    })
}

fn push_active_inventory(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    match report {
        Some(report) if report.summary.hosts_total > 0 && report.summary.services_total > 0 => {
            checks.push(pass(
                "active-inventory",
                "engine",
                "Aktivní inventář služeb",
                vec![
                    format!("hosts={}", report.summary.hosts_total),
                    format!("services={}", report.summary.services_total),
                    format!(
                        "nmap_mode={}",
                        report.run.sources.nmap_mode.as_deref().unwrap_or("replay")
                    ),
                ],
            ));
        }
        Some(report) => checks.push(warn(
            "active-inventory",
            "engine",
            "Aktivní inventář služeb",
            vec![
                format!("hosts={}", report.summary.hosts_total),
                format!("services={}", report.summary.services_total),
            ],
            "Spusť běh se skutečným Nmap vstupem nebo s povoleným live Nmap režimem.",
            0.45,
        )),
        None => checks.push(fail(
            "active-inventory",
            "engine",
            "Aktivní inventář služeb",
            vec!["latest_run=missing".to_string()],
            "Vytvoř alespoň jeden běh, aby šlo hodnotit engine a UI nad reálným reportem.",
        )),
    }
}

fn push_vulnerability_enrichment(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let Some(report) = report else {
        checks.push(fail(
            "vulnerability-enrichment",
            "intel",
            "CVE obohacení",
            vec!["latest_run=missing".to_string()],
            "Bez reportu nejde ověřit CVE obohacení.",
        ));
        return;
    };
    let production_provider = matches!(
        report.run.provider.as_str(),
        "nvd" | "vulners" | "public" | "auto"
    );
    if report.summary.cves_total > 0 && production_provider {
        checks.push(pass(
            "vulnerability-enrichment",
            "intel",
            "CVE obohacení",
            vec![
                format!("provider={}", report.run.provider),
                format!("cves={}", report.summary.cves_total),
                format!("public_context={}", has_public_intel_context(report)),
            ],
        ));
    } else if report.summary.cves_total > 0 {
        checks.push(warn(
            "vulnerability-enrichment",
            "intel",
            "CVE obohacení",
            vec![
                format!("provider={}", report.run.provider),
                format!("cves={}", report.summary.cves_total),
            ],
            "Pro produkční provoz přepni provider na public, nvd nebo vulners a drž demo provider jen pro offline test.",
            0.72,
        ));
    } else {
        checks.push(warn(
            "vulnerability-enrichment",
            "intel",
            "CVE obohacení",
            vec![
                format!("provider={}", report.run.provider),
                "cves=0".to_string(),
            ],
            "Ověř CPE identitu služeb a zapni public/NVD provider pro skutečné zranitelnosti.",
            0.42,
        ));
    }
}

fn push_vulners_automation(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let has_vulners_key = std::env::var("VULNERS_API_KEY")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let report_uses_vulners = report.is_some_and(|report| {
        report.run.provider == "vulners"
            || report
                .hosts
                .iter()
                .flat_map(|host| host.services.iter())
                .flat_map(|service| service.cves.iter())
                .any(|cve| cve.source == "vulners")
    });
    let has_public_context = report.is_some_and(has_public_intel_context);
    if has_public_context || has_vulners_key || report_uses_vulners {
        checks.push(pass(
            "vulners-automation",
            "intel",
            "Veřejný intel stack a volitelný Vulners",
            vec![
                format!("public_context={has_public_context}"),
                format!("vulners_key={has_vulners_key}"),
                format!("report_uses_vulners={report_uses_vulners}"),
                format!("catalog_sources={}", intel::public_intel_sources().len()),
            ],
        ));
    } else {
        checks.push(warn(
            "vulners-automation",
            "intel",
            "Veřejný intel stack a volitelný Vulners",
            vec![
                format!("public_context={has_public_context}"),
                "VULNERS_API_KEY=optional-missing".to_string(),
                format!("report_uses_vulners={report_uses_vulners}"),
            ],
            "Spusť nový běh s public providerem a CIRCL/OSV/KEV/EPSS kontextem; Vulners klíč nech jako volitelný bonus.",
            0.68,
        ));
    }
}

fn push_passive_monitoring(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let Some(report) = report else {
        checks.push(fail(
            "passive-monitoring",
            "passive",
            "Pasivní monitoring",
            vec!["latest_run=missing".to_string()],
            "Přidej Suricata EVE nebo Zeek adresář a spusť nový běh.",
        ));
        return;
    };
    let has_passive_source = report.run.sources.suricata_eve.is_some()
        || report.run.sources.zeek_dir.is_some()
        || report
            .monitoring_lanes
            .iter()
            .any(|lane| matches!(lane.source.as_str(), "suricata" | "zeek"));
    if has_passive_source && report.summary.events_total > 0 {
        checks.push(pass(
            "passive-monitoring",
            "passive",
            "Pasivní monitoring",
            vec![
                format!("events={}", report.summary.events_total),
                format!("live_lanes={}", report.summary.live_lanes_total),
            ],
        ));
    } else if has_passive_source {
        checks.push(warn(
            "passive-monitoring",
            "passive",
            "Pasivní monitoring",
            vec![
                "passive_source=true".to_string(),
                format!("events={}", report.summary.events_total),
            ],
            "Zkontroluj časové okno a korelaci IP/port, protože zdroj existuje, ale nepřinesl události.",
            0.7,
        ));
    } else {
        checks.push(fail(
            "passive-monitoring",
            "passive",
            "Pasivní monitoring",
            vec!["passive_source=false".to_string()],
            "Připoj Zeek/Suricata vstup, jinak program neplní pasivní část zadání v produkčním běhu.",
        ));
    }
}

fn push_live_telemetry(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let Some(report) = report else {
        checks.push(fail(
            "live-telemetry",
            "passive",
            "Live a flow telemetrie",
            vec!["latest_run=missing".to_string()],
            "Bez reportu nejde ověřit live telemetry.",
        ));
        return;
    };
    let has_live_source = report.run.sources.ntopng_snapshot.is_some()
        || report.run.sources.flow_snapshot.is_some()
        || report.summary.live_lanes_total > 0;
    if has_live_source && report.summary.live_lanes_total > 0 {
        checks.push(pass(
            "live-telemetry",
            "passive",
            "Live a flow telemetrie",
            vec![
                format!("live_lanes={}", report.summary.live_lanes_total),
                format!("realtime_sources={}", report.summary.realtime_sources_total),
            ],
        ));
    } else {
        checks.push(warn(
            "live-telemetry",
            "passive",
            "Live a flow telemetrie",
            vec![
                format!("live_source={has_live_source}"),
                format!("live_lanes={}", report.summary.live_lanes_total),
            ],
            "Pro komerční srovnání připoj ntopng nebo NetFlow/IPFIX snapshot a nech ho korelovat s nálezy.",
            0.64,
        ));
    }
}

fn push_decision_engine(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let Some(report) = report else {
        checks.push(fail(
            "decision-engine",
            "decision",
            "Forenzní decision engine",
            vec!["latest_run=missing".to_string()],
            "Bez reportu nejde ověřit rozhodovací vrstva.",
        ));
        return;
    };
    let has_ranking = has_lane(report, "decision-risk-ranking");
    let has_inference = has_lane(report, "decision-inference-graph");
    let has_triage = !report.triage_actions.is_empty();
    if has_ranking && has_inference && has_triage {
        checks.push(pass(
            "decision-engine",
            "decision",
            "Forenzní decision engine",
            vec![
                format!("risk_ranking={has_ranking}"),
                format!("inference_graph={has_inference}"),
                format!("triage={}", report.triage_actions.len()),
            ],
        ));
    } else {
        checks.push(warn(
            "decision-engine",
            "decision",
            "Forenzní decision engine",
            vec![
                format!("risk_ranking={has_ranking}"),
                format!("inference_graph={has_inference}"),
                format!("triage={}", report.triage_actions.len()),
            ],
            "Spusť běh přes aktuální pipeline, aby se doplnily decision lane, ranking a agentní doporučení.",
            0.6,
        ));
    }
}

fn push_safe_pentest_validation(checks: &mut Vec<ReadinessCheck>, report: Option<&RunReport>) {
    let Some(report) = report else {
        checks.push(fail(
            "safe-pentest-validation",
            "decision",
            "Bezpečné ověření a pentest validace",
            vec!["latest_run=missing".to_string()],
            "Bez reportu nejde ověřit validační/pentestovací vrstvu.",
        ));
        return;
    };
    let has_matrix = has_lane(report, "validation-matrix");
    let has_safe_pentest = has_lane(report, "safe-pentest-validator");
    let has_ai_bridge = has_lane(report, "ai-context-bridge");
    let web_targets_total = report
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
                    || matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880 | 6789))
        })
        .count();
    let has_active_web_confirmation = report.summary.web_probes_total > 0
        || report.summary.active_checks_total > 0
        || lane_metric(report, "internal-pentest", "tcp_reachable").unwrap_or(0) > 0;
    let validation_actions = report
        .triage_actions
        .iter()
        .filter(|action| {
            matches!(
                action.action_type.as_str(),
                "spawn-agent:cve-proof-agent"
                    | "spawn-agent:web-pentest-agent"
                    | "spawn-agent:credential-exposure-validator"
                    | "spawn-agent:traffic-pcap-analyst"
                    | "spawn-agent:exposure-retest-agent"
            )
        })
        .count();
    let has_signal = report.summary.cves_total > 0
        || report.summary.events_total > 0
        || report.summary.web_probes_total > 0
        || report.summary.active_checks_total > 0
        || report.summary.findings_total > 0;
    if has_matrix
        && has_safe_pentest
        && has_ai_bridge
        && (validation_actions > 0 || has_signal)
        && (web_targets_total == 0 || has_active_web_confirmation)
    {
        checks.push(pass(
            "safe-pentest-validation",
            "decision",
            "Bezpečné ověření a pentest validace",
            vec![
                format!("validation_matrix={has_matrix}"),
                format!("safe_pentest={has_safe_pentest}"),
                format!("ai_context_bridge={has_ai_bridge}"),
                format!("validation_actions={validation_actions}"),
                format!("active_checks={}", report.summary.active_checks_total),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("web_targets={web_targets_total}"),
                format!("cves={}", report.summary.cves_total),
            ],
        ));
    } else if has_matrix
        && has_safe_pentest
        && has_ai_bridge
        && (validation_actions > 0 || has_signal)
    {
        checks.push(warn(
            "safe-pentest-validation",
            "decision",
            "Bezpečné ověření a pentest validace",
            vec![
                format!("validation_matrix={has_matrix}"),
                format!("safe_pentest={has_safe_pentest}"),
                format!("ai_context_bridge={has_ai_bridge}"),
                format!("validation_actions={validation_actions}"),
                format!("active_checks={}", report.summary.active_checks_total),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("web_targets={web_targets_total}"),
            ],
            "Validační/pentest agenti jsou vytvoření, ale web cíle v posledním běhu neodpověděly. Pro plné aktivní potvrzení spusť běh v dosahu cílové sítě nebo připoj výsledky autorizovaného web scanneru.",
            0.88,
        ));
    } else {
        checks.push(warn(
            "safe-pentest-validation",
            "decision",
            "Bezpečné ověření a pentest validace",
            vec![
                format!("validation_matrix={has_matrix}"),
                format!("safe_pentest={has_safe_pentest}"),
                format!("ai_context_bridge={has_ai_bridge}"),
                format!("validation_actions={validation_actions}"),
                format!("signal={has_signal}"),
                format!("web_targets={web_targets_total}"),
            ],
            "Spusť nový běh přes aktuální pipeline, aby nálezy prošly validační maticí a bezpečným pentest validátorem.",
            0.62,
        ));
    }
}

fn push_agent_governor(
    checks: &mut Vec<ReadinessCheck>,
    report: Option<&RunReport>,
    automation_latest: Option<&automation::AutomationReport>,
) {
    let agent_count = automation_latest
        .map(|item| item.summary.automation_agents_total)
        .or_else(|| report.map(|report| report.summary.automation_agents_total))
        .unwrap_or(0);
    let has_lifecycle = report.is_some_and(|report| has_lane(report, "agent-lifecycle"));
    let consensus = automation_latest
        .map(|item| item.summary.mas_consensus_score)
        .or_else(|| report.map(|report| report.summary.mas_consensus_score))
        .unwrap_or(0.0);
    if agent_count >= 14 && has_lifecycle && consensus >= 0.55 {
        checks.push(pass(
            "agent-governor",
            "decision",
            "Multiagentní governor",
            vec![
                format!("agents={agent_count}"),
                format!("lifecycle_lane={has_lifecycle}"),
                format!("consensus={consensus:.2}"),
            ],
        ));
    } else {
        checks.push(warn(
            "agent-governor",
            "decision",
            "Multiagentní governor",
            vec![
                format!("agents={agent_count}"),
                format!("lifecycle_lane={has_lifecycle}"),
                format!("consensus={consensus:.2}"),
            ],
            "Nech doběhnout autopilot a ověř, že summary obsahuje agent lifecycle, konsenzus a dynamické spawn/kill stopy.",
            0.58,
        ));
    }
}

fn push_local_ai(checks: &mut Vec<ReadinessCheck>, diagnostic: &ai::AiDiagnostic) {
    if diagnostic.status == "ready" {
        checks.push(pass(
            "local-ai",
            "ai",
            "Lokální AI Skoky",
            vec![
                format!("model={}", diagnostic.selected_model),
                format!("rules={}", diagnostic.knowledge_rules_total),
                format!("examples={}", diagnostic.training_examples_total),
                format!("public_sources={}", diagnostic.public_sources_total),
            ],
        ));
    } else {
        checks.push(warn(
            "local-ai",
            "ai",
            "Lokální AI Skoky",
            vec![
                format!("status={}", diagnostic.status),
                format!("model={}", diagnostic.selected_model),
                format!("public_sources={}", diagnostic.public_sources_total),
            ],
            "Spusť .\\scripts\\setup-skoky-ai.ps1 -Pull a znovu ověř cargo run -- ai diagnostika.",
            0.4,
        ));
    }
}

fn push_security(checks: &mut Vec<ReadinessCheck>, auth_required: bool) {
    if auth_required {
        checks.push(pass(
            "api-hardening",
            "platform",
            "Ochrana API/UI",
            vec!["api_token_required=true".to_string()],
        ));
    } else {
        checks.push(warn(
            "api-hardening",
            "platform",
            "Ochrana API/UI",
            vec!["api_token_required=false".to_string()],
            "Pro produkční server spusť UI s --require-api-token a tokenem v BAKULA_API_TOKEN.",
            0.66,
        ));
    }
}

fn push_evidence_retention(
    checks: &mut Vec<ReadinessCheck>,
    workspace_root: &Path,
    latest_run_id: Option<&str>,
) {
    let Some(run_id) = latest_run_id else {
        checks.push(fail(
            "evidence-retention",
            "platform",
            "Auditní artefakty",
            vec!["latest_run=missing".to_string()],
            "Vytvoř běh a ověř uložení report.json/report.md/report.txt/raw/manifest.",
        ));
        return;
    };
    let run_dir = workspace_root.join("runs").join(run_id);
    let expected = [
        "report.json",
        "report.md",
        "report.txt",
        "manifest.json",
        "raw/nmap.xml",
    ];
    let missing = expected
        .iter()
        .filter(|item| !run_dir.join(item).exists())
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        checks.push(pass(
            "evidence-retention",
            "platform",
            "Auditní artefakty",
            expected
                .iter()
                .map(|item| format!("exists={item}"))
                .collect(),
        ));
    } else {
        checks.push(warn(
            "evidence-retention",
            "platform",
            "Auditní artefakty",
            missing
                .iter()
                .map(|item| format!("missing={item}"))
                .collect(),
            "Zkontroluj ukládání raw artefaktů a exportů v adresáři běhu.",
            0.6,
        ));
    }
}

fn push_verification(checks: &mut Vec<ReadinessCheck>, verification: Option<&VerificationSummary>) {
    match verification {
        Some(summary) if summary.failed == 0 && summary.total > 0 => checks.push(pass(
            "verification",
            "quality",
            "Regresní ověření scénářů",
            vec![
                format!("passed={}", summary.passed),
                format!("total={}", summary.total),
            ],
        )),
        Some(summary) => checks.push(warn(
            "verification",
            "quality",
            "Regresní ověření scénářů",
            vec![
                format!("passed={}", summary.passed),
                format!("failed={}", summary.failed),
                format!("total={}", summary.total),
            ],
            "Spusť ověření scénářů a oprav selhané případy před produkčním předáním.",
            0.5,
        )),
        None => checks.push(warn(
            "verification",
            "quality",
            "Regresní ověření scénářů",
            vec!["verification/latest.json=missing".to_string()],
            "Spusť cargo test a případně bakula overeni spust nad scénáři, aby byla uložená auditní verifikace.",
            0.55,
        )),
    }
}

fn has_lane(report: &RunReport, source: &str) -> bool {
    report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == source)
}

fn lane_metric(report: &RunReport, source: &str, key: &str) -> Option<usize> {
    let prefix = format!("{key}=");
    report
        .monitoring_lanes
        .iter()
        .find(|lane| lane.source == source)
        .and_then(|lane| {
            lane.evidence.iter().find_map(|item| {
                item.strip_prefix(&prefix)
                    .and_then(|value| value.parse::<usize>().ok())
            })
        })
}

fn has_public_intel_context(report: &RunReport) -> bool {
    if matches!(report.run.provider.as_str(), "public" | "auto" | "nvd") {
        return true;
    }
    if report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.cves.iter())
        .any(|cve| {
            cve.source == "nvd"
                || cve
                    .exploit_context
                    .as_ref()
                    .is_some_and(|context| context.epss.is_some() || context.cisa_kev.is_some())
        })
    {
        return true;
    }
    report.intel_matches.iter().any(|item| {
        matches!(
            item.source.as_str(),
            "CIRCL Vulnerability-Lookup" | "OSV.dev" | "MITRE ATT&CK Context"
        )
    }) || report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "public-intel-stack")
}

fn pass(check_id: &str, category: &str, label: &str, evidence: Vec<String>) -> ReadinessCheck {
    ReadinessCheck {
        check_id: check_id.to_string(),
        category: category.to_string(),
        label: label.to_string(),
        status: "pass".to_string(),
        score: 1.0,
        evidence,
        next_step: "Bez zásahu.".to_string(),
    }
}

fn warn(
    check_id: &str,
    category: &str,
    label: &str,
    evidence: Vec<String>,
    next_step: &str,
    score: f64,
) -> ReadinessCheck {
    ReadinessCheck {
        check_id: check_id.to_string(),
        category: category.to_string(),
        label: label.to_string(),
        status: "warn".to_string(),
        score,
        evidence,
        next_step: next_step.to_string(),
    }
}

fn fail(
    check_id: &str,
    category: &str,
    label: &str,
    evidence: Vec<String>,
    next_step: &str,
) -> ReadinessCheck {
    ReadinessCheck {
        check_id: check_id.to_string(),
        category: category.to_string(),
        label: label.to_string(),
        status: "fail".to_string(),
        score: 0.0,
        evidence,
        next_step: next_step.to_string(),
    }
}

#[derive(Debug, Clone)]
struct VerificationSummary {
    total: usize,
    passed: usize,
    failed: usize,
}

fn load_verification_summary(workspace_root: &Path) -> Option<VerificationSummary> {
    let path = workspace_root.join("verification").join("latest.json");
    let value = serde_json::from_slice::<serde_json::Value>(&fs::read(path).ok()?).ok()?;
    let summary = value.get("summary")?;
    Some(VerificationSummary {
        total: summary.get("total")?.as_u64()? as usize,
        passed: summary.get("passed")?.as_u64()? as usize,
        failed: summary.get("failed")?.as_u64()? as usize,
    })
}

fn load_automation(workspace_root: &Path) -> Option<automation::AutomationReport> {
    let path = automation::latest_report_path(workspace_root);
    serde_json::from_slice::<automation::AutomationReport>(&fs::read(path).ok()?).ok()
}

fn commercial_gap_notes(checks: &[ReadinessCheck]) -> Vec<String> {
    let mut notes = Vec::new();
    if checks
        .iter()
        .any(|check| check.check_id == "live-telemetry" && check.status != "pass")
    {
        notes.push(
            "Profesionální nástroje typicky běží nad dlouhodobým live senzorem; tady je potřeba připojený Zeek/Suricata/flow zdroj, ne jen jednorázový replay."
                .to_string(),
        );
    }
    if checks
        .iter()
        .any(|check| check.check_id == "api-hardening" && check.status != "pass")
    {
        notes.push(
            "Produkční UI/API musí být chráněné tokenem a provozované jen v důvěryhodné síti."
                .to_string(),
        );
    }
    if checks
        .iter()
        .any(|check| check.check_id == "vulners-automation" && check.status != "pass")
    {
        notes.push(
            "Vulners klíč je volitelný doplněk; produkční minimum je veřejný stack NVD, CISA KEV, FIRST EPSS, CIRCL a OSV.dev."
                .to_string(),
        );
    }
    if checks
        .iter()
        .any(|check| check.check_id == "verification" && check.status != "pass")
    {
        notes.push(
            "Před předáním ukládej regresní verifikaci scénářů spolu s reportem, jinak nejde zpětně prokázat kvalitu enginu."
                .to_string(),
        );
    }
    if notes.is_empty() {
        notes.push(
            "Aktuální běh má všechny hlavní auditní stopy pro aktivní, pasivní, AI a agentní vrstvu."
                .to_string(),
        );
    }
    notes
}

fn round_ratio(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[allow(dead_code)]
fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn readiness_report_scores_existing_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let report = assess_workspace(&workspace, false).expect("readiness");
        assert!(!report.checks.is_empty());
        assert!(report.score > 0.45);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.check_id == "local-ai")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.check_id == "decision-engine")
        );
    }
}
