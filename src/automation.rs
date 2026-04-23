use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{BakulaError, Result},
    model::{Confidence, MonitoringLane, RunReport},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapability {
    pub capability_id: String,
    pub label: String,
    pub available: bool,
    pub activated: bool,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub role: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBlueprint {
    pub agent_id: String,
    pub role: String,
    pub depends_on: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationSummary {
    pub generated_at: DateTime<Utc>,
    pub cycles_total: usize,
    pub run_ids: Vec<String>,
    pub tooling_coverage_ratio: f64,
    pub service_identity_coverage_ratio: f64,
    pub service_identity_high_confidence_total: usize,
    pub realtime_sources_total: usize,
    pub automation_agents_total: usize,
    pub automation_rounds_total: usize,
    pub forensic_targets_total: usize,
    pub mas_parallelism_ratio: f64,
    pub mas_queue_wait_ms_avg: f64,
    pub mas_agent_sla_ratio: f64,
    pub mas_consensus_score: f64,
    pub mas_consensus_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationReport {
    pub generated_at: DateTime<Utc>,
    pub summary: AutomationSummary,
    pub capabilities: Vec<ToolCapability>,
    pub agents: Vec<AgentSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePhaseStatus {
    pub phase_id: String,
    pub label: String,
    pub status: String,
    pub progress_pct: u8,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAutomationStatus {
    pub state: String,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub workspace_root: String,
    pub current_cycle: usize,
    pub total_cycles: usize,
    pub progress_ratio: f64,
    pub progress_pct: u8,
    pub current_phase: String,
    pub current_phase_label: String,
    pub message: String,
    #[serde(default)]
    pub latest_run_id: Option<String>,
    #[serde(default)]
    pub phases: Vec<RuntimePhaseStatus>,
    #[serde(default)]
    pub agents: Vec<AgentSnapshot>,
    #[serde(default)]
    pub process_running: bool,
}

#[derive(Debug, Clone)]
pub struct AutomationInsights {
    pub capabilities: Vec<ToolCapability>,
    pub agent_lanes: Vec<MonitoringLane>,
    pub tooling_coverage_ratio: f64,
    pub service_identity_coverage_ratio: f64,
    pub service_identity_high_confidence_total: usize,
    pub realtime_sources_total: usize,
    pub automation_agents_total: usize,
    pub automation_rounds_total: usize,
    pub forensic_targets_total: usize,
    pub mas_parallelism_ratio: f64,
    pub mas_queue_wait_ms_avg: f64,
    pub mas_agent_sla_ratio: f64,
    pub mas_consensus_score: f64,
    pub mas_consensus_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSnapshot {
    pub followup_confidence: f64,
    pub forensic_confidence: f64,
    pub correlator_confidence: f64,
    pub weighted_score: f64,
    pub state: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

const RUNTIME_PHASES: [(&str, &str, f64); 8] = [
    ("planning", "Plánování běhu", 0.06),
    ("inventory", "Základní inventář", 0.18),
    ("followup", "Cílené zpřesnění", 0.36),
    ("forensic", "Forenzní ověření", 0.56),
    ("context", "Topologie a kontext", 0.72),
    ("passive", "Toky a pasivní telemetry", 0.82),
    ("correlation", "Korelace a nálezy", 0.92),
    ("finalize", "Finalizace reportu", 1.0),
];

const MAS_AGENT_ROLES: [(&str, &str); 14] = [
    ("agent:planner", "planner"),
    ("agent:inventory", "inventory"),
    ("agent:followup", "followup"),
    ("agent:forensic", "forensic"),
    ("agent:web-pentest", "web-pentest"),
    ("agent:live-observer", "live-observer"),
    ("agent:credential-hunter", "credential-hunter"),
    ("agent:traffic-forensics", "traffic-forensics"),
    ("agent:context-fusion", "context-fusion"),
    ("agent:correlator", "correlator"),
    ("agent:intel", "intel"),
    ("agent:validation", "validation"),
    ("agent:remediation", "remediation"),
    ("agent:reporter", "reporter"),
];

pub fn mas_agent_blueprint() -> Vec<AgentBlueprint> {
    vec![
        agent_blueprint(
            "agent:planner",
            "planner",
            &[],
            "Plánuje pořadí kroků, metriky a provozní limity běhu.",
        ),
        agent_blueprint(
            "agent:inventory",
            "inventory",
            &["planner"],
            "Buduje aktivní inventář hostů a služeb.",
        ),
        agent_blueprint(
            "agent:followup",
            "followup",
            &["inventory"],
            "Spouští cílené follow-up skeny pro zpřesnění identit služeb.",
        ),
        agent_blueprint(
            "agent:forensic",
            "forensic",
            &["followup"],
            "Provádí forenzní drill-down nad prioritními cíli.",
        ),
        agent_blueprint(
            "agent:web-pentest",
            "web-pentest",
            &["forensic"],
            "Ověřuje HTTP cíle bezpečnými nedestruktivními šablonami.",
        ),
        agent_blueprint(
            "agent:live-observer",
            "live-observer",
            &["planner"],
            "Normalizuje pasivní telemetry a provozní události.",
        ),
        agent_blueprint(
            "agent:credential-hunter",
            "credential-hunter",
            &["live-observer"],
            "Hledá důkazy nešifrovaného přihlášení bez čtení hesel.",
        ),
        agent_blueprint(
            "agent:traffic-forensics",
            "traffic-forensics",
            &["live-observer"],
            "Skládá časový kontext podezřelých toků, timeoutů a objemů.",
        ),
        agent_blueprint(
            "agent:context-fusion",
            "context-fusion",
            &["inventory"],
            "Skládá topologii a autorizovaný kontext z controller zdrojů.",
        ),
        agent_blueprint(
            "agent:correlator",
            "correlator",
            &[
                "forensic",
                "web-pentest",
                "live-observer",
                "credential-hunter",
                "traffic-forensics",
                "context-fusion",
            ],
            "Koreluje nálezy, události a změny mezi běhy.",
        ),
        agent_blueprint(
            "agent:intel",
            "intel",
            &["correlator"],
            "Obohacuje výsledky o externí CVE/intel feedy.",
        ),
        agent_blueprint(
            "agent:validation",
            "validation",
            &["intel", "correlator"],
            "Validuje CVE, web checks, pasivní důkazy a hypotézy před doporučením.",
        ),
        agent_blueprint(
            "agent:remediation",
            "remediation",
            &["validation"],
            "Překládá ověřené důkazy do bezpečných kroků nápravy.",
        ),
        agent_blueprint(
            "agent:reporter",
            "reporter",
            &["validation", "remediation"],
            "Finalizuje auditovatelný report a artefakty běhu.",
        ),
    ]
}

pub fn derive_insights(report: &RunReport) -> AutomationInsights {
    let open_services = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| service.port_state == "open")
        .collect::<Vec<_>>();
    let strong_identity_total = open_services
        .iter()
        .filter(|service| has_strong_identity(service))
        .count();
    let service_identity_coverage_ratio = if open_services.is_empty() {
        1.0
    } else {
        round_ratio(strong_identity_total as f64 / open_services.len() as f64)
    };

    let suspicious_targets = report
        .findings
        .iter()
        .filter_map(|finding| {
            if matches!(
                finding.finding_type.as_str(),
                "identification_gap"
                    | "management_surface_exposure"
                    | "high_risk_cve_exposure"
                    | "known_exploited_vulnerability"
                    | "probable_exploitation_interest"
            ) {
                finding.service_key.clone()
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    let sources = &report.run.sources;
    let controller_sources_available = [
        sources.snmp_snapshot.as_ref(),
        sources.librenms_snapshot.as_ref(),
        sources.librenms_base_url.as_ref(),
        sources.meraki_snapshot.as_ref(),
        sources.meraki_network_id.as_ref(),
        sources.unifi_snapshot.as_ref(),
        sources.aruba_snapshot.as_ref(),
        sources.omada_snapshot.as_ref(),
    ]
    .iter()
    .any(|item| item.is_some());

    let audit_sources_available = [
        sources.greenbone_report.as_ref(),
        sources.wazuh_report.as_ref(),
        sources.napalm_snapshot.as_ref(),
        sources.netmiko_snapshot.as_ref(),
        sources.scrapli_snapshot.as_ref(),
    ]
    .iter()
    .any(|item| item.is_some());

    let passive_sources_available = sources.suricata_eve.is_some()
        || sources.zeek_dir.is_some()
        || report.summary.events_total > 0;
    let live_sources_available = sources.ntopng_snapshot.is_some()
        || sources.flow_snapshot.is_some()
        || report.summary.live_lanes_total > 0;
    let realtime_sources_total = usize::from(passive_sources_available)
        + usize::from(live_sources_available)
        + usize::from(report.summary.events_total > 0);

    let any_http = open_services.iter().any(|service| {
        matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880 | 6789)
            || service.inventory.service_name.contains("http")
    });
    let context_activated = report.monitoring_lanes.iter().any(|lane| {
        matches!(
            lane.source.as_str(),
            "snmp" | "librenms" | "meraki" | "unifi" | "aruba" | "omada"
        )
    }) || report.network_assets.len() > report.hosts.len();
    let config_audit_activated = report.monitoring_lanes.iter().any(|lane| {
        matches!(
            lane.source.as_str(),
            "greenbone" | "wazuh" | "napalm" | "netmiko" | "scrapli"
        )
    });
    let passive_lane_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| matches!(lane.source.as_str(), "suricata" | "zeek"));
    let web_fingerprint_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "httpx");
    let active_web_checks_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "nuclei");
    let validation_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "validation-matrix");
    let safe_pentest_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "safe-pentest-validator" || lane.source == "internal-pentest");
    let aggressive_pentest_activated = report.monitoring_lanes.iter().any(|lane| {
        lane.source == "internal-pentest"
            && lane.evidence.iter().any(|item| item == "mode=aggressive")
    });
    let ai_context_bridge_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "ai-context-bridge");
    let credential_validation_activated = report
        .triage_actions
        .iter()
        .any(|action| action.action_type == "spawn-agent:credential-exposure-validator");
    let traffic_forensics_activated = report
        .triage_actions
        .iter()
        .any(|action| action.action_type == "spawn-agent:traffic-pcap-analyst");
    let followup_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "nmap-followup");
    let forensic_activated = report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "nmap-forensic");
    let external_intel_activated = report.summary.intel_matches_total > 0;
    let external_intel_sources = report
        .intel_matches
        .iter()
        .map(|item| item.source.clone())
        .collect::<BTreeSet<_>>();
    let live_nmap_mode = report.run.sources.nmap_mode.as_deref() == Some("live");

    let capabilities = vec![
        capability(
            "active_inventory",
            "Aktivní inventář služeb",
            true,
            true,
            vec![format!("hosts={}", report.summary.hosts_total)],
        ),
        capability(
            "targeted_followup",
            "Cílený druhý průchod Nmap",
            live_nmap_mode && !open_services.is_empty(),
            followup_activated,
            collect_lane_evidence(report, "nmap-followup"),
        ),
        capability(
            "forensic_refinement",
            "Forenzní zpřesnění prioritních cílů",
            live_nmap_mode && !suspicious_targets.is_empty(),
            forensic_activated,
            collect_lane_evidence(report, "nmap-forensic"),
        ),
        capability(
            "web_fingerprint",
            "Web fingerprinting",
            any_http,
            web_fingerprint_activated,
            vec![format!("web_probes={}", report.summary.web_probes_total)],
        ),
        capability(
            "active_web_checks",
            "Řízené web checks",
            any_http,
            active_web_checks_activated,
            vec![format!(
                "active_checks={}",
                report.summary.active_checks_total
            )],
        ),
        capability(
            "safe_pentest_validation",
            "Bezpečné ověření nálezů",
            any_http || report.summary.cves_total > 0 || report.summary.events_total > 0,
            safe_pentest_activated || report.summary.active_checks_total > 0,
            vec![
                format!("safe_pentest_lane={safe_pentest_activated}"),
                format!("aggressive_pentest={aggressive_pentest_activated}"),
                format!("active_checks={}", report.summary.active_checks_total),
                format!("cves={}", report.summary.cves_total),
            ],
        ),
        capability(
            "passive_telemetry",
            "Pasivní korelace provozu",
            passive_sources_available,
            passive_lane_activated || report.summary.events_total > 0,
            vec![format!("events={}", report.summary.events_total)],
        ),
        capability(
            "live_flows",
            "Live flow telemetry",
            live_sources_available,
            report.summary.live_lanes_total > 0,
            vec![format!("live_lanes={}", report.summary.live_lanes_total)],
        ),
        capability(
            "authorized_context",
            "Autorizovaný kontext topologie",
            controller_sources_available,
            context_activated,
            vec![
                format!("network_assets={}", report.summary.network_assets_total),
                format!("topology_edges={}", report.summary.topology_edges_total),
            ],
        ),
        capability(
            "audit_lane",
            "Auditní lane a konfigurace",
            audit_sources_available,
            config_audit_activated,
            vec![format!("audit_lanes={}", report.summary.audit_lanes_total)],
        ),
        capability(
            "vulnerability_enrichment",
            "Mapování CPE a zranitelností",
            !open_services.is_empty(),
            !report.run.provider.trim().is_empty(),
            vec![
                format!("provider={}", report.run.provider),
                format!("cves={}", report.summary.cves_total),
            ],
        ),
        capability(
            "external_intel",
            "Externí intel feedy",
            report.summary.cves_total > 0
                || report.summary.web_probes_total > 0
                || report.summary.events_total > 0,
            external_intel_activated,
            vec![
                format!("intel_matches={}", report.summary.intel_matches_total),
                format!(
                    "sources={}",
                    if external_intel_sources.is_empty() {
                        "-".to_string()
                    } else {
                        external_intel_sources
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("|")
                    }
                ),
            ],
        ),
    ];

    let available = capabilities.iter().filter(|item| item.available).count();
    let activated = capabilities
        .iter()
        .filter(|item| item.available && item.activated)
        .count();
    let tooling_coverage_ratio = if available == 0 {
        1.0
    } else {
        round_ratio(activated as f64 / available as f64)
    };
    let mas_parallelism_ratio = round_ratio(report.summary.mas_parallelism_ratio);
    let mas_queue_wait_ms_avg = round_ratio(report.summary.mas_queue_wait_ms_avg);
    let mas_agent_sla_ratio = round_ratio(report.summary.mas_agent_sla_ratio);
    let mas_consensus_score = round_ratio(report.summary.mas_consensus_score);
    let mas_consensus_state = if report.summary.mas_consensus_state.trim().is_empty() {
        "pending".to_string()
    } else {
        report.summary.mas_consensus_state.clone()
    };

    let mut agents = vec![
        agent_lane(
            "agent:planner",
            "planner",
            "ok",
            format!(
                "Plánovač seřadil {} prioritních cílů a rozdělil běh do kroků inventář -> zpřesnění -> korelace -> intel.",
                suspicious_targets.len()
            ),
            vec![
                format!("tooling_coverage_ratio={tooling_coverage_ratio:.2}"),
                format!("service_identity_ratio={service_identity_coverage_ratio:.2}"),
            ],
        ),
        agent_lane(
            "agent:inventory",
            "inventory",
            "ok",
            format!(
                "Inventarizační agent zpracoval {} hostů a {} služeb.",
                report.summary.hosts_total, report.summary.services_total
            ),
            vec![
                format!("followup={followup_activated}"),
                format!("forensic={forensic_activated}"),
            ],
        ),
        agent_lane(
            "agent:followup",
            "followup",
            if followup_activated { "ok" } else { "limited" },
            if followup_activated {
                "Follow-up agent spustil cílené zpřesnění služeb po prvním inventáři.".to_string()
            } else {
                "Follow-up agent ponechal běh bez druhého průchodu (není potřeba nebo není live režim).".to_string()
            },
            vec![
                format!("followup={followup_activated}"),
                format!("live_nmap_mode={live_nmap_mode}"),
            ],
        ),
        agent_lane(
            "agent:live-observer",
            "live-observer",
            if report.summary.live_lanes_total > 0 || report.summary.events_total > 0 {
                "ok"
            } else {
                "limited"
            },
            format!(
                "Live/pasivní vrstva vidí {} lane a {} korelovaných událostí.",
                report.summary.live_lanes_total, report.summary.events_total
            ),
            vec![
                format!("passive_sources={passive_sources_available}"),
                format!("live_sources={live_sources_available}"),
            ],
        ),
        agent_lane(
            "agent:credential-hunter",
            "credential-hunter",
            if credential_validation_activated {
                "ok"
            } else if passive_sources_available {
                "limited"
            } else {
                "idle"
            },
            if credential_validation_activated {
                "Credential hunter vytvořil ověřovací úkol pro nešifrované přihlášení bez práce s obsahem hesel."
                    .to_string()
            } else if passive_sources_available {
                "Credential hunter sleduje pasivní zdroje, ale tento běh nemá potvrzený plaintext signál."
                    .to_string()
            } else {
                "Credential hunter čeká na Zeek nebo Suricata vstup.".to_string()
            },
            vec![
                format!("credential_validation={credential_validation_activated}"),
                format!("passive_sources={passive_sources_available}"),
            ],
        ),
        agent_lane(
            "agent:traffic-forensics",
            "traffic-forensics",
            if traffic_forensics_activated {
                "ok"
            } else if report.summary.events_total > 0 || report.summary.live_lanes_total > 0 {
                "limited"
            } else {
                "idle"
            },
            if traffic_forensics_activated {
                "Traffic forensics agent má ověřovací úkol pro provozní anomálii a skládá flow/Zeek/Suricata důkazy."
                    .to_string()
            } else if report.summary.events_total > 0 || report.summary.live_lanes_total > 0 {
                "Traffic forensics agent má provozní data, ale zatím bez silné anomálie pro samostatné ověření."
                    .to_string()
            } else {
                "Traffic forensics agent čeká na živé flow nebo pasivní telemetry.".to_string()
            },
            vec![
                format!("traffic_forensics={traffic_forensics_activated}"),
                format!("events={}", report.summary.events_total),
                format!("live_lanes={}", report.summary.live_lanes_total),
            ],
        ),
        agent_lane(
            "agent:context-fusion",
            "context-fusion",
            if context_activated || config_audit_activated {
                "ok"
            } else {
                "limited"
            },
            format!(
                "Context agent sjednotil {} aktiv a {} vazeb z autorizovaných zdrojů.",
                report.summary.network_assets_total, report.summary.topology_edges_total
            ),
            vec![
                format!("context_activated={context_activated}"),
                format!("audit_sources={audit_sources_available}"),
            ],
        ),
        agent_lane(
            "agent:forensic",
            "forensic",
            if forensic_activated { "ok" } else { "pending" },
            if forensic_activated {
                "Forenzní agent provedl další cílené ověření nad prioritními nebo nejasnými službami."
                    .to_string()
            } else if suspicious_targets.is_empty() {
                "Forenzní agent nenašel další cíle, které by vyžadovaly hlubší průchod.".to_string()
            } else {
                "Forenzní agent označil další kandidáty, ale hlubší průchod v tomto běhu neproběhl."
                    .to_string()
            },
            vec![format!("suspicious_targets={}", suspicious_targets.len())],
        ),
        agent_lane(
            "agent:web-pentest",
            "web-pentest",
            if safe_pentest_activated || active_web_checks_activated {
                "ok"
            } else if any_http {
                "limited"
            } else {
                "idle"
            },
            if safe_pentest_activated || active_web_checks_activated {
                "Web pentest agent má bezpečnou validační lane nebo aktivní kontrolované checks."
                    .to_string()
            } else if any_http {
                "Web pentest agent vidí HTTP cíle a čeká na povolené kontrolované ověření."
                    .to_string()
            } else {
                "Web pentest agent nenašel HTTP službu, kterou by měl ověřovat.".to_string()
            },
            vec![
                format!("http_targets={any_http}"),
                format!("safe_pentest={safe_pentest_activated}"),
                format!("aggressive_pentest={aggressive_pentest_activated}"),
                format!("active_web_checks={active_web_checks_activated}"),
            ],
        ),
        agent_lane(
            "agent:correlator",
            "correlator",
            "ok",
            format!(
                "Korelační agent navázal {} nálezů a {} doporučených kroků.",
                report.summary.findings_total, report.summary.triage_actions_total
            ),
            vec![format!(
                "audit_findings={}",
                report.summary.audit_findings_total
            )],
        ),
        agent_lane(
            "agent:intel",
            "intel",
            if external_intel_activated {
                "ok"
            } else {
                "limited"
            },
            format!(
                "Intel agent zpracoval {} externích matchů, provider {} a veřejný stack používá Vulners jen jako volitelný doplněk.",
                report.summary.intel_matches_total, report.run.provider
            ),
            vec![
                format!("cves={}", report.summary.cves_total),
                format!(
                    "sources={}",
                    if external_intel_sources.is_empty() {
                        "-".to_string()
                    } else {
                        external_intel_sources
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("|")
                    }
                ),
            ],
        ),
        agent_lane(
            "agent:validation",
            "validation",
            if validation_activated {
                "ok"
            } else {
                "limited"
            },
            if validation_activated {
                "Validační agent rozpadl nálezy na důkazní matice a bezpečné ověřovací úkoly."
                    .to_string()
            } else {
                "Validační agent čeká na report z aktuální pipeline.".to_string()
            },
            vec![
                format!("validation_matrix={validation_activated}"),
                format!("ai_context_bridge={ai_context_bridge_activated}"),
            ],
        ),
        agent_lane(
            "agent:remediation",
            "remediation",
            if validation_activated && report.summary.triage_actions_total > 0 {
                "ok"
            } else {
                "limited"
            },
            format!(
                "Remediation agent převádí ověřené nálezy na {} doporučených kroků s důkazy.",
                report.summary.triage_actions_total
            ),
            vec![
                format!("triage_actions={}", report.summary.triage_actions_total),
                format!("validation_ready={validation_activated}"),
            ],
        ),
        agent_lane(
            "agent:reporter",
            "reporter",
            "ok",
            format!(
                "Report agent sjednotil {} lane, {} nálezů a {} doporučených kroků.",
                report.summary.monitoring_lanes_total,
                report.summary.findings_total,
                report.summary.triage_actions_total
            ),
            vec![
                format!("run_id={}", report.run.run_id),
                format!("tooling_coverage={tooling_coverage_ratio:.2}"),
            ],
        ),
    ];
    agents.extend(dynamic_agent_lanes(report));

    let dynamic_agent_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| {
            lane.lane_type == "automation"
                && matches!(
                    lane.source.as_str(),
                    "decision-hypotheses"
                        | "decision-risk-ranking"
                        | "decision-inference-graph"
                        | "agent-spawner"
                        | "agent-governor"
                        | "agent-lifecycle"
                        | "case-memory"
                        | "public-intel-gap"
                        | "validation-matrix"
                        | "safe-pentest-validator"
                        | "internal-pentest"
                        | "ai-context-bridge"
                )
        })
        .count();
    let automation_rounds_total = 1
        + usize::from(followup_activated)
        + usize::from(forensic_activated)
        + usize::from(safe_pentest_activated || active_web_checks_activated)
        + usize::from(validation_activated);
    let forensic_targets_total = report
        .monitoring_lanes
        .iter()
        .find(|lane| lane.source == "nmap-forensic")
        .and_then(|lane| {
            lane.evidence.iter().find_map(|item| {
                item.strip_prefix("ports=")
                    .and_then(|value| value.parse::<usize>().ok())
            })
        })
        .unwrap_or(suspicious_targets.len());
    let automation_agents_total = agents
        .len()
        .max(MAS_AGENT_ROLES.len() + dynamic_agent_total);

    AutomationInsights {
        capabilities,
        agent_lanes: agents,
        tooling_coverage_ratio,
        service_identity_coverage_ratio,
        service_identity_high_confidence_total: strong_identity_total,
        realtime_sources_total,
        automation_agents_total,
        automation_rounds_total,
        forensic_targets_total,
        mas_parallelism_ratio,
        mas_queue_wait_ms_avg,
        mas_agent_sla_ratio,
        mas_consensus_score,
        mas_consensus_state,
    }
}

pub fn build_consensus_snapshot(report: &RunReport) -> ConsensusSnapshot {
    let open_services = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| service.port_state == "open")
        .collect::<Vec<_>>();
    let strong_identity_total = open_services
        .iter()
        .filter(|service| has_strong_identity(service))
        .count();
    let identity_ratio = if open_services.is_empty() {
        1.0
    } else {
        strong_identity_total as f64 / open_services.len() as f64
    };

    let followup_lane = report
        .monitoring_lanes
        .iter()
        .find(|lane| lane.source == "nmap-followup");
    let forensic_lane = report
        .monitoring_lanes
        .iter()
        .find(|lane| lane.source == "nmap-forensic");
    let correlated_density = if report.summary.hosts_total == 0 {
        0.0
    } else {
        (report.summary.findings_total as f64 / report.summary.hosts_total as f64).min(1.0)
    };

    let followup_confidence = round_ratio(neural_score(
        &[
            f64::from(followup_lane.is_some()),
            identity_ratio,
            (report.summary.service_identity_high_confidence_total as f64 / 12.0).clamp(0.0, 1.0),
        ],
        &[0.95, 1.25, 0.45],
        -0.35,
    ));

    let forensic_ports = forensic_lane
        .and_then(|lane| parse_lane_metric(lane, "ports"))
        .unwrap_or(0) as f64;
    let forensic_signal = (forensic_ports / 12.0).clamp(0.0, 1.0);
    let high_findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= crate::model::Severity::Medium)
        .count() as f64;
    let forensic_findings_signal = (high_findings / 8.0).clamp(0.0, 1.0);
    let forensic_confidence = round_ratio(neural_score(
        &[
            f64::from(forensic_lane.is_some()),
            forensic_signal,
            forensic_findings_signal,
        ],
        &[0.9, 0.85, 0.8],
        -0.4,
    ));

    let correlator_confidence = round_ratio(neural_score(
        &[
            correlated_density,
            (report.summary.events_total as f64 / 24.0).clamp(0.0, 1.0),
            (report.summary.findings_total as f64 / 20.0).clamp(0.0, 1.0),
        ],
        &[0.85, 0.6, 0.7],
        -0.38,
    ));

    let followup_weight = 0.30 * followup_confidence.max(0.2);
    let forensic_weight = 0.34 * forensic_confidence.max(0.2);
    let correlator_weight = 0.36 * correlator_confidence.max(0.2);
    let total_weight = followup_weight + forensic_weight + correlator_weight;
    let weighted_score = if total_weight <= f64::EPSILON {
        0.0
    } else {
        round_ratio(neural_score(
            &[
                followup_confidence,
                forensic_confidence,
                correlator_confidence,
            ],
            &[
                followup_weight / total_weight,
                forensic_weight / total_weight,
                correlator_weight / total_weight,
            ],
            -0.08,
        ))
    };
    let state = consensus_state_for_score(weighted_score).to_string();

    ConsensusSnapshot {
        followup_confidence,
        forensic_confidence,
        correlator_confidence,
        weighted_score,
        state: state.clone(),
        evidence: vec![
            format!("identity_ratio={identity_ratio:.2}"),
            format!("forensic_ports={forensic_ports:.0}"),
            format!("findings_per_host={correlated_density:.2}"),
            format!("weights={followup_weight:.2}/{forensic_weight:.2}/{correlator_weight:.2}"),
            "consensus_head=sigmoid(weighted)".to_string(),
            format!("state={state}"),
        ],
    }
}

pub fn build_automation_report(cycle_reports: &[RunReport]) -> AutomationReport {
    let latest = cycle_reports
        .last()
        .expect("automation report vyzaduje alespon jeden run");
    let insights = derive_insights(latest);
    AutomationReport {
        generated_at: Utc::now(),
        summary: AutomationSummary {
            generated_at: Utc::now(),
            cycles_total: cycle_reports.len(),
            run_ids: cycle_reports
                .iter()
                .map(|report| report.run.run_id.clone())
                .collect(),
            tooling_coverage_ratio: insights.tooling_coverage_ratio,
            service_identity_coverage_ratio: insights.service_identity_coverage_ratio,
            service_identity_high_confidence_total: insights.service_identity_high_confidence_total,
            realtime_sources_total: insights.realtime_sources_total,
            automation_agents_total: insights.automation_agents_total,
            automation_rounds_total: insights.automation_rounds_total,
            forensic_targets_total: insights.forensic_targets_total,
            mas_parallelism_ratio: insights.mas_parallelism_ratio,
            mas_queue_wait_ms_avg: insights.mas_queue_wait_ms_avg,
            mas_agent_sla_ratio: insights.mas_agent_sla_ratio,
            mas_consensus_score: insights.mas_consensus_score,
            mas_consensus_state: insights.mas_consensus_state,
        },
        capabilities: insights.capabilities,
        agents: insights
            .agent_lanes
            .into_iter()
            .map(|lane| AgentSnapshot {
                agent_id: lane.lane_id,
                role: lane.source,
                status: lane.status,
                summary: lane.summary,
                evidence: lane.evidence,
            })
            .collect(),
    }
}

pub fn runtime_status_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("automation").join("status.json")
}

pub fn latest_report_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("automation").join("latest.json")
}

pub fn runtime_agent_templates() -> Vec<AgentSnapshot> {
    MAS_AGENT_ROLES
        .iter()
        .map(|(agent_id, role)| runtime_agent(agent_id, role))
        .collect()
}

pub fn idle_runtime_status(workspace_root: &Path) -> RuntimeAutomationStatus {
    let now = Utc::now();
    RuntimeAutomationStatus {
        state: "idle".to_string(),
        started_at: now,
        updated_at: now,
        workspace_root: workspace_root.display().to_string(),
        current_cycle: 0,
        total_cycles: 0,
        progress_ratio: 0.0,
        progress_pct: 0,
        current_phase: "idle".to_string(),
        current_phase_label: "Neaktivní".to_string(),
        message: "Autopilot neběží.".to_string(),
        latest_run_id: None,
        phases: runtime_phase_templates("pending"),
        agents: runtime_agent_templates(),
        process_running: false,
    }
}

pub fn load_runtime_status(workspace_root: &Path) -> Result<RuntimeAutomationStatus> {
    let path = runtime_status_path(workspace_root);
    if !path.exists() {
        return Ok(idle_runtime_status(workspace_root));
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(BakulaError::Json)
}

pub fn save_runtime_status(
    workspace_root: &Path,
    status: &RuntimeAutomationStatus,
) -> Result<PathBuf> {
    let path = runtime_status_path(workspace_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(status).map_err(BakulaError::Json)?,
    )?;
    Ok(path)
}

pub fn clear_runtime_status(workspace_root: &Path) -> Result<PathBuf> {
    let status = idle_runtime_status(workspace_root);
    save_runtime_status(workspace_root, &status)
}

pub fn begin_runtime(
    workspace_root: &Path,
    total_cycles: usize,
    run_label: &str,
) -> Result<RuntimeAutomationStatus> {
    let mut status = idle_runtime_status(workspace_root);
    status.state = "running".to_string();
    status.total_cycles = total_cycles.max(1);
    status.current_cycle = 1;
    status.current_phase = "planning".to_string();
    status.current_phase_label = "Plánování běhu".to_string();
    status.message = format!("Autopilot startuje: {run_label}");
    status.progress_ratio = 0.0;
    status.progress_pct = 0;
    status.phases = runtime_phase_templates("pending");
    status.agents = runtime_agent_templates();
    status.agents.iter_mut().for_each(|agent| {
        agent.status = "pending".to_string();
        agent.summary = "Čeká na přidělení kroku.".to_string();
        agent.evidence.clear();
    });
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn begin_cycle(
    workspace_root: &Path,
    cycle: usize,
    total_cycles: usize,
    run_label: &str,
) -> Result<RuntimeAutomationStatus> {
    let mut status = load_runtime_status(workspace_root)?;
    status.state = "running".to_string();
    status.current_cycle = cycle.max(1);
    status.total_cycles = total_cycles.max(1);
    status.current_phase = "planning".to_string();
    status.current_phase_label = "Plánování běhu".to_string();
    status.message = format!(
        "Cyklus {} z {}: {run_label}",
        status.current_cycle, status.total_cycles
    );
    status.progress_ratio = cycle_base_ratio(status.current_cycle, status.total_cycles, 0.0);
    status.progress_pct = ratio_to_pct(status.progress_ratio);
    status.phases = runtime_phase_templates("pending");
    status.agents = runtime_agent_templates();
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn update_runtime_phase(
    workspace_root: &Path,
    phase_id: &str,
    message: &str,
) -> Result<RuntimeAutomationStatus> {
    let mut status = load_runtime_status(workspace_root)?;
    let Some((_, label, phase_ratio)) = RUNTIME_PHASES.iter().find(|item| item.0 == phase_id)
    else {
        return Ok(status);
    };
    status.state = "running".to_string();
    status.updated_at = Utc::now();
    status.current_phase = phase_id.to_string();
    status.current_phase_label = (*label).to_string();
    status.message = message.to_string();
    status.progress_ratio = cycle_base_ratio(
        status.current_cycle.max(1),
        status.total_cycles.max(1),
        *phase_ratio,
    );
    status.progress_pct = ratio_to_pct(status.progress_ratio);
    status.phases.iter_mut().for_each(|phase| {
        phase.status = if phase.phase_id == phase_id {
            "running".to_string()
        } else if phase_progress_ratio(&phase.phase_id) < *phase_ratio {
            "done".to_string()
        } else {
            "pending".to_string()
        };
        phase.progress_pct = if phase.phase_id == phase_id {
            ratio_to_pct(*phase_ratio)
        } else if phase_progress_ratio(&phase.phase_id) < *phase_ratio {
            100
        } else {
            0
        };
        phase.summary = runtime_phase_summary(&phase.phase_id, &phase.status);
    });
    update_runtime_agents(&mut status.agents, phase_id);
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn finish_cycle(workspace_root: &Path, run_id: &str) -> Result<RuntimeAutomationStatus> {
    let mut status = load_runtime_status(workspace_root)?;
    status.updated_at = Utc::now();
    status.latest_run_id = Some(run_id.to_string());
    status.current_phase = "finalize".to_string();
    status.current_phase_label = "Finalizace reportu".to_string();
    status.message = format!(
        "Cyklus {} dokončen, report {} uložen.",
        status.current_cycle, run_id
    );
    status.progress_ratio =
        cycle_base_ratio(status.current_cycle.max(1), status.total_cycles.max(1), 1.0);
    status.progress_pct = ratio_to_pct(status.progress_ratio);
    status.phases.iter_mut().for_each(|phase| {
        phase.status = "done".to_string();
        phase.progress_pct = 100;
        phase.summary = runtime_phase_summary(&phase.phase_id, &phase.status);
    });
    update_runtime_agents(&mut status.agents, "complete");
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn complete_runtime(
    workspace_root: &Path,
    automation_report: &AutomationReport,
) -> Result<RuntimeAutomationStatus> {
    let mut status = load_runtime_status(workspace_root)?;
    status.updated_at = Utc::now();
    status.state = "completed".to_string();
    status.current_cycle = status.total_cycles.max(status.current_cycle);
    status.progress_ratio = 1.0;
    status.progress_pct = 100;
    status.current_phase = "complete".to_string();
    status.current_phase_label = "Hotovo".to_string();
    status.message = format!(
        "Autopilot dokončen: {} cyklů, coverage {:.0} %.",
        automation_report.summary.cycles_total,
        automation_report.summary.tooling_coverage_ratio * 100.0
    );
    status.latest_run_id = automation_report.summary.run_ids.last().cloned();
    status.phases.iter_mut().for_each(|phase| {
        phase.status = "done".to_string();
        phase.progress_pct = 100;
        phase.summary = runtime_phase_summary(&phase.phase_id, &phase.status);
    });
    status.agents = automation_report.agents.clone();
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn fail_runtime(workspace_root: &Path, message: &str) -> Result<RuntimeAutomationStatus> {
    let mut status = load_runtime_status(workspace_root)?;
    status.updated_at = Utc::now();
    status.state = "failed".to_string();
    status.message = message.to_string();
    save_runtime_status(workspace_root, &status)?;
    Ok(status)
}

pub fn save_automation_report(workspace_root: &Path, report: &AutomationReport) -> Result<PathBuf> {
    let directory = workspace_root.join("automation");
    fs::create_dir_all(&directory)?;
    let latest = directory.join("latest.json");
    fs::write(
        &latest,
        serde_json::to_vec_pretty(report).map_err(BakulaError::Json)?,
    )?;
    Ok(latest)
}

fn capability(
    capability_id: &str,
    label: &str,
    available: bool,
    activated: bool,
    evidence: Vec<String>,
) -> ToolCapability {
    ToolCapability {
        capability_id: capability_id.to_string(),
        label: label.to_string(),
        available,
        activated,
        evidence,
    }
}

fn agent_blueprint(
    agent_id: &str,
    role: &str,
    depends_on: &[&str],
    description: &str,
) -> AgentBlueprint {
    AgentBlueprint {
        agent_id: agent_id.to_string(),
        role: role.to_string(),
        depends_on: depends_on
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        description: description.to_string(),
    }
}

fn agent_lane(
    lane_id: &str,
    source: &str,
    status: &str,
    summary: String,
    evidence: Vec<String>,
) -> MonitoringLane {
    MonitoringLane {
        lane_id: lane_id.to_string(),
        lane_type: "automation".to_string(),
        source: source.to_string(),
        title: format!("Agent {source}"),
        status: status.to_string(),
        summary,
        evidence,
        recommended_tools: Vec::new(),
    }
}

fn dynamic_agent_lanes(report: &RunReport) -> Vec<MonitoringLane> {
    let mut seen = BTreeSet::new();
    let mut lanes = Vec::new();
    for action in &report.triage_actions {
        if let Some(role) = action.action_type.strip_prefix("spawn-agent:") {
            let lane_id = format!("agent:dynamic:{role}");
            if !seen.insert(lane_id.clone()) {
                continue;
            }
            let mut evidence = action.evidence.iter().take(6).cloned().collect::<Vec<_>>();
            evidence.push(format!("source_action={}", action.action_id));
            lanes.push(agent_lane(
                &lane_id,
                &format!("agent:{role}"),
                "spawned",
                format!(
                    "Dynamický agent {role} vznikl z rozhodovací vrstvy, protože běh má konkrétní důkaz a ověřovací úkol."
                ),
                evidence,
            ));
        }
        if let Some(role) = action.action_type.strip_prefix("kill-agent:") {
            let lane_id = format!("agent:retired:{role}");
            if !seen.insert(lane_id.clone()) {
                continue;
            }
            lanes.push(agent_lane(
                &lane_id,
                &format!("agent-retired:{role}"),
                "retired",
                format!(
                    "Agent {role} je pro tento běh vypnutý, protože governor nenašel dost silný signál pro jeho spuštění."
                ),
                action.evidence.iter().take(6).cloned().collect(),
            ));
        }
    }
    for lane in &report.monitoring_lanes {
        for item in &lane.evidence {
            if let Some(role) = item
                .strip_prefix("kill=")
                .and_then(|value| value.split_whitespace().next())
            {
                let lane_id = format!("agent:retired:{role}");
                if seen.insert(lane_id.clone()) {
                    lanes.push(agent_lane(
                        &lane_id,
                        &format!("agent-retired:{role}"),
                        "retired",
                        format!(
                            "Agent {role} je kandidát na vypnutí podle evidence governor lane."
                        ),
                        vec![item.clone(), format!("source_lane={}", lane.source)],
                    ));
                }
            }
        }
    }
    lanes.sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    lanes
}

fn collect_lane_evidence(report: &RunReport, source: &str) -> Vec<String> {
    report
        .monitoring_lanes
        .iter()
        .find(|lane| lane.source == source)
        .map(|lane| lane.evidence.clone())
        .unwrap_or_default()
}

fn parse_lane_metric(lane: &MonitoringLane, key: &str) -> Option<usize> {
    let prefix = format!("{key}=");
    lane.evidence.iter().find_map(|item| {
        item.strip_prefix(&prefix)
            .and_then(|value| value.parse::<usize>().ok())
    })
}

fn neural_score(features: &[f64], weights: &[f64], bias: f64) -> f64 {
    let linear = features
        .iter()
        .zip(weights.iter())
        .fold(bias, |acc, (feature, weight)| acc + feature * weight);
    1.0 / (1.0 + (-linear).exp())
}

fn round_ratio(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn consensus_state_for_score(score: f64) -> &'static str {
    if score >= 0.75 {
        "strong"
    } else if score >= 0.55 {
        "review"
    } else {
        "weak"
    }
}

fn has_strong_identity(service: &crate::model::ServiceReport) -> bool {
    matches!(
        service.inventory.confidence,
        Confidence::High | Confidence::Medium
    ) || (!service.cpe.is_empty())
        || (service.inventory.product.is_some() && service.inventory.version.is_some())
}

fn runtime_phase_templates(initial_status: &str) -> Vec<RuntimePhaseStatus> {
    RUNTIME_PHASES
        .iter()
        .map(|(phase_id, label, _)| RuntimePhaseStatus {
            phase_id: (*phase_id).to_string(),
            label: (*label).to_string(),
            status: initial_status.to_string(),
            progress_pct: 0,
            summary: runtime_phase_summary(phase_id, initial_status),
        })
        .collect()
}

fn runtime_phase_summary(phase_id: &str, status: &str) -> String {
    let phase_label = RUNTIME_PHASES
        .iter()
        .find(|item| item.0 == phase_id)
        .map(|item| item.1)
        .unwrap_or("Fáze");
    match status {
        "done" => format!("{phase_label} je dokončená."),
        "running" => format!("{phase_label} právě běží."),
        "failed" => format!("{phase_label} selhala."),
        _ => format!("{phase_label} čeká na spuštění."),
    }
}

fn runtime_agent(agent_id: &str, role: &str) -> AgentSnapshot {
    AgentSnapshot {
        agent_id: agent_id.to_string(),
        role: role.to_string(),
        status: "pending".to_string(),
        summary: "Čeká na přidělení kroku.".to_string(),
        evidence: Vec::new(),
    }
}

fn phase_progress_ratio(phase_id: &str) -> f64 {
    RUNTIME_PHASES
        .iter()
        .find(|item| item.0 == phase_id)
        .map(|item| item.2)
        .unwrap_or(0.0)
}

fn cycle_base_ratio(current_cycle: usize, total_cycles: usize, phase_ratio: f64) -> f64 {
    let total = total_cycles.max(1) as f64;
    let completed_cycles = current_cycle.saturating_sub(1) as f64;
    ((completed_cycles + phase_ratio.clamp(0.0, 1.0)) / total).clamp(0.0, 1.0)
}

fn ratio_to_pct(ratio: f64) -> u8 {
    (ratio.clamp(0.0, 1.0) * 100.0).round() as u8
}

fn update_runtime_agents(agents: &mut [AgentSnapshot], phase_id: &str) {
    let (running, finished): (&[&str], &[&str]) = match phase_id {
        "planning" => (&["planner"], &[]),
        "inventory" => (&["inventory"], &["planner"]),
        "followup" => (&["followup"], &["planner", "inventory"]),
        "forensic" => (
            &["forensic", "web-pentest"],
            &["planner", "inventory", "followup"],
        ),
        "context" => (
            &["context-fusion", "live-observer"],
            &[
                "planner",
                "inventory",
                "followup",
                "forensic",
                "web-pentest",
            ],
        ),
        "passive" => (
            &["live-observer", "credential-hunter", "traffic-forensics"],
            &[
                "planner",
                "inventory",
                "followup",
                "forensic",
                "web-pentest",
                "context-fusion",
            ],
        ),
        "correlation" => (
            &["correlator"],
            &[
                "planner",
                "inventory",
                "followup",
                "forensic",
                "web-pentest",
                "live-observer",
                "credential-hunter",
                "traffic-forensics",
                "context-fusion",
            ],
        ),
        "finalize" => (
            &["intel", "validation", "remediation", "reporter"],
            &[
                "planner",
                "inventory",
                "followup",
                "forensic",
                "web-pentest",
                "live-observer",
                "credential-hunter",
                "traffic-forensics",
                "context-fusion",
                "correlator",
            ],
        ),
        "complete" => (
            &[],
            &[
                "planner",
                "inventory",
                "followup",
                "forensic",
                "web-pentest",
                "live-observer",
                "credential-hunter",
                "traffic-forensics",
                "context-fusion",
                "correlator",
                "intel",
                "validation",
                "remediation",
                "reporter",
            ],
        ),
        _ => (&[], &[]),
    };
    for agent in agents {
        if finished.iter().any(|role| *role == agent.role) {
            agent.status = "ok".to_string();
            agent.summary = format!("Agent {} dokončil svoji část běhu.", agent.role);
            continue;
        }
        if running.iter().any(|role| *role == agent.role) {
            agent.status = "running".to_string();
            agent.summary = format!("Agent {} právě zpracovává aktuální fázi.", agent.role);
            continue;
        }
        if phase_id == "complete" {
            agent.status = "ok".to_string();
            agent.summary = format!("Agent {} dokončil svoji část běhu.", agent.role);
        } else {
            agent.status = "pending".to_string();
            agent.summary = format!("Agent {} čeká na další krok.", agent.role);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mas_templates_define_distinct_roles() {
        let agents = runtime_agent_templates();
        assert!(agents.len() >= 14);
        let unique_roles = agents
            .iter()
            .map(|agent| agent.role.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique_roles.len(), agents.len());
    }

    #[test]
    fn context_phase_runs_parallel_agents() {
        let mut agents = runtime_agent_templates();
        update_runtime_agents(&mut agents, "context");
        let running_roles = agents
            .iter()
            .filter(|agent| agent.status == "running")
            .map(|agent| agent.role.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(running_roles.len(), 2);
        assert!(running_roles.contains("context-fusion"));
        assert!(running_roles.contains("live-observer"));
    }

    #[test]
    fn finalize_phase_runs_intel_and_reporter() {
        let mut agents = runtime_agent_templates();
        update_runtime_agents(&mut agents, "finalize");
        let running_roles = agents
            .iter()
            .filter(|agent| agent.status == "running")
            .map(|agent| agent.role.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(running_roles.len(), 4);
        assert!(running_roles.contains("intel"));
        assert!(running_roles.contains("validation"));
        assert!(running_roles.contains("remediation"));
        assert!(running_roles.contains("reporter"));
    }

    #[test]
    fn mas_blueprint_has_acyclic_dependencies() {
        let blueprint = mas_agent_blueprint();
        let mut completed = std::collections::BTreeSet::<String>::new();
        let mut pending = blueprint;
        let mut safety = 0;
        while !pending.is_empty() {
            safety += 1;
            assert!(safety < 32, "Dependency graph appears cyclic");
            let ready_now = pending
                .iter()
                .filter(|agent| agent.depends_on.iter().all(|dep| completed.contains(dep)))
                .map(|agent| agent.role.clone())
                .collect::<Vec<_>>();
            assert!(
                !ready_now.is_empty(),
                "No ready agent found while dependencies remain"
            );
            for role in &ready_now {
                completed.insert(role.clone());
            }
            pending.retain(|agent| !ready_now.iter().any(|role| role == &agent.role));
        }
        assert_eq!(completed.len(), MAS_AGENT_ROLES.len());
    }

    #[test]
    fn consensus_state_thresholds_are_stable() {
        assert_eq!(consensus_state_for_score(0.82), "strong");
        assert_eq!(consensus_state_for_score(0.62), "review");
        assert_eq!(consensus_state_for_score(0.44), "weak");
    }

    #[test]
    fn parse_lane_metric_extracts_numeric_evidence() {
        let lane = MonitoringLane {
            lane_id: "lane:test".to_string(),
            lane_type: "automation".to_string(),
            source: "test".to_string(),
            title: "test".to_string(),
            status: "ok".to_string(),
            summary: "test".to_string(),
            evidence: vec!["hosts=3".to_string(), "ports=11".to_string()],
            recommended_tools: Vec::new(),
        };

        assert_eq!(parse_lane_metric(&lane, "hosts"), Some(3));
        assert_eq!(parse_lane_metric(&lane, "ports"), Some(11));
        assert_eq!(parse_lane_metric(&lane, "missing"), None);
    }
}
