use std::collections::BTreeSet;

use crate::model::{Confidence, Finding, MonitoringLane, RunReport, Severity, TriageAction};

#[derive(Debug, Clone)]
pub struct DecisionBundle {
    pub actions: Vec<TriageAction>,
    pub lanes: Vec<MonitoringLane>,
}

pub fn build_decision_bundle(report: &RunReport) -> DecisionBundle {
    let mut actions = Vec::new();
    let mut lanes = Vec::new();
    let high_findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::High)
        .collect::<Vec<_>>();
    let medium_or_high = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::Medium)
        .collect::<Vec<_>>();
    let uncertain = report
        .findings
        .iter()
        .filter(|finding| {
            finding.confidence != Confidence::High
                || finding.finding_type == "identification_gap"
                || finding.finding_type == "correlation_uncertainty"
        })
        .collect::<Vec<_>>();
    let plaintext = report
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "plaintext_management_protocol")
        .collect::<Vec<_>>();
    let cve_like = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.finding_type.as_str(),
                "high_risk_cve_exposure"
                    | "known_exploited_vulnerability"
                    | "probable_exploitation_interest"
            )
        })
        .collect::<Vec<_>>();
    let traffic_like = report
        .findings
        .iter()
        .filter(|finding| {
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
        })
        .collect::<Vec<_>>();
    let has_public_intel = has_public_intel_context(report);
    let ranked = ranked_decisions(report);
    let inference_evidence = inference_graph_evidence(report, &ranked);

    if !inference_evidence.is_empty() {
        lanes.push(decision_lane(
            "lane:decision:inference-graph",
            "decision-inference-graph",
            "ok",
            "Inference graph oddělil dedukci z pravidel, indukci z provozních vzorců a abdukci pro neověřené hypotézy.".to_string(),
            inference_evidence,
            vec![
                "deductive-rules".to_string(),
                "inductive-baseline".to_string(),
                "abductive-hypotheses".to_string(),
            ],
        ));
    }

    if !ranked.is_empty() {
        lanes.push(decision_lane(
            "lane:decision:risk-ranking",
            "decision-risk-ranking",
            "ok",
            format!(
                "Risk scorer seřadil {} hypotéz podle dopadu, jistoty, pasivních důkazů, CVE signálů a změn proti paměti případů.",
                ranked.len()
            ),
            ranked
                .iter()
                .take(8)
                .map(|item| item.to_evidence())
                .collect(),
            vec![
                "evidence-scoring".to_string(),
                "mas-consensus".to_string(),
                "case-memory".to_string(),
            ],
        ));
    }

    if !medium_or_high.is_empty() {
        lanes.push(decision_lane(
            "lane:decision:hypotheses",
            "decision-hypotheses",
            "ok",
            format!(
                "Decision engine sestavil {} hypotéz z prioritních nálezů a oddělil ověření od okamžité mitigace.",
                medium_or_high.len()
            ),
            medium_or_high
                .iter()
                .take(6)
                .map(|finding| {
                    format!(
                        "hypothesis={} target={}",
                        finding.finding_type,
                        target_of(finding)
                    )
                })
                .collect(),
            vec![
                "nmap-forensic".to_string(),
                "passive-correlation".to_string(),
                "case-memory".to_string(),
            ],
        ));
    }

    if !high_findings.is_empty() || !uncertain.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:forensic-plan:{}", report.run.run_id),
            action_type: "forensic-decision-plan".to_string(),
            title: "Spustit rozhodovací forenzní plán".to_string(),
            priority: if !high_findings.is_empty() {
                Severity::High
            } else {
                Severity::Medium
            },
            rationale: "Nálezy nejsou brané jen jako shoda textu. Decision engine z nich skládá hypotézy a chce je potvrdit dalším zdrojem: aktivním follow-upem, pasivní telemetrií nebo autorizovaným kontextem.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&medium_or_high),
            recommended_tools: vec![
                "nmap-forensic".to_string(),
                "zeek".to_string(),
                "suricata".to_string(),
                "controller-context".to_string(),
            ],
            evidence: hypothesis_evidence(&medium_or_high, 8),
        });
    }

    if !uncertain.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:identity-verifier:{}", report.run.run_id),
            action_type: "spawn-agent:identity-verifier".to_string(),
            title: "Vytvořit agenta pro ověření identity služby".to_string(),
            priority: Severity::Medium,
            rationale: "Některé závěry mají nižší jistotu nebo chybí přesná identita služby. Agent má doplnit banner, CPE, controller inventář a pasivní relace, aby se nerozhodovalo jen podle hrubé shody.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&uncertain),
            recommended_tools: vec![
                "nmap-followup".to_string(),
                "service-banner".to_string(),
                "controller-context".to_string(),
                "case-memory".to_string(),
            ],
            evidence: hypothesis_evidence(&uncertain, 8),
        });
    }

    if !cve_like.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:vuln-intel-verifier:{}", report.run.run_id),
            action_type: "spawn-agent:vuln-intel-verifier".to_string(),
            title: "Vytvořit agenta pro ověření CVE a exploitability".to_string(),
            priority: Severity::High,
            rationale: "U zranitelností nestačí bannerová shoda. Agent má porovnat verzi, CPE, CVE, KEV/EPSS a reálnou síťovou expozici, aby oddělil teoretickou zranitelnost od praktického rizika.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&cve_like),
            recommended_tools: vec![
                "nvd".to_string(),
                "cisa-kev".to_string(),
                "first-epss".to_string(),
                "circl".to_string(),
                "osv".to_string(),
                "vulners-optional".to_string(),
                "vendor-advisory".to_string(),
            ],
            evidence: hypothesis_evidence(&cve_like, 8),
        });
    }

    if report.summary.cves_total > 0 && !has_public_intel {
        actions.push(TriageAction {
            action_id: format!("decision:public-intel-cross-checker:{}", report.run.run_id),
            action_type: "spawn-agent:public-intel-cross-checker".to_string(),
            title: "Vytvořit agenta pro veřejné ověření CVE".to_string(),
            priority: Severity::Medium,
            rationale: "Report obsahuje CVE, ale chybí veřejný doplňkový kontext z CIRCL/OSV/KEV/EPSS nebo public intel lane. Agent má znovu ověřit veřejné zdroje a oddělit skutečný exploitační kontext od samotného CVE záznamu.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&cve_like),
            recommended_tools: vec![
                "nvd".to_string(),
                "cisa-kev".to_string(),
                "first-epss".to_string(),
                "circl".to_string(),
                "osv".to_string(),
            ],
            evidence: vec![
                format!("cves={}", report.summary.cves_total),
                format!("intel_matches={}", report.summary.intel_matches_total),
                "public_context=false".to_string(),
            ],
        });
        lanes.push(decision_lane(
            "lane:decision:public-intel-gap",
            "public-intel-gap",
            "pending",
            "Decision engine vytvořil úkol pro veřejné křížové ověření CVE, protože samotný CVE záznam nestačí jako důkaz praktického rizika.".to_string(),
            vec![
                format!("cves={}", report.summary.cves_total),
                format!("intel_matches={}", report.summary.intel_matches_total),
            ],
            vec![
                "nvd".to_string(),
                "cisa-kev".to_string(),
                "first-epss".to_string(),
                "circl".to_string(),
                "osv".to_string(),
            ],
        ));
    }

    if !plaintext.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:plaintext-passive-hunter:{}", report.run.run_id),
            action_type: "spawn-agent:passive-credential-hunter".to_string(),
            title: "Vytvořit agenta pro nešifrované přihlášení".to_string(),
            priority: Severity::High,
            rationale: "Nešifrovaný Telnet nebo FTP je potřeba ověřit v pasivních datech, protože aktivní sken ukáže port, ale pasivní provoz ukáže, jestli přes něj opravdu tečou relace.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&plaintext),
            recommended_tools: vec![
                "zeek".to_string(),
                "suricata".to_string(),
                "pcap-review".to_string(),
                "firewall".to_string(),
            ],
            evidence: hypothesis_evidence(&plaintext, 8),
        });
    }

    if !traffic_like.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:traffic-forensics:{}", report.run.run_id),
            action_type: "spawn-agent:traffic-forensics".to_string(),
            title: "Vytvořit agenta pro vzorce provozu".to_string(),
            priority: Severity::High,
            rationale: "U provozních anomálií je důležitý kontext v čase. Agent má porovnat cíle, zdroje, objem, timeouty a vazbu na běžné služby.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&traffic_like),
            recommended_tools: vec![
                "netflow-ipfix".to_string(),
                "ntopng".to_string(),
                "zeek".to_string(),
                "baseline-profiler".to_string(),
            ],
            evidence: hypothesis_evidence(&traffic_like, 8),
        });
    }

    if report.summary.live_lanes_total == 0
        && (!traffic_like.is_empty()
            || !plaintext.is_empty()
            || !cve_like.is_empty()
            || !medium_or_high.is_empty())
    {
        actions.push(TriageAction {
            action_id: format!("decision:live-observer:{}", report.run.run_id),
            action_type: "spawn-agent:live-observer".to_string(),
            title: "Zapnout live agenta pro průběžné ověřování".to_string(),
            priority: Severity::Medium,
            rationale: "Aktivní sken ukáže stav v jednom okamžiku. Live agent má průběžně sbírat Zeek/Suricata/flow signály, aby šlo poznat, jestli se riziko opravdu používá nebo jen existuje jako otevřený port.".to_string(),
            target_asset_id: None,
            target_service_key: first_target(&medium_or_high),
            recommended_tools: vec![
                "zeek".to_string(),
                "suricata".to_string(),
                "netflow-ipfix".to_string(),
                "ntopng".to_string(),
            ],
            evidence: vec![
                format!("live_lanes_total={}", report.summary.live_lanes_total),
                format!("events_total={}", report.summary.events_total),
                format!("ranked_hypotheses={}", ranked.len()),
            ],
        });
    }

    if report.summary.live_lanes_total == 0 && report.summary.events_total == 0 {
        lanes.push(decision_lane(
            "lane:decision:spawn-live-observer",
            "agent-spawner",
            "pending",
            "Agentní společenství doporučuje vytvořit live-observer, protože běh nemá průběžnou pasivní telemetrii.".to_string(),
            vec!["missing=live_lanes".to_string(), "events_total=0".to_string()],
            vec![
                "zeek".to_string(),
                "suricata".to_string(),
                "ntopng".to_string(),
            ],
        ));
    }

    let lifecycle_evidence = agent_lifecycle_evidence(
        report,
        &ranked,
        !cve_like.is_empty(),
        !plaintext.is_empty(),
        !traffic_like.is_empty(),
        !uncertain.is_empty(),
    );
    if !lifecycle_evidence.is_empty() {
        lanes.push(decision_lane(
            "lane:decision:agent-lifecycle",
            "agent-lifecycle",
            "ok",
            "Agent governor vyhodnotil, které role mají běžet, které se mají vytvořit a které je možné nechat vypnuté kvůli slabému signálu.".to_string(),
            lifecycle_evidence,
            vec![
                "scheduler".to_string(),
                "resource-budget".to_string(),
                "agent-registry".to_string(),
            ],
        ));
    }

    let changed_services_total = diff_changed_services_total(report);
    if changed_services_total > 0 {
        lanes.push(decision_lane(
            "lane:decision:case-memory",
            "case-memory",
            "ok",
            "Paměť případů porovnala aktuální běh s předchozím stavem a zvýraznila změněné služby."
                .to_string(),
            vec![format!("changed_services={changed_services_total}")],
            vec![
                "diff".to_string(),
                "baseline".to_string(),
                "regression-review".to_string(),
            ],
        ));
    }

    if high_findings.is_empty() && traffic_like.is_empty() && cve_like.is_empty() {
        actions.push(TriageAction {
            action_id: format!("decision:kill-heavy-forensics:{}", report.run.run_id),
            action_type: "kill-agent:nmap-forensic".to_string(),
            title: "Vypnout těžký forenzní agent pro tento běh".to_string(),
            priority: Severity::Low,
            rationale: "Autonomní governor nevidí vysoký, exploitability ani provozně podezřelý signál. Těžký forenzní průchod by v tomto běhu plýtval časem a má zůstat vypnutý, dokud nepřijde nový důkaz.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec!["scheduler".to_string(), "resource-budget".to_string()],
            evidence: vec![
                "kill_candidate=nmap-forensic".to_string(),
                "reason=no-high-signal".to_string(),
            ],
        });
        lanes.push(decision_lane(
            "lane:decision:retire-heavy-forensics",
            "agent-governor",
            "ok",
            "Agent governor by v tomto běhu pozastavil těžké forenzní agenty, protože nejsou vidět vysoké ani provozně podezřelé signály.".to_string(),
            vec![
                "kill_candidate=nmap-forensic".to_string(),
                "reason=no-high-signal".to_string(),
            ],
            vec!["scheduler".to_string(), "resource-budget".to_string()],
        ));
    }

    actions.sort_by(|left, right| right.priority.cmp(&left.priority));
    actions.dedup_by(|left, right| left.action_id == right.action_id);
    lanes.sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    lanes.dedup_by(|left, right| left.lane_id == right.lane_id);
    DecisionBundle { actions, lanes }
}

#[derive(Debug, Clone)]
struct RankedDecision {
    score: f64,
    target: String,
    finding_type: String,
    severity: Severity,
    confidence: Confidence,
    decision: String,
    reasons: Vec<String>,
}

impl RankedDecision {
    fn to_evidence(&self) -> String {
        format!(
            "score={:.2} decision={} target={} type={} severity={:?} confidence={:?} reasons={}",
            self.score,
            self.decision,
            self.target,
            self.finding_type,
            self.severity,
            self.confidence,
            self.reasons.join("|")
        )
    }
}

fn decision_lane(
    lane_id: &str,
    source: &str,
    status: &str,
    summary: String,
    evidence: Vec<String>,
    recommended_tools: Vec<String>,
) -> MonitoringLane {
    MonitoringLane {
        lane_id: lane_id.to_string(),
        lane_type: "automation".to_string(),
        source: source.to_string(),
        title: source.replace('-', " "),
        status: status.to_string(),
        summary,
        evidence,
        recommended_tools,
    }
}

fn first_target(findings: &[&Finding]) -> Option<String> {
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

fn hypothesis_evidence(findings: &[&Finding], limit: usize) -> Vec<String> {
    let mut seen = BTreeSet::new();
    findings
        .iter()
        .filter_map(|finding| {
            let value = format!("{}:{}", finding.finding_type, target_of(finding));
            if seen.insert(value.clone()) {
                Some(value)
            } else {
                None
            }
        })
        .take(limit)
        .collect()
}

fn diff_changed_services_total(report: &RunReport) -> usize {
    report
        .diff
        .as_ref()
        .map(|diff| diff.changed_services.len())
        .unwrap_or(0)
}

fn ranked_decisions(report: &RunReport) -> Vec<RankedDecision> {
    let changed_targets = report
        .diff
        .as_ref()
        .map(|diff| {
            diff.changed_services
                .iter()
                .map(|item| item.service_key.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut ranked = report
        .findings
        .iter()
        .map(|finding| rank_finding(finding, &changed_targets))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.severity.cmp(&left.severity))
            .then_with(|| right.confidence.cmp(&left.confidence))
    });
    ranked
}

fn inference_graph_evidence(report: &RunReport, ranked: &[RankedDecision]) -> Vec<String> {
    if report.findings.is_empty() {
        return Vec::new();
    }

    let cve_count = report
        .findings
        .iter()
        .filter(|finding| is_cve_signal(finding))
        .count();
    let plaintext_count = report
        .findings
        .iter()
        .filter(|finding| is_plaintext_signal(finding))
        .count();
    let traffic_count = report
        .findings
        .iter()
        .filter(|finding| is_traffic_signal(finding))
        .count();
    let uncertain_count = report
        .findings
        .iter()
        .filter(|finding| {
            finding.confidence != Confidence::High
                || finding.finding_type == "identification_gap"
                || finding.finding_type == "correlation_uncertainty"
        })
        .count();
    let changed_services = diff_changed_services_total(report);

    let mut evidence = Vec::new();
    if cve_count > 0 {
        evidence.push(format!(
            "deduction=cve-exposure-implies-exploitability-review count={cve_count}"
        ));
    }
    if plaintext_count > 0 {
        evidence.push(format!(
            "deduction=plaintext-management-implies-credential-risk count={plaintext_count}"
        ));
    }
    if traffic_count > 0 || report.summary.events_total > 0 {
        evidence.push(format!(
            "induction=traffic-patterns events={} anomaly_findings={} live_lanes={}",
            report.summary.events_total, traffic_count, report.summary.live_lanes_total
        ));
    }
    if changed_services > 0 {
        evidence.push(format!(
            "induction=baseline-drift changed_services={changed_services}"
        ));
    }
    if uncertain_count > 0 {
        evidence.push(format!(
            "abduction=service-identity-or-correlation-gap hypotheses={uncertain_count} action=verify-before-mitigate"
        ));
    }
    if let Some(top) = ranked.first() {
        evidence.push(format!(
            "decision-frontier target={} decision={} score={:.2} reasons={}",
            top.target,
            top.decision,
            top.score,
            top.reasons.join("|")
        ));
    }
    evidence.push(format!(
        "context-window hosts={} services={} findings={} triage={}",
        report.summary.hosts_total,
        report.summary.services_total,
        report.summary.findings_total,
        report.summary.triage_actions_total
    ));
    evidence
}

fn rank_finding(finding: &Finding, changed_targets: &BTreeSet<String>) -> RankedDecision {
    let mut score: f64 = match finding.severity {
        Severity::High => 0.62,
        Severity::Medium => 0.42,
        Severity::Low => 0.18,
    };
    score += match finding.confidence {
        Confidence::High => 0.18,
        Confidence::Medium => 0.1,
        Confidence::Low => -0.04,
    };

    let mut reasons = Vec::new();
    if is_cve_signal(finding) {
        score += 0.16;
        reasons.push("cve-intel".to_string());
    }
    if is_plaintext_signal(finding) {
        score += 0.15;
        reasons.push("plaintext-login".to_string());
    }
    if is_traffic_signal(finding) {
        score += 0.14;
        reasons.push("traffic-pattern".to_string());
    }
    if has_passive_evidence(finding) {
        score += 0.1;
        reasons.push("passive-evidence".to_string());
    }
    if finding
        .service_key
        .as_ref()
        .is_some_and(|service_key| changed_targets.contains(service_key))
    {
        score += 0.12;
        reasons.push("changed-since-baseline".to_string());
    }
    if finding.finding_type == "identification_gap"
        || finding.finding_type == "correlation_uncertainty"
        || finding.confidence != Confidence::High
    {
        score += 0.05;
        reasons.push("needs-verification".to_string());
    }
    if reasons.is_empty() {
        reasons.push("structured-finding".to_string());
    }

    let score = score.clamp(0.0, 1.0);
    let decision = if finding.confidence != Confidence::High
        || finding.finding_type == "identification_gap"
        || finding.finding_type == "correlation_uncertainty"
    {
        "verify"
    } else if finding.severity == Severity::High
        && (is_cve_signal(finding) || is_plaintext_signal(finding) || is_traffic_signal(finding))
    {
        "mitigate"
    } else if finding.severity >= Severity::Medium {
        "investigate"
    } else {
        "watch"
    }
    .to_string();

    RankedDecision {
        score,
        target: target_of(finding),
        finding_type: finding.finding_type.clone(),
        severity: finding.severity,
        confidence: finding.confidence,
        decision,
        reasons,
    }
}

fn agent_lifecycle_evidence(
    report: &RunReport,
    ranked: &[RankedDecision],
    has_cve: bool,
    has_plaintext: bool,
    has_traffic: bool,
    has_uncertain: bool,
) -> Vec<String> {
    let mut evidence = Vec::new();
    if has_cve {
        evidence.push("spawn=vuln-intel-verifier reason=cve-or-exploitability-signal".to_string());
    }
    if has_plaintext {
        evidence.push(
            "spawn=passive-credential-hunter reason=plaintext-management-protocol".to_string(),
        );
    }
    if has_traffic {
        evidence.push("spawn=traffic-forensics reason=traffic-pattern-anomaly".to_string());
    }
    if has_uncertain {
        evidence
            .push("spawn=identity-verifier reason=low-confidence-or-correlation-gap".to_string());
    }
    if report.summary.live_lanes_total == 0 && ranked.iter().any(|item| item.score >= 0.55) {
        evidence
            .push("spawn=live-observer reason=priority-without-continuous-telemetry".to_string());
    }
    if ranked.iter().all(|item| item.score < 0.45) {
        evidence.push("kill=nmap-forensic reason=no-ranked-high-signal".to_string());
    }
    if report.summary.events_total > 0 || has_traffic {
        evidence.push("keep=correlator reason=passive-or-flow-context-present".to_string());
    }
    if evidence.is_empty() && !ranked.is_empty() {
        evidence.push("keep=planner reason=ranked-hypotheses-present".to_string());
    }
    evidence
}

fn is_cve_signal(finding: &Finding) -> bool {
    matches!(
        finding.finding_type.as_str(),
        "high_risk_cve_exposure"
            | "known_exploited_vulnerability"
            | "probable_exploitation_interest"
    ) || finding.evidence.iter().any(|item| {
        let value = item.to_ascii_lowercase();
        value.contains("cve") || value.contains("kev") || value.contains("epss")
    })
}

fn is_plaintext_signal(finding: &Finding) -> bool {
    finding.finding_type == "plaintext_management_protocol"
        || finding.evidence.iter().any(|item| {
            let value = item.to_ascii_lowercase();
            value.contains("telnet") || value.contains("ftp") || value.contains("plaintext")
        })
}

fn is_traffic_signal(finding: &Finding) -> bool {
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
}

fn has_passive_evidence(finding: &Finding) -> bool {
    is_traffic_signal(finding)
        || finding.evidence.iter().any(|item| {
            let value = item.to_ascii_lowercase();
            value.contains("zeek")
                || value.contains("suricata")
                || value.contains("flow")
                || value.contains("event")
                || value.contains("passive")
        })
}

fn has_public_intel_context(report: &RunReport) -> bool {
    report
        .monitoring_lanes
        .iter()
        .any(|lane| lane.source == "public-intel-stack")
        || report.intel_matches.iter().any(|item| {
            matches!(
                item.source.as_str(),
                "CIRCL Vulnerability-Lookup" | "OSV.dev" | "MITRE ATT&CK Context"
            )
        })
        || report
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
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::storage::Workspace;

    use super::*;

    #[test]
    fn decision_bundle_adds_forensic_and_agent_context() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let report = Workspace::open(&workspace)
            .expect("workspace")
            .load_report("run-20260408082442-1-0efa89d558394082947b40f7de9a7801")
            .expect("report");
        let bundle = build_decision_bundle(&report);

        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "decision-hypotheses")
        );
        assert!(
            bundle
                .actions
                .iter()
                .any(|action| action.action_type.starts_with("spawn-agent:"))
        );
        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "decision-risk-ranking")
        );
        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "decision-inference-graph"
                    && lane.evidence.iter().any(|item| item.contains("deduction=")
                        || item.contains("induction=")
                        || item.contains("abduction=")))
        );
        assert!(
            bundle
                .lanes
                .iter()
                .any(|lane| lane.source == "agent-lifecycle")
        );
    }
}
