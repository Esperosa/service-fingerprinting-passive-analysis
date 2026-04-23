use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Result,
    error::BakulaError,
    model::RunReport,
    verification::{CheckResult, ScenarioManifest, ScenarioVerification},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvalMetrics {
    pub scenario_key: String,
    pub scenario_name: String,
    pub run_id: String,
    pub passed: bool,
    pub duration_seconds: f64,
    pub checks_total: usize,
    pub checks_passed: usize,
    pub check_pass_ratio: f64,
    pub findings_total: usize,
    pub distinct_finding_types_total: usize,
    pub affected_targets_total: usize,
    pub average_findings_per_target: f64,
    pub average_finding_families_per_target: f64,
    pub max_findings_per_target: usize,
    pub max_finding_families_per_target: usize,
    pub max_core_families_per_target: usize,
    pub expected_core_types: Vec<String>,
    pub predicted_core_types: Vec<String>,
    pub true_positive_core_types: Vec<String>,
    pub false_positive_core_types: Vec<String>,
    pub false_negative_core_types: Vec<String>,
    #[serde(default)]
    pub mas_parallelism_ratio: f64,
    #[serde(default)]
    pub mas_queue_wait_ms_avg: f64,
    #[serde(default)]
    pub mas_agent_sla_ratio: f64,
    #[serde(default)]
    pub mas_consensus_score: f64,
    #[serde(default)]
    pub mas_progress_score: f64,
    #[serde(default)]
    pub forensic_depth_score: f64,
    #[serde(default)]
    pub fusion_coverage_ratio: f64,
    #[serde(default)]
    pub failed_checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSummary {
    pub scenarios_total: usize,
    pub scenarios_passed: usize,
    pub scenarios_failed: usize,
    pub runtime_seconds_total: f64,
    pub scenario_duration_seconds_avg: f64,
    pub scenario_duration_seconds_p95: f64,
    pub checks_total: usize,
    pub checks_passed: usize,
    pub check_pass_ratio: f64,
    pub core_expected_total: usize,
    pub core_predicted_total: usize,
    pub core_true_positive_total: usize,
    pub core_false_positive_total: usize,
    pub core_false_negative_total: usize,
    pub core_precision: f64,
    pub core_recall: f64,
    pub core_f1: f64,
    #[serde(default)]
    pub mas_parallelism_ratio_avg: f64,
    #[serde(default)]
    pub mas_queue_wait_ms_avg: f64,
    #[serde(default)]
    pub mas_agent_sla_ratio_avg: f64,
    #[serde(default)]
    pub mas_consensus_score_avg: f64,
    #[serde(default)]
    pub mas_progress_score_avg: f64,
    #[serde(default)]
    pub forensic_depth_score_avg: f64,
    #[serde(default)]
    pub fusion_coverage_ratio_avg: f64,
    pub average_findings_per_scenario: f64,
    pub average_findings_per_target: f64,
    pub average_finding_families_per_target: f64,
    pub max_findings_per_target: usize,
    pub max_finding_families_per_target: usize,
    pub max_core_families_per_target: usize,
    #[serde(default)]
    pub top_false_positive_types: Vec<EvaluationCount>,
    #[serde(default)]
    pub top_false_negative_types: Vec<EvaluationCount>,
    #[serde(default)]
    pub worst_scenarios: Vec<ScenarioEvalMetrics>,
    #[serde(default)]
    pub improvement_hypotheses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub generated_at: DateTime<Utc>,
    pub seed: u64,
    pub random_pairs: usize,
    pub workers: usize,
    pub provider: String,
    pub tracked_core_types: Vec<String>,
    pub summary: EvaluationSummary,
    pub scenarios: Vec<ScenarioEvalMetrics>,
}

pub fn scenario_metrics(
    scenario_key: &str,
    manifest: &ScenarioManifest,
    report: &RunReport,
    verification: &ScenarioVerification,
    tracked_core_types: &BTreeSet<String>,
) -> ScenarioEvalMetrics {
    let expected_core_types = manifest
        .expectations
        .required_finding_types
        .iter()
        .filter(|item| tracked_core_types.contains(*item))
        .cloned()
        .collect::<BTreeSet<_>>();
    let predicted_core_types = report
        .findings
        .iter()
        .map(|finding| finding.finding_type.clone())
        .filter(|item| tracked_core_types.contains(item))
        .collect::<BTreeSet<_>>();
    let distinct_finding_types = report
        .findings
        .iter()
        .map(|finding| finding.finding_type.clone())
        .collect::<BTreeSet<_>>();

    let true_positive_core_types = expected_core_types
        .intersection(&predicted_core_types)
        .cloned()
        .collect::<Vec<_>>();
    let false_positive_core_types = predicted_core_types
        .difference(&expected_core_types)
        .cloned()
        .collect::<Vec<_>>();
    let false_negative_core_types = expected_core_types
        .difference(&predicted_core_types)
        .cloned()
        .collect::<Vec<_>>();

    let mut target_finding_counts = BTreeMap::<String, usize>::new();
    let mut target_finding_families = BTreeMap::<String, BTreeSet<String>>::new();
    let mut target_core_families = BTreeMap::<String, BTreeSet<String>>::new();
    for finding in &report.findings {
        let target = finding
            .service_key
            .clone()
            .or_else(|| finding.host_key.clone())
            .unwrap_or_else(|| "global".to_string());
        *target_finding_counts.entry(target.clone()).or_insert(0) += 1;
        target_finding_families
            .entry(target.clone())
            .or_default()
            .insert(finding.finding_type.clone());
        if tracked_core_types.contains(&finding.finding_type) {
            target_core_families
                .entry(target)
                .or_default()
                .insert(finding.finding_type.clone());
        }
    }

    let affected_targets_total = target_finding_counts.len();
    let average_findings_per_target = if affected_targets_total == 0 {
        0.0
    } else {
        round_ratio(report.findings.len() as f64 / affected_targets_total as f64)
    };
    let average_finding_families_per_target = if affected_targets_total == 0 {
        0.0
    } else {
        round_ratio(
            target_finding_families
                .values()
                .map(BTreeSet::len)
                .sum::<usize>() as f64
                / affected_targets_total as f64,
        )
    };
    let max_findings_per_target = target_finding_counts.values().copied().max().unwrap_or(0);
    let max_finding_families_per_target = target_finding_families
        .values()
        .map(BTreeSet::len)
        .max()
        .unwrap_or(0);
    let max_core_families_per_target = target_core_families
        .values()
        .map(BTreeSet::len)
        .max()
        .unwrap_or(0);
    let checks_total = verification.checks.len();
    let checks_passed = verification
        .checks
        .iter()
        .filter(|item| item.passed)
        .count();
    let mas_parallelism_ratio = report.summary.mas_parallelism_ratio;
    let mas_queue_wait_ms_avg = report.summary.mas_queue_wait_ms_avg;
    let mas_agent_sla_ratio = report.summary.mas_agent_sla_ratio;
    let mas_consensus_score = report.summary.mas_consensus_score;
    let mas_progress_score = round_ratio(
        ((report.summary.tooling_coverage_ratio
            + report.summary.service_identity_coverage_ratio
            + mas_agent_sla_ratio
            + mas_parallelism_ratio)
            / 4.0)
            .clamp(0.0, 1.0),
    );
    let forensic_depth_score = if report.summary.services_high_priority == 0 {
        round_ratio(
            (report.summary.forensic_targets_total as f64
                / report.summary.services_total.max(1) as f64)
                .clamp(0.0, 1.0),
        )
    } else {
        round_ratio(
            (report.summary.forensic_targets_total as f64
                / report.summary.services_high_priority.max(1) as f64)
                .clamp(0.0, 1.0),
        )
    };
    let asset_ratio = if report.summary.hosts_total == 0 {
        1.0
    } else {
        (report.summary.network_assets_total as f64 / report.summary.hosts_total as f64)
            .clamp(0.0, 2.0)
            / 2.0
    };
    let lane_ratio = (report.summary.monitoring_lanes_total as f64 / 14.0).clamp(0.0, 1.0);
    let fusion_coverage_ratio =
        round_ratio((asset_ratio * 0.55 + lane_ratio * 0.45).clamp(0.0, 1.0));

    ScenarioEvalMetrics {
        scenario_key: scenario_key.to_string(),
        scenario_name: manifest.nazev.clone(),
        run_id: report.run.run_id.clone(),
        passed: verification.passed,
        duration_seconds: round_ratio(
            (report.run.finished_at - report.run.started_at).num_milliseconds() as f64 / 1000.0,
        ),
        checks_total,
        checks_passed,
        check_pass_ratio: ratio(checks_passed, checks_total),
        findings_total: report.findings.len(),
        distinct_finding_types_total: distinct_finding_types.len(),
        affected_targets_total,
        average_findings_per_target,
        average_finding_families_per_target,
        max_findings_per_target,
        max_finding_families_per_target,
        max_core_families_per_target,
        expected_core_types: expected_core_types.into_iter().collect(),
        predicted_core_types: predicted_core_types.into_iter().collect(),
        true_positive_core_types,
        false_positive_core_types,
        false_negative_core_types,
        mas_parallelism_ratio,
        mas_queue_wait_ms_avg,
        mas_agent_sla_ratio,
        mas_consensus_score,
        mas_progress_score,
        forensic_depth_score,
        fusion_coverage_ratio,
        failed_checks: verification
            .checks
            .iter()
            .filter(|item| !item.passed)
            .cloned()
            .collect(),
    }
}

pub fn build_evaluation_report(
    seed: u64,
    random_pairs: usize,
    workers: usize,
    provider: &str,
    tracked_core_types: BTreeSet<String>,
    mut scenarios: Vec<ScenarioEvalMetrics>,
) -> EvaluationReport {
    scenarios.sort_by(|left, right| left.scenario_key.cmp(&right.scenario_key));

    let scenarios_total = scenarios.len();
    let scenarios_passed = scenarios.iter().filter(|item| item.passed).count();
    let checks_total = scenarios
        .iter()
        .map(|item| item.checks_total)
        .sum::<usize>();
    let checks_passed = scenarios
        .iter()
        .map(|item| item.checks_passed)
        .sum::<usize>();
    let runtime_seconds_total = round_ratio(
        scenarios
            .iter()
            .map(|item| item.duration_seconds)
            .sum::<f64>(),
    );
    let scenario_duration_seconds_avg = if scenarios_total == 0 {
        0.0
    } else {
        round_ratio(runtime_seconds_total / scenarios_total as f64)
    };
    let scenario_duration_seconds_p95 = percentile(
        scenarios
            .iter()
            .map(|item| item.duration_seconds)
            .collect::<Vec<_>>(),
        0.95,
    );
    let core_expected_total = scenarios
        .iter()
        .map(|item| item.expected_core_types.len())
        .sum::<usize>();
    let core_predicted_total = scenarios
        .iter()
        .map(|item| item.predicted_core_types.len())
        .sum::<usize>();
    let core_true_positive_total = scenarios
        .iter()
        .map(|item| item.true_positive_core_types.len())
        .sum::<usize>();
    let core_false_positive_total = scenarios
        .iter()
        .map(|item| item.false_positive_core_types.len())
        .sum::<usize>();
    let core_false_negative_total = scenarios
        .iter()
        .map(|item| item.false_negative_core_types.len())
        .sum::<usize>();
    let average_findings_per_scenario = if scenarios_total == 0 {
        0.0
    } else {
        round_ratio(
            scenarios
                .iter()
                .map(|item| item.findings_total)
                .sum::<usize>() as f64
                / scenarios_total as f64,
        )
    };
    let average_findings_per_target = {
        let sum = scenarios
            .iter()
            .map(|item| item.average_findings_per_target)
            .sum::<f64>();
        if scenarios_total == 0 {
            0.0
        } else {
            round_ratio(sum / scenarios_total as f64)
        }
    };
    let average_finding_families_per_target = {
        let sum = scenarios
            .iter()
            .map(|item| item.average_finding_families_per_target)
            .sum::<f64>();
        if scenarios_total == 0 {
            0.0
        } else {
            round_ratio(sum / scenarios_total as f64)
        }
    };
    let max_findings_per_target = scenarios
        .iter()
        .map(|item| item.max_findings_per_target)
        .max()
        .unwrap_or(0);
    let max_finding_families_per_target = scenarios
        .iter()
        .map(|item| item.max_finding_families_per_target)
        .max()
        .unwrap_or(0);
    let max_core_families_per_target = scenarios
        .iter()
        .map(|item| item.max_core_families_per_target)
        .max()
        .unwrap_or(0);

    let top_false_positive_types = top_counts(
        scenarios
            .iter()
            .flat_map(|item| item.false_positive_core_types.iter().cloned())
            .collect(),
    );
    let top_false_negative_types = top_counts(
        scenarios
            .iter()
            .flat_map(|item| item.false_negative_core_types.iter().cloned())
            .collect(),
    );

    let mut worst_scenarios = scenarios.clone();
    worst_scenarios.sort_by(|left, right| {
        right
            .false_negative_core_types
            .len()
            .cmp(&left.false_negative_core_types.len())
            .then(
                right
                    .false_positive_core_types
                    .len()
                    .cmp(&left.false_positive_core_types.len()),
            )
            .then(
                left.check_pass_ratio
                    .partial_cmp(&right.check_pass_ratio)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    worst_scenarios.truncate(12);

    let core_precision = ratio(
        core_true_positive_total,
        core_true_positive_total + core_false_positive_total,
    );
    let core_recall = ratio(
        core_true_positive_total,
        core_true_positive_total + core_false_negative_total,
    );
    let core_f1 = if core_precision + core_recall == 0.0 {
        0.0
    } else {
        round_ratio((2.0 * core_precision * core_recall) / (core_precision + core_recall))
    };
    let mas_parallelism_ratio_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.mas_parallelism_ratio)
            .collect(),
        scenarios_total,
    );
    let mas_queue_wait_ms_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.mas_queue_wait_ms_avg)
            .collect(),
        scenarios_total,
    );
    let mas_agent_sla_ratio_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.mas_agent_sla_ratio)
            .collect(),
        scenarios_total,
    );
    let mas_consensus_score_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.mas_consensus_score)
            .collect(),
        scenarios_total,
    );
    let mas_progress_score_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.mas_progress_score)
            .collect(),
        scenarios_total,
    );
    let forensic_depth_score_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.forensic_depth_score)
            .collect(),
        scenarios_total,
    );
    let fusion_coverage_ratio_avg = average_metric(
        scenarios
            .iter()
            .map(|item| item.fusion_coverage_ratio)
            .collect(),
        scenarios_total,
    );

    let summary = EvaluationSummary {
        scenarios_total,
        scenarios_passed,
        scenarios_failed: scenarios_total.saturating_sub(scenarios_passed),
        runtime_seconds_total,
        scenario_duration_seconds_avg,
        scenario_duration_seconds_p95,
        checks_total,
        checks_passed,
        check_pass_ratio: ratio(checks_passed, checks_total),
        core_expected_total,
        core_predicted_total,
        core_true_positive_total,
        core_false_positive_total,
        core_false_negative_total,
        core_precision,
        core_recall,
        core_f1,
        mas_parallelism_ratio_avg,
        mas_queue_wait_ms_avg,
        mas_agent_sla_ratio_avg,
        mas_consensus_score_avg,
        mas_progress_score_avg,
        forensic_depth_score_avg,
        fusion_coverage_ratio_avg,
        average_findings_per_scenario,
        average_findings_per_target,
        average_finding_families_per_target,
        max_findings_per_target,
        max_finding_families_per_target,
        max_core_families_per_target,
        top_false_positive_types,
        top_false_negative_types,
        worst_scenarios,
        improvement_hypotheses: build_improvement_hypotheses(
            core_false_positive_total,
            core_false_negative_total,
            average_finding_families_per_target,
            max_finding_families_per_target,
            max_core_families_per_target,
            mas_progress_score_avg,
            mas_agent_sla_ratio_avg,
            mas_parallelism_ratio_avg,
            forensic_depth_score_avg,
            fusion_coverage_ratio_avg,
        ),
    };

    EvaluationReport {
        generated_at: Utc::now(),
        seed,
        random_pairs,
        workers,
        provider: provider.to_string(),
        tracked_core_types: tracked_core_types.into_iter().collect(),
        summary,
        scenarios,
    }
}

pub fn save_evaluation_report(workspace_root: &Path, report: &EvaluationReport) -> Result<PathBuf> {
    let directory = workspace_root.join("evaluation");
    fs::create_dir_all(&directory)?;
    let latest = directory.join("latest.json");
    fs::write(
        &latest,
        serde_json::to_vec_pretty(report).map_err(BakulaError::Json)?,
    )?;
    fs::write(directory.join("latest.md"), render_markdown(report))?;
    Ok(latest)
}

fn render_markdown(report: &EvaluationReport) -> String {
    let summary = &report.summary;
    let worst = report
        .summary
        .worst_scenarios
        .iter()
        .map(|item| {
            format!(
                "- `{}`: checks {:.0}% | FN {} | FP {} | findings {}",
                item.scenario_key,
                item.check_pass_ratio * 100.0,
                item.false_negative_core_types.len(),
                item.false_positive_core_types.len(),
                item.findings_total
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        concat!(
            "# Eval Bakula\n\n",
            "- generated_at: `{}`\n",
            "- provider: `{}`\n",
            "- random_pairs: `{}`\n",
            "- workers: `{}`\n\n",
            "## Souhrn\n\n",
            "- scénáře: `{}` / prošlo `{}`\n",
            "- runtime celkem: `{:.2}` s\n",
            "- průměr na scénář: `{:.2}` s\n",
            "- p95 scénáře: `{:.2}` s\n",
            "- check pass ratio: `{:.2}`\n",
            "- core precision: `{:.2}`\n",
            "- core recall: `{:.2}`\n",
            "- core f1: `{:.2}`\n",
            "- MAS parallelism avg: `{:.2}`\n",
            "- MAS queue wait avg: `{:.2}` ms\n",
            "- MAS SLA avg: `{:.2}`\n",
            "- MAS consensus avg: `{:.2}`\n",
            "- MAS progress avg: `{:.2}`\n",
            "- forensic depth avg: `{:.2}`\n",
            "- fusion coverage avg: `{:.2}`\n",
            "- average findings / scenario: `{:.2}`\n",
            "- average findings / target: `{:.2}`\n",
            "- average finding families / target: `{:.2}`\n",
            "- max findings / target: `{}`\n",
            "- max finding families / target: `{}`\n",
            "- max core families / target: `{}`\n\n",
            "## Nejhorší scénáře\n\n",
            "{}\n\n",
            "## Doporučení\n\n",
            "{}\n"
        ),
        report.generated_at.to_rfc3339(),
        report.provider,
        report.random_pairs,
        report.workers,
        summary.scenarios_total,
        summary.scenarios_passed,
        summary.runtime_seconds_total,
        summary.scenario_duration_seconds_avg,
        summary.scenario_duration_seconds_p95,
        summary.check_pass_ratio,
        summary.core_precision,
        summary.core_recall,
        summary.core_f1,
        summary.mas_parallelism_ratio_avg,
        summary.mas_queue_wait_ms_avg,
        summary.mas_agent_sla_ratio_avg,
        summary.mas_consensus_score_avg,
        summary.mas_progress_score_avg,
        summary.forensic_depth_score_avg,
        summary.fusion_coverage_ratio_avg,
        summary.average_findings_per_scenario,
        summary.average_findings_per_target,
        summary.average_finding_families_per_target,
        summary.max_findings_per_target,
        summary.max_finding_families_per_target,
        summary.max_core_families_per_target,
        if worst.is_empty() {
            "- bez odchylek".to_string()
        } else {
            worst
        },
        report
            .summary
            .improvement_hypotheses
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn build_improvement_hypotheses(
    false_positives: usize,
    false_negatives: usize,
    average_finding_families_per_target: f64,
    max_finding_families_per_target: usize,
    max_core_families_per_target: usize,
    mas_progress_score_avg: f64,
    mas_agent_sla_ratio_avg: f64,
    mas_parallelism_ratio_avg: f64,
    forensic_depth_score_avg: f64,
    fusion_coverage_ratio_avg: f64,
) -> Vec<String> {
    let mut notes = Vec::new();
    if false_negatives > 0 {
        notes.push(
            "Doplnit silnější mapování služby -> CPE/CVE a přesnější korelaci pasivních událostí, protože část očekávaných core nálezů chybí.".to_string(),
        );
    }
    if false_positives > 0 {
        notes.push(
            "Zpřísnit pravidla pro generické findingy a potlačit slabší obecný finding ve chvíli, kdy už existuje silnější specifický důkaz.".to_string(),
        );
    }
    if average_finding_families_per_target > 2.0 || max_finding_families_per_target > 4 {
        notes.push(
            "Na části cílů se hromadí více finding rodin najednou; vyplatí se zavést merge nebo dominance pravidla pro překryvné nálezy stejné příčiny."
                .to_string(),
        );
    }
    if max_core_families_per_target > 3 {
        notes.push(
            "Omezit šířku findingů na cíl: jeden target by neměl bez silného důvodu dostávat příliš mnoho různých core rodin nálezů najednou.".to_string(),
        );
    }
    if mas_progress_score_avg < 0.7 || mas_agent_sla_ratio_avg < 0.75 {
        notes.push(
            "MAS orchestrace má rezervu ve stabilitě kroku/progressu; doporučeno zvýšit budget scheduleru a oddělit pomalé ingest lane od rychlých agentů.".to_string(),
        );
    }
    if mas_parallelism_ratio_avg < 0.45 {
        notes.push(
            "Paralelizace běhu je nízká vůči dostupným workerům. Pomůže jemnější dělení práce (context shards, passive shards) a menší batch jednotky.".to_string(),
        );
    }
    if forensic_depth_score_avg < 0.55 {
        notes.push(
            "Forenzní hloubka je nižší než očekávaná; zpřesni heuristiku výběru forenzních cílů podle rizika a přidej více follow-up datových důkazů.".to_string(),
        );
    }
    if fusion_coverage_ratio_avg < 0.6 {
        notes.push(
            "Data fusion coverage je omezená; rozšiř autorizované snapshot zdroje a zvyš vazbu assetů na host/service klíče pro lepší korelaci.".to_string(),
        );
    }
    if notes.is_empty() {
        notes.push(
            "Na testovaných scénářích je jádro stabilní; další zlepšení dává smysl hlavně ve větší šíři scénářů a richer live telemetry."
                .to_string(),
        );
    }
    notes
}

fn top_counts(items: Vec<String>) -> Vec<EvaluationCount> {
    let mut counts = BTreeMap::<String, usize>::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut rows = counts
        .into_iter()
        .map(|(name, count)| EvaluationCount { name, count })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then(left.name.cmp(&right.name))
    });
    rows.truncate(8);
    rows
}

fn average_metric(values: Vec<f64>, count: usize) -> f64 {
    if count == 0 {
        return 0.0;
    }
    round_ratio(values.into_iter().sum::<f64>() / count as f64)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        round_ratio(numerator as f64 / denominator as f64)
    }
}

fn round_ratio(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn percentile(mut values: Vec<f64>, pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((values.len() - 1) as f64 * pct.clamp(0.0, 1.0)).round() as usize;
    round_ratio(values[index])
}
