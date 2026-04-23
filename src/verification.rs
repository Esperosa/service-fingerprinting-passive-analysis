use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    error::{BakulaError, Result},
    model::RunReport,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioManifest {
    pub nazev: String,
    pub popis: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub provider: Option<String>,
    pub scope: Vec<IpNet>,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub compare_to: Option<String>,
    #[serde(default)]
    pub expectations: ScenarioExpectations,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScenarioExpectations {
    #[serde(default)]
    pub min_hosts: usize,
    #[serde(default)]
    pub min_services: usize,
    #[serde(default)]
    pub min_cves: usize,
    #[serde(default)]
    pub min_events: usize,
    #[serde(default)]
    pub min_findings: usize,
    #[serde(default)]
    pub min_high_priority_services: usize,
    #[serde(default)]
    pub required_event_types: Vec<String>,
    #[serde(default)]
    pub required_finding_types: Vec<String>,
    #[serde(default)]
    pub required_service_keys: Vec<String>,
    #[serde(default)]
    pub expected_new_hosts: Vec<String>,
    #[serde(default)]
    pub expected_changed_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub generated_at: DateTime<Utc>,
    pub provider: String,
    pub summary: VerificationSummary,
    pub scenarios: Vec<ScenarioVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioVerification {
    pub scenario_key: String,
    pub scenario_name: String,
    pub run_id: String,
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub expected: String,
    pub actual: String,
}

pub fn discover_scenarios(root: &Path) -> Result<Vec<PathBuf>> {
    let mut scenarios = fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .map(|entry| entry.path())
        .filter(|path| path.join("manifest.json").exists())
        .collect::<Vec<_>>();
    scenarios.sort();
    Ok(scenarios)
}

pub fn load_manifest(path: &Path) -> Result<ScenarioManifest> {
    let content = fs::read(path)?;
    serde_json::from_slice(&content)
        .map_err(|error| BakulaError::Processing(format!("Nelze nacist manifest scenare: {error}")))
}

pub fn validate_scenario(
    scenario_key: &str,
    manifest: &ScenarioManifest,
    report: &RunReport,
    base_report: Option<&RunReport>,
) -> ScenarioVerification {
    let mut checks = vec![
        check_minimum(
            "minimum_hosts",
            manifest.expectations.min_hosts,
            report.summary.hosts_total,
        ),
        check_minimum(
            "minimum_services",
            manifest.expectations.min_services,
            report.summary.services_total,
        ),
        check_minimum(
            "minimum_cves",
            manifest.expectations.min_cves,
            report.summary.cves_total,
        ),
        check_minimum(
            "minimum_events",
            manifest.expectations.min_events,
            report.summary.events_total,
        ),
        check_minimum(
            "minimum_findings",
            manifest.expectations.min_findings,
            report.summary.findings_total,
        ),
        check_minimum(
            "minimum_high_priority_services",
            manifest.expectations.min_high_priority_services,
            report.summary.services_high_priority,
        ),
    ];

    let present_event_types = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .flat_map(|service| service.events.iter())
        .map(|item| item.event.event_type.clone())
        .collect::<BTreeSet<_>>();
    for required in &manifest.expectations.required_event_types {
        checks.push(check_presence(
            "required_event_type",
            required,
            &present_event_types,
        ));
    }

    let present_finding_types = report
        .findings
        .iter()
        .map(|item| item.finding_type.clone())
        .collect::<BTreeSet<_>>();
    for required in &manifest.expectations.required_finding_types {
        checks.push(check_presence(
            "required_finding_type",
            required,
            &present_finding_types,
        ));
    }

    let present_service_keys = report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .map(|service| service.service_key.clone())
        .collect::<BTreeSet<_>>();
    for required in &manifest.expectations.required_service_keys {
        checks.push(check_presence(
            "required_service_key",
            required,
            &present_service_keys,
        ));
    }

    if manifest.compare_to.is_some() {
        checks.push(CheckResult {
            name: "diff_present".to_string(),
            passed: report.diff.is_some() && base_report.is_some(),
            expected: "report obsahuje diff proti referenčnímu scénáři".to_string(),
            actual: if report.diff.is_some() && base_report.is_some() {
                "diff je k dispozici".to_string()
            } else {
                "diff chybí".to_string()
            },
        });
    }

    let diff = report.diff.as_ref();
    for expected_host in &manifest.expectations.expected_new_hosts {
        let present = diff
            .map(|item| item.new_hosts.iter().any(|value| value == expected_host))
            .unwrap_or(false);
        checks.push(CheckResult {
            name: "expected_new_host".to_string(),
            passed: present,
            expected: expected_host.clone(),
            actual: diff
                .map(|item| item.new_hosts.join(", "))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "bez diffu".to_string()),
        });
    }

    for expected_service in &manifest.expectations.expected_changed_services {
        let present = diff
            .map(|item| {
                item.changed_services
                    .iter()
                    .any(|value| &value.service_key == expected_service)
            })
            .unwrap_or(false);
        checks.push(CheckResult {
            name: "expected_changed_service".to_string(),
            passed: present,
            expected: expected_service.clone(),
            actual: diff
                .map(|item| {
                    item.changed_services
                        .iter()
                        .map(|value| value.service_key.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "bez diffu".to_string()),
        });
    }

    let passed = checks.iter().all(|item| item.passed);
    ScenarioVerification {
        scenario_key: scenario_key.to_string(),
        scenario_name: manifest.nazev.clone(),
        run_id: report.run.run_id.clone(),
        passed,
        checks,
    }
}

pub fn build_verification_report(
    provider: &str,
    scenarios: Vec<ScenarioVerification>,
) -> VerificationReport {
    let total = scenarios.len();
    let passed = scenarios.iter().filter(|item| item.passed).count();
    VerificationReport {
        generated_at: Utc::now(),
        provider: provider.to_string(),
        summary: VerificationSummary {
            total,
            passed,
            failed: total.saturating_sub(passed),
        },
        scenarios,
    }
}

pub fn save_verification_report(
    workspace_root: &Path,
    report: &VerificationReport,
) -> Result<PathBuf> {
    let verification_dir = workspace_root.join("verification");
    fs::create_dir_all(&verification_dir)?;
    let path = verification_dir.join("latest.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).map_err(BakulaError::Json)?,
    )?;
    Ok(path)
}

pub fn load_latest_verification_report(
    workspace_root: &Path,
) -> Result<Option<VerificationReport>> {
    let path = workspace_root.join("verification").join("latest.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let report = serde_json::from_slice(&bytes).map_err(BakulaError::Json)?;
    Ok(Some(report))
}

fn check_minimum(name: &str, expected: usize, actual: usize) -> CheckResult {
    CheckResult {
        name: name.to_string(),
        passed: actual >= expected,
        expected: format!(">= {expected}"),
        actual: actual.to_string(),
    }
}

fn check_presence(name: &str, expected: &str, values: &BTreeSet<String>) -> CheckResult {
    CheckResult {
        name: name.to_string(),
        passed: values.contains(expected),
        expected: expected.to_string(),
        actual: values.iter().cloned().collect::<Vec<_>>().join(", "),
    }
}

fn default_ports() -> Vec<u16> {
    vec![21, 22, 23, 80, 443, 8080]
}

fn default_profile() -> String {
    "overeni".to_string()
}
