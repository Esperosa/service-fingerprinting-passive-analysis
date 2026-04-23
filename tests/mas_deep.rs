use std::{fs, path::Path, process::Command};

use serde_json::Value;
use tempfile::TempDir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

fn scenario_dir_count(root: &Path) -> usize {
    fs::read_dir(root)
        .expect("scenario dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter(|entry| entry.path().join("manifest.json").exists())
        .count()
}

fn latest_report_json(workspace: &Path) -> Value {
    let mut run_dirs = fs::read_dir(workspace.join("runs"))
        .expect("runs dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .collect::<Vec<_>>();
    run_dirs.sort_by_key(|entry| entry.file_name());
    let latest = run_dirs.last().expect("at least one run").path();
    serde_json::from_slice(&fs::read(latest.join("report.json")).expect("report json"))
        .expect("report value")
}

#[test]
fn generator_large_profile_creates_hundreds_of_scenarios() {
    let temp = TempDir::new().expect("tempdir");
    let scenarios = temp.path().join("simulace-large");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "2026",
            "--nahodnych",
            "60",
            "--profil",
            "enterprise",
        ])
        .status()
        .expect("generate large simulation");
    assert!(status.success());

    let total = scenario_dir_count(&scenarios);
    assert_eq!(total, 122, "2 fixed + 2*60 random scenarios expected");

    let manifest: Value = serde_json::from_slice(
        &fs::read(scenarios.join("nahodny-001-zaklad").join("manifest.json"))
            .expect("manifest read"),
    )
    .expect("manifest json");
    assert!(
        manifest["expectations"]["min_hosts"]
            .as_u64()
            .unwrap_or_default()
            >= 40
    );
    assert!(
        manifest["expectations"]["min_events"]
            .as_u64()
            .unwrap_or_default()
            >= 60
    );
}

#[test]
fn evaluation_large_profile_tracks_mas_metrics() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");

    let status = Command::new(bin_path())
        .args([
            "evaluace",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--seed",
            "404",
            "--nahodnych",
            "12",
            "--workers",
            "6",
            "--provider",
            "demo",
            "--profil",
            "large",
        ])
        .status()
        .expect("run evaluation");
    assert!(status.success());

    let evaluation: Value = serde_json::from_slice(
        &fs::read(workspace.join("evaluation").join("latest.json")).expect("evaluation read"),
    )
    .expect("evaluation json");

    assert_eq!(evaluation["summary"]["scenarios_failed"], 0);
    assert_eq!(evaluation["summary"]["scenarios_total"], 26);
    assert!(
        evaluation["summary"]["mas_progress_score_avg"]
            .as_f64()
            .unwrap_or_default()
            > 0.2
    );
    assert!(
        evaluation["summary"]["mas_agent_sla_ratio_avg"]
            .as_f64()
            .unwrap_or_default()
            > 0.2
    );
    assert!(
        evaluation["summary"]["forensic_depth_score_avg"]
            .as_f64()
            .unwrap_or_default()
            >= 0.0
    );
    assert!(
        evaluation["summary"]["fusion_coverage_ratio_avg"]
            .as_f64()
            .unwrap_or_default()
            > 0.1
    );
}

#[test]
fn enterprise_run_emits_timeout_overload_and_inductive_findings() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace-realism");
    let scenarios = temp.path().join("simulace-realism");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "5150",
            "--nahodnych",
            "1",
            "--profil",
            "enterprise",
        ])
        .status()
        .expect("generate enterprise simulation");
    assert!(status.success());

    let scenario_dir = scenarios.join("nahodny-001-zmena");
    let status = Command::new(bin_path())
        .args([
            "beh",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Realism constraints",
            "--scope",
            "10.22.91.0/24",
            "--nmap-xml",
            scenario_dir.join("nmap.xml").to_str().expect("nmap"),
            "--suricata-eve",
            scenario_dir
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve"),
            "--zeek-dir",
            scenario_dir.join("zeek").to_str().expect("zeek"),
            "--provider",
            "demo",
            "--disable-circl",
        ])
        .status()
        .expect("run constraints scenario");
    assert!(status.success());

    let report = latest_report_json(&workspace);
    let findings = report["findings"].as_array().expect("findings array");

    assert!(
        findings
            .iter()
            .any(|item| item["finding_type"] == "connection_timeout_burst"),
        "timeout bursts should be surfaced"
    );
    assert!(
        findings
            .iter()
            .any(|item| item["finding_type"] == "packet_rate_spike"),
        "packet-rate spikes should be surfaced"
    );
    assert!(
        findings
            .iter()
            .any(|item| item["finding_type"] == "service_overload_risk"),
        "overload risk should be surfaced"
    );
    assert!(
        findings
            .iter()
            .any(|item| item["finding_type"] == "inductive_volume_anomaly"),
        "inductive non-template anomaly should be surfaced"
    );
}

#[test]
#[ignore = "heavy stress test with >120 scenarios"]
fn evaluation_enterprise_profile_stress_122_scenarios() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace-stress");

    let status = Command::new(bin_path())
        .args([
            "evaluace",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--seed",
            "909",
            "--nahodnych",
            "60",
            "--workers",
            "8",
            "--provider",
            "demo",
            "--profil",
            "enterprise",
        ])
        .status()
        .expect("run heavy evaluation");
    assert!(status.success());

    let evaluation: Value = serde_json::from_slice(
        &fs::read(workspace.join("evaluation").join("latest.json")).expect("evaluation read"),
    )
    .expect("evaluation json");

    assert_eq!(evaluation["summary"]["scenarios_total"], 122);
    assert!(
        evaluation["summary"]["check_pass_ratio"]
            .as_f64()
            .unwrap_or_default()
            >= 0.95
    );
}
