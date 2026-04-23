use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::Value;
use tempfile::TempDir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

#[test]
fn demo_e2e_vytvori_reporty_a_diff() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");

    let status = Command::new(bin_path())
        .args(["demo", "e2e", "--workspace"])
        .arg(&workspace)
        .status()
        .expect("spusteni demo prikazu");
    assert!(status.success(), "demo e2e musi probehnout uspesne");

    let reports = load_reports(&workspace);
    assert_eq!(reports.len(), 2, "musi vzniknout dva reporty");
    let run_dirs = fs::read_dir(workspace.join("runs"))
        .expect("runs dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .collect::<Vec<_>>();
    assert!(
        run_dirs
            .iter()
            .all(|entry| entry.path().join("report.md").exists()),
        "u kazdeho behu musi existovat markdown export"
    );
    assert!(
        run_dirs
            .iter()
            .all(|entry| entry.path().join("report.txt").exists()),
        "u kazdeho behu musi existovat textovy export"
    );
    assert!(
        run_dirs
            .iter()
            .all(|entry| entry.path().join("manifest.json").exists()),
        "u kazdeho behu musi existovat ulozny manifest"
    );
    for entry in &run_dirs {
        let md = fs::read_to_string(entry.path().join("report.md")).expect("markdown export");
        let txt = fs::read_to_string(entry.path().join("report.txt")).expect("text export");
        assert!(
            md.contains("## Nálezy")
                && md.contains("## Doporučené kroky")
                && md.contains("## Rozhodovací a monitorovací vrstvy")
                && md.contains("Doporučení")
                && md.contains("Evidence"),
            "markdown export musi obsahovat citelne nalezy, doporuceni, rozhodovaci vrstvy a dukazy"
        );
        assert!(
            txt.contains("NÁLEZY")
                && txt.contains("DOPORUČENÉ KROKY")
                && txt.contains("ROZHODOVACÍ A MONITOROVACÍ VRSTVY")
                && txt.contains("Doporučení"),
            "textovy export musi obsahovat citelne nalezy, doporuceni a rozhodovaci vrstvy"
        );
    }

    let baseline = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Zakladni scenar")
        .expect("zakladni report");
    let changed = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Zmenovy scenar")
        .expect("zmenovy report");

    assert!(
        baseline["summary"]["events_total"]
            .as_u64()
            .unwrap_or_default()
            >= 4
    );
    assert!(
        changed["summary"]["events_total"]
            .as_u64()
            .unwrap_or_default()
            >= 3
    );
    assert_eq!(changed["diff"]["new_hosts"][0], "192.168.56.40");
    assert!(
        changed["diff"]["changed_services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["service_key"] == "192.168.56.10/tcp/8080")
    );
    assert!(
        baseline["findings"].as_array().unwrap().len() >= 3,
        "zakladni report musi obsahovat samostatne nalezy"
    );
    assert!(
        changed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["finding_type"] == "new_exposed_service")
    );
    let changed_lanes = changed["monitoringLanes"]
        .as_array()
        .expect("monitoring lanes");
    assert!(
        changed_lanes
            .iter()
            .any(|item| item["source"] == "decision-risk-ranking"),
        "report musi obsahovat rozhodovaci risk ranking"
    );
    assert!(
        changed_lanes
            .iter()
            .any(|item| item["source"] == "decision-inference-graph"),
        "report musi obsahovat deduktivni a induktivni inference graph"
    );
    assert!(
        changed_lanes
            .iter()
            .any(|item| item["source"] == "agent-lifecycle"),
        "report musi obsahovat agent lifecycle rozhodnuti"
    );
    assert!(
        changed_lanes.iter().any(|item| item["source"]
            .as_str()
            .unwrap_or_default()
            .starts_with("agent:")),
        "report musi obsahovat dynamicke agentni lane"
    );
    let changed_actions = changed["triageActions"].as_array().expect("triage actions");
    assert!(
        changed_actions.iter().any(|item| item["action_type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("spawn-agent:")),
        "triage musi obsahovat agentni spawn krok"
    );
    assert!(
        changed["summary"]["automation_agents_total"]
            .as_u64()
            .unwrap_or_default()
            >= 14,
        "souhrn musi drzet MAS agentni metriku"
    );
}

#[test]
fn autopilot_vytvori_vice_cyklu_a_automation_report() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let status = Command::new(bin_path())
        .args([
            "autopilot",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Autopilot test",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap"),
            "--suricata-eve",
            scenarios
                .join("zakladni")
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve"),
            "--zeek-dir",
            scenarios
                .join("zakladni")
                .join("zeek")
                .to_str()
                .expect("zeek"),
            "--provider",
            "demo",
            "--cycles",
            "2",
        ])
        .status()
        .expect("spusteni autopilota");
    assert!(status.success());

    let automation_path = workspace.join("automation").join("latest.json");
    let automation: Value =
        serde_json::from_slice(&fs::read(&automation_path).expect("nacteni automation reportu"))
            .expect("automation json");
    assert_eq!(automation["summary"]["cycles_total"], 2);
    assert!(
        automation["summary"]["tooling_coverage_ratio"]
            .as_f64()
            .unwrap_or_default()
            >= 0.5
    );
    assert_eq!(load_reports(&workspace).len(), 2);
}

#[test]
fn monitor_spust_opakovane_behy_s_diffem() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let status = Command::new(bin_path())
        .args([
            "monitor",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Monitor test",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap"),
            "--suricata-eve",
            scenarios
                .join("zakladni")
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve"),
            "--zeek-dir",
            scenarios
                .join("zakladni")
                .join("zeek")
                .to_str()
                .expect("zeek"),
            "--provider",
            "demo",
            "--cycles",
            "2",
            "--interval-s",
            "0",
        ])
        .status()
        .expect("spusteni monitoru");
    assert!(status.success(), "monitor musi probehnout uspesne");

    let reports = load_reports(&workspace);
    assert_eq!(reports.len(), 2);
    let first = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Monitor test / monitor 1")
        .expect("prvni monitor report");
    let second = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Monitor test / monitor 2")
        .expect("druhy monitor report");

    assert!(first["diff"].is_null());
    assert!(second["diff"]["base_run_id"].as_str().is_some());
    assert!(
        second["summary"]["events_total"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );
}

#[test]
fn production_beh_vyzaduje_pasivni_telemetrii() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let output = Command::new(bin_path())
        .args([
            "beh",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Production without passive",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap"),
            "--production",
        ])
        .output()
        .expect("spusteni produkcniho behu");

    assert!(
        !output.status.success(),
        "produkcni beh bez pasivni casti musi skoncit chybou"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pasiv"),
        "chyba ma vysvetlit chybejici pasivni zdroj"
    );
}

#[test]
fn server_vraci_api_a_ui() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");

    let status = Command::new(bin_path())
        .args(["demo", "e2e", "--workspace"])
        .arg(&workspace)
        .status()
        .expect("spusteni demo prikazu");
    assert!(status.success());

    let port = free_port();
    let mut child = spawn_server(&workspace, port);

    wait_for_server(port);

    let health: Value = reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/health"))
        .expect("health request")
        .json()
        .expect("health json");
    assert_eq!(health["stav"], "ok");

    let meta: Value = reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/meta"))
        .expect("meta request")
        .json()
        .expect("meta json");
    assert_eq!(meta["service"], "bakula-program");
    assert_eq!(meta["auth_required"], false);

    let ready: Value = reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/ready"))
        .expect("ready request")
        .json()
        .expect("ready json");
    assert_eq!(ready["stav"], "ready");
    assert_eq!(ready["runs_total"], 2);

    let runs: Value = reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/runs"))
        .expect("runs request")
        .json()
        .expect("runs json");
    assert_eq!(runs.as_array().unwrap().len(), 2);

    let html = reqwest::blocking::get(format!("http://127.0.0.1:{port}/"))
        .expect("ui request")
        .text()
        .expect("ui text");
    assert!(html.contains("Bezpecnostni prehled site"));
    assert!(html.contains("id=\"app\""));
    assert!(html.contains("/styles.css?v="));
    assert!(html.contains("/app.js?v="));

    let first_id = runs[0]["run_id"].as_str().expect("run_id");
    let report: Value =
        reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/runs/{first_id}"))
            .expect("report request")
            .json()
            .expect("report json");
    assert!(report["hosts"].as_array().unwrap().len() >= 3);
    assert!(report["findings"].as_array().unwrap().len() >= 3);

    let verification: Value =
        reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/verification/latest"))
            .expect("verification request")
            .json()
            .expect("verification json");
    assert!(verification.is_null());

    let metrics = reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/metrics"))
        .expect("metrics request")
        .text()
        .expect("metrics text");
    assert!(metrics.contains("bakula_runs_total 2"));
    assert!(metrics.contains("bakula_latest_hosts_total"));

    child.kill().expect("ukonceni serveru");
    child.wait().expect("wait");
}

#[test]
fn server_respektuje_api_token() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");

    let status = Command::new(bin_path())
        .args(["demo", "e2e", "--workspace"])
        .arg(&workspace)
        .status()
        .expect("spusteni demo prikazu");
    assert!(status.success());

    let port = free_port();
    let mut child = spawn_server_with_options(
        &workspace,
        port,
        &[
            "--require-api-token",
            "--api-token-env",
            "BAKULA_TEST_API_TOKEN",
        ],
        &[("BAKULA_TEST_API_TOKEN", "tajny-token")],
    );

    wait_for_server(port);

    let client = reqwest::blocking::Client::new();
    let read_only = client
        .get(format!("http://127.0.0.1:{port}/api/runs"))
        .send()
        .expect("read-only request");
    assert_eq!(read_only.status(), 200);

    let unauthorized_write = client
        .post(format!("http://127.0.0.1:{port}/api/automation/reset"))
        .send()
        .expect("unauthorized write request");
    assert_eq!(unauthorized_write.status(), 401);

    let authorized_read = client
        .get(format!("http://127.0.0.1:{port}/api/runs"))
        .header("Authorization", "Bearer tajny-token")
        .send()
        .expect("authorized read request");
    assert_eq!(authorized_read.status(), 200);

    let authorized_write = client
        .post(format!("http://127.0.0.1:{port}/api/automation/reset"))
        .header("Authorization", "Bearer tajny-token")
        .send()
        .expect("authorized write request");
    assert_eq!(authorized_write.status(), 200);

    child.kill().expect("ukonceni serveru");
    child.wait().expect("wait");
}

#[test]
fn random_generator_and_verification_report() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "123",
            "--nahodnych",
            "2",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success(), "simulace musi probehnout uspesne");

    let status = Command::new(bin_path())
        .args([
            "overeni",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--scenare",
            scenarios.to_str().expect("scenarios"),
            "--provider",
            "demo",
        ])
        .status()
        .expect("overeni scenaru");
    assert!(status.success(), "overeni musi probehnout uspesne");

    let verification_path = workspace.join("verification").join("latest.json");
    let verification: Value = serde_json::from_slice(
        &fs::read(&verification_path).expect("nacteni verification reportu"),
    )
    .expect("json verification");

    assert_eq!(verification["summary"]["failed"], 0);
    assert_eq!(verification["summary"]["total"], 6);
    assert!(
        verification["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["passed"] == true)
    );
}

#[test]
fn run_with_authorized_snapshots_enriches_assets_and_triage() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let snmp_snapshot = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("snmp_demo_snapshot.json");
    let meraki_snapshot = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("meraki_demo_snapshot.json");

    let status = Command::new(bin_path())
        .args([
            "beh",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Snapshot enriched run",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap xml"),
            "--suricata-eve",
            scenarios
                .join("zakladni")
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve json"),
            "--zeek-dir",
            scenarios
                .join("zakladni")
                .join("zeek")
                .to_str()
                .expect("zeek"),
            "--provider",
            "demo",
            "--disable-circl",
            "--snmp-snapshot",
            snmp_snapshot.to_str().expect("snmp snapshot"),
            "--meraki-snapshot",
            meraki_snapshot.to_str().expect("meraki snapshot"),
        ])
        .status()
        .expect("spusteni behu");
    assert!(status.success(), "běh se snapshoty musí proběhnout");

    let reports = load_reports(&workspace);
    let report = reports.first().expect("report");
    assert!(
        report["networkAssets"].as_array().unwrap().len() >= 4,
        "report má obsahovat autorizované assety"
    );
    assert!(
        report["topologyEdges"].as_array().unwrap().len() >= 2,
        "report má obsahovat topologické vazby"
    );
    assert!(
        report["triageActions"].as_array().unwrap().len() >= 1,
        "report má obsahovat triage doporučení"
    );
}

#[test]
fn full_visibility_stack_populates_lanes_and_findings() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data");

    let status = Command::new(bin_path())
        .args([
            "beh",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Full visibility stack",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap xml"),
            "--suricata-eve",
            scenarios
                .join("zakladni")
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve json"),
            "--zeek-dir",
            scenarios
                .join("zakladni")
                .join("zeek")
                .to_str()
                .expect("zeek"),
            "--provider",
            "demo",
            "--disable-circl",
            "--snmp-snapshot",
            data_dir
                .join("snmp_demo_snapshot.json")
                .to_str()
                .expect("snmp"),
            "--librenms-snapshot",
            data_dir
                .join("librenms_demo_snapshot.json")
                .to_str()
                .expect("librenms"),
            "--meraki-snapshot",
            data_dir
                .join("meraki_demo_snapshot.json")
                .to_str()
                .expect("meraki"),
            "--unifi-snapshot",
            data_dir
                .join("unifi_demo_snapshot.json")
                .to_str()
                .expect("unifi"),
            "--aruba-snapshot",
            data_dir
                .join("aruba_demo_snapshot.json")
                .to_str()
                .expect("aruba"),
            "--omada-snapshot",
            data_dir
                .join("omada_demo_snapshot.json")
                .to_str()
                .expect("omada"),
            "--ntopng-snapshot",
            data_dir
                .join("ntopng_demo_snapshot.json")
                .to_str()
                .expect("ntopng"),
            "--flow-snapshot",
            data_dir
                .join("flow_demo_snapshot.json")
                .to_str()
                .expect("flow"),
            "--greenbone-report",
            data_dir
                .join("greenbone_demo_report.json")
                .to_str()
                .expect("greenbone"),
            "--wazuh-report",
            data_dir
                .join("wazuh_demo_report.json")
                .to_str()
                .expect("wazuh"),
            "--napalm-snapshot",
            data_dir
                .join("napalm_demo_snapshot.json")
                .to_str()
                .expect("napalm"),
            "--netmiko-snapshot",
            data_dir
                .join("netmiko_demo_snapshot.json")
                .to_str()
                .expect("netmiko"),
            "--scrapli-snapshot",
            data_dir
                .join("scrapli_demo_snapshot.json")
                .to_str()
                .expect("scrapli"),
        ])
        .status()
        .expect("spusteni plneho behu");
    assert!(status.success(), "plny beh musi probehnout");

    let report = load_reports(&workspace).pop().expect("report");
    assert!(report["monitoringLanes"].as_array().unwrap().len() >= 6);
    assert!(report["networkAssets"].as_array().unwrap().len() >= 10);
    assert!(report["topologyEdges"].as_array().unwrap().len() >= 8);
    assert!(
        report["summary"]["live_lanes_total"]
            .as_u64()
            .unwrap_or_default()
            >= 2
    );
    assert!(
        report["summary"]["audit_lanes_total"]
            .as_u64()
            .unwrap_or_default()
            >= 4
    );
    assert!(report["findings"].as_array().unwrap().len() >= 8);
}

#[test]
fn hard_pentest_rezim_najde_vic_duvodu_na_realisticke_lokalni_sluzbe() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let lab = HttpPentestLab::start();
    let nmap_xml = temp.path().join("lab-nmap.xml");
    fs::write(&nmap_xml, lab_nmap_xml(lab.port)).expect("nmap xml");

    let smart_status = Command::new(bin_path())
        .args(["beh", "spust", "--workspace"])
        .arg(&workspace)
        .args([
            "--nazev",
            "Smart pentest lab",
            "--scope",
            "127.0.0.1/32",
            "--ports",
            &lab.port.to_string(),
            "--provider",
            "demo",
            "--nmap-xml",
        ])
        .arg(&nmap_xml)
        .arg("--pentest")
        .status()
        .expect("smart beh");
    assert!(smart_status.success());

    let hard_status = Command::new(bin_path())
        .args(["beh", "spust", "--workspace"])
        .arg(&workspace)
        .args([
            "--nazev",
            "Hard pentest lab",
            "--scope",
            "127.0.0.1/32",
            "--ports",
            &lab.port.to_string(),
            "--provider",
            "demo",
            "--nmap-xml",
        ])
        .arg(&nmap_xml)
        .args(["--pentest", "--aggressive-pentest"])
        .status()
        .expect("hard beh");
    assert!(hard_status.success());

    let reports = load_reports(&workspace);
    let smart = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Smart pentest lab")
        .expect("smart report");
    let hard = reports
        .iter()
        .find(|report| report["run"]["nazev"] == "Hard pentest lab")
        .expect("hard report");
    let smart_checks = active_template_ids(smart);
    let hard_checks = active_template_ids(hard);

    assert!(
        smart_checks.contains(&"bakula-login-surface-over-http".to_string()),
        "smart rezim musi najit nebezpecny login povrch pres HTTP"
    );
    assert!(
        hard_checks.len() > smart_checks.len(),
        "hard rezim musi pridat dalsi read-only pentest dukazy"
    );
    assert!(hard_checks.contains(&"bakula-git-head-exposed".to_string()));
    assert!(hard_checks.contains(&"bakula-backup-directory-exposed".to_string()));
    assert!(hard_checks.contains(&"bakula-config-yaml-accessible".to_string()));
    assert!(hard_checks.contains(&"bakula-cookie-missing-security-flags".to_string()));
    assert!(hard_checks.contains(&"bakula-cors-wildcard-origin".to_string()));
    assert!(hard_checks.contains(&"bakula-admin-product-exposed".to_string()));
    assert!(hard_checks.contains(&"bakula-admin-endpoint-reachable".to_string()));
    assert!(hard_checks.contains(&"bakula-private-key-accessible".to_string()));
    assert!(
        hard["monitoringLanes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane["source"] == "internal-pentest"
                && lane["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item == "mode=aggressive")),
        "hard report musi mit auditni lane internal-pentest s aggressive modem"
    );
}

#[test]
fn evaluation_batch_reports_precision_and_recall() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");

    let status = Command::new(bin_path())
        .args([
            "evaluace",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--seed",
            "123",
            "--nahodnych",
            "4",
            "--workers",
            "3",
            "--provider",
            "demo",
        ])
        .status()
        .expect("spusteni evaluace");
    assert!(status.success(), "evaluace musi probehnout uspesne");

    let evaluation_path = workspace.join("evaluation").join("latest.json");
    let evaluation: Value =
        serde_json::from_slice(&fs::read(&evaluation_path).expect("nacteni evaluation reportu"))
            .expect("evaluation json");

    assert_eq!(evaluation["summary"]["scenarios_failed"], 0);
    assert_eq!(evaluation["summary"]["scenarios_total"], 10);
    assert!(
        evaluation["summary"]["core_precision"]
            .as_f64()
            .unwrap_or_default()
            >= 0.9
    );
    assert!(
        evaluation["summary"]["core_recall"]
            .as_f64()
            .unwrap_or_default()
            >= 0.99
    );
    assert!(
        evaluation["summary"]["max_finding_families_per_target"]
            .as_u64()
            .unwrap_or_default()
            >= 2
    );
    assert!(
        evaluation["summary"]["mas_progress_score_avg"]
            .as_f64()
            .unwrap_or_default()
            > 0.0
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
            > 0.0
    );
}

#[test]
fn platform_rbac_scheduler_cluster_and_server_work_end_to_end() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");
    let db = temp.path().join("platform.sqlite");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    assert!(run_output_json(&["platform", "init", "--db", db.to_str().expect("db")]).is_object());
    run_output_json(&[
        "platform",
        "user",
        "add",
        "--db",
        db.to_str().expect("db"),
        "--username",
        "admin",
        "--role",
        "admin",
    ]);
    run_output_json(&[
        "platform",
        "user",
        "add",
        "--db",
        db.to_str().expect("db"),
        "--username",
        "viewer",
        "--role",
        "viewer",
    ]);

    run_output_json(&[
        "platform",
        "ha",
        "set-policy",
        "--db",
        db.to_str().expect("db"),
        "--quorum",
        "2",
        "--min-ready",
        "2",
        "--batch-size",
        "1",
        "--target-version",
        "2.0.0",
    ]);
    for node_id in ["node-a", "node-b", "node-c"] {
        run_output_json(&[
            "platform",
            "ha",
            "register-node",
            "--db",
            db.to_str().expect("db"),
            "--node-id",
            node_id,
            "--version",
            "1.0.0",
        ]);
    }
    let ha_plan_before =
        run_output_json(&["platform", "ha", "plan", "--db", db.to_str().expect("db")]);
    assert_eq!(
        ha_plan_before["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|candidate| candidate["eligible"] == true)
            .count(),
        3
    );
    let rollout = run_output_json(&[
        "platform",
        "ha",
        "advance",
        "--db",
        db.to_str().expect("db"),
    ]);
    assert_eq!(rollout["selected"].as_array().unwrap().len(), 1);
    let ha_plan_during =
        run_output_json(&["platform", "ha", "plan", "--db", db.to_str().expect("db")]);
    assert_eq!(ha_plan_during["upgrading_nodes"], 1);
    let first_selected = rollout["selected"][0].as_str().expect("selected node");
    run_output_json(&[
        "platform",
        "ha",
        "mark-ready",
        "--db",
        db.to_str().expect("db"),
        "--node-id",
        first_selected,
        "--version",
        "2.0.0",
    ]);

    let admin_issue = run_output_json(&[
        "platform",
        "token",
        "issue",
        "--db",
        db.to_str().expect("db"),
        "--username",
        "admin",
        "--name",
        "admin-cli",
    ]);
    let admin_token = admin_issue["raw_token"].as_str().expect("admin token");

    let viewer_issue = run_output_json(&[
        "platform",
        "token",
        "issue",
        "--db",
        db.to_str().expect("db"),
        "--username",
        "viewer",
        "--name",
        "viewer-cli",
    ]);
    let viewer_token = viewer_issue["raw_token"].as_str().expect("viewer token");

    let enqueue = run_output_json(&[
        "platform",
        "job",
        "enqueue-scenario",
        "--db",
        db.to_str().expect("db"),
        "--workspace",
        workspace.to_str().expect("workspace"),
        "--scenario-dir",
        scenarios.join("zakladni").to_str().expect("scenario path"),
        "--nazev",
        "DB scenario job",
        "--scope",
        "192.168.56.0/24",
    ]);
    assert!(enqueue["job_id"].as_i64().unwrap_or_default() > 0);

    let worker_a = run_output_json(&[
        "platform",
        "worker",
        "run",
        "--db",
        db.to_str().expect("db"),
        "--node-id",
        "node-a",
        "--once",
    ]);
    assert!(worker_a["run_id"].as_str().is_some());

    let _worker_b = run_output_json(&[
        "platform",
        "worker",
        "run",
        "--db",
        db.to_str().expect("db"),
        "--node-id",
        "node-b",
        "--once",
    ]);

    let status_json = run_output_json(&["platform", "status", "--db", db.to_str().expect("db")]);
    assert_eq!(status_json["leader_node_id"], "node-a");
    assert_eq!(status_json["nodes"].as_array().unwrap().len(), 3);
    assert!(
        status_json["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job["status"] == "succeeded")
    );

    let reports = load_reports(&workspace);
    assert_eq!(reports.len(), 1);

    let config_path = workspace.join("bakula.toml");
    fs::write(
        &config_path,
        r#"
workspace_root = "./workspace"
host = "127.0.0.1"
port = 8080

[retention]
max_runs = 50
keep_raw = true

[security]
require_api_token = false
api_token_env = "BAKULA_API_TOKEN"

[platform]
enabled = true
database_path = "../platform.sqlite"
leader_lease_seconds = 30
job_lease_seconds = 120
"#,
    )
    .expect("config write");

    let port = free_port();
    let mut child = spawn_server_with_options(
        &workspace,
        port,
        &["--config", config_path.to_str().expect("config")],
        &[],
    );
    wait_for_server(port);

    let client = reqwest::blocking::Client::new();
    let runs = client
        .get(format!("http://127.0.0.1:{port}/api/runs"))
        .header("Authorization", format!("Bearer {viewer_token}"))
        .send()
        .expect("viewer runs");
    assert_eq!(runs.status(), 200);

    let forbidden = client
        .get(format!("http://127.0.0.1:{port}/api/platform/users"))
        .header("Authorization", format!("Bearer {viewer_token}"))
        .send()
        .expect("viewer users");
    assert_eq!(forbidden.status(), 403);

    let allowed = client
        .get(format!("http://127.0.0.1:{port}/api/platform/users"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .send()
        .expect("admin users");
    assert_eq!(allowed.status(), 200);

    let cluster = client
        .get(format!("http://127.0.0.1:{port}/api/platform/cluster"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .send()
        .expect("admin cluster");
    assert_eq!(cluster.status(), 200);

    let ha = client
        .get(format!("http://127.0.0.1:{port}/api/platform/ha"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .send()
        .expect("admin ha");
    assert_eq!(ha.status(), 200);

    child.kill().expect("ukonceni serveru");
    child.wait().expect("wait");
}

fn load_reports(workspace: &Path) -> Vec<Value> {
    let runs_dir = workspace.join("runs");
    let mut reports = Vec::new();
    for entry in fs::read_dir(runs_dir).expect("runs dir") {
        let entry = entry.expect("entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let report_path = entry.path().join("report.json");
        if report_path.exists() {
            let value: Value =
                serde_json::from_slice(&fs::read(report_path).expect("report bytes"))
                    .expect("report json");
            reports.push(value);
        }
    }
    reports
}

fn active_template_ids(report: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for host in report["hosts"].as_array().into_iter().flatten() {
        for service in host["services"].as_array().into_iter().flatten() {
            for check in service["activeChecks"].as_array().into_iter().flatten() {
                if let Some(id) = check["template_id"].as_str() {
                    ids.push(id.to_string());
                }
            }
        }
    }
    ids
}

fn lab_nmap_xml(port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="lab-web"/></hostnames>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Bakula Lab Web" version="1.2" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>"#
    )
}

struct HttpPentestLab {
    port: u16,
    running: Arc<AtomicBool>,
}

impl HttpPentestLab {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind pentest lab");
        listener
            .set_nonblocking(true)
            .expect("nonblocking pentest lab");
        let port = listener.local_addr().expect("addr").port();
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0_u8; 2048];
                        let bytes = stream.read(&mut buffer).unwrap_or(0);
                        if bytes == 0 {
                            continue;
                        }
                        let request = String::from_utf8_lossy(&buffer[..bytes]);
                        let method = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().next())
                            .unwrap_or("GET");
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let (status, content_type, body, extra) = if method == "OPTIONS" {
                            (
                                "200 OK",
                                "text/plain",
                                "",
                                "Allow: GET, POST, OPTIONS, TRACE\r\n",
                            )
                        } else if method == "TRACE" {
                            ("200 OK", "message/http", "TRACE accepted", "")
                        } else {
                            match path {
                                "/.git/HEAD" => {
                                    ("200 OK", "text/plain", "ref: refs/heads/main\n", "")
                                }
                                "/backup/" => (
                                    "200 OK",
                                    "text/html",
                                    "<title>Index of /backup</title><h1>Index of /backup</h1>",
                                    "",
                                ),
                                "/config.yaml" => ("200 OK", "text/plain", "redacted: true\n", ""),
                                "/manager/html" => {
                                    ("200 OK", "text/html", "<h1>Tomcat Manager</h1>", "")
                                }
                                "/id_rsa" => ("200 OK", "text/plain", "redacted-key", ""),
                                "/metrics" => ("200 OK", "text/plain", "requests_total 42\n", ""),
                                _ => (
                                    "200 OK",
                                    "text/html",
                                    "<title>Directory listing for /</title><h1>Grafana Admin Login</h1><p>login</p>",
                                    "Access-Control-Allow-Origin: *\r\nSet-Cookie: sid=test\r\n",
                                ),
                            }
                        };
                        let response = format!(
                            "HTTP/1.1 {status}\r\nServer: BakulaLab/1.2\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Self { port, running }
    }
}

impl Drop for HttpPentestLab {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("listener")
        .local_addr()
        .expect("addr")
        .port()
}

fn run_output_json(args: &[&str]) -> Value {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("spusteni prikazu");
    assert!(
        output.status.success(),
        "prikaz selhal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json stdout")
}

fn spawn_server(workspace: &Path, port: u16) -> Child {
    spawn_server_with_options(workspace, port, &[], &[])
}

fn spawn_server_with_options(
    workspace: &Path,
    port: u16,
    extra_args: &[&str],
    envs: &[(&str, &str)],
) -> Child {
    let mut command = Command::new(bin_path());
    command
        .args(["server", "spust", "--workspace"])
        .arg(workspace)
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    command.spawn().expect("spusteni serveru")
}

fn wait_for_server(port: u16) {
    for _ in 0..30 {
        if reqwest::blocking::get(format!("http://127.0.0.1:{port}/api/health")).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!("server se nerozbehl vcas");
}
