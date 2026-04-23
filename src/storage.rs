use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    error::{BakulaError, Result},
    model::{RunIndex, RunIndexEntry, RunReport},
    narrative,
};

pub struct Workspace {
    root: PathBuf,
}

#[derive(Debug, Serialize)]
struct RunStorageManifest {
    run_id: String,
    generated_at: chrono::DateTime<Utc>,
    files: Vec<StoredFile>,
}

#[derive(Debug, Serialize)]
struct StoredFile {
    path: String,
    bytes: u64,
    sha256: String,
}

impl Workspace {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        fs::create_dir_all(root.join("runs"))?;
        fs::create_dir_all(root.join("cache"))?;
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("ui-state"))?;
        fs::create_dir_all(root.join("verification"))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn save_run(
        &self,
        report: &RunReport,
        nmap_path: &Path,
        nmap_followup_path: Option<&PathBuf>,
        nmap_forensic_path: Option<&PathBuf>,
        suricata_path: Option<&PathBuf>,
        zeek_dir: Option<&PathBuf>,
        httpx_output_jsonl: Option<&str>,
        nuclei_output_jsonl: Option<&str>,
        pentest_output_jsonl: Option<&str>,
        snmp_snapshot_json: Option<&str>,
        librenms_snapshot_json: Option<&str>,
        meraki_snapshot_json: Option<&str>,
        unifi_snapshot_json: Option<&str>,
        aruba_snapshot_json: Option<&str>,
        omada_snapshot_json: Option<&str>,
        ntopng_json: Option<&str>,
        flow_json: Option<&str>,
        greenbone_json: Option<&str>,
        wazuh_json: Option<&str>,
        napalm_json: Option<&str>,
        netmiko_json: Option<&str>,
        scrapli_json: Option<&str>,
    ) -> Result<()> {
        let run_dir = self.root.join("runs").join(&report.run.run_id);
        let raw_dir = run_dir.join("raw");
        fs::create_dir_all(&raw_dir)?;
        fs::write(
            run_dir.join("report.json"),
            serde_json::to_vec_pretty(report).map_err(BakulaError::Json)?,
        )?;
        fs::write(
            run_dir.join("report.md"),
            narrative::report_to_markdown(report),
        )?;
        fs::write(
            run_dir.join("report.txt"),
            narrative::report_to_text(report),
        )?;
        fs::copy(nmap_path, raw_dir.join("nmap.xml"))?;
        if let Some(path) = nmap_followup_path {
            fs::copy(path, raw_dir.join("nmap-followup.xml"))?;
        }
        if let Some(path) = nmap_forensic_path {
            fs::copy(path, raw_dir.join("nmap-forensic.xml"))?;
        }
        if let Some(path) = suricata_path {
            fs::copy(path, raw_dir.join("suricata-eve.json"))?;
        }
        if let Some(dir) = zeek_dir {
            let zeek_target = raw_dir.join("zeek");
            fs::create_dir_all(&zeek_target)?;
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::copy(entry.path(), zeek_target.join(entry.file_name()))?;
                }
            }
        }
        if let Some(output) = httpx_output_jsonl {
            fs::write(raw_dir.join("httpx.jsonl"), output)?;
        }
        if let Some(output) = nuclei_output_jsonl {
            fs::write(raw_dir.join("nuclei.jsonl"), output)?;
        }
        if let Some(output) = pentest_output_jsonl {
            fs::write(raw_dir.join("internal-pentest.jsonl"), output)?;
        }
        if let Some(output) = snmp_snapshot_json {
            fs::write(raw_dir.join("snmp-snapshot.json"), output)?;
        }
        if let Some(output) = librenms_snapshot_json {
            fs::write(raw_dir.join("librenms-snapshot.json"), output)?;
        }
        if let Some(output) = meraki_snapshot_json {
            fs::write(raw_dir.join("meraki-snapshot.json"), output)?;
        }
        if let Some(output) = unifi_snapshot_json {
            fs::write(raw_dir.join("unifi-snapshot.json"), output)?;
        }
        if let Some(output) = aruba_snapshot_json {
            fs::write(raw_dir.join("aruba-snapshot.json"), output)?;
        }
        if let Some(output) = omada_snapshot_json {
            fs::write(raw_dir.join("omada-snapshot.json"), output)?;
        }
        if let Some(output) = ntopng_json {
            fs::write(raw_dir.join("ntopng-snapshot.json"), output)?;
        }
        if let Some(output) = flow_json {
            fs::write(raw_dir.join("flow-snapshot.json"), output)?;
        }
        if let Some(output) = greenbone_json {
            fs::write(raw_dir.join("greenbone-report.json"), output)?;
        }
        if let Some(output) = wazuh_json {
            fs::write(raw_dir.join("wazuh-report.json"), output)?;
        }
        if let Some(output) = napalm_json {
            fs::write(raw_dir.join("napalm-snapshot.json"), output)?;
        }
        if let Some(output) = netmiko_json {
            fs::write(raw_dir.join("netmiko-snapshot.json"), output)?;
        }
        if let Some(output) = scrapli_json {
            fs::write(raw_dir.join("scrapli-snapshot.json"), output)?;
        }

        let mut index = self.load_index()?;
        index.runs.retain(|entry| entry.run_id != report.run.run_id);
        index.runs.push(RunIndexEntry {
            run_id: report.run.run_id.clone(),
            nazev: report.run.nazev.clone(),
            created_at: Utc::now(),
            scope: report.run.scope.clone(),
            hosts_total: report.summary.hosts_total,
            services_total: report.summary.services_total,
            cves_total: report.summary.cves_total,
            events_total: report.summary.events_total,
            findings_total: report.summary.findings_total,
            triage_actions_total: report.summary.triage_actions_total,
            monitoring_lanes_total: report.summary.monitoring_lanes_total,
        });
        index
            .runs
            .sort_by(|left, right| right.created_at.cmp(&left.created_at));
        self.sync_index(&index)?;
        self.write_manifest(&run_dir)?;

        Ok(())
    }

    pub fn load_report(&self, run_id: &str) -> Result<RunReport> {
        let path = self.root.join("runs").join(run_id).join("report.json");
        let data = fs::read(path)?;
        serde_json::from_slice(&data).map_err(BakulaError::Json)
    }

    pub fn list_runs(&self) -> Result<Vec<RunIndexEntry>> {
        Ok(self.load_index()?.runs)
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    pub fn enforce_retention(&self, max_runs: usize, keep_raw: bool) -> Result<()> {
        let mut index = self.load_index()?;
        index
            .runs
            .sort_by(|left, right| right.created_at.cmp(&left.created_at));

        let removed = if index.runs.len() > max_runs {
            index.runs.split_off(max_runs)
        } else {
            Vec::new()
        };
        for entry in removed {
            let run_dir = self.root.join("runs").join(entry.run_id);
            if run_dir.exists() {
                fs::remove_dir_all(run_dir)?;
            }
        }

        for entry in &index.runs {
            let run_dir = self.root.join("runs").join(&entry.run_id);
            if !keep_raw {
                let raw_dir = run_dir.join("raw");
                if raw_dir.exists() {
                    fs::remove_dir_all(&raw_dir)?;
                }
            }
            if run_dir.exists() {
                self.write_manifest(&run_dir)?;
            }
        }

        self.sync_index(&index)?;
        Ok(())
    }

    fn load_index(&self) -> Result<RunIndex> {
        let path = self.root.join("runs").join("index.json");
        if !path.exists() {
            return Ok(RunIndex::default());
        }
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(BakulaError::Json)
    }

    fn sync_index(&self, index: &RunIndex) -> Result<()> {
        fs::write(
            self.root.join("runs").join("index.json"),
            serde_json::to_vec_pretty(index).map_err(BakulaError::Json)?,
        )?;
        Ok(())
    }

    fn write_manifest(&self, run_dir: &Path) -> Result<()> {
        let run_id = run_dir
            .file_name()
            .and_then(|item| item.to_str())
            .ok_or_else(|| {
                BakulaError::Processing(format!("Neplatny run adresar: {}", run_dir.display()))
            })?
            .to_string();
        let mut files = Vec::new();
        collect_manifest_files(run_dir, run_dir, &mut files)?;
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = RunStorageManifest {
            run_id,
            generated_at: Utc::now(),
            files,
        };
        fs::write(
            run_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).map_err(BakulaError::Json)?,
        )?;
        Ok(())
    }
}

fn collect_manifest_files(root: &Path, current: &Path, files: &mut Vec<StoredFile>) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_manifest_files(root, &path, files)?;
            continue;
        }
        if path.file_name().and_then(|item| item.to_str()) == Some("manifest.json") {
            continue;
        }
        let bytes = fs::read(&path)?;
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let relative = path
            .strip_prefix(root)
            .map_err(|error| {
                BakulaError::Processing(format!(
                    "Nelze odvodit relativni cestu pro {}: {error}",
                    path.display()
                ))
            })?
            .to_string_lossy()
            .replace('\\', "/");
        files.push(StoredFile {
            path: relative,
            bytes: bytes.len() as u64,
            sha256: format!("{:x}", digest.finalize()),
        });
    }
    Ok(())
}
