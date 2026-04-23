use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    cpe,
    error::{BakulaError, Result},
    model::{Confidence, CveRecord, CvssRecord, EpssRecord, ExploitContext, HostReport, KevRecord},
};

pub trait VulnerabilityProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn query_by_cpe(&self, cpe23_uri: &str) -> Result<Vec<CveRecord>>;
}

pub fn build_provider(
    workspace: &Path,
    provider_name: &str,
    supplement_vulners: bool,
    freeze: bool,
) -> Result<Box<dyn VulnerabilityProvider>> {
    let cache_dir = workspace.join("cache").join(provider_name);
    fs::create_dir_all(&cache_dir)?;
    match provider_name {
        "public" | "auto" => {
            let nvd_cache = cache_dir.join("nvd");
            let vulners_cache = cache_dir.join("vulners");
            fs::create_dir_all(&nvd_cache)?;
            fs::create_dir_all(&vulners_cache)?;
            Ok(Box::new(CompositeProvider::new(
                "public",
                Box::new(NvdProvider::new(nvd_cache, freeze)),
                Box::new(VulnersProvider::new(vulners_cache, freeze)),
            )))
        }
        "nvd" if supplement_vulners => {
            let nvd_cache = cache_dir.join("nvd");
            let vulners_cache = cache_dir.join("vulners");
            fs::create_dir_all(&nvd_cache)?;
            fs::create_dir_all(&vulners_cache)?;
            Ok(Box::new(CompositeProvider::new(
                "nvd",
                Box::new(NvdProvider::new(nvd_cache, freeze)),
                Box::new(VulnersProvider::new(vulners_cache, freeze)),
            )))
        }
        "nvd" => Ok(Box::new(NvdProvider::new(cache_dir, freeze))),
        "vulners" => {
            let nvd_cache = cache_dir.join("nvd-fallback");
            let vulners_cache = cache_dir.join("vulners");
            fs::create_dir_all(&nvd_cache)?;
            fs::create_dir_all(&vulners_cache)?;
            Ok(Box::new(CompositeProvider::new(
                "vulners",
                Box::new(VulnersProvider::new(vulners_cache, freeze)),
                Box::new(NvdProvider::new(nvd_cache, freeze)),
            )))
        }
        _ => Ok(Box::new(DemoProvider::new(
            workspace.join("data").join("demo_vulnerabilities.json"),
            cache_dir,
            freeze,
        )?)),
    }
}

pub fn enrich_with_vulnerabilities(
    hosts: &mut [HostReport],
    provider: &dyn VulnerabilityProvider,
) -> Result<()> {
    for service in hosts.iter_mut().flat_map(|host| host.services.iter_mut()) {
        let mut findings = Vec::new();
        for candidate in &service.cpe {
            if candidate.confidence == Confidence::Low && candidate.method == "partial" {
                continue;
            }
            if matches!(provider.name(), "nvd" | "public" | "vulners" | "composite")
                && candidate.method == "partial"
            {
                continue;
            }
            match provider.query_by_cpe(&candidate.cpe23_uri) {
                Ok(mut items) => findings.append(&mut items),
                Err(error) => eprintln!(
                    "Varovani: CVE provider {} selhal pro {}: {}",
                    provider.name(),
                    candidate.cpe23_uri,
                    error
                ),
            }
        }
        findings.sort_by(|left, right| left.cve_id.cmp(&right.cve_id));
        findings.dedup_by(|left, right| left.cve_id == right.cve_id);
        service.cves = findings;
    }
    Ok(())
}

struct DemoProvider {
    database: DemoDatabase,
    cache_dir: PathBuf,
    freeze: bool,
}

#[derive(Debug, Deserialize)]
struct DemoDatabase {
    entries: Vec<DemoEntry>,
}

#[derive(Debug, Deserialize)]
struct DemoEntry {
    cpe_prefix: String,
    cves: Vec<DemoCve>,
}

#[derive(Debug, Deserialize)]
struct DemoCve {
    cve_id: String,
    summary: String,
    cvss_version: String,
    base_score: f64,
    severity: String,
    references: Vec<String>,
}

impl DemoProvider {
    fn new(path: PathBuf, cache_dir: PathBuf, freeze: bool) -> Result<Self> {
        let database = if path.exists() {
            let content = fs::read_to_string(path)?;
            serde_json::from_str(&content).map_err(|error| {
                BakulaError::Processing(format!("Nelze nacist demo databazi: {error}"))
            })?
        } else {
            default_demo_database()
        };
        Ok(Self {
            database,
            cache_dir,
            freeze,
        })
    }
}

impl VulnerabilityProvider for DemoProvider {
    fn name(&self) -> &'static str {
        "demo"
    }

    fn query_by_cpe(&self, cpe23_uri: &str) -> Result<Vec<CveRecord>> {
        let cache_path = cache_file_path(&self.cache_dir, cpe23_uri);
        if let Some(records) = try_read_cache(&cache_path)? {
            return Ok(records);
        }
        if self.freeze {
            return Ok(Vec::new());
        }

        let records = self
            .database
            .entries
            .iter()
            .find(|entry| cpe23_uri.starts_with(&entry.cpe_prefix))
            .map(|entry| {
                entry
                    .cves
                    .iter()
                    .map(|cve| CveRecord {
                        cve_id: cve.cve_id.clone(),
                        summary: Some(cve.summary.clone()),
                        cvss: Some(CvssRecord {
                            version: cve.cvss_version.clone(),
                            base_score: cve.base_score,
                            severity: Some(cve.severity.clone()),
                        }),
                        source: self.name().to_string(),
                        retrieved_at: Utc::now(),
                        references: cve.references.clone(),
                        exploit_context: None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        write_cache(&cache_path, &records)?;
        Ok(records)
    }
}

struct NvdProvider {
    cache_dir: PathBuf,
    freeze: bool,
    feed_cache: Mutex<FeedCache>,
}

struct VulnersProvider {
    cache_dir: PathBuf,
    freeze: bool,
}

struct CompositeProvider {
    provider_name: &'static str,
    primary: Box<dyn VulnerabilityProvider>,
    supplemental: Box<dyn VulnerabilityProvider>,
}

#[derive(Default)]
struct FeedCache {
    kev: Option<HashMap<String, KevRecord>>,
    epss: HashMap<String, EpssRecord>,
    epss_absent: HashSet<String>,
}

impl NvdProvider {
    fn new(cache_dir: PathBuf, freeze: bool) -> Self {
        Self {
            cache_dir,
            freeze,
            feed_cache: Mutex::new(FeedCache::default()),
        }
    }

    fn enrich_exploit_context(
        &self,
        client: &reqwest::blocking::Client,
        records: &mut [CveRecord],
    ) {
        let cve_ids = records
            .iter()
            .map(|item| item.cve_id.clone())
            .collect::<Vec<_>>();
        if cve_ids.is_empty() {
            return;
        }

        let epss_by_cve = self
            .fetch_epss_context(client, &cve_ids)
            .unwrap_or_else(|error| {
                eprintln!("Varovani: EPSS enrichment selhal: {error}");
                HashMap::new()
            });
        let kev_by_cve = self
            .fetch_kev_context(client, &cve_ids)
            .unwrap_or_else(|error| {
                eprintln!("Varovani: CISA KEV enrichment selhal: {error}");
                HashMap::new()
            });

        for record in records.iter_mut() {
            let epss = epss_by_cve.get(&record.cve_id).cloned();
            let cisa_kev = kev_by_cve.get(&record.cve_id).cloned();
            if epss.is_some() || cisa_kev.is_some() {
                record.exploit_context = Some(ExploitContext { epss, cisa_kev });
            }
        }
    }

    fn fetch_epss_context(
        &self,
        client: &reqwest::blocking::Client,
        cve_ids: &[String],
    ) -> Result<HashMap<String, EpssRecord>> {
        let mut result = HashMap::new();
        let mut missing = Vec::new();
        {
            let cache = self.feed_cache.lock().map_err(|_| {
                BakulaError::Processing("Nelze zamknout cache pro EPSS enrichment.".to_string())
            })?;
            for cve_id in cve_ids {
                if let Some(item) = cache.epss.get(cve_id) {
                    result.insert(cve_id.clone(), item.clone());
                } else if !cache.epss_absent.contains(cve_id) {
                    missing.push(cve_id.clone());
                }
            }
        }

        for chunk in missing.chunks(100) {
            let joined = chunk.join(",");
            let response = client
                .get("https://api.first.org/data/v1/epss")
                .query(&[("cve", joined.as_str())])
                .send()?
                .error_for_status()?;

            let payload: EpssApiResponse = response.json()?;
            let mut fetched = HashMap::new();
            for item in payload.data {
                let Some(score) = parse_decimal(&item.epss) else {
                    continue;
                };
                let Some(percentile) = parse_decimal(&item.percentile) else {
                    continue;
                };
                fetched.insert(
                    item.cve.clone(),
                    EpssRecord {
                        score,
                        percentile,
                        date: item.date,
                        source: "FIRST EPSS API".to_string(),
                    },
                );
            }

            {
                let mut cache = self.feed_cache.lock().map_err(|_| {
                    BakulaError::Processing(
                        "Nelze zamknout cache pro ulozeni EPSS enrichmentu.".to_string(),
                    )
                })?;
                for (cve_id, record) in &fetched {
                    cache.epss.insert(cve_id.clone(), record.clone());
                    cache.epss_absent.remove(cve_id);
                }
                for cve_id in chunk {
                    if !fetched.contains_key(cve_id) {
                        cache.epss_absent.insert(cve_id.clone());
                    }
                }
            }

            result.extend(fetched);
        }

        Ok(result)
    }

    fn fetch_kev_context(
        &self,
        client: &reqwest::blocking::Client,
        cve_ids: &[String],
    ) -> Result<HashMap<String, KevRecord>> {
        {
            let cache = self.feed_cache.lock().map_err(|_| {
                BakulaError::Processing("Nelze zamknout cache pro KEV enrichment.".to_string())
            })?;
            if let Some(kev) = &cache.kev {
                return Ok(filter_kev_records(kev, cve_ids));
            }
        }

        let response = client
            .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            .send()?
            .error_for_status()?;
        let payload: KevFeed = response.json()?;
        let mapped = payload
            .vulnerabilities
            .into_iter()
            .map(|item| {
                let record = KevRecord {
                    known_exploited: true,
                    vendor_project: item.vendor_project,
                    product: item.product,
                    vulnerability_name: item.vulnerability_name,
                    short_description: item.short_description,
                    date_added: item.date_added,
                    due_date: item.due_date,
                    required_action: item.required_action,
                    known_ransomware_campaign_use: item.known_ransomware_campaign_use,
                    source: "CISA Known Exploited Vulnerabilities".to_string(),
                };
                (item.cve_id, record)
            })
            .collect::<HashMap<_, _>>();

        {
            let mut cache = self.feed_cache.lock().map_err(|_| {
                BakulaError::Processing(
                    "Nelze zamknout cache pro ulozeni KEV enrichmentu.".to_string(),
                )
            })?;
            cache.kev = Some(mapped.clone());
        }

        Ok(filter_kev_records(&mapped, cve_ids))
    }
}

impl VulnersProvider {
    fn new(cache_dir: PathBuf, freeze: bool) -> Self {
        Self { cache_dir, freeze }
    }
}

impl CompositeProvider {
    fn new(
        provider_name: &'static str,
        primary: Box<dyn VulnerabilityProvider>,
        supplemental: Box<dyn VulnerabilityProvider>,
    ) -> Self {
        Self {
            provider_name,
            primary,
            supplemental,
        }
    }
}

impl VulnerabilityProvider for NvdProvider {
    fn name(&self) -> &'static str {
        "nvd"
    }

    fn query_by_cpe(&self, cpe23_uri: &str) -> Result<Vec<CveRecord>> {
        let cache_path = cache_file_path(&self.cache_dir, cpe23_uri);
        if let Some(records) = try_read_cache(&cache_path)? {
            return Ok(records);
        }
        if self.freeze {
            return Ok(Vec::new());
        }

        let client = reqwest::blocking::Client::builder()
            .user_agent("bakula-program/0.1")
            .timeout(Duration::from_secs(20))
            .build()?;

        let mut response_value: Option<serde_json::Value> = None;
        for attempt in 0..3 {
            let mut request = client
                .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
                .query(&[("cpeName", cpe23_uri), ("resultsPerPage", "2000")]);

            if let Ok(api_key) = env::var("NVD_API_KEY") {
                if !api_key.trim().is_empty() {
                    request = request.header("apiKey", api_key);
                }
            }

            let response = request.send()?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                write_cache(&cache_path, &[])?;
                return Ok(Vec::new());
            }
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                if attempt < 2 {
                    thread::sleep(Duration::from_millis(800 * (attempt + 1) as u64));
                    continue;
                }
            }
            let parsed: serde_json::Value = response.error_for_status()?.json()?;
            response_value = Some(parsed);
            break;
        }

        let response_value = response_value.ok_or_else(|| {
            BakulaError::Processing(format!(
                "NVD odpoved nebyla dostupna pro CPE {} ani po opakovani.",
                cpe23_uri
            ))
        })?;
        let vulnerabilities = response_value["vulnerabilities"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let mut records = Vec::new();
        for item in vulnerabilities {
            let cve = &item["cve"];
            if !nvd_item_matches_cpe(cve, cpe23_uri) {
                continue;
            }
            let cve_id = cve["id"].as_str().unwrap_or_default().to_string();
            if cve_id.is_empty() {
                continue;
            }
            let summary = cve["descriptions"]
                .as_array()
                .and_then(|descriptions| {
                    descriptions
                        .iter()
                        .find(|desc| desc["lang"].as_str() == Some("en"))
                        .or_else(|| descriptions.first())
                })
                .and_then(|desc| desc["value"].as_str())
                .map(ToString::to_string);
            let cvss = extract_cvss(cve);
            let references = cve["references"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|entry| entry["url"].as_str().map(ToString::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            records.push(CveRecord {
                cve_id,
                summary,
                cvss,
                source: self.name().to_string(),
                retrieved_at: Utc::now(),
                references,
                exploit_context: None,
            });
        }

        self.enrich_exploit_context(&client, &mut records);
        write_cache(&cache_path, &records)?;
        Ok(records)
    }
}

impl VulnerabilityProvider for CompositeProvider {
    fn name(&self) -> &'static str {
        self.provider_name
    }

    fn query_by_cpe(&self, cpe23_uri: &str) -> Result<Vec<CveRecord>> {
        let mut primary = match self.primary.query_by_cpe(cpe23_uri) {
            Ok(items) => items,
            Err(error) => {
                eprintln!(
                    "Varovani: primarni CVE provider {} selhal pro {}: {}",
                    self.primary.name(),
                    cpe23_uri,
                    error
                );
                Vec::new()
            }
        };
        let supplemental = match self.supplemental.query_by_cpe(cpe23_uri) {
            Ok(items) => items,
            Err(error) => {
                eprintln!(
                    "Varovani: doplnkovy CVE provider {} selhal pro {}: {}",
                    self.supplemental.name(),
                    cpe23_uri,
                    error
                );
                Vec::new()
            }
        };
        for extra in supplemental {
            if let Some(existing) = primary.iter_mut().find(|item| item.cve_id == extra.cve_id) {
                for reference in extra.references {
                    if !existing.references.contains(&reference) {
                        existing.references.push(reference);
                    }
                }
                if existing.summary.is_none() {
                    existing.summary = extra.summary;
                }
            } else {
                primary.push(extra);
            }
        }
        primary.sort_by(|left, right| left.cve_id.cmp(&right.cve_id));
        Ok(primary)
    }
}

impl VulnerabilityProvider for VulnersProvider {
    fn name(&self) -> &'static str {
        "vulners"
    }

    fn query_by_cpe(&self, cpe23_uri: &str) -> Result<Vec<CveRecord>> {
        let cache_path = cache_file_path(&self.cache_dir, cpe23_uri);
        if let Some(records) = try_read_cache(&cache_path)? {
            return Ok(records);
        }
        if self.freeze {
            return Ok(Vec::new());
        }

        let Some(api_key) = env::var("VULNERS_API_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(Vec::new());
        };

        let client = reqwest::blocking::Client::builder()
            .user_agent("bakula-program/0.1")
            .timeout(Duration::from_secs(20))
            .build()?;

        let payload = serde_json::json!({
            "software": [cpe23_uri],
            "match": "partial",
            "fields": [
                "title",
                "short_description",
                "description",
                "href",
                "published",
                "cvelist"
            ]
        });

        let endpoint = env::var("VULNERS_API_URL")
            .unwrap_or_else(|_| "https://vulners.com/api/v4/audit/software".to_string());

        let response: serde_json::Value = client
            .post(endpoint)
            .header("X-Api-Key", api_key)
            .json(&payload)
            .send()?
            .error_for_status()?
            .json()?;

        let mut records = parse_vulners_records(&response, Utc::now());
        records.sort_by(|left, right| left.cve_id.cmp(&right.cve_id));
        records.dedup_by(|left, right| left.cve_id == right.cve_id);
        write_cache(&cache_path, &records)?;
        Ok(records)
    }
}

#[derive(Debug, Deserialize)]
struct EpssApiResponse {
    #[serde(default)]
    data: Vec<EpssApiItem>,
}

#[derive(Debug, Deserialize)]
struct EpssApiItem {
    cve: String,
    epss: String,
    percentile: String,
    date: String,
}

#[derive(Debug, Deserialize)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevFeedItem>,
}

#[derive(Debug, Deserialize)]
struct KevFeedItem {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: Option<String>,
    product: Option<String>,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: Option<String>,
    #[serde(rename = "shortDescription")]
    short_description: Option<String>,
    #[serde(rename = "dateAdded")]
    date_added: Option<String>,
    #[serde(rename = "dueDate")]
    due_date: Option<String>,
    #[serde(rename = "requiredAction")]
    required_action: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse")]
    known_ransomware_campaign_use: Option<String>,
}

fn nvd_item_matches_cpe(cve: &serde_json::Value, target_cpe: &str) -> bool {
    let Some(configurations) = cve["configurations"].as_array() else {
        return true;
    };

    configurations
        .iter()
        .flat_map(|config| config["nodes"].as_array().into_iter().flatten())
        .any(|node| node_matches_target(node, target_cpe))
}

fn node_matches_target(node: &serde_json::Value, target_cpe: &str) -> bool {
    if node["cpeMatch"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| {
            entry["vulnerable"].as_bool().unwrap_or(false)
                && entry["criteria"]
                    .as_str()
                    .map(|criteria| cpe::cpe_matches_target(criteria, target_cpe, entry))
                    .unwrap_or(false)
        })
    {
        return true;
    }

    node["children"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|child| node_matches_target(child, target_cpe))
}

fn extract_cvss(cve: &serde_json::Value) -> Option<CvssRecord> {
    let metrics = cve.get("metrics")?;
    let options = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ];
    for key in options {
        if let Some(item) = metrics
            .get(key)
            .and_then(|value| value.as_array())
            .and_then(|array| array.first())
        {
            let cvss_data = &item["cvssData"];
            if let (Some(version), Some(base_score)) = (
                cvss_data["version"].as_str(),
                cvss_data["baseScore"].as_f64(),
            ) {
                return Some(CvssRecord {
                    version: version.to_string(),
                    base_score,
                    severity: item["baseSeverity"].as_str().map(ToString::to_string),
                });
            }
        }
    }
    None
}

fn parse_vulners_records(
    response: &serde_json::Value,
    retrieved_at: DateTime<Utc>,
) -> Vec<CveRecord> {
    let rows = vulners_rows(response);
    let mut records = Vec::new();

    for row in rows {
        let vulnerabilities = row
            .get("vulnerabilities")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_else(|| vec![row.clone()]);
        for item in vulnerabilities {
            let title = vulners_string(
                &item,
                &[
                    "short_description",
                    "description",
                    "title",
                    "bulletinFamily",
                ],
            );
            let href = vulners_string(&item, &["href", "vhref"]);
            let mut cve_ids = collect_cve_ids(&item);
            cve_ids.sort();
            cve_ids.dedup();
            for cve_id in cve_ids {
                records.push(CveRecord {
                    cve_id,
                    summary: title.clone(),
                    cvss: None,
                    source: "vulners".to_string(),
                    retrieved_at,
                    references: href.clone().into_iter().collect(),
                    exploit_context: None,
                });
            }
        }
    }

    records
}

fn vulners_rows(response: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(array) = response.as_array() {
        return array.clone();
    }
    if let Some(array) = response.get("data").and_then(|value| value.as_array()) {
        return array.clone();
    }
    if let Some(data) = response.get("data") {
        if data.get("vulnerabilities").is_some() {
            return vec![data.clone()];
        }
        if let Some(object) = data.as_object() {
            return object
                .values()
                .flat_map(|value| {
                    value
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![value.clone()])
                })
                .collect();
        }
    }
    Vec::new()
}

fn first_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(|item| item.as_str()))
        .find(|item| !item.trim().is_empty())
        .map(ToString::to_string)
}

fn vulners_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    first_string(value, keys).or_else(|| {
        value
            .get("_source")
            .and_then(|source| first_string(source, keys))
    })
}

fn collect_cve_ids(value: &serde_json::Value) -> Vec<String> {
    let mut cve_ids = value
        .get("cvelist")
        .and_then(|item| item.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str().map(ToString::to_string))
        .filter(|entry| entry.starts_with("CVE-"))
        .collect::<Vec<_>>();

    if cve_ids.is_empty() {
        if let Some(id) = first_string(value, &["cve", "id", "_id"]) {
            if id.starts_with("CVE-") {
                cve_ids.push(id);
            }
        }
    }

    if cve_ids.is_empty() {
        if let Some(source) = value.get("_source") {
            cve_ids = collect_cve_ids(source);
        }
    }

    cve_ids
}

fn filter_kev_records(
    kev_by_cve: &HashMap<String, KevRecord>,
    cve_ids: &[String],
) -> HashMap<String, KevRecord> {
    cve_ids
        .iter()
        .filter_map(|cve_id| {
            kev_by_cve
                .get(cve_id)
                .cloned()
                .map(|item| (cve_id.clone(), item))
        })
        .collect()
}

fn parse_decimal(value: &str) -> Option<f64> {
    value.trim().parse::<f64>().ok()
}

fn cache_file_path(cache_dir: &Path, cpe23_uri: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(cpe23_uri.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    cache_dir.join(format!("{digest}.json"))
}

fn try_read_cache(path: &Path) -> Result<Option<Vec<CveRecord>>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read(path)?;
    let items = serde_json::from_slice(&content).map_err(BakulaError::Json)?;
    Ok(Some(items))
}

fn write_cache(path: &Path, records: &[CveRecord]) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(records).map_err(BakulaError::Json)?,
    )?;
    Ok(())
}

fn default_demo_database() -> DemoDatabase {
    DemoDatabase {
        entries: vec![
            DemoEntry {
                cpe_prefix: "cpe:2.3:a:apache:http_server:2.4.49".to_string(),
                cves: vec![
                    DemoCve {
                        cve_id: "CVE-2021-41773".to_string(),
                        summary: "Path traversal a moznost RCE v Apache HTTP Server 2.4.49."
                            .to_string(),
                        cvss_version: "3.1".to_string(),
                        base_score: 7.5,
                        severity: "HIGH".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773".to_string(),
                        ],
                    },
                    DemoCve {
                        cve_id: "CVE-2021-42013".to_string(),
                        summary: "Nedostatecne odstranena chyba po CVE-2021-41773.".to_string(),
                        cvss_version: "3.1".to_string(),
                        base_score: 9.8,
                        severity: "CRITICAL".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013".to_string(),
                        ],
                    },
                ],
            },
            DemoEntry {
                cpe_prefix: "cpe:2.3:a:openbsd:openssh:8.9".to_string(),
                cves: vec![DemoCve {
                    cve_id: "CVE-2023-38408".to_string(),
                    summary: "Lokalni RCE pres ssh-agent pri urcitych podminkach.".to_string(),
                    cvss_version: "3.1".to_string(),
                    base_score: 8.8,
                    severity: "HIGH".to_string(),
                    references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-38408".to_string()],
                }],
            },
            DemoEntry {
                cpe_prefix: "cpe:2.3:a:vsftpd_project:vsftpd:3.0.3".to_string(),
                cves: vec![DemoCve {
                    cve_id: "CVE-2021-3618".to_string(),
                    summary: "Problem v pristupovych pravech pri urcite konfiguraci vsftpd."
                        .to_string(),
                    cvss_version: "3.1".to_string(),
                    base_score: 6.5,
                    severity: "MEDIUM".to_string(),
                    references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-3618".to_string()],
                }],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_epss_payload() {
        let payload = serde_json::json!({
            "data": [
                {
                    "cve": "CVE-2021-41773",
                    "epss": "0.943910000",
                    "percentile": "0.999730000",
                    "date": "2026-04-07"
                }
            ]
        });

        let parsed: EpssApiResponse = serde_json::from_value(payload).expect("valid epss payload");
        assert_eq!(parsed.data.len(), 1);
        assert_eq!(parsed.data[0].cve, "CVE-2021-41773");
        assert_eq!(parse_decimal(&parsed.data[0].epss), Some(0.94391));
    }

    #[test]
    fn parses_kev_payload() {
        let payload = serde_json::json!({
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-41773",
                    "vendorProject": "Apache",
                    "product": "HTTP Server",
                    "vulnerabilityName": "Apache HTTP Server Path Traversal",
                    "shortDescription": "Known exploited vulnerability.",
                    "dateAdded": "2021-11-03",
                    "dueDate": "2021-11-17",
                    "requiredAction": "Apply updates.",
                    "knownRansomwareCampaignUse": "Unknown"
                }
            ]
        });

        let parsed: KevFeed = serde_json::from_value(payload).expect("valid kev payload");
        assert_eq!(parsed.vulnerabilities.len(), 1);
        assert_eq!(parsed.vulnerabilities[0].cve_id, "CVE-2021-41773");
        assert_eq!(
            parsed.vulnerabilities[0].vendor_project.as_deref(),
            Some("Apache")
        );
    }

    #[test]
    fn parses_vulners_audit_payload() {
        let payload = serde_json::json!({
            "result": "OK",
            "data": [
                {
                    "software": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    "vulnerabilities": [
                        {
                            "short_description": "Apache HTTP Server path traversal.",
                            "href": "https://vulners.com/cve/CVE-2021-41773",
                            "cvelist": ["CVE-2021-41773", "CVE-2021-42013"]
                        }
                    ]
                }
            ]
        });
        let retrieved_at = Utc
            .with_ymd_and_hms(2026, 4, 21, 12, 0, 0)
            .single()
            .expect("fixed time");

        let mut records = parse_vulners_records(&payload, retrieved_at);
        records.sort_by(|left, right| left.cve_id.cmp(&right.cve_id));

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].cve_id, "CVE-2021-41773");
        assert_eq!(records[0].source, "vulners");
        assert_eq!(records[0].retrieved_at, retrieved_at);
        assert_eq!(
            records[0].references,
            vec!["https://vulners.com/cve/CVE-2021-41773".to_string()]
        );
    }

    #[test]
    fn parses_vulners_search_wrapper_payload() {
        let payload = serde_json::json!({
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_id": "CVE-2023-38408",
                        "_source": {
                            "title": "OpenSSH ssh-agent issue",
                            "href": "https://vulners.com/cve/CVE-2023-38408",
                            "cvelist": ["CVE-2023-38408"]
                        }
                    }
                ]
            }
        });
        let retrieved_at = Utc
            .with_ymd_and_hms(2026, 4, 21, 13, 0, 0)
            .single()
            .expect("fixed time");

        let records = parse_vulners_records(&payload, retrieved_at);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cve_id, "CVE-2023-38408");
        assert_eq!(
            records[0].summary.as_deref(),
            Some("OpenSSH ssh-agent issue")
        );
        assert_eq!(
            records[0].references,
            vec!["https://vulners.com/cve/CVE-2023-38408".to_string()]
        );
    }
}
