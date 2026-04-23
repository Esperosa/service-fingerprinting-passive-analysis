use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub workspace_root: String,
    pub host: String,
    pub port: u16,
    pub nvd_api_key_env: Option<String>,
    pub retention: RetentionConfig,
    pub security: SecurityConfig,
    pub platform: PlatformConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionConfig {
    pub max_runs: usize,
    pub keep_raw: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_runs: 50,
            keep_raw: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub require_api_token: bool,
    pub api_token_env: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_api_token: false,
            api_token_env: Some("BAKULA_API_TOKEN".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformConfig {
    pub enabled: bool,
    pub database_path: String,
    pub leader_lease_seconds: i64,
    pub job_lease_seconds: i64,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: "platform.sqlite".to_string(),
            leader_lease_seconds: 30,
            job_lease_seconds: 120,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            workspace_root: "./workspace".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8080,
            nvd_api_key_env: Some("NVD_API_KEY".to_string()),
            retention: RetentionConfig::default(),
            security: SecurityConfig::default(),
            platform: PlatformConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub run: RunMetadata,
    pub summary: Summary,
    pub hosts: Vec<HostReport>,
    #[serde(default, rename = "unmappedEvents")]
    pub unmapped_events: Vec<CorrelatedEvent>,
    #[serde(default, rename = "networkAssets")]
    pub network_assets: Vec<NetworkAsset>,
    #[serde(default, rename = "topologyEdges")]
    pub topology_edges: Vec<TopologyEdge>,
    #[serde(default, rename = "monitoringLanes")]
    pub monitoring_lanes: Vec<MonitoringLane>,
    #[serde(default, rename = "intelMatches")]
    pub intel_matches: Vec<IntelMatch>,
    pub findings: Vec<Finding>,
    #[serde(default, rename = "triageActions")]
    pub triage_actions: Vec<TriageAction>,
    pub diff: Option<DiffReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: String,
    pub nazev: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub scope: Vec<IpNet>,
    pub ports: Vec<u16>,
    pub profile: String,
    pub enrichment_mode: String,
    pub provider: String,
    pub passive_window: PassiveWindow,
    pub sources: SourceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub time_window_s: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceMetadata {
    #[serde(default)]
    pub nmap_mode: Option<String>,
    pub nmap_xml: Option<String>,
    #[serde(default)]
    pub nmap_followup_xml: Option<String>,
    #[serde(default)]
    pub nmap_forensic_xml: Option<String>,
    pub suricata_eve: Option<String>,
    pub zeek_dir: Option<String>,
    #[serde(default)]
    pub snmp_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_base_url: Option<String>,
    #[serde(default)]
    pub meraki_snapshot: Option<String>,
    #[serde(default)]
    pub meraki_network_id: Option<String>,
    #[serde(default)]
    pub unifi_snapshot: Option<String>,
    #[serde(default)]
    pub aruba_snapshot: Option<String>,
    #[serde(default)]
    pub omada_snapshot: Option<String>,
    #[serde(default)]
    pub ntopng_snapshot: Option<String>,
    #[serde(default)]
    pub flow_snapshot: Option<String>,
    #[serde(default)]
    pub greenbone_report: Option<String>,
    #[serde(default)]
    pub wazuh_report: Option<String>,
    #[serde(default)]
    pub napalm_snapshot: Option<String>,
    #[serde(default)]
    pub netmiko_snapshot: Option<String>,
    #[serde(default)]
    pub scrapli_snapshot: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    #[serde(default)]
    pub hosts_total: usize,
    #[serde(default)]
    pub services_total: usize,
    #[serde(default)]
    pub cves_total: usize,
    #[serde(default)]
    pub events_total: usize,
    #[serde(default)]
    pub unmapped_events_total: usize,
    #[serde(default)]
    pub findings_total: usize,
    #[serde(default)]
    pub services_high_priority: usize,
    #[serde(default)]
    pub web_probes_total: usize,
    #[serde(default)]
    pub active_checks_total: usize,
    #[serde(default)]
    pub network_assets_total: usize,
    #[serde(default)]
    pub wireless_clients_total: usize,
    #[serde(default)]
    pub topology_edges_total: usize,
    #[serde(default)]
    pub triage_actions_total: usize,
    #[serde(default)]
    pub monitoring_lanes_total: usize,
    #[serde(default)]
    pub live_lanes_total: usize,
    #[serde(default)]
    pub audit_lanes_total: usize,
    #[serde(default)]
    pub intel_matches_total: usize,
    #[serde(default)]
    pub audit_findings_total: usize,
    #[serde(default)]
    pub automation_agents_total: usize,
    #[serde(default)]
    pub automation_rounds_total: usize,
    #[serde(default)]
    pub periodic_cycles_total: usize,
    #[serde(default)]
    pub forensic_targets_total: usize,
    #[serde(default)]
    pub realtime_sources_total: usize,
    #[serde(default)]
    pub service_identity_high_confidence_total: usize,
    #[serde(default)]
    pub service_identity_coverage_ratio: f64,
    #[serde(default)]
    pub tooling_coverage_ratio: f64,
    #[serde(default)]
    pub mas_parallelism_ratio: f64,
    #[serde(default)]
    pub mas_queue_wait_ms_avg: f64,
    #[serde(default)]
    pub mas_agent_sla_ratio: f64,
    #[serde(default)]
    pub mas_consensus_score: f64,
    #[serde(default)]
    pub mas_consensus_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostReport {
    pub host_id: String,
    pub host_key: String,
    pub ip: String,
    pub hostname: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    pub services: Vec<ServiceReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceReport {
    pub service_id: String,
    pub service_key: String,
    pub proto: String,
    pub port: u16,
    pub port_state: String,
    pub state_reason: Option<String>,
    pub inventory: InventoryRecord,
    pub cpe: Vec<CpeCandidate>,
    pub cves: Vec<CveRecord>,
    pub events: Vec<CorrelatedEvent>,
    #[serde(default, rename = "webProbe")]
    pub web_probe: Option<WebProbeRecord>,
    #[serde(default, rename = "activeChecks")]
    pub active_checks: Vec<ActiveCheckRecord>,
    pub score: f64,
    pub priorita: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryRecord {
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub detection_source: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeCandidate {
    #[serde(rename = "cpe23Uri")]
    pub cpe23_uri: String,
    pub method: String,
    pub confidence: Confidence,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    #[serde(rename = "cveId")]
    pub cve_id: String,
    pub summary: Option<String>,
    pub cvss: Option<CvssRecord>,
    pub source: String,
    pub retrieved_at: DateTime<Utc>,
    pub references: Vec<String>,
    #[serde(default)]
    pub exploit_context: Option<ExploitContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssRecord {
    pub version: String,
    pub base_score: f64,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExploitContext {
    #[serde(default)]
    pub epss: Option<EpssRecord>,
    #[serde(default)]
    pub cisa_kev: Option<KevRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssRecord {
    pub score: f64,
    pub percentile: f64,
    pub date: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevRecord {
    pub known_exploited: bool,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub short_description: Option<String>,
    pub date_added: Option<String>,
    pub due_date: Option<String>,
    pub required_action: Option<String>,
    pub known_ransomware_campaign_use: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebProbeRecord {
    pub source: String,
    pub scanned_at: DateTime<Utc>,
    pub url: String,
    pub final_url: Option<String>,
    pub scheme: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub webserver: Option<String>,
    pub technologies: Vec<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub favicon_mmh3: Option<i64>,
    pub tls_subject_cn: Option<String>,
    pub tls_subject_an: Vec<String>,
    pub tls_issuer_cn: Option<String>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveCheckRecord {
    pub check_id: String,
    pub source: String,
    pub template_id: String,
    pub template_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub matched_at: DateTime<Utc>,
    pub matched_url: String,
    pub matcher_name: Option<String>,
    pub description: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<String>,
    pub dst_ip: String,
    pub proto: String,
    pub dst_port: Option<u16>,
    pub event_type: String,
    pub severity: Severity,
    pub source: String,
    pub rule_id: Option<String>,
    pub message: String,
    pub raw_ref: Option<String>,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub event: NormalizedEvent,
    pub correlation: CorrelationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationInfo {
    pub method: String,
    pub confidence: Confidence,
    pub time_window_s: i64,
    pub host_id: Option<String>,
    pub service_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub base_run_id: String,
    pub new_hosts: Vec<String>,
    pub removed_hosts: Vec<String>,
    pub changed_services: Vec<ServiceChange>,
    pub new_cves: Vec<CveDiffItem>,
    pub new_events: Vec<EventDiffItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChange {
    pub service_key: String,
    pub change_type: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDiffItem {
    pub service_key: String,
    pub cve_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDiffItem {
    pub service_key: Option<String>,
    pub event_id: String,
    pub event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub finding_type: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host_key: Option<String>,
    pub service_key: Option<String>,
    pub rationale: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAsset {
    pub asset_id: String,
    pub asset_type: String,
    pub name: String,
    pub source: String,
    pub confidence: Confidence,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub status: Option<String>,
    pub location: Option<String>,
    pub linked_host_key: Option<String>,
    #[serde(default)]
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub edge_id: String,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub relation: String,
    pub source: String,
    pub confidence: Confidence,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageAction {
    pub action_id: String,
    pub action_type: String,
    pub title: String,
    pub priority: Severity,
    pub rationale: String,
    pub target_asset_id: Option<String>,
    pub target_service_key: Option<String>,
    #[serde(default)]
    pub recommended_tools: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringLane {
    pub lane_id: String,
    pub lane_type: String,
    pub source: String,
    pub title: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub recommended_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelMatch {
    pub match_id: String,
    pub source: String,
    pub indicator_type: String,
    pub indicator: String,
    pub status: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub summary: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub linked_host_key: Option<String>,
    #[serde(default)]
    pub linked_service_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn weight(self) -> f64 {
        match self {
            Self::Low => 0.5,
            Self::Medium => 0.75,
            Self::High => 1.0,
        }
    }
}

impl Severity {
    pub fn from_numeric(value: i64) -> Self {
        match value {
            0 | 1 => Self::High,
            2 => Self::Medium,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIndexEntry {
    pub run_id: String,
    pub nazev: String,
    pub created_at: DateTime<Utc>,
    pub scope: Vec<IpNet>,
    pub hosts_total: usize,
    pub services_total: usize,
    pub cves_total: usize,
    pub events_total: usize,
    #[serde(default)]
    pub findings_total: usize,
    #[serde(default)]
    pub triage_actions_total: usize,
    #[serde(default)]
    pub monitoring_lanes_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunIndex {
    pub runs: Vec<RunIndexEntry>,
}
