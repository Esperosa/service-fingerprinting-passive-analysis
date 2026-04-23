use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{BakulaError, Result},
    model::AppConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    Operator,
    Analyst,
    Viewer,
}

impl Role {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "analyst" => Ok(Self::Analyst),
            "viewer" => Ok(Self::Viewer),
            other => Err(BakulaError::Config(format!(
                "Neplatna role {other}. Povolené role: admin, operator, analyst, viewer."
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Analyst => "analyst",
            Self::Viewer => "viewer",
        }
    }

    pub fn permissions(&self) -> &'static [&'static str] {
        match self {
            Self::Admin => &["*"],
            Self::Operator => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "jobs.write",
                "jobs.execute",
                "cluster.read",
                "cluster.manage",
            ],
            Self::Analyst => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "jobs.write",
                "cluster.read",
            ],
            Self::Viewer => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "cluster.read",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuedToken {
    pub username: String,
    pub role: String,
    pub token_name: String,
    pub raw_token: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthIdentity {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub token_name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobSpec {
    pub workspace_root: String,
    pub nazev: String,
    pub scope: Vec<String>,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub supplement_vulners: bool,
    #[serde(default)]
    pub freeze: bool,
    pub nmap_xml: Option<String>,
    #[serde(default)]
    pub nmap_followup_xml: Option<String>,
    pub suricata_eve: Option<String>,
    pub zeek_dir: Option<String>,
    #[serde(default)]
    pub porovnat_s: Option<String>,
    #[serde(default)]
    pub spustit_nmap: bool,
    #[serde(default)]
    pub web_fingerprint: bool,
    #[serde(default)]
    pub web_checks: bool,
    #[serde(default)]
    pub pentest: bool,
    #[serde(default)]
    pub aggressive_pentest: bool,
    #[serde(default)]
    pub httpx_bin: Option<String>,
    #[serde(default)]
    pub nuclei_bin: Option<String>,
    #[serde(default)]
    pub nuclei_templates: Option<String>,
    #[serde(default)]
    pub snmp_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_base_url: Option<String>,
    #[serde(default = "default_librenms_token_env")]
    pub librenms_token_env: String,
    #[serde(default)]
    pub meraki_snapshot: Option<String>,
    #[serde(default)]
    pub meraki_network_id: Option<String>,
    #[serde(default = "default_meraki_token_env")]
    pub meraki_api_key_env: String,
    #[serde(default = "default_meraki_timespan")]
    pub meraki_timespan_seconds: u32,
    #[serde(default)]
    pub unifi_snapshot: Option<String>,
    #[serde(default)]
    pub unifi_devices_url: Option<String>,
    #[serde(default)]
    pub unifi_clients_url: Option<String>,
    #[serde(default)]
    pub unifi_links_url: Option<String>,
    #[serde(default = "default_unifi_token_env")]
    pub unifi_api_key_env: String,
    #[serde(default)]
    pub aruba_snapshot: Option<String>,
    #[serde(default)]
    pub aruba_base_url: Option<String>,
    #[serde(default = "default_aruba_token_env")]
    pub aruba_token_env: String,
    #[serde(default)]
    pub aruba_site_id: Option<String>,
    #[serde(default)]
    pub omada_snapshot: Option<String>,
    #[serde(default)]
    pub omada_devices_url: Option<String>,
    #[serde(default)]
    pub omada_clients_url: Option<String>,
    #[serde(default)]
    pub omada_links_url: Option<String>,
    #[serde(default = "default_omada_token_env")]
    pub omada_access_token_env: String,
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
    #[serde(default = "default_urlhaus_auth_env")]
    pub urlhaus_auth_env: String,
    #[serde(default = "default_abuseipdb_key_env")]
    pub abuseipdb_key_env: String,
    #[serde(default)]
    pub disable_circl: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobRecord {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub next_run_at: DateTime<Utc>,
    pub schedule_interval_s: Option<i64>,
    pub claimed_by: Option<String>,
    pub claim_until: Option<DateTime<Utc>>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub last_run_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub display_name: String,
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
    pub leader_until: Option<DateTime<Utc>>,
    pub capabilities: Vec<String>,
    pub software_version: Option<String>,
    pub desired_version: Option<String>,
    pub ready: bool,
    pub drain_state: String,
    pub upgrade_state: String,
    pub last_upgrade_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaPolicy {
    pub quorum_size: i64,
    pub min_ready_nodes: i64,
    pub rollout_batch_size: i64,
    pub target_version: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HaCandidate {
    pub node_id: String,
    pub current_version: Option<String>,
    pub target_version: Option<String>,
    pub eligible: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HaStatus {
    pub policy: Option<HaPolicy>,
    pub active_nodes: usize,
    pub ready_nodes: usize,
    pub upgrading_nodes: usize,
    pub quorum_ok: bool,
    pub candidates: Vec<HaCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformSnapshot {
    pub users: Vec<UserRecord>,
    pub jobs: Vec<JobRecord>,
    pub nodes: Vec<NodeRecord>,
    pub leader_node_id: Option<String>,
    pub leader_until: Option<DateTime<Utc>>,
    pub ha_status: Option<HaStatus>,
}

#[derive(Debug, Clone)]
pub struct ClaimedJob {
    pub id: i64,
    pub name: String,
    pub schedule_interval_s: Option<i64>,
    pub spec: PipelineJobSpec,
}

pub fn init_database(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = open_connection(path)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            spec_json TEXT NOT NULL,
            schedule_interval_s INTEGER,
            next_run_at TEXT NOT NULL,
            claimed_by TEXT,
            claim_until TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            last_run_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL,
            last_heartbeat TEXT NOT NULL,
            leader_until TEXT,
            capabilities_json TEXT NOT NULL,
            software_version TEXT,
            desired_version TEXT,
            ready INTEGER NOT NULL DEFAULT 1,
            drain_state TEXT NOT NULL DEFAULT 'ready',
            upgrade_state TEXT NOT NULL DEFAULT 'idle',
            last_upgrade_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ha_policy (
            policy_key TEXT PRIMARY KEY,
            quorum_size INTEGER NOT NULL,
            min_ready_nodes INTEGER NOT NULL,
            rollout_batch_size INTEGER NOT NULL,
            target_version TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_jobs_due ON jobs(status, next_run_at);
        CREATE INDEX IF NOT EXISTS idx_nodes_last_heartbeat ON nodes(last_heartbeat);
        ",
    )
    .map_err(to_processing_error)?;
    add_column_if_missing(&conn, "nodes", "software_version", "TEXT")?;
    add_column_if_missing(&conn, "nodes", "desired_version", "TEXT")?;
    add_column_if_missing(&conn, "nodes", "ready", "INTEGER NOT NULL DEFAULT 1")?;
    add_column_if_missing(
        &conn,
        "nodes",
        "drain_state",
        "TEXT NOT NULL DEFAULT 'ready'",
    )?;
    add_column_if_missing(
        &conn,
        "nodes",
        "upgrade_state",
        "TEXT NOT NULL DEFAULT 'idle'",
    )?;
    add_column_if_missing(&conn, "nodes", "last_upgrade_at", "TEXT")?;
    Ok(())
}

pub fn init_platform_from_config(config: &AppConfig) -> Result<Option<PathBuf>> {
    let Some(path) = crate::config::resolve_platform_db_path(config) else {
        return Ok(None);
    };
    init_database(&path)?;
    Ok(Some(path))
}

pub fn create_or_update_user(path: &Path, username: &str, role: Role) -> Result<UserRecord> {
    let conn = open_connection(path)?;
    let now = now_string();
    conn.execute(
        "
        INSERT INTO users (username, role, enabled, created_at)
        VALUES (?1, ?2, 1, ?3)
        ON CONFLICT(username) DO UPDATE SET role = excluded.role, enabled = 1
        ",
        params![username, role.as_str(), now],
    )
    .map_err(to_processing_error)?;
    load_user_by_username(&conn, username)?
        .ok_or_else(|| BakulaError::Processing(format!("Uzivatel {username} nebyl ulozen.")))
}

pub fn issue_token(path: &Path, username: &str, token_name: &str) -> Result<IssuedToken> {
    let conn = open_connection(path)?;
    let user = load_user_by_username(&conn, username)?
        .ok_or_else(|| BakulaError::Processing(format!("Uzivatel {username} neexistuje.")))?;
    let raw_token = format!("bakula_{}_{}", username, Uuid::new_v4().simple());
    let token_hash = hash_token(&raw_token);
    let created_at = Utc::now();
    conn.execute(
        "
        INSERT INTO api_tokens (user_id, name, token_hash, enabled, created_at)
        VALUES (?1, ?2, ?3, 1, ?4)
        ",
        params![user.id, token_name, token_hash, format_dt(created_at)],
    )
    .map_err(to_processing_error)?;
    Ok(IssuedToken {
        username: user.username,
        role: user.role,
        token_name: token_name.to_string(),
        raw_token,
        created_at,
    })
}

pub fn authenticate_token(path: &Path, raw_token: &str) -> Result<Option<AuthIdentity>> {
    let conn = open_connection(path)?;
    let token_hash = hash_token(raw_token);
    let row = conn
        .query_row(
            "
            SELECT users.id, users.username, users.role, api_tokens.name
            FROM api_tokens
            JOIN users ON users.id = api_tokens.user_id
            WHERE api_tokens.token_hash = ?1
              AND api_tokens.enabled = 1
              AND users.enabled = 1
            ",
            params![token_hash],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;

    let Some((user_id, username, role_name, token_name)) = row else {
        return Ok(None);
    };
    let role = Role::parse(&role_name)?;
    conn.execute(
        "UPDATE api_tokens SET last_used_at = ?1 WHERE token_hash = ?2",
        params![now_string(), token_hash],
    )
    .map_err(to_processing_error)?;
    Ok(Some(AuthIdentity {
        user_id,
        username,
        role: role.as_str().to_string(),
        token_name,
        permissions: role
            .permissions()
            .iter()
            .map(|item| item.to_string())
            .collect(),
    }))
}

pub fn list_users(path: &Path) -> Result<Vec<UserRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare("SELECT id, username, role, enabled, created_at FROM users ORDER BY username ASC")
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        })
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn list_jobs(path: &Path) -> Result<Vec<JobRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT id, name, status, next_run_at, schedule_interval_s, claimed_by, claim_until,
                   attempts, last_error, last_run_id, created_at, updated_at
            FROM jobs
            ORDER BY created_at DESC, id DESC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], map_job_row)
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn list_nodes(path: &Path) -> Result<Vec<NodeRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
                   software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
            FROM nodes
            ORDER BY node_id ASC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], |row| {
            let capabilities_json: String = row.get(5)?;
            Ok(NodeRecord {
                node_id: row.get(0)?,
                display_name: row.get(1)?,
                status: row.get(2)?,
                last_heartbeat: parse_dt(&row.get::<_, String>(3)?).map_err(to_rusqlite_error)?,
                leader_until: row
                    .get::<_, Option<String>>(4)?
                    .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
                    .transpose()?,
                capabilities: serde_json::from_str(&capabilities_json)
                    .map_err(|error| to_rusqlite_error(BakulaError::Json(error)))?,
                software_version: row.get(6)?,
                desired_version: row.get(7)?,
                ready: row.get::<_, i64>(8)? != 0,
                drain_state: row.get(9)?,
                upgrade_state: row.get(10)?,
                last_upgrade_at: row
                    .get::<_, Option<String>>(11)?
                    .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
                    .transpose()?,
            })
        })
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn snapshot(path: &Path) -> Result<PlatformSnapshot> {
    let nodes = list_nodes(path)?;
    let users = list_users(path)?;
    let jobs = list_jobs(path)?;
    let ha_status = ha_status(path, Some(&nodes)).ok();
    let leader = nodes
        .iter()
        .filter_map(|node| node.leader_until.map(|until| (node.node_id.clone(), until)))
        .filter(|(_, until)| *until > Utc::now())
        .max_by(|left, right| left.1.cmp(&right.1));
    Ok(PlatformSnapshot {
        users,
        jobs,
        nodes,
        leader_node_id: leader.as_ref().map(|item| item.0.clone()),
        leader_until: leader.map(|item| item.1),
        ha_status,
    })
}

pub fn upsert_node_heartbeat(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    let now = now_string();
    let caps = serde_json::to_string(capabilities).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO nodes (
            node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
            software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
        )
        VALUES (?1, ?2, 'follower', ?3, NULL, ?4, NULL, NULL, 1, 'ready', 'idle', NULL)
        ON CONFLICT(node_id) DO UPDATE SET
            display_name = excluded.display_name,
            last_heartbeat = excluded.last_heartbeat,
            capabilities_json = excluded.capabilities_json
        ",
        params![node_id, display_name, now, caps],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl ulozen.")))
}

pub fn register_managed_node(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    software_version: &str,
    ready: bool,
) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    let caps = serde_json::to_string(capabilities).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO nodes (
            node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
            software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
        )
        VALUES (?1, ?2, 'follower', ?3, NULL, ?4, ?5, ?5, ?6, 'ready', 'idle', NULL)
        ON CONFLICT(node_id) DO UPDATE SET
            display_name = excluded.display_name,
            last_heartbeat = excluded.last_heartbeat,
            capabilities_json = excluded.capabilities_json,
            software_version = excluded.software_version,
            desired_version = COALESCE(nodes.desired_version, excluded.software_version),
            ready = excluded.ready
        ",
        params![
            node_id,
            display_name,
            now_string(),
            caps,
            software_version,
            if ready { 1 } else { 0 }
        ],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl ulozen.")))
}

pub fn acquire_leader_lease(path: &Path, node_id: &str, ttl_seconds: i64) -> Result<bool> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let current = tx
        .query_row(
            "
            SELECT node_id, leader_until
            FROM nodes
            WHERE leader_until IS NOT NULL
            ORDER BY leader_until DESC
            LIMIT 1
            ",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(to_processing_error)?;
    let can_take = match current {
        None => true,
        Some((leader_id, leader_until)) => {
            let until = parse_dt(&leader_until)?;
            leader_id == node_id || until <= now
        }
    };
    if can_take {
        tx.execute(
            "UPDATE nodes SET status = 'follower', leader_until = NULL WHERE node_id <> ?1",
            params![node_id],
        )
        .map_err(to_processing_error)?;
        tx.execute(
            "UPDATE nodes SET status = 'leader', leader_until = ?1, last_heartbeat = ?2 WHERE node_id = ?3",
            params![
                format_dt(now + chrono::Duration::seconds(ttl_seconds)),
                format_dt(now),
                node_id
            ],
        )
        .map_err(to_processing_error)?;
    } else {
        tx.execute(
            "UPDATE nodes SET status = 'follower', last_heartbeat = ?1 WHERE node_id = ?2",
            params![format_dt(now), node_id],
        )
        .map_err(to_processing_error)?;
    }
    tx.commit().map_err(to_processing_error)?;
    Ok(can_take)
}

pub fn set_ha_policy(
    path: &Path,
    quorum_size: i64,
    min_ready_nodes: i64,
    rollout_batch_size: i64,
    target_version: Option<&str>,
) -> Result<HaPolicy> {
    let conn = open_connection(path)?;
    let updated_at = Utc::now();
    conn.execute(
        "
        INSERT INTO ha_policy (policy_key, quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at)
        VALUES ('default', ?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(policy_key) DO UPDATE SET
            quorum_size = excluded.quorum_size,
            min_ready_nodes = excluded.min_ready_nodes,
            rollout_batch_size = excluded.rollout_batch_size,
            target_version = excluded.target_version,
            updated_at = excluded.updated_at
        ",
        params![
            quorum_size,
            min_ready_nodes,
            rollout_batch_size,
            target_version,
            format_dt(updated_at)
        ],
    )
    .map_err(to_processing_error)?;
    get_ha_policy(path)?.ok_or_else(|| {
        BakulaError::Processing("HA policy se nepodarilo nahrat po ulozeni.".to_string())
    })
}

pub fn get_ha_policy(path: &Path) -> Result<Option<HaPolicy>> {
    let conn = open_connection(path)?;
    conn.query_row(
        "
        SELECT quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at
        FROM ha_policy
        WHERE policy_key = 'default'
        ",
        [],
        |row| {
            Ok(HaPolicy {
                quorum_size: row.get(0)?,
                min_ready_nodes: row.get(1)?,
                rollout_batch_size: row.get(2)?,
                target_version: row.get(3)?,
                updated_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        },
    )
    .optional()
    .map_err(to_processing_error)
}

pub fn ha_status(path: &Path, prefetched_nodes: Option<&[NodeRecord]>) -> Result<HaStatus> {
    let nodes = match prefetched_nodes {
        Some(items) => items.to_vec(),
        None => list_nodes(path)?,
    };
    let policy = get_ha_policy(path)?;
    let active_nodes = nodes
        .iter()
        .filter(|node| node.last_heartbeat > Utc::now() - chrono::Duration::minutes(5))
        .count();
    let ready_nodes = nodes
        .iter()
        .filter(|node| node.ready && node.drain_state == "ready")
        .count();
    let upgrading_nodes = nodes
        .iter()
        .filter(|node| node.upgrade_state == "upgrading")
        .count();
    let candidates = build_ha_candidates(&nodes, policy.as_ref());
    let quorum_ok = policy.as_ref().is_none_or(|policy| {
        ready_nodes as i64 >= policy.quorum_size && ready_nodes as i64 >= policy.min_ready_nodes
    });
    Ok(HaStatus {
        policy,
        active_nodes,
        ready_nodes,
        upgrading_nodes,
        quorum_ok,
        candidates,
    })
}

pub fn advance_rollout(path: &Path) -> Result<Vec<String>> {
    let status = ha_status(path, None)?;
    let Some(policy) = status.policy.as_ref() else {
        return Ok(Vec::new());
    };
    let selected = status
        .candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .take(policy.rollout_batch_size.max(0) as usize)
        .map(|candidate| candidate.node_id.clone())
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(selected);
    }
    let conn = open_connection(path)?;
    let now = Utc::now();
    for node_id in &selected {
        conn.execute(
            "
            UPDATE nodes
            SET desired_version = ?1,
                ready = 0,
                drain_state = 'draining',
                upgrade_state = 'upgrading',
                last_upgrade_at = ?2
            WHERE node_id = ?3
            ",
            params![policy.target_version.clone(), format_dt(now), node_id],
        )
        .map_err(to_processing_error)?;
    }
    Ok(selected)
}

pub fn mark_node_ready(path: &Path, node_id: &str, software_version: &str) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    conn.execute(
        "
        UPDATE nodes
        SET software_version = ?1,
            desired_version = ?1,
            ready = 1,
            drain_state = 'ready',
            upgrade_state = 'idle',
            last_upgrade_at = ?2
        WHERE node_id = ?3
        ",
        params![software_version, now_string(), node_id],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl nalezen.")))
}

pub fn enqueue_job(
    path: &Path,
    name: &str,
    spec: &PipelineJobSpec,
    schedule_interval_s: Option<i64>,
    next_run_at: Option<DateTime<Utc>>,
) -> Result<i64> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let next = next_run_at.unwrap_or(now);
    let spec_json = serde_json::to_string(spec).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO jobs (
            name, status, spec_json, schedule_interval_s, next_run_at, claimed_by, claim_until,
            attempts, last_error, last_run_id, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0, NULL, NULL, ?6, ?6)
        ",
        params![
            name,
            if schedule_interval_s.is_some() {
                "scheduled"
            } else {
                "queued"
            },
            spec_json,
            schedule_interval_s,
            format_dt(next),
            format_dt(now),
        ],
    )
    .map_err(to_processing_error)?;
    Ok(conn.last_insert_rowid())
}

pub fn claim_due_job(
    path: &Path,
    node_id: &str,
    lease_seconds: i64,
    allow_scheduled_jobs: bool,
) -> Result<Option<ClaimedJob>> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let maybe_job = tx
        .query_row(
            "
            SELECT id, name, spec_json, schedule_interval_s
            FROM jobs
            WHERE next_run_at <= ?1
              AND status IN ('queued', 'scheduled', 'failed')
              AND (claim_until IS NULL OR claim_until <= ?1)
              AND (?2 = 1 OR schedule_interval_s IS NULL)
            ORDER BY next_run_at ASC, id ASC
            LIMIT 1
            ",
            params![format_dt(now), if allow_scheduled_jobs { 1 } else { 0 }],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;

    let Some((job_id, name, spec_json, schedule_interval_s)) = maybe_job else {
        tx.commit().map_err(to_processing_error)?;
        return Ok(None);
    };
    let spec = serde_json::from_str::<PipelineJobSpec>(&spec_json).map_err(BakulaError::Json)?;
    tx.execute(
        "
        UPDATE jobs
        SET status = 'running',
            claimed_by = ?1,
            claim_until = ?2,
            attempts = attempts + 1,
            updated_at = ?3,
            last_error = NULL
        WHERE id = ?4
        ",
        params![
            node_id,
            format_dt(now + chrono::Duration::seconds(lease_seconds)),
            format_dt(now),
            job_id
        ],
    )
    .map_err(to_processing_error)?;
    tx.commit().map_err(to_processing_error)?;
    Ok(Some(ClaimedJob {
        id: job_id,
        name,
        schedule_interval_s,
        spec,
    }))
}

pub fn list_due_job_ids(path: &Path) -> Result<Vec<i64>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT id
            FROM jobs
            WHERE next_run_at <= ?1
              AND status IN ('queued', 'scheduled', 'failed')
              AND (claim_until IS NULL OR claim_until <= ?1)
            ORDER BY next_run_at ASC, id ASC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map(params![format_dt(Utc::now())], |row| row.get::<_, i64>(0))
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn claim_job_by_id(
    path: &Path,
    job_id: i64,
    node_id: &str,
    lease_seconds: i64,
) -> Result<Option<ClaimedJob>> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let maybe_job = tx
        .query_row(
            "
            SELECT id, name, spec_json, schedule_interval_s
            FROM jobs
            WHERE id = ?1
              AND next_run_at <= ?2
              AND status IN ('queued', 'scheduled', 'failed')
              AND (claim_until IS NULL OR claim_until <= ?2)
            ",
            params![job_id, format_dt(now)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;
    let Some((job_id, name, spec_json, schedule_interval_s)) = maybe_job else {
        tx.commit().map_err(to_processing_error)?;
        return Ok(None);
    };
    let spec = serde_json::from_str::<PipelineJobSpec>(&spec_json).map_err(BakulaError::Json)?;
    tx.execute(
        "
        UPDATE jobs
        SET status = 'running',
            claimed_by = ?1,
            claim_until = ?2,
            attempts = attempts + 1,
            updated_at = ?3,
            last_error = NULL
        WHERE id = ?4
        ",
        params![
            node_id,
            format_dt(now + chrono::Duration::seconds(lease_seconds)),
            format_dt(now),
            job_id
        ],
    )
    .map_err(to_processing_error)?;
    tx.commit().map_err(to_processing_error)?;
    Ok(Some(ClaimedJob {
        id: job_id,
        name,
        schedule_interval_s,
        spec,
    }))
}

pub fn mark_job_succeeded(
    path: &Path,
    job_id: i64,
    run_id: &str,
    schedule_interval_s: Option<i64>,
) -> Result<()> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let (status, next_run_at) = if let Some(interval) = schedule_interval_s {
        (
            "scheduled",
            Some(format_dt(now + chrono::Duration::seconds(interval))),
        )
    } else {
        ("succeeded", None)
    };
    conn.execute(
        "
        UPDATE jobs
        SET status = ?1,
            next_run_at = COALESCE(?2, next_run_at),
            claimed_by = NULL,
            claim_until = NULL,
            updated_at = ?3,
            last_run_id = ?4,
            last_error = NULL
        WHERE id = ?5
        ",
        params![status, next_run_at, format_dt(now), run_id, job_id],
    )
    .map_err(to_processing_error)?;
    Ok(())
}

pub fn mark_job_failed(
    path: &Path,
    job_id: i64,
    error: &str,
    schedule_interval_s: Option<i64>,
) -> Result<()> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let (status, next_run_at) = if let Some(interval) = schedule_interval_s {
        (
            "scheduled",
            format_dt(now + chrono::Duration::seconds(interval.max(30))),
        )
    } else {
        ("failed", format_dt(now))
    };
    conn.execute(
        "
        UPDATE jobs
        SET status = ?1,
            next_run_at = ?2,
            claimed_by = NULL,
            claim_until = NULL,
            updated_at = ?3,
            last_error = ?4
        WHERE id = ?5
        ",
        params![
            status,
            next_run_at,
            format_dt(now),
            truncate_error(error),
            job_id
        ],
    )
    .map_err(to_processing_error)?;
    Ok(())
}

pub fn worker_cycle<F>(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    leader_ttl_seconds: i64,
    job_lease_seconds: i64,
    mut executor: F,
) -> Result<Option<String>>
where
    F: FnMut(PipelineJobSpec) -> std::result::Result<String, String>,
{
    upsert_node_heartbeat(path, node_id, display_name, capabilities)?;
    let is_leader = acquire_leader_lease(path, node_id, leader_ttl_seconds)?;
    let Some(job) = claim_due_job(path, node_id, job_lease_seconds, is_leader)? else {
        return Ok(None);
    };
    match executor(job.spec) {
        Ok(run_id) => {
            mark_job_succeeded(path, job.id, &run_id, job.schedule_interval_s)?;
            Ok(Some(run_id))
        }
        Err(error) => {
            mark_job_failed(path, job.id, &error, job.schedule_interval_s)?;
            Err(BakulaError::Processing(format!(
                "Job {} ({}) selhal: {error}",
                job.id, job.name
            )))
        }
    }
}

pub fn worker_loop<F>(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    leader_ttl_seconds: i64,
    job_lease_seconds: i64,
    mut executor: F,
    idle_sleep: Duration,
) where
    F: FnMut(PipelineJobSpec) -> std::result::Result<String, String>,
{
    loop {
        let _ = worker_cycle(
            path,
            node_id,
            display_name,
            capabilities,
            leader_ttl_seconds,
            job_lease_seconds,
            |spec| executor(spec),
        );
        thread::sleep(idle_sleep);
    }
}

fn load_user_by_username(conn: &Connection, username: &str) -> Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, username, role, enabled, created_at FROM users WHERE username = ?1",
        params![username],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        },
    )
    .optional()
    .map_err(to_processing_error)
}

fn open_connection(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(to_processing_error)?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(to_processing_error)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(to_processing_error)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(to_processing_error)?;
    Ok(conn)
}

fn build_ha_candidates(nodes: &[NodeRecord], policy: Option<&HaPolicy>) -> Vec<HaCandidate> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let ready_nodes = nodes
        .iter()
        .filter(|node| node.ready && node.drain_state == "ready")
        .count() as i64;
    let upgrading_nodes = nodes
        .iter()
        .filter(|node| node.upgrade_state == "upgrading")
        .count() as i64;
    nodes
        .iter()
        .filter(
            |node| match (&node.software_version, &policy.target_version) {
                (_, None) => false,
                (Some(current), Some(target)) => current != target,
                (None, Some(_)) => true,
            },
        )
        .map(|node| {
            let mut eligible = true;
            let mut reason = None;
            if !node.ready || node.drain_state != "ready" || node.upgrade_state != "idle" {
                eligible = false;
                reason = Some("uzel neni v pripravenem stavu".to_string());
            } else if upgrading_nodes >= policy.rollout_batch_size {
                eligible = false;
                reason = Some("dosazen rollout batch limit".to_string());
            } else if ready_nodes - 1 < policy.quorum_size
                || ready_nodes - 1 < policy.min_ready_nodes
            {
                eligible = false;
                reason = Some("upgrade by porusil quorum nebo minimum ready uzlu".to_string());
            }
            HaCandidate {
                node_id: node.node_id.clone(),
                current_version: node.software_version.clone(),
                target_version: policy.target_version.clone(),
                eligible,
                reason,
            }
        })
        .collect()
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    match conn.execute(&sql, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message.contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(error) => Err(to_processing_error(error)),
    }
}

fn map_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        status: row.get(2)?,
        next_run_at: parse_dt(&row.get::<_, String>(3)?).map_err(to_rusqlite_error)?,
        schedule_interval_s: row.get(4)?,
        claimed_by: row.get(5)?,
        claim_until: row
            .get::<_, Option<String>>(6)?
            .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
            .transpose()?,
        attempts: row.get(7)?,
        last_error: row.get(8)?,
        last_run_id: row.get(9)?,
        created_at: parse_dt(&row.get::<_, String>(10)?).map_err(to_rusqlite_error)?,
        updated_at: parse_dt(&row.get::<_, String>(11)?).map_err(to_rusqlite_error)?,
    })
}

fn hash_token(raw_token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(raw_token.as_bytes());
    format!("{:x}", digest.finalize())
}

fn now_string() -> String {
    format_dt(Utc::now())
}

fn format_dt(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

fn parse_dt(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|item| item.with_timezone(&Utc))
        .map_err(|error| {
            BakulaError::Processing(format!("Nelze zpracovat datum/cas {value}: {error}"))
        })
}

fn truncate_error(value: &str) -> String {
    value.chars().take(4000).collect()
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(to_processing_error)?);
    }
    Ok(items)
}

fn to_processing_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("SQLite chyba: {error}"))
}

fn to_rusqlite_error(error: BakulaError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn default_ports() -> Vec<u16> {
    vec![21, 22, 23, 80, 443, 8080]
}

fn default_profile() -> String {
    "bezny".to_string()
}

fn default_provider() -> String {
    "demo".to_string()
}

fn default_librenms_token_env() -> String {
    "LIBRENMS_TOKEN".to_string()
}

fn default_meraki_token_env() -> String {
    "MERAKI_DASHBOARD_API_KEY".to_string()
}

fn default_meraki_timespan() -> u32 {
    86400
}

fn default_unifi_token_env() -> String {
    "UNIFI_API_KEY".to_string()
}

fn default_aruba_token_env() -> String {
    "ARUBA_CENTRAL_TOKEN".to_string()
}

fn default_omada_token_env() -> String {
    "OMADA_ACCESS_TOKEN".to_string()
}

fn default_urlhaus_auth_env() -> String {
    "URLHAUS_AUTH_KEY".to_string()
}

fn default_abuseipdb_key_env() -> String {
    "ABUSEIPDB_API_KEY".to_string()
}
