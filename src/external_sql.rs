use chrono::Utc;
use postgres::{Client, NoTls, Row};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{BakulaError, Result},
    platform::{
        AuthIdentity, HaCandidate, HaPolicy, HaStatus, IssuedToken, JobRecord, NodeRecord,
        PlatformSnapshot, Role, UserRecord,
    },
};

pub fn init_database(db_uri: &str) -> Result<()> {
    let mut client = connect(db_uri)?;
    client
        .batch_execute(
            "
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_tokens (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL,
                last_used_at TIMESTAMPTZ
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                next_run_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                status TEXT NOT NULL,
                last_heartbeat TIMESTAMPTZ NOT NULL,
                leader_until TIMESTAMPTZ,
                capabilities_json TEXT NOT NULL,
                software_version TEXT,
                desired_version TEXT,
                ready BOOLEAN NOT NULL DEFAULT TRUE,
                drain_state TEXT NOT NULL DEFAULT 'ready',
                upgrade_state TEXT NOT NULL DEFAULT 'idle',
                last_upgrade_at TIMESTAMPTZ
            );
            CREATE TABLE IF NOT EXISTS ha_policy (
                policy_key TEXT PRIMARY KEY,
                quorum_size BIGINT NOT NULL,
                min_ready_nodes BIGINT NOT NULL,
                rollout_batch_size BIGINT NOT NULL,
                target_version TEXT,
                updated_at TIMESTAMPTZ NOT NULL
            );
            ",
        )
        .map_err(to_processing_error)?;
    Ok(())
}

pub fn create_or_update_user(db_uri: &str, username: &str, role: Role) -> Result<UserRecord> {
    let mut client = connect(db_uri)?;
    let row = client
        .query_one(
            "
            INSERT INTO users (username, role, enabled, created_at)
            VALUES ($1, $2, TRUE, NOW())
            ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role, enabled = TRUE
            RETURNING id, username, role, enabled, created_at
            ",
            &[&username, &role.as_str()],
        )
        .map_err(to_processing_error)?;
    map_user_row(&row)
}

pub fn issue_token(db_uri: &str, username: &str, token_name: &str) -> Result<IssuedToken> {
    let mut client = connect(db_uri)?;
    let user = client
        .query_opt(
            "SELECT id, username, role FROM users WHERE username = $1 AND enabled = TRUE",
            &[&username],
        )
        .map_err(to_processing_error)?
        .ok_or_else(|| BakulaError::Processing(format!("Uzivatel {username} neexistuje.")))?;
    let user_id: i64 = user.get(0);
    let username: String = user.get(1);
    let role: String = user.get(2);
    let raw_token = format!("bakula_pg_{}_{}", username, Uuid::new_v4().simple());
    client
        .execute(
            "
            INSERT INTO api_tokens (user_id, name, token_hash, enabled, created_at)
            VALUES ($1, $2, $3, TRUE, NOW())
            ",
            &[&user_id, &token_name, &hash_token(&raw_token)],
        )
        .map_err(to_processing_error)?;
    Ok(IssuedToken {
        username,
        role,
        token_name: token_name.to_string(),
        raw_token,
        created_at: Utc::now(),
    })
}

pub fn authenticate_token(db_uri: &str, raw_token: &str) -> Result<Option<AuthIdentity>> {
    let mut client = connect(db_uri)?;
    let row = client
        .query_opt(
            "
            SELECT users.id, users.username, users.role, api_tokens.name
            FROM api_tokens
            JOIN users ON users.id = api_tokens.user_id
            WHERE api_tokens.token_hash = $1
              AND api_tokens.enabled = TRUE
              AND users.enabled = TRUE
            ",
            &[&hash_token(raw_token)],
        )
        .map_err(to_processing_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role = Role::parse(row.get::<_, String>(2).as_str())?;
    Ok(Some(AuthIdentity {
        user_id: row.get(0),
        username: row.get(1),
        role: role.as_str().to_string(),
        token_name: row.get(3),
        permissions: role
            .permissions()
            .iter()
            .map(|item| item.to_string())
            .collect(),
    }))
}

pub fn list_users(db_uri: &str) -> Result<Vec<UserRecord>> {
    let mut client = connect(db_uri)?;
    let rows = client
        .query(
            "SELECT id, username, role, enabled, created_at FROM users ORDER BY username ASC",
            &[],
        )
        .map_err(to_processing_error)?;
    rows.iter().map(map_user_row).collect()
}

pub fn enqueue_job(db_uri: &str, name: &str) -> Result<i64> {
    let mut client = connect(db_uri)?;
    let row = client
        .query_one(
            "
            INSERT INTO jobs (name, status, next_run_at, created_at, updated_at)
            VALUES ($1, 'queued', NOW(), NOW(), NOW())
            RETURNING id
            ",
            &[&name],
        )
        .map_err(to_processing_error)?;
    Ok(row.get(0))
}

pub fn list_jobs(db_uri: &str) -> Result<Vec<JobRecord>> {
    let mut client = connect(db_uri)?;
    let rows = client
        .query(
            "
            SELECT id, name, status, next_run_at, NULL::BIGINT AS schedule_interval_s, NULL::TEXT AS claimed_by,
                   NULL::TIMESTAMPTZ AS claim_until, 0::BIGINT AS attempts, NULL::TEXT AS last_error,
                   NULL::TEXT AS last_run_id, created_at, updated_at
            FROM jobs
            ORDER BY created_at DESC, id DESC
            ",
            &[],
        )
        .map_err(to_processing_error)?;
    rows.iter().map(map_job_row).collect()
}

pub fn register_managed_node(
    db_uri: &str,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    software_version: &str,
    ready: bool,
) -> Result<NodeRecord> {
    let mut client = connect(db_uri)?;
    let capabilities_json = serde_json::to_string(capabilities).map_err(BakulaError::Json)?;
    let row = client
        .query_one(
            "
            INSERT INTO nodes (
                node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
                software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
            ) VALUES ($1, $2, 'follower', NOW(), NULL, $3, $4, $4, $5, 'ready', 'idle', NULL)
            ON CONFLICT (node_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                last_heartbeat = NOW(),
                capabilities_json = EXCLUDED.capabilities_json,
                software_version = EXCLUDED.software_version,
                desired_version = COALESCE(nodes.desired_version, EXCLUDED.software_version),
                ready = EXCLUDED.ready
            RETURNING node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
                      software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
            ",
            &[&node_id, &display_name, &capabilities_json, &software_version, &ready],
        )
        .map_err(to_processing_error)?;
    map_node_row(&row)
}

pub fn set_ha_policy(
    db_uri: &str,
    quorum_size: i64,
    min_ready_nodes: i64,
    rollout_batch_size: i64,
    target_version: Option<&str>,
) -> Result<HaPolicy> {
    let mut client = connect(db_uri)?;
    let row = client
        .query_one(
            "
            INSERT INTO ha_policy (policy_key, quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at)
            VALUES ('default', $1, $2, $3, $4, NOW())
            ON CONFLICT (policy_key) DO UPDATE SET
                quorum_size = EXCLUDED.quorum_size,
                min_ready_nodes = EXCLUDED.min_ready_nodes,
                rollout_batch_size = EXCLUDED.rollout_batch_size,
                target_version = EXCLUDED.target_version,
                updated_at = NOW()
            RETURNING quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at
            ",
            &[&quorum_size, &min_ready_nodes, &rollout_batch_size, &target_version],
        )
        .map_err(to_processing_error)?;
    map_policy_row(&row)
}

pub fn list_nodes(db_uri: &str) -> Result<Vec<NodeRecord>> {
    let mut client = connect(db_uri)?;
    let rows = client
        .query(
            "
            SELECT node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
                   software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
            FROM nodes
            ORDER BY node_id ASC
            ",
            &[],
        )
        .map_err(to_processing_error)?;
    rows.iter().map(map_node_row).collect()
}

pub fn snapshot(db_uri: &str) -> Result<PlatformSnapshot> {
    let users = list_users(db_uri)?;
    let jobs = list_jobs(db_uri)?;
    let nodes = list_nodes(db_uri)?;
    let ha_status = ha_status(db_uri, Some(&nodes)).ok();
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

pub fn ha_status(db_uri: &str, prefetched_nodes: Option<&[NodeRecord]>) -> Result<HaStatus> {
    let nodes = match prefetched_nodes {
        Some(nodes) => nodes.to_vec(),
        None => list_nodes(db_uri)?,
    };
    let policy = get_ha_policy(db_uri)?;
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
    let candidates = build_candidates(&nodes, policy.as_ref());
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

fn get_ha_policy(db_uri: &str) -> Result<Option<HaPolicy>> {
    let mut client = connect(db_uri)?;
    client
        .query_opt(
            "
            SELECT quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at
            FROM ha_policy
            WHERE policy_key = 'default'
            ",
            &[],
        )
        .map_err(to_processing_error)?
        .map(|row| map_policy_row(&row))
        .transpose()
}

fn connect(db_uri: &str) -> Result<Client> {
    Client::connect(db_uri, NoTls).map_err(to_processing_error)
}

fn map_user_row(row: &Row) -> Result<UserRecord> {
    Ok(UserRecord {
        id: row.get(0),
        username: row.get(1),
        role: row.get(2),
        enabled: row.get(3),
        created_at: row.get(4),
    })
}

fn map_job_row(row: &Row) -> Result<JobRecord> {
    Ok(JobRecord {
        id: row.get(0),
        name: row.get(1),
        status: row.get(2),
        next_run_at: row.get(3),
        schedule_interval_s: row.get(4),
        claimed_by: row.get(5),
        claim_until: row.get(6),
        attempts: row.get(7),
        last_error: row.get(8),
        last_run_id: row.get(9),
        created_at: row.get(10),
        updated_at: row.get(11),
    })
}

fn map_node_row(row: &Row) -> Result<NodeRecord> {
    let capabilities_json: String = row.get(5);
    Ok(NodeRecord {
        node_id: row.get(0),
        display_name: row.get(1),
        status: row.get(2),
        last_heartbeat: row.get(3),
        leader_until: row.get(4),
        capabilities: serde_json::from_str(&capabilities_json).map_err(BakulaError::Json)?,
        software_version: row.get(6),
        desired_version: row.get(7),
        ready: row.get(8),
        drain_state: row.get(9),
        upgrade_state: row.get(10),
        last_upgrade_at: row.get(11),
    })
}

fn map_policy_row(row: &Row) -> Result<HaPolicy> {
    Ok(HaPolicy {
        quorum_size: row.get(0),
        min_ready_nodes: row.get(1),
        rollout_batch_size: row.get(2),
        target_version: row.get(3),
        updated_at: row.get(4),
    })
}

fn build_candidates(nodes: &[NodeRecord], policy: Option<&HaPolicy>) -> Vec<HaCandidate> {
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

fn hash_token(raw_token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(raw_token.as_bytes());
    format!("{:x}", digest.finalize())
}

fn to_processing_error(error: impl std::fmt::Display) -> BakulaError {
    BakulaError::Processing(format!("PostgreSQL chyba: {error}"))
}
