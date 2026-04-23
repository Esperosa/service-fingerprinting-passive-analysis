use std::{collections::HashMap, fs, path::Path};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::Result,
    model::{NormalizedEvent, Severity},
    passive::{ConnectionObservation, event_in_window, in_scope, parse_zeek_ts},
};

pub struct ZeekParseResult {
    pub events: Vec<NormalizedEvent>,
    pub connections: Vec<ConnectionObservation>,
}

pub fn parse_zeek_dir(
    path: &Path,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<ZeekParseResult> {
    let mut events = Vec::new();
    let mut connections = Vec::new();

    let notice_path = path.join("notice.log");
    if notice_path.exists() {
        for row in parse_zeek_log(&notice_path)? {
            let timestamp = parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0"))?;
            let dst_ip = row
                .get("id.resp_h")
                .cloned()
                .or_else(|| row.get("dst_ip").cloned())
                .unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let rule = row.get("note").cloned();
            let message = row
                .get("msg")
                .cloned()
                .unwrap_or_else(|| "Zeek notice".to_string());
            let dst_port = row
                .get("id.resp_p")
                .and_then(|value| value.parse::<u16>().ok());

            events.push(NormalizedEvent {
                event_id: format!(
                    "zeek:{}:{}",
                    row.get("uid")
                        .cloned()
                        .unwrap_or_else(|| "notice".to_string()),
                    timestamp.timestamp()
                ),
                timestamp,
                src_ip: row.get("id.orig_h").cloned(),
                dst_ip,
                proto: "tcp".to_string(),
                dst_port,
                event_type: classify_notice(&message),
                severity: Severity::Medium,
                source: "zeek".to_string(),
                rule_id: rule,
                message,
                raw_ref: Some(notice_path.to_string_lossy().to_string()),
                count: 1,
            });
        }
    }

    let http_path = path.join("http.log");
    if http_path.exists() {
        for row in parse_zeek_log(&http_path)? {
            let timestamp = parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0"))?;
            let dst_ip = row.get("id.resp_h").cloned().unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let dst_port = row
                .get("id.resp_p")
                .and_then(|value| value.parse::<u16>().ok());
            let uri = row.get("uri").cloned().unwrap_or_default();
            let path_upper = uri.to_ascii_lowercase();
            let auth_type = row
                .get("auth_type")
                .cloned()
                .or_else(|| row.get("proxied").cloned())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut maybe_event = None;
            if auth_type.contains("basic") {
                maybe_event = Some(("http_basic_without_tls".to_string(), Severity::High));
            } else if dst_port == Some(80)
                && (path_upper.contains("login")
                    || path_upper.contains("signin")
                    || path_upper.contains("auth"))
            {
                maybe_event = Some(("insecure_auth_possible".to_string(), Severity::Low));
            }

            if let Some((event_type, severity)) = maybe_event {
                events.push(NormalizedEvent {
                    event_id: format!(
                        "zeek:{}:http:{}",
                        row.get("uid")
                            .cloned()
                            .unwrap_or_else(|| "http".to_string()),
                        timestamp.timestamp()
                    ),
                    timestamp,
                    src_ip: row.get("id.orig_h").cloned(),
                    dst_ip,
                    proto: "tcp".to_string(),
                    dst_port,
                    event_type,
                    severity,
                    source: "zeek".to_string(),
                    rule_id: Some("heuristika:http".to_string()),
                    message: format!("HTTP pozorovani: {}", uri),
                    raw_ref: Some(http_path.to_string_lossy().to_string()),
                    count: 1,
                });
            }
        }
    }

    let conn_path = path.join("conn.log");
    if conn_path.exists() {
        for row in parse_zeek_log(&conn_path)? {
            let timestamp = parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0"))?;
            let dst_ip = row.get("id.resp_h").cloned().unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let orig_pkts = parse_u64_field(&row, &["orig_pkts"]);
            let resp_pkts = parse_u64_field(&row, &["resp_pkts"]);
            let orig_bytes = parse_u64_field(&row, &["orig_bytes"]);
            let resp_bytes = parse_u64_field(&row, &["resp_bytes"]);
            connections.push(ConnectionObservation {
                timestamp,
                dst_ip,
                src_ip: row.get("id.orig_h").cloned(),
                proto: row
                    .get("proto")
                    .cloned()
                    .unwrap_or_else(|| "tcp".to_string())
                    .to_ascii_lowercase(),
                dst_port: row
                    .get("id.resp_p")
                    .and_then(|value| value.parse::<u16>().ok()),
                duration_s: row
                    .get("duration")
                    .and_then(|value| value.parse::<f64>().ok()),
                orig_bytes,
                resp_bytes,
                total_bytes: combine_optional(orig_bytes, resp_bytes),
                orig_pkts,
                resp_pkts,
                total_pkts: combine_optional(orig_pkts, resp_pkts),
                conn_state: row.get("conn_state").cloned(),
                history: row.get("history").cloned(),
                missed_bytes: parse_u64_field(&row, &["missed_bytes"]),
            });
        }
    }

    Ok(ZeekParseResult {
        events,
        connections,
    })
}

fn parse_zeek_log(path: &Path) -> Result<Vec<HashMap<String, String>>> {
    let content = fs::read_to_string(path)?;
    let mut fields = Vec::new();
    let mut rows = Vec::new();

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("#fields\t") {
            fields = rest.split('\t').map(ToString::to_string).collect();
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let values = line.split('\t').collect::<Vec<_>>();
        let mut row = HashMap::new();
        for (index, field) in fields.iter().enumerate() {
            if let Some(value) = values.get(index) {
                row.insert(field.clone(), (*value).to_string());
            }
        }
        rows.push(row);
    }

    Ok(rows)
}

fn classify_notice(message: &str) -> String {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("telnet") || lowered.contains("ftp") {
        "plaintext_protocol".to_string()
    } else if lowered.contains("basic") {
        "http_basic_without_tls".to_string()
    } else {
        "zeek_notice".to_string()
    }
}

fn parse_u64_field(row: &HashMap<String, String>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        row.get(*key).and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() || trimmed == "-" {
                None
            } else {
                trimmed.parse::<u64>().ok()
            }
        })
    })
}

fn combine_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}
