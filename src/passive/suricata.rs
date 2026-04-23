use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::Result,
    model::{NormalizedEvent, Severity},
    passive::{event_in_window, in_scope, parse_suricata_ts},
};

pub fn parse_suricata(
    path: &Path,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<NormalizedEvent>> {
    let content = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let timestamp = parse_suricata_ts(row["timestamp"].as_str().unwrap_or_default())?;
        let dst_ip = row["dest_ip"].as_str().unwrap_or_default().to_string();
        if dst_ip.is_empty() || !in_scope(scope, &dst_ip) || !event_in_window(timestamp, start, end)
        {
            continue;
        }

        let src_ip = row["src_ip"].as_str().map(ToString::to_string);
        let proto = row["proto"].as_str().unwrap_or("tcp").to_ascii_lowercase();
        let dst_port = row["dest_port"].as_u64().map(|value| value as u16);
        let signature = row["alert"]["signature"]
            .as_str()
            .unwrap_or("Suricata alert");
        let signature_id = row["alert"]["signature_id"].as_i64().unwrap_or_default();
        let severity = Severity::from_numeric(row["alert"]["severity"].as_i64().unwrap_or(3));
        let event_type = classify_signature(signature, dst_port);
        let event_id = format!(
            "suricata:{}:{}",
            row["flow_id"].as_i64().unwrap_or_default(),
            timestamp.timestamp()
        );

        events.push(NormalizedEvent {
            event_id,
            timestamp,
            src_ip,
            dst_ip,
            proto,
            dst_port,
            event_type,
            severity,
            source: "suricata".to_string(),
            rule_id: Some(signature_id.to_string()),
            message: signature.to_string(),
            raw_ref: Some(path.to_string_lossy().to_string()),
            count: 1,
        });
    }
    Ok(events)
}

fn classify_signature(signature: &str, dst_port: Option<u16>) -> String {
    let lowered = signature.to_ascii_lowercase();
    if lowered.contains("basic") {
        "http_basic_without_tls".to_string()
    } else if lowered.contains("telnet") {
        "plaintext_protocol".to_string()
    } else if lowered.contains("ftp") {
        "plaintext_protocol".to_string()
    } else if dst_port == Some(80) {
        "insecure_auth_possible".to_string()
    } else {
        "suricata_alert".to_string()
    }
}
