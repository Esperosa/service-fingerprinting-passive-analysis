use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::model::{NormalizedEvent, Severity};

use super::ConnectionObservation;

type ServiceKey = (String, String, u16);

pub(super) fn detect_connection_anomalies(
    connections: Vec<ConnectionObservation>,
    known_services: &HashSet<ServiceKey>,
) -> Vec<NormalizedEvent> {
    let mut events = Vec::new();
    let mut unexpected: HashMap<ServiceKey, (u32, DateTime<Utc>)> = HashMap::new();
    let mut aggregates: HashMap<ServiceKey, ConnectionAggregate> = HashMap::new();

    for connection in connections {
        let Some(port) = connection.dst_port else {
            continue;
        };
        let key = (connection.dst_ip.clone(), connection.proto.clone(), port);
        if !known_services.contains(&key) {
            let entry = unexpected
                .entry(key.clone())
                .or_insert((0, connection.timestamp));
            entry.0 += 1;
            if connection.timestamp < entry.1 {
                entry.1 = connection.timestamp;
            }
        }

        let aggregate = aggregates.entry(key).or_insert_with(|| {
            ConnectionAggregate::new(connection.timestamp, connection.src_ip.clone())
        });
        aggregate.observe(&connection);
    }

    events.extend(unexpected_traffic_events(unexpected));
    events.extend(aggregate_pattern_events(&aggregates));
    events.extend(inductive_outlier_events(&aggregates));
    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    events
}

fn unexpected_traffic_events(
    unexpected: HashMap<ServiceKey, (u32, DateTime<Utc>)>,
) -> Vec<NormalizedEvent> {
    let mut events = Vec::new();
    for ((dst_ip, proto, port), (count, timestamp)) in unexpected {
        if count < 3 {
            continue;
        }
        events.push(NormalizedEvent {
            event_id: format!("anomaly:{dst_ip}:{proto}:{port}:{count}"),
            timestamp,
            src_ip: None,
            dst_ip,
            proto,
            dst_port: Some(port),
            event_type: "unexpected_traffic".to_string(),
            severity: Severity::Low,
            source: "zeek".to_string(),
            rule_id: Some("heuristika:unexpected_traffic".to_string()),
            message: format!(
                "Pozorovan provoz na port {}, ktery neni v aktivnim inventari jako otevrena sluzba.",
                port
            ),
            raw_ref: Some("conn.log".to_string()),
            count,
        });
    }
    events
}

fn aggregate_pattern_events(
    aggregates: &HashMap<ServiceKey, ConnectionAggregate>,
) -> Vec<NormalizedEvent> {
    let mut events = Vec::new();
    let mut keys = aggregates.keys().cloned().collect::<Vec<_>>();
    keys.sort();

    for (dst_ip, proto, port) in keys {
        let Some(aggregate) = aggregates.get(&(dst_ip.clone(), proto.clone(), port)) else {
            continue;
        };
        let timeout_ratio = aggregate.timeout_ratio();
        if aggregate.timeout_like >= 2 && timeout_ratio >= 0.22 {
            events.push(NormalizedEvent {
                event_id: format!(
                    "anomaly:timeout:{}:{}:{}:{}",
                    dst_ip, proto, port, aggregate.timeout_like
                ),
                timestamp: aggregate.first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "connection_timeout_burst".to_string(),
                severity: if timeout_ratio >= 0.45 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                source: "zeek".to_string(),
                rule_id: Some("heuristika:timeout-burst".to_string()),
                message: format!(
                    "Spojeni vykazuje timeout/retry tlak (ratio {:.2}, timeout_like {}, celkem {}).",
                    timeout_ratio, aggregate.timeout_like, aggregate.count
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.timeout_like,
            });
        }

        if aggregate.max_pps >= 2_800.0 || aggregate.max_bps >= 40_000_000.0 {
            events.push(NormalizedEvent {
                event_id: format!(
                    "anomaly:rate:{}:{}:{}:{:.0}",
                    dst_ip, proto, port, aggregate.max_pps
                ),
                timestamp: aggregate.first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "packet_rate_spike".to_string(),
                severity: if aggregate.max_pps >= 4_800.0 || aggregate.max_bps >= 90_000_000.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                source: "zeek".to_string(),
                rule_id: Some("heuristika:packet-rate-spike".to_string()),
                message: format!(
                    "Pozorovan prudky narust rychlosti paketu (max_pps {:.0}, max_bps {:.0}, timeout_ratio {:.2}).",
                    aggregate.max_pps, aggregate.max_bps, timeout_ratio
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.count,
            });
        }

        if aggregate.loss_votes >= 2 {
            events.push(NormalizedEvent {
                event_id: format!(
                    "anomaly:loss:{}:{}:{}:{}",
                    dst_ip, proto, port, aggregate.loss_votes
                ),
                timestamp: aggregate.first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "packet_loss_signal".to_string(),
                severity: Severity::Medium,
                source: "zeek".to_string(),
                rule_id: Some("heuristika:packet-loss".to_string()),
                message: format!(
                    "Opakovane ztraty/missed bytes na spojeni (loss_votes {}, timeout_ratio {:.2}).",
                    aggregate.loss_votes, timeout_ratio
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.loss_votes,
            });
        }

        if (aggregate.overload_votes >= 3 && aggregate.count >= 4)
            || (aggregate.max_pps >= 4_500.0 && timeout_ratio >= 0.15)
        {
            events.push(NormalizedEvent {
                event_id: format!(
                    "anomaly:overload:{}:{}:{}:{}",
                    dst_ip, proto, port, aggregate.overload_votes
                ),
                timestamp: aggregate.first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                dst_ip,
                proto,
                dst_port: Some(port),
                event_type: "service_overload_risk".to_string(),
                severity: Severity::High,
                source: "zeek".to_string(),
                rule_id: Some("heuristika:overload-risk".to_string()),
                message: format!(
                    "Kombinace vysokych rychlosti, retry a zatizeni ukazuje na riziko pretizeni sluzby (votes {}, max_pps {:.0}).",
                    aggregate.overload_votes, aggregate.max_pps
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.count,
            });
        }
    }

    events
}

fn inductive_outlier_events(
    aggregates: &HashMap<ServiceKey, ConnectionAggregate>,
) -> Vec<NormalizedEvent> {
    if aggregates.len() < 4 {
        return Vec::new();
    }

    let mut count_values = aggregates
        .values()
        .map(|item| item.count as f64)
        .collect::<Vec<_>>();
    let mut pps_values = aggregates
        .values()
        .map(|item| item.max_pps)
        .collect::<Vec<_>>();
    let (count_median, count_mad) = median_and_mad(&mut count_values);
    let (pps_median, pps_mad) = median_and_mad(&mut pps_values);
    let mut events = Vec::new();
    let mut keys = aggregates.keys().cloned().collect::<Vec<_>>();
    keys.sort();

    for (dst_ip, proto, port) in keys {
        let Some(aggregate) = aggregates.get(&(dst_ip.clone(), proto.clone(), port)) else {
            continue;
        };
        if aggregate.count < 3 {
            continue;
        }
        let timeout_component = aggregate.timeout_ratio() * 4.0;
        let score = robust_zscore(aggregate.count as f64, count_median, count_mad)
            .max(robust_zscore(aggregate.max_pps, pps_median, pps_mad))
            .max(timeout_component);
        let composite_signal = timeout_component
            + (aggregate.max_pps / 5_000.0).clamp(0.0, 2.0)
            + (aggregate.count as f64 / 10.0).clamp(0.0, 2.0);
        if score < 3.2 && composite_signal < 2.4 {
            continue;
        }
        events.push(NormalizedEvent {
            event_id: format!("anomaly:inductive:{}:{}:{}:{:.2}", dst_ip, proto, port, score),
            timestamp: aggregate.first_seen,
            src_ip: aggregate.representative_src_ip.clone(),
            dst_ip,
            proto,
            dst_port: Some(port),
            event_type: "inductive_volume_anomaly".to_string(),
            severity: if score >= 6.0 {
                Severity::High
            } else {
                Severity::Medium
            },
            source: "zeek".to_string(),
            rule_id: Some("heuristika:inductive-volume".to_string()),
            message: format!(
                "Induktivni detektor oznacil netypickou kombinaci objemu/rychlosti (score {:.2}, count {}, max_pps {:.0}).",
                score, aggregate.count, aggregate.max_pps
            ),
            raw_ref: Some("conn.log".to_string()),
            count: aggregate.count,
        });
    }

    events
}

#[derive(Debug, Clone)]
struct ConnectionAggregate {
    first_seen: DateTime<Utc>,
    representative_src_ip: Option<String>,
    count: u32,
    timeout_like: u32,
    overload_votes: u32,
    loss_votes: u32,
    max_pps: f64,
    max_bps: f64,
}

impl ConnectionAggregate {
    fn new(first_seen: DateTime<Utc>, representative_src_ip: Option<String>) -> Self {
        Self {
            first_seen,
            representative_src_ip,
            count: 0,
            timeout_like: 0,
            overload_votes: 0,
            loss_votes: 0,
            max_pps: 0.0,
            max_bps: 0.0,
        }
    }

    fn observe(&mut self, connection: &ConnectionObservation) {
        self.count = self.count.saturating_add(1);
        if connection.timestamp < self.first_seen {
            self.first_seen = connection.timestamp;
        }
        if self.representative_src_ip.is_none() {
            self.representative_src_ip = connection.src_ip.clone();
        }

        let timeout_like = is_timeout_like(connection);
        if timeout_like {
            self.timeout_like = self.timeout_like.saturating_add(1);
        }

        if connection.missed_bytes.unwrap_or_default() > 2_048 {
            self.loss_votes = self.loss_votes.saturating_add(1);
        }

        let duration_s = connection
            .duration_s
            .filter(|value| *value > 0.001)
            .unwrap_or(0.0);
        if duration_s <= 0.0 {
            if timeout_like {
                self.overload_votes = self.overload_votes.saturating_add(1);
            }
            return;
        }

        let total_pkts = connection
            .total_pkts
            .or_else(|| combine_optional(connection.orig_pkts, connection.resp_pkts))
            .unwrap_or(0);
        let total_bytes = connection
            .total_bytes
            .or_else(|| combine_optional(connection.orig_bytes, connection.resp_bytes))
            .unwrap_or(0);
        let pps = total_pkts as f64 / duration_s;
        let bps = (total_bytes as f64 * 8.0) / duration_s;
        self.max_pps = self.max_pps.max(pps);
        self.max_bps = self.max_bps.max(bps);

        if pps >= 2_500.0 || bps >= 35_000_000.0 || timeout_like {
            self.overload_votes = self.overload_votes.saturating_add(1);
        }
    }

    fn timeout_ratio(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.timeout_like as f64 / self.count as f64
        }
    }
}

fn is_timeout_like(connection: &ConnectionObservation) -> bool {
    let state = connection
        .conn_state
        .as_deref()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let history = connection
        .history
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(state.as_str(), "S0" | "REJ" | "RSTOS0" | "RSTRH" | "SH")
        || history.contains('t')
        || history.contains('r')
}

fn median_and_mad(values: &mut [f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let median = median_sorted(values);
    let mut deviations = values
        .iter()
        .map(|value| (value - median).abs())
        .collect::<Vec<_>>();
    deviations.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mad = median_sorted(&deviations);
    (median, mad)
}

fn median_sorted(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn robust_zscore(value: f64, median: f64, mad: f64) -> f64 {
    if mad <= 0.0001 {
        return 0.0;
    }
    (0.6745 * (value - median).abs()) / mad
}

fn combine_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}
