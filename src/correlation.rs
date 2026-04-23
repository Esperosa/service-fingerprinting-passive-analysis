use crate::model::{Confidence, CorrelatedEvent, CorrelationInfo, HostReport, NormalizedEvent};

pub fn correlate_events(
    hosts: &[HostReport],
    events: Vec<NormalizedEvent>,
    time_window_s: i64,
) -> Vec<CorrelatedEvent> {
    let mut result = Vec::new();

    for event in events {
        let exact_match = hosts.iter().find_map(|host| {
            host.services.iter().find_map(|service| {
                let dst_port = event.dst_port?;
                if service.port == dst_port
                    && service.port_state == "open"
                    && host.ip == event.dst_ip
                    && (service.proto.eq_ignore_ascii_case(&event.proto) || event.proto == "tcp")
                {
                    Some((host.host_id.clone(), service.service_id.clone()))
                } else {
                    None
                }
            })
        });

        let correlation = if let Some((host_id, service_id)) = exact_match {
            CorrelationInfo {
                method: "ip+port".to_string(),
                confidence: Confidence::High,
                time_window_s,
                host_id: Some(host_id),
                service_id: Some(service_id),
            }
        } else if let Some(host) = hosts.iter().find(|host| host.ip == event.dst_ip) {
            CorrelationInfo {
                method: "ip-only".to_string(),
                confidence: Confidence::Low,
                time_window_s,
                host_id: Some(host.host_id.clone()),
                service_id: None,
            }
        } else {
            CorrelationInfo {
                method: "unmapped".to_string(),
                confidence: Confidence::Low,
                time_window_s,
                host_id: None,
                service_id: None,
            }
        };

        result.push(CorrelatedEvent { event, correlation });
    }

    result
}
