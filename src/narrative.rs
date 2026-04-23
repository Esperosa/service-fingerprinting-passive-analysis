use crate::model::{
    CorrelatedEvent, Finding, HostReport, MonitoringLane, RunReport, ServiceReport, Severity,
    TriageAction,
};

pub fn report_to_markdown(report: &RunReport) -> String {
    let mut lines = vec![
        format!("# {}", report.run.nazev),
        String::new(),
        "## Souhrn".to_string(),
        String::new(),
        format!("- ID běhu: `{}`", report.run.run_id),
        format!(
            "- Rozsah: {}",
            report
                .run
                .scope
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("- Profil: `{}`", report.run.profile),
        format!(
            "- Provider: `{}` ({})",
            report.run.provider, report.run.enrichment_mode
        ),
        format!("- Hosté: {}", report.summary.hosts_total),
        format!("- Služby: {}", report.summary.services_total),
        format!("- CVE: {}", report.summary.cves_total),
        format!("- Události: {}", report.summary.events_total),
        format!(
            "- Události bez vazby na inventář: {}",
            report.summary.unmapped_events_total
        ),
        format!("- Nálezy: {}", report.summary.findings_total),
        String::new(),
    ];

    if !report.findings.is_empty() {
        lines.push("## Nálezy".to_string());
        lines.push(String::new());
        for finding in &report.findings {
            lines.extend(render_finding_markdown(finding));
        }
    }

    if !report.triage_actions.is_empty() {
        lines.push("## Doporučené kroky".to_string());
        lines.push(String::new());
        for action in &report.triage_actions {
            lines.extend(render_action_markdown(action));
        }
    }

    if !report.monitoring_lanes.is_empty() {
        lines.push("## Rozhodovací a monitorovací vrstvy".to_string());
        lines.push(String::new());
        for lane in report.monitoring_lanes.iter().take(24) {
            lines.extend(render_lane_markdown(lane));
        }
    }

    if !report.unmapped_events.is_empty() {
        lines.push("## Události, které jsem nespároval s inventářem".to_string());
        lines.push(String::new());
        for event in &report.unmapped_events {
            lines.extend(render_unmapped_event_markdown(event));
        }
    }

    lines.push("## Hosté a služby".to_string());
    lines.push(String::new());
    for host in &report.hosts {
        lines.extend(render_host_markdown(host));
    }

    if let Some(diff) = &report.diff {
        lines.push("## Diff".to_string());
        lines.push(String::new());
        lines.push(format!("- Referenční běh: `{}`", diff.base_run_id));
        lines.push(format!("- Nové hosty: {}", diff.new_hosts.join(", ")));
        lines.push(format!(
            "- Změněné služby: {}",
            diff.changed_services
                .iter()
                .map(|item| item.service_key.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        lines.push(String::new());
    }

    lines.join("\n")
}

pub fn report_to_text(report: &RunReport) -> String {
    let mut lines = vec![
        report.run.nazev.clone(),
        "=".repeat(report.run.nazev.len()),
        String::new(),
        format!("ID běhu: {}", report.run.run_id),
        format!(
            "Rozsah: {}",
            report
                .run
                .scope
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("Hosté: {}", report.summary.hosts_total),
        format!("Služby: {}", report.summary.services_total),
        format!("CVE: {}", report.summary.cves_total),
        format!("Události: {}", report.summary.events_total),
        format!(
            "Události bez vazby na inventář: {}",
            report.summary.unmapped_events_total
        ),
        format!("Nálezy: {}", report.summary.findings_total),
        String::new(),
    ];

    if !report.findings.is_empty() {
        lines.push("NÁLEZY".to_string());
        lines.push("-".repeat(6));
        for finding in &report.findings {
            lines.push(format!(
                "* [{} / {}] {}",
                severity_label(finding),
                confidence_label(finding),
                finding.title
            ));
            if let Some(service_key) = &finding.service_key {
                lines.push(format!("  Služba: {}", service_key));
            }
            lines.push(format!("  Důvod: {}", finding.rationale));
            lines.push(format!("  Doporučení: {}", finding.recommendation));
            if !finding.evidence.is_empty() {
                lines.push("  Evidence:".to_string());
                for item in &finding.evidence {
                    lines.push(format!("    - {}", item));
                }
            }
        }
        lines.push(String::new());
    }

    if !report.triage_actions.is_empty() {
        lines.push("DOPORUČENÉ KROKY".to_string());
        lines.push("-".repeat(16));
        for action in &report.triage_actions {
            lines.extend(render_action_text(action));
        }
        lines.push(String::new());
    }

    if !report.monitoring_lanes.is_empty() {
        lines.push("ROZHODOVACÍ A MONITOROVACÍ VRSTVY".to_string());
        lines.push("-".repeat(36));
        for lane in report.monitoring_lanes.iter().take(24) {
            lines.extend(render_lane_text(lane));
        }
        lines.push(String::new());
    }

    if !report.unmapped_events.is_empty() {
        lines.push("UDÁLOSTI, KTERÉ JSEM NESPÁROVAL S INVENTÁŘEM".to_string());
        lines.push("-".repeat(45));
        for event in &report.unmapped_events {
            lines.push(format!(
                "* {} | {}:{} | {} | {}",
                event.event.event_type,
                event.event.dst_ip,
                event.event.dst_port.unwrap_or(0),
                event.correlation.method,
                event.event.message
            ));
        }
        lines.push(String::new());
    }

    lines.push("HOSTÉ A SLUŽBY".to_string());
    lines.push("-".repeat(13));
    for host in &report.hosts {
        lines.push(format!(
            "{} ({})",
            host.ip,
            host.hostname
                .clone()
                .unwrap_or_else(|| "bez hostname".to_string())
        ));
        for service in &host.services {
            lines.push(format!(
                "  - {} | {} | {} | priorita={} | CVE={} | události={}",
                service.service_key,
                service.inventory.service_name,
                service
                    .inventory
                    .product
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                service.priorita,
                service.cves.len(),
                service.events.len()
            ));
        }
    }

    lines.join("\n")
}

fn render_finding_markdown(finding: &Finding) -> Vec<String> {
    let mut lines = vec![
        format!(
            "### {} [{} / {}]",
            finding.title,
            severity_label(finding),
            confidence_label(finding)
        ),
        String::new(),
        format!("- Typ: `{}`", finding.finding_type),
        format!(
            "- Cíl: {}",
            finding
                .service_key
                .clone()
                .or_else(|| finding.host_key.clone())
                .unwrap_or_else(|| "neuvedeno".to_string())
        ),
        format!("- Důvod: {}", finding.rationale),
        format!("- Doporučení: {}", finding.recommendation),
    ];
    if !finding.evidence.is_empty() {
        lines.push("- Evidence:".to_string());
        for item in &finding.evidence {
            lines.push(format!("  - {}", item));
        }
    }
    lines.push(String::new());
    lines
}

fn render_action_markdown(action: &TriageAction) -> Vec<String> {
    let mut lines = vec![
        format!(
            "### {} [{}]",
            action.title,
            severity_value_label(action.priority)
        ),
        String::new(),
        format!("- Typ: `{}`", action.action_type),
        format!(
            "- Cíl: {}",
            action
                .target_service_key
                .clone()
                .or_else(|| action.target_asset_id.clone())
                .unwrap_or_else(|| "neuvedeno".to_string())
        ),
        format!("- Důvod: {}", action.rationale),
    ];
    if !action.recommended_tools.is_empty() {
        lines.push(format!(
            "- Nástroje: {}",
            action.recommended_tools.join(", ")
        ));
    }
    if !action.evidence.is_empty() {
        lines.push("- Evidence:".to_string());
        for item in &action.evidence {
            lines.push(format!("  - {}", item));
        }
    }
    lines.push(String::new());
    lines
}

fn render_lane_markdown(lane: &MonitoringLane) -> Vec<String> {
    let mut lines = vec![
        format!("### {} [{}]", lane.title, lane.status),
        String::new(),
        format!("- Zdroj: `{}`", lane.source),
        format!("- Typ: `{}`", lane.lane_type),
        format!("- Souhrn: {}", lane.summary),
    ];
    if !lane.recommended_tools.is_empty() {
        lines.push(format!("- Nástroje: {}", lane.recommended_tools.join(", ")));
    }
    if !lane.evidence.is_empty() {
        lines.push("- Evidence:".to_string());
        for item in lane.evidence.iter().take(10) {
            lines.push(format!("  - {}", item));
        }
    }
    lines.push(String::new());
    lines
}

fn render_unmapped_event_markdown(event: &CorrelatedEvent) -> Vec<String> {
    vec![
        format!(
            "- `{}` | {}:{} | {}",
            event.event.event_type,
            event.event.dst_ip,
            event.event.dst_port.unwrap_or(0),
            event.event.message
        ),
        format!(
            "  - korelace: {} / {:?}",
            event.correlation.method, event.correlation.confidence
        ),
        format!("  - zdroj: {}", event.event.source),
        String::new(),
    ]
}

fn render_host_markdown(host: &HostReport) -> Vec<String> {
    let mut lines = vec![
        format!("### {}", host.ip),
        String::new(),
        format!(
            "- Hostname: {}",
            host.hostname
                .clone()
                .unwrap_or_else(|| "bez hostname".to_string())
        ),
        format!("- Počet služeb: {}", host.services.len()),
        String::new(),
    ];

    for service in &host.services {
        lines.extend(render_service_markdown(service));
    }
    lines
}

fn render_action_text(action: &TriageAction) -> Vec<String> {
    let mut lines = vec![
        format!(
            "* [{}] {}",
            severity_value_label(action.priority),
            action.title
        ),
        format!("  Typ: {}", action.action_type),
        format!("  Důvod: {}", action.rationale),
    ];
    if !action.recommended_tools.is_empty() {
        lines.push(format!(
            "  Nástroje: {}",
            action.recommended_tools.join(", ")
        ));
    }
    if !action.evidence.is_empty() {
        lines.push("  Evidence:".to_string());
        for item in action.evidence.iter().take(10) {
            lines.push(format!("    - {}", item));
        }
    }
    lines
}

fn render_lane_text(lane: &MonitoringLane) -> Vec<String> {
    let mut lines = vec![
        format!("* {} | {} | {}", lane.source, lane.status, lane.title),
        format!("  Souhrn: {}", lane.summary),
    ];
    if !lane.recommended_tools.is_empty() {
        lines.push(format!("  Nástroje: {}", lane.recommended_tools.join(", ")));
    }
    if !lane.evidence.is_empty() {
        lines.push("  Evidence:".to_string());
        for item in lane.evidence.iter().take(10) {
            lines.push(format!("    - {}", item));
        }
    }
    lines
}

fn render_service_markdown(service: &ServiceReport) -> Vec<String> {
    let mut lines = vec![format!(
        "- `{}` | {} | stav={} | priorita={} | skóre={}",
        service.service_key,
        service.inventory.service_name,
        service.port_state,
        service.priorita,
        service.score
    )];

    if let Some(product) = &service.inventory.product {
        lines.push(format!(
            "  - produkt: {} {}",
            product,
            service.inventory.version.clone().unwrap_or_default()
        ));
    }
    if !service.cpe.is_empty() {
        lines.push(format!(
            "  - CPE: {}",
            service
                .cpe
                .iter()
                .map(|item| item.cpe23_uri.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !service.cves.is_empty() {
        lines.push(format!(
            "  - CVE: {}",
            service
                .cves
                .iter()
                .map(render_cve_label)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(probe) = &service.web_probe {
        lines.push(format!(
            "  - HTTPX: {} | status={} | title={} | server={}",
            probe.url,
            probe
                .status_code
                .map(|item| item.to_string())
                .unwrap_or_else(|| "-".to_string()),
            probe.title.clone().unwrap_or_else(|| "-".to_string()),
            probe.webserver.clone().unwrap_or_else(|| "-".to_string())
        ));
    }
    if !service.active_checks.is_empty() {
        lines.push(format!(
            "  - Aktivni web checks: {}",
            service
                .active_checks
                .iter()
                .map(|item| format!("{} ({:?})", item.template_id, item.severity))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !service.events.is_empty() {
        lines.push(format!(
            "  - Události: {}",
            service
                .events
                .iter()
                .map(|item| item.event.event_type.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}

fn severity_label(finding: &Finding) -> &'static str {
    severity_value_label(finding.severity)
}

fn severity_value_label(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "vysoká",
        Severity::Medium => "střední",
        Severity::Low => "nízká",
    }
}

fn confidence_label(finding: &Finding) -> &'static str {
    match finding.confidence {
        crate::model::Confidence::High => "vysoká jistota",
        crate::model::Confidence::Medium => "střední jistota",
        crate::model::Confidence::Low => "nízká jistota",
    }
}

fn render_cve_label(item: &crate::model::CveRecord) -> String {
    let mut label = item.cve_id.clone();
    let mut tags = Vec::new();
    if let Some(cvss) = &item.cvss {
        tags.push(format!("CVSS {:.1}", cvss.base_score));
    }
    if let Some(epss) = item
        .exploit_context
        .as_ref()
        .and_then(|context| context.epss.as_ref())
    {
        tags.push(format!("EPSS {:.3}", epss.score));
    }
    if item
        .exploit_context
        .as_ref()
        .and_then(|context| context.cisa_kev.as_ref())
        .is_some()
    {
        tags.push("CISA-KEV".to_string());
    }
    if !tags.is_empty() {
        label.push_str(" [");
        label.push_str(&tags.join(" | "));
        label.push(']');
    }
    label
}
