use std::collections::{BTreeMap, BTreeSet};

use crate::model::{CveDiffItem, DiffReport, EventDiffItem, RunReport, ServiceChange};

pub fn build_diff(base: &RunReport, current: &RunReport) -> DiffReport {
    let base_hosts = base
        .hosts
        .iter()
        .map(|host| (host.host_key.clone(), host))
        .collect::<BTreeMap<_, _>>();
    let current_hosts = current
        .hosts
        .iter()
        .map(|host| (host.host_key.clone(), host))
        .collect::<BTreeMap<_, _>>();

    let new_hosts = current_hosts
        .keys()
        .filter(|key| !base_hosts.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let removed_hosts = base_hosts
        .keys()
        .filter(|key| !current_hosts.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();

    let mut changed_services = Vec::new();
    let mut new_cves = Vec::new();
    let mut new_events = Vec::new();

    let base_services = collect_services(base);
    let current_services = collect_services(current);
    for (service_key, service) in &current_services {
        match base_services.get(service_key) {
            None => changed_services.push(ServiceChange {
                service_key: service_key.clone(),
                change_type: "nova_sluzba".to_string(),
                before: None,
                after: Some(service_signature(service)),
            }),
            Some(base_service) => {
                let before = service_signature(base_service);
                let after = service_signature(service);
                if before != after {
                    changed_services.push(ServiceChange {
                        service_key: service_key.clone(),
                        change_type: "zmena_atributu".to_string(),
                        before: Some(before),
                        after: Some(after),
                    });
                }

                let base_cves = base_service
                    .cves
                    .iter()
                    .map(|item| item.cve_id.clone())
                    .collect::<BTreeSet<_>>();
                for cve in service
                    .cves
                    .iter()
                    .filter(|item| !base_cves.contains(&item.cve_id))
                {
                    new_cves.push(CveDiffItem {
                        service_key: service_key.clone(),
                        cve_id: cve.cve_id.clone(),
                    });
                }

                let base_events = base_service
                    .events
                    .iter()
                    .map(|item| item.event.event_id.clone())
                    .collect::<BTreeSet<_>>();
                for event in service
                    .events
                    .iter()
                    .filter(|item| !base_events.contains(&item.event.event_id))
                {
                    new_events.push(EventDiffItem {
                        service_key: Some(service_key.clone()),
                        event_id: event.event.event_id.clone(),
                        event_type: event.event.event_type.clone(),
                    });
                }
            }
        }
    }

    for service_key in base_services
        .keys()
        .filter(|key| !current_services.contains_key(*key))
    {
        changed_services.push(ServiceChange {
            service_key: service_key.clone(),
            change_type: "odebrana_sluzba".to_string(),
            before: Some(service_signature(base_services[service_key])),
            after: None,
        });
    }

    let base_unmapped_events = base
        .unmapped_events
        .iter()
        .map(|item| item.event.event_id.clone())
        .collect::<BTreeSet<_>>();
    for event in current
        .unmapped_events
        .iter()
        .filter(|item| !base_unmapped_events.contains(&item.event.event_id))
    {
        new_events.push(EventDiffItem {
            service_key: None,
            event_id: event.event.event_id.clone(),
            event_type: event.event.event_type.clone(),
        });
    }

    DiffReport {
        base_run_id: base.run.run_id.clone(),
        new_hosts,
        removed_hosts,
        changed_services,
        new_cves,
        new_events,
    }
}

fn collect_services<'a>(
    report: &'a RunReport,
) -> BTreeMap<String, &'a crate::model::ServiceReport> {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .map(|service| (service.service_key.clone(), service))
        .collect()
}

fn service_signature(service: &crate::model::ServiceReport) -> String {
    format!(
        "{}|{}|{}|{}",
        service.port_state,
        service.inventory.product.clone().unwrap_or_default(),
        service.inventory.version.clone().unwrap_or_default(),
        service.inventory.service_name
    )
}
