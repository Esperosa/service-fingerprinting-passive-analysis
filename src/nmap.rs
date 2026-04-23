use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;
use ipnet::IpNet;
use roxmltree::Document;

use crate::{
    error::{BakulaError, Result},
    model::{Confidence, HostReport},
};

#[derive(Debug, Clone)]
pub struct FollowupExecution {
    pub output_path: PathBuf,
    pub targeted_hosts: usize,
    pub targeted_ports: usize,
}

#[derive(Debug, Clone)]
struct FollowupTarget {
    ip: String,
    ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ParsedInventory {
    pub hosts: Vec<ParsedHost>,
}

#[derive(Debug, Clone)]
pub struct ParsedHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub services: Vec<ParsedService>,
}

#[derive(Debug, Clone)]
pub struct ParsedService {
    pub proto: String,
    pub port: u16,
    pub port_state: String,
    pub state_reason: Option<String>,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub detection_source: String,
    pub confidence: Confidence,
    pub cpes: Vec<String>,
}

pub fn run_real_nmap(
    workspace: &Path,
    scope: &[IpNet],
    ports: &[u16],
    profile: &str,
) -> Result<PathBuf> {
    let raw_dir = workspace.join("tmp");
    fs::create_dir_all(&raw_dir)?;
    let output_path = raw_dir.join(format!("nmap-{}.xml", Utc::now().format("%Y%m%d-%H%M%S")));
    let ports_arg = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let scope_arg = scope.iter().map(ToString::to_string).collect::<Vec<_>>();

    let mut args = vec![
        "-Pn".to_string(),
        "-sV".to_string(),
        "-oX".to_string(),
        output_path.to_string_lossy().to_string(),
        "-p".to_string(),
        ports_arg,
    ];

    match profile {
        "opatrny" => {
            args.push("-T2".to_string());
            args.push("--version-light".to_string());
        }
        "agresivnejsi" => {
            args.push("-T4".to_string());
            args.push("--version-all".to_string());
        }
        _ => {
            args.push("-T3".to_string());
            args.push("--version-light".to_string());
        }
    }

    args.extend(scope_arg);
    let status = Command::new("nmap").args(&args).status()?;
    if !status.success() {
        return Err(BakulaError::Processing(
            "Nmap se nepodarilo uspesne spustit.".to_string(),
        ));
    }
    Ok(output_path)
}

pub fn run_targeted_followup_nmap(
    workspace: &Path,
    inventory: &ParsedInventory,
    profile: &str,
) -> Result<Option<FollowupExecution>> {
    let targets = collect_followup_targets(inventory);
    if targets.is_empty() {
        return Ok(None);
    }

    let raw_dir = workspace.join("tmp");
    fs::create_dir_all(&raw_dir)?;
    let output_path = raw_dir.join(format!(
        "nmap-followup-{}.xml",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let mut union_ports = targets
        .iter()
        .flat_map(|target| target.ports.iter().copied())
        .collect::<Vec<_>>();
    union_ports.sort_unstable();
    union_ports.dedup();
    let host_args = targets
        .iter()
        .map(|target| target.ip.clone())
        .collect::<Vec<_>>();

    let mut args = vec![
        "-Pn".to_string(),
        "-sV".to_string(),
        "--version-all".to_string(),
        "-sC".to_string(),
        "--script".to_string(),
        "banner,http-title,ssl-cert".to_string(),
        "--script-timeout".to_string(),
        "20s".to_string(),
        "-oX".to_string(),
        output_path.to_string_lossy().to_string(),
        "-p".to_string(),
        union_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ];

    match profile {
        "opatrny" => args.push("-T2".to_string()),
        "agresivnejsi" => args.push("-T4".to_string()),
        _ => args.push("-T3".to_string()),
    }

    args.extend(host_args);
    let status = Command::new("nmap").args(&args).status()?;
    if !status.success() {
        return Err(BakulaError::Processing(
            "Cílený follow-up Nmap průchod selhal.".to_string(),
        ));
    }

    Ok(Some(FollowupExecution {
        output_path,
        targeted_hosts: targets.len(),
        targeted_ports: union_ports.len(),
    }))
}

pub fn run_forensic_followup_nmap(
    workspace: &Path,
    hosts: &[HostReport],
    profile: &str,
) -> Result<Option<FollowupExecution>> {
    let targets = collect_forensic_targets(hosts);
    if targets.is_empty() {
        return Ok(None);
    }

    let raw_dir = workspace.join("tmp");
    fs::create_dir_all(&raw_dir)?;
    let output_path = raw_dir.join(format!(
        "nmap-forensic-{}.xml",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let mut union_ports = targets
        .iter()
        .flat_map(|target| target.ports.iter().copied())
        .collect::<Vec<_>>();
    union_ports.sort_unstable();
    union_ports.dedup();
    let host_args = targets
        .iter()
        .map(|target| target.ip.clone())
        .collect::<Vec<_>>();

    let mut args = vec![
        "-Pn".to_string(),
        "-sV".to_string(),
        "--version-all".to_string(),
        "-sC".to_string(),
        "--script".to_string(),
        "banner,http-title,http-headers,ssl-cert,ssh-hostkey,smb-os-discovery".to_string(),
        "--script-timeout".to_string(),
        "30s".to_string(),
        "-oX".to_string(),
        output_path.to_string_lossy().to_string(),
        "-p".to_string(),
        union_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ];

    match profile {
        "opatrny" => args.push("-T2".to_string()),
        "agresivnejsi" => args.push("-T4".to_string()),
        _ => args.push("-T3".to_string()),
    }

    args.extend(host_args);
    let status = Command::new("nmap").args(&args).status()?;
    if !status.success() {
        return Err(BakulaError::Processing(
            "Forenzní Nmap průchod selhal.".to_string(),
        ));
    }

    Ok(Some(FollowupExecution {
        output_path,
        targeted_hosts: targets.len(),
        targeted_ports: union_ports.len(),
    }))
}

pub fn merge_followup_inventory(
    mut primary: ParsedInventory,
    followup: ParsedInventory,
) -> ParsedInventory {
    let mut followup_hosts = followup
        .hosts
        .into_iter()
        .map(|host| (host.ip.clone(), host))
        .collect::<std::collections::BTreeMap<_, _>>();

    for host in &mut primary.hosts {
        if let Some(followup_host) = followup_hosts.remove(&host.ip) {
            if host.hostname.is_none() {
                host.hostname = followup_host.hostname.clone();
            }
            if host.mac.is_none() {
                host.mac = followup_host.mac.clone();
            }
            if host.vendor.is_none() {
                host.vendor = followup_host.vendor.clone();
            }

            for followup_service in followup_host.services {
                if let Some(existing) = host.services.iter_mut().find(|service| {
                    service.proto == followup_service.proto && service.port == followup_service.port
                }) {
                    merge_service(existing, &followup_service);
                } else {
                    host.services.push(followup_service);
                }
            }

            host.services.sort_by(|left, right| {
                left.port
                    .cmp(&right.port)
                    .then(left.proto.cmp(&right.proto))
            });
        }
    }

    primary.hosts.extend(followup_hosts.into_values());
    primary.hosts.sort_by(|left, right| left.ip.cmp(&right.ip));
    primary
}

pub fn parse_nmap_xml(path: &Path) -> Result<ParsedInventory> {
    let xml = sanitize_nmap_xml(&fs::read_to_string(path)?);
    let doc = Document::parse(&xml)
        .map_err(|error| BakulaError::Processing(format!("Nelze parsovat Nmap XML: {error}")))?;

    let mut hosts = Vec::new();
    for host_node in doc.descendants().filter(|node| node.has_tag_name("host")) {
        let host_status = host_node
            .children()
            .find(|node| node.has_tag_name("status"))
            .and_then(|node| node.attribute("state"))
            .unwrap_or("unknown");
        if host_status != "up" {
            continue;
        }

        let ip = host_node
            .descendants()
            .find(|node| node.has_tag_name("address") && node.attribute("addrtype") == Some("ipv4"))
            .and_then(|node| node.attribute("addr"))
            .ok_or_else(|| BakulaError::Processing("Host bez IPv4 adresy.".to_string()))?
            .to_string();

        let hostname = host_node
            .descendants()
            .find(|node| node.has_tag_name("hostname"))
            .and_then(|node| node.attribute("name"))
            .map(ToString::to_string);
        let mac_node = host_node
            .descendants()
            .find(|node| node.has_tag_name("address") && node.attribute("addrtype") == Some("mac"));
        let mac = mac_node
            .and_then(|node| node.attribute("addr"))
            .map(ToString::to_string);
        let vendor = mac_node
            .and_then(|node| node.attribute("vendor"))
            .map(ToString::to_string);

        let mut services = Vec::new();
        for port_node in host_node
            .descendants()
            .filter(|node| node.has_tag_name("port"))
        {
            let port = port_node
                .attribute("portid")
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| BakulaError::Processing("Port bez platneho cisla.".to_string()))?;
            let proto = port_node.attribute("protocol").unwrap_or("tcp").to_string();

            let state_node = port_node
                .children()
                .find(|node| node.has_tag_name("state"))
                .ok_or_else(|| BakulaError::Processing("Port bez stavu.".to_string()))?;
            let port_state = state_node
                .attribute("state")
                .unwrap_or("unknown")
                .to_string();
            let state_reason = state_node.attribute("reason").map(ToString::to_string);

            let service_node = port_node
                .children()
                .find(|node| node.has_tag_name("service"));
            let service_name = service_node
                .and_then(|node| node.attribute("name"))
                .map(ToString::to_string);
            let product = service_node
                .and_then(|node| node.attribute("product"))
                .map(ToString::to_string);
            let version = service_node
                .and_then(|node| node.attribute("version"))
                .map(ToString::to_string);
            let extrainfo = service_node
                .and_then(|node| node.attribute("extrainfo"))
                .map(ToString::to_string);
            let detection_source = service_node
                .and_then(|node| node.attribute("method"))
                .unwrap_or("nmap")
                .to_string();
            let confidence = match service_node.and_then(|node| node.attribute("conf")) {
                Some("10") | Some("9") | Some("8") => Confidence::High,
                Some("7") | Some("6") | Some("5") => Confidence::Medium,
                Some(_) => Confidence::Low,
                None if product.is_some() => Confidence::Medium,
                None => Confidence::Low,
            };
            let cpes = port_node
                .descendants()
                .filter(|node| node.has_tag_name("cpe"))
                .filter_map(|node| node.text())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();

            services.push(ParsedService {
                proto,
                port,
                port_state,
                state_reason,
                service_name,
                product,
                version,
                extrainfo,
                detection_source,
                confidence,
                cpes,
            });
        }

        services.sort_by(|left, right| {
            left.port
                .cmp(&right.port)
                .then(left.proto.cmp(&right.proto))
        });
        hosts.push(ParsedHost {
            ip,
            hostname,
            mac,
            vendor,
            services,
        });
    }

    hosts.sort_by(|left, right| left.ip.cmp(&right.ip));
    Ok(ParsedInventory { hosts })
}

fn sanitize_nmap_xml(xml: &str) -> String {
    xml.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("<!DOCTYPE") && !trimmed.starts_with("<?xml-stylesheet")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_followup_targets(inventory: &ParsedInventory) -> Vec<FollowupTarget> {
    inventory
        .hosts
        .iter()
        .filter_map(|host| {
            let mut ports = host
                .services
                .iter()
                .filter(|service| is_followup_candidate(service))
                .map(|service| service.port)
                .collect::<Vec<_>>();
            ports.sort_unstable();
            ports.dedup();
            (!ports.is_empty()).then(|| FollowupTarget {
                ip: host.ip.clone(),
                ports,
            })
        })
        .collect()
}

fn collect_forensic_targets(hosts: &[HostReport]) -> Vec<FollowupTarget> {
    let mut ranked = hosts
        .iter()
        .flat_map(|host| {
            host.services.iter().filter_map(|service| {
                if service.port_state != "open" {
                    return None;
                }
                let mut score = 0_u32;
                if matches!(
                    service.inventory.confidence,
                    Confidence::Low | Confidence::Medium
                ) {
                    score += 3;
                }
                if service.inventory.product.is_none() || service.inventory.version.is_none() {
                    score += 2;
                }
                if service.cpe.is_empty() {
                    score += 2;
                }
                if service.score >= 7.5 {
                    score += 5;
                } else if service.score >= 4.0 {
                    score += 3;
                }
                if !service.active_checks.is_empty() {
                    score += 4;
                }
                if service.cves.iter().any(|item| {
                    item.cvss
                        .as_ref()
                        .map(|cvss| cvss.base_score >= 7.0)
                        .unwrap_or(false)
                }) {
                    score += 4;
                }
                if matches!(
                    service.port,
                    22 | 23
                        | 80
                        | 139
                        | 161
                        | 389
                        | 443
                        | 445
                        | 3306
                        | 3389
                        | 5432
                        | 5900
                        | 6379
                        | 8080
                        | 8443
                        | 8843
                        | 8880
                ) {
                    score += 2;
                }
                if score == 0 {
                    return None;
                }
                Some((host.ip.clone(), service.port, score))
            })
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then(left.0.cmp(&right.0))
            .then(left.1.cmp(&right.1))
    });
    ranked.truncate(16);

    let mut grouped = std::collections::BTreeMap::<String, Vec<u16>>::new();
    for (ip, port, _) in ranked {
        grouped.entry(ip).or_default().push(port);
    }
    grouped
        .into_iter()
        .take(8)
        .map(|(ip, mut ports)| {
            ports.sort_unstable();
            ports.dedup();
            FollowupTarget { ip, ports }
        })
        .collect()
}

fn is_followup_candidate(service: &ParsedService) -> bool {
    if service.port_state != "open" {
        return false;
    }

    let service_name = service
        .service_name
        .clone()
        .unwrap_or_default()
        .to_lowercase();
    let missing_identity = service.product.is_none() || service.version.is_none();
    let weak_confidence = matches!(service.confidence, Confidence::Low | Confidence::Medium);
    let interesting_port = matches!(
        service.port,
        21 | 22
            | 23
            | 25
            | 53
            | 80
            | 110
            | 143
            | 443
            | 465
            | 587
            | 993
            | 995
            | 161
            | 389
            | 636
            | 873
            | 1433
            | 1521
            | 3306
            | 3389
            | 5432
            | 5900
            | 6379
            | 8080
            | 8443
            | 8880
            | 8843
            | 6789
    );
    let interesting_service = [
        "http",
        "https",
        "ssl/http",
        "ssh",
        "ftp",
        "telnet",
        "smtp",
        "imap",
        "pop3",
        "rdp",
        "ldap",
        "mysql",
        "postgresql",
    ]
    .iter()
    .any(|needle| service_name.contains(needle));

    missing_identity || weak_confidence || interesting_port || interesting_service
}

fn merge_service(current: &mut ParsedService, followup: &ParsedService) {
    if current.port_state != "open" && followup.port_state == "open" {
        current.port_state = followup.port_state.clone();
    }
    if current.state_reason.is_none() {
        current.state_reason = followup.state_reason.clone();
    }

    if should_take_followup(current, followup) {
        if followup.service_name.is_some() {
            current.service_name = followup.service_name.clone();
        }
        if followup.product.is_some() {
            current.product = followup.product.clone();
        }
        if followup.version.is_some() {
            current.version = followup.version.clone();
        }
        if followup.extrainfo.is_some() {
            current.extrainfo = followup.extrainfo.clone();
        }
        if !current.detection_source.contains("followup") {
            current.detection_source = format!("{}+followup", current.detection_source);
        }
    }

    if followup.confidence > current.confidence {
        current.confidence = followup.confidence;
    }

    for cpe in &followup.cpes {
        if !current.cpes.contains(cpe) {
            current.cpes.push(cpe.clone());
        }
    }
}

fn should_take_followup(current: &ParsedService, followup: &ParsedService) -> bool {
    detail_score(followup) >= detail_score(current)
}

fn detail_score(service: &ParsedService) -> usize {
    let mut score = 0usize;
    if service.service_name.is_some() {
        score += 1;
    }
    if service.product.is_some() {
        score += 2;
    }
    if service.version.is_some() {
        score += 3;
    }
    if service.extrainfo.is_some() {
        score += 1;
    }
    score += service.cpes.len() * 2;
    score += match service.confidence {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
    };
    score
}

#[cfg(test)]
mod tests {
    use super::{
        ParsedHost, ParsedInventory, ParsedService, collect_followup_targets,
        collect_forensic_targets, merge_followup_inventory, parse_nmap_xml,
    };
    use crate::model::{Confidence, HostReport, InventoryRecord, ServiceReport};

    #[test]
    fn parse_nmap_xml_accepts_doctype() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nmap.xml");
        std::fs::write(
            &path,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///tmp/nmap.xsl" type="text/xsl"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" method="probed" conf="8"/>
      </port>
    </ports>
  </host>
</nmaprun>"#,
        )
        .expect("write xml");

        let parsed = parse_nmap_xml(&path).expect("parsed inventory");
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].services[0].port, 80);
    }

    #[test]
    fn followup_targets_include_uncertain_open_services() {
        let inventory = ParsedInventory {
            hosts: vec![ParsedHost {
                ip: "192.168.1.10".to_string(),
                hostname: Some("web".to_string()),
                mac: None,
                vendor: None,
                services: vec![
                    ParsedService {
                        proto: "tcp".to_string(),
                        port: 443,
                        port_state: "open".to_string(),
                        state_reason: None,
                        service_name: Some("https".to_string()),
                        product: None,
                        version: None,
                        extrainfo: None,
                        detection_source: "nmap".to_string(),
                        confidence: Confidence::Low,
                        cpes: Vec::new(),
                    },
                    ParsedService {
                        proto: "tcp".to_string(),
                        port: 53,
                        port_state: "closed".to_string(),
                        state_reason: None,
                        service_name: Some("domain".to_string()),
                        product: None,
                        version: None,
                        extrainfo: None,
                        detection_source: "nmap".to_string(),
                        confidence: Confidence::Low,
                        cpes: Vec::new(),
                    },
                ],
            }],
        };

        let targets = collect_followup_targets(&inventory);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ports, vec![443]);
    }

    #[test]
    fn merge_followup_inventory_prefers_richer_identity() {
        let primary = ParsedInventory {
            hosts: vec![ParsedHost {
                ip: "192.168.1.20".to_string(),
                hostname: Some("srv".to_string()),
                mac: None,
                vendor: None,
                services: vec![ParsedService {
                    proto: "tcp".to_string(),
                    port: 22,
                    port_state: "open".to_string(),
                    state_reason: Some("syn-ack".to_string()),
                    service_name: Some("ssh".to_string()),
                    product: None,
                    version: None,
                    extrainfo: None,
                    detection_source: "nmap".to_string(),
                    confidence: Confidence::Low,
                    cpes: Vec::new(),
                }],
            }],
        };
        let followup = ParsedInventory {
            hosts: vec![ParsedHost {
                ip: "192.168.1.20".to_string(),
                hostname: Some("srv".to_string()),
                mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
                vendor: Some("Vendor".to_string()),
                services: vec![ParsedService {
                    proto: "tcp".to_string(),
                    port: 22,
                    port_state: "open".to_string(),
                    state_reason: Some("syn-ack".to_string()),
                    service_name: Some("ssh".to_string()),
                    product: Some("OpenSSH".to_string()),
                    version: Some("9.2".to_string()),
                    extrainfo: Some("protocol 2.0".to_string()),
                    detection_source: "probed".to_string(),
                    confidence: Confidence::High,
                    cpes: vec!["cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*".to_string()],
                }],
            }],
        };

        let merged = merge_followup_inventory(primary, followup);
        let host = &merged.hosts[0];
        let service = &host.services[0];
        assert_eq!(host.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("9.2"));
        assert!(service.detection_source.contains("followup"));
        assert_eq!(service.confidence, Confidence::High);
        assert_eq!(service.cpes.len(), 1);
    }

    #[test]
    fn forensic_targets_prioritize_risky_and_uncertain_services() {
        let hosts = vec![HostReport {
            host_id: "host:192.168.1.50".to_string(),
            host_key: "192.168.1.50".to_string(),
            ip: "192.168.1.50".to_string(),
            hostname: Some("db".to_string()),
            mac: None,
            vendor: None,
            services: vec![
                ServiceReport {
                    service_id: "svc:192.168.1.50/tcp/3306".to_string(),
                    service_key: "192.168.1.50/tcp/3306".to_string(),
                    proto: "tcp".to_string(),
                    port: 3306,
                    port_state: "open".to_string(),
                    state_reason: None,
                    inventory: InventoryRecord {
                        service_name: "mysql".to_string(),
                        product: None,
                        version: None,
                        extrainfo: None,
                        detection_source: "nmap".to_string(),
                        confidence: Confidence::Low,
                    },
                    cpe: Vec::new(),
                    cves: Vec::new(),
                    events: Vec::new(),
                    web_probe: None,
                    active_checks: Vec::new(),
                    score: 8.2,
                    priorita: "vysoka".to_string(),
                },
                ServiceReport {
                    service_id: "svc:192.168.1.50/tcp/22".to_string(),
                    service_key: "192.168.1.50/tcp/22".to_string(),
                    proto: "tcp".to_string(),
                    port: 22,
                    port_state: "open".to_string(),
                    state_reason: None,
                    inventory: InventoryRecord {
                        service_name: "ssh".to_string(),
                        product: Some("OpenSSH".to_string()),
                        version: Some("9.8".to_string()),
                        extrainfo: None,
                        detection_source: "followup".to_string(),
                        confidence: Confidence::High,
                    },
                    cpe: vec![],
                    cves: Vec::new(),
                    events: Vec::new(),
                    web_probe: None,
                    active_checks: Vec::new(),
                    score: 1.2,
                    priorita: "nizka".to_string(),
                },
            ],
        }];

        let targets = collect_forensic_targets(&hosts);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, "192.168.1.50");
        assert!(targets[0].ports.contains(&3306));
    }
}
