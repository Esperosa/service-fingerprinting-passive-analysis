use std::{fs, path::Path};

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    Result,
    verification::{ScenarioExpectations, ScenarioManifest},
};

#[derive(Debug, Clone)]
pub struct SimulationScaleProfile {
    pub name: String,
    pub extra_hosts: usize,
    pub max_services_per_host: usize,
    pub telemetry_burst_per_host: usize,
    pub flow_repetitions: usize,
}

impl SimulationScaleProfile {
    pub fn standard() -> Self {
        Self {
            name: "standard".to_string(),
            extra_hosts: 0,
            max_services_per_host: 3,
            telemetry_burst_per_host: 1,
            flow_repetitions: 3,
        }
    }

    pub fn large() -> Self {
        Self {
            name: "large".to_string(),
            extra_hosts: 16,
            max_services_per_host: 4,
            telemetry_burst_per_host: 2,
            flow_repetitions: 5,
        }
    }

    pub fn enterprise() -> Self {
        Self {
            name: "enterprise".to_string(),
            extra_hosts: 48,
            max_services_per_host: 5,
            telemetry_burst_per_host: 3,
            flow_repetitions: 8,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "standard" | "std" => Some(Self::standard()),
            "large" | "lg" => Some(Self::large()),
            "enterprise" | "ent" => Some(Self::enterprise()),
            _ => None,
        }
    }

    pub fn with_overrides(
        mut self,
        extra_hosts: Option<usize>,
        max_services_per_host: Option<usize>,
        telemetry_burst_per_host: Option<usize>,
        flow_repetitions: Option<usize>,
    ) -> Self {
        if let Some(value) = extra_hosts {
            self.extra_hosts = value.min(160);
        }
        if let Some(value) = max_services_per_host {
            self.max_services_per_host = value.clamp(1, 8);
        }
        if let Some(value) = telemetry_burst_per_host {
            self.telemetry_burst_per_host = value.clamp(1, 6);
        }
        if let Some(value) = flow_repetitions {
            self.flow_repetitions = value.clamp(3, 16);
        }
        self
    }
}

pub fn generate_simulation(output_dir: &Path, seed: u64, nahodnych: usize) -> Result<()> {
    generate_simulation_with_profile(
        output_dir,
        seed,
        nahodnych,
        &SimulationScaleProfile::standard(),
    )
}

pub fn generate_simulation_with_profile(
    output_dir: &Path,
    seed: u64,
    nahodnych: usize,
    profile: &SimulationScaleProfile,
) -> Result<()> {
    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;

    let (baseline, changed) = build_fixed_pair();
    write_scenario(output_dir, "zakladni", baseline)?;
    write_scenario(output_dir, "zmena", changed)?;

    for index in 0..nahodnych {
        let (baseline, changed) = build_random_pair(seed, index + 1, profile);
        write_scenario(
            output_dir,
            &format!("nahodny-{:03}-zaklad", index + 1),
            baseline,
        )?;
        write_scenario(
            output_dir,
            &format!("nahodny-{:03}-zmena", index + 1),
            changed,
        )?;
    }

    Ok(())
}

fn write_scenario(root: &Path, name: &str, scenario: ScenarioBundle) -> Result<()> {
    let base = root.join(name);
    fs::create_dir_all(base.join("suricata"))?;
    fs::create_dir_all(base.join("zeek"))?;
    fs::write(base.join("nmap.xml"), scenario.nmap_xml)?;
    fs::write(
        base.join("suricata").join("eve.json"),
        scenario.suricata_eve,
    )?;
    fs::write(base.join("zeek").join("notice.log"), scenario.zeek_notice)?;
    fs::write(base.join("zeek").join("http.log"), scenario.zeek_http)?;
    fs::write(base.join("zeek").join("conn.log"), scenario.zeek_conn)?;
    fs::write(
        base.join("manifest.json"),
        serde_json::to_vec_pretty(&scenario.manifest)?,
    )?;
    Ok(())
}

struct ScenarioBundle {
    nmap_xml: String,
    suricata_eve: String,
    zeek_notice: String,
    zeek_http: String,
    zeek_conn: String,
    manifest: ScenarioManifest,
}

#[derive(Clone)]
struct HostSpec {
    ip: String,
    hostname: String,
    services: Vec<ServiceSpec>,
}

#[derive(Clone)]
struct ServiceSpec {
    proto: String,
    port: u16,
    service_name: String,
    product: Option<String>,
    version: Option<String>,
    method: String,
    conf: u8,
    cpe: Option<String>,
}

struct SuricataAlertSpec {
    timestamp: DateTime<Utc>,
    flow_id: i64,
    src_ip: String,
    dest_ip: String,
    dest_port: u16,
    proto: String,
    signature_id: i64,
    signature: String,
    severity: i64,
}

struct ZeekNoticeSpec {
    timestamp: DateTime<Utc>,
    uid: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    note: String,
    msg: String,
}

struct ZeekHttpSpec {
    timestamp: DateTime<Utc>,
    uid: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    host: String,
    uri: String,
    auth_type: String,
}

struct ZeekConnSpec {
    timestamp: DateTime<Utc>,
    uid: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    proto: String,
    duration_s: f64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
    missed_bytes: u64,
    conn_state: String,
    history: String,
}

struct ScenarioSpec {
    description: String,
    scope: Vec<String>,
    profile: String,
    hosts: Vec<HostSpec>,
    suricata_alerts: Vec<SuricataAlertSpec>,
    zeek_notices: Vec<ZeekNoticeSpec>,
    zeek_http: Vec<ZeekHttpSpec>,
    zeek_conn: Vec<ZeekConnSpec>,
    compare_to: Option<String>,
    required_event_types: Vec<String>,
    required_finding_types: Vec<String>,
    expected_new_hosts: Vec<String>,
    expected_changed_services: Vec<String>,
}

fn build_fixed_pair() -> (ScenarioBundle, ScenarioBundle) {
    let base_time = fixed_time(0);

    let web = HostSpec {
        ip: "192.168.56.10".to_string(),
        hostname: "web-frontend".to_string(),
        services: vec![
            apache_http(80, "2.4.49"),
            ServiceSpec {
                proto: "tcp".to_string(),
                port: 443,
                service_name: "https".to_string(),
                product: Some("Apache httpd".to_string()),
                version: Some("2.4.49".to_string()),
                method: "probed".to_string(),
                conf: 8,
                cpe: Some("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*".to_string()),
            },
        ],
    };
    let admin = HostSpec {
        ip: "192.168.56.20".to_string(),
        hostname: "admin-gateway".to_string(),
        services: vec![vsftpd(), telnet()],
    };
    let file = HostSpec {
        ip: "192.168.56.30".to_string(),
        hostname: "fileserver".to_string(),
        services: vec![openssh()],
    };

    let baseline = ScenarioSpec {
        description: "Zakladni laboratorni stav s telnetem, FTP a Apachem 2.4.49.".to_string(),
        scope: vec!["192.168.56.0/24".to_string()],
        profile: "demo".to_string(),
        hosts: vec![web.clone(), admin.clone(), file.clone()],
        suricata_alerts: vec![
            plaintext_alert(
                base_time + Duration::seconds(60),
                1001,
                "192.168.56.2",
                &admin.ip,
                23,
                "TELNET plaintext management traffic",
                2100010,
                2,
            ),
            http_basic_alert(
                base_time + Duration::seconds(100),
                1002,
                "192.168.56.3",
                &web.ip,
                80,
            ),
        ],
        zeek_notices: vec![ZeekNoticeSpec {
            timestamp: base_time + Duration::seconds(60),
            uid: "C1".to_string(),
            src_ip: "192.168.56.2".to_string(),
            src_port: 53211,
            dst_ip: admin.ip.clone(),
            dst_port: 23,
            note: "Plaintext::Telnet".to_string(),
            msg: "Telnet management session observed".to_string(),
        }],
        zeek_http: vec![ZeekHttpSpec {
            timestamp: base_time + Duration::seconds(100),
            uid: "H1".to_string(),
            src_ip: "192.168.56.3".to_string(),
            src_port: 54001,
            dst_ip: web.ip.clone(),
            dst_port: 80,
            host: web.hostname.clone(),
            uri: "/login".to_string(),
            auth_type: "basic".to_string(),
        }],
        zeek_conn: repeated_conn(
            base_time + Duration::seconds(180),
            "CX",
            "192.168.56.90",
            &file.ip,
            3306,
            3,
        ),
        compare_to: None,
        required_event_types: vec![
            "plaintext_protocol".to_string(),
            "http_basic_without_tls".to_string(),
            "unexpected_traffic".to_string(),
            "connection_timeout_burst".to_string(),
            "packet_rate_spike".to_string(),
            "service_overload_risk".to_string(),
        ],
        required_finding_types: vec![
            "high_risk_cve_exposure".to_string(),
            "plaintext_management_protocol".to_string(),
            "http_basic_without_tls".to_string(),
            "unexpected_traffic".to_string(),
            "service_overload_risk".to_string(),
        ],
        expected_new_hosts: Vec::new(),
        expected_changed_services: Vec::new(),
    };

    let monitor = HostSpec {
        ip: "192.168.56.40".to_string(),
        hostname: "monitor".to_string(),
        services: vec![nginx_http(80)],
    };
    let changed = ScenarioSpec {
        description: "Zmena prostredi: Apache je aktualizovan, pribyla sluzba na 8080 a novy host."
            .to_string(),
        scope: vec!["192.168.56.0/24".to_string()],
        profile: "demo".to_string(),
        hosts: vec![
            HostSpec {
                services: vec![
                    apache_http(80, "2.4.58"),
                    ServiceSpec {
                        proto: "tcp".to_string(),
                        port: 443,
                        service_name: "https".to_string(),
                        product: Some("Apache httpd".to_string()),
                        version: Some("2.4.58".to_string()),
                        method: "probed".to_string(),
                        conf: 8,
                        cpe: Some("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*".to_string()),
                    },
                    nginx_http(8080),
                ],
                ..web.clone()
            },
            admin,
            file,
            monitor.clone(),
        ],
        suricata_alerts: vec![
            plaintext_alert(
                base_time + Duration::minutes(30) + Duration::seconds(60),
                2001,
                "192.168.56.2",
                "192.168.56.20",
                23,
                "TELNET plaintext management traffic",
                2100010,
                2,
            ),
            SuricataAlertSpec {
                timestamp: base_time + Duration::minutes(30) + Duration::seconds(130),
                flow_id: 2002,
                src_ip: "192.168.56.6".to_string(),
                dest_ip: "192.168.56.10".to_string(),
                dest_port: 8080,
                proto: "TCP".to_string(),
                signature_id: 2100100,
                signature: "Administrative HTTP endpoint observed on port 8080".to_string(),
                severity: 3,
            },
        ],
        zeek_notices: vec![ZeekNoticeSpec {
            timestamp: base_time + Duration::minutes(30) + Duration::seconds(60),
            uid: "C8".to_string(),
            src_ip: "192.168.56.2".to_string(),
            src_port: 53211,
            dst_ip: "192.168.56.20".to_string(),
            dst_port: 23,
            note: "Plaintext::Telnet".to_string(),
            msg: "Telnet management session observed".to_string(),
        }],
        zeek_http: vec![
            ZeekHttpSpec {
                timestamp: base_time + Duration::minutes(30) + Duration::seconds(120),
                uid: "H8".to_string(),
                src_ip: "192.168.56.7".to_string(),
                src_port: 54022,
                dst_ip: "192.168.56.10".to_string(),
                dst_port: 8080,
                host: "web-frontend".to_string(),
                uri: "/admin".to_string(),
                auth_type: "-".to_string(),
            },
            ZeekHttpSpec {
                timestamp: base_time + Duration::minutes(30) + Duration::seconds(150),
                uid: "H9".to_string(),
                src_ip: "192.168.56.9".to_string(),
                src_port: 54023,
                dst_ip: monitor.ip.clone(),
                dst_port: 80,
                host: monitor.hostname.clone(),
                uri: "/login".to_string(),
                auth_type: "basic".to_string(),
            },
        ],
        zeek_conn: repeated_conn(
            base_time + Duration::minutes(30) + Duration::seconds(200),
            "CY",
            "192.168.56.91",
            "192.168.56.10",
            8443,
            3,
        ),
        compare_to: Some("zakladni".to_string()),
        required_event_types: vec![
            "plaintext_protocol".to_string(),
            "http_basic_without_tls".to_string(),
            "unexpected_traffic".to_string(),
            "connection_timeout_burst".to_string(),
            "packet_rate_spike".to_string(),
            "service_overload_risk".to_string(),
        ],
        required_finding_types: vec![
            "high_risk_cve_exposure".to_string(),
            "plaintext_management_protocol".to_string(),
            "new_exposed_service".to_string(),
            "service_overload_risk".to_string(),
        ],
        expected_new_hosts: vec![monitor.ip.clone()],
        expected_changed_services: vec![
            "192.168.56.10/tcp/80".to_string(),
            "192.168.56.10/tcp/8080".to_string(),
            "192.168.56.40/tcp/80".to_string(),
        ],
    };

    (bundle_from_spec(&baseline), bundle_from_spec(&changed))
}

fn build_random_pair(
    seed: u64,
    index: usize,
    profile: &SimulationScaleProfile,
) -> (ScenarioBundle, ScenarioBundle) {
    let mut rng = StdRng::seed_from_u64(seed ^ ((index as u64) * 7919));
    let subnet = 90 + (index % 80) as u8;
    let scope = format!("10.{}.{}.0/24", subnet / 4, subnet);
    let base_time = fixed_time(index as i64);

    let web_ip = format!("10.{}.{}.10", subnet / 4, subnet);
    let admin_ip = format!("10.{}.{}.20", subnet / 4, subnet);
    let file_ip = format!("10.{}.{}.30", subnet / 4, subnet);
    let extra_ip = format!("10.{}.{}.40", subnet / 4, subnet);

    let telnet_enabled = rng.random_bool(0.6);
    let ftp_enabled = if telnet_enabled {
        rng.random_bool(0.5)
    } else {
        true
    };
    let expose_443 = rng.random_bool(0.5);
    let mut add_new_service = rng.random_bool(0.85);
    let add_new_host = rng.random_bool(0.65);
    if !add_new_service && !add_new_host {
        add_new_service = true;
    }
    let add_basic_on_new_host = rng.random_bool(0.6);

    let mut web_services = vec![apache_http(80, "2.4.49")];
    if expose_443 {
        web_services.push(ServiceSpec {
            proto: "tcp".to_string(),
            port: 443,
            service_name: "https".to_string(),
            product: Some("Apache httpd".to_string()),
            version: Some("2.4.49".to_string()),
            method: "probed".to_string(),
            conf: 8,
            cpe: Some("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*".to_string()),
        });
    }
    let web_host = HostSpec {
        ip: web_ip.clone(),
        hostname: format!("web-{:03}", index),
        services: web_services,
    };

    let mut admin_services = Vec::new();
    if ftp_enabled {
        admin_services.push(vsftpd());
    }
    if telnet_enabled {
        admin_services.push(telnet());
    }
    let admin_host = HostSpec {
        ip: admin_ip.clone(),
        hostname: format!("admin-{:03}", index),
        services: admin_services,
    };

    let file_host = HostSpec {
        ip: file_ip.clone(),
        hostname: format!("files-{:03}", index),
        services: vec![openssh()],
    };

    let notice_port = if telnet_enabled { 23 } else { 21 };
    let notice_label = if telnet_enabled {
        ("Plaintext::Telnet", "Telnet management session observed")
    } else {
        ("Plaintext::Ftp", "FTP control session observed")
    };
    let signature = if telnet_enabled {
        "TELNET plaintext management traffic"
    } else {
        "FTP plaintext control channel observed"
    };
    let signature_id = if telnet_enabled { 3100100 } else { 3100101 };

    let dense_hosts_baseline = build_dense_hosts(index, subnet, profile, false);
    let dense_hosts_changed = build_dense_hosts(index, subnet, profile, true);
    let mut baseline_hosts = vec![web_host.clone(), admin_host.clone(), file_host.clone()];
    baseline_hosts.extend(dense_hosts_baseline.clone());

    let mut baseline_suricata = vec![
        plaintext_alert(
            base_time + Duration::seconds(45),
            3000 + index as i64,
            "10.0.0.2",
            &admin_ip,
            notice_port,
            signature,
            signature_id,
            2,
        ),
        http_basic_alert(
            base_time + Duration::seconds(90),
            3200 + index as i64,
            "10.0.0.3",
            &web_ip,
            80,
        ),
    ];
    let mut baseline_notices = vec![ZeekNoticeSpec {
        timestamp: base_time + Duration::seconds(45),
        uid: format!("R{index}N1"),
        src_ip: "10.0.0.2".to_string(),
        src_port: 53000 + index as u16,
        dst_ip: admin_ip.clone(),
        dst_port: notice_port,
        note: notice_label.0.to_string(),
        msg: notice_label.1.to_string(),
    }];
    let mut baseline_http = vec![ZeekHttpSpec {
        timestamp: base_time + Duration::seconds(90),
        uid: format!("R{index}H1"),
        src_ip: "10.0.0.3".to_string(),
        src_port: 54000 + index as u16,
        dst_ip: web_ip.clone(),
        dst_port: 80,
        host: web_host.hostname.clone(),
        uri: if rng.random_bool(0.5) {
            "/login".to_string()
        } else {
            "/signin".to_string()
        },
        auth_type: "basic".to_string(),
    }];
    let mut baseline_conn = repeated_conn(
        base_time + Duration::seconds(180),
        &format!("R{index}C"),
        "10.0.0.90",
        &file_ip,
        if rng.random_bool(0.5) { 3306 } else { 8443 },
        profile.flow_repetitions.max(3),
    );
    append_dense_telemetry(
        base_time + Duration::seconds(220),
        index,
        &dense_hosts_baseline,
        profile,
        false,
        &mut baseline_suricata,
        &mut baseline_notices,
        &mut baseline_http,
        &mut baseline_conn,
    );

    let baseline = ScenarioSpec {
        description: format!(
            "Nahodny laboratorni zaklad #{index}: inventar s plaintext spravou a webovou vrstvou."
        ),
        scope: vec![scope.clone()],
        profile: format!("simulace-random-{}", profile.name),
        hosts: baseline_hosts,
        suricata_alerts: baseline_suricata,
        zeek_notices: baseline_notices,
        zeek_http: baseline_http,
        zeek_conn: baseline_conn,
        compare_to: None,
        required_event_types: vec![
            "plaintext_protocol".to_string(),
            "http_basic_without_tls".to_string(),
            "unexpected_traffic".to_string(),
            "connection_timeout_burst".to_string(),
            "packet_rate_spike".to_string(),
            "service_overload_risk".to_string(),
        ],
        required_finding_types: vec![
            "high_risk_cve_exposure".to_string(),
            "plaintext_management_protocol".to_string(),
            "http_basic_without_tls".to_string(),
            "unexpected_traffic".to_string(),
            "service_overload_risk".to_string(),
        ],
        expected_new_hosts: Vec::new(),
        expected_changed_services: Vec::new(),
    };

    let mut changed_hosts = vec![
        HostSpec {
            services: web_host
                .services
                .iter()
                .map(|service| {
                    if matches!(service.port, 80 | 443) {
                        ServiceSpec {
                            version: Some("2.4.58".to_string()),
                            cpe: Some(
                                "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*".to_string(),
                            ),
                            ..service.clone()
                        }
                    } else {
                        service.clone()
                    }
                })
                .collect(),
            ..web_host.clone()
        },
        admin_host.clone(),
        file_host.clone(),
    ];
    changed_hosts.extend(dense_hosts_changed.clone());

    let mut expected_changed_services = vec![format!("{}/tcp/80", web_ip)];
    if expose_443 {
        expected_changed_services.push(format!("{}/tcp/443", web_ip));
    }
    if add_new_service {
        changed_hosts[0].services.push(nginx_http(8080));
        expected_changed_services.push(format!("{}/tcp/8080", web_ip));
    }

    let mut expected_new_hosts = Vec::new();
    let mut changed_http = vec![ZeekHttpSpec {
        timestamp: base_time + Duration::minutes(25) + Duration::seconds(90),
        uid: format!("R{index}H9"),
        src_ip: "10.0.0.9".to_string(),
        src_port: 56000 + index as u16,
        dst_ip: web_ip.clone(),
        dst_port: if add_new_service { 8080 } else { 80 },
        host: web_host.hostname.clone(),
        uri: if add_new_service {
            "/admin".to_string()
        } else {
            "/login".to_string()
        },
        auth_type: if add_new_service {
            "-".to_string()
        } else {
            "basic".to_string()
        },
    }];

    if add_new_host {
        let extra_host = HostSpec {
            ip: extra_ip.clone(),
            hostname: format!("monitor-{:03}", index),
            services: vec![nginx_http(80)],
        };
        expected_new_hosts.push(extra_ip.clone());
        expected_changed_services.push(format!("{}/tcp/80", extra_ip));
        if add_basic_on_new_host {
            changed_http.push(ZeekHttpSpec {
                timestamp: base_time + Duration::minutes(25) + Duration::seconds(130),
                uid: format!("R{index}H10"),
                src_ip: "10.0.0.10".to_string(),
                src_port: 56500 + index as u16,
                dst_ip: extra_ip.clone(),
                dst_port: 80,
                host: extra_host.hostname.clone(),
                uri: "/login".to_string(),
                auth_type: "basic".to_string(),
            });
        }
        changed_hosts.push(extra_host);
    }

    let mut changed_suricata = vec![
        plaintext_alert(
            base_time + Duration::minutes(25) + Duration::seconds(45),
            4000 + index as i64,
            "10.0.0.2",
            &admin_ip,
            notice_port,
            signature,
            signature_id,
            2,
        ),
        SuricataAlertSpec {
            timestamp: base_time + Duration::minutes(25) + Duration::seconds(100),
            flow_id: 4200 + index as i64,
            src_ip: "10.0.0.11".to_string(),
            dest_ip: web_ip.clone(),
            dest_port: if add_new_service { 8080 } else { 80 },
            proto: "TCP".to_string(),
            signature_id: 420100 + index as i64,
            signature: if add_new_service {
                "Administrative HTTP endpoint observed on port 8080".to_string()
            } else {
                "HTTP Basic credentials over plaintext channel".to_string()
            },
            severity: if add_new_service { 3 } else { 1 },
        },
    ];
    let mut changed_notices = vec![ZeekNoticeSpec {
        timestamp: base_time + Duration::minutes(25) + Duration::seconds(45),
        uid: format!("R{index}N9"),
        src_ip: "10.0.0.2".to_string(),
        src_port: 53100 + index as u16,
        dst_ip: admin_ip,
        dst_port: notice_port,
        note: notice_label.0.to_string(),
        msg: notice_label.1.to_string(),
    }];
    let mut changed_conn = repeated_conn(
        base_time + Duration::minutes(25) + Duration::seconds(180),
        &format!("R{index}Y"),
        "10.0.0.91",
        &web_ip,
        if add_new_service { 8443 } else { 3306 },
        profile.flow_repetitions.max(3),
    );
    append_dense_telemetry(
        base_time + Duration::minutes(25) + Duration::seconds(220),
        index,
        &dense_hosts_changed,
        profile,
        true,
        &mut changed_suricata,
        &mut changed_notices,
        &mut changed_http,
        &mut changed_conn,
    );

    let changed = ScenarioSpec {
        description: format!(
            "Nahodny laboratorni zmenovy scenar #{index}: patch, nova expozice a dalsi overeni."
        ),
        scope: vec![scope],
        profile: format!("simulace-random-{}", profile.name),
        hosts: changed_hosts,
        suricata_alerts: changed_suricata,
        zeek_notices: changed_notices,
        zeek_http: changed_http,
        zeek_conn: changed_conn,
        compare_to: Some(format!("nahodny-{:03}-zaklad", index)),
        required_event_types: vec![
            "plaintext_protocol".to_string(),
            "unexpected_traffic".to_string(),
            "connection_timeout_burst".to_string(),
            "packet_rate_spike".to_string(),
            "service_overload_risk".to_string(),
        ],
        required_finding_types: vec![
            "high_risk_cve_exposure".to_string(),
            "plaintext_management_protocol".to_string(),
            "new_exposed_service".to_string(),
            "service_overload_risk".to_string(),
        ],
        expected_new_hosts,
        expected_changed_services,
    };

    (bundle_from_spec(&baseline), bundle_from_spec(&changed))
}

fn build_dense_hosts(
    index: usize,
    subnet: u8,
    profile: &SimulationScaleProfile,
    patched: bool,
) -> Vec<HostSpec> {
    let extra_hosts = profile.extra_hosts.min(160);
    (0..extra_hosts)
        .map(|offset| {
            let octet = 50 + (offset as u16 % 180);
            let ip = format!("10.{}.{}.{}", subnet / 4, subnet, octet);
            let mut services = vec![openssh()];
            if offset % 2 == 0 {
                services.push(apache_http(80, if patched { "2.4.58" } else { "2.4.49" }));
            }
            if offset % 3 == 0 {
                services.push(vsftpd());
            }
            if offset % 5 == 0 {
                services.push(telnet());
            }
            if offset % 7 == 0 {
                services.push(nginx_http(8080));
            }
            services.sort_by(|left, right| left.port.cmp(&right.port));
            services.dedup_by(|left, right| left.port == right.port && left.proto == right.proto);
            services.truncate(profile.max_services_per_host.max(1));
            HostSpec {
                ip,
                hostname: format!("edge-{:03}-{:03}", index, offset),
                services,
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn append_dense_telemetry(
    base_time: DateTime<Utc>,
    index: usize,
    hosts: &[HostSpec],
    profile: &SimulationScaleProfile,
    changed: bool,
    suricata: &mut Vec<SuricataAlertSpec>,
    notices: &mut Vec<ZeekNoticeSpec>,
    http_rows: &mut Vec<ZeekHttpSpec>,
    conn_rows: &mut Vec<ZeekConnSpec>,
) {
    let flow_repetitions = profile.flow_repetitions.max(3);
    let telemetry_burst = profile.telemetry_burst_per_host.max(1);
    for (offset, host) in hosts.iter().enumerate() {
        for burst in 0..telemetry_burst {
            if let Some(service) = host.services.get(burst % host.services.len()) {
                suricata.push(SuricataAlertSpec {
                    timestamp: base_time + Duration::seconds((offset * 2 + burst) as i64),
                    flow_id: (if changed { 90_000 } else { 50_000 })
                        + (index as i64 * 300)
                        + offset as i64 * 4
                        + burst as i64,
                    src_ip: format!("10.1.{}.{}", (offset % 16) + 1, (burst % 200) + 2),
                    dest_ip: host.ip.clone(),
                    dest_port: service.port,
                    proto: "TCP".to_string(),
                    signature_id: 510_000 + (offset % 64) as i64,
                    signature: if matches!(service.port, 21 | 23) {
                        "Plaintext management channel observed".to_string()
                    } else {
                        "Administrative surface probe".to_string()
                    },
                    severity: if matches!(service.port, 21 | 23) {
                        2
                    } else {
                        1
                    },
                });
            }
        }

        if let Some(plaintext_service) = host
            .services
            .iter()
            .find(|service| service.service_name == "telnet" || service.service_name == "ftp")
        {
            notices.push(ZeekNoticeSpec {
                timestamp: base_time + Duration::seconds((offset * 2 + 1) as i64),
                uid: format!("R{index}{}N{:03}", if changed { "Y" } else { "X" }, offset),
                src_ip: format!("10.2.{}.{}", (offset % 16) + 1, (offset % 200) + 2),
                src_port: 53_500 + (offset % 500) as u16,
                dst_ip: host.ip.clone(),
                dst_port: plaintext_service.port,
                note: if plaintext_service.service_name == "telnet" {
                    "Plaintext::Telnet".to_string()
                } else {
                    "Plaintext::Ftp".to_string()
                },
                msg: "Plaintext management session observed".to_string(),
            });
        }

        if let Some(http_service) = host
            .services
            .iter()
            .find(|service| matches!(service.port, 80 | 8080))
        {
            http_rows.push(ZeekHttpSpec {
                timestamp: base_time + Duration::seconds((offset * 3 + 2) as i64),
                uid: format!("R{index}{}H{:03}", if changed { "Y" } else { "X" }, offset),
                src_ip: format!("10.3.{}.{}", (offset % 16) + 1, (offset % 200) + 3),
                src_port: 54_500 + (offset % 1000) as u16,
                dst_ip: host.ip.clone(),
                dst_port: http_service.port,
                host: host.hostname.clone(),
                uri: if offset % 2 == 0 {
                    "/admin".to_string()
                } else {
                    "/login".to_string()
                },
                auth_type: if changed && offset % 3 == 0 {
                    "-".to_string()
                } else {
                    "basic".to_string()
                },
            });
        }

        let dynamic_repetitions = if changed && offset % 9 == 0 {
            flow_repetitions.saturating_add(4)
        } else if !changed && offset % 13 == 0 {
            flow_repetitions.saturating_add(2)
        } else {
            flow_repetitions
        };

        conn_rows.extend(repeated_conn(
            base_time + Duration::seconds((offset * 4 + 2) as i64),
            &format!("R{index}{}C{:03}", if changed { "Y" } else { "X" }, offset),
            &format!("10.4.{}.{}", (offset % 16) + 1, (offset % 200) + 4),
            &host.ip,
            9_000 + (offset % 140) as u16,
            dynamic_repetitions,
        ));
    }
}

fn bundle_from_spec(spec: &ScenarioSpec) -> ScenarioBundle {
    let min_cves = spec
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .map(demo_cve_count)
        .sum::<usize>();

    let manifest = ScenarioManifest {
        nazev: spec.description.clone(),
        popis: spec.description.clone(),
        profile: spec.profile.clone(),
        provider: Some("demo".to_string()),
        scope: spec
            .scope
            .iter()
            .filter_map(|item| item.parse().ok())
            .collect(),
        ports: vec![21, 22, 23, 80, 443, 8080, 8443],
        compare_to: spec.compare_to.clone(),
        expectations: ScenarioExpectations {
            min_hosts: spec.hosts.len(),
            min_services: spec.hosts.iter().map(|host| host.services.len()).sum(),
            min_cves,
            min_events: expected_event_count(spec),
            min_findings: spec.required_finding_types.len(),
            min_high_priority_services: if min_cves > 0 { 1 } else { 0 },
            required_event_types: spec.required_event_types.clone(),
            required_finding_types: spec.required_finding_types.clone(),
            required_service_keys: vec![format!(
                "{}/tcp/80",
                spec.hosts
                    .first()
                    .map(|host| host.ip.clone())
                    .unwrap_or_default()
            )],
            expected_new_hosts: spec.expected_new_hosts.clone(),
            expected_changed_services: spec.expected_changed_services.clone(),
        },
    };

    ScenarioBundle {
        nmap_xml: render_nmap_xml(&spec.hosts),
        suricata_eve: render_suricata(&spec.suricata_alerts),
        zeek_notice: render_notice(&spec.zeek_notices),
        zeek_http: render_http(&spec.zeek_http),
        zeek_conn: render_conn(&spec.zeek_conn),
        manifest,
    }
}

fn render_nmap_xml(hosts: &[HostSpec]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun scanner=\"nmap\" args=\"nmap -sV\" startstr=\"2026-04-07 10:00 CET\">\n",
    );
    for host in hosts {
        xml.push_str("  <host>\n");
        xml.push_str("    <status state=\"up\"/>\n");
        xml.push_str(&format!(
            "    <address addr=\"{}\" addrtype=\"ipv4\"/>\n",
            host.ip
        ));
        xml.push_str(&format!(
            "    <hostnames><hostname name=\"{}\"/></hostnames>\n",
            host.hostname
        ));
        xml.push_str("    <ports>\n");
        for service in &host.services {
            xml.push_str(&format!(
                "      <port protocol=\"{}\" portid=\"{}\">\n",
                service.proto, service.port
            ));
            xml.push_str("        <state state=\"open\" reason=\"syn-ack\"/>\n");
            xml.push_str(&format!(
                "        <service name=\"{}\"{}{} method=\"{}\" conf=\"{}\">",
                service.service_name,
                opt_attr("product", service.product.as_deref()),
                opt_attr("version", service.version.as_deref()),
                service.method,
                service.conf
            ));
            if let Some(cpe) = &service.cpe {
                xml.push_str(&format!("\n          <cpe>{}</cpe>\n        ", cpe));
            }
            xml.push_str("</service>\n");
            xml.push_str("      </port>\n");
        }
        xml.push_str("    </ports>\n");
        xml.push_str("  </host>\n");
    }
    xml.push_str("</nmaprun>\n");
    xml
}

fn render_suricata(alerts: &[SuricataAlertSpec]) -> String {
    alerts
        .iter()
        .map(|alert| {
            format!(
                r#"{{"timestamp":"{}","flow_id":{},"src_ip":"{}","dest_ip":"{}","dest_port":{},"proto":"{}","event_type":"alert","alert":{{"signature_id":{},"signature":"{}","severity":{}}}}}"#,
                rfc3339(alert.timestamp),
                alert.flow_id,
                alert.src_ip,
                alert.dest_ip,
                alert.dest_port,
                alert.proto,
                alert.signature_id,
                alert.signature,
                alert.severity
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_notice(rows: &[ZeekNoticeSpec]) -> String {
    let mut lines = vec![
        "#separator \\x09".to_string(),
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tnote\tmsg".to_string(),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring".to_string(),
    ];
    lines.extend(rows.iter().map(|row| {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            epoch(row.timestamp),
            row.uid,
            row.src_ip,
            row.src_port,
            row.dst_ip,
            row.dst_port,
            row.note,
            row.msg
        )
    }));
    lines.join("\n")
}

fn render_http(rows: &[ZeekHttpSpec]) -> String {
    let mut lines = vec![
        "#separator \\x09".to_string(),
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\thost\turi\tauth_type"
            .to_string(),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring".to_string(),
    ];
    lines.extend(rows.iter().map(|row| {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            epoch(row.timestamp),
            row.uid,
            row.src_ip,
            row.src_port,
            row.dst_ip,
            row.dst_port,
            row.host,
            row.uri,
            row.auth_type
        )
    }));
    lines.join("\n")
}

fn render_conn(rows: &[ZeekConnSpec]) -> String {
    let mut lines = vec![
        "#separator \\x09".to_string(),
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tmissed_bytes\tconn_state\thistory".to_string(),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tinterval\tcount\tcount\tcount\tcount\tcount\tstring\tstring".to_string(),
    ];
    lines.extend(rows.iter().map(|row| {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            epoch(row.timestamp),
            row.uid,
            row.src_ip,
            row.src_port,
            row.dst_ip,
            row.dst_port,
            row.proto,
            row.duration_s,
            row.orig_bytes,
            row.resp_bytes,
            row.orig_pkts,
            row.resp_pkts,
            row.missed_bytes,
            row.conn_state,
            row.history
        )
    }));
    lines.join("\n")
}

fn apache_http(port: u16, version: &str) -> ServiceSpec {
    ServiceSpec {
        proto: "tcp".to_string(),
        port,
        service_name: "http".to_string(),
        product: Some("Apache httpd".to_string()),
        version: Some(version.to_string()),
        method: "probed".to_string(),
        conf: 10,
        cpe: Some(format!(
            "cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*",
            version
        )),
    }
}

fn nginx_http(port: u16) -> ServiceSpec {
    ServiceSpec {
        proto: "tcp".to_string(),
        port,
        service_name: "http".to_string(),
        product: Some("nginx".to_string()),
        version: Some("1.24.0".to_string()),
        method: "probed".to_string(),
        conf: 8,
        cpe: None,
    }
}

fn vsftpd() -> ServiceSpec {
    ServiceSpec {
        proto: "tcp".to_string(),
        port: 21,
        service_name: "ftp".to_string(),
        product: Some("vsftpd".to_string()),
        version: Some("3.0.3".to_string()),
        method: "probed".to_string(),
        conf: 10,
        cpe: Some("cpe:2.3:a:vsftpd_project:vsftpd:3.0.3:*:*:*:*:*:*:*".to_string()),
    }
}

fn telnet() -> ServiceSpec {
    ServiceSpec {
        proto: "tcp".to_string(),
        port: 23,
        service_name: "telnet".to_string(),
        product: Some("BusyBox telnetd".to_string()),
        version: Some("1.36.1".to_string()),
        method: "table".to_string(),
        conf: 6,
        cpe: None,
    }
}

fn openssh() -> ServiceSpec {
    ServiceSpec {
        proto: "tcp".to_string(),
        port: 22,
        service_name: "ssh".to_string(),
        product: Some("OpenSSH".to_string()),
        version: Some("8.9".to_string()),
        method: "probed".to_string(),
        conf: 10,
        cpe: Some("cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*".to_string()),
    }
}

fn plaintext_alert(
    timestamp: DateTime<Utc>,
    flow_id: i64,
    src_ip: &str,
    dest_ip: &str,
    dest_port: u16,
    signature: &str,
    signature_id: i64,
    severity: i64,
) -> SuricataAlertSpec {
    SuricataAlertSpec {
        timestamp,
        flow_id,
        src_ip: src_ip.to_string(),
        dest_ip: dest_ip.to_string(),
        dest_port,
        proto: "TCP".to_string(),
        signature_id,
        signature: signature.to_string(),
        severity,
    }
}

fn http_basic_alert(
    timestamp: DateTime<Utc>,
    flow_id: i64,
    src_ip: &str,
    dest_ip: &str,
    dest_port: u16,
) -> SuricataAlertSpec {
    SuricataAlertSpec {
        timestamp,
        flow_id,
        src_ip: src_ip.to_string(),
        dest_ip: dest_ip.to_string(),
        dest_port,
        proto: "TCP".to_string(),
        signature_id: 2100011,
        signature: "HTTP Basic credentials over plaintext channel".to_string(),
        severity: 1,
    }
}

fn repeated_conn(
    start: DateTime<Utc>,
    prefix: &str,
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    count: usize,
) -> Vec<ZeekConnSpec> {
    (0..count)
        .map(|index| ZeekConnSpec {
            timestamp: start + Duration::seconds((index * 2) as i64),
            uid: format!("{prefix}{}", index + 1),
            src_ip: src_ip.to_string(),
            src_port: 41000 + index as u16,
            dst_ip: dst_ip.to_string(),
            dst_port,
            proto: "tcp".to_string(),
            duration_s: if index % 2 == 0 {
                0.06 + (index as f64 * 0.01)
            } else {
                0.8 + (index as f64 * 0.25)
            },
            orig_bytes: 16_000 + (index as u64 * 2_400),
            resp_bytes: 9_000 + (index as u64 * 1_200),
            orig_pkts: if index % 2 == 0 {
                240 + (index as u64 * 16)
            } else {
                65 + (index as u64 * 5)
            },
            resp_pkts: if index % 2 == 0 {
                170 + (index as u64 * 10)
            } else {
                44 + (index as u64 * 3)
            },
            missed_bytes: if index % 6 == 0 { 3_072 } else { 0 },
            conn_state: if index % 2 == 0 {
                "S0".to_string()
            } else {
                "SF".to_string()
            },
            history: if index % 2 == 0 {
                "ShADtr".to_string()
            } else {
                "ShADadf".to_string()
            },
        })
        .collect()
}

fn expected_event_count(spec: &ScenarioSpec) -> usize {
    let explicit_http = spec
        .zeek_http
        .iter()
        .filter(|row| row.auth_type.eq_ignore_ascii_case("basic") || row.dst_port == 80)
        .count();

    let unexpected = spec
        .zeek_conn
        .first()
        .map(|row| {
            let count = spec
                .zeek_conn
                .iter()
                .filter(|item| item.dst_ip == row.dst_ip && item.dst_port == row.dst_port)
                .count();
            usize::from(count >= 3)
        })
        .unwrap_or(0);

    spec.suricata_alerts.len() + spec.zeek_notices.len() + explicit_http + unexpected
}

fn demo_cve_count(service: &ServiceSpec) -> usize {
    match service.cpe.as_deref() {
        Some(value) if value.starts_with("cpe:2.3:a:apache:http_server:2.4.49") => 2,
        Some(value) if value.starts_with("cpe:2.3:a:openbsd:openssh:8.9") => 1,
        Some(value) if value.starts_with("cpe:2.3:a:vsftpd_project:vsftpd:3.0.3") => 1,
        _ => 0,
    }
}

fn fixed_time(offset_index: i64) -> DateTime<Utc> {
    let bounded_slot = offset_index.rem_euclid(120);
    Utc::now() - Duration::minutes(20) + Duration::seconds(bounded_slot * 10)
}

fn rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn epoch(value: DateTime<Utc>) -> String {
    format!("{}.0", value.timestamp())
}

fn opt_attr(name: &str, value: Option<&str>) -> String {
    value
        .map(|item| format!(" {}=\"{}\"", name, item))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{SimulationScaleProfile, build_fixed_pair, build_random_pair};

    #[test]
    fn large_profile_produces_dense_random_scenarios() {
        let profile = SimulationScaleProfile::large();
        let (baseline, changed) = build_random_pair(123, 11, &profile);
        let baseline_manifest = super::load_manifest_from_bundle(&baseline);
        let changed_manifest = super::load_manifest_from_bundle(&changed);

        assert!(baseline_manifest.expectations.min_hosts >= 10);
        assert!(
            changed_manifest.expectations.min_hosts >= baseline_manifest.expectations.min_hosts
        );
        assert!(baseline_manifest.expectations.min_events >= 12);
        assert!(changed_manifest.expectations.min_events >= 12);
    }

    #[test]
    fn enterprise_profile_keeps_manifest_invariants_across_120_pairs() {
        let profile = SimulationScaleProfile::enterprise();
        for index in 1..=120 {
            let (baseline, changed) = build_random_pair(9001, index, &profile);
            let baseline_manifest = super::load_manifest_from_bundle(&baseline);
            let changed_manifest = super::load_manifest_from_bundle(&changed);

            assert!(
                baseline_manifest.expectations.min_hosts >= 30,
                "baseline hosts for pair {index}"
            );
            assert!(
                changed_manifest.expectations.min_hosts >= baseline_manifest.expectations.min_hosts
            );
            assert!(
                baseline_manifest.expectations.min_events >= 25,
                "baseline events for pair {index}"
            );
            assert!(
                changed_manifest.expectations.min_events >= 25,
                "changed events for pair {index}"
            );
            assert!(
                changed_manifest
                    .expectations
                    .required_finding_types
                    .iter()
                    .any(|item| item == "new_exposed_service"),
                "missing expected changed finding type for pair {index}"
            );
        }
    }

    #[test]
    fn fixed_pair_still_has_diff_expectations() {
        let (baseline, changed) = build_fixed_pair();
        let baseline_manifest = super::load_manifest_from_bundle(&baseline);
        let changed_manifest = super::load_manifest_from_bundle(&changed);
        assert!(baseline_manifest.compare_to.is_none());
        assert_eq!(changed_manifest.compare_to.as_deref(), Some("zakladni"));
        assert!(
            changed_manifest
                .expectations
                .expected_changed_services
                .len()
                >= 2
        );
    }
}

#[cfg(test)]
fn load_manifest_from_bundle(bundle: &ScenarioBundle) -> ScenarioManifest {
    serde_json::from_slice(&serde_json::to_vec(&bundle.manifest).expect("manifest serialization"))
        .expect("manifest deserialization")
}
