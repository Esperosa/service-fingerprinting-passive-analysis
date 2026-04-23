use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    error::{BakulaError, Result},
    model::{ActiveCheckRecord, Confidence, HostReport, Severity, WebProbeRecord},
    paths,
};

#[derive(Debug, Clone, Default)]
pub struct WebScanConfig {
    pub enable_httpx: bool,
    pub enable_nuclei: bool,
    pub httpx_bin: Option<PathBuf>,
    pub nuclei_bin: Option<PathBuf>,
    pub nuclei_templates_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct WebScanArtifacts {
    pub httpx_output_jsonl: Option<String>,
    pub nuclei_output_jsonl: Option<String>,
}

#[derive(Debug, Clone)]
struct WebTarget {
    service_key: String,
    url: String,
    scheme: String,
    ip: String,
    port: u16,
}

pub fn enrich_http_services(
    hosts: &mut [HostReport],
    workspace: &Path,
    run_id: &str,
    config: &WebScanConfig,
) -> Result<WebScanArtifacts> {
    if !config.enable_httpx && !config.enable_nuclei {
        return Ok(WebScanArtifacts::default());
    }

    let targets = collect_web_targets(hosts);
    if targets.is_empty() {
        return Ok(WebScanArtifacts::default());
    }

    let temp_dir = workspace.join("tmp").join(format!("{run_id}-webscan"));
    fs::create_dir_all(&temp_dir)?;

    let mut artifacts = WebScanArtifacts::default();
    let httpx_path = if config.enable_httpx || config.enable_nuclei {
        Some(resolve_tool_path(
            config.httpx_bin.as_deref(),
            "httpx.exe",
            &[
                workspace
                    .join("tools")
                    .join("projectdiscovery")
                    .join("httpx")
                    .join("httpx.exe"),
                paths::project_path(&["tools", "projectdiscovery", "httpx", "httpx.exe"]),
            ],
        )?)
    } else {
        None
    };

    let httpx_records = if config.enable_httpx || config.enable_nuclei {
        let httpx_output = temp_dir.join("httpx.jsonl");
        run_httpx(
            httpx_path
                .as_deref()
                .ok_or_else(|| BakulaError::Processing("httpx neni dostupny.".to_string()))?,
            &targets,
            &httpx_output,
        )?;
        let output = fs::read_to_string(&httpx_output)?;
        let records = parse_httpx_output(&output)?;
        attach_httpx_records(hosts, &targets, &records);
        artifacts.httpx_output_jsonl = Some(output);
        records
    } else {
        Vec::new()
    };

    if config.enable_nuclei {
        let nuclei_path = resolve_tool_path(
            config.nuclei_bin.as_deref(),
            "nuclei.exe",
            &[
                workspace
                    .join("tools")
                    .join("projectdiscovery")
                    .join("nuclei")
                    .join("nuclei.exe"),
                paths::project_path(&["tools", "projectdiscovery", "nuclei", "nuclei.exe"]),
            ],
        )?;
        let templates_dir = config
            .nuclei_templates_dir
            .clone()
            .unwrap_or_else(default_nuclei_templates_dir);
        if !templates_dir.is_dir() {
            return Err(BakulaError::Processing(format!(
                "Adresar s ridicimi nuclei templaty neexistuje: {}",
                templates_dir.display()
            )));
        }

        let nuclei_output = temp_dir.join("nuclei.jsonl");
        let probes_by_url = httpx_records
            .iter()
            .map(|item| (item.url.clone(), item.clone()))
            .collect::<HashMap<_, _>>();
        run_nuclei(
            &nuclei_path,
            &templates_dir,
            &targets,
            &probes_by_url,
            &nuclei_output,
        )?;
        let output = fs::read_to_string(&nuclei_output).unwrap_or_default();
        let checks = parse_nuclei_output(&output)?;
        attach_nuclei_checks(hosts, &targets, &checks);
        artifacts.nuclei_output_jsonl = Some(output);
    }

    Ok(artifacts)
}

fn default_nuclei_templates_dir() -> PathBuf {
    if let Ok(user_profile) = env::var("USERPROFILE") {
        let local = PathBuf::from(user_profile)
            .join("nuclei-templates")
            .join("bakula-controlled");
        if local.is_dir() {
            return local;
        }
    }
    paths::project_path(&["resources", "nuclei-templates", "controlled"])
}

fn collect_web_targets(hosts: &[HostReport]) -> Vec<WebTarget> {
    let mut targets = hosts
        .iter()
        .flat_map(|host| {
            host.services.iter().filter_map(|service| {
                if service.port_state != "open" || !is_http_candidate(service) {
                    return None;
                }
                let scheme = if is_https_candidate(service) {
                    "https"
                } else {
                    "http"
                };
                Some(WebTarget {
                    service_key: service.service_key.clone(),
                    url: format!("{scheme}://{}:{}", host.ip, service.port),
                    scheme: scheme.to_string(),
                    ip: host.ip.clone(),
                    port: service.port,
                })
            })
        })
        .collect::<Vec<_>>();
    targets.sort_by(|left, right| left.url.cmp(&right.url));
    targets.dedup_by(|left, right| left.url == right.url);
    targets
}

fn is_http_candidate(service: &crate::model::ServiceReport) -> bool {
    let name = service.inventory.service_name.to_ascii_lowercase();
    name.contains("http")
        || matches!(
            service.port,
            80 | 81
                | 3000
                | 5000
                | 5601
                | 8000
                | 8080
                | 8081
                | 8443
                | 8888
                | 9200
                | 18080
                | 18081
                | 18082
        )
}

fn is_https_candidate(service: &crate::model::ServiceReport) -> bool {
    let name = service.inventory.service_name.to_ascii_lowercase();
    name.contains("https") || matches!(service.port, 443 | 8443)
}

fn resolve_tool_path(
    explicit: Option<&Path>,
    file_name: &str,
    defaults: &[PathBuf],
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    for path in defaults {
        if path.is_file() {
            return Ok(path.clone());
        }
    }

    if let Some(paths) = env::var_os("PATH") {
        for path in env::split_paths(&paths) {
            let candidate = path.join(file_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(BakulaError::Processing(format!(
        "Nepodarilo se najit nastroj {file_name}. Ocekava se v tools/projectdiscovery nebo explicitne v argumentu."
    )))
}

fn run_httpx(binary: &Path, targets: &[WebTarget], output_path: &Path) -> Result<()> {
    let list_path = output_path.with_file_name("httpx-targets.txt");
    fs::write(
        &list_path,
        targets
            .iter()
            .map(|target| target.url.clone())
            .collect::<Vec<_>>()
            .join("\n"),
    )?;

    let status = Command::new(binary)
        .args([
            "-l",
            list_path.to_string_lossy().as_ref(),
            "-j",
            "-silent",
            "-duc",
            "-nfs",
            "-sc",
            "-cl",
            "-ct",
            "-location",
            "-favicon",
            "-rt",
            "-title",
            "-server",
            "-tls-grab",
            "-timeout",
            "5",
            "-retries",
            "1",
            "-fr",
            "-o",
            output_path.to_string_lossy().as_ref(),
        ])
        .status()?;

    if !status.success() {
        return Err(BakulaError::Processing(format!(
            "httpx selhal nad vystupem {}",
            output_path.display()
        )));
    }
    Ok(())
}

fn run_nuclei(
    binary: &Path,
    templates_dir: &Path,
    targets: &[WebTarget],
    probes_by_url: &HashMap<String, HttpxResult>,
    output_path: &Path,
) -> Result<()> {
    let all_urls = targets
        .iter()
        .filter_map(|target| {
            probes_by_url
                .get(&target.url)
                .map(|record| record.url.clone())
                .or_else(|| {
                    probes_by_url
                        .get(&target.url)
                        .and_then(|_| Some(target.url.clone()))
                })
        })
        .collect::<Vec<_>>();
    let http_only_urls = targets
        .iter()
        .filter(|target| target.scheme == "http")
        .filter_map(|target| {
            probes_by_url
                .get(&target.url)
                .map(|record| record.url.clone())
        })
        .collect::<Vec<_>>();

    let mut combined = Vec::new();
    let shared_templates = vec![
        templates_dir.join("prometheus-metrics-exposed.yaml"),
        templates_dir.join("swagger-ui-exposed.yaml"),
        templates_dir.join("directory-listing-exposed.yaml"),
        templates_dir.join("grafana-login-exposed.yaml"),
        templates_dir.join("kibana-login-exposed.yaml"),
        templates_dir.join("openapi-json-exposed.yaml"),
        templates_dir.join("actuator-health-exposed.yaml"),
    ];
    if !all_urls.is_empty() {
        let chunk = run_nuclei_batch(binary, &all_urls, &shared_templates)?;
        if !chunk.is_empty() {
            combined.push(chunk);
        }
    }

    let http_only_templates = vec![templates_dir.join("basic-auth-over-http.yaml")];
    if !http_only_urls.is_empty() {
        let chunk = run_nuclei_batch(binary, &http_only_urls, &http_only_templates)?;
        if !chunk.is_empty() {
            combined.push(chunk);
        }
    }

    fs::write(output_path, combined.join("\n"))?;
    Ok(())
}

fn run_nuclei_batch(binary: &Path, urls: &[String], templates: &[PathBuf]) -> Result<String> {
    let temp_root = env::temp_dir().join(format!(
        "bakula-nuclei-{}",
        Utc::now().format("%Y%m%d%H%M%S%3f")
    ));
    fs::create_dir_all(&temp_root)?;
    let targets_path = temp_root.join("targets.txt");
    let output_path = temp_root.join("nuclei.jsonl");
    fs::write(&targets_path, urls.join("\n"))?;

    let mut command = Command::new(binary);
    command.args([
        "-l",
        targets_path.to_string_lossy().as_ref(),
        "-silent",
        "-duc",
        "-nh",
        "-or",
        "-fr",
        "-jle",
        output_path.to_string_lossy().as_ref(),
    ]);
    for template in templates {
        if template.is_file() {
            command.arg("-t").arg(template);
        }
    }

    let status = command.status()?;
    if !status.success() {
        return Err(BakulaError::Processing(format!(
            "nuclei selhal pro sadu templatu {}",
            templates
                .iter()
                .map(|item| item.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let output = fs::read_to_string(&output_path).unwrap_or_default();
    let _ = fs::remove_dir_all(&temp_root);
    Ok(output)
}

#[derive(Debug, Clone)]
struct HttpxResult {
    input: Option<String>,
    url: String,
    scheme: String,
    port: u16,
    ip: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    webserver: Option<String>,
    content_type: Option<String>,
    content_length: Option<u64>,
    location: Option<String>,
    favicon: Option<i64>,
    technologies: Vec<String>,
    response_time_ms: Option<u64>,
    tls_subject_cn: Option<String>,
    tls_subject_an: Vec<String>,
    tls_issuer_cn: Option<String>,
}

fn parse_httpx_output(output: &str) -> Result<Vec<HttpxResult>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_httpx_line)
        .collect()
}

fn parse_httpx_line(line: &str) -> Result<HttpxResult> {
    let value: Value = serde_json::from_str(line)?;
    let url = value["url"]
        .as_str()
        .or_else(|| value["input"].as_str())
        .ok_or_else(|| {
            BakulaError::Processing("httpx vystup neobsahuje pole url ani input.".to_string())
        })?
        .to_string();

    let port = value["port"]
        .as_u64()
        .or_else(|| extract_port_from_url(&url).map(u64::from))
        .unwrap_or(0) as u16;
    let scheme = value["scheme"]
        .as_str()
        .or_else(|| infer_scheme_from_url(&url))
        .unwrap_or("http")
        .to_string();
    let response_time_ms = parse_response_time_ms(
        value["response-time"]
            .as_str()
            .or_else(|| value["response_time"].as_str())
            .or_else(|| value["time"].as_str()),
    );
    let (tls_subject_cn, tls_subject_an, tls_issuer_cn) = extract_tls_fields(&value);

    Ok(HttpxResult {
        input: value["input"].as_str().map(ToString::to_string),
        url,
        scheme,
        port,
        ip: value["ip"].as_str().map(ToString::to_string),
        status_code: value["status-code"]
            .as_u64()
            .or_else(|| value["status_code"].as_u64())
            .map(|item| item as u16),
        title: value["title"].as_str().map(ToString::to_string),
        webserver: value["webserver"]
            .as_str()
            .or_else(|| value["web_server"].as_str())
            .map(ToString::to_string),
        content_type: value["content-type"]
            .as_str()
            .or_else(|| value["content_type"].as_str())
            .map(ToString::to_string),
        content_length: value["content-length"]
            .as_u64()
            .or_else(|| value["content_length"].as_u64()),
        location: value["location"].as_str().map(ToString::to_string),
        favicon: value["favicon"].as_i64(),
        technologies: value["tech"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        response_time_ms,
        tls_subject_cn,
        tls_subject_an,
        tls_issuer_cn,
    })
}

fn attach_httpx_records(hosts: &mut [HostReport], targets: &[WebTarget], records: &[HttpxResult]) {
    let index = targets
        .iter()
        .map(|item| (item.url.clone(), item))
        .collect::<HashMap<_, _>>();

    for record in records {
        let target = record
            .input
            .as_ref()
            .and_then(|input| index.get(input).copied())
            .or_else(|| index.get(&record.url).copied())
            .or_else(|| {
                targets.iter().find(|target| {
                    target.port == record.port
                        && (record.ip.as_deref() == Some(target.ip.as_str())
                            || record
                                .url
                                .contains(&format!("{}:{}", target.ip, target.port)))
                })
            });
        let Some(target) = target else {
            continue;
        };

        if let Some(service) = hosts
            .iter_mut()
            .flat_map(|host| host.services.iter_mut())
            .find(|service| service.service_key == target.service_key)
        {
            service.web_probe = Some(WebProbeRecord {
                source: "httpx".to_string(),
                scanned_at: Utc::now(),
                url: target.url.clone(),
                final_url: if record.url != target.url {
                    Some(record.url.clone())
                } else {
                    record.location.clone()
                },
                scheme: record.scheme.clone(),
                status_code: record.status_code,
                title: record.title.clone(),
                webserver: record.webserver.clone(),
                technologies: record.technologies.clone(),
                content_type: record.content_type.clone(),
                content_length: record.content_length,
                favicon_mmh3: record.favicon,
                tls_subject_cn: record.tls_subject_cn.clone(),
                tls_subject_an: record.tls_subject_an.clone(),
                tls_issuer_cn: record.tls_issuer_cn.clone(),
                response_time_ms: record.response_time_ms,
            });
        }
    }
}

fn parse_nuclei_output(output: &str) -> Result<Vec<NucleiResult>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_nuclei_line)
        .collect()
}

#[derive(Debug, Clone)]
struct NucleiResult {
    template_id: String,
    template_name: String,
    severity: Severity,
    matched_url: String,
    matcher_name: Option<String>,
    description: Option<String>,
    evidence: Vec<String>,
    matched_at: DateTime<Utc>,
}

fn parse_nuclei_line(line: &str) -> Result<NucleiResult> {
    let value: Value = serde_json::from_str(line)?;
    let info = &value["info"];
    let severity = severity_from_text(
        info["severity"]
            .as_str()
            .or_else(|| value["severity"].as_str())
            .unwrap_or("medium"),
    );
    let matched_url = value["matched-at"]
        .as_str()
        .or_else(|| value["matched"].as_str())
        .or_else(|| value["host"].as_str())
        .ok_or_else(|| {
            BakulaError::Processing("nuclei vystup neobsahuje pole matched-at/host.".to_string())
        })?
        .to_string();
    let matched_at = value["timestamp"]
        .as_str()
        .and_then(|item| DateTime::parse_from_rfc3339(item).ok())
        .map(|item| item.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let mut evidence = Vec::new();
    if let Some(extracted) = value["extracted-results"].as_array() {
        evidence.extend(
            extracted
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string)),
        );
    }
    if evidence.is_empty() {
        evidence.push(format!("matched_url={matched_url}"));
    }

    Ok(NucleiResult {
        template_id: value["template-id"]
            .as_str()
            .unwrap_or("unknown-template")
            .to_string(),
        template_name: info["name"]
            .as_str()
            .unwrap_or("Neznamy nuclei check")
            .to_string(),
        severity,
        matched_url,
        matcher_name: value["matcher-name"].as_str().map(ToString::to_string),
        description: info["description"].as_str().map(ToString::to_string),
        evidence,
        matched_at,
    })
}

fn attach_nuclei_checks(hosts: &mut [HostReport], targets: &[WebTarget], checks: &[NucleiResult]) {
    for check in checks {
        let Some(target) = match_nuclei_target(targets, &check.matched_url) else {
            continue;
        };
        if let Some(service) = hosts
            .iter_mut()
            .flat_map(|host| host.services.iter_mut())
            .find(|service| service.service_key == target.service_key)
        {
            service.active_checks.push(ActiveCheckRecord {
                check_id: format!(
                    "active-check:{}:{}:{}",
                    check.template_id, target.service_key, check.matched_url
                ),
                source: "nuclei".to_string(),
                template_id: check.template_id.clone(),
                template_name: check.template_name.clone(),
                severity: check.severity,
                confidence: Confidence::High,
                matched_at: check.matched_at,
                matched_url: check.matched_url.clone(),
                matcher_name: check.matcher_name.clone(),
                description: check.description.clone(),
                evidence: check.evidence.clone(),
            });
            service.active_checks.sort_by(|left, right| {
                right
                    .severity
                    .cmp(&left.severity)
                    .then(left.template_id.cmp(&right.template_id))
            });
            service
                .active_checks
                .dedup_by(|left, right| left.template_id == right.template_id);
        }
    }
}

fn match_nuclei_target<'a>(targets: &'a [WebTarget], matched_url: &str) -> Option<&'a WebTarget> {
    targets
        .iter()
        .find(|target| matched_url.starts_with(&target.url))
        .or_else(|| {
            let port = extract_port_from_url(matched_url)?;
            let ip = extract_host_from_url(matched_url)?;
            targets
                .iter()
                .find(|target| target.port == port && target.ip == ip)
        })
}

fn infer_scheme_from_url(url: &str) -> Option<&str> {
    if url.starts_with("https://") {
        Some("https")
    } else if url.starts_with("http://") {
        Some("http")
    } else {
        None
    }
}

fn extract_port_from_url(url: &str) -> Option<u16> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    if let Some((_, port)) = host_port.rsplit_once(':') {
        return port.parse().ok();
    }
    match infer_scheme_from_url(url) {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}

fn extract_host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    Some(host_port.split(':').next()?.to_string())
}

fn parse_response_time_ms(value: Option<&str>) -> Option<u64> {
    let raw = value?.trim();
    if let Some(ms) = raw.strip_suffix("ms") {
        let value = ms.trim().parse::<f64>().ok()?;
        return Some(value.round() as u64);
    }
    if let Some(seconds) = raw.strip_suffix('s') {
        let value = seconds.trim().parse::<f64>().ok()?;
        return Some((value * 1000.0).round() as u64);
    }
    raw.parse::<u64>().ok()
}

fn extract_tls_fields(value: &Value) -> (Option<String>, Vec<String>, Option<String>) {
    let tls = value
        .get("tls-grab")
        .or_else(|| value.get("tls_grab"))
        .unwrap_or(&Value::Null);

    let subject_cn = tls
        .pointer("/subject_cn")
        .and_then(|item| item.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            tls.pointer("/subject-an")
                .and_then(|item| item.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.as_str())
                .map(ToString::to_string)
        });
    let subject_an = tls
        .pointer("/subject-an")
        .and_then(|item| item.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let issuer_cn = tls
        .pointer("/issuer_cn")
        .and_then(|item| item.as_str())
        .map(ToString::to_string);
    (subject_cn, subject_an, issuer_cn)
}

fn severity_from_text(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_nuclei_templates_dir, extract_port_from_url, parse_httpx_line, parse_nuclei_line,
        parse_response_time_ms,
    };
    use std::fs;

    #[test]
    fn parses_httpx_json_line() {
        let record = parse_httpx_line(
            r#"{"input":"http://127.0.0.1:8080","url":"http://127.0.0.1:8080","port":8080,"scheme":"http","status-code":200,"title":"Bakula","webserver":"Bakula","content-type":"text/html","content-length":1234,"response-time":"45ms","favicon":123456}"#,
        )
        .expect("httpx parse");
        assert_eq!(record.port, 8080);
        assert_eq!(record.status_code, Some(200));
        assert_eq!(record.title.as_deref(), Some("Bakula"));
        assert_eq!(record.response_time_ms, Some(45));
    }

    #[test]
    fn parses_nuclei_json_line() {
        let record = parse_nuclei_line(
            r#"{"template-id":"bakula-basic-auth-over-http","matcher-name":"basic-auth","matched-at":"http://127.0.0.1:18081/","timestamp":"2026-04-08T10:00:00Z","info":{"name":"HTTP Basic Authentication over cleartext","severity":"high","description":"Basic auth challenge is available over plaintext HTTP."},"extracted-results":["WWW-Authenticate: Basic realm=Admin"]}"#,
        )
        .expect("nuclei parse");
        assert_eq!(record.template_id, "bakula-basic-auth-over-http");
        assert_eq!(record.severity, crate::model::Severity::High);
        assert_eq!(record.evidence.len(), 1);
    }

    #[test]
    fn parses_response_time_variants() {
        assert_eq!(parse_response_time_ms(Some("45ms")), Some(45));
        assert_eq!(parse_response_time_ms(Some("1.2s")), Some(1200));
        assert_eq!(
            extract_port_from_url("https://127.0.0.1:8443/path"),
            Some(8443)
        );
        assert_eq!(extract_port_from_url("http://127.0.0.1/"), Some(80));
    }

    #[test]
    fn controlled_templates_have_required_sections() {
        let templates_dir = default_nuclei_templates_dir();
        let entries = fs::read_dir(&templates_dir)
            .expect("templates dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("yaml"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert!(
            entries.len() >= 4,
            "expected at least 4 controlled templates"
        );

        for entry in entries {
            let content = fs::read_to_string(entry.path()).expect("template content");
            assert!(content.contains("id:"));
            assert!(content.contains("info:"));
            assert!(content.contains("severity:"));
            assert!(content.contains("http:"));
            assert!(content.contains("matchers:"));
        }
    }

    #[test]
    fn parses_large_batch_of_synthetic_template_results() {
        for index in 0..160 {
            let severity = if index % 3 == 0 {
                "high"
            } else if index % 3 == 1 {
                "medium"
            } else {
                "low"
            };
            let line = format!(
                r#"{{"template-id":"bakula-synth-{index}","matcher-name":"m{index}","matched-at":"http://127.0.0.1:{}/","timestamp":"2026-04-08T10:00:00Z","info":{{"name":"Synthetic template #{index}","severity":"{severity}","description":"Synthetic batch parse."}},"extracted-results":["evidence-{index}"]}}"#,
                18080 + (index % 100)
            );
            let record = parse_nuclei_line(&line).expect("synthetic nuclei parse");
            assert!(record.template_id.starts_with("bakula-synth-"));
            assert_eq!(record.evidence.len(), 1);
        }
    }
}
