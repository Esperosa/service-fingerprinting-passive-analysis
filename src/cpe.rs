use std::{fs, path::Path};

use serde::Deserialize;

use crate::{
    error::{BakulaError, Result},
    model::{Confidence, CpeCandidate, HostReport},
};

#[derive(Debug, Deserialize)]
struct CpeRule {
    name: String,
    service_name: Option<String>,
    product_contains: Option<String>,
    vendor: String,
    product: String,
}

#[derive(Debug, Clone)]
pub struct ParsedCpe23 {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
}

pub fn enrich_services_with_cpe(hosts: &mut [HostReport], data_dir: &Path) -> Result<()> {
    let rules = load_rules(data_dir)?;
    for service in hosts.iter_mut().flat_map(|host| host.services.iter_mut()) {
        if !service.cpe.is_empty() {
            continue;
        }

        let product = service
            .inventory
            .product
            .clone()
            .unwrap_or_else(|| service.inventory.service_name.clone());
        let version = service.inventory.version.clone();

        if let Some(rule) = rules
            .iter()
            .find(|rule| matches_rule(rule, &service.inventory.service_name, &product))
        {
            let version_part = version.clone().unwrap_or_else(|| "*".to_string());
            service.cpe.push(CpeCandidate {
                cpe23_uri: format!(
                    "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
                    normalize_token(&rule.vendor),
                    normalize_token(&rule.product),
                    normalize_token(&version_part)
                ),
                method: "curated".to_string(),
                confidence: if version.is_some() {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                note: Some(format!("Pravidlo {}.", rule.name)),
            });
            continue;
        }

        if !product.trim().is_empty() {
            let version_part = version.clone().unwrap_or_else(|| "*".to_string());
            service.cpe.push(CpeCandidate {
                cpe23_uri: format!(
                    "cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*",
                    normalize_token(&product),
                    normalize_token(&version_part)
                ),
                method: "partial".to_string(),
                confidence: if version.is_some() {
                    Confidence::Medium
                } else {
                    Confidence::Low
                },
                note: Some("Heuristicke mapovani z nazvu produktu.".to_string()),
            });
        }
    }
    Ok(())
}

fn load_rules(data_dir: &Path) -> Result<Vec<CpeRule>> {
    let path = data_dir.join("cpe_rules.json");
    if !path.exists() {
        return Ok(default_rules());
    }
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|error| BakulaError::Processing(format!("Nelze nacist CPE pravidla: {error}")))
}

fn matches_rule(rule: &CpeRule, service_name: &str, product: &str) -> bool {
    let service_ok = rule
        .service_name
        .as_ref()
        .map(|value| service_name.eq_ignore_ascii_case(value))
        .unwrap_or(true);
    let product_ok = rule
        .product_contains
        .as_ref()
        .map(|value| {
            product
                .to_ascii_lowercase()
                .contains(&value.to_ascii_lowercase())
        })
        .unwrap_or(true);
    service_ok && product_ok
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "_")
        .replace('/', "_")
        .replace('\\', "_")
}

pub fn parse_cpe23_uri(value: &str) -> Option<ParsedCpe23> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() < 6 || parts.first()? != &"cpe" || parts.get(1)? != &"2.3" {
        return None;
    }
    Some(ParsedCpe23 {
        part: parts.get(2)?.to_string(),
        vendor: parts.get(3)?.to_string(),
        product: parts.get(4)?.to_string(),
        version: parts.get(5)?.to_string(),
    })
}

pub fn cpe_matches_target(criteria: &str, target: &str, entry: &serde_json::Value) -> bool {
    let Some(target_cpe) = parse_cpe23_uri(target) else {
        return false;
    };
    let Some(criteria_cpe) = parse_cpe23_uri(criteria) else {
        return false;
    };

    if criteria_cpe.part != target_cpe.part {
        return false;
    }
    if !token_matches(&criteria_cpe.vendor, &target_cpe.vendor) {
        return false;
    }
    if !token_matches(&criteria_cpe.product, &target_cpe.product) {
        return false;
    }

    if criteria_cpe.version != "*"
        && criteria_cpe.version != "-"
        && criteria_cpe.version != target_cpe.version
    {
        return false;
    }

    version_in_range(&target_cpe.version, entry)
}

fn token_matches(criteria: &str, target: &str) -> bool {
    criteria == "*" || criteria == "-" || criteria.eq_ignore_ascii_case(target)
}

fn version_in_range(target_version: &str, entry: &serde_json::Value) -> bool {
    let start_including = entry["versionStartIncluding"].as_str();
    let start_excluding = entry["versionStartExcluding"].as_str();
    let end_including = entry["versionEndIncluding"].as_str();
    let end_excluding = entry["versionEndExcluding"].as_str();

    if target_version == "*" || target_version == "-" {
        return start_including.is_none()
            && start_excluding.is_none()
            && end_including.is_none()
            && end_excluding.is_none();
    }

    if let Some(start) = start_including {
        if compare_versions(target_version, start).is_lt() {
            return false;
        }
    }
    if let Some(start) = start_excluding {
        let ordering = compare_versions(target_version, start);
        if ordering.is_lt() || ordering.is_eq() {
            return false;
        }
    }
    if let Some(end) = end_including {
        if compare_versions(target_version, end).is_gt() {
            return false;
        }
    }
    if let Some(end) = end_excluding {
        let ordering = compare_versions(target_version, end);
        if ordering.is_gt() || ordering.is_eq() {
            return false;
        }
    }
    true
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = split_version(left);
    let right_parts = split_version(right);
    let max = left_parts.len().max(right_parts.len());
    for index in 0..max {
        let left_part = left_parts.get(index).cloned().unwrap_or_default();
        let right_part = right_parts.get(index).cloned().unwrap_or_default();
        let ordering = compare_part(&left_part, &right_part);
        if !ordering.is_eq() {
            return ordering;
        }
    }
    std::cmp::Ordering::Equal
}

fn split_version(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut is_digit = None;

    for ch in value.chars() {
        let digit = ch.is_ascii_digit();
        if ch == '.' || ch == '-' || ch == '_' {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            is_digit = None;
            continue;
        }

        if let Some(flag) = is_digit {
            if flag != digit && !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
        }
        is_digit = Some(digit);
        current.push(ch.to_ascii_lowercase());
    }

    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn compare_part(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(left_number), Ok(right_number)) => left_number.cmp(&right_number),
        _ => left.cmp(right),
    }
}

fn default_rules() -> Vec<CpeRule> {
    vec![
        CpeRule {
            name: "apache-httpd".to_string(),
            service_name: Some("http".to_string()),
            product_contains: Some("apache".to_string()),
            vendor: "apache".to_string(),
            product: "http_server".to_string(),
        },
        CpeRule {
            name: "nginx".to_string(),
            service_name: Some("http".to_string()),
            product_contains: Some("nginx".to_string()),
            vendor: "nginx".to_string(),
            product: "nginx".to_string(),
        },
        CpeRule {
            name: "openssh".to_string(),
            service_name: Some("ssh".to_string()),
            product_contains: Some("openssh".to_string()),
            vendor: "openbsd".to_string(),
            product: "openssh".to_string(),
        },
        CpeRule {
            name: "vsftpd".to_string(),
            service_name: Some("ftp".to_string()),
            product_contains: Some("vsftpd".to_string()),
            vendor: "vsftpd_project".to_string(),
            product: "vsftpd".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{compare_versions, cpe_matches_target, parse_cpe23_uri};

    #[test]
    fn parse_cpe23_extracts_vendor_product_and_version() {
        let cpe = parse_cpe23_uri("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
            .expect("parsed cpe");
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.49");
    }

    #[test]
    fn compare_versions_handles_numeric_tokens() {
        assert!(compare_versions("2.4.58", "2.4.49").is_gt());
        assert!(compare_versions("2.4.49", "2.4.49").is_eq());
        assert!(compare_versions("8.9", "9.0").is_lt());
    }

    #[test]
    fn cpe_match_respects_version_ranges() {
        let entry = serde_json::json!({
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.0",
            "versionEndExcluding": "2.4.50"
        });
        assert!(cpe_matches_target(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            &entry
        ));
        assert!(!cpe_matches_target(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
            &entry
        ));
    }
}
