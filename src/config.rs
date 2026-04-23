use std::{
    env, fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{BakulaError, Result},
    model::AppConfig,
};

pub fn load_or_default(path: &Path) -> Result<AppConfig> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let config = toml::from_str(&content)
            .map_err(|error| BakulaError::Config(format!("Nelze nacist konfiguraci: {error}")))?;
        validate(&config)?;
        Ok(config)
    } else {
        let config = AppConfig::default();
        write(path, &config)?;
        Ok(config)
    }
}

pub fn write(path: &Path, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    validate(config)?;
    let content = toml::to_string_pretty(config)
        .map_err(|error| BakulaError::Config(format!("Nelze serializovat konfiguraci: {error}")))?;
    fs::write(path, content)?;
    Ok(())
}

pub fn validate(config: &AppConfig) -> Result<()> {
    if config.workspace_root.trim().is_empty() {
        return Err(BakulaError::Config(
            "workspace_root nesmi byt prazdny".to_string(),
        ));
    }
    if config.host.trim().is_empty() {
        return Err(BakulaError::Config("host nesmi byt prazdny".to_string()));
    }
    if config.port == 0 {
        return Err(BakulaError::Config(
            "port musi byt v intervalu 1-65535".to_string(),
        ));
    }
    if config.retention.max_runs == 0 {
        return Err(BakulaError::Config(
            "retention.max_runs musi byt alespon 1".to_string(),
        ));
    }
    if config.security.require_api_token
        && config
            .security
            .api_token_env
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
    {
        return Err(BakulaError::Config(
            "pri zapnutem security.require_api_token musi byt nastaven security.api_token_env"
                .to_string(),
        ));
    }
    if config.platform.enabled && config.platform.database_path.trim().is_empty() {
        return Err(BakulaError::Config(
            "pri zapnute platform.enabled musi byt nastaven platform.database_path".to_string(),
        ));
    }
    if config.platform.enabled && config.platform.leader_lease_seconds <= 0 {
        return Err(BakulaError::Config(
            "platform.leader_lease_seconds musi byt kladne cislo".to_string(),
        ));
    }
    if config.platform.enabled && config.platform.job_lease_seconds <= 0 {
        return Err(BakulaError::Config(
            "platform.job_lease_seconds musi byt kladne cislo".to_string(),
        ));
    }
    Ok(())
}

pub fn resolve_api_token(config: &AppConfig) -> Result<Option<String>> {
    let token = config
        .security
        .api_token_env
        .as_deref()
        .and_then(|name| env::var(name).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if config.security.require_api_token && token.is_none() {
        return Err(BakulaError::Config(format!(
            "API token je vyzadovan, ale promenna prostredi {} neni nastavena",
            config
                .security
                .api_token_env
                .as_deref()
                .unwrap_or("BAKULA_API_TOKEN")
        )));
    }

    Ok(token)
}

pub fn resolve_platform_db_path(config: &AppConfig) -> Option<PathBuf> {
    if !config.platform.enabled {
        return None;
    }
    let path = PathBuf::from(&config.platform.database_path);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(PathBuf::from(&config.workspace_root).join(path))
    }
}

pub fn resolve_platform_target(config: &AppConfig) -> Option<String> {
    if !config.platform.enabled {
        return None;
    }
    let raw = config.platform.database_path.trim();
    if raw.starts_with("postgres://") || raw.starts_with("postgresql://") {
        return Some(raw.to_string());
    }
    resolve_platform_db_path(config).map(|path| path.to_string_lossy().to_string())
}
