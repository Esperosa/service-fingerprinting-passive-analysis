use chrono::Utc;
use serde::Serialize;

use crate::{
    error::{BakulaError, Result},
    platform,
};

#[derive(Debug, Clone)]
pub struct RedisBrokerConfig {
    pub uri: String,
    pub stream_key: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrokerMessage {
    pub stream_id: String,
    pub job_id: i64,
}

impl RedisBrokerConfig {
    pub fn for_uri(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
            stream_key: "bakula.jobs".to_string(),
            group: "bakula-workers".to_string(),
        }
    }
}

pub fn ensure_group(config: &RedisBrokerConfig) -> Result<()> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let result: redis::RedisResult<String> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg("0")
        .arg("MKSTREAM")
        .query(&mut conn);
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("BUSYGROUP") => Ok(()),
        Err(error) => Err(BakulaError::Processing(format!(
            "Nelze vytvorit Redis consumer group: {error}"
        ))),
    }
}

pub fn publish_job(config: &RedisBrokerConfig, job_id: i64) -> Result<String> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let message_id: String = redis::cmd("XADD")
        .arg(&config.stream_key)
        .arg("*")
        .arg("job_id")
        .arg(job_id)
        .arg("queued_at")
        .arg(Utc::now().to_rfc3339())
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XADD chyba: {error}")))?;
    Ok(message_id)
}

pub fn publish_due_jobs(config: &RedisBrokerConfig, db: &std::path::Path) -> Result<Vec<i64>> {
    ensure_group(config)?;
    let due = platform::list_due_job_ids(db)?;
    let mut published = Vec::new();
    for job_id in due {
        let _ = publish_job(config, job_id)?;
        published.push(job_id);
    }
    Ok(published)
}

pub fn claim_one(
    config: &RedisBrokerConfig,
    consumer: &str,
    block_ms: usize,
) -> Result<Option<BrokerMessage>> {
    ensure_group(config)?;
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let response: redis::Value = redis::cmd("XREADGROUP")
        .arg("GROUP")
        .arg(&config.group)
        .arg(consumer)
        .arg("COUNT")
        .arg(1)
        .arg("BLOCK")
        .arg(block_ms)
        .arg("STREAMS")
        .arg(&config.stream_key)
        .arg(">")
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XREADGROUP chyba: {error}")))?;

    parse_claimed_message(response)
}

pub fn ack(config: &RedisBrokerConfig, stream_id: &str) -> Result<()> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let _: i64 = redis::cmd("XACK")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(stream_id)
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XACK chyba: {error}")))?;
    Ok(())
}

fn parse_claimed_message(value: redis::Value) -> Result<Option<BrokerMessage>> {
    let Some(streams) = value.as_sequence() else {
        return Ok(None);
    };
    let Some(first_stream) = streams.first().and_then(|item| item.as_sequence()) else {
        return Ok(None);
    };
    let Some(entries) = first_stream.get(1).and_then(|item| item.as_sequence()) else {
        return Ok(None);
    };
    let Some(entry) = entries.first().and_then(|item| item.as_sequence()) else {
        return Ok(None);
    };
    let stream_id = entry
        .first()
        .and_then(redis_value_as_string)
        .ok_or_else(|| BakulaError::Processing("Redis zprava neobsahuje stream ID.".to_string()))?
        .to_string();
    let fields = entry
        .get(1)
        .and_then(|item| item.as_sequence())
        .ok_or_else(|| BakulaError::Processing("Redis zprava nema fields.".to_string()))?;
    let mut job_id = None;
    let mut index = 0;
    while index + 1 < fields.len() {
        let key = redis_value_as_string(&fields[index]).unwrap_or_default();
        let value = redis_value_as_string(&fields[index + 1]).unwrap_or_default();
        if key == "job_id" {
            job_id = Some(value.parse::<i64>().map_err(|error| {
                BakulaError::Processing(format!("Neplatne job_id z Redis zpravy: {error}"))
            })?);
        }
        index += 2;
    }
    Ok(job_id.map(|job_id| BrokerMessage { stream_id, job_id }))
}

fn redis_value_as_string(value: &redis::Value) -> Option<&str> {
    match value {
        redis::Value::BulkString(bytes) => std::str::from_utf8(bytes).ok(),
        redis::Value::SimpleString(value) => Some(value.as_str()),
        _ => None,
    }
}
