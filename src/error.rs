use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BakulaError {
    #[error("I/O chyba: {0}")]
    Io(#[from] io::Error),
    #[error("JSON chyba: {0}")]
    Json(#[from] serde_json::Error),
    #[error("XML chyba: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("HTTP chyba: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Chyba konfigurace: {0}")]
    Config(String),
    #[error("Chyba zpracovani: {0}")]
    Processing(String),
}

pub type Result<T> = std::result::Result<T, BakulaError>;
