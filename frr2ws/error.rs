use thiserror::Error;

#[derive(Debug, Error)]
pub enum SuiteError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Scan error: {0}")]
    Scan(String),
}

pub type Result<T> = std::result::Result<T, SuiteError>;
