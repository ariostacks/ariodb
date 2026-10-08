//! Reading and checking the ariodb config file.

use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::Path;

/// The whole config file, as it appears in `ariodb.toml`.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: Database,
    pub limits: Limits,
    #[serde(default)]
    pub on_failure: FailureMode,
    #[serde(default)]
    pub agents: Vec<Agent>,
}

#[derive(Debug, Deserialize)]
pub struct Database {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct Limits {
    pub max_rows_per_write: u64,
    pub statement_timeout_ms: u64,
}

/// What ariodb does when its own checks cannot run.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// Refuse the query. The safe choice, and the default.
    #[default]
    Closed,
    /// Let the query through unchecked.
    Open,
}

#[derive(Debug, Deserialize)]
pub struct Agent {
    pub name: String,
    pub access: Access,
    pub tables: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

/// Everything that can go wrong while loading a config.
#[derive(Debug)]
pub enum ConfigError {
    Unreadable { path: String, source: std::io::Error },
    Invalid(toml::de::Error),
    Problem(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::Unreadable { path, source } => write!(f, "cannot read {path}: {source}"),
            ConfigError::Invalid(err) => write!(f, "config is not valid TOML: {err}"),
            ConfigError::Problem(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Read a config file from disk, parse it and check it.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.display().to_string(),
            source,
        })?;
        Config::from_toml(&text)
    }

    /// Parse and check config text. Split out from `load` so tests need no files.
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text).map_err(ConfigError::Invalid)?;
        config.check()?;
        Ok(config)
    }

    /// Rules that TOML alone cannot express.
    fn check(&self) -> Result<(), ConfigError> {
        let url = &self.database.url;
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            return Err(ConfigError::Problem(
                "database.url must start with postgres:// or postgresql://".to_string(),
            ));
        }
        if self.limits.max_rows_per_write == 0 {
            return Err(ConfigError::Problem(
                "limits.max_rows_per_write must be at least 1".to_string(),
            ));
        }
        for agent in &self.agents {
            if agent.tables.is_empty() {
                return Err(ConfigError::Problem(format!(
                    "agent '{}' must list at least one table",
                    agent.name
                )));
            }
        }
        Ok(())
    }
}

/// Hide the password in a database URL before printing it.
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((credentials, host)) => {
            let user = credentials.split(':').next().unwrap_or("");
            format!("{scheme}://{user}:***@{host}")
        }
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        [database]
        url = "postgres://localhost:5432/app"

        [limits]
        max_rows_per_write = 500
        statement_timeout_ms = 5000

        [[agents]]
        name = "coding-agent"
        access = "read_write"
        tables = ["orders"]
    "#;

    #[test]
    fn reads_a_good_config() {
        let config = Config::from_toml(GOOD).expect("config should load");
        assert_eq!(config.limits.max_rows_per_write, 500);
        assert_eq!(config.on_failure, FailureMode::Closed);
        assert_eq!(config.agents[0].access, Access::ReadWrite);
    }

    #[test]
    fn rejects_a_zero_row_limit() {
        let text = GOOD.replace("max_rows_per_write = 500", "max_rows_per_write = 0");
        assert!(matches!(Config::from_toml(&text), Err(ConfigError::Problem(_))));
    }

    #[test]
    fn rejects_an_unknown_access_level() {
        let text = GOOD.replace("read_write", "superuser");
        assert!(matches!(Config::from_toml(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn hides_passwords() {
        assert_eq!(
            redact_url("postgres://app:not-a-real-password@db:5432/app"),
            "postgres://app:***@db:5432/app"
        );
        assert_eq!(redact_url("postgres://localhost/app"), "postgres://localhost/app");
    }
}
