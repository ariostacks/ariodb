//! Reading and checking the ariodb config file.

use crate::tls::TlsMode;
use crate::upstream::Target;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::Path;

/// The whole config file, as it appears in `ariodb.toml`.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: Database,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub on_failure: FailureMode,
    #[serde(default)]
    pub agents: Vec<Agent>,
    #[serde(default)]
    pub proxy: Proxy,
    #[serde(default)]
    pub journal: Journal,
    /// Extra database logins, so different agents can use different roles.
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// CEL rules on top of each agent's built-in policy.
    #[serde(default)]
    pub rules: Vec<crate::rules::RuleConfig>,
    /// Who can approve statements that rules hold for approval.
    #[serde(default)]
    pub approvers: Vec<crate::approvals::ApproverConfig>,
    #[serde(default)]
    pub approvals: crate::approvals::Settings,
    #[serde(default)]
    pub dashboard: Dashboard,
    #[serde(default)]
    pub audit: crate::audit::Settings,
    #[serde(default)]
    pub clickhouse: ClickHouse,
    /// Side processes (cloud-sql-proxy, SSH port-forwards) that carry
    /// connections to the database. Started by `ariodb serve`.
    #[serde(default)]
    pub tunnels: Vec<crate::tunnels::TunnelConfig>,
}

/// ClickHouse: ariodb fronts its HTTP interface and its native protocol.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ClickHouse {
    /// Where agents send ClickHouse HTTP requests. Empty turns it off.
    pub http_listen: String,
    /// The real ClickHouse HTTP interface, such as http://127.0.0.1:8123.
    pub http_url: String,
    /// Where agents connect with the native protocol (clickhouse-client). Empty turns it off.
    pub native_listen: String,
    /// The real ClickHouse native port, such as 127.0.0.1:9000.
    pub native_addr: String,
    /// The ClickHouse login ariodb uses; agents never see it.
    pub user: String,
    pub password_env: Option<String>,
    pub password_secret: Option<String>,
    /// For https:// upstreams with a private CA.
    pub accept_invalid_certificate: bool,
    /// Reach ClickHouse (both interfaces) through this tunnel. The tunnel
    /// must forward to whichever port is used, HTTP or native.
    pub tunnel: Option<String>,
}

impl Default for ClickHouse {
    fn default() -> Self {
        ClickHouse {
            http_listen: String::new(),
            http_url: "http://127.0.0.1:8123".to_string(),
            native_listen: String::new(),
            native_addr: "127.0.0.1:9000".to_string(),
            user: "default".to_string(),
            password_env: None,
            password_secret: None,
            accept_invalid_certificate: false,
            tunnel: None,
        }
    }
}

/// An agent's ClickHouse access, separate from its Postgres access.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseAccess {
    pub access: Access,
    pub tables: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    /// Where the dashboard and approval callbacks listen. Empty turns it off.
    pub listen: String,
    /// The address people and Slack use to reach the dashboard, for links.
    pub public_url: String,
    /// Let the dashboard save edits to the config file. Leave off when the
    /// config is managed in Git; the dashboard then shows the edit to copy.
    pub config_writes: bool,
}

impl Default for Dashboard {
    fn default() -> Self {
        Dashboard {
            listen: "127.0.0.1:8080".to_string(),
            public_url: "http://127.0.0.1:8080".to_string(),
            config_writes: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Proxy {
    /// Address agents connect to, as if it were Postgres. Empty turns the
    /// Postgres proxy off.
    pub listen: String,
    /// Certificate and key (PEM) for TLS between agents and ariodb.
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Refuse agents that do not use TLS. Tokens are sent as passwords, so
    /// turn this on whenever agents connect over a network.
    pub require_tls: bool,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            listen: "127.0.0.1:6543".to_string(),
            tls_cert: None,
            tls_key: None,
            require_tls: false,
        }
    }
}

/// A named database login. Agents pick one with `credential = "<name>"`.
#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub name: String,
    /// Environment variable holding the postgres:// URL for this login.
    pub url_env: Option<String>,
    /// Or: the name of a secret (see `ariodb secret set`) holding the URL.
    pub secret: Option<String>,
    pub tls: Option<TlsMode>,
    pub ca_file: Option<String>,
    /// Connect through this tunnel instead of the URL's host and port.
    pub tunnel: Option<String>,
}

/// Where and how ariodb records every row an agent changes.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Journal {
    pub enabled: bool,
    /// Directory for the change journal and audit log.
    pub dir: String,
    /// Postgres logical replication slot ariodb reads changes from.
    pub slot: String,
    /// Postgres publication listing the tables ariodb protects.
    pub publication: String,
}

impl Default for Journal {
    fn default() -> Self {
        Journal {
            enabled: true,
            dir: ".ariodb".to_string(),
            slot: "ariodb".to_string(),
            publication: "ariodb".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Database {
    pub url: String,
    /// The name of a secret holding the URL, used instead of `url`.
    pub secret: Option<String>,
    /// `disable`, `require` (encrypt, accept any certificate) or `verify`.
    /// Default: `disable` for a database on this host, `verify` otherwise.
    pub tls: Option<TlsMode>,
    /// Extra trusted CA certificate (PEM) for `verify`.
    pub ca_file: Option<String>,
    /// Connect through this tunnel instead of the URL's host and port.
    /// Also used by setup, the journal and undo.
    pub tunnel: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_rows_per_write: u64,
    pub statement_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_rows_per_write: 500,
            statement_timeout_ms: 5000,
        }
    }
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

#[derive(Debug, Clone, Deserialize)]
pub struct Agent {
    pub name: String,
    pub access: Access,
    pub tables: Vec<String>,
    /// Name of the environment variable holding this agent's token.
    /// The token is what the agent uses as its password; it is never the
    /// database password.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Or: the name of a secret holding the token.
    #[serde(default)]
    pub token_secret: Option<String>,
    /// Overrides `limits.max_rows_per_write` for this agent.
    pub max_rows_per_write: Option<u64>,
    /// Which database login this agent's queries run as. Default: `[database]`.
    pub credential: Option<String>,
    /// ClickHouse access, if this agent may use ClickHouse.
    #[serde(default)]
    pub clickhouse: Option<ClickHouseAccess>,
}

impl Agent {
    /// May this agent touch this table? Names are compared after normalising.
    pub fn allows_table(&self, table: &str) -> bool {
        let table = crate::classify::normalise_table(table);
        self.tables
            .iter()
            .any(|t| t == "*" || crate::classify::normalise_table(t) == table)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

/// Everything that can go wrong while loading a config.
#[derive(Debug)]
pub enum ConfigError {
    Unreadable {
        path: String,
        source: std::io::Error,
    },
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
        crate::rules::RuleSet::compile(&self.rules).map_err(ConfigError::Problem)?;
        crate::tunnels::validate(&self.tunnels).map_err(ConfigError::Problem)?;
        let uses = std::iter::once(("[database]".to_string(), &self.database.tunnel))
            .chain(
                self.credentials
                    .iter()
                    .map(|c| (format!("credential '{}'", c.name), &c.tunnel)),
            )
            .chain(std::iter::once((
                "[clickhouse]".to_string(),
                &self.clickhouse.tunnel,
            )));
        for (who, tunnel) in uses {
            if let Some(name) = tunnel
                && !self.tunnels.iter().any(|t| &t.name == name)
            {
                return Err(ConfigError::Problem(format!(
                    "{who} uses tunnel '{name}', which is not defined in [[tunnels]]"
                )));
            }
        }
        crate::approvals::validate(&self.approvers, &self.rules).map_err(ConfigError::Problem)?;
        let mut names = std::collections::HashSet::new();
        for agent in &self.agents {
            if !names.insert(agent.name.as_str()) {
                return Err(ConfigError::Problem(format!(
                    "agent '{}' is listed twice",
                    agent.name
                )));
            }
            if let Some(c) = &agent.credential
                && !self.credentials.iter().any(|cred| &cred.name == c)
            {
                return Err(ConfigError::Problem(format!(
                    "agent '{}' uses credential '{c}', which is not defined",
                    agent.name
                )));
            }
            if agent.token_env.is_some() == agent.token_secret.is_some() {
                return Err(ConfigError::Problem(format!(
                    "agent '{}' needs exactly one of token_env or token_secret",
                    agent.name
                )));
            }
            if agent.tables.is_empty() {
                return Err(ConfigError::Problem(format!(
                    "agent '{}' must list at least one table",
                    agent.name
                )));
            }
        }
        Ok(())
    }

    /// The real database URL. `ARIODB_DATABASE_URL` wins over the config file,
    /// so the password never needs to live in the file.
    pub fn database_url(&self) -> String {
        if let Ok(url) = std::env::var("ARIODB_DATABASE_URL") {
            return url;
        }
        if let Some(name) = &self.database.secret
            && let Ok(Some(url)) = self.secret(name)
        {
            return url;
        }
        self.database.url.clone()
    }

    /// Read a value from the encrypted secret store.
    pub fn secret(&self, name: &str) -> Result<Option<String>, String> {
        crate::secrets::Store::open(Path::new(&self.journal.dir))?.get(name)
    }

    /// The ClickHouse password ariodb uses upstream.
    pub fn clickhouse_password(&self) -> Result<String, String> {
        match (
            &self.clickhouse.password_secret,
            &self.clickhouse.password_env,
        ) {
            (Some(name), _) => self
                .secret(name)?
                .ok_or_else(|| format!("secret '{name}' is not set")),
            (None, Some(env)) => std::env::var(env).map_err(|_| format!("{env} is not set")),
            (None, None) => Ok(String::new()),
        }
    }

    /// An agent's token, from its environment variable or the secret store.
    pub fn agent_token(&self, agent: &Agent) -> Option<String> {
        let value = match (&agent.token_env, &agent.token_secret) {
            (Some(env), _) => std::env::var(env).ok(),
            (None, Some(name)) => self.secret(name).ok().flatten(),
            (None, None) => None,
        };
        value.filter(|t| !t.is_empty())
    }

    /// Where an agent's queries go, and as which database login.
    pub fn target_for(&self, agent: &Agent) -> Result<Target, String> {
        match &agent.credential {
            None => self.through(
                Target::from_url(
                    &self.database_url(),
                    self.database.tls,
                    self.database.ca_file.clone(),
                )?,
                &self.database.tunnel,
            ),
            Some(name) => {
                let cred = self
                    .credentials
                    .iter()
                    .find(|c| &c.name == name)
                    .ok_or_else(|| format!("credential '{name}' is not defined"))?;
                let url = match (&cred.url_env, &cred.secret) {
                    (Some(env), _) => std::env::var(env)
                        .map_err(|_| format!("credential '{name}': set {env} to its postgres:// URL"))?,
                    (None, Some(secret)) => self.secret(secret)?.ok_or_else(|| {
                        format!("credential '{name}': secret '{secret}' is not set (ariodb secret set {secret})")
                    })?,
                    (None, None) => return Err(format!("credential '{name}' needs url_env or secret")),
                };
                let target =
                    Target::from_url(&url, cred.tls.or(self.database.tls), cred.ca_file.clone())?;
                self.through(target, &cred.tunnel)
            }
        }
    }

    /// The admin connection (setup, journal, undo) uses the default database
    /// settings, including its tunnel.
    pub fn admin_target(&self, url: &str) -> Result<Target, String> {
        let target = Target::from_url(url, self.database.tls, self.database.ca_file.clone())?;
        self.through(target, &self.database.tunnel)
    }

    /// Route a connection through the named tunnel, if any.
    fn through(&self, target: Target, tunnel: &Option<String>) -> Result<Target, String> {
        match tunnel {
            None => Ok(target),
            Some(name) => target.through(crate::tunnels::find(&self.tunnels, name)?),
        }
    }

    /// The tunnel ClickHouse traffic goes through, if any.
    fn clickhouse_tunnel(&self) -> Result<Option<&crate::tunnels::TunnelConfig>, String> {
        self.clickhouse
            .tunnel
            .as_deref()
            .map(|name| crate::tunnels::find(&self.tunnels, name))
            .transpose()
    }

    /// Where to open the native-protocol connection to ClickHouse.
    pub fn clickhouse_native_addr(&self) -> Result<String, String> {
        Ok(match self.clickhouse_tunnel()? {
            Some(t) => t.listen.clone(),
            None => self.clickhouse.native_addr.clone(),
        })
    }

    /// The ClickHouse HTTP URL, and, through a tunnel, the name to resolve
    /// to the tunnel's address. Resolving rather than rewriting the host
    /// keeps the real name for TLS.
    pub fn clickhouse_http_url(
        &self,
    ) -> Result<(reqwest::Url, Option<(String, std::net::SocketAddr)>), String> {
        let mut url = reqwest::Url::parse(&self.clickhouse.http_url)
            .map_err(|e| format!("bad clickhouse.http_url: {e}"))?;
        let Some(tunnel) = self.clickhouse_tunnel()? else {
            return Ok((url, None));
        };
        let addr = tunnel.addr()?;
        let bad = |_| "clickhouse.http_url cannot be sent through a tunnel".to_string();
        url.set_port(Some(addr.port())).map_err(bad)?;
        match url.domain().map(str::to_string) {
            Some(domain) => Ok((url, Some((domain, addr)))),
            None => {
                url.set_ip_host(addr.ip()).map_err(bad)?;
                Ok((url, None))
            }
        }
    }

    pub fn agent(&self, name: &str) -> Option<&Agent> {
        self.agents.iter().find(|a| a.name == name)
    }

    /// Every table any agent may write to. These are the tables the journal
    /// must watch for undo to work.
    pub fn protected_tables(&self) -> Vec<String> {
        let mut tables: Vec<String> = self
            .agents
            .iter()
            .filter(|a| a.access == Access::ReadWrite)
            .flat_map(|a| {
                a.tables
                    .iter()
                    .filter(|t| *t != "*")
                    .map(|t| crate::classify::normalise_table(t))
            })
            .collect();
        tables.sort();
        tables.dedup();
        tables
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
        token_env = "ARIODB_TOKEN_TEST"
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
        assert!(matches!(
            Config::from_toml(&text),
            Err(ConfigError::Problem(_))
        ));
    }

    #[test]
    fn rejects_an_unknown_access_level() {
        let text = GOOD.replace("read_write", "superuser");
        assert!(matches!(
            Config::from_toml(&text),
            Err(ConfigError::Invalid(_))
        ));
    }

    const TUNNELLED: &str = r#"
        [database]
        url = "postgres://gw:not-a-real-password@db.internal.example:5432/app"
        tls = "verify"
        tunnel = "pg"

        [[tunnels]]
        name = "pg"
        command = ["cloud-sql-proxy", "--port", "5433", "project:region:instance"]
        listen = "127.0.0.1:5433"

        [[agents]]
        name = "coding-agent"
        access = "read_write"
        tables = ["orders"]
        token_env = "ARIODB_TOKEN_TEST"
    "#;

    #[test]
    fn a_tunnel_changes_where_to_dial_and_nothing_else() {
        let config = Config::from_toml(TUNNELLED).expect("config should load");
        let t = &config.tunnels[0];
        assert_eq!(t.ready_timeout_seconds, 30);
        assert!(t.restart);
        let target = config.target_for(&config.agents[0]).unwrap();
        assert_eq!(target.dial_addr(), "127.0.0.1:5433");
        assert_eq!(target.host, "db.internal.example");
        assert_eq!(target.port, 5432);
        assert_eq!(target.user, "gw");
        assert_eq!(target.password.as_deref(), Some("not-a-real-password"));
        assert_eq!(target.database, "app");
        assert_eq!(target.tls, TlsMode::Verify);
        let admin = config
            .admin_target("postgres://admin@db.internal.example/app")
            .unwrap();
        assert_eq!(admin.dial_addr(), "127.0.0.1:5433");
    }

    #[test]
    fn unknown_and_duplicate_tunnels_are_refused() {
        let unknown = TUNNELLED.replace("tunnel = \"pg\"", "tunnel = \"nope\"");
        let err = Config::from_toml(&unknown).err().unwrap().to_string();
        assert!(err.contains("[database] uses tunnel 'nope'"), "{err}");

        let twice = format!(
            "{TUNNELLED}\n[[tunnels]]\nname = \"pg\"\ncommand = [\"x\"]\nlisten = \"127.0.0.1:5434\"\n"
        );
        let err = Config::from_toml(&twice).err().unwrap().to_string();
        assert!(err.contains("listed twice"), "{err}");

        let empty = TUNNELLED.replace(
            r#"command = ["cloud-sql-proxy", "--port", "5433", "project:region:instance"]"#,
            "command = []",
        );
        let err = Config::from_toml(&empty).err().unwrap().to_string();
        assert!(err.contains("needs a command"), "{err}");

        let cred = format!(
            "{TUNNELLED}\n[[credentials]]\nname = \"ro\"\nurl_env = \"X\"\ntunnel = \"other\"\n"
        );
        let err = Config::from_toml(&cred).err().unwrap().to_string();
        assert!(err.contains("credential 'ro' uses tunnel 'other'"), "{err}");
    }

    #[test]
    fn clickhouse_through_a_tunnel_keeps_its_name_for_tls() {
        let text = format!(
            "{TUNNELLED}\n[clickhouse]\nhttp_url = \"https://ch.internal.example:8443\"\ntunnel = \"pg\"\n"
        );
        let config = Config::from_toml(&text).unwrap();
        let (url, resolve) = config.clickhouse_http_url().unwrap();
        assert_eq!(url.as_str(), "https://ch.internal.example:5433/");
        assert_eq!(
            resolve,
            Some((
                "ch.internal.example".to_string(),
                "127.0.0.1:5433".parse().unwrap()
            ))
        );
        assert_eq!(config.clickhouse_native_addr().unwrap(), "127.0.0.1:5433");
    }

    #[test]
    fn hides_passwords() {
        assert_eq!(
            redact_url("postgres://app:not-a-real-password@db:5432/app"),
            "postgres://app:***@db:5432/app"
        );
        assert_eq!(
            redact_url("postgres://localhost/app"),
            "postgres://localhost/app"
        );
    }
}
