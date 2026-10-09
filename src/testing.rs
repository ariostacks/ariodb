//! `ariodb test`: replay recorded or hand-written actions against a policy
//! and report any verdict that drifted. Use it in CI before a policy change
//! ships. Exit codes: 0 all match, 1 drift, 2 usage or config error.
//!
//! Fixture format (one object, or an array of them, per `.json` file):
//!
//! ```json
//! {
//!   "name": "agents cannot read secrets",
//!   "action": { "agent": "coding-agent", "sql": { "statement": "SELECT * FROM secrets", "database": "app" } },
//!   "match":  { "verdict": "deny", "rule": "no-secrets" }
//! }
//! ```
//!
//! `verdict` is `allow`, `deny` or `approve`. `rule` is optional; when given,
//! the deciding rule must match too (`policy` means the built-in policy).

use crate::classify;
use crate::config::Config;
use crate::policy::{self, Decision};
use crate::rules::{Facts, Outcome, RuleSet};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    #[serde(default)]
    pub name: Option<String>,
    pub action: Action,
    #[serde(rename = "match")]
    pub expect: Expect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub agent: String,
    /// `postgres` (the default), `clickhouse` or `mysql`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    pub sql: SqlAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlAction {
    pub statement: String,
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expect {
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// What the policy would decide for one statement string, before it runs.
#[derive(Debug, Clone, PartialEq)]
pub struct Preview {
    pub verdict: &'static str,
    /// `policy` for the built-in policy, a rule name, or empty for a plain allow.
    pub rule: String,
    pub reason: String,
}

pub fn preview(
    config: &Config,
    rules: &RuleSet,
    agent_name: &str,
    sql: &str,
    database: &str,
    engine: &str,
) -> Preview {
    let deny = |reason: String| Preview {
        verdict: "deny",
        rule: "policy".into(),
        reason,
    };
    let Some(agent) = config.agent(agent_name) else {
        return deny(format!("unknown agent '{agent_name}'"));
    };
    // ClickHouse and MySQL statements are judged against the agent's access
    // to that engine.
    let (agent, statements) = if engine == "mysql" {
        let Some(my) = &agent.mysql else {
            return deny("this agent has no MySQL access".into());
        };
        let mut view = agent.clone();
        view.access = my.access;
        view.tables = my.tables.clone();
        match crate::mysql_sql::classify(sql) {
            Ok(mut s) => {
                crate::mysql_sql::scope_to_database(&mut s, database);
                (view, s)
            }
            Err(e) => return deny(e.to_string()),
        }
    } else if engine == "clickhouse" {
        let Some(ch) = &agent.clickhouse else {
            return deny("this agent has no ClickHouse access".into());
        };
        let mut view = agent.clone();
        view.access = ch.access;
        view.tables = ch.tables.clone();
        match crate::chsql::classify(sql) {
            Ok(mut s) => {
                crate::chsql::scope_to_database(&mut s, database);
                (view, vec![s])
            }
            Err(e) => return deny(e),
        }
    } else {
        match classify::classify(sql) {
            Ok(s) => (agent.clone(), s),
            Err(e) => return deny(e.to_string()),
        }
    };
    let agent = &agent;
    let mut approve: Option<(String, String)> = None;
    let mut allow_rule = String::new();
    for stmt in &statements {
        if let Decision::Deny(reason) = policy::decide(agent, stmt) {
            return Preview {
                verdict: "deny",
                rule: "policy".into(),
                reason,
            };
        }
        match rules.evaluate(&Facts {
            agent,
            statement: stmt,
            database,
        }) {
            Outcome::Deny { rule, reason } => {
                return Preview {
                    verdict: "deny",
                    rule,
                    reason,
                };
            }
            Outcome::Approve { rule, reason, .. } => {
                approve.get_or_insert((rule, reason));
            }
            Outcome::Allow { rule } => {
                if allow_rule.is_empty() {
                    allow_rule = rule;
                }
            }
            Outcome::NoMatch => {}
        }
    }
    match approve {
        Some((rule, reason)) => Preview {
            verdict: "approve",
            rule,
            reason,
        },
        None => Preview {
            verdict: "allow",
            rule: allow_rule,
            reason: String::new(),
        },
    }
}

/// The database name statements run in when none is given.
pub fn default_database(config: &Config, engine: &str) -> String {
    match engine {
        "clickhouse" => return "default".to_string(),
        "mysql" => return config.mysql.database.clone(),
        _ => {}
    }
    crate::upstream::Target::from_url(&config.database_url(), config.database.tls, None)
        .map(|t| t.database)
        .unwrap_or_default()
}

/// A recorded decision as a fixture, or `None` when it depended on data
/// rather than policy (rollbacks and failures). A decision a rule sent for
/// approval is expected to need approval again, whatever the approver said.
pub fn fixture_for(d: &crate::audit::Decision, config: &Config) -> Option<serde_json::Value> {
    let approval_rule = d
        .rule
        .as_ref()
        .and_then(|r| config.rules.iter().find(|x| &x.name == r))
        .is_some_and(|x| x.verdict == crate::rules::Verdict::Approve);
    let verdict = match d.outcome.as_str() {
        "allowed" | "refused" if approval_rule => "approve",
        "allowed" => "allow",
        "refused" => "deny",
        _ => return None,
    };
    let mut expect = serde_json::json!({ "verdict": verdict });
    if let Some(rule) = &d.rule {
        expect["rule"] = serde_json::json!(rule);
    } else if verdict == "deny" {
        expect["rule"] = serde_json::json!("policy");
    }
    let mut action = serde_json::json!({ "agent": d.agent, "sql": { "statement": d.sql } });
    if !d.database.is_empty() {
        action["sql"]["database"] = serde_json::json!(d.database);
    }
    if d.engine != "postgres" {
        action["engine"] = serde_json::json!(d.engine);
    }
    Some(serde_json::json!({
        "name": format!("decision {} ({})", d.id, d.agent),
        "action": action,
        "match": expect,
    }))
}

pub fn load_fixtures(path: &Path) -> Result<Vec<(String, Fixture)>, String> {
    let mut files = Vec::new();
    if path.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|x| x == "json") {
                files.push(p);
            }
        }
        files.sort();
    } else {
        files.push(path.to_path_buf());
    }
    let mut out = Vec::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
        let items = match value {
            serde_json::Value::Array(a) => a,
            other => vec![other],
        };
        for (i, item) in items.into_iter().enumerate() {
            let f: Fixture = serde_json::from_value(item)
                .map_err(|e| format!("{} item {}: {e}", file.display(), i + 1))?;
            let label = f.name.clone().unwrap_or_else(|| {
                format!(
                    "{} #{}",
                    file.file_name().unwrap_or_default().to_string_lossy(),
                    i + 1
                )
            });
            out.push((label, f));
        }
    }
    Ok(out)
}

/// Run fixtures; returns (passed, drifted).
pub fn run(config: &Config, fixtures: &[(String, Fixture)]) -> Result<(usize, usize), String> {
    let rules = RuleSet::compile(&config.rules)?;
    let default_db =
        crate::upstream::Target::from_url(&config.database_url(), config.database.tls, None)
            .map(|t| t.database)
            .unwrap_or_default();
    let (mut passed, mut drifted) = (0, 0);
    for (label, f) in fixtures {
        let engine = f.action.engine.as_deref().unwrap_or("postgres");
        let fallback = match engine {
            "clickhouse" => "default".to_string(),
            "mysql" => config.mysql.database.clone(),
            _ => default_db.clone(),
        };
        let database = f.action.sql.database.clone().unwrap_or(fallback);
        let got = preview(
            config,
            &rules,
            &f.action.agent,
            &f.action.sql.statement,
            &database,
            engine,
        );
        let verdict_ok = got.verdict == f.expect.verdict;
        let rule_ok = f.expect.rule.as_ref().is_none_or(|r| *r == got.rule);
        if verdict_ok && rule_ok {
            passed += 1;
            println!("ok     {label}");
        } else {
            drifted += 1;
            let rule = if got.rule.is_empty() {
                "-".to_string()
            } else {
                got.rule.clone()
            };
            println!(
                "DRIFT  {label}: expected {}{}, got {} (rule {rule}) {}",
                f.expect.verdict,
                f.expect
                    .rule
                    .as_ref()
                    .map(|r| format!(" (rule {r})"))
                    .unwrap_or_default(),
                got.verdict,
                got.reason
            );
        }
    }
    Ok((passed, drifted))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
        [database]
        url = "postgres://x@localhost/app"
        [limits]
        max_rows_per_write = 10
        statement_timeout_ms = 1000
        [[agents]]
        name = "bot"
        access = "read_write"
        tables = ["orders", "users"]
        token_env = "UNUSED"
        [[rules]]
        name = "pii"
        condition = "'users' in sql.tables"
        verdict = "deny"
    "#;

    #[test]
    fn previews_policy_and_rules() {
        let config = Config::from_toml(CONFIG).unwrap();
        let rules = RuleSet::compile(&config.rules).unwrap();
        assert_eq!(
            preview(
                &config,
                &rules,
                "bot",
                "SELECT * FROM users",
                "app",
                "postgres"
            )
            .rule,
            "pii"
        );
        assert_eq!(
            preview(
                &config,
                &rules,
                "bot",
                "DROP TABLE orders",
                "app",
                "postgres"
            )
            .rule,
            "policy"
        );
        assert_eq!(
            preview(
                &config,
                &rules,
                "bot",
                "SELECT * FROM orders",
                "app",
                "postgres"
            )
            .verdict,
            "allow"
        );
    }

    #[test]
    fn reports_drift() {
        let config = Config::from_toml(CONFIG).unwrap();
        let fixtures = vec![
            ("ok".to_string(), serde_json::from_str::<Fixture>(r#"{"action":{"agent":"bot","sql":{"statement":"SELECT 1 FROM users"}},"match":{"verdict":"deny","rule":"pii"}}"#).unwrap()),
            ("drift".to_string(), serde_json::from_str::<Fixture>(r#"{"action":{"agent":"bot","sql":{"statement":"SELECT 1 FROM orders"}},"match":{"verdict":"deny"}}"#).unwrap()),
        ];
        assert_eq!(run(&config, &fixtures).unwrap(), (1, 1));
    }

    #[test]
    fn approvals_and_clickhouse_round_trip_as_fixtures() {
        let text = CONFIG.replace(
            "[[rules]]",
            "[[approvers]]\nname = \"ops\"\ntype = \"dashboard\"\n\n[[rules]]\nname = \"ask\"\ncondition = \"'orders' in sql.tables\"\nverdict = \"approve\"\napprove = [\"ops\"]\n\n[[rules]]",
        ) + "\n[agents.clickhouse]\naccess = \"read_only\"\ntables = [\"events\"]\n";
        let config = Config::from_toml(&text).unwrap();
        let decision =
            |sql: &str, outcome: &str, rule: Option<&str>, engine: &str| crate::audit::Decision {
                id: 1,
                at_ms: 0,
                session: "s".into(),
                agent: "bot".into(),
                sql: sql.into(),
                kind: "read".into(),
                tables: vec![],
                outcome: outcome.into(),
                rows: None,
                reason: None,
                rule: rule.map(str::to_string),
                latency_ms: None,
                engine: engine.into(),
                database: String::new(),
            };
        let cases = [
            decision("SELECT * FROM orders", "allowed", Some("ask"), "postgres"),
            decision("SELECT * FROM orders", "refused", Some("ask"), "postgres"),
            decision("SELECT count() FROM events", "allowed", None, "clickhouse"),
            decision("SELECT * FROM secrets", "refused", None, "clickhouse"),
        ];
        let fixtures: Vec<(String, Fixture)> = cases
            .iter()
            .map(|d| {
                (
                    "x".to_string(),
                    serde_json::from_value(fixture_for(d, &config).unwrap()).unwrap(),
                )
            })
            .collect();
        assert_eq!(fixtures[0].1.expect.verdict, "approve");
        assert_eq!(fixtures[1].1.expect.verdict, "approve");
        assert_eq!(run(&config, &fixtures).unwrap(), (4, 0));
    }
}
