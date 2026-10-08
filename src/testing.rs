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
) -> Preview {
    let Some(agent) = config.agent(agent_name) else {
        return Preview {
            verdict: "deny",
            rule: "policy".into(),
            reason: format!("unknown agent '{agent_name}'"),
        };
    };
    let statements = match classify::classify(sql) {
        Ok(s) => s,
        Err(e) => {
            return Preview {
                verdict: "deny",
                rule: "policy".into(),
                reason: e.to_string(),
            };
        }
    };
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
        let database = f
            .action
            .sql
            .database
            .clone()
            .unwrap_or_else(|| default_db.clone());
        let got = preview(
            config,
            &rules,
            &f.action.agent,
            &f.action.sql.statement,
            &database,
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
            preview(&config, &rules, "bot", "SELECT * FROM users", "app").rule,
            "pii"
        );
        assert_eq!(
            preview(&config, &rules, "bot", "DROP TABLE orders", "app").rule,
            "policy"
        );
        assert_eq!(
            preview(&config, &rules, "bot", "SELECT * FROM orders", "app").verdict,
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
}
