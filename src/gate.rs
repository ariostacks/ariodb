//! The decision layer shared by every way an agent can reach the database
//! (the wire proxy and the MCP server).
//!
//! Before a statement runs: the built-in policy decides. After a write runs
//! but before it commits: its measured effect is judged.

use crate::audit::AuditLog;
use crate::classify::{Kind, Statement};
use crate::config::{Agent, Config};
use crate::policy::{self, Decision, Mode};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Everything shared across connections. The config can be swapped while
/// running (hot reload); each decision reads the current one.
pub struct State {
    config: RwLock<Arc<Config>>,
    pub config_path: PathBuf,
    pub audit: Arc<AuditLog>,
}

impl State {
    pub fn new(config: Config, config_path: PathBuf, audit: Arc<AuditLog>) -> Arc<State> {
        Arc::new(State {
            config: RwLock::new(Arc::new(config)),
            config_path,
            audit,
        })
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.read().expect("config lock").clone()
    }

    pub fn replace_config(&self, config: Config) {
        *self.config.write().expect("config lock") = Arc::new(config);
    }
}

/// How a set of statements must run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// In a READ ONLY transaction.
    Read,
    /// In a transaction measured before commit.
    Write,
}

#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl Refusal {
    pub fn new(message: impl Into<String>) -> Refusal {
        Refusal {
            code: "42501",
            message: message.into(),
        }
    }
}

/// Decide whether an agent may run these statements, and how.
pub async fn check(
    _state: &State,
    agent: &Agent,
    statements: &[Statement],
) -> Result<Plan, Refusal> {
    if statements.is_empty() {
        return Ok(Plan::Read);
    }
    let mut plan = Plan::Read;
    for stmt in statements {
        match policy::decide(agent, stmt) {
            Decision::Deny(reason) => return Err(Refusal::new(reason)),
            Decision::Allow(Mode::CheckedWrite) => plan = Plan::Write,
            Decision::Allow(Mode::ReadOnly) => {}
        }
    }
    Ok(plan)
}

/// One table changed inside the current transaction.
#[derive(Debug, Clone)]
pub struct Effect {
    pub table: String,
    pub rows: i64,
}

/// SQL that lists every table changed in the current transaction, including
/// changes made by triggers, cascades and functions.
pub const EFFECTS_SQL: &str = "SELECT schemaname || '.' || relname, (n_tup_ins + n_tup_upd + n_tup_del)::bigint \
     FROM pg_stat_xact_user_tables WHERE n_tup_ins + n_tup_upd + n_tup_del > 0 ORDER BY 1";

pub fn parse_effects(rows: &[Vec<Option<String>>]) -> Vec<Effect> {
    rows.iter()
        .filter_map(|r| {
            let table = crate::classify::normalise_table(r.first()?.as_deref()?);
            let rows = r.get(1)?.as_deref()?.parse().ok()?;
            Some(Effect { table, rows })
        })
        .collect()
}

/// Judge a write by what it actually did. `Err` means roll it back.
pub fn judge_effects(config: &Config, agent: &Agent, effects: &[Effect]) -> Result<(), Refusal> {
    let limit = agent
        .max_rows_per_write
        .unwrap_or(config.limits.max_rows_per_write);
    let total: i64 = effects.iter().map(|e| e.rows).sum();
    let summary = describe(effects);
    if let Some(bad) = effects.iter().find(|e| !agent.allows_table(&e.table)) {
        return Err(Refusal::new(format!(
            "rolled back: the statement also changed table '{}', which agent '{}' may not change ({summary})",
            bad.table, agent.name
        )));
    }
    if total > limit as i64 {
        return Err(Refusal::new(format!(
            "rolled back: the statement would change {total} rows ({summary}); the limit is {limit}"
        )));
    }
    Ok(())
}

pub fn describe(effects: &[Effect]) -> String {
    effects
        .iter()
        .map(|e| format!("{} {}", e.rows, e.table))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn total_rows(effects: &[Effect]) -> u64 {
    effects.iter().map(|e| e.rows.max(0) as u64).sum()
}

/// A short label for the audit log, such as "read" or "write, read".
pub fn kinds(statements: &[Statement]) -> String {
    let mut kinds: Vec<Kind> = statements.iter().map(|s| s.kind).collect();
    kinds.sort();
    kinds.dedup();
    kinds
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn tables(statements: &[Statement]) -> Vec<String> {
    let mut t: Vec<String> = statements.iter().flat_map(|s| s.tables.clone()).collect();
    t.sort();
    t.dedup();
    t
}
