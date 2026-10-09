//! The decision layer shared by every way an agent can reach the database
//! (the wire proxy and the MCP server).
//!
//! Before a statement runs: the built-in policy decides. After a write runs
//! but before it commits: its measured effect is judged.

use crate::audit::AuditLog;
use crate::classify::{Kind, Statement};
use crate::config::{Agent, Config};
use crate::policy::{self, Decision, Mode};
use crate::rules::{EffectFacts, Facts, Outcome as RuleOutcome, RuleSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Everything shared across connections. The config can be swapped while
/// running (hot reload); each decision reads the current one.
pub struct State {
    current: RwLock<Arc<Loaded>>,
    pub config_path: PathBuf,
    pub audit: Arc<AuditLog>,
    pub db: Arc<crate::store::Db>,
}

/// A config together with its compiled rules.
pub struct Loaded {
    pub config: Arc<Config>,
    pub rules: Arc<RuleSet>,
}

impl State {
    pub fn new(
        config: Config,
        config_path: PathBuf,
        audit: Arc<AuditLog>,
    ) -> Result<Arc<State>, String> {
        let db = Arc::new(crate::store::Db::open(std::path::Path::new(
            &config.journal.dir,
        ))?);
        let loaded = load(config)?;
        Ok(Arc::new(State {
            current: RwLock::new(Arc::new(loaded)),
            config_path,
            audit,
            db,
        }))
    }

    pub fn config(&self) -> Arc<Config> {
        self.current.read().expect("config lock").config.clone()
    }

    pub fn rules(&self) -> Arc<RuleSet> {
        self.current.read().expect("config lock").rules.clone()
    }

    /// Swap in a new config. Rejected (and the old one kept) if its rules
    /// do not compile.
    pub fn replace_config(&self, config: Config) -> Result<(), String> {
        let loaded = load(config)?;
        *self.current.write().expect("config lock") = Arc::new(loaded);
        Ok(())
    }
}

fn load(config: Config) -> Result<Loaded, String> {
    let rules = RuleSet::compile(&config.rules)?;
    Ok(Loaded {
        config: Arc::new(config),
        rules: Arc::new(rules),
    })
}

/// Watch the config file and reload it when it changes. Policy changes take
/// effect for the next statement; listen addresses need a restart.
pub async fn watch_config(state: Arc<State>) {
    let modified = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = modified(&state.config_path);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let now = modified(&state.config_path);
        if now == last {
            continue;
        }
        last = now;
        match Config::load(&state.config_path) {
            Ok(config) => match state.replace_config(config) {
                Ok(()) => println!("ariodb: reloaded {}", state.config_path.display()),
                Err(e) => eprintln!("ariodb: kept the previous config: {e}"),
            },
            Err(e) => eprintln!("ariodb: kept the previous config: {e}"),
        }
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
    /// The rule that refused, if a rule did.
    pub rule: Option<String>,
}

impl Refusal {
    pub fn new(message: impl Into<String>) -> Refusal {
        Refusal {
            code: "42501",
            message: message.into(),
            rule: None,
        }
    }

    pub fn by_rule(rule: &str, message: impl Into<String>) -> Refusal {
        Refusal {
            code: "42501",
            message: message.into(),
            rule: Some(rule.to_string()),
        }
    }
}

/// Who is asking, for rules and approvals.
pub struct Ctx<'a> {
    pub agent: &'a Agent,
    pub session: &'a str,
    pub database: &'a str,
    /// Whether the agent is still there. Approvals give up when it is not.
    pub live: Option<&'a Liveness>,
}

/// Set by the connection: the agent disconnected, or asked to cancel.
#[derive(Debug, Default)]
pub struct Liveness {
    pub gone: std::sync::atomic::AtomicBool,
    pub cancelled: std::sync::atomic::AtomicBool,
}

impl Liveness {
    /// Why the agent is no longer waiting, if it is not.
    pub fn stopped(&self) -> Option<&'static str> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.gone.load(SeqCst) {
            Some("the agent disconnected")
        } else if self.cancelled.load(SeqCst) {
            Some("the agent cancelled the statement")
        } else {
            None
        }
    }
}

/// An approval a rule asked for.
#[derive(Debug, Clone)]
pub struct ApprovalNeed {
    pub rule: String,
    pub approvers: Vec<String>,
    pub reason: String,
}

/// Decide whether an agent may run these statements, and how. The built-in
/// policy must allow every statement, no rule may deny, and any approval a
/// rule asks for must be granted.
pub async fn check(
    state: &State,
    ctx: &Ctx<'_>,
    statements: &[Statement],
) -> Result<Plan, Refusal> {
    check_detailed(state, ctx, statements)
        .await
        .map(|(plan, _)| plan)
}

/// Like `check`, and also names the rule whose approval let it through.
pub async fn check_detailed(
    state: &State,
    ctx: &Ctx<'_>,
    statements: &[Statement],
) -> Result<(Plan, Option<String>), Refusal> {
    let mut plan = Plan::Read;
    let rules = state.rules();
    let mut needs: Vec<ApprovalNeed> = Vec::new();
    for stmt in statements {
        match policy::decide(ctx.agent, stmt) {
            Decision::Deny(reason) => return Err(Refusal::new(reason)),
            Decision::Allow(Mode::CheckedWrite) => plan = Plan::Write,
            Decision::Allow(Mode::ReadOnly) => {}
        }
        match rules.evaluate(&Facts {
            agent: ctx.agent,
            statement: stmt,
            database: ctx.database,
        }) {
            RuleOutcome::Deny { rule, reason } => return Err(Refusal::by_rule(&rule, reason)),
            RuleOutcome::Approve {
                rule,
                approvers,
                reason,
            } => {
                if !needs.iter().any(|n| n.rule == rule) {
                    needs.push(ApprovalNeed {
                        rule,
                        approvers,
                        reason,
                    });
                }
            }
            RuleOutcome::Allow { .. } | RuleOutcome::NoMatch => {}
        }
    }
    let approved = needs.first().map(|n| n.rule.clone());
    for need in needs {
        crate::approvals::require(state, ctx, statements, &need).await?;
    }
    // An approval can arrive just as the agent leaves; do not run then.
    if let Some(why) = ctx.live.and_then(|l| l.stopped()) {
        return Err(Refusal::new(format!("{why} while the statement waited")));
    }
    Ok((plan, approved))
}

/// Judge a write by what it actually did, against the row limit, the
/// agent's tables and any after-stage rules. `Err` means roll it back.
pub async fn judge_write(
    state: &State,
    ctx: &Ctx<'_>,
    statements: &[Statement],
    effects: &[Effect],
) -> Result<(), Refusal> {
    let config = state.config();
    judge_effects(&config, ctx.agent, effects)?;
    let facts = EffectFacts {
        agent: ctx.agent,
        statements,
        database: ctx.database,
        rows: effects.iter().map(|e| e.rows).sum(),
        tables: effects.iter().map(|e| e.table.clone()).collect(),
    };
    match state.rules().evaluate_effects(&facts) {
        RuleOutcome::Deny { rule, reason } => {
            Err(Refusal::by_rule(&rule, format!("rolled back: {reason}")))
        }
        RuleOutcome::Approve {
            rule,
            approvers,
            reason,
        } => {
            let need = ApprovalNeed {
                rule,
                approvers,
                reason,
            };
            crate::approvals::require(state, ctx, statements, &need)
                .await
                .map_err(|r| Refusal {
                    message: format!("rolled back: {}", r.message),
                    ..r
                })
        }
        RuleOutcome::Allow { .. } | RuleOutcome::NoMatch => Ok(()),
    }
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
