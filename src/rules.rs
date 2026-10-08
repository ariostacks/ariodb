//! Rules written in CEL, the Common Expression Language.
//!
//! Variables a condition can read:
//!
//! | Variable | Type | Meaning |
//! |---|---|---|
//! | `sql.verb` | string | First keyword, lower case: `select`, `update`, `drop`, ... |
//! | `sql.kind` | string | ariodb's judgement: `read`, `write`, `schema_change`, `destructive`, ... |
//! | `sql.tables` | list | Tables named, lower case, without `public.` |
//! | `sql.functions` | list | Functions called, lower case |
//! | `sql.statement` | string | The statement as sent |
//! | `sql.database` | string | The database the agent connected to |
//! | `agent.name`, `agent.access` | string | Who is asking |
//! | `effects.rows` | int | Rows actually changed (after-stage rules only) |
//! | `effects.tables` | list | Tables actually changed, including by triggers (after-stage only) |
//!
//! Matching: every rule is evaluated. Any matching `deny` wins. Otherwise
//! the highest-priority matching rule decides between `allow` and
//! `approve`. A condition that cannot be evaluated counts as a deny.

use crate::classify::Statement;
use crate::config::Agent;
use cel_interpreter::{Context, Program, Value};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    /// CEL condition. Omit to match everything (useful for a catch-all).
    #[serde(default)]
    pub condition: Option<String>,
    pub verdict: Verdict,
    /// Approvers for `verdict = "approve"`, all of which must allow.
    #[serde(default)]
    pub approve: Vec<String>,
    pub reason: Option<String>,
    /// Limit the rule to these agents. Empty means every agent.
    #[serde(default)]
    pub agents: Vec<String>,
    #[serde(default)]
    pub priority: i64,
    /// `before` (default): judged on the SQL before it runs.
    /// `after`: judged on what a write actually changed, before commit.
    #[serde(default)]
    pub stage: Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    #[default]
    Before,
    After,
}

struct Rule {
    config: RuleConfig,
    program: Option<Program>,
}

/// Compiled rules, rebuilt whenever the config is (re)loaded.
#[derive(Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

/// The outcome of evaluating rules.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// No rule had an opinion.
    NoMatch,
    Allow {
        rule: String,
    },
    Deny {
        rule: String,
        reason: String,
    },
    Approve {
        rule: String,
        approvers: Vec<String>,
        reason: String,
    },
}

/// Facts about one statement for `before`-stage rules.
pub struct Facts<'a> {
    pub agent: &'a Agent,
    pub statement: &'a Statement,
    pub database: &'a str,
}

/// Facts about a finished write for `after`-stage rules.
pub struct EffectFacts<'a> {
    pub agent: &'a Agent,
    pub statements: &'a [Statement],
    pub database: &'a str,
    pub rows: i64,
    pub tables: Vec<String>,
}

impl RuleSet {
    pub fn compile(configs: &[RuleConfig]) -> Result<RuleSet, String> {
        let mut rules = Vec::new();
        let mut names = std::collections::HashSet::new();
        for c in configs {
            if !names.insert(c.name.clone()) {
                return Err(format!("rule '{}' is defined twice", c.name));
            }
            if c.verdict == Verdict::Approve && c.approve.is_empty() {
                return Err(format!(
                    "rule '{}' has verdict approve but no approvers",
                    c.name
                ));
            }
            let program = match &c.condition {
                Some(text) => Some(compile(&c.name, text)?),
                None => None,
            };
            rules.push(Rule {
                config: c.clone(),
                program,
            });
        }
        // Highest priority first; ties keep file order.
        rules.sort_by_key(|r| std::cmp::Reverse(r.config.priority));
        Ok(RuleSet { rules })
    }

    pub fn names(&self) -> Vec<&RuleConfig> {
        self.rules.iter().map(|r| &r.config).collect()
    }

    pub fn evaluate(&self, facts: &Facts) -> Outcome {
        let ctx = context_for(
            facts.agent,
            std::slice::from_ref(facts.statement),
            facts.database,
            None,
        );
        self.run(Stage::Before, &facts.agent.name, &ctx)
    }

    pub fn evaluate_effects(&self, facts: &EffectFacts) -> Outcome {
        let effects = (facts.rows, facts.tables.clone());
        let ctx = context_for(facts.agent, facts.statements, facts.database, Some(effects));
        self.run(Stage::After, &facts.agent.name, &ctx)
    }

    fn run(&self, stage: Stage, agent: &str, ctx: &Context) -> Outcome {
        let mut decided: Option<Outcome> = None;
        for rule in &self.rules {
            let c = &rule.config;
            if c.stage != stage || (!c.agents.is_empty() && !c.agents.iter().any(|a| a == agent)) {
                continue;
            }
            let matched = match &rule.program {
                None => Ok(true),
                Some(p) => match p.execute(ctx) {
                    Ok(Value::Bool(b)) => Ok(b),
                    Ok(other) => Err(format!("condition returned {other:?}, not true or false")),
                    Err(e) => Err(e.to_string()),
                },
            };
            let matched = match matched {
                Ok(m) => m,
                Err(e) => {
                    // Fail closed: an unevaluable condition is a deny.
                    return Outcome::Deny {
                        rule: c.name.clone(),
                        reason: format!("rule '{}' could not be evaluated: {e}", c.name),
                    };
                }
            };
            if !matched {
                continue;
            }
            let reason = c
                .reason
                .clone()
                .unwrap_or_else(|| format!("rule '{}'", c.name));
            match c.verdict {
                Verdict::Deny => {
                    return Outcome::Deny {
                        rule: c.name.clone(),
                        reason,
                    };
                }
                Verdict::Allow => {
                    decided.get_or_insert(Outcome::Allow {
                        rule: c.name.clone(),
                    });
                }
                Verdict::Approve => {
                    decided.get_or_insert(Outcome::Approve {
                        rule: c.name.clone(),
                        approvers: c.approve.clone(),
                        reason,
                    });
                }
            }
        }
        decided.unwrap_or(Outcome::NoMatch)
    }
}

/// Compile a condition. The CEL parser can panic on some malformed input,
/// so a bad rule is caught here and reported instead of crashing ariodb.
fn compile(name: &str, text: &str) -> Result<Program, String> {
    let source = compat(text);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| Program::compile(&source));
    std::panic::set_hook(previous);
    match result {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(format!("rule '{name}': condition does not compile: {e}")),
        Err(_) => Err(format!(
            "rule '{name}': condition does not compile: `{text}`"
        )),
    }
}

/// Accept the CEL sets extension's `sets.intersects(a, b)` spelling as well as ours.
fn compat(text: &str) -> String {
    text.replace("sets.intersects(", "intersects(")
}

/// The statement's verb: its first keyword, except that `with` resolves to
/// the command it wraps.
pub fn verb(stmt: &Statement) -> String {
    let text = stmt
        .sql
        .trim_start_matches(|c: char| c.is_whitespace() || c == '(');
    let first: String = text
        .chars()
        .take_while(|c| c.is_alphabetic())
        .collect::<String>()
        .to_lowercase();
    if first == "with" || first.is_empty() {
        stmt.command.to_lowercase()
    } else {
        first
    }
}

fn kind_name(stmt: &Statement) -> String {
    serde_json::to_value(stmt.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn list(items: impl IntoIterator<Item = String>) -> Value {
    Value::List(Arc::new(
        items
            .into_iter()
            .map(|s| Value::String(Arc::new(s)))
            .collect(),
    ))
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    let m: HashMap<String, Value> = entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    Value::Map(m.into())
}

fn s(text: &str) -> Value {
    Value::String(Arc::new(text.to_string()))
}

fn context_for(
    agent: &Agent,
    statements: &[Statement],
    database: &str,
    effects: Option<(i64, Vec<String>)>,
) -> Context<'static> {
    let first = statements.first();
    let mut tables: Vec<String> = statements.iter().flat_map(|s| s.tables.clone()).collect();
    tables.sort();
    tables.dedup();
    let mut functions: Vec<String> = statements
        .iter()
        .flat_map(|s| s.functions.clone())
        .collect();
    functions.sort();
    functions.dedup();
    let statement_text = statements
        .iter()
        .map(|s| s.sql.as_str())
        .collect::<Vec<_>>()
        .join("; ");

    let sql = map(vec![
        ("verb", s(&first.map(verb).unwrap_or_default())),
        ("kind", s(&first.map(kind_name).unwrap_or_default())),
        ("tables", list(tables)),
        ("functions", list(functions)),
        ("statement", s(&statement_text)),
        ("database", s(database)),
    ]);
    let access = match agent.access {
        crate::config::Access::ReadOnly => "read_only",
        crate::config::Access::ReadWrite => "read_write",
    };
    let agent_value = map(vec![("name", s(&agent.name)), ("access", s(access))]);

    let mut ctx = Context::default();
    ctx.add_variable_from_value("sql", sql);
    ctx.add_variable_from_value("agent", agent_value);
    if let Some((rows, tables)) = effects {
        ctx.add_variable_from_value(
            "effects",
            map(vec![("rows", Value::Int(rows)), ("tables", list(tables))]),
        );
    }
    ctx.add_function(
        "intersects",
        |a: Arc<Vec<Value>>, b: Arc<Vec<Value>>| -> bool { a.iter().any(|x| b.contains(x)) },
    );
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify;
    use crate::config::Access;

    fn agent() -> Agent {
        Agent {
            name: "bot".into(),
            access: Access::ReadWrite,
            tables: vec!["*".into()],
            token_env: Some("UNUSED".into()),
            token_secret: None,
            max_rows_per_write: None,
            credential: None,
        }
    }

    fn rules(toml_text: &str) -> RuleSet {
        #[derive(Deserialize)]
        struct F {
            rules: Vec<RuleConfig>,
        }
        let f: F = toml::from_str(toml_text).unwrap();
        RuleSet::compile(&f.rules).unwrap()
    }

    fn eval(set: &RuleSet, sql: &str) -> Outcome {
        let stmt = classify(sql).unwrap().remove(0);
        let a = agent();
        set.evaluate(&Facts {
            agent: &a,
            statement: &stmt,
            database: "app",
        })
    }

    const RULES: &str = r#"
        [[rules]]
        name = "no-file-functions"
        condition = "sets.intersects(sql.functions, ['pg_read_file', 'lo_get']) || sql.functions.exists(f, f.startsWith('dblink'))"
        verdict = "deny"
        reason = "Filesystem-reaching functions are off-limits"

        [[rules]]
        name = "pii-reads"
        condition = "sql.verb == 'select' && 'users' in sql.tables"
        verdict = "approve"
        approve = ["ops"]
        priority = 50

        [[rules]]
        name = "reads"
        condition = "sql.verb in ['select', 'show', 'explain']"
        verdict = "allow"

        [[rules]]
        name = "no-passwords"
        condition = '''sql.statement.matches('(?i)\\bpassword\\b')'''
        verdict = "deny"
        priority = -10
    "#;

    #[test]
    fn deny_wins_regardless_of_priority() {
        let set = rules(RULES);
        assert!(
            matches!(eval(&set, "SELECT pg_read_file('/etc/passwd')"), Outcome::Deny { rule, .. } if rule == "no-file-functions")
        );
        assert!(matches!(
            eval(&set, "SELECT dblink_connect('x')"),
            Outcome::Deny { .. }
        ));
        // Low-priority deny still beats the higher-priority approve and allow.
        assert!(
            matches!(eval(&set, "SELECT password FROM users"), Outcome::Deny { rule, .. } if rule == "no-passwords")
        );
    }

    #[test]
    fn priority_orders_allow_and_approve() {
        let set = rules(RULES);
        assert!(
            matches!(eval(&set, "SELECT email FROM users"), Outcome::Approve { rule, .. } if rule == "pii-reads")
        );
        assert!(
            matches!(eval(&set, "SELECT * FROM orders"), Outcome::Allow { rule } if rule == "reads")
        );
        assert_eq!(
            eval(&set, "UPDATE orders SET a = 1 WHERE id = 1"),
            Outcome::NoMatch
        );
    }

    #[test]
    fn verbs_name_the_real_command() {
        let v = |sql: &str| verb(&classify(sql).unwrap().remove(0));
        assert_eq!(
            v("WITH x AS (SELECT 1) DELETE FROM t WHERE id IN (SELECT * FROM x)"),
            "delete"
        );
        assert_eq!(v("  (SELECT 1)"), "select");
        assert_eq!(v("TRUNCATE t"), "truncate");
    }

    #[test]
    fn unevaluable_conditions_deny() {
        let set = rules(
            r#"
            [[rules]]
            name = "typo"
            condition = "sql.no_such_field == 'x'"
            verdict = "allow"
        "#,
        );
        assert!(matches!(eval(&set, "SELECT 1"), Outcome::Deny { rule, .. } if rule == "typo"));
    }

    #[test]
    fn after_stage_sees_effects() {
        let set = rules(
            r#"
            [[rules]]
            name = "big-customer-change"
            stage = "after"
            condition = "'customers' in effects.tables && effects.rows > 10"
            verdict = "deny"
        "#,
        );
        let stmts = classify("DELETE FROM customers WHERE id = 3").unwrap();
        let a = agent();
        let facts = EffectFacts {
            agent: &a,
            statements: &stmts,
            database: "app",
            rows: 21,
            tables: vec!["customers".into(), "orders".into()],
        };
        assert!(matches!(set.evaluate_effects(&facts), Outcome::Deny { .. }));
        // Before-stage evaluation ignores after-stage rules.
        assert_eq!(
            eval(&set, "DELETE FROM customers WHERE id = 3"),
            Outcome::NoMatch
        );
    }

    #[test]
    fn bad_rules_are_rejected_at_load() {
        #[derive(Deserialize)]
        struct F {
            rules: Vec<RuleConfig>,
        }
        let f: F = toml::from_str(
            r#"
            [[rules]]
            name = "broken"
            condition = "sql.verb == "
            verdict = "deny"
        "#,
        )
        .unwrap();
        assert!(RuleSet::compile(&f.rules).is_err());
    }
}
