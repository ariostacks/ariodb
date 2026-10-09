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
//! | `sql.engine` | string | `postgres` or `clickhouse` |
//! | `agent.name`, `agent.access` | string | Who is asking |
//! | `agent.credential` | string | The `[[credentials]]` login the agent's Postgres queries run as, or `""` for `[database]` |
//! | `effects.rows` | int | Rows actually changed (after-stage rules only) |
//! | `effects.tables` | list | Tables actually changed, including by triggers (after-stage only) |
//! | `plugin.<name>.<key>` | any | Facts from a `[[plugins]]` entry (before-stage only) |
//!
//! Matching: every rule is evaluated. Any matching `deny` wins. Otherwise
//! the highest-priority matching rule decides between `allow` and
//! `approve`. A condition that cannot be evaluated counts as a deny.
//!
//! Plugin facts are fetched only for rules that mention `plugin.<name>`,
//! and only when such a rule applies to the agent. A plugin that fails or
//! times out makes those rules unevaluable, so they deny.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    #[default]
    Before,
    After,
}

struct Rule {
    config: RuleConfig,
    program: Option<Program>,
    /// Plugins whose facts the condition reads.
    plugins: Vec<String>,
}

/// Facts from plugins for one statement, by plugin name. An `Err` makes
/// every rule that reads that plugin unevaluable.
pub type PluginFacts = HashMap<String, Result<serde_json::Value, String>>;

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
            let plugins = match &c.condition {
                Some(text) => {
                    plugins_mentioned(text).map_err(|e| format!("rule '{}': {e}", c.name))?
                }
                None => Vec::new(),
            };
            if !plugins.is_empty() && c.stage == Stage::After {
                return Err(format!(
                    "rule '{}': plugin facts are only available to before-stage rules",
                    c.name
                ));
            }
            rules.push(Rule {
                config: c.clone(),
                program,
                plugins,
            });
        }
        // Highest priority first; ties keep file order.
        rules.sort_by_key(|r| std::cmp::Reverse(r.config.priority));
        Ok(RuleSet { rules })
    }

    /// Evaluate before-stage rules without plugin facts (`ariodb explain`
    /// and `ariodb test`): rules that read plugin facts cannot be evaluated.
    pub fn evaluate(&self, facts: &Facts) -> Outcome {
        self.evaluate_with(facts, &PluginFacts::new())
    }

    pub fn evaluate_with(&self, facts: &Facts, plugin_facts: &PluginFacts) -> Outcome {
        let ctx = context_for(
            facts.agent,
            std::slice::from_ref(facts.statement),
            facts.database,
            None,
            plugin_facts,
        );
        self.run(Stage::Before, &facts.agent.name, &ctx, plugin_facts)
    }

    pub fn evaluate_effects(&self, facts: &EffectFacts) -> Outcome {
        let effects = (facts.rows, facts.tables.clone());
        let none = PluginFacts::new();
        let ctx = context_for(
            facts.agent,
            facts.statements,
            facts.database,
            Some(effects),
            &none,
        );
        self.run(Stage::After, &facts.agent.name, &ctx, &none)
    }

    /// The plugins whose facts some before-stage rule for this agent reads.
    /// Only these are asked, so a statement no such rule applies to costs
    /// no plugin call.
    pub fn facts_plugins(&self, agent: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.config.stage == Stage::Before && applies(&r.config, agent))
            .flat_map(|r| r.plugins.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn run(&self, stage: Stage, agent: &str, ctx: &Context, plugin_facts: &PluginFacts) -> Outcome {
        let mut decided: Option<Outcome> = None;
        for rule in &self.rules {
            let c = &rule.config;
            if c.stage != stage || !applies(c, agent) {
                continue;
            }
            let unavailable = rule.plugins.iter().find_map(|p| match plugin_facts.get(p) {
                Some(Ok(_)) => None,
                Some(Err(e)) => Some(format!("plugin '{p}': {e}")),
                None => Some(format!("facts from plugin '{p}' are not available here")),
            });
            if let Some(why) = unavailable {
                return Outcome::Deny {
                    rule: c.name.clone(),
                    reason: format!("rule '{}' could not be evaluated: {why}", c.name),
                };
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

fn applies(rule: &RuleConfig, agent: &str) -> bool {
    rule.agents.is_empty() || rule.agents.iter().any(|a| a == agent)
}

/// The plugins a condition reads facts from, written `plugin.<name>`.
/// Any other use of `plugin` (such as `plugin[name]`) is refused, so that
/// ariodb always knows which plugins a rule needs. Text in string literals
/// and comments is skipped.
pub fn plugins_mentioned(condition: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = condition.chars().collect();
    let is_start = |c: char| c.is_ascii_alphabetic() || c == '_';
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let skip_space = |mut i: usize| {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        i
    };
    let mut names: Vec<String> = Vec::new();
    let mut previous: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            i = skip_string(&chars, i, false);
            previous = Some(c);
            continue;
        }
        if !is_start(c) {
            if !c.is_whitespace() {
                previous = Some(c);
            }
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_ident(chars[i]) {
            i += 1;
        }
        let word: String = chars[start..i].iter().collect();
        let quote = chars.get(i).is_some_and(|q| *q == '\'' || *q == '"');
        if quote && matches!(word.to_ascii_lowercase().as_str(), "r" | "b" | "rb" | "br") {
            i = skip_string(&chars, i, word.to_ascii_lowercase().contains('r'));
            previous = Some('"');
            continue;
        }
        if word == "plugin" && previous != Some('.') {
            let dot = skip_space(i);
            let name_start = skip_space(dot + 1);
            let mut end = name_start;
            while end < chars.len() && is_ident(chars[end]) {
                end += 1;
            }
            if chars.get(dot) != Some(&'.') || end == name_start {
                return Err(
                    "read plugin facts as plugin.<plugin name>.<key>, so ariodb knows which plugin to ask"
                        .to_string(),
                );
            }
            let name: String = chars[name_start..end].iter().collect();
            if !names.contains(&name) {
                names.push(name);
            }
            i = end;
            previous = Some('x');
            continue;
        }
        previous = Some('x');
    }
    Ok(names)
}

/// Skip a CEL string literal starting at `i` (its opening quote), with
/// triple quotes and, unless raw, backslash escapes.
fn skip_string(chars: &[char], mut i: usize, raw: bool) -> usize {
    let q = chars[i];
    let triple = chars.len() >= i + 3 && chars[i + 1] == q && chars[i + 2] == q;
    i += if triple { 3 } else { 1 };
    while i < chars.len() {
        if !raw && chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == q {
            if !triple {
                return i + 1;
            }
            if chars.len() >= i + 3 && chars[i + 1] == q && chars[i + 2] == q {
                return i + 3;
            }
        }
        i += 1;
    }
    chars.len()
}

/// Plugin facts (JSON) as CEL values.
fn json_value(v: &serde_json::Value) -> Value {
    use serde_json::Value as J;
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .or_else(|| n.as_u64().map(Value::UInt))
            .unwrap_or_else(|| Value::Float(n.as_f64().unwrap_or(f64::NAN))),
        J::String(text) => s(text),
        J::Array(items) => Value::List(Arc::new(items.iter().map(json_value).collect())),
        J::Object(o) => {
            let m: HashMap<String, Value> =
                o.iter().map(|(k, v)| (k.clone(), json_value(v))).collect();
            Value::Map(m.into())
        }
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
    plugin_facts: &PluginFacts,
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
        ("engine", s(first.map(|st| st.engine).unwrap_or("postgres"))),
    ]);
    let access = match agent.access {
        crate::config::Access::ReadOnly => "read_only",
        crate::config::Access::ReadWrite => "read_write",
    };
    let agent_value = map(vec![
        ("name", s(&agent.name)),
        ("access", s(access)),
        ("credential", s(agent.credential.as_deref().unwrap_or(""))),
    ]);

    let mut ctx = Context::default();
    ctx.add_variable_from_value("sql", sql);
    ctx.add_variable_from_value("agent", agent_value);
    if let Some((rows, tables)) = effects {
        ctx.add_variable_from_value(
            "effects",
            map(vec![("rows", Value::Int(rows)), ("tables", list(tables))]),
        );
    }
    let available: HashMap<String, Value> = plugin_facts
        .iter()
        .filter_map(|(name, facts)| Some((name.clone(), json_value(facts.as_ref().ok()?))))
        .collect();
    if !available.is_empty() {
        ctx.add_variable_from_value("plugin", Value::Map(available.into()));
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
            clickhouse: None,
            mysql: None,
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
    fn rules_can_test_the_database_login() {
        let set = rules(
            r#"
            [[rules]]
            name = "reporting-reads-only"
            condition = "agent.credential == 'reporting' && sql.kind != 'read'"
            verdict = "deny"

            [[rules]]
            name = "default-login"
            condition = "agent.credential == ''"
            verdict = "allow"
        "#,
        );
        let update = classify("UPDATE t SET a = 1 WHERE id = 1")
            .unwrap()
            .remove(0);
        let judge = |credential: Option<&str>| {
            let mut a = agent();
            a.credential = credential.map(str::to_string);
            set.evaluate(&Facts {
                agent: &a,
                statement: &update,
                database: "app",
            })
        };
        assert!(
            matches!(judge(Some("reporting")), Outcome::Deny { rule, .. } if rule == "reporting-reads-only")
        );
        assert_eq!(judge(Some("writer")), Outcome::NoMatch);
        assert_eq!(
            judge(None),
            Outcome::Allow {
                rule: "default-login".into()
            }
        );
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
    fn finds_the_plugins_a_condition_reads() {
        let m = |text: &str| plugins_mentioned(text);
        assert_eq!(
            m("plugin.clock.out_of_hours && sql.kind == 'write'").unwrap(),
            vec!["clock"]
        );
        assert_eq!(
            m("plugin . a.x || plugin.b['y'] || plugin.a.z").unwrap(),
            vec!["a", "b"]
        );
        // Strings, raw strings, triple quotes and comments are not code.
        assert!(m("sql.statement.contains('plugin[0]')").unwrap().is_empty());
        assert!(
            m(r#"sql.statement == "plugin" || sql.statement == r'\plugin'"#)
                .unwrap()
                .is_empty()
        );
        assert!(m("sql.statement == '''it's plugin'''").unwrap().is_empty());
        assert!(m("true // plugin facts later").unwrap().is_empty());
        // A field called plugin elsewhere is not plugin facts.
        assert!(m("sql.plugin == 1").unwrap().is_empty());
        assert!(m("plugin[name].x").is_err());
        assert!(m("has(plugin)").is_err());
        assert!(m("plugin.").is_err());
    }

    fn eval_with(set: &RuleSet, sql: &str, facts: &PluginFacts) -> Outcome {
        let stmt = classify(sql).unwrap().remove(0);
        let a = agent();
        set.evaluate_with(
            &Facts {
                agent: &a,
                statement: &stmt,
                database: "app",
            },
            facts,
        )
    }

    #[test]
    fn plugin_facts_drive_rules_and_fail_closed() {
        let set = rules(
            r#"
            [[rules]]
            name = "freeze"
            condition = "plugin.clock.freeze && sql.kind == 'write'"
            verdict = "deny"
            reason = "change freeze"

            [[rules]]
            name = "reads"
            condition = "sql.kind == 'read' && plugin.clock.hour >= 0 && plugin.clock.tags[0] == 'x'"
            verdict = "allow"
            agents = ["someone-else"]
        "#,
        );
        assert_eq!(set.facts_plugins("bot"), vec!["clock"]);
        assert_eq!(set.facts_plugins("someone-else"), vec!["clock"]);
        let facts = |v: serde_json::Value| PluginFacts::from([("clock".to_string(), Ok(v))]);
        let frozen = facts(serde_json::json!({"freeze": true, "hour": 19, "tags": ["x"]}));
        let open = facts(serde_json::json!({"freeze": false, "hour": 9.5, "tags": []}));
        let update = "UPDATE t SET a = 1 WHERE id = 1";
        assert!(
            matches!(eval_with(&set, update, &frozen), Outcome::Deny { reason, .. } if reason == "change freeze")
        );
        assert_eq!(eval_with(&set, update, &open), Outcome::NoMatch);
        // A failed plugin call makes the rule unevaluable: deny.
        let failed = PluginFacts::from([(
            "clock".to_string(),
            Err("no answer within 5000 ms".to_string()),
        )]);
        assert!(
            matches!(eval_with(&set, update, &failed), Outcome::Deny { reason, .. } if reason.contains("no answer within 5000 ms"))
        );
        // Without plugins (ariodb explain, ariodb test), likewise.
        assert!(matches!(eval(&set, update), Outcome::Deny { rule, .. } if rule == "freeze"));
        // A missing key is an evaluation error, which also denies.
        let partial = facts(serde_json::json!({"hour": 3}));
        assert!(matches!(
            eval_with(&set, update, &partial),
            Outcome::Deny { .. }
        ));
    }

    #[test]
    fn plugin_facts_are_before_stage_only() {
        #[derive(Deserialize)]
        struct F {
            rules: Vec<RuleConfig>,
        }
        let f: F = toml::from_str(
            r#"
            [[rules]]
            name = "late"
            stage = "after"
            condition = "plugin.clock.freeze"
            verdict = "deny"
        "#,
        )
        .unwrap();
        let err = RuleSet::compile(&f.rules).err().unwrap();
        assert!(err.contains("before-stage"), "{err}");
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
