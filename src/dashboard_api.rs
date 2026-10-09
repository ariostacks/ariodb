//! The dashboard's JSON API beyond login and approvals. Reads need a
//! logged-in user; changes also need the CSRF token (see dashboard.rs).

use crate::audit::{self, Filter};
use crate::config::Config;
use crate::dashboard::{ApiError, require_user, require_writer};
use crate::gate::State;
use crate::{journal, mysql_journal, mysql_undo, testing, undo};
use axum::extract::{Path, Query, State as AxState};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path as FsPath;
use std::sync::Arc;

pub fn routes() -> Router<Arc<State>> {
    Router::new()
        .route("/api/overview", get(overview))
        .route("/api/decisions", get(decisions))
        .route("/api/decisions/{id}/fixture", get(decision_fixture))
        .route("/api/sessions", get(sessions))
        .route("/api/sessions/{id}/plan", get(session_plan))
        .route("/api/sessions/{id}/undo", post(session_undo))
        .route("/api/rules", get(rules))
        .route("/api/explain", post(explain))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/config/check", post(check_config))
        .route("/api/block-like", post(block_like))
        .route("/api/secrets", get(list_secrets))
        .route("/api/secrets/{name}", post(set_secret))
        .route("/api/users", get(list_users).post(add_user))
        .route("/api/audit/verify", get(verify_audit))
}

fn state_dir(state: &State) -> std::path::PathBuf {
    std::path::PathBuf::from(&state.config().journal.dir)
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

async fn overview(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let config = state.config();
    let since = crate::store::now_ms() - 86_400_000;
    let counts = audit::counts_since(&state_dir(&state), since)?;
    let pending = state.db.approvals(true, 1000)?.len();
    let sessions = undo::sessions(&all_records(&config).unwrap_or_default());
    Ok(Json(json!({
        "pending_approvals": pending,
        "decisions_24h": counts.into_iter().map(|(o, n)| json!({ "outcome": o, "count": n })).collect::<Vec<_>>(),
        "sessions_with_changes": sessions.len(),
        "sessions_undone": sessions.iter().filter(|s| s.undone).count(),
        "agents": config.agents.iter().map(|a| json!({
            "name": a.name,
            "access": match a.access { crate::config::Access::ReadOnly => "read only", crate::config::Access::ReadWrite => "read and write" },
            "tables": a.tables,
            "credential": a.credential,
            "token_set": config.agent_token(a).is_some(),
        })).collect::<Vec<_>>(),
        "rules": config.rules.len(),
        "approvers": config.approvers.iter().map(|a| json!({ "name": a.name, "type": a.kind })).collect::<Vec<_>>(),
        "journal": config.journal.enabled,
        "proxy": config.proxy.listen,
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

async fn decisions(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let items = audit::query(&state_dir(&state), &f)?;
    Ok(Json(json!({ "decisions": items })))
}

async fn decision_fixture(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let d = audit::get(&state_dir(&state), id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such decision".into()))?;
    testing::fixture_for(&d, &state.config())
        .map(Json)
        .ok_or_else(|| {
            bad(format!(
                "a {} decision depends on data, so it makes no policy fixture",
                d.outcome
            ))
        })
}

async fn sessions(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let records = all_records(&state.config())?;
    let list: Vec<Value> = undo::sessions(&records)
        .into_iter()
        .map(|s| {
            json!({
                "session": s.session,
                "agent": s.agent,
                "transactions": s.transactions,
                "rows": s.rows,
                "tables": s.tables,
                "last_at_ms": s.last_at_ms,
                "undone": s.undone,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": list })))
}

async fn session_plan(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let config = state.config();
    let mysql_records = mysql_journal::read_all(&config)?;
    if has_session(&mysql_records, &id) {
        let mut conn = mysql_undo::connect(&config).await?;
        let plan = mysql_undo::plan(&mut conn, &config, &mysql_records, &id)
            .await
            .map_err(bad)?;
        return Ok(Json(json!({
            "session": plan.session,
            "steps": plan.steps.iter().map(|s| s.description.clone()).collect::<Vec<_>>(),
            "conflicts": plan.conflicts.iter().map(|c| c.text.clone()).collect::<Vec<_>>(),
            "blocked": plan.blocked,
            "warnings": plan.warnings,
            "already_undone": plan.already_undone,
        })));
    }
    let records = journal::read_all(&config)?;
    let client = undo::connect(&config).await?;
    let plan = undo::plan(&client, &records, &id).await.map_err(bad)?;
    Ok(Json(plan_json(&plan)))
}

/// Every recorded transaction, Postgres and MySQL.
fn all_records(config: &Config) -> Result<Vec<journal::TxnRecord>, String> {
    let mut records = journal::read_all(config)?;
    records.extend(mysql_journal::read_all(config)?);
    Ok(records)
}

fn has_session(records: &[journal::TxnRecord], session: &str) -> bool {
    records.iter().any(|r| r.session.as_deref() == Some(session))
}

fn plan_json(plan: &undo::Plan) -> Value {
    json!({
        "session": plan.session,
        "steps": plan.steps.iter().map(|s| s.description.clone()).collect::<Vec<_>>(),
        "conflicts": plan.conflicts.iter().map(|c| c.text.clone()).collect::<Vec<_>>(),
        "blocked": plan.blocked,
        "already_undone": plan.already_undone,
    })
}

#[derive(Deserialize)]
struct UndoBody {
    #[serde(default)]
    skip_conflicts: bool,
}

async fn session_undo(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UndoBody>,
) -> Result<Json<Value>, ApiError> {
    let user = require_writer(&state, &headers)?;
    let config = state.config();
    let mysql_records = mysql_journal::read_all(&config)?;
    let restored = if has_session(&mysql_records, &id) {
        let mut conn = mysql_undo::connect(&config).await?;
        let plan = mysql_undo::plan(&mut conn, &config, &mysql_records, &id)
            .await
            .map_err(bad)?;
        mysql_undo::apply_plan(&mut conn, &config, &plan, body.skip_conflicts)
            .await
            .map_err(|e| ApiError(StatusCode::CONFLICT, e))?
    } else {
        let records = journal::read_all(&config)?;
        let mut client = undo::connect(&config).await?;
        let plan = undo::plan(&client, &records, &id).await.map_err(bad)?;
        undo::apply(&mut client, &plan, body.skip_conflicts)
            .await
            .map_err(|e| ApiError(StatusCode::CONFLICT, e))?
    };
    println!(
        "ariodb: {} undid session {id} from the dashboard ({restored} rows)",
        user.name
    );
    Ok(Json(json!({ "restored": restored })))
}

async fn rules(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let config = state.config();
    let rules: Vec<Value> = config
        .rules
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "condition": r.condition,
                "verdict": r.verdict,
                "approve": r.approve,
                "reason": r.reason,
                "agents": r.agents,
                "priority": r.priority,
                "stage": r.stage,
            })
        })
        .collect();
    Ok(Json(json!({ "rules": rules })))
}

#[derive(Deserialize)]
struct ExplainBody {
    agent: String,
    sql: String,
    #[serde(default)]
    engine: Option<String>,
}

async fn explain(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<ExplainBody>,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let config = state.config();
    let engine = body.engine.as_deref().unwrap_or("postgres");
    let database = testing::default_database(&config, engine);
    let p = testing::preview(
        &config,
        &state.rules(),
        &body.agent,
        &body.sql,
        &database,
        engine,
    );
    Ok(Json(
        json!({ "verdict": p.verdict, "rule": p.rule, "reason": p.reason }),
    ))
}

/// Find `scheme://user:password@` in config text.
fn url_passwords(text: &str) -> Vec<(usize, usize, String, String)> {
    let mut out = Vec::new();
    for scheme in ["postgres://", "postgresql://"] {
        let mut from = 0;
        while let Some(i) = text[from..].find(scheme) {
            let start = from + i + scheme.len();
            let rest = &text[start..];
            let end_of_url = rest
                .find(|c: char| c == '"' || c == '\'' || c.is_whitespace())
                .unwrap_or(rest.len());
            let url = &rest[..end_of_url];
            if let (Some(colon), Some(at)) = (url.find(':'), url.rfind('@'))
                && colon < at
            {
                let user_host = format!("{}@{}", &url[..colon], &url[at + 1..]);
                out.push((
                    start + colon + 1,
                    start + at,
                    user_host,
                    url[colon + 1..at].to_string(),
                ));
            }
            from = start;
        }
    }
    out.sort_by_key(|p| p.0);
    out
}

/// Replace passwords in database URLs with `***` for display.
fn mask(text: &str) -> String {
    let mut out = text.to_string();
    for (a, b, _, _) in url_passwords(text).into_iter().rev() {
        out.replace_range(a..b, "***");
    }
    out
}

/// Put real passwords back where an edited config still says `***`.
fn unmask(edited: &str, current: &str) -> String {
    let known: std::collections::HashMap<String, String> = url_passwords(current)
        .into_iter()
        .map(|(_, _, uh, pw)| (uh, pw))
        .collect();
    let mut out = edited.to_string();
    for (a, b, user_host, pw) in url_passwords(edited).into_iter().rev() {
        if pw == "***"
            && let Some(real) = known.get(&user_host)
        {
            out.replace_range(a..b, real);
        }
    }
    out
}

async fn get_config(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let text = mask(&std::fs::read_to_string(&state.config_path).map_err(|e| e.to_string())?);
    Ok(Json(json!({
        "text": text,
        "path": state.config_path.display().to_string(),
        "writable": state.config().dashboard.config_writes,
    })))
}

#[derive(Deserialize)]
struct ConfigBody {
    text: String,
}

async fn check_config(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<ConfigBody>,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    Ok(Json(match Config::from_toml(&body.text) {
        Ok(c) => {
            json!({ "ok": true, "agents": c.agents.len(), "rules": c.rules.len(), "approvers": c.approvers.len() })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }))
}

/// Save a new config: validated first, written atomically with a backup,
/// then applied at once.
fn save_config(state: &State, text: &str) -> Result<(), ApiError> {
    if !state.config().dashboard.config_writes {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "the dashboard may not change the config (dashboard.config_writes = false); copy the text into your config repository instead".into(),
        ));
    }
    let parsed = Config::from_toml(text).map_err(|e| bad(e.to_string()))?;
    let path = &state.config_path;
    let backup = path.with_extension("toml.bak");
    let _ = std::fs::copy(path, &backup);
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    state.replace_config(parsed).map_err(bad)?;
    Ok(())
}

async fn put_config(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<ConfigBody>,
) -> Result<Json<Value>, ApiError> {
    let user = require_writer(&state, &headers)?;
    let current = std::fs::read_to_string(&state.config_path).map_err(|e| e.to_string())?;
    save_config(&state, &unmask(&body.text, &current))?;
    println!("ariodb: {} saved the config from the dashboard", user.name);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct BlockBody {
    decision: i64,
    #[serde(default)]
    apply: bool,
}

/// "Block requests like this": write a deny rule matching a decision's
/// agent, verb and tables. Previewed and validated against the whole config
/// before anything is written.
async fn block_like(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<BlockBody>,
) -> Result<Json<Value>, ApiError> {
    let user = if body.apply {
        require_writer(&state, &headers)?
    } else {
        require_user(&state, &headers)?
    };
    let d = audit::get(&state_dir(&state), body.decision)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such decision".into()))?;
    let stmt = crate::classify::classify(&d.sql)
        .ok()
        .and_then(|mut s| {
            if s.is_empty() {
                None
            } else {
                Some(s.remove(0))
            }
        })
        .ok_or_else(|| bad("the decision's statement cannot be parsed"))?;
    let verb = crate::rules::verb(&stmt);
    let (name, snippet) = deny_rule_snippet(&d.agent, &verb, &stmt.tables, d.id);
    let current = std::fs::read_to_string(&state.config_path).map_err(|e| e.to_string())?;
    let candidate = format!(
        "{}{snippet}",
        current.trim_end_matches('\n').to_string() + "\n"
    );
    if let Err(e) = Config::from_toml(&candidate) {
        return Err(bad(format!("the generated rule does not validate: {e}")));
    }
    if body.apply {
        save_config(&state, &candidate)?;
        println!("ariodb: {} added rule {name} from the dashboard", user.name);
    }
    Ok(Json(
        json!({ "rule": name, "snippet": snippet, "applied": body.apply }),
    ))
}

/// The deny rule "block requests like this" writes. Table names come from
/// the agent's own SQL, and a quoted Postgres identifier may hold quotes,
/// backslashes or new lines, so every value is escaped for CEL and then the
/// whole condition for TOML. Otherwise an agent could name a table so that
/// the rule an operator saves also adds config of the agent's choosing.
fn deny_rule_snippet(
    agent: &str,
    verb: &str,
    tables: &[String],
    decision: i64,
) -> (String, String) {
    let mut parts = vec![
        format!("agent.name == {}", cel_string(agent)),
        format!("sql.verb == {}", cel_string(verb)),
    ];
    if !tables.is_empty() {
        let list = tables
            .iter()
            .map(|t| cel_string(t))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("intersects(sql.tables, [{list}])"));
    }
    let slug = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    };
    let first_table = tables.first().map(String::as_str).unwrap_or("any");
    let name = format!(
        "block-{}-{}-{}-{decision}",
        slug(agent),
        slug(verb),
        slug(first_table)
    );
    let snippet = format!(
        "\n[[rules]]\nname = {}\ncondition = {}\nverdict = \"deny\"\nreason = \"blocked from the dashboard after decision {decision}\"\n",
        toml_string(&name),
        toml_string(&parts.join(" && ")),
    );
    (name, snippet)
}

/// A CEL string literal: single quotes, with backslashes, single quotes and
/// control characters escaped. (Double quotes need no escape here, and
/// TOML's escaping covers them in the config file.)
fn cel_string(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// A TOML basic string, escaped by the TOML library itself.
fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

async fn list_secrets(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let store = crate::secrets::Store::open(FsPath::new(&state.config().journal.dir))?;
    Ok(Json(json!({ "secrets": store.names()? })))
}

#[derive(Deserialize)]
struct SecretBody {
    value: String,
}

async fn set_secret(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<SecretBody>,
) -> Result<Json<Value>, ApiError> {
    let user = require_writer(&state, &headers)?;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(bad("secret names use letters, digits, - and _"));
    }
    if body.value.is_empty() {
        return Err(bad("the value is empty"));
    }
    let store = crate::secrets::Store::open(FsPath::new(&state.config().journal.dir))?;
    store.set(&name, &body.value)?;
    println!(
        "ariodb: {} set secret '{name}' from the dashboard",
        user.name
    );
    Ok(Json(json!({ "ok": true })))
}

async fn list_users(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    let users: Vec<String> = state.db.with(|c| {
        let mut stmt = c.prepare("SELECT name FROM dashboard_users ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    })?;
    Ok(Json(json!({ "users": users })))
}

#[derive(Deserialize)]
struct UserBody {
    name: String,
    password: String,
}

async fn add_user(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<UserBody>,
) -> Result<Json<Value>, ApiError> {
    let user = require_writer(&state, &headers)?;
    if body.name.is_empty()
        || !body
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        return Err(bad("user names use letters, digits and - _ . @"));
    }
    crate::dashboard::set_password(&state.db, &body.name, &body.password).map_err(bad)?;
    println!(
        "ariodb: {} set the password for dashboard user '{}'",
        user.name, body.name
    );
    Ok(Json(json!({ "ok": true })))
}

async fn verify_audit(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_user(&state, &headers)?;
    Ok(Json(match audit::verify(&state_dir(&state)) {
        Ok(n) => json!({ "ok": true, "entries": n }),
        Err(e) => json!({ "ok": false, "error": e }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_like_this_escapes_what_the_agent_named() {
        use crate::rules::{Facts, Outcome, RuleSet};
        let base = r#"
[database]
url = "postgres://localhost:5432/app"

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders"]
token_env = "ARIODB_TOKEN_TEST"
"#;
        // A quoted identifier can hold quotes, backslashes and new lines.
        let table = "a'b\\c\"d\n[[agents]]\nname = 'planted'\naccess = \"read_write\"";
        let sql = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
        let stmt = crate::classify::classify(&sql).unwrap().remove(0);
        assert_eq!(stmt.tables, vec![table.to_string()]);

        let (name, snippet) =
            deny_rule_snippet("coding-agent", &crate::rules::verb(&stmt), &stmt.tables, 7);
        assert!(name.starts_with("block-coding-agent-select-a-b-c-d-"));
        let config = Config::from_toml(&format!("{base}{snippet}")).expect("still valid TOML");
        assert_eq!(config.agents.len(), 1, "no agent was planted");
        assert_eq!(config.rules.len(), 1);

        // And the rule blocks exactly that table.
        let rules = RuleSet::compile(&config.rules).expect("the rule compiles");
        let facts = |s| Facts {
            agent: &config.agents[0],
            statement: s,
            database: "app",
        };
        assert!(matches!(
            rules.evaluate(&facts(&stmt)),
            Outcome::Deny { .. }
        ));
        let other = crate::classify::classify("SELECT * FROM orders")
            .unwrap()
            .remove(0);
        assert_eq!(rules.evaluate(&facts(&other)), Outcome::NoMatch);
    }

    #[test]
    fn masks_and_restores_url_passwords() {
        let file = "url = \"postgres://gw:s3cret-not-real@db:5432/app\"\nother = \"postgresql://ro:also-fake@db2/app\"\n";
        let shown = mask(file);
        assert!(!shown.contains("s3cret") && !shown.contains("also-fake"));
        assert!(shown.contains("postgres://gw:***@db:5432/app"));
        assert_eq!(unmask(&shown, file), file);
        // A deliberately changed password is kept.
        let edited = shown.replace("gw:***", "gw:new-fake-pw");
        assert!(unmask(&edited, file).contains("gw:new-fake-pw@db"));
    }
}
