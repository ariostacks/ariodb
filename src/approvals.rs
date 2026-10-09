//! Approvals: a rule with `verdict = "approve"` holds the statement until
//! every listed approver allows it. Nothing reaches the database while it
//! waits; a deny or a timeout refuses the statement.
//!
//! Approver types:
//! - `dashboard`: a person decides in the dashboard or with `ariodb approvals`.
//! - `slack`: posts to a channel, optionally with Approve and Deny buttons.
//! - `webhook`: POSTs a signed request to any URL (Discord, Telegram, PagerDuty,
//!   your own service), which answers by following a signed link.
//! - `llm`: a model judges the statement against a written policy. The
//!   providers' APIs live in `llm.rs`.

use crate::classify::Statement;
use crate::gate::{ApprovalNeed, Ctx, Refusal, State};
use crate::llm::Judged;
use crate::store::{self, Approval};
use hmac::{KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// How long a person has to decide. Agents should wait longer than this.
    pub timeout_seconds: u64,
    /// When the model cannot be reached (network, 429, 5xx): `closed`
    /// refuses, `open` allows. Configuration errors always refuse.
    pub llm_fail_mode: FailMode,
    /// Reuse a model's decision for the same agent and statement this long.
    pub llm_cache_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            timeout_seconds: 90,
            llm_fail_mode: FailMode::Closed,
            llm_cache_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    Closed,
    Open,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproverConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ApproverKind,
    /// Overrides `approvals.timeout_seconds`.
    pub timeout_seconds: Option<u64>,
    // slack
    pub channel: Option<String>,
    pub bot_token_secret: Option<String>,
    pub bot_token_env: Option<String>,
    pub signing_secret_secret: Option<String>,
    pub signing_secret_env: Option<String>,
    #[serde(default)]
    pub interactive: bool,
    // webhook
    pub url: Option<String>,
    pub hmac_secret_secret: Option<String>,
    pub hmac_secret_env: Option<String>,
    // llm
    /// `anthropic` (default), `openai`, `gemini`, `azure_openai` or
    /// `openai_compatible`.
    pub provider: Option<String>,
    /// The API's address: required for `openai_compatible` and
    /// `azure_openai` (the resource endpoint), optional for the others.
    pub base_url: Option<String>,
    /// For `azure_openai`, the deployment name.
    pub model: Option<String>,
    pub policy: Option<String>,
    pub api_key_secret: Option<String>,
    pub api_key_env: Option<String>,
    pub effort: Option<String>,
    /// `azure_openai` only: `v1` (default) or `preview`.
    pub api_version: Option<String>,
    // plugin
    /// The `[[plugins]]` entry that decides.
    pub plugin: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverKind {
    Dashboard,
    Slack,
    Webhook,
    Llm,
    Plugin,
}

/// Check approver definitions when the config loads.
pub fn validate(
    approvers: &[ApproverConfig],
    rules: &[crate::rules::RuleConfig],
) -> Result<(), String> {
    let mut names = std::collections::HashSet::new();
    for a in approvers {
        if !names.insert(a.name.as_str()) {
            return Err(format!("approver '{}' is defined twice", a.name));
        }
        let missing =
            |what: &str| Err(format!("approver '{}' ({:?}) needs {what}", a.name, a.kind));
        match a.kind {
            ApproverKind::Dashboard => {}
            ApproverKind::Slack => {
                if a.channel.is_none() {
                    return missing("channel");
                }
                if a.bot_token_secret.is_none() && a.bot_token_env.is_none() {
                    return missing("bot_token_secret or bot_token_env");
                }
                if a.interactive
                    && a.signing_secret_secret.is_none()
                    && a.signing_secret_env.is_none()
                {
                    return missing(
                        "signing_secret_secret or signing_secret_env for interactive buttons",
                    );
                }
            }
            ApproverKind::Webhook => {
                if a.url.is_none() {
                    return missing("url");
                }
                if a.hmac_secret_secret.is_none() && a.hmac_secret_env.is_none() {
                    return missing("hmac_secret_secret or hmac_secret_env");
                }
            }
            ApproverKind::Llm => {
                if a.policy.is_none() {
                    return missing("policy");
                }
                for warning in crate::llm::validate(a)? {
                    eprintln!("ariodb: warning: {warning}");
                }
            }
            ApproverKind::Plugin => {
                if a.plugin.is_none() {
                    return missing("plugin");
                }
            }
        }
    }
    for r in rules {
        for name in &r.approve {
            if !names.contains(name.as_str()) {
                return Err(format!(
                    "rule '{}' uses approver '{name}', which is not defined",
                    r.name
                ));
            }
        }
    }
    Ok(())
}

/// Ask every approver in order. All must allow.
pub async fn require(
    state: &State,
    ctx: &Ctx<'_>,
    statements: &[Statement],
    need: &ApprovalNeed,
) -> Result<(), Refusal> {
    let config = state.config();
    let sql = statements
        .iter()
        .map(|s| s.sql.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    for name in &need.approvers {
        let Some(approver) = config.approvers.iter().find(|a| &a.name == name) else {
            return Err(Refusal::by_rule(
                &need.rule,
                format!("approver '{name}' is not defined"),
            ));
        };
        // Notifiers get the statement as the decisions log stores it.
        let stored = statements
            .iter()
            .map(|s| crate::audit::stored_sql(&s.sql, config.audit.redact_literals))
            .collect::<Vec<_>>()
            .join("; ");
        let event = json!({
            "rule": need.rule,
            "approver": approver.name,
            "approver_type": approver.kind,
            "agent": ctx.agent.name,
            "session": ctx.session,
            "database": ctx.database,
            "sql": stored,
            "reason": need.reason,
        });
        crate::plugins::notify("approval_requested", event.clone());
        let verdict = match approver.kind {
            ApproverKind::Llm => ask_model(state, approver, ctx, statements, need).await,
            ApproverKind::Plugin => {
                crate::plugins::ask(state, approver, ctx, statements, need).await
            }
            _ => ask_person(state, approver, ctx, &sql, need).await,
        };
        let mut decided = event;
        decided["verdict"] = json!(if verdict.is_ok() { "allow" } else { "deny" });
        decided["why"] = json!(verdict.as_ref().err());
        crate::plugins::notify("approval_decided", decided);
        if let Err(why) = verdict {
            return Err(Refusal::by_rule(
                &need.rule,
                format!("{}: {why}", need.reason),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// People: dashboard, Slack and webhooks all wait on the same stored request.

async fn ask_person(
    state: &State,
    approver: &crate::approvals::ApproverConfig,
    ctx: &Ctx<'_>,
    sql: &str,
    need: &ApprovalNeed,
) -> Result<(), String> {
    let config = state.config();
    let timeout = approver
        .timeout_seconds
        .unwrap_or(config.approvals.timeout_seconds);
    let now = store::now_ms();
    let approval = Approval {
        id: format!("a-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
        created_ms: now,
        expires_ms: now + timeout as i64 * 1000,
        agent: ctx.agent.name.clone(),
        session: ctx.session.to_string(),
        sql: sql.to_string(),
        rule: need.rule.clone(),
        approver: approver.name.clone(),
        reason: need.reason.clone(),
        status: "pending".to_string(),
        decided_by: None,
        note: None,
        decided_ms: None,
    };
    state.db.insert_approval(&approval)?;

    let notified = match approver.kind {
        ApproverKind::Slack => notify_slack(&config, approver, &approval).await,
        ApproverKind::Webhook => notify_webhook(&config, approver, &approval).await,
        _ => Ok(()),
    };
    if let Err(e) = notified {
        state.db.decide(&approval.id, false, "ariodb", Some(&e))?;
        return Err(format!("could not reach approver '{}': {e}", approver.name));
    }

    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        if let Some(a) = state.db.approval(&approval.id)? {
            match a.status.as_str() {
                "allowed" => return Ok(()),
                "denied" => {
                    let by = a.decided_by.unwrap_or_default();
                    let note = a.note.map(|n| format!(" ({n})")).unwrap_or_default();
                    return Err(format!("denied by {by}{note}"));
                }
                "expired" => return Err("the approval request expired".to_string()),
                _ => {}
            }
        }
        if let Some(why) = ctx.live.and_then(|l| l.stopped()) {
            state.db.withdraw(&approval.id, why)?;
            return Err(format!("{why}, so the request was withdrawn"));
        }
        if Instant::now() >= deadline {
            state.db.expire(&approval.id)?;
            return Err(format!(
                "no decision from '{}' within {timeout} seconds",
                approver.name
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

pub(crate) fn secret_value(
    config: &crate::config::Config,
    secret: &Option<String>,
    env: &Option<String>,
) -> Result<String, String> {
    if let Some(name) = secret {
        return config
            .secret(name)?
            .ok_or_else(|| format!("secret '{name}' is not set"));
    }
    if let Some(var) = env {
        return std::env::var(var).map_err(|_| format!("environment variable {var} is not set"));
    }
    Err("no credential configured".to_string())
}

fn dashboard_link(config: &crate::config::Config, id: &str) -> String {
    format!(
        "{}/#approval-{id}",
        config.dashboard.public_url.trim_end_matches('/')
    )
}

async fn notify_slack(
    config: &crate::config::Config,
    approver: &ApproverConfig,
    a: &Approval,
) -> Result<(), String> {
    let token = secret_value(config, &approver.bot_token_secret, &approver.bot_token_env)?;
    let text = format!(
        "*ariodb approval needed* ({})\nAgent `{}` wants to run:\n```{}```\nRule: {}\n<{}|Open in the dashboard>",
        slack_escape(&a.reason),
        slack_escape(&a.agent),
        slack_escape(&truncate(&a.sql, 2500)),
        slack_escape(&a.rule),
        dashboard_link(config, &a.id)
    );
    let mut blocks = vec![json!({ "type": "section", "text": { "type": "mrkdwn", "text": text } })];
    if approver.interactive {
        blocks.push(json!({ "type": "actions", "block_id": a.id, "elements": [
            { "type": "button", "style": "primary", "text": { "type": "plain_text", "text": "Approve" }, "action_id": "approve", "value": a.id },
            { "type": "button", "style": "danger", "text": { "type": "plain_text", "text": "Deny" }, "action_id": "deny", "value": a.id }
        ]}));
    }
    let body = json!({ "channel": approver.channel, "text": format!("ariodb approval needed: {}", a.reason), "blocks": blocks });
    let base =
        std::env::var("ARIODB_SLACK_API").unwrap_or_else(|_| "https://slack.com/api".to_string());
    let resp: Value = http()
        .post(format!("{base}/chat.postMessage"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if resp["ok"] != true {
        return Err(format!(
            "Slack said: {}",
            resp["error"].as_str().unwrap_or("unknown error")
        ));
    }
    Ok(())
}

async fn notify_webhook(
    config: &crate::config::Config,
    approver: &ApproverConfig,
    a: &Approval,
) -> Result<(), String> {
    let key = secret_value(
        config,
        &approver.hmac_secret_secret,
        &approver.hmac_secret_env,
    )?;
    let base = config.dashboard.public_url.trim_end_matches('/');
    let link = |verdict: &str| {
        let token = sign(&key, &format!("{}:{verdict}", a.id));
        format!(
            "{base}/hooks/approvals/{}?verdict={verdict}&token={token}",
            a.id
        )
    };
    let body = json!({
        "id": a.id,
        "agent": a.agent,
        "session": a.session,
        "sql": a.sql,
        "rule": a.rule,
        "reason": a.reason,
        "expires_ms": a.expires_ms,
        "approve_url": link("allow"),
        "deny_url": link("deny"),
        "dashboard_url": dashboard_link(config, &a.id),
    })
    .to_string();
    let resp = http()
        .post(approver.url.as_deref().unwrap_or_default())
        .header("content-type", "application/json")
        .header(
            "x-ariodb-signature",
            format!("sha256={}", sign(&key, &body)),
        )
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("webhook answered {}", resp.status()));
    }
    Ok(())
}

/// HMAC-SHA256 as hex.
pub fn sign(key: &str, message: &str) -> String {
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Check a webhook decision link.
pub fn verify_link(config: &crate::config::Config, id: &str, verdict: &str, token: &str) -> bool {
    let Some(a) = config_approver_for(config, id) else {
        return false;
    };
    let Ok(key) = secret_value(config, &a.hmac_secret_secret, &a.hmac_secret_env) else {
        return false;
    };
    let expected = sign(&key, &format!("{id}:{verdict}"));
    expected.len() == token.len()
        && expected
            .bytes()
            .zip(token.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn config_approver_for<'a>(
    config: &'a crate::config::Config,
    id: &str,
) -> Option<&'a ApproverConfig> {
    // The approval row names its approver; links are only valid for webhooks.
    let db = crate::store::Db::open(std::path::Path::new(&config.journal.dir)).ok()?;
    let row = db.approval(id).ok()??;
    config
        .approvers
        .iter()
        .find(|a| a.name == row.approver && a.kind == ApproverKind::Webhook)
}

/// Check a Slack interactivity request: `v0=` HMAC of `v0:{timestamp}:{body}`,
/// with the timestamp within five minutes. Returns the Slack approvers whose
/// signing secret signed it (none means the request is not genuine).
pub fn verify_slack(
    config: &crate::config::Config,
    timestamp: &str,
    body: &str,
    signature: &str,
) -> Vec<String> {
    let Ok(ts) = timestamp.parse::<i64>() else {
        return Vec::new();
    };
    if (store::now_ms() / 1000 - ts).abs() > 300 {
        return Vec::new();
    }
    config
        .approvers
        .iter()
        .filter(|a| a.kind == ApproverKind::Slack && a.interactive)
        .filter(|a| {
            secret_value(config, &a.signing_secret_secret, &a.signing_secret_env).is_ok_and(|key| {
                let expected = format!("v0={}", sign(&key, &format!("v0:{timestamp}:{body}")));
                expected.len() == signature.len()
                    && expected
                        .bytes()
                        .zip(signature.bytes())
                        .fold(0, |acc, (x, y)| acc | (x ^ y))
                        == 0
            })
        })
        .map(|a| a.name.clone())
        .collect()
}

/// Make agent-written text safe inside a Slack message. `&`, `<` and `>`
/// are escaped as Slack asks, so the SQL cannot make links or mentions, and
/// runs of backticks are broken up with zero-width spaces, so the SQL cannot
/// close its code block and write the rest of the message (a fake "approve
/// here" link, say) in Slack formatting.
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('`', "`\u{200b}")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn http() -> reqwest::Client {
    crate::tls::init();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("HTTP client")
}

// ---------------------------------------------------------------------------
// Models: a model judges the statement against a policy (see `llm.rs`).

/// A cached model decision and when it was made.
type Cached = (Instant, Result<(), String>);
static LLM_CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);
/// Past this many cached decisions, expired ones are swept out.
const LLM_CACHE_SWEEP: usize = 1_000;

/// What a cached decision may be reused for: the same question, put to the
/// same model at the same address under the same policy. A changed policy,
/// rule, database, provider or model asks again rather than reusing an
/// answer to a different question.
fn cache_key(
    approver: &ApproverConfig,
    agent: &str,
    database: &str,
    rule: &str,
    sql: &str,
) -> String {
    let parts = json!([
        approver.name,
        crate::llm::decider(approver),
        approver.base_url,
        approver.api_version,
        approver.policy,
        agent,
        database,
        rule,
        sql
    ]);
    hex::encode(<Sha256 as sha2::Digest>::digest(
        parts.to_string().as_bytes(),
    ))
}

async fn ask_model(
    state: &State,
    approver: &ApproverConfig,
    ctx: &Ctx<'_>,
    statements: &[Statement],
    need: &ApprovalNeed,
) -> Result<(), String> {
    let config = state.config();
    let sql = statements
        .iter()
        .map(|s| s.sql.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let key = cache_key(approver, &ctx.agent.name, ctx.database, &need.rule, &sql);
    let ttl = Duration::from_secs(config.approvals.llm_cache_seconds);
    if let Some((at, verdict)) = LLM_CACHE
        .lock()
        .expect("cache")
        .as_ref()
        .and_then(|m| m.get(&key))
        .cloned()
        && at.elapsed() < ttl
    {
        return verdict;
    }

    let judged = judge(&config, approver, ctx, statements, need).await;
    // Only the model's own answers are reused. An outage (allowed under
    // fail-open) or a setup error must not stand in for a decision.
    let cacheable = matches!(judged, Judged::Allow | Judged::Deny(_));
    let decider = crate::llm::decider(approver);
    let who = format!("model approver '{}' ({decider})", approver.name);
    // An allow the model never gave must not look like one in the record.
    let mut failed_open = None;
    let verdict = match judged {
        Judged::Allow => Ok(()),
        Judged::Deny(reason) => Err(format!("denied by {who}: {reason}")),
        Judged::ConfigError(e) => Err(format!("{who} is misconfigured: {e}")),
        Judged::Unavailable(e) => match config.approvals.llm_fail_mode {
            FailMode::Closed => Err(format!("{who} unavailable ({e}); failing closed")),
            FailMode::Open => {
                let why = format!("{who} unavailable ({e}); failing open");
                eprintln!("ariodb: {why}");
                failed_open = Some(why);
                Ok(())
            }
        },
    };

    // Record the decision alongside people's decisions, for the dashboard and audit.
    let now = store::now_ms();
    let _ = state.db.insert_approval(&Approval {
        id: format!("a-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
        created_ms: now,
        expires_ms: now,
        agent: ctx.agent.name.clone(),
        session: ctx.session.to_string(),
        sql,
        rule: need.rule.clone(),
        approver: approver.name.clone(),
        reason: need.reason.clone(),
        status: if verdict.is_ok() {
            "allowed".into()
        } else {
            "denied".into()
        },
        decided_by: Some(decider),
        note: verdict.as_ref().err().cloned().or(failed_open),
        decided_ms: Some(now),
    });

    if cacheable {
        let mut cache = LLM_CACHE.lock().expect("cache");
        let cache = cache.get_or_insert_with(HashMap::new);
        if cache.len() >= LLM_CACHE_SWEEP {
            cache.retain(|_, (at, _)| at.elapsed() < ttl);
        }
        cache.insert(key, (Instant::now(), verdict.clone()));
    }
    verdict
}

async fn judge(
    config: &crate::config::Config,
    approver: &ApproverConfig,
    ctx: &Ctx<'_>,
    statements: &[Statement],
    need: &ApprovalNeed,
) -> Judged {
    let target = match crate::llm::Target::new(config, approver) {
        Ok(t) => t,
        Err(e) => return Judged::ConfigError(e),
    };
    let request = json!({
        "agent": ctx.agent.name,
        "database": ctx.database,
        "rule": need.rule,
        "rule_reason": need.reason,
        "statements": statements.iter().map(|s| json!({
            "sql": s.sql,
            "kind": s.kind,
            "tables": s.tables,
            "functions": s.functions,
        })).collect::<Vec<_>>(),
    });
    let question = crate::llm::question(approver.policy.as_deref().unwrap_or_default(), &request);
    crate::llm::ask(&target, &question).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slack_messages_cannot_be_rewritten_by_the_sql() {
        let sql = "SELECT 1 ``` <https://evil.example|Approve here> & <!channel>";
        let safe = slack_escape(sql);
        assert!(!safe.contains("```"));
        assert!(!safe.contains('<') && !safe.contains('>'));
        assert!(safe.contains("&lt;https://evil.example|Approve here&gt; &amp; &lt;!channel&gt;"));
    }

    #[test]
    fn model_cache_keys_cover_the_whole_question() {
        let approver = |policy: &str| ApproverConfig {
            name: "judge".into(),
            kind: ApproverKind::Llm,
            timeout_seconds: None,
            channel: None,
            bot_token_secret: None,
            bot_token_env: None,
            signing_secret_secret: None,
            signing_secret_env: None,
            interactive: false,
            url: None,
            hmac_secret_secret: None,
            hmac_secret_env: None,
            model: None,
            policy: Some(policy.into()),
            api_key_secret: None,
            api_key_env: None,
            effort: None,
            provider: None,
            base_url: None,
            api_version: None,
            plugin: None,
        };
        let lenient = approver("Allow anything.");
        let strict = approver("Deny writes.");
        let key = |a, db, rule| cache_key(a, "bot", db, rule, "UPDATE t SET a = 1 WHERE id = 1");
        assert_eq!(key(&lenient, "app", "r1"), key(&lenient, "app", "r1"));
        assert_ne!(key(&lenient, "app", "r1"), key(&strict, "app", "r1"));
        assert_ne!(key(&lenient, "app", "r1"), key(&lenient, "other", "r1"));
        assert_ne!(key(&lenient, "app", "r1"), key(&lenient, "app", "r2"));
        let elsewhere = |provider: &str, base: Option<&str>, model: Option<&str>| {
            let mut a = approver("Allow anything.");
            a.provider = Some(provider.into());
            a.base_url = base.map(str::to_string);
            a.model = model.map(str::to_string);
            a
        };
        let local = elsewhere(
            "openai_compatible",
            Some("http://localhost:11434/v1"),
            Some("m"),
        );
        let other = elsewhere(
            "openai_compatible",
            Some("http://localhost:8000/v1"),
            Some("m"),
        );
        assert_ne!(key(&local, "app", "r1"), key(&other, "app", "r1"));
        let openai = elsewhere("openai", None, None);
        let gemini = elsewhere("gemini", None, None);
        let luna = elsewhere("openai", None, Some("gpt-6-luna"));
        assert_ne!(key(&openai, "app", "r1"), key(&gemini, "app", "r1"));
        assert_ne!(key(&openai, "app", "r1"), key(&luna, "app", "r1"));
    }

    #[test]
    fn signatures_are_stable() {
        assert_eq!(sign("key", "a-1:allow"), sign("key", "a-1:allow"));
        assert_ne!(sign("key", "a-1:allow"), sign("key", "a-1:deny"));
    }
}
