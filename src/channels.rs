//! People's approval channels beyond Slack and the generic webhook: Discord,
//! Telegram, Microsoft Teams, Google Chat, Mattermost, PagerDuty, Opsgenie
//! and email.
//!
//! Each one posts the request with Approve and Deny links to the dashboard's
//! confirmation page, the same signed links the webhook approver sends, so
//! no channel needs an endpoint of its own that the internet can reach. The
//! links only open a page; the decision is the button on that page.
//!
//! Agent SQL is escaped for each channel's format and kept apart from the
//! links (in a code block, a plain-text run, a quoted block or a details
//! field), so it cannot add links, mentions or formatting of its own.

use crate::approvals::{ApproverConfig, ApproverKind, secret_value};
use serde_json::{Value, json};
use std::time::Duration;

/// What every channel shows about a request.
pub struct Notice<'a> {
    pub id: &'a str,
    pub agent: &'a str,
    pub rule: &'a str,
    pub reason: &'a str,
    pub sql: &'a str,
    pub expires_in_seconds: i64,
    pub approve_url: String,
    pub deny_url: String,
    pub dashboard_url: String,
}

const TITLE: &str = "ariodb approval needed";
/// Said wherever the links appear, so nobody expects a click to decide.
const CONFIRM: &str = "Each link opens a page that asks you to confirm.";
/// Said before a statement too long to show in full.
const SHORTENED: &str = "shortened here (the confirmation page shows all of it)";

/// Post a request to the approver's channel.
pub async fn notify(
    config: &crate::config::Config,
    approver: &ApproverConfig,
    n: &Notice<'_>,
) -> Result<(), String> {
    match approver.kind {
        ApproverKind::Discord => {
            let mut url = webhook_url(config, approver)?;
            // `wait` makes Discord say whether the message was saved;
            // `with_components` lets a channel webhook send link buttons.
            url.query_pairs_mut()
                .append_pair("wait", "true")
                .append_pair("with_components", "true");
            post(url.as_str(), None, &discord(n)).await
        }
        ApproverKind::Teams | ApproverKind::GoogleChat | ApproverKind::Mattermost => {
            let url = webhook_url(config, approver)?;
            let body = match approver.kind {
                ApproverKind::Teams => teams(n),
                ApproverKind::GoogleChat => google_chat(n),
                _ => mattermost(n, approver.channel.as_deref()),
            };
            post(url.as_str(), None, &body).await
        }
        ApproverKind::Telegram => {
            let token = secret_value(config, &approver.bot_token_secret, &approver.bot_token_env)?;
            let chat = approver
                .chat_id
                .as_ref()
                .map(ChatId::json)
                .unwrap_or_default();
            let base = api("ARIODB_TELEGRAM_API", "https://api.telegram.org");
            post(
                &format!("{base}/bot{}/sendMessage", token.trim()),
                None,
                &telegram(n, chat),
            )
            .await
        }
        ApproverKind::Pagerduty => {
            let key = secret_value(
                config,
                &approver.routing_key_secret,
                &approver.routing_key_env,
            )?;
            post(
                &format!("{}/v2/enqueue", pagerduty_api(approver)),
                None,
                &pagerduty_trigger(n, key.trim()),
            )
            .await
        }
        ApproverKind::Opsgenie => {
            let key = secret_value(config, &approver.api_key_secret, &approver.api_key_env)?;
            post(
                &format!("{}/v2/alerts", opsgenie_api(approver)),
                Some(format!("GenieKey {}", key.trim())),
                &opsgenie_alert(n),
            )
            .await
        }
        ApproverKind::Email => send_email(config, approver, n).await,
        _ => Ok(()),
    }
}

/// Once a request is decided, expired or withdrawn, resolve the PagerDuty
/// incident or close the Opsgenie alert, so nobody is paged for a question
/// that has been answered. A failure here is only logged: the decision
/// stands either way.
pub async fn settle(
    config: &crate::config::Config,
    approver: &ApproverConfig,
    id: &str,
    outcome: &str,
) {
    let sent = match approver.kind {
        ApproverKind::Pagerduty => {
            match secret_value(
                config,
                &approver.routing_key_secret,
                &approver.routing_key_env,
            ) {
                Ok(key) => {
                    post(
                        &format!("{}/v2/enqueue", pagerduty_api(approver)),
                        None,
                        &json!({ "routing_key": key.trim(), "event_action": "resolve", "dedup_key": id }),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        }
        ApproverKind::Opsgenie => {
            match secret_value(config, &approver.api_key_secret, &approver.api_key_env) {
                Ok(key) => {
                    post(
                        &format!(
                            "{}/v2/alerts/{id}/close?identifierType=alias",
                            opsgenie_api(approver)
                        ),
                        Some(format!("GenieKey {}", key.trim())),
                        &json!({ "source": "ariodb", "note": format!("ariodb: {outcome}") }),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        }
        _ => Ok(()),
    };
    if let Err(e) = sent {
        eprintln!(
            "ariodb: could not close request {id} in approver '{}': {e}",
            approver.name
        );
    }
}

/// Check a channel approver's settings when the config loads.
pub fn validate(a: &ApproverConfig) -> Result<(), String> {
    let missing = |what: &str| {
        Err(format!(
            "approver '{}' ({}) needs {what}",
            a.name,
            a.kind.name()
        ))
    };
    match a.kind {
        ApproverKind::Discord
        | ApproverKind::Teams
        | ApproverKind::GoogleChat
        | ApproverKind::Mattermost => {
            if a.url.is_some() {
                return Err(format!(
                    "approver '{}' ({}): put the webhook URL in url_secret or url_env, not url: the URL itself is the credential",
                    a.name,
                    a.kind.name()
                ));
            }
            if a.url_secret.is_none() && a.url_env.is_none() {
                return missing("url_secret or url_env (the incoming webhook's URL)");
            }
        }
        ApproverKind::Telegram => {
            if a.bot_token_secret.is_none() && a.bot_token_env.is_none() {
                return missing("bot_token_secret or bot_token_env");
            }
            if a.chat_id.is_none() {
                return missing("chat_id");
            }
        }
        ApproverKind::Pagerduty => {
            if a.routing_key_secret.is_none() && a.routing_key_env.is_none() {
                return missing(
                    "routing_key_secret or routing_key_env (an Events API v2 integration key)",
                );
            }
        }
        ApproverKind::Opsgenie => {
            if a.api_key_secret.is_none() && a.api_key_env.is_none() {
                return missing("api_key_secret or api_key_env");
            }
        }
        ApproverKind::Email => {
            let Some(host) = &a.smtp_host else {
                return missing("smtp_host");
            };
            let Some(from) = &a.from else {
                return missing("from");
            };
            if a.to.is_empty() {
                return missing("at least one address in to");
            }
            for address in std::iter::once(from).chain(&a.to) {
                address.parse::<lettre::message::Mailbox>().map_err(|e| {
                    format!(
                        "approver '{}': '{address}' is not an email address: {e}",
                        a.name
                    )
                })?;
            }
            match a.smtp_tls.as_deref().unwrap_or("starttls") {
                "starttls" | "tls" => {}
                "none" if is_local(host) => {}
                "none" => {
                    return Err(format!(
                        "approver '{}': smtp_tls = \"none\" is only allowed for a mail server on this machine; use \"starttls\" or \"tls\"",
                        a.name
                    ));
                }
                other => {
                    return Err(format!(
                        "approver '{}': smtp_tls must be \"starttls\", \"tls\" or \"none\", not \"{other}\"",
                        a.name
                    ));
                }
            }
            let password = a.smtp_password_secret.is_some() || a.smtp_password_env.is_some();
            if a.smtp_user.is_some() != password {
                return missing(
                    "both smtp_user and smtp_password_secret or smtp_password_env, or neither",
                );
            }
        }
        _ => {}
    }
    if matches!(a.kind, ApproverKind::Pagerduty | ApproverKind::Opsgenie)
        && !matches!(a.region.as_deref(), None | Some("us") | Some("eu"))
    {
        return Err(format!(
            "approver '{}': region must be \"us\" or \"eu\"",
            a.name
        ));
    }
    Ok(())
}

/// A Telegram chat: a number, or `@channelusername`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum ChatId {
    Number(i64),
    Name(String),
}

impl ChatId {
    fn json(&self) -> Value {
        match self {
            ChatId::Number(n) => json!(n),
            ChatId::Name(s) => json!(s),
        }
    }
}

// ---------------------------------------------------------------------------
// Messages. Each builder is pure so tests can check what a channel is sent.

/// Discord: markdown content, with link buttons. Mentions are switched off
/// and the SQL sits in a code block it cannot close.
pub fn discord(n: &Notice<'_>) -> Value {
    // Content is capped at 2000 characters, and escaping lengthens the SQL,
    // so shorten the SQL until the whole message fits.
    let mut max_sql = 1200;
    let content = loop {
        let (sql, shortened) = shown_sql(n.sql, max_sql);
        let content = format!(
            "**{TITLE}**: {}\nAgent {}{}\n{}\nRule: {}. Expires in {} s. {CONFIRM}",
            md_text(n.reason),
            md_text(n.agent),
            wants_to_run(shortened),
            md_code_block(&sql),
            md_text(n.rule),
            n.expires_in_seconds
        );
        if content.chars().count() <= 2000 || max_sql < 100 {
            // The ellipsis `truncate` adds is the 2000th character.
            break truncate(&content, 1999);
        }
        max_sql /= 2;
    };
    let button =
        |label: &str, url: &str| json!({ "type": 2, "style": 5, "label": label, "url": url });
    json!({
        "content": content,
        "allowed_mentions": { "parse": [] },
        "components": [{ "type": 1, "components": [
            button("Approve", &n.approve_url),
            button("Deny", &n.deny_url),
            button("Open in the dashboard", &n.dashboard_url),
        ]}],
    })
}

/// Telegram: HTML parse mode, with an inline keyboard of URL buttons.
pub fn telegram(n: &Notice<'_>, chat_id: Value) -> Value {
    let (sql, shortened) = shown_sql(n.sql, 3000);
    let text = format!(
        "<b>{TITLE}</b>: {}\nAgent <b>{}</b>{}\n<pre><code class=\"language-sql\">{}</code></pre>\nRule: {}. Expires in {} s. {CONFIRM}",
        html_escape(n.reason),
        html_escape(n.agent),
        wants_to_run(shortened),
        html_escape(&sql),
        html_escape(n.rule),
        n.expires_in_seconds
    );
    json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "link_preview_options": { "is_disabled": true },
        "reply_markup": { "inline_keyboard": [
            [
                { "text": "Approve", "url": n.approve_url, "style": "success" },
                { "text": "Deny", "url": n.deny_url, "style": "danger" },
            ],
            [{ "text": "Open in the dashboard", "url": n.dashboard_url }],
        ]},
    })
}

/// Teams: an Adaptive Card, as a Workflows (or older incoming) webhook
/// takes it. Everything that is not ariodb's own wording goes in TextRuns,
/// which Teams never reads as markdown.
pub fn teams(n: &Notice<'_>) -> Value {
    let run = |text: &str| json!({ "type": "TextRun", "text": text });
    let rich = |inlines: Vec<Value>| json!({ "type": "RichTextBlock", "inlines": inlines });
    let open = |title: &str, url: &str, style: Option<&str>| {
        let mut action = json!({ "type": "Action.OpenUrl", "title": title, "url": url });
        if let Some(style) = style {
            action["style"] = json!(style);
        }
        action
    };
    let (sql, shortened) = shown_sql(n.sql, 2500);
    let card = json!({
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": { "width": "Full" },
        "body": [
            { "type": "TextBlock", "text": TITLE, "weight": "Bolder", "size": "Medium", "wrap": true },
            rich(vec![run(n.reason)]),
            rich(vec![
                run("Agent "),
                json!({ "type": "TextRun", "text": n.agent, "weight": "Bolder" }),
                run(&wants_to_run(shortened)),
            ]),
            rich(vec![json!({ "type": "TextRun", "text": sql, "fontType": "Monospace" })]),
            rich(vec![run(&format!(
                "Rule: {}. Expires in {} s. {CONFIRM}",
                n.rule, n.expires_in_seconds
            ))]),
        ],
        "actions": [
            open("Approve", &n.approve_url, Some("positive")),
            open("Deny", &n.deny_url, Some("destructive")),
            open("Open in the dashboard", &n.dashboard_url, None),
        ],
    });
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": card,
        }],
    })
}

/// Google Chat: a card whose paragraphs are HTML (escaped here), with
/// buttons that open links.
pub fn google_chat(n: &Notice<'_>) -> Value {
    let paragraph = |text: String| json!({ "textParagraph": { "text": text } });
    let button =
        |text: &str, url: &str| json!({ "text": text, "onClick": { "openLink": { "url": url } } });
    let (sql, shortened) = shown_sql(n.sql, 2500);
    json!({
        "text": TITLE,
        "cardsV2": [{
            "cardId": n.id,
            "card": {
                "header": { "title": TITLE },
                "sections": [{ "widgets": [
                    paragraph(html_escape(n.reason)),
                    paragraph(format!("Agent <b>{}</b>{}", html_escape(n.agent), wants_to_run(shortened))),
                    paragraph(format!("<pre><code>{}</code></pre>", html_escape(&sql))),
                    paragraph(format!(
                        "Rule: {}. Expires in {} s. {CONFIRM}",
                        html_escape(n.rule),
                        n.expires_in_seconds
                    )),
                    { "buttonList": { "buttons": [
                        button("Approve", &n.approve_url),
                        button("Deny", &n.deny_url),
                        button("Open in the dashboard", &n.dashboard_url),
                    ]}},
                ]}],
            },
        }],
    })
}

/// Mattermost: markdown, with the links written by ariodb after the SQL's
/// code block. Message attachments' buttons call back to a server, so plain
/// links are what works without a public endpoint.
pub fn mattermost(n: &Notice<'_>, channel: Option<&str>) -> Value {
    let (sql, shortened) = shown_sql(n.sql, 2500);
    let text = format!(
        "#### {TITLE}\n{}\nAgent {}{}\n{}\nRule: {}. Expires in {} s.\n\n[Approve]({}) · [Deny]({}) · [Open in the dashboard]({})\n{CONFIRM}",
        md_text(n.reason),
        md_text(n.agent),
        wants_to_run(shortened),
        md_code_block(&sql),
        md_text(n.rule),
        n.expires_in_seconds,
        n.approve_url,
        n.deny_url,
        n.dashboard_url
    );
    let mut body = json!({ "text": text });
    if let Some(channel) = channel {
        body["channel"] = json!(channel);
    }
    body
}

/// PagerDuty: an Events API v2 trigger. The approval id is the dedup key,
/// so the incident can be resolved once the request is decided. The SQL
/// goes in the details, never the summary.
pub fn pagerduty_trigger(n: &Notice<'_>, routing_key: &str) -> Value {
    let (sql, shortened) = shown_sql(n.sql, 4000);
    let mut event = json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": n.id,
        "payload": {
            "summary": truncate(&format!("{TITLE}: {} (agent {}, rule {})", one_line(n.reason), one_line(n.agent), one_line(n.rule)), 1000),
            "source": "ariodb",
            "severity": "warning",
            "component": "ariodb",
            "class": "approval",
            "custom_details": {
                "agent": n.agent,
                "rule": n.rule,
                "reason": n.reason,
                "sql": sql,
                "expires_in_seconds": n.expires_in_seconds,
                "how_to_decide": CONFIRM,
            },
        },
        "links": [
            { "href": n.approve_url, "text": "Approve" },
            { "href": n.deny_url, "text": "Deny" },
            { "href": n.dashboard_url, "text": "Open in the dashboard" },
        ],
        "client": "ariodb",
        "client_url": n.dashboard_url,
    });
    if shortened {
        event["payload"]["custom_details"]["note"] =
            json!(format!("The statement is {SHORTENED}."));
    }
    event
}

/// Opsgenie: an alert whose alias is the approval id, so it can be closed
/// once the request is decided. The links come first in the description and
/// the SQL after them, quoted line by line, so it cannot pass for them.
pub fn opsgenie_alert(n: &Notice<'_>) -> Value {
    json!({
        "message": truncate(&format!("{TITLE}: {}", one_line(n.reason)), 125),
        "alias": n.id,
        "description": plain_text(n, 10_000),
        "details": {
            "agent": truncate(n.agent, 200),
            "rule": truncate(n.rule, 200),
            "approve_url": n.approve_url,
            "deny_url": n.deny_url,
            "dashboard_url": n.dashboard_url,
        },
        "source": "ariodb",
        "tags": ["ariodb", "approval"],
        "priority": "P3",
    })
}

/// Email: the subject, a plain-text part and an HTML part.
pub fn email(n: &Notice<'_>) -> (String, String, String) {
    let subject = truncate(&format!("{TITLE}: {}", one_line(n.reason)), 150);
    let link = |label: &str, url: &str, colour: &str| {
        format!(
            "<a href=\"{}\" style=\"display:inline-block;padding:8px 16px;margin-right:8px;border-radius:4px;color:#fff;background:{colour};text-decoration:none\">{label}</a>",
            html_escape(url)
        )
    };
    let (sql, shortened) = shown_sql(n.sql, 20_000);
    let html = format!(
        "<!doctype html><html><body style=\"font-family:sans-serif\">\
         <h3>{TITLE}</h3><p>{}</p><p>Agent <b>{}</b>{}</p>\
         <pre style=\"background:#f4f4f4;padding:8px;white-space:pre-wrap\">{}</pre>\
         <p>Rule: {}. The request expires in {} seconds.</p>\
         <p>{}{}<a href=\"{}\">Open in the dashboard</a></p><p>{CONFIRM}</p></body></html>",
        html_escape(n.reason),
        html_escape(n.agent),
        wants_to_run(shortened),
        html_escape(&sql),
        html_escape(n.rule),
        n.expires_in_seconds,
        link("Approve", &n.approve_url, "#15803d"),
        link("Deny", &n.deny_url, "#b91c1c"),
        html_escape(&n.dashboard_url),
    );
    (subject, plain_text(n, 20_000), html)
}

/// The request as plain text: ariodb's own lines and links first, then the
/// SQL with every line marked, so the SQL cannot add lines that look like
/// ariodb's ("Approve: https://...").
fn plain_text(n: &Notice<'_>, max_sql: usize) -> String {
    // Every character a reader might show as a line break starts a new,
    // marked line.
    let breaks = [
        '\n', '\r', '\u{b}', '\u{c}', '\u{85}', '\u{2028}', '\u{2029}',
    ];
    let (sql, shortened) = shown_sql(n.sql, max_sql);
    let quoted = sql
        .replace("\r\n", "\n")
        .split(breaks)
        .map(|l| format!("| {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{TITLE}: {}\n\nAgent {} wants to run the statement below (rule {}).{}\n\nApprove: {}\nDeny: {}\nDashboard: {}\n\n{CONFIRM} The request expires in {} seconds.\n\nStatement:\n{quoted}\n",
        one_line(n.reason),
        one_line(n.agent),
        one_line(n.rule),
        if shortened {
            format!(" The statement is {SHORTENED}.")
        } else {
            String::new()
        },
        n.approve_url,
        n.deny_url,
        n.dashboard_url,
        n.expires_in_seconds
    )
}

// ---------------------------------------------------------------------------
// Escaping.

/// Text outside a code block in Discord and Mattermost markdown: markdown
/// punctuation is backslash-escaped, and `@` and `<` are followed by a
/// zero-width space so they cannot form a mention (`@here`, `<@id>`,
/// `<!channel>`) or an autolink.
fn md_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '~' | '|' | '[' | ']' | '(' | ')' | '#' | '>' => {
                out.push('\\');
                out.push(c);
            }
            '@' | '<' => {
                out.push(c);
                out.push('\u{200b}');
            }
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// A fenced code block the text cannot close: every backtick is followed by
/// a zero-width space, so no run of three appears. Mentions are broken up
/// too, for clients that look for them inside code.
fn md_code_block(s: &str) -> String {
    let body = s
        .replace('`', "`\u{200b}")
        .replace('@', "@\u{200b}")
        .replace('<', "<\u{200b}");
    format!("```sql\n{body}\n```")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The statement as a message shows it, and whether it had to be shortened.
/// Characters that reorder or hide text (bidirectional controls and
/// zero-width characters) are written out as `<U+202E>` and the like, so
/// the approver reads the statement that would run.
fn shown_sql(sql: &str, max: usize) -> (String, bool) {
    let mut shown = String::with_capacity(sql.len());
    for c in sql.chars() {
        if matches!(
            c,
            '\u{ad}'
                | '\u{61c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        ) {
            shown.push_str(&format!("<U+{:04X}>", c as u32));
        } else {
            shown.push(c);
        }
    }
    let shortened = shown.chars().count() > max;
    (truncate(&shown, max), shortened)
}

/// How a message introduces the statement.
fn wants_to_run(shortened: bool) -> String {
    if shortened {
        format!(" wants to run this statement, {SHORTENED}:")
    } else {
        " wants to run:".to_string()
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// ---------------------------------------------------------------------------
// Sending.

/// The API's address, or the environment variable tests use to replace it.
fn api(var: &str, default: &str) -> String {
    std::env::var(var)
        .unwrap_or_else(|_| default.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn pagerduty_api(a: &ApproverConfig) -> String {
    let default = if a.region.as_deref() == Some("eu") {
        "https://events.eu.pagerduty.com"
    } else {
        "https://events.pagerduty.com"
    };
    api("ARIODB_PAGERDUTY_API", default)
}

fn opsgenie_api(a: &ApproverConfig) -> String {
    let default = if a.region.as_deref() == Some("eu") {
        "https://api.eu.opsgenie.com"
    } else {
        "https://api.opsgenie.com"
    };
    api("ARIODB_OPSGENIE_API", default)
}

/// The incoming webhook's URL. It is a credential (it holds the token), so
/// it never appears in an error message.
fn webhook_url(config: &crate::config::Config, a: &ApproverConfig) -> Result<reqwest::Url, String> {
    let raw = secret_value(config, &a.url_secret, &a.url_env)?;
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|_| format!("the {} webhook URL is not a valid URL", a.kind.name()))?;
    let local = url.host_str().is_some_and(is_local);
    match url.scheme() {
        "https" => Ok(url),
        "http" if local => Ok(url),
        _ => Err(format!(
            "the {} webhook URL must use https (plain http is allowed only for this machine)",
            a.kind.name()
        )),
    }
}

/// This machine: localhost or a loopback address.
pub fn is_local(host: &str) -> bool {
    let ip = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn http() -> reqwest::Client {
    crate::tls::init();
    // No redirects: a redirect would carry the body, credentials included,
    // somewhere the operator did not name.
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client")
}

/// POST JSON and expect a 2xx answer. Errors leave out the URL, which for
/// several channels holds the credential.
async fn post(url: &str, authorization: Option<String>, body: &Value) -> Result<(), String> {
    let mut request = http().post(url).json(body);
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let text = resp.text().await.unwrap_or_default();
    Err(match error_message(&text) {
        Some(m) => format!("answered {status}: {m}"),
        None => format!("answered {status}"),
    })
}

/// The error in a JSON answer, in the field each service uses for it.
fn error_message(text: &str) -> Option<String> {
    let v: Value = serde_json::from_str(text).ok()?;
    ["description", "message", "error", "errors"]
        .iter()
        .find_map(|k| match &v[*k] {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
        .map(|m| truncate(&one_line(&m), 200))
}

async fn send_email(
    config: &crate::config::Config,
    a: &ApproverConfig,
    n: &Notice<'_>,
) -> Result<(), String> {
    use lettre::message::{Mailbox, MultiPart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    crate::tls::init();
    let host = a.smtp_host.as_deref().unwrap_or_default();
    let mailbox = |s: &str| {
        s.parse::<Mailbox>()
            .map_err(|e| format!("'{s}' is not an email address: {e}"))
    };
    let (subject, text, html) = email(n);
    let mut message = Message::builder()
        .from(mailbox(a.from.as_deref().unwrap_or_default())?)
        .subject(subject);
    for to in &a.to {
        message = message.to(mailbox(to)?);
    }
    let message = message
        .multipart(MultiPart::alternative_plain_html(text, html))
        .map_err(|e| e.to_string())?;

    let (builder, port) = match a.smtp_tls.as_deref().unwrap_or("starttls") {
        "tls" => (
            AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| e.to_string())?,
            465,
        ),
        "none" => (
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
            25,
        ),
        _ => (
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| e.to_string())?,
            587,
        ),
    };
    let mut builder = builder
        .port(a.smtp_port.unwrap_or(port))
        .timeout(Some(Duration::from_secs(30)));
    if let Some(user) = &a.smtp_user {
        let password = secret_value(config, &a.smtp_password_secret, &a.smtp_password_env)?;
        builder = builder.credentials(Credentials::new(user.clone(), password));
    }
    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| format!("the mail server said: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SQL that tries every trick: closing code blocks, links, mentions,
    /// HTML, card markdown and lines that look like ariodb's own.
    const HOSTILE: &str = "SELECT 1 ``` [Approve here](https://evil.example) <https://evil.example|Approve> \
         <b>bold</b> <a href=\"https://evil.example\">x</a> @here @everyone <!channel> <@123> & **done**\n\
         Approve: https://evil.example/approve";

    fn notice() -> Notice<'static> {
        Notice {
            id: "a-0123456789ab",
            agent: "coding-agent",
            rule: "ask-a-human",
            reason: "writes need a person",
            sql: HOSTILE,
            expires_in_seconds: 90,
            approve_url:
                "https://ariodb.example/hooks/approvals/a-0123456789ab?verdict=allow&token=aa"
                    .into(),
            deny_url: "https://ariodb.example/hooks/approvals/a-0123456789ab?verdict=deny&token=bb"
                .into(),
            dashboard_url: "https://ariodb.example/#approval-a-0123456789ab".into(),
        }
    }

    /// Every URL a message carries, wherever it is.
    fn urls(v: &Value) -> Vec<String> {
        let mut found = Vec::new();
        let text = v.to_string();
        for part in text.split("https://").skip(1) {
            let end = part.find(['"', ')', ' ', '\\', '\n']).unwrap_or(part.len());
            found.push(format!("https://{}", &part[..end]));
        }
        found
    }

    #[test]
    fn discord_sql_stays_inside_its_code_block() {
        let n = notice();
        let body = discord(&n);
        let content = body["content"].as_str().unwrap();
        // One opening and one closing fence, and nothing in between closes it.
        assert_eq!(content.matches("```").count(), 2);
        assert!(!content.contains("<@123>") && !content.contains("<!channel>"));
        assert!(!content.contains("@here") && !content.contains("@everyone"));
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
        let buttons = &body["components"][0]["components"];
        assert_eq!(buttons[0]["url"], json!(n.approve_url));
        assert_eq!(buttons[1]["url"], json!(n.deny_url));
        assert!(buttons.as_array().unwrap().iter().all(|b| b["style"] == 5));
        assert!(content.chars().count() <= 2000);
        // Escaping doubles every backtick; the message still fits.
        let ticks = "`".repeat(5000);
        let long = Notice {
            sql: &ticks,
            ..notice()
        };
        let content = discord(&long)["content"].as_str().unwrap().to_string();
        assert!(content.chars().count() <= 2000);
        assert!(content.ends_with(CONFIRM));
    }

    #[test]
    fn telegram_escapes_html_and_sends_url_buttons() {
        let n = notice();
        let body = telegram(&n, json!(-100123));
        let text = body["text"].as_str().unwrap();
        assert!(!text.contains("<b>bold</b>") && !text.contains("<a href"));
        assert!(
            text.contains(
                "&lt;b&gt;bold&lt;/b&gt; &lt;a href=&quot;https://evil.example&quot;&gt;"
            )
        );
        assert!(text.contains("&amp; **done**"));
        let keyboard = &body["reply_markup"]["inline_keyboard"];
        assert_eq!(keyboard[0][0]["url"], json!(n.approve_url));
        assert_eq!(keyboard[0][1]["url"], json!(n.deny_url));
        assert_eq!(body["chat_id"], json!(-100123));
        assert_eq!(body["parse_mode"], "HTML");
    }

    #[test]
    fn teams_never_reads_the_sql_as_markdown() {
        let n = notice();
        let body = teams(&n);
        let card = &body["attachments"][0]["content"];
        // TextBlocks read markdown; the only one holds ariodb's own title.
        for block in card["body"].as_array().unwrap() {
            if block["type"] == "TextBlock" {
                assert_eq!(block["text"], TITLE);
            }
        }
        assert!(
            card["body"]
                .to_string()
                .contains("[Approve here](https://evil.example)")
        );
        let actions = card["actions"].as_array().unwrap();
        assert_eq!(actions[0]["url"], json!(n.approve_url));
        assert_eq!(actions[1]["url"], json!(n.deny_url));
        assert!(actions.iter().all(|a| a["type"] == "Action.OpenUrl"));
    }

    #[test]
    fn google_chat_escapes_html_and_links_with_buttons() {
        let n = notice();
        let body = google_chat(&n);
        let widgets = &body["cardsV2"][0]["card"]["sections"][0]["widgets"];
        let text = widgets.to_string();
        assert!(!text.contains("<b>bold") && !text.contains("<a href"));
        assert!(text.contains("&lt;a href=&quot;https://evil.example&quot;&gt;"));
        let buttons = &widgets[4]["buttonList"]["buttons"];
        assert_eq!(
            buttons[0]["onClick"]["openLink"]["url"],
            json!(n.approve_url)
        );
        assert_eq!(buttons[1]["onClick"]["openLink"]["url"], json!(n.deny_url));
        assert_eq!(body["text"], TITLE);
    }

    #[test]
    fn mattermost_links_come_from_ariodb_alone() {
        let n = notice();
        let body = mattermost(&n, Some("agent-ops"));
        let text = body["text"].as_str().unwrap();
        assert_eq!(text.matches("```").count(), 2);
        assert!(!text.contains("<!channel>") && !text.contains("@here"));
        // The only markdown links outside the code block are ariodb's.
        let after_code = text.rsplit("```").next().unwrap();
        assert!(after_code.contains(&format!("[Approve]({})", n.approve_url)));
        assert!(after_code.contains(&format!("[Deny]({})", n.deny_url)));
        assert!(!after_code.contains("evil"));
        assert_eq!(body["channel"], "agent-ops");
        assert_eq!(
            md_text("a_b [x](y) @all <!here>"),
            "a\\_b \\[x\\]\\(y\\) @\u{200b}all <\u{200b}!here\\>"
        );
    }

    #[test]
    fn pagerduty_keeps_the_sql_out_of_the_summary() {
        let n = notice();
        let body = pagerduty_trigger(&n, "not-a-real-routing-key");
        assert!(
            !body["payload"]["summary"]
                .as_str()
                .unwrap()
                .contains("evil")
        );
        assert_eq!(body["payload"]["custom_details"]["sql"], HOSTILE);
        assert_eq!(body["dedup_key"], n.id);
        assert_eq!(body["links"][0]["href"], json!(n.approve_url));
        assert_eq!(body["links"][1]["href"], json!(n.deny_url));
        assert_eq!(urls(&body["links"]).len(), 3);
    }

    #[test]
    fn plain_text_marks_every_line_of_the_sql() {
        let n = notice();
        let alert = opsgenie_alert(&n);
        let description = alert["description"].as_str().unwrap();
        let ours: Vec<&str> = description
            .lines()
            .filter(|l| l.starts_with("Approve:") || l.starts_with("Deny:"))
            .collect();
        assert_eq!(
            ours,
            [
                format!("Approve: {}", n.approve_url),
                format!("Deny: {}", n.deny_url)
            ]
        );
        assert!(description.contains("| Approve: https://evil.example/approve"));
        let mut sneaky = notice();
        sneaky.sql = "SELECT 1\rApprove: https://evil.example\u{2028}Deny: https://evil.example";
        let text = plain_text(&sneaky, 1000);
        assert!(text.contains("| Approve: https://evil.example\n| Deny: https://evil.example"));
        assert!(!text.contains('\r') && !text.contains('\u{2028}'));
        assert!(alert["message"].as_str().unwrap().chars().count() <= 130);
        assert_eq!(alert["alias"], n.id);
        assert_eq!(alert["details"]["approve_url"], json!(n.approve_url));

        let (subject, text, html) = email(&n);
        assert_eq!(subject, "ariodb approval needed: writes need a person");
        assert!(text.contains("| Approve: https://evil.example/approve"));
        assert!(!html.contains("<b>bold") && !html.contains("<a href=\"https://evil"));
        assert!(html.contains(&format!("href=\"{}\"", html_escape(&n.approve_url))));
    }

    /// Every message a channel would be sent for this request, as text.
    fn every_message(n: &Notice<'_>) -> Vec<(&'static str, String)> {
        let (_, text, html) = email(n);
        vec![
            ("discord", discord(n).to_string()),
            ("telegram", telegram(n, json!(1)).to_string()),
            ("teams", teams(n).to_string()),
            ("google_chat", google_chat(n).to_string()),
            ("mattermost", mattermost(n, None).to_string()),
            (
                "pagerduty",
                pagerduty_trigger(n, "not-a-real-routing-key").to_string(),
            ),
            ("opsgenie", opsgenie_alert(n).to_string()),
            ("email text", text),
            ("email html", html),
        ]
    }

    #[test]
    fn characters_that_reorder_or_hide_text_are_shown() {
        // Bidirectional overrides can make the statement read differently
        // from what runs ("Trojan Source"); zero-width characters hide.
        let sql =
            "UPDATE t SET a = 1 /* \u{202E} } \u{2066}x\u{2069} */ WHERE id = 1\u{200B}\u{FEFF}";
        let n = Notice { sql, ..notice() };
        for (channel, message) in every_message(&n) {
            for hidden in ['\u{202E}', '\u{2066}', '\u{2069}', '\u{FEFF}'] {
                assert!(!message.contains(hidden), "{channel} carries {hidden:?}");
            }
            assert!(message.contains("U+202E"), "{channel} hides the override");
            assert!(
                message.contains("U+200B"),
                "{channel} hides a zero-width space"
            );
        }
    }

    #[test]
    fn a_shortened_statement_says_so_before_it() {
        // Padding can push the end of a statement past what a message shows;
        // the approver is told before the statement, not only by an ellipsis.
        let sql = format!(
            "UPDATE t SET a = 1 WHERE id = 1{}; DELETE FROM t",
            " ".repeat(30_000)
        );
        let n = Notice {
            sql: &sql,
            ..notice()
        };
        for (channel, message) in every_message(&n) {
            let told = message
                .find(SHORTENED)
                .unwrap_or_else(|| panic!("{channel} does not say"));
            let statement = message.find("UPDATE t").expect("statement");
            assert!(
                told < statement,
                "{channel} says so only after the statement"
            );
            assert!(!message.contains("DELETE"), "{channel} was not shortened");
        }
        for (channel, message) in every_message(&notice()) {
            assert!(
                !message.contains(SHORTENED),
                "{channel} says a short statement was shortened"
            );
        }
    }

    #[test]
    fn channel_settings_are_checked_at_load() {
        let check = |toml_text: &str| {
            let a: ApproverConfig = toml::from_str(toml_text).expect("approver");
            validate(&a)
        };
        assert!(check("name = \"d\"\ntype = \"discord\"\nurl_env = \"X\"").is_ok());
        assert!(
            check("name = \"d\"\ntype = \"discord\"")
                .unwrap_err()
                .contains("url_secret or url_env")
        );
        assert!(
            check(
                "name = \"d\"\ntype = \"teams\"\nurl = \"https://example.test/x\"\nurl_env = \"X\""
            )
            .unwrap_err()
            .contains("the URL itself is the credential")
        );
        assert!(
            check("name = \"t\"\ntype = \"telegram\"\nbot_token_env = \"X\"")
                .unwrap_err()
                .contains("chat_id")
        );
        assert!(
            check("name = \"t\"\ntype = \"telegram\"\nbot_token_env = \"X\"\nchat_id = -100123")
                .is_ok()
        );
        assert!(
            check("name = \"t\"\ntype = \"telegram\"\nbot_token_env = \"X\"\nchat_id = \"@ops\"")
                .is_ok()
        );
        assert!(
            check("name = \"p\"\ntype = \"pagerduty\"")
                .unwrap_err()
                .contains("routing_key")
        );
        assert!(
            check("name = \"o\"\ntype = \"opsgenie\"\napi_key_env = \"X\"\nregion = \"mars\"")
                .unwrap_err()
                .contains("region")
        );
        let mail = "name = \"m\"\ntype = \"email\"\nfrom = \"ariodb <ariodb@example.test>\"\nto = [\"ops@example.test\"]\n";
        assert!(check(&format!("{mail}smtp_host = \"smtp.example.test\"")).is_ok());
        assert!(
            check(&format!(
                "{mail}smtp_host = \"smtp.example.test\"\nsmtp_tls = \"none\""
            ))
            .unwrap_err()
            .contains("this machine")
        );
        assert!(
            check(&format!(
                "{mail}smtp_host = \"127.0.0.1\"\nsmtp_tls = \"none\""
            ))
            .is_ok()
        );
        assert!(
            check(&format!(
                "{mail}smtp_host = \"smtp.example.test\"\nsmtp_user = \"u\""
            ))
            .unwrap_err()
            .contains("smtp_password")
        );
        assert!(check("name = \"m\"\ntype = \"email\"\nsmtp_host = \"h\"\nfrom = \"not an address\"\nto = [\"ops@example.test\"]")
            .unwrap_err()
            .contains("not an email address"));
    }

    #[test]
    fn errors_name_no_url() {
        assert_eq!(
            error_message(r#"{"ok":false,"description":"Bad Request: chat not found"}"#).as_deref(),
            Some("Bad Request: chat not found")
        );
        assert_eq!(
            error_message(r#"{"message":"Invalid Webhook Token","code":50027}"#).as_deref(),
            Some("Invalid Webhook Token")
        );
        assert_eq!(error_message("not json"), None);
    }
}
