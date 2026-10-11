//! The built-in Splunk exporter: the decisions log, and approval and undo
//! events, sent to Splunk's HTTP Event Collector (HEC). See docs/splunk.md.
//!
//! Decisions travel as they do to audit-sink plugins: read from the log in
//! order, from a cursor kept in ariodb.db that moves only once Splunk has
//! accepted the batch (with `ack`, once Splunk says it is indexed). An
//! outage or a restart of either side therefore loses and reorders nothing.
//! An entry can arrive twice when Splunk took a batch but its answer was
//! lost; `id` tells repeats apart. Nothing waits in memory: a long outage
//! costs only the backlog in the log.
//!
//! Approval and undo events are best effort, like notifier events: queued
//! in memory, held while the collector is down, and dropped (counted) when
//! the queue is full.

use crate::audit::{Chained, SinkCursor};
use crate::config::Config;
use serde::Deserialize;
use serde::Serialize;
use serde::de::IgnoredAny;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

pub const DECISION_SOURCETYPE: &str = "ariodb:decision";
pub const EVENT_SOURCETYPE: &str = "ariodb:event";
/// The exporter's cursor in the decisions log. Plugin names cannot contain
/// a colon, so no plugin can share it.
const CURSOR: &str = "builtin:splunk";
/// Statements (and reasons) per batch, on top of `batch_size`. Small enough
/// for collectors still on the old 1 MB `max_content_length`.
const MAX_BATCH_BYTES: usize = 512 * 1024;
/// Events waiting to be sent. Past this, new events are dropped.
const EVENT_QUEUE: usize = 1_000;
const EVENT_BATCH: usize = 100;
/// Retries after a network error, 429 or 5xx: 1 s doubling to a minute,
/// each with jitter so a fleet of ariodbs does not return all at once.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Retries after an answer that will not change until someone fixes the
/// configuration (a bad token, an unknown index).
const REFUSED_RETRY: Duration = Duration::from_secs(60);
/// While disabled, how often to look for the section being turned on.
const DISABLED_POLL: Duration = Duration::from_secs(1);
/// With `ack`, how often to ask whether a batch is indexed: from 250 ms,
/// doubling to 5 s.
const FIRST_ACK_POLL: Duration = Duration::from_millis(250);
const MAX_ACK_POLL: Duration = Duration::from_secs(5);

/// `[audit.splunk]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    /// The collector's base address, such as https://splunk.example.com:8088.
    pub url: String,
    /// The HEC token, from an environment variable or the secret store.
    /// Never from the file.
    pub token_env: Option<String>,
    pub token_secret: Option<String>,
    /// Default: the token's default index.
    pub index: Option<String>,
    pub source: String,
    /// Default: this machine's host name.
    pub host: Option<String>,
    /// An extra trusted CA certificate (PEM), on top of the system's roots.
    pub ca_file: Option<String>,
    /// Skip certificate checks. For test setups only.
    pub accept_invalid_certificate: bool,
    /// Use indexer acknowledgement: a batch counts as delivered only once
    /// Splunk says it is indexed. The token must have it turned on.
    pub ack: bool,
    /// With `ack`, send a batch again if Splunk has not confirmed it by then.
    pub ack_timeout_ms: u64,
    /// Send approval and undo events too.
    pub events: bool,
    pub batch_size: usize,
    /// How often to look for new decisions once everything is sent.
    pub flush_interval_ms: u64,
    /// The limit on each request to the collector.
    pub timeout_ms: u64,
    /// Never used: a token written in the file is refused when it loads.
    token: Option<IgnoredAny>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: false,
            url: String::new(),
            token_env: None,
            token_secret: None,
            index: None,
            source: "ariodb".to_string(),
            host: None,
            ca_file: None,
            accept_invalid_certificate: false,
            ack: false,
            ack_timeout_ms: 300_000,
            events: true,
            batch_size: 100,
            flush_interval_ms: 1_000,
            timeout_ms: 10_000,
            token: None,
        }
    }
}

/// Checks TOML alone cannot express.
pub fn validate(s: &Settings) -> Result<(), String> {
    if s.token.is_some() {
        return Err("[audit.splunk] token must not be written in the config file: store it with `ariodb secret set <name>` and set token_secret, or set token_env".to_string());
    }
    if !s.enabled {
        return Ok(());
    }
    base_url(&s.url)?;
    if s.token_env.is_some() == s.token_secret.is_some() {
        return Err("[audit.splunk] needs exactly one of token_env or token_secret".to_string());
    }
    for (key, value) in [
        ("batch_size", s.batch_size as u64),
        ("flush_interval_ms", s.flush_interval_ms),
        ("timeout_ms", s.timeout_ms),
        ("ack_timeout_ms", s.ack_timeout_ms),
    ] {
        if value == 0 {
            return Err(format!("[audit.splunk] {key} must be at least 1"));
        }
    }
    for (key, value) in [
        ("index", s.index.as_deref()),
        ("host", s.host.as_deref()),
        ("source", Some(s.source.as_str())),
    ] {
        if value.is_some_and(|v| v.trim().is_empty()) {
            return Err(format!("[audit.splunk] {key} must not be empty"));
        }
    }
    Ok(())
}

/// The collector's base address, without a trailing slash.
fn base_url(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| format!("[audit.splunk] url '{url}' is not a URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(format!(
            "[audit.splunk] url must be an http:// or https:// address, such as https://splunk.example.com:8088, not '{url}'"
        ));
    }
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() {
        return Err(format!(
            "[audit.splunk] url is the collector's base address, such as https://splunk.example.com:8088, without /services/collector or a query: '{url}'"
        ));
    }
    Ok(url.trim_end_matches('/').to_string())
}

// ---------------------------------------------------------------------------
// What is sent.

/// The metadata every event carries.
struct Meta {
    source: String,
    host: Option<String>,
    index: Option<String>,
}

impl Meta {
    fn new(s: &Settings) -> Meta {
        Meta {
            source: s.source.clone(),
            host: s.host.clone().or_else(this_host),
            index: s.index.clone(),
        }
    }

    /// One event in HEC's JSON event protocol.
    fn envelope(&self, at_ms: i64, sourcetype: &str, event: Value) -> Value {
        let mut v = json!({
            "time": seconds(at_ms),
            "source": self.source,
            "sourcetype": sourcetype,
            "event": event,
        });
        if let Some(host) = &self.host {
            v["host"] = json!(host);
        }
        if let Some(index) = &self.index {
            v["index"] = json!(index);
        }
        v
    }
}

/// Epoch seconds with milliseconds, as HEC reads `time`.
fn seconds(at_ms: i64) -> Value {
    serde_json::Number::from_f64(at_ms as f64 / 1000.0)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// A decision as Splunk gets it. The fields are in the event itself, which
/// Splunk extracts at search time; ariodb sends no indexed `fields`, since a
/// field both indexed and in the JSON shows each value twice.
fn decision_event(meta: &Meta, entry: &Chained) -> Value {
    let d = &entry.decision;
    meta.envelope(
        d.at_ms,
        DECISION_SOURCETYPE,
        json!({
            "id": d.id,
            "agent": d.agent,
            "engine": d.engine,
            "database": d.database,
            "session": d.session,
            "outcome": d.outcome,
            "rule": d.rule,
            "deciders": d.decided_by,
            "kind": d.kind,
            "tables": d.tables,
            "rows": d.rows,
            "latency_ms": d.latency_ms,
            "reason": d.reason,
            "sql": d.sql,
            "prev": entry.prev,
            "hash": entry.hash,
        }),
    )
}

/// The notifier events Splunk gets. Refusals and rollbacks are decisions
/// already, so they are not sent twice.
fn wanted(event: &str) -> bool {
    matches!(
        event,
        "approval_requested" | "approval_decided" | "undo_applied"
    )
}

/// An event as Splunk gets it: its name, then its details.
fn event_event(meta: &Meta, queued: &Queued) -> Value {
    let mut event = json!({ "event": queued.name });
    if let Some(details) = queued.details.as_object() {
        for (k, v) in details {
            if k != "event" {
                event[k] = v.clone();
            }
        }
    }
    meta.envelope(queued.at_ms, EVENT_SOURCETYPE, event)
}

/// Several events in one request: JSON objects one after another.
fn batch_body(events: impl Iterator<Item = Value>) -> String {
    events.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
}

#[cfg(unix)]
fn this_host() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at
    // most that many bytes.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(not(unix))]
fn this_host() -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// What the collector says.

/// What became of one request.
#[derive(Debug, PartialEq)]
enum Answer {
    /// Accepted; with indexer acknowledgement, the id to ask about.
    Accepted(Option<u64>),
    /// Worth trying again soon: the collector is busy, down or failing.
    Retry(String),
    /// Will not succeed until someone changes something: tried again slowly.
    Refused(String),
    /// The request was too large; a smaller batch may go through.
    TooLarge,
}

/// HEC's answer body: `{"text": "...", "code": n}`, plus `ackID` when the
/// token uses indexer acknowledgement.
fn parse_body(body: &str) -> (Option<String>, Option<i64>, Option<u64>) {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return (None, None, None);
    };
    let text = v.get("text").and_then(Value::as_str).map(|t| clean(t, 200));
    let code = v.get("code").and_then(Value::as_i64);
    let ack = match v.get("ackID") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    (text, code, ack)
}

/// What an HEC status code means for ariodb, when it says more than the
/// HTTP status does.
fn hint(code: i64) -> Option<&'static str> {
    Some(match code {
        1 | 4 | 21 | 22 => {
            "the collector does not accept this token (unknown or disabled): check token_env or token_secret"
        }
        2 | 3 => "the token did not reach the collector in a form it reads",
        7 => "the token may not write to this index: check index, and the indexes the token allows",
        10 | 11 => "this token uses indexer acknowledgement: set ack = true",
        14 => "this token does not use indexer acknowledgement: set ack = false",
        5 | 6 | 12 | 13 | 15 => "the collector could not read what ariodb sent",
        _ => return None,
    })
}

fn describe(status: u16, body: &str) -> String {
    let (text, code, _) = parse_body(body);
    let mut out = format!("HTTP {status}");
    match (code, text) {
        (Some(code), Some(text)) => out.push_str(&format!(", code {code} ({text})")),
        (Some(code), None) => out.push_str(&format!(", code {code}")),
        (None, _) if !body.trim().is_empty() => {
            out.push_str(&format!(": {}", clean(body.trim(), 200)))
        }
        _ => {}
    }
    if let Some(h) = code.and_then(hint) {
        out.push_str(&format!(": {h}"));
    }
    out
}

/// Sort an answer to a POST of events, by its status and body.
fn read_answer(status: u16, body: &str) -> Answer {
    match status {
        200..=299 => Answer::Accepted(parse_body(body).2),
        413 => Answer::TooLarge,
        408 | 429 | 500..=599 => Answer::Retry(describe(status, body)),
        300..=399 => Answer::Refused(format!(
            "{}: the collector redirected, and ariodb does not follow redirects (they could carry the token elsewhere): set url to the final address",
            describe(status, body)
        )),
        404 | 405 => Answer::Refused(format!(
            "{}: nothing takes events at /services/collector/event here: check url (the collector's base address, port 8088 by default) and that HEC is on",
            describe(status, body)
        )),
        _ => Answer::Refused(describe(status, body)),
    }
}

/// Text from the collector, safe to log: no control characters.
fn clean(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// A request error with its causes, which reqwest keeps apart. Requests
/// carry the token only in a header, so none of this contains it.
fn network_error(e: &reqwest::Error) -> String {
    let mut out = if e.is_timeout() {
        "no answer in time".to_string()
    } else {
        "cannot reach the collector".to_string()
    };
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(&format!(": {s}"));
        source = s.source();
    }
    out
}

// ---------------------------------------------------------------------------
// Talking to the collector.

/// One configured collector. Holds the token, so it is never printed.
struct Collector {
    http: reqwest::Client,
    base: String,
    auth: String,
    /// With `ack`, this process's channel: a GUID of its own, as Splunk asks.
    channel: Option<String>,
    ack_timeout: Duration,
    /// The token turned out not to use acknowledgement, and the log said so.
    warned_no_ack: AtomicBool,
}

impl Collector {
    fn new(s: &Settings, state_dir: &Path) -> Result<Collector, String> {
        let token = token(s, state_dir)?;
        crate::tls::init();
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(s.timeout_ms))
            .danger_accept_invalid_certs(s.accept_invalid_certificate);
        if let Some(path) = &s.ca_file {
            let pem = std::fs::read(path).map_err(|e| format!("ca_file {path}: {e}"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| format!("ca_file {path}: {e}"))?;
            if certs.is_empty() {
                return Err(format!("ca_file {path}: no PEM certificate found"));
            }
            builder = builder.tls_certs_merge(certs);
        }
        Ok(Collector {
            http: builder
                .build()
                .map_err(|e| format!("cannot set up the HTTP client: {e}"))?,
            base: base_url(&s.url)?,
            auth: format!("Splunk {token}"),
            channel: s.ack.then(|| uuid::Uuid::new_v4().to_string()),
            ack_timeout: Duration::from_millis(s.ack_timeout_ms),
            warned_no_ack: AtomicBool::new(false),
        })
    }

    fn post(&self, path: &str, body: String) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(channel) = &self.channel {
            req = req.header("X-Splunk-Request-Channel", channel);
        }
        req
    }

    async fn send(&self, path: &str, body: String) -> Result<(u16, String), String> {
        let resp = self
            .post(path, body)
            .send()
            .await
            .map_err(|e| network_error(&e))?;
        let status = resp.status().as_u16();
        // A body is short; a huge one is not HEC's, and only its start matters.
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body.chars().take(4_000).collect()))
    }

    /// Send events, and with `ack`, wait until Splunk says they are indexed.
    async fn deliver(&self, body: String) -> Answer {
        let answer = match self.send("/services/collector/event", body).await {
            Ok((status, body)) => read_answer(status, &body),
            Err(e) => Answer::Retry(e),
        };
        match (answer, &self.channel) {
            (Answer::Accepted(Some(id)), Some(_)) => self.wait_for_ack(id).await,
            (Answer::Accepted(None), Some(_)) => {
                if !self.warned_no_ack.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "ariodb: Splunk exporter: ack = true, but the collector returned no ackID (the token does not use indexer acknowledgement); counting accepted batches as delivered"
                    );
                }
                Answer::Accepted(None)
            }
            (answer, _) => answer,
        }
    }

    /// Ask about one ackID until it is true, the time is up, or the
    /// collector fails. Splunk forgets an ackID once it has said true.
    async fn wait_for_ack(&self, id: u64) -> Answer {
        let deadline = Instant::now() + self.ack_timeout;
        let mut poll = FIRST_ACK_POLL;
        loop {
            tokio::time::sleep(poll.min(deadline.saturating_duration_since(Instant::now()))).await;
            let body = json!({ "acks": [id] }).to_string();
            let path = format!(
                "/services/collector/ack?channel={}",
                self.channel.as_deref().unwrap_or_default()
            );
            match self.send(&path, body).await {
                Ok((200, body)) => {
                    let done = serde_json::from_str::<Value>(&body)
                        .ok()
                        .and_then(|v| v["acks"][id.to_string()].as_bool());
                    if done == Some(true) {
                        return Answer::Accepted(Some(id));
                    }
                }
                Ok((status, body)) => {
                    return match read_answer(status, &body) {
                        Answer::Accepted(_) | Answer::TooLarge => {
                            Answer::Retry(format!("asking about ackID {id}: HTTP {status}"))
                        }
                        Answer::Retry(why) => {
                            Answer::Retry(format!("asking about ackID {id}: {why}"))
                        }
                        Answer::Refused(why) => {
                            Answer::Refused(format!("asking about ackID {id}: {why}"))
                        }
                    };
                }
                // A blip while asking: keep asking until the deadline.
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Answer::Retry(format!(
                    "Splunk did not confirm ackID {id} as indexed within {} s, so the batch is sent again",
                    self.ack_timeout.as_secs()
                ));
            }
            poll = (poll * 2).min(MAX_ACK_POLL);
        }
    }

    /// GET /services/collector/health, which needs no token.
    async fn health(&self) -> Result<(u16, String), String> {
        let resp = self
            .http
            .get(format!("{}/services/collector/health", self.base))
            .send()
            .await
            .map_err(|e| network_error(&e))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }

    /// Whether the collector takes the token, without indexing anything:
    /// a request with no events. (The health endpoint checks a token only
    /// in the query string, where Splunk's access log would record it.)
    async fn check_token(&self, ack: bool) -> Result<(), String> {
        let (status, body) = self
            .send("/services/collector/event", String::new())
            .await?;
        token_verdict(status, &body, ack)
    }
}

/// Read the answer to an empty request: "No data" means the token passed.
fn token_verdict(status: u16, body: &str, ack: bool) -> Result<(), String> {
    match parse_body(body).1 {
        Some(5 | 6 | 12 | 13) => Ok(()),
        Some(10 | 11) if !ack => Err(describe(status, body)),
        Some(10 | 11) => Ok(()),
        _ => match read_answer(status, body) {
            Answer::Accepted(_) => Ok(()),
            Answer::Refused(why) | Answer::Retry(why) => Err(why),
            Answer::TooLarge => Err(describe(status, body)),
        },
    }
}

/// The token, from its environment variable or the secret store.
fn token(s: &Settings, state_dir: &Path) -> Result<String, String> {
    let value = match (&s.token_env, &s.token_secret) {
        (Some(env), _) => {
            std::env::var(env).map_err(|_| format!("token_env names {env}, which is not set"))?
        }
        (None, Some(name)) => crate::secrets::Store::open(state_dir)?
            .get(name)?
            .ok_or_else(|| format!("secret '{name}' is not set (ariodb secret set {name})"))?,
        (None, None) => return Err("needs token_env or token_secret".to_string()),
    };
    let value = value.trim().to_string();
    if value.is_empty() || value.contains(char::is_control) {
        return Err("the token is empty or not one line".to_string());
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// The running exporter.

/// How the exporter is doing, for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    /// `disabled`, `starting`, `sending`, `idle` (everything sent),
    /// `retrying` (the collector is down or busy) or `refused` (a
    /// configuration problem: see `last_error`).
    pub state: &'static str,
    pub url: String,
    /// Whether this process sends decisions (only `ariodb serve` does).
    pub decisions: bool,
    /// The last decisions-log entry Splunk accepted.
    pub delivered_to: i64,
    /// Entries in the log after it.
    pub backlog: i64,
    pub last_success_ms: Option<i64>,
    pub last_error: Option<String>,
    pub last_error_ms: Option<i64>,
    pub decisions_sent: u64,
    pub events_sent: u64,
    pub events_dropped: u64,
}

struct Queued {
    name: String,
    at_ms: i64,
    details: Value,
}

struct Shared {
    status: Mutex<Status>,
    events: mpsc::Sender<Queued>,
    /// Events queued or in the event task's hands, not yet sent or given
    /// up on. Counted from the moment they are queued, so stopping cannot
    /// miss one the task has just taken.
    events_pending: AtomicU64,
    dropped: AtomicU64,
}

impl Shared {
    fn update(&self, f: impl FnOnce(&mut Status)) {
        f(&mut self.status.lock().expect("status"));
    }

    fn failed(&self, state: &'static str, why: &str) {
        self.update(|s| {
            s.state = state;
            s.last_error = Some(why.to_string());
            s.last_error_ms = Some(crate::store::now_ms());
        });
    }
}

/// Where the exporter reads its settings: `ariodb serve`'s current config,
/// so `[audit.splunk]` reloads, or a one-off command's fixed one.
pub type Source = Arc<dyn Fn() -> Arc<Config> + Send + Sync>;

pub fn fixed(config: Arc<Config>) -> Source {
    Arc::new(move || config.clone())
}

pub struct Exporter {
    shared: Arc<Shared>,
    source: Source,
    stop: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

static CURRENT: RwLock<Option<Arc<Shared>>> = RwLock::new(None);

/// Start the exporter for this process. `decisions` sends the decisions
/// log too; only `ariodb serve` does, so entries are not sent twice. Other
/// processes send only their events, and start nothing when the section is
/// off (they do not reload it).
pub fn start(source: Source, decisions: bool) -> Option<Arc<Exporter>> {
    let config = source();
    let s = &config.audit.splunk;
    if !decisions && !s.enabled {
        return None;
    }
    if s.enabled && s.accept_invalid_certificate {
        eprintln!(
            "ariodb: Splunk exporter: accept_invalid_certificate is on, so the collector's certificate is not checked; use it only for tests"
        );
    }
    let (events, queue) = mpsc::channel(EVENT_QUEUE);
    let shared = Arc::new(Shared {
        status: Mutex::new(Status {
            state: if s.enabled { "starting" } else { "disabled" },
            url: s.url.clone(),
            decisions,
            delivered_to: 0,
            backlog: 0,
            last_success_ms: None,
            last_error: None,
            last_error_ms: None,
            decisions_sent: 0,
            events_sent: 0,
            events_dropped: 0,
        }),
        events,
        events_pending: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
    });
    let (stop, _) = watch::channel(false);
    let dir = PathBuf::from(&config.journal.dir);
    let mut tasks = vec![tokio::spawn(deliver_events(
        shared.clone(),
        source.clone(),
        dir.clone(),
        queue,
        stop.subscribe(),
    ))];
    if decisions {
        tasks.push(tokio::spawn(deliver_decisions(
            shared.clone(),
            source.clone(),
            dir,
            stop.subscribe(),
        )));
    }
    *CURRENT.write().expect("splunk") = Some(shared.clone());
    Some(Arc::new(Exporter {
        shared,
        source,
        stop,
        tasks: Mutex::new(tasks),
    }))
}

/// Send queued events (for up to five seconds), then stop. Decisions not
/// yet sent wait in the log for the next start.
pub async fn stop(exporter: Option<Arc<Exporter>>) {
    let Some(e) = exporter else {
        return;
    };
    *CURRENT.write().expect("splunk") = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && e.events_waiting() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = e.stop.send(true);
    let tasks: Vec<_> = e.tasks.lock().expect("tasks").drain(..).collect();
    for t in tasks {
        let _ = t.await;
    }
}

impl Exporter {
    fn events_waiting(&self) -> bool {
        let config = (self.source)();
        let s = &config.audit.splunk;
        self.shared.events_pending.load(Ordering::Relaxed) > 0 && s.enabled && s.events
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        for t in self.tasks.lock().expect("tasks").iter() {
            t.abort();
        }
    }
}

/// The exporter's status, if this process runs one.
pub fn status() -> Option<Status> {
    let shared = CURRENT.read().expect("splunk").clone()?;
    let mut s = shared.status.lock().expect("status").clone();
    s.events_dropped = shared.dropped.load(Ordering::Relaxed);
    Some(s)
}

/// Queue a notifier event for Splunk. Never waits.
pub fn event(name: &str, details: &Value) {
    if !wanted(name) {
        return;
    }
    let Some(shared) = CURRENT.read().expect("splunk").clone() else {
        return;
    };
    let queued = Queued {
        name: name.to_string(),
        at_ms: crate::store::now_ms(),
        details: details.clone(),
    };
    shared.events_pending.fetch_add(1, Ordering::Relaxed);
    if shared.events.try_send(queued).is_err() {
        shared.events_pending.fetch_sub(1, Ordering::Relaxed);
        let n = shared.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() || n.is_multiple_of(1000) {
            eprintln!(
                "ariodb: Splunk exporter: events are not being sent fast enough; {n} dropped so far"
            );
        }
    }
}

/// A delay with jitter: between half and all of `d`.
fn jittered(d: Duration) -> Duration {
    let half = d.as_millis() as u64 / 2;
    Duration::from_millis(half + rand::random::<u64>() % (half + 1))
}

/// Sleep for `d`, waking early when told to stop (false) or when the
/// `[audit.splunk]` section changes (true, so a fixed setting applies at
/// once rather than after a minute's wait).
async fn nap(
    stop: &mut watch::Receiver<bool>,
    d: Duration,
    source: &Source,
    current: &Settings,
) -> bool {
    let until = Instant::now() + d;
    loop {
        if *stop.borrow() {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || source().audit.splunk != *current {
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(left.min(Duration::from_secs(1))) => {}
            _ = stop.changed() => return false,
        }
    }
}

/// The collector for the current settings, kept until they change. Built
/// again after a refusal, so a token rotated in the secret store is read.
struct Link {
    settings: Option<Settings>,
    collector: Option<Arc<Collector>>,
}

impl Link {
    fn get(&mut self, s: &Settings, dir: &Path) -> Result<Arc<Collector>, String> {
        if self.settings.as_ref() != Some(s) {
            self.collector = None;
        }
        if let Some(c) = &self.collector {
            return Ok(c.clone());
        }
        self.settings = Some(s.clone());
        let c = Arc::new(Collector::new(s, dir)?);
        self.collector = Some(c.clone());
        Ok(c)
    }

    fn reset(&mut self) {
        self.collector = None;
    }
}

/// Logs a refusal once, until a different one or a success.
#[derive(Default)]
struct Quiet(Option<String>);

impl Quiet {
    fn first(&mut self, why: &str) -> bool {
        if self.0.as_deref() == Some(why) {
            return false;
        }
        self.0 = Some(why.to_string());
        true
    }
}

/// What to do after one attempt at a batch of decisions.
#[derive(Debug, PartialEq)]
enum Next {
    /// Move the cursor to this id.
    Advance(i64),
    /// Try again after this long.
    Wait(Duration),
    /// Try again with at most this many entries.
    Shrink(usize),
}

/// The decision after an answer, with the retry state it changes: the
/// backoff for transient failures, and how many entries to send at once.
fn after_answer(answer: &Answer, ids: &[i64], backoff: &mut Duration) -> Next {
    match answer {
        Answer::Accepted(_) => {
            *backoff = FIRST_BACKOFF;
            Next::Advance(*ids.last().expect("a batch is never empty"))
        }
        Answer::Retry(_) => {
            let delay = jittered(*backoff);
            *backoff = (*backoff * 2).min(MAX_BACKOFF);
            Next::Wait(delay)
        }
        Answer::TooLarge if ids.len() > 1 => Next::Shrink(ids.len() / 2),
        Answer::Refused(_) | Answer::TooLarge => Next::Wait(REFUSED_RETRY),
    }
}

/// Send the decisions log, in order, from the exporter's cursor.
async fn deliver_decisions(
    shared: Arc<Shared>,
    source: Source,
    dir: PathBuf,
    mut stop: watch::Receiver<bool>,
) {
    let cursor = match SinkCursor::open(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ariodb: Splunk exporter: cannot read the decisions log: {e}");
            shared.failed("refused", &format!("cannot read the decisions log: {e}"));
            return;
        }
    };
    let record = Record::open(&dir);
    let mut link = Link {
        settings: None,
        collector: None,
    };
    let mut backoff = FIRST_BACKOFF;
    let mut limit: Option<usize> = None;
    let mut quiet = Quiet::default();
    let mut was_failing = false;
    loop {
        let config = source();
        let s = config.audit.splunk.clone();
        if !s.enabled {
            link.reset();
            shared.update(|st| st.state = "disabled");
            if !nap(&mut stop, DISABLED_POLL, &source, &s).await {
                return;
            }
            continue;
        }
        shared.update(|st| st.url = s.url.clone());
        let collector = match link.get(&s, &dir) {
            Ok(c) => c,
            Err(e) => {
                let why = format!("[audit.splunk]: {e}");
                if quiet.first(&why) {
                    eprintln!(
                        "ariodb: Splunk exporter: {why}. Decisions wait in the log; trying again every {} s",
                        REFUSED_RETRY.as_secs()
                    );
                }
                shared.failed("refused", &why);
                record.failure(&why);
                if !nap(&mut stop, REFUSED_RETRY, &source, &s).await {
                    return;
                }
                continue;
            }
        };
        let limit_now = limit.unwrap_or(s.batch_size).min(s.batch_size);
        let read = cursor
            .position(CURSOR)
            .and_then(|from| Ok((from, cursor.after(from, limit_now, MAX_BATCH_BYTES)?)));
        let (from, batch) = match read {
            Ok(read) => read,
            Err(e) => {
                eprintln!("ariodb: Splunk exporter: cannot read the decisions log: {e}");
                if !nap(&mut stop, MAX_BACKOFF, &source, &s).await {
                    return;
                }
                continue;
            }
        };
        let backlog = cursor.backlog(from).unwrap_or(0);
        shared.update(|st| {
            st.delivered_to = from;
            st.backlog = backlog;
        });
        if batch.is_empty() {
            shared.update(|st| st.state = "idle");
            if !nap(
                &mut stop,
                Duration::from_millis(s.flush_interval_ms),
                &source,
                &s,
            )
            .await
            {
                return;
            }
            continue;
        }
        shared.update(|st| {
            if st.state != "retrying" && st.state != "refused" {
                st.state = "sending";
            }
        });
        let meta = Meta::new(&s);
        let ids: Vec<i64> = batch.iter().map(|e| e.decision.id).collect();
        let body = batch_body(batch.iter().map(|e| decision_event(&meta, e)));
        let answer = tokio::select! {
            a = collector.deliver(body) => a,
            // Unsent, the batch waits in the log for the next start.
            _ = stop.changed() => return,
        };
        let range = if ids.len() == 1 {
            format!("decision {}", ids[0])
        } else {
            format!("decisions {} to {}", ids[0], ids[ids.len() - 1])
        };
        match after_answer(&answer, &ids, &mut backoff) {
            Next::Advance(id) => {
                if let Err(e) = cursor.advance(CURSOR, id) {
                    eprintln!("ariodb: Splunk exporter: cannot move its cursor: {e}");
                }
                if was_failing {
                    eprintln!("ariodb: Splunk exporter: delivering again ({range} accepted)");
                    was_failing = false;
                }
                quiet = Quiet::default();
                limit = Some((limit_now * 2).min(s.batch_size));
                let now = crate::store::now_ms();
                shared.update(|st| {
                    st.state = if backlog > ids.len() as i64 {
                        "sending"
                    } else {
                        "idle"
                    };
                    st.delivered_to = id;
                    st.backlog = (backlog - ids.len() as i64).max(0);
                    st.last_success_ms = Some(now);
                    st.decisions_sent += ids.len() as u64;
                });
                record.success(now);
            }
            Next::Shrink(n) => {
                eprintln!(
                    "ariodb: Splunk exporter: the collector found {range} too large (HTTP 413); sending {n} at a time"
                );
                limit = Some(n);
            }
            Next::Wait(delay) => {
                was_failing = true;
                let (state, why) = match answer {
                    Answer::Retry(why) => ("retrying", why),
                    Answer::Refused(why) => ("refused", format!("Splunk refused {range}: {why}")),
                    _ => (
                        "refused",
                        format!(
                            "{range} is larger than the collector accepts (HTTP 413): raise max_content_length in Splunk's limits.conf"
                        ),
                    ),
                };
                if state == "retrying" {
                    eprintln!(
                        "ariodb: Splunk exporter: could not deliver {range} ({why}); trying again in {} s",
                        delay.as_secs().max(1)
                    );
                } else {
                    // A refusal will not change by itself: say so once, and
                    // read the token again before the next try.
                    link.reset();
                    if quiet.first(&why) {
                        eprintln!(
                            "ariodb: Splunk exporter: {why}. Nothing is dropped: decisions wait in the log, and ariodb tries again every {} s",
                            REFUSED_RETRY.as_secs()
                        );
                    }
                }
                shared.failed(state, &why);
                record.failure(&why);
                if !nap(&mut stop, delay, &source, &s).await {
                    return;
                }
            }
        }
    }
}

/// Send queued events in batches. While the collector is down the batch in
/// hand waits (and the queue may fill); nothing here holds up a statement.
async fn deliver_events(
    shared: Arc<Shared>,
    source: Source,
    dir: PathBuf,
    mut queue: mpsc::Receiver<Queued>,
    mut stop: watch::Receiver<bool>,
) {
    let mut link = Link {
        settings: None,
        collector: None,
    };
    let mut quiet = Quiet::default();
    loop {
        let first = tokio::select! {
            q = queue.recv() => match q {
                Some(q) => q,
                None => return,
            },
            _ = stop.changed() => return,
        };
        let mut batch = vec![first];
        while batch.len() < EVENT_BATCH {
            match queue.try_recv() {
                Ok(q) => batch.push(q),
                Err(_) => break,
            }
        }
        let mut backoff = FIRST_BACKOFF;
        loop {
            let config = source();
            let s = config.audit.splunk.clone();
            if !s.enabled || !s.events {
                break;
            }
            let collector = match link.get(&s, &dir) {
                Ok(c) => c,
                Err(e) => {
                    let why = format!("[audit.splunk]: {e}");
                    if quiet.first(&why) {
                        eprintln!("ariodb: Splunk exporter: events wait: {why}");
                    }
                    if !nap(&mut stop, REFUSED_RETRY, &source, &s).await {
                        return;
                    }
                    continue;
                }
            };
            let meta = Meta::new(&s);
            let body = batch_body(batch.iter().map(|q| event_event(&meta, q)));
            let answer = tokio::select! {
                a = collector.deliver(body) => a,
                _ = stop.changed() => return,
            };
            let delay = match answer {
                Answer::Accepted(_) => {
                    quiet = Quiet::default();
                    shared.update(|st| st.events_sent += batch.len() as u64);
                    break;
                }
                Answer::TooLarge => {
                    // Best effort: an event too large to send is dropped.
                    eprintln!(
                        "ariodb: Splunk exporter: the collector found {} events too large (HTTP 413); dropped",
                        batch.len()
                    );
                    shared
                        .dropped
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    break;
                }
                Answer::Retry(why) => {
                    if quiet.first(&why) {
                        eprintln!(
                            "ariodb: Splunk exporter: could not send {} events ({why}); trying again",
                            batch.len()
                        );
                    }
                    let d = jittered(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    d
                }
                Answer::Refused(why) => {
                    link.reset();
                    if quiet.first(&why) {
                        eprintln!(
                            "ariodb: Splunk exporter: Splunk refused {} events: {why}; trying again every {} s",
                            batch.len(),
                            REFUSED_RETRY.as_secs()
                        );
                    }
                    REFUSED_RETRY
                }
            };
            if !nap(&mut stop, delay, &source, &s).await {
                return;
            }
        }
        shared
            .events_pending
            .fetch_sub(batch.len() as u64, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// What `ariodb doctor` reads: the last success and failure, kept in
// ariodb.db because doctor runs in another process.

struct Record {
    db: Option<crate::store::Db>,
    last_write: Mutex<Option<Instant>>,
}

const RECORD_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS splunk_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_success_ms INTEGER,
    last_error TEXT,
    last_error_ms INTEGER
);
INSERT OR IGNORE INTO splunk_status (id) VALUES (1);";

impl Record {
    fn open(dir: &Path) -> Record {
        let db = crate::store::Db::open(dir)
            .and_then(|db| db.with(|c| c.execute_batch(RECORD_SCHEMA)).map(|_| db));
        if let Err(e) = &db {
            eprintln!("ariodb: Splunk exporter: cannot record its status for doctor: {e}");
        }
        Record {
            db: db.ok(),
            last_write: Mutex::new(None),
        }
    }

    /// At most every two seconds while all is well: a busy log need not
    /// mean a write per batch.
    fn success(&self, at_ms: i64) {
        let mut last = self.last_write.lock().expect("record");
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
            return;
        }
        *last = Some(Instant::now());
        if let Some(db) = &self.db {
            let _ = db.with(|c| {
                c.execute(
                    "UPDATE splunk_status SET last_success_ms = ?1 WHERE id = 1",
                    [at_ms],
                )
            });
        }
    }

    fn failure(&self, why: &str) {
        *self.last_write.lock().expect("record") = None;
        if let Some(db) = &self.db {
            let _ = db.with(|c| {
                c.execute(
                    "UPDATE splunk_status SET last_error = ?1, last_error_ms = ?2 WHERE id = 1",
                    rusqlite::params![why, crate::store::now_ms()],
                )
            });
        }
    }
}

/// The last success and the last failure, as the exporter recorded them.
fn recorded(dir: &Path) -> Option<(Option<i64>, Option<String>, Option<i64>)> {
    let db = crate::store::Db::open(dir).ok()?;
    db.with(|c| {
        c.execute_batch(RECORD_SCHEMA)?;
        c.query_row(
            "SELECT last_success_ms, last_error, last_error_ms FROM splunk_status WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
    })
    .ok()
}

fn ago(ms: i64) -> String {
    let s = ((crate::store::now_ms() - ms) / 1000).max(0);
    match s {
        0..120 => format!("{s} s ago"),
        120..7_200 => format!("{} min ago", s / 60),
        7_200..172_800 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

/// `ariodb doctor`'s Splunk section: can the collector be reached, does it
/// take the token, and how far delivery has got.
pub async fn doctor_section(config: &Config) -> Option<crate::doctor::Section> {
    use crate::doctor::{Finding, Section, Status as S};
    let s = &config.audit.splunk;
    if !s.enabled {
        return None;
    }
    let mut findings = Vec::new();
    let mut push = |status, text: String| findings.push(Finding { status, text });
    let dir = Path::new(&config.journal.dir);
    let index = s
        .index
        .as_deref()
        .map(|i| format!(", index {i}"))
        .unwrap_or_else(|| ", the token's default index".to_string());
    let title = format!("splunk: {}{index}", s.url);
    if s.accept_invalid_certificate {
        push(
            S::Warn,
            "accept_invalid_certificate is on: the collector's certificate is not checked (for tests only)".into(),
        );
    }
    if let Ok(url) = reqwest::Url::parse(&s.url)
        && url.scheme() == "http"
        && !url.host_str().is_some_and(is_loopback)
    {
        push(
            S::Warn,
            "url is http://: the token and the decisions travel unencrypted".into(),
        );
    }
    match Collector::new(s, dir) {
        Err(e) => push(S::Fail, e),
        Ok(c) => match c.health().await {
            Err(e) => push(S::Fail, e),
            Ok((status, body)) => {
                let text = parse_body(&body)
                    .0
                    .unwrap_or_else(|| format!("HTTP {status}"));
                match status {
                    200 => push(S::Ok, format!("the collector answers: {text}")),
                    503 | 429 => push(
                        S::Warn,
                        format!("the collector answers, but is not taking events now: {text}"),
                    ),
                    _ => push(
                        S::Warn,
                        format!(
                            "the health check answered {}; is url the collector's base address?",
                            describe(status, &body)
                        ),
                    ),
                }
                match c.check_token(s.ack).await {
                    Ok(()) => push(S::Ok, "the collector accepts the token".into()),
                    Err(why) => push(S::Fail, format!("the token is not accepted: {why}")),
                }
            }
        },
    }
    if let Ok(cursor) = SinkCursor::open(dir)
        && let Ok(at) = cursor.position(CURSOR)
        && let Ok(backlog) = cursor.backlog(at)
    {
        let (success, error, error_ms) = recorded(dir).unwrap_or_default();
        let last = success
            .map(|ms| format!("; the last batch was accepted {}", ago(ms)))
            .unwrap_or_default();
        if backlog == 0 {
            push(
                S::Ok,
                format!("every decision is delivered (up to entry {at}){last}"),
            );
        } else {
            push(
                S::Warn,
                format!(
                    "{backlog} decisions wait to be delivered (delivered up to entry {at}){last}"
                ),
            );
        }
        if let (Some(e), Some(ms)) = (error, error_ms)
            && success.is_none_or(|ok| ms > ok)
        {
            push(
                S::Warn,
                format!("the last attempt failed ({}): {e}", ago(ms)),
            );
        }
    }
    Some(Section { title, findings })
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Decision;

    fn settings(extra: &str) -> Result<Settings, String> {
        #[derive(Deserialize)]
        struct Wrap {
            splunk: Settings,
        }
        let text = format!(
            "[splunk]\nenabled = true\nurl = \"https://splunk.example.test:8088\"\ntoken_env = \"HEC\"\n{extra}"
        );
        let s = toml::from_str::<Wrap>(&text)
            .map_err(|e| e.to_string())?
            .splunk;
        validate(&s)?;
        Ok(s)
    }

    fn chained(id: i64) -> Chained {
        Chained {
            decision: Decision {
                id,
                at_ms: 1_791_548_400_123,
                session: "s-1".into(),
                agent: "coding-agent".into(),
                sql: "UPDATE orders SET status = $1 WHERE id = $2".into(),
                kind: "write".into(),
                tables: vec!["orders".into()],
                outcome: "rolled_back".into(),
                rows: Some(50),
                reason: Some("50 rows changed; the limit is 5".into()),
                rule: Some("row-limit".into()),
                latency_ms: Some(7),
                engine: "postgres".into(),
                database: "app".into(),
                decided_by: vec!["dashboard:root".into()],
            },
            prev: "aa".into(),
            hash: "bb".into(),
        }
    }

    #[test]
    fn settings_are_checked() {
        let s = settings("").unwrap();
        assert_eq!(s.batch_size, 100);
        assert!(!s.accept_invalid_certificate);
        assert!(s.events);
        let err = |extra: &str| settings(extra).unwrap_err();
        assert!(err("token = \"hec-token-local-test-only\"").contains("must not be written"));
        assert!(err("token_secret = \"hec\"").contains("exactly one"));
        assert!(err("batch_size = 0").contains("batch_size must be at least 1"));
        assert!(err("index = \" \"").contains("index must not be empty"));
        assert!(err("tokn_env = \"X\"").contains("unknown field"));
        // A token in the file is refused even with the exporter off.
        let off: Settings =
            toml::from_str("enabled = false\ntoken = \"hec-token-local-test-only\"").unwrap();
        assert!(validate(&off).unwrap_err().contains("must not be written"));
        // Off and otherwise empty is fine.
        assert!(validate(&Settings::default()).is_ok());
    }

    #[test]
    fn the_url_is_the_collectors_base_address() {
        assert_eq!(
            base_url("https://splunk.example.test:8088/").unwrap(),
            "https://splunk.example.test:8088"
        );
        assert!(base_url("https://splunk.example.test:8088/services/collector/event").is_err());
        assert!(base_url("splunk.example.test:8088").is_err());
        assert!(base_url("ftp://splunk.example.test").is_err());
    }

    #[test]
    fn a_decision_maps_to_natural_fields() {
        let meta = Meta {
            source: "ariodb".into(),
            host: Some("gw-1".into()),
            index: Some("ariodb".into()),
        };
        let v = decision_event(&meta, &chained(41));
        assert_eq!(v["sourcetype"], "ariodb:decision");
        assert_eq!(v["source"], "ariodb");
        assert_eq!(v["host"], "gw-1");
        assert_eq!(v["index"], "ariodb");
        // Epoch seconds, keeping the milliseconds.
        assert_eq!(v["time"].to_string(), "1791548400.123");
        let e = &v["event"];
        assert_eq!(e["id"], 41);
        assert_eq!(e["agent"], "coding-agent");
        assert_eq!(e["engine"], "postgres");
        assert_eq!(e["database"], "app");
        assert_eq!(e["session"], "s-1");
        assert_eq!(e["outcome"], "rolled_back");
        assert_eq!(e["rule"], "row-limit");
        assert_eq!(e["deciders"], json!(["dashboard:root"]));
        assert_eq!(e["kind"], "write");
        assert_eq!(e["tables"], json!(["orders"]));
        assert_eq!(e["rows"], 50);
        assert_eq!(e["latency_ms"], 7);
        assert_eq!(e["reason"], "50 rows changed; the limit is 5");
        // The statement as stored (here, redacted).
        assert_eq!(e["sql"], "UPDATE orders SET status = $1 WHERE id = $2");
        assert_eq!(e["hash"], "bb");
        // No index or host: the token's defaults apply.
        let bare = Meta {
            source: "ariodb".into(),
            host: None,
            index: None,
        };
        let v = decision_event(&bare, &chained(1));
        assert!(v.get("index").is_none() && v.get("host").is_none());
    }

    #[test]
    fn events_carry_their_name_and_details() {
        let meta = Meta {
            source: "ariodb".into(),
            host: None,
            index: None,
        };
        let q = Queued {
            name: "approval_decided".into(),
            at_ms: 2_000,
            details: json!({ "agent": "bot", "verdict": "allow", "event": "spoofed" }),
        };
        let v = event_event(&meta, &q);
        assert_eq!(v["sourcetype"], "ariodb:event");
        assert_eq!(v["time"].to_string(), "2.0");
        assert_eq!(v["event"]["event"], "approval_decided");
        assert_eq!(v["event"]["verdict"], "allow");
        assert!(wanted("approval_requested") && wanted("undo_applied"));
        // Already decisions.
        assert!(!wanted("statement_refused") && !wanted("write_rolled_back"));
    }

    #[test]
    fn a_batch_is_events_one_after_another() {
        let meta = Meta {
            source: "ariodb".into(),
            host: None,
            index: None,
        };
        let body = batch_body(
            [chained(1), chained(2)]
                .iter()
                .map(|e| decision_event(&meta, e)),
        );
        let ids: Vec<i64> = serde_json::Deserializer::from_str(&body)
            .into_iter::<Value>()
            .map(|v| v.unwrap()["event"]["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, [1, 2]);
        // A statement's own newlines are escaped, so they cannot split it.
        let mut odd = chained(3);
        odd.decision.sql = "SELECT 1;\n{\"event\": \"forged\"}".into();
        let body = batch_body(std::iter::once(decision_event(&meta, &odd)));
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn answers_are_sorted_by_what_to_do_next() {
        assert_eq!(
            read_answer(200, r#"{"text":"Success","code":0}"#),
            Answer::Accepted(None)
        );
        assert_eq!(
            read_answer(200, r#"{"text":"Success","code":0,"ackID":7}"#),
            Answer::Accepted(Some(7))
        );
        assert_eq!(
            read_answer(200, r#"{"ackID":"8"}"#),
            Answer::Accepted(Some(8))
        );
        for (status, body) in [
            (503, r#"{"text":"Server is busy","code":9}"#),
            (503, r#"{"text":"Server is shutting down","code":23}"#),
            (500, r#"{"text":"Internal server error","code":8}"#),
            (429, r#"{"text":"HEC queue is at capacity","code":26}"#),
            (502, "<html>bad gateway</html>"),
        ] {
            assert!(
                matches!(read_answer(status, body), Answer::Retry(_)),
                "{status}"
            );
        }
        let refused = |status, body| match read_answer(status, body) {
            Answer::Refused(why) => why,
            other => panic!("{other:?}"),
        };
        let why = refused(403, r#"{"text":"Invalid token","code":4}"#);
        assert!(why.contains("HTTP 403, code 4 (Invalid token)"), "{why}");
        assert!(why.contains("token_env or token_secret"), "{why}");
        assert!(refused(401, r#"{"text":"Token is required","code":2}"#).contains("code 2"));
        assert!(refused(400, r#"{"text":"Incorrect index","code":7}"#).contains("index"));
        assert!(
            refused(400, r#"{"text":"Data channel is missing","code":10}"#)
                .contains("set ack = true")
        );
        assert!(
            refused(400, r#"{"text":"ACK is disabled","code":14}"#).contains("set ack = false")
        );
        assert!(refused(404, "").contains("base address"));
        assert!(refused(301, "").contains("redirect"));
        assert_eq!(read_answer(413, ""), Answer::TooLarge);
    }

    #[test]
    fn an_empty_request_tells_whether_the_token_is_accepted() {
        assert!(token_verdict(400, r#"{"text":"No data","code":5}"#, false).is_ok());
        let bad = token_verdict(403, r#"{"text":"Invalid token","code":4}"#, false).unwrap_err();
        assert!(bad.contains("Invalid token"));
        assert!(
            token_verdict(
                400,
                r#"{"text":"Data channel is missing","code":10}"#,
                false
            )
            .unwrap_err()
            .contains("set ack = true")
        );
        assert!(
            token_verdict(400, r#"{"text":"Data channel is missing","code":10}"#, true).is_ok()
        );
        assert!(token_verdict(503, r#"{"text":"Server is busy","code":9}"#, false).is_err());
    }

    #[test]
    fn retries_back_off_and_refusals_wait_without_dropping() {
        let ids = [4, 5, 6, 7];
        let mut backoff = FIRST_BACKOFF;
        let retry = Answer::Retry("HTTP 503".into());
        let mut delays = Vec::new();
        for _ in 0..8 {
            match after_answer(&retry, &ids, &mut backoff) {
                Next::Wait(d) => delays.push(d),
                other => panic!("{other:?}"),
            }
        }
        // Jitter keeps each between half and all of the doubling backoff,
        // which stops at a minute.
        for (i, d) in delays.iter().enumerate() {
            let full = (FIRST_BACKOFF * 2u32.pow(i as u32)).min(MAX_BACKOFF);
            assert!(*d >= full / 2 && *d <= full, "{i}: {d:?}");
        }
        assert_eq!(backoff, MAX_BACKOFF);
        // Success moves the cursor to the last id and resets the backoff.
        assert_eq!(
            after_answer(&Answer::Accepted(None), &ids, &mut backoff),
            Next::Advance(7)
        );
        assert_eq!(backoff, FIRST_BACKOFF);
        // A refusal never moves the cursor: it waits and tries again.
        assert_eq!(
            after_answer(&Answer::Refused("bad token".into()), &ids, &mut backoff),
            Next::Wait(REFUSED_RETRY)
        );
        // Too large: halve the batch, down to a single entry.
        assert_eq!(
            after_answer(&Answer::TooLarge, &ids, &mut backoff),
            Next::Shrink(2)
        );
        assert_eq!(
            after_answer(&Answer::TooLarge, &[9], &mut backoff),
            Next::Wait(REFUSED_RETRY)
        );
    }

    #[test]
    fn quiet_logs_a_refusal_once() {
        let mut q = Quiet::default();
        assert!(q.first("bad token"));
        assert!(!q.first("bad token"));
        assert!(q.first("unknown index"));
    }

    #[test]
    fn the_token_comes_from_the_environment_or_the_secret_store() {
        let dir = std::env::temp_dir().join(format!("ariodb-splunk-t-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = settings("").unwrap();
        s.token_env = Some("ARIODB_SPLUNK_TEST_UNSET_VAR".into());
        assert!(token(&s, &dir).unwrap_err().contains("is not set"));
        s.token_env = None;
        s.token_secret = Some("hec".into());
        assert!(
            token(&s, &dir)
                .unwrap_err()
                .contains("ariodb secret set hec")
        );
        crate::secrets::Store::open(&dir)
            .unwrap()
            .set("hec", "hec-token-local-test-only")
            .unwrap();
        assert_eq!(token(&s, &dir).unwrap(), "hec-token-local-test-only");
        // The collector holds it only in its header value.
        let c = Collector::new(&s, &dir).unwrap();
        assert_eq!(c.auth, "Splunk hec-token-local-test-only");
        assert!(c.channel.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The exporter against a stand-in collector: in order, once, resumed
    /// from the cursor, and nothing moves while Splunk refuses.
    #[tokio::test]
    async fn the_cursor_moves_only_past_what_splunk_accepted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = std::env::temp_dir().join(format!("ariodb-splunk-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = crate::audit::AuditLog::open(&dir, &crate::audit::Settings::default()).unwrap();
        let record = |sql: &str| {
            log.record(&crate::audit::Entry {
                session: "s1",
                agent: "bot",
                sql,
                kind: "read".into(),
                tables: &[],
                outcome: "allowed",
                rows: Some(1),
                reason: None,
                rule: None,
                latency_ms: Some(1),
                engine: "postgres",
                database: "app",
                decided_by: &[],
            })
        };
        for i in 1..=5 {
            record(&format!("SELECT {i}"));
        }
        // A collector that refuses while `refuse` is set, and records the
        // ids it accepted.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let refuse = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::<i64>::new()));
        let (r, s2) = (refuse.clone(), seen.clone());
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // Read the head, then the body by its length.
                let body = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let head = head.to_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .map_or(0, |v| v.trim().parse().unwrap());
                        if body.len() >= len {
                            assert!(
                                head.contains("authorization: splunk hec-token-local-test-only")
                            );
                            break body.to_string();
                        }
                    }
                    if n == 0 {
                        break String::new();
                    }
                };
                let (status, reply) = if r.load(Ordering::Relaxed) {
                    ("403 Forbidden", r#"{"text":"Invalid token","code":4}"#)
                } else {
                    for v in serde_json::Deserializer::from_str(&body).into_iter::<Value>() {
                        s2.lock()
                            .unwrap()
                            .push(v.unwrap()["event"]["id"].as_i64().unwrap());
                    }
                    ("200 OK", r#"{"text":"Success","code":0}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        // SAFETY: the variable is unique to this test.
        unsafe { std::env::set_var("ARIODB_SPLUNK_TEST_TOKEN", "hec-token-local-test-only") };
        let text = format!(
            "[database]\nurl = \"postgres://localhost/app\"\n[journal]\ndir = \"{}\"\n[audit.splunk]\nenabled = true\nurl = \"http://127.0.0.1:{port}\"\ntoken_env = \"ARIODB_SPLUNK_TEST_TOKEN\"\nbatch_size = 2\nflush_interval_ms = 50\n",
            dir.display()
        );
        let config = Arc::new(Config::from_toml(&text).unwrap());
        let exporter = start(fixed(config), true);
        let cursor = SinkCursor::open(&dir).unwrap();
        // Refused: nothing delivered, the cursor stays put.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(cursor.position(CURSOR).unwrap(), 0);
        let st = status().unwrap();
        assert_eq!(st.state, "refused");
        assert!(st.last_error.unwrap().contains("Invalid token"));
        assert_eq!(st.backlog, 5);
        stop(exporter).await;
        // Restarted and accepted: everything, in order, once.
        refuse.store(false, Ordering::Relaxed);
        let config = Arc::new(Config::from_toml(&text).unwrap());
        let exporter = start(fixed(config.clone()), true);
        for _ in 0..100 {
            if cursor.position(CURSOR).unwrap() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(*seen.lock().unwrap(), [1, 2, 3, 4, 5]);
        stop(exporter).await;
        // Another restart resumes after the cursor.
        record("SELECT 6");
        let exporter = start(fixed(config), true);
        for _ in 0..100 {
            if cursor.position(CURSOR).unwrap() == 6 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(*seen.lock().unwrap(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(status().unwrap().backlog, 0);
        stop(exporter).await;
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
