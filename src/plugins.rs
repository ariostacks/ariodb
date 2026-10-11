//! Plugins: programs ariodb starts and talks to over stdin and stdout with
//! newline-delimited JSON-RPC 2.0, as MCP's stdio transport does. A plugin
//! can be an approver, supply facts for rules, receive notifications, or
//! receive the decisions log. See docs/plugins.md for the protocol.
//!
//! `ariodb serve` starts every plugin, restarts it with backoff when it
//! exits, and stops it on shutdown, as it does tunnels. Every failure on a
//! path that decides a statement (a plugin that is down, slow, crashes or
//! answers nonsense) refuses the statement.

use crate::classify::Statement;
use crate::gate::{ApprovalNeed, Ctx, Liveness, State};
use crate::rules::PluginFacts;
use crate::store::{self, Approval};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// The protocol version this ariodb speaks.
pub const PROTOCOL_VERSION: u64 = 1;
/// The longest line ariodb reads from a plugin. A longer one is a protocol
/// error: the plugin is restarted.
pub const MAX_LINE: usize = 1 << 20;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Events waiting for one notifier. Past this, new events are dropped.
const EVENT_QUEUE: usize = 1_000;
/// Lines waiting to be written to one plugin. A plugin that stops reading
/// fills it, and further calls to it fail.
const OUTBOX: usize = 256;
const AUDIT_BATCH: usize = 100;
const AUDIT_BATCH_BYTES: usize = 4 << 20;
const AUDIT_POLL: Duration = Duration::from_millis(500);
/// The most text kept from a plugin's note, error message or log line.
const MAX_TEXT: usize = 1_000;
/// The most facts answers kept per plugin (with `facts_cache_ms`).
const FACTS_CACHE_SWEEP: usize = 1_000;
/// Restart delays, as for tunnels: 1 s doubling to 30 s, reset by a
/// minute's good running.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    /// The program and its arguments. Run directly, not through a shell.
    pub command: Vec<String>,
    /// Environment for the plugin. Nothing else from ariodb's environment
    /// is passed on, apart from PATH, HOME and `pass_env`.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Names of ariodb's own environment variables to pass on, so
    /// credentials need not be written in the config file.
    #[serde(default)]
    pub pass_env: Vec<String>,
    /// Variables filled from the secret store: variable name to secret name.
    #[serde(default)]
    pub secret_env: HashMap<String, String>,
    /// How long one call may take, unless the call has its own limit
    /// (approvals use the approver's timeout).
    pub timeout_ms: Option<u64>,
    /// Reuse a facts answer for the same request for this long. 0 (the
    /// default) asks every time.
    #[serde(default)]
    pub facts_cache_ms: u64,
}

impl PluginConfig {
    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS))
    }
}

/// Checks TOML alone cannot express, including every reference to a plugin
/// from approvers and rules.
pub fn validate(config: &crate::config::Config) -> Result<(), String> {
    let mut names = std::collections::HashSet::new();
    for p in &config.plugins {
        let mut chars = p.name.chars();
        let good = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !good {
            return Err(format!(
                "plugin name '{}' must be letters, digits and underscores, starting with a letter (rules read its facts as plugin.<name>)",
                p.name
            ));
        }
        if !names.insert(p.name.as_str()) {
            return Err(format!("plugin '{}' is listed twice", p.name));
        }
        if p.command.first().is_none_or(|c| c.trim().is_empty()) {
            return Err(format!(
                "plugin '{}' needs a command, such as [\"python3\", \"plugin.py\"]",
                p.name
            ));
        }
        if p.timeout_ms == Some(0) {
            return Err(format!(
                "plugin '{}': timeout_ms must be at least 1",
                p.name
            ));
        }
        let vars = p
            .env
            .keys()
            .chain(p.secret_env.keys())
            .chain(p.pass_env.iter());
        for var in vars {
            if var.is_empty() || var.contains(['=', '\0']) {
                return Err(format!(
                    "plugin '{}': '{var}' is not an environment variable name",
                    p.name
                ));
            }
        }
    }
    for a in &config.approvers {
        if a.kind == crate::approvals::ApproverKind::Plugin
            && let Some(name) = &a.plugin
            && !names.contains(name.as_str())
        {
            return Err(format!(
                "approver '{}' uses plugin '{name}', which is not defined in [[plugins]]",
                a.name
            ));
        }
    }
    for r in &config.rules {
        let Some(condition) = &r.condition else {
            continue;
        };
        for name in crate::rules::plugins_mentioned(condition).unwrap_or_default() {
            if !names.contains(name.as_str()) {
                return Err(format!(
                    "rule '{}' reads facts from plugin '{name}', which is not defined in [[plugins]]",
                    r.name
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The protocol: what a plugin says, and how ariodb reads it.

/// What a plugin says it can do. Calls for anything else are refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Capabilities {
    #[serde(default)]
    pub approver: bool,
    #[serde(default)]
    pub facts: bool,
    #[serde(default)]
    pub notifier: bool,
    #[serde(default)]
    pub audit_sink: bool,
}

#[derive(Debug, Clone, Copy)]
enum Cap {
    Approver,
    Facts,
    Notifier,
    AuditSink,
}

impl Cap {
    fn name(self) -> &'static str {
        match self {
            Cap::Approver => "approver",
            Cap::Facts => "facts",
            Cap::Notifier => "notifier",
            Cap::AuditSink => "audit_sink",
        }
    }
}

impl Capabilities {
    fn has(&self, cap: Cap) -> bool {
        match cap {
            Cap::Approver => self.approver,
            Cap::Facts => self.facts,
            Cap::Notifier => self.notifier,
            Cap::AuditSink => self.audit_sink,
        }
    }

    pub fn names(&self) -> Vec<&'static str> {
        [Cap::Approver, Cap::Facts, Cap::Notifier, Cap::AuditSink]
            .into_iter()
            .filter(|c| self.has(*c))
            .map(Cap::name)
            .collect()
    }
}

/// The plugin's answer to `initialize`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Hello {
    pub name: String,
    pub version: String,
    pub capabilities: Capabilities,
}

fn parse_hello(v: &Value) -> Result<Hello, String> {
    let obj = v
        .as_object()
        .ok_or("the answer to initialize must be an object")?;
    if let Some(version) = obj.get("protocol_version")
        && version.as_u64() != Some(PROTOCOL_VERSION)
    {
        return Err(format!(
            "it speaks protocol version {version}; this ariodb speaks {PROTOCOL_VERSION}"
        ));
    }
    let text = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .map(|s| clean(s, 100))
            .ok_or_else(|| format!("the answer to initialize needs a string \"{key}\""))
    };
    let capabilities = obj
        .get("capabilities")
        .cloned()
        .ok_or("the answer to initialize needs \"capabilities\"")?;
    Ok(Hello {
        name: text("name")?,
        version: text("version")?,
        capabilities: serde_json::from_value(capabilities)
            .map_err(|e| format!("capabilities: {e}"))?,
    })
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Allow(Option<String>),
    Deny(Option<String>),
}

fn parse_verdict(v: &Value) -> Result<Verdict, String> {
    let obj = v
        .as_object()
        .ok_or("the answer to approve must be an object")?;
    let note = match obj.get("note") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(clean(s, MAX_TEXT)),
        Some(_) => return Err("note must be a string".to_string()),
    };
    match obj.get("verdict").and_then(Value::as_str) {
        Some("allow") => Ok(Verdict::Allow(note)),
        Some("deny") => Ok(Verdict::Deny(note)),
        _ => Err("verdict must be \"allow\" or \"deny\"".to_string()),
    }
}

/// One line from a plugin.
#[derive(Debug, PartialEq)]
enum Incoming {
    /// The answer to one of ariodb's requests.
    Answer {
        id: u64,
        result: Result<Value, String>,
    },
    /// A request from the plugin, which ariodb refuses.
    Request {
        id: Value,
        method: String,
    },
    Notification {
        method: String,
    },
    Malformed(String),
}

fn parse_incoming(line: &[u8]) -> Incoming {
    let Ok(v) = serde_json::from_slice::<Value>(line) else {
        return Incoming::Malformed("not JSON".into());
    };
    let Some(obj) = v.as_object() else {
        return Incoming::Malformed("not a JSON object (batches are not supported)".into());
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Incoming::Malformed("no \"jsonrpc\": \"2.0\"".into());
    }
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        let method = clean(method, 100);
        return match obj.get("id") {
            Some(id) if !id.is_null() => Incoming::Request {
                id: id.clone(),
                method,
            },
            _ => Incoming::Notification { method },
        };
    }
    let Some(id) = obj.get("id").and_then(Value::as_u64) else {
        return Incoming::Malformed("an answer needs the id of the request it answers".into());
    };
    let result = match (obj.get("result"), obj.get("error")) {
        (Some(r), None) => Ok(r.clone()),
        (None, Some(e)) => Err(error_text(e)),
        _ => Err("the answer needs exactly one of result and error".into()),
    };
    Incoming::Answer { id, result }
}

fn error_text(e: &Value) -> String {
    let message = clean(
        e.get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message"),
        MAX_TEXT,
    );
    match e.get("code").and_then(Value::as_i64) {
        Some(code) => format!("plugin error {code}: {message}"),
        None => format!("plugin error: {message}"),
    }
}

/// Text from a plugin, safe to log and show: no control characters (so no
/// terminal escapes or forged log lines), at most `max` characters.
fn clean(text: &str, max: usize) -> String {
    let mut out: String = text.chars().filter(|c| !c.is_control()).take(max).collect();
    if text.chars().filter(|c| !c.is_control()).count() > max {
        out.push('…');
    }
    out
}

/// One line read with a length cap.
#[derive(Debug, PartialEq)]
enum Frame {
    Line(Vec<u8>),
    /// The line is longer than the cap. What was read of it is thrown
    /// away; the rest is still unread (see `skip_line`).
    TooLong,
}

/// Read one newline-terminated line, holding at most `cap` bytes of it in
/// memory. Returns as soon as a line passes the cap, so a line that never
/// ends cannot keep the caller waiting. `None` at the end of the stream.
async fn read_frame<R: AsyncBufRead + Unpin>(
    r: &mut R,
    cap: usize,
) -> std::io::Result<Option<Frame>> {
    let mut buf = Vec::new();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok((!buf.is_empty()).then_some(Frame::Line(buf)));
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(available.len());
        if buf.len() + take > cap {
            r.consume(take);
            return Ok(Some(Frame::TooLong));
        }
        buf.extend_from_slice(&available[..take]);
        r.consume(newline.map_or(take, |i| i + 1));
        if newline.is_some() {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(Frame::Line(buf)));
        }
    }
}

/// Discard the rest of the current line, without holding any of it.
async fn skip_line<R: AsyncBufRead + Unpin>(r: &mut R) -> std::io::Result<()> {
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(());
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let used = newline.map_or(available.len(), |i| i + 1);
        r.consume(used);
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn notification(method: &str, params: Value) -> String {
    json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string()
}

// ---------------------------------------------------------------------------
// One running plugin process.

enum Out {
    Line(String),
    /// Close the plugin's stdin, after everything queued before it.
    Close,
}

type Answer = Result<Value, String>;
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Answer>>>>;

/// The connection to one running plugin process. Each process has its own
/// pipes, and every line ariodb writes is one serialised JSON value (which
/// cannot contain a raw newline), so nothing in one message (agent SQL, say)
/// can start another, and no plugin can write into another's stream.
struct Link {
    name: String,
    outbox: mpsc::Sender<Out>,
    pending: Pending,
    next_id: AtomicU64,
    hello: OnceLock<Hello>,
}

impl Link {
    fn request(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(u64, oneshot::Receiver<Answer>), String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending").insert(id, tx);
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        if let Err(e) = self.outbox.try_send(Out::Line(line.to_string())) {
            self.forget(id);
            return Err(match e {
                mpsc::error::TrySendError::Full(_) => {
                    format!("plugin '{}' is not reading its input", self.name)
                }
                mpsc::error::TrySendError::Closed(_) => {
                    format!("plugin '{}' is not running", self.name)
                }
            });
        }
        Ok((id, rx))
    }

    fn forget(&self, id: u64) {
        self.pending.lock().expect("pending").remove(&id);
    }

    fn capable(&self, cap: Cap) -> Result<(), String> {
        match self.hello.get() {
            Some(h) if h.capabilities.has(cap) => Ok(()),
            Some(_) => Err(format!(
                "plugin '{}' did not declare the {} capability",
                self.name,
                cap.name()
            )),
            None => Err(format!("plugin '{}' has not finished starting", self.name)),
        }
    }

    /// Wait for the answer to request `id`, giving up after `timeout`.
    async fn answer(&self, id: u64, rx: oneshot::Receiver<Answer>, timeout: Duration) -> Answer {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(format!("plugin '{}' stopped before answering", self.name)),
            Err(_) => {
                self.forget(id);
                Err(format!(
                    "no answer from plugin '{}' within {} ms",
                    self.name,
                    timeout.as_millis()
                ))
            }
        }
    }

    async fn call(&self, method: &str, params: Value, timeout: Duration) -> Answer {
        let (id, rx) = self.request(method, params)?;
        self.answer(id, rx, timeout).await
    }
}

struct Session {
    child: Child,
    link: Arc<Link>,
    /// Ends when the plugin's output does, saying why.
    reader: JoinHandle<String>,
    writer: JoinHandle<()>,
}

/// Start a plugin and complete the handshake.
async fn open(config: &PluginConfig, state_dir: &Path) -> Result<Session, String> {
    let name = &config.name;
    let mut cmd = Command::new(&config.command[0]);
    cmd.args(&config.command[1..])
        .env_clear()
        .envs(environment(config, state_dir)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Its own process group, as for tunnels: ariodb stops it in order.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("plugin '{name}': cannot start {}: {e}", config.command[0]))?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(format!("plugin '{name}': no pipes"));
    };
    tokio::spawn(relay_stderr(name.clone(), stderr));
    let (outbox, outgoing) = mpsc::channel(OUTBOX);
    let pending = Pending::default();
    let writer = tokio::spawn(write_loop(stdin, outgoing));
    let reader = tokio::spawn(read_loop(
        name.clone(),
        BufReader::new(stdout),
        pending.clone(),
        outbox.clone(),
    ));
    let link = Arc::new(Link {
        name: name.clone(),
        outbox,
        pending,
        next_id: AtomicU64::new(1),
        hello: OnceLock::new(),
    });
    let mut session = Session {
        child,
        link,
        reader,
        writer,
    };
    match session.handshake(config).await {
        Ok(()) => Ok(session),
        Err(e) => {
            session.close().await;
            Err(e)
        }
    }
}

impl Session {
    async fn handshake(&mut self, config: &PluginConfig) -> Result<(), String> {
        let name = &config.name;
        let params = json!({
            "protocol_version": PROTOCOL_VERSION,
            "ariodb_version": env!("CARGO_PKG_VERSION"),
            "name": name,
        });
        let (id, rx) = self.link.request("initialize", params)?;
        // A plugin that exits early ends its output too: report how it exited.
        let answer = match self.link.answer(id, rx, HANDSHAKE_TIMEOUT).await {
            Err(e) => {
                match tokio::time::timeout(Duration::from_millis(500), self.child.wait()).await {
                    Ok(Ok(status)) => Err(format!(
                        "plugin '{name}' {} before it answered initialize",
                        crate::tunnels::describe(status)
                    )),
                    _ => Err(e),
                }
            }
            ok => ok,
        };
        let hello = parse_hello(&answer?).map_err(|e| format!("plugin '{name}': {e}"))?;
        let _ = self.link.hello.set(hello);
        Ok(())
    }

    /// Close the plugin's stdin and give it two seconds to exit, then stop
    /// its process group.
    async fn close(mut self) {
        let _ =
            tokio::time::timeout(Duration::from_secs(1), self.link.outbox.send(Out::Close)).await;
        if tokio::time::timeout(Duration::from_secs(2), self.child.wait())
            .await
            .is_err()
        {
            crate::tunnels::terminate(&mut self.child).await;
        }
        self.writer.abort();
        self.reader.abort();
        self.link.pending.lock().expect("pending").clear();
    }
}

/// The plugin's environment: PATH and HOME, `pass_env`, `secret_env`, then `env`.
fn environment(config: &PluginConfig, state_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    let passed = ["PATH", "HOME"]
        .iter()
        .map(|s| s.to_string())
        .chain(config.pass_env.iter().cloned());
    for var in passed {
        if let Ok(value) = std::env::var(&var) {
            env.push((var, value));
        }
    }
    if !config.secret_env.is_empty() {
        let store = crate::secrets::Store::open(state_dir)?;
        for (var, secret) in &config.secret_env {
            let value = store
                .get(secret)?
                .ok_or_else(|| format!("plugin '{}': secret '{secret}' is not set", config.name))?;
            env.push((var.clone(), value));
        }
    }
    env.extend(config.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    Ok(env)
}

async fn write_loop(mut stdin: ChildStdin, mut outgoing: mpsc::Receiver<Out>) {
    while let Some(Out::Line(line)) = outgoing.recv().await {
        let written = async {
            stdin.write_all(line.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        };
        if written.await.is_err() {
            break;
        }
    }
    // Dropping stdin closes it: the plugin sees the end of its input.
}

/// Why a plugin's output ended when it simply closed it.
const CLOSED: &str = "closed its output";

/// Read the plugin's output, handing each answer to whoever is waiting
/// for it. Answers to requests nobody is waiting for (late, or never asked)
/// are dropped, so an answer can only ever decide the request it names.
async fn read_loop<R: AsyncRead + Unpin>(
    name: String,
    mut stdout: BufReader<R>,
    pending: Pending,
    outbox: mpsc::Sender<Out>,
) -> String {
    let why = loop {
        let line = match read_frame(&mut stdout, MAX_LINE).await {
            Ok(None) => break CLOSED.to_string(),
            Err(e) => break format!("could not be read: {e}"),
            Ok(Some(Frame::TooLong)) => break format!("sent a line longer than {MAX_LINE} bytes"),
            Ok(Some(Frame::Line(line))) => line,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match parse_incoming(&line) {
            Incoming::Answer { id, result } => {
                let waiting = pending.lock().expect("pending").remove(&id);
                match waiting {
                    Some(tx) => {
                        let _ = tx.send(result);
                    }
                    None => eprintln!(
                        "ariodb: plugin '{name}' answered request {id}, which is not waiting (too late, or never sent); ignored"
                    ),
                }
            }
            Incoming::Request { id, method } => {
                eprintln!("ariodb: plugin '{name}' sent a request ({method}); ariodb takes none");
                let refusal = json!({ "jsonrpc": "2.0", "id": id, "error": {
                    "code": -32601, "message": "ariodb does not take requests from plugins" } });
                let _ = outbox.try_send(Out::Line(refusal.to_string()));
            }
            Incoming::Notification { method } => {
                eprintln!("ariodb: plugin '{name}' sent a notification ({method}); ignored");
            }
            Incoming::Malformed(why) => {
                eprintln!(
                    "ariodb: plugin '{name}' wrote a line that is not JSON-RPC 2.0 ({why}); ignored (log to stderr instead)"
                );
            }
        }
    };
    // Whoever is still waiting hears now that no answer is coming.
    pending.lock().expect("pending").clear();
    why
}

/// Copy the plugin's stderr into ariodb's log with its name in front.
async fn relay_stderr<R: AsyncRead + Unpin>(name: String, from: R) {
    let mut from = BufReader::new(from);
    while let Ok(Some(frame)) = read_frame(&mut from, MAX_LINE).await {
        match frame {
            Frame::Line(line) => {
                eprintln!(
                    "plugin {name}: {}",
                    clean(&String::from_utf8_lossy(&line), 4 * MAX_TEXT)
                )
            }
            Frame::TooLong => {
                eprintln!("plugin {name}: (a line over {MAX_LINE} bytes was dropped)");
                if skip_line(&mut from).await.is_err() {
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Supervised plugins.

/// How a plugin is doing, for `ariodb plugin list` and the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub name: String,
    pub command: Vec<String>,
    /// `starting`, `running`, `restarting` or `stopped`.
    pub state: &'static str,
    /// What the plugin said about itself when it last started.
    pub declared: Option<Hello>,
    pub pid: Option<u32>,
    pub restarts: u64,
    pub last_error: Option<String>,
    pub dropped_events: u64,
}

struct Plugin {
    config: PluginConfig,
    link: RwLock<Option<Arc<Link>>>,
    /// Bumped whenever the link comes or goes, for tasks waiting on it.
    generation: watch::Sender<u64>,
    status: Mutex<Status>,
    events: mpsc::Sender<Value>,
    /// The event delivery task holds an event it has not yet written.
    event_in_hand: AtomicBool,
    dropped: AtomicU64,
    facts_cache: Mutex<FactsCache>,
}

enum Approved {
    Allow(Option<String>),
    Deny(Option<String>),
    Failed(String),
    Withdrawn(&'static str),
}

impl Plugin {
    fn link(&self) -> Option<Arc<Link>> {
        self.link.read().expect("link").clone()
    }

    fn status(&self) -> Status {
        let mut s = self.status.lock().expect("status").clone();
        s.dropped_events = self.dropped.load(Ordering::Relaxed);
        s
    }

    fn set_link(&self, link: Option<Arc<Link>>) {
        *self.link.write().expect("link") = link;
        self.generation.send_modify(|g| *g += 1);
    }

    /// The live link, if the plugin is running and declared `cap`.
    fn ready(&self, cap: Cap) -> Result<Arc<Link>, String> {
        let Some(link) = self.link() else {
            let s = self.status();
            let why = s.last_error.map(|e| format!(": {e}")).unwrap_or_default();
            return Err(format!("plugin '{}' is {}{why}", self.config.name, s.state));
        };
        link.capable(cap)?;
        Ok(link)
    }

    /// Wait until the plugin is running. `None` if told to stop first.
    async fn wait_link(&self, stop: &mut watch::Receiver<bool>) -> Option<Arc<Link>> {
        let mut changes = self.generation.subscribe();
        loop {
            if *stop.borrow() {
                return None;
            }
            if let Some(link) = self.link() {
                return Some(link);
            }
            tokio::select! {
                r = changes.changed() => if r.is_err() { return None },
                _ = stop.changed() => return None,
            }
        }
    }

    async fn approve(&self, params: Value, timeout: Duration, live: Option<&Liveness>) -> Approved {
        let link = match self.ready(Cap::Approver) {
            Ok(l) => l,
            Err(e) => return Approved::Failed(e),
        };
        let approval_id = params["approval_id"].clone();
        let (id, mut rx) = match link.request("approve", params) {
            Ok(r) => r,
            Err(e) => return Approved::Failed(e),
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            tokio::select! {
                answer = &mut rx => {
                    return match answer {
                        Ok(Ok(v)) => match parse_verdict(&v) {
                            Ok(Verdict::Allow(note)) => Approved::Allow(note),
                            Ok(Verdict::Deny(note)) => Approved::Deny(note),
                            Err(e) => Approved::Failed(format!("plugin '{}' answered approve wrongly: {e}", self.config.name)),
                        },
                        Ok(Err(e)) => Approved::Failed(e),
                        Err(_) => Approved::Failed(format!("plugin '{}' stopped before answering", self.config.name)),
                    };
                }
                _ = tokio::time::sleep_until(deadline) => {
                    link.forget(id);
                    return Approved::Failed(format!(
                        "no answer from plugin '{}' within {} seconds",
                        self.config.name,
                        timeout.as_secs()
                    ));
                }
                _ = tokio::time::sleep(Duration::from_millis(300)) => {
                    if let Some(why) = live.and_then(|l| l.stopped()) {
                        link.forget(id);
                        let cancel = json!({ "id": id, "approval_id": approval_id, "reason": why });
                        let _ = link.outbox.try_send(Out::Line(notification("cancel", cancel)));
                        return Approved::Withdrawn(why);
                    }
                }
            }
        }
    }

    async fn facts(&self, params: Value) -> Result<Value, String> {
        let ttl = Duration::from_millis(self.config.facts_cache_ms);
        let key = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            params.to_string().as_bytes(),
        ));
        if !ttl.is_zero()
            && let Some((at, facts)) = self.facts_cache.lock().expect("cache").get(&key)
            && at.elapsed() < ttl
        {
            return Ok(facts.clone());
        }
        let link = self.ready(Cap::Facts)?;
        let facts = link.call("facts", params, self.config.timeout()).await?;
        if !facts.is_object() {
            return Err("the answer to facts must be a JSON object".to_string());
        }
        if !ttl.is_zero() {
            remember(
                &mut self.facts_cache.lock().expect("cache"),
                key,
                facts.clone(),
                ttl,
            );
        }
        Ok(facts)
    }

    /// Queue an event without waiting. A full queue drops it, counted.
    fn enqueue(&self, event: &Value) {
        let declared = self.status.lock().expect("status").declared.clone();
        if declared.is_some_and(|h| !h.capabilities.notifier) {
            return;
        }
        if self.events.try_send(event.clone()).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() || n.is_multiple_of(1000) {
                eprintln!(
                    "ariodb: plugin '{}' is not taking events fast enough; {n} dropped so far",
                    self.config.name
                );
            }
        }
    }

    /// Events are queued or being written, and the plugin may yet take them.
    fn events_waiting(&self) -> bool {
        let waiting =
            self.events.capacity() < EVENT_QUEUE || self.event_in_hand.load(Ordering::Relaxed);
        let s = self.status.lock().expect("status");
        let able = matches!(s.state, "starting" | "running")
            && s.declared.as_ref().is_none_or(|h| h.capabilities.notifier);
        waiting && able
    }
}

type FactsCache = HashMap<String, (Instant, Value)>;

/// Keep a facts answer. Agents choose their statements, so every distinct
/// one is a new key: the cache never holds more than FACTS_CACHE_SWEEP
/// answers, dropping expired ones first and then the oldest.
fn remember(cache: &mut FactsCache, key: String, facts: Value, ttl: Duration) {
    if cache.len() >= FACTS_CACHE_SWEEP {
        cache.retain(|_, (at, _)| at.elapsed() < ttl);
    }
    while cache.len() >= FACTS_CACHE_SWEEP {
        let oldest = cache
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => cache.remove(&k),
            None => break,
        };
    }
    cache.insert(key, (Instant::now(), facts));
}

/// The plugins one ariodb process runs.
pub struct Host {
    plugins: Vec<Arc<Plugin>>,
    stop: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// What this process does with its plugins.
#[derive(Debug, Clone, Copy)]
pub struct Roles {
    /// Deliver the decisions log to audit sinks. Only `ariodb serve` does,
    /// so that entries are not sent twice by two processes.
    pub audit_sink: bool,
}

impl Host {
    /// Start every plugin. Returns at once; see `settle`.
    pub fn start(configs: &[PluginConfig], state_dir: &Path, roles: Roles) -> Arc<Host> {
        let (stop, _) = watch::channel(false);
        let mut plugins = Vec::new();
        let mut tasks = Vec::new();
        for config in configs {
            let (events, queue) = mpsc::channel(EVENT_QUEUE);
            let plugin = Arc::new(Plugin {
                status: Mutex::new(Status {
                    name: config.name.clone(),
                    command: config.command.clone(),
                    state: "starting",
                    declared: None,
                    pid: None,
                    restarts: 0,
                    last_error: None,
                    dropped_events: 0,
                }),
                config: config.clone(),
                link: RwLock::new(None),
                generation: watch::channel(0).0,
                events,
                event_in_hand: AtomicBool::new(false),
                dropped: AtomicU64::new(0),
                facts_cache: Mutex::new(HashMap::new()),
            });
            let dir = state_dir.to_path_buf();
            tasks.push(tokio::spawn(supervise(
                plugin.clone(),
                dir.clone(),
                stop.subscribe(),
            )));
            tasks.push(tokio::spawn(deliver_events(
                plugin.clone(),
                queue,
                stop.subscribe(),
            )));
            if roles.audit_sink {
                tasks.push(tokio::spawn(deliver_audit(
                    plugin.clone(),
                    dir,
                    stop.subscribe(),
                )));
            }
            plugins.push(plugin);
        }
        Arc::new(Host {
            plugins,
            stop,
            tasks: Mutex::new(tasks),
        })
    }

    fn get(&self, name: &str) -> Option<&Arc<Plugin>> {
        self.plugins.iter().find(|p| p.config.name == name)
    }

    pub fn statuses(&self) -> Vec<Status> {
        self.plugins.iter().map(|p| p.status()).collect()
    }

    /// Wait (up to `limit`) until every plugin has started or failed once,
    /// so the first statements do not find their plugins still starting.
    pub async fn settle(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline && self.statuses().iter().any(|s| s.state == "starting") {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Deliver queued events (for up to five seconds), then stop every
    /// plugin and wait for them to exit.
    pub async fn stop(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && self.plugins.iter().any(|p| p.events_waiting()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = self.stop.send(true);
        let tasks: Vec<_> = self.tasks.lock().expect("tasks").drain(..).collect();
        for t in tasks {
            let _ = t.await;
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // The processes are spawned with kill_on_drop.
        for t in self.tasks.lock().expect("tasks").iter() {
            t.abort();
        }
    }
}

/// Sleep, unless told to stop first. False if told to stop.
async fn nap(stop: &mut watch::Receiver<bool>, d: Duration) -> bool {
    if *stop.borrow() {
        return false;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => !*stop.borrow(),
        _ = stop.changed() => false,
    }
}

/// Run one plugin until told to stop, restarting it with backoff.
async fn supervise(plugin: Arc<Plugin>, state_dir: PathBuf, mut stop: watch::Receiver<bool>) {
    let name = plugin.config.name.clone();
    let mut backoff = FIRST_BACKOFF;
    loop {
        let opened = tokio::select! {
            s = open(&plugin.config, &state_dir) => s,
            _ = stop.changed() => {
                plugin.status.lock().expect("status").state = "stopped";
                return;
            }
        };
        let why = match opened {
            Err(e) => e,
            Ok(mut session) => {
                let started = Instant::now();
                let hello = session.link.hello.get().cloned();
                {
                    let mut s = plugin.status.lock().expect("status");
                    s.state = "running";
                    s.pid = session.child.id();
                    s.declared = hello.clone();
                }
                plugin.set_link(Some(session.link.clone()));
                if let Some(h) = &hello {
                    let caps = h.capabilities.names();
                    eprintln!(
                        "ariodb: plugin '{name}' is running (pid {}; {} {}; {})",
                        session.child.id().unwrap_or(0),
                        h.name,
                        h.version,
                        if caps.is_empty() {
                            "no capabilities".to_string()
                        } else {
                            caps.join(", ")
                        }
                    );
                }
                let why = tokio::select! {
                    status = session.child.wait() => match status {
                        Ok(s) => crate::tunnels::describe(s),
                        Err(e) => e.to_string(),
                    },
                    r = &mut session.reader => {
                        let why = r.unwrap_or_else(|e| e.to_string());
                        // Output usually ends because the process did: say
                        // how. A protocol error is the reason, though, even
                        // if the plugin then dies of the closed pipe.
                        let exited = tokio::time::timeout(Duration::from_millis(500), session.child.wait()).await;
                        match exited {
                            Ok(Ok(status)) if why == CLOSED => crate::tunnels::describe(status),
                            _ => why,
                        }
                    }
                    _ = stop.changed() => {
                        plugin.set_link(None);
                        plugin.status.lock().expect("status").state = "stopped";
                        session.close().await;
                        return;
                    }
                };
                let why = format!("plugin '{name}' {why}");
                plugin.status.lock().expect("status").state = "restarting";
                plugin.set_link(None);
                session.close().await;
                if started.elapsed() >= STABLE_AFTER {
                    backoff = FIRST_BACKOFF;
                }
                why
            }
        };
        {
            let mut s = plugin.status.lock().expect("status");
            s.state = "restarting";
            s.pid = None;
            s.restarts += 1;
            s.last_error = Some(why.clone());
        }
        eprintln!("ariodb: {why}; restarting it in {} s", backoff.as_secs());
        let delay = backoff;
        backoff = (backoff * 2).min(MAX_BACKOFF);
        if !nap(&mut stop, delay).await {
            plugin.status.lock().expect("status").state = "stopped";
            return;
        }
    }
}

/// Write queued events to the plugin, one at a time. While the plugin is
/// restarting they wait (and the queue may fill); nothing here ever holds
/// up a statement.
async fn deliver_events(
    plugin: Arc<Plugin>,
    mut queue: mpsc::Receiver<Value>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let event = tokio::select! {
            e = queue.recv() => match e {
                Some(e) => e,
                None => return,
            },
            _ = stop.changed() => return,
        };
        plugin.event_in_hand.store(true, Ordering::Relaxed);
        let Some(link) = plugin.wait_link(&mut stop).await else {
            return;
        };
        if link.capable(Cap::Notifier).is_ok() {
            let line = Out::Line(notification("event", event));
            tokio::select! {
                _ = link.outbox.send(line) => {}
                _ = stop.changed() => return,
            }
        }
        plugin.event_in_hand.store(false, Ordering::Relaxed);
    }
}

/// Send the decisions log to an audit sink in order, from where its cursor
/// stands, moving the cursor only past entries it acknowledged. Entries are
/// therefore delivered at least once, in order, across restarts of either
/// side.
async fn deliver_audit(plugin: Arc<Plugin>, state_dir: PathBuf, mut stop: watch::Receiver<bool>) {
    let name = plugin.config.name.clone();
    let cursor = match crate::audit::SinkCursor::open(&state_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ariodb: plugin '{name}': cannot read the decisions log: {e}");
            return;
        }
    };
    let mut backoff = FIRST_BACKOFF;
    loop {
        let Some(link) = plugin.wait_link(&mut stop).await else {
            return;
        };
        if link.capable(Cap::AuditSink).is_err() {
            // Not a sink, at least until it restarts as one.
            let mut changes = plugin.generation.subscribe();
            tokio::select! {
                _ = changes.changed() => continue,
                _ = stop.changed() => return,
            }
        }
        let batch = cursor
            .position(&name)
            .and_then(|from| cursor.after(from, AUDIT_BATCH, AUDIT_BATCH_BYTES));
        let batch = match batch {
            Ok(b) if b.is_empty() => {
                if !nap(&mut stop, AUDIT_POLL).await {
                    return;
                }
                continue;
            }
            Ok(b) => b,
            Err(e) => {
                eprintln!("ariodb: plugin '{name}': cannot read the decisions log: {e}");
                if !nap(&mut stop, MAX_BACKOFF).await {
                    return;
                }
                continue;
            }
        };
        let ids: Vec<i64> = batch.iter().map(|e| e.decision.id).collect();
        let answer = link
            .call(
                "audit",
                json!({ "entries": batch }),
                plugin.config.timeout(),
            )
            .await;
        let acked = answer.and_then(|v| match v.get("ack").and_then(Value::as_i64) {
            Some(id) if ids.contains(&id) => Ok(id),
            Some(id) => Err(format!(
                "acknowledged entry {id}, which was not in the batch ({} to {})",
                ids[0],
                ids[ids.len() - 1]
            )),
            None => {
                Err("the answer to audit must be {\"ack\": <id of the last entry stored>}".into())
            }
        });
        match acked.and_then(|id| cursor.advance(&name, id)) {
            Ok(()) => backoff = FIRST_BACKOFF,
            Err(e) => {
                eprintln!(
                    "ariodb: plugin '{name}': audit delivery failed ({e}); trying again in {} s",
                    backoff.as_secs()
                );
                plugin.status.lock().expect("status").last_error = Some(e);
                let delay = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                if !nap(&mut stop, delay).await {
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// What the rest of ariodb calls.

/// The plugins this process runs, if it runs any.
static HOST: RwLock<Option<Arc<Host>>> = RwLock::new(None);

pub fn install(host: Arc<Host>) {
    *HOST.write().expect("host") = Some(host);
}

pub fn uninstall() {
    *HOST.write().expect("host") = None;
}

fn current() -> Option<Arc<Host>> {
    HOST.read().expect("host").clone()
}

/// Every plugin's status, for the dashboard.
pub fn statuses() -> Vec<Status> {
    current().map(|h| h.statuses()).unwrap_or_default()
}

/// What approvers and facts plugins are told about a request.
fn request_params(ctx: &Ctx<'_>, statements: &[Statement]) -> Value {
    json!({
        "agent": ctx.agent.name,
        "session": ctx.session,
        "database": ctx.database,
        "engine": statements.first().map(|s| s.engine).unwrap_or("postgres"),
        "statements": statements.iter().map(|s| json!({
            "sql": s.sql,
            "kind": s.kind,
            "tables": s.tables,
            "functions": s.functions,
        })).collect::<Vec<_>>(),
    })
}

/// Ask a plugin approver. An `Ok` verdict allows; `Err` refuses, with the
/// reason. The decision is recorded with people's and models' decisions.
pub(crate) async fn ask(
    state: &State,
    approver: &crate::approvals::ApproverConfig,
    ctx: &Ctx<'_>,
    statements: &[Statement],
    need: &ApprovalNeed,
) -> crate::approvals::Answer {
    let config = state.config();
    let name = approver.plugin.clone().unwrap_or_default();
    let timeout = approver
        .timeout_seconds
        .unwrap_or(config.approvals.timeout_seconds);
    let approval_id = format!("a-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let mut params = request_params(ctx, statements);
    params["approval_id"] = json!(approval_id);
    params["approver"] = json!(approver.name);
    params["rule"] = json!(need.rule);
    params["reason"] = json!(need.reason);
    let created = store::now_ms();
    let plugin = current().and_then(|h| h.get(&name).cloned());
    let outcome = match plugin {
        Some(p) => {
            p.approve(params, Duration::from_secs(timeout), ctx.live)
                .await
        }
        None => Approved::Failed(format!("plugin '{name}' is not running in this process")),
    };
    let by_plugin = format!("plugin:{name}");
    let (status, by, note, verdict) = match outcome {
        Approved::Allow(note) => ("allowed", by_plugin, note, Ok(())),
        Approved::Deny(note) => {
            let why = format!(
                "denied by plugin approver '{}'{}",
                approver.name,
                note.as_ref().map(|n| format!(": {n}")).unwrap_or_default()
            );
            ("denied", by_plugin, note, Err(why))
        }
        Approved::Failed(e) => {
            let why = format!(
                "plugin approver '{}' failed ({e}); failing closed",
                approver.name
            );
            ("denied", "ariodb".to_string(), Some(e), Err(why))
        }
        Approved::Withdrawn(why) => (
            "expired",
            "ariodb".to_string(),
            Some(why.to_string()),
            Err(format!("{why}, so the request was withdrawn")),
        ),
    };
    let recorded = state.db.insert_approval(&Approval {
        id: approval_id,
        created_ms: created,
        expires_ms: created + timeout as i64 * 1000,
        agent: ctx.agent.name.clone(),
        session: ctx.session.to_string(),
        sql: statements
            .iter()
            .map(|s| s.sql.as_str())
            .collect::<Vec<_>>()
            .join("; "),
        rule: need.rule.clone(),
        approver: approver.name.clone(),
        reason: need.reason.clone(),
        status: status.to_string(),
        decided_by: Some(by.clone()),
        note,
        decided_ms: Some(store::now_ms()),
    });
    if let Err(e) = recorded {
        eprintln!(
            "ariodb: could not record plugin approver '{}''s decision: {e}",
            approver.name
        );
    }
    crate::approvals::Answer {
        by: (status != "expired").then_some(by),
        verdict,
    }
}

/// Ask facts plugins about one statement, all at once. Each answer, or why
/// there is none, goes to the rules.
pub async fn facts(names: &[String], ctx: &Ctx<'_>, statement: &Statement) -> PluginFacts {
    let params = request_params(ctx, std::slice::from_ref(statement));
    let host = current();
    let asks = names.iter().map(|name| {
        let plugin = host.as_ref().and_then(|h| h.get(name).cloned());
        let params = params.clone();
        async move {
            let answer = match plugin {
                Some(p) => p.facts(params).await,
                None => Err(format!("plugin '{name}' is not running in this process")),
            };
            (name.clone(), answer)
        }
    });
    futures::future::join_all(asks).await.into_iter().collect()
}

/// Tell every notifier about an event. Never waits.
pub fn notify(event: &str, details: Value) {
    // The Splunk exporter hears of approvals and undo the same way.
    crate::splunk::event(event, &details);
    let Some(host) = current() else {
        return;
    };
    let message = json!({ "event": event, "at_ms": store::now_ms(), "details": details });
    for p in &host.plugins {
        p.enqueue(&message);
    }
}

// ---------------------------------------------------------------------------
// `ariodb plugin list` and `ariodb plugin test`.

/// Start each configured plugin once and show what it says it can do.
pub async fn list_command(config: &crate::config::Config) -> Result<(), String> {
    if config.plugins.is_empty() {
        println!("no plugins configured");
        return Ok(());
    }
    let dir = Path::new(&config.journal.dir);
    let mut failed = 0;
    for p in &config.plugins {
        println!("{:<16} {}", p.name, p.command.join(" "));
        match open(p, dir).await {
            Ok(session) => {
                if let Some(h) = session.link.hello.get() {
                    let caps = h.capabilities.names();
                    println!(
                        "{:<16} {} {}: {}",
                        "",
                        h.name,
                        h.version,
                        if caps.is_empty() {
                            "no capabilities".to_string()
                        } else {
                            caps.join(", ")
                        }
                    );
                }
                session.close().await;
            }
            Err(e) => {
                println!("{:<16} could not start: {e}", "");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        return Err(format!("{failed} plugin(s) did not start"));
    }
    Ok(())
}

/// Start one plugin, send it a sample call for each capability it
/// declared, and print what came back. Samples carry `"test": true`.
pub async fn test_command(config: &crate::config::Config, name: &str) -> Result<(), String> {
    let p = config
        .plugins
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("plugin '{name}' is not defined in [[plugins]]"))?;
    let session = open(p, Path::new(&config.journal.dir)).await?;
    let link = session.link.clone();
    let hello = link.hello.get().cloned().expect("handshake done");
    println!("started: {} {}", hello.name, hello.version);
    let caps = hello.capabilities;
    let mut failures = 0;
    let mut report = |what: &str, result: Result<String, String>| match result {
        Ok(text) => println!("  ok    {what}: {text}"),
        Err(e) => {
            failures += 1;
            println!("  FAIL  {what}: {e}");
        }
    };
    if caps.names().is_empty() {
        report("capabilities", Err("the plugin declared none".to_string()));
    }
    let sample = json!({
        "test": true,
        "agent": "ariodb-plugin-test",
        "session": "test",
        "database": "test",
        "engine": "postgres",
        "statements": [{ "sql": "SELECT 1", "kind": "read", "tables": [], "functions": [] }],
    });
    let timeout = p.timeout();
    if caps.approver {
        let mut params = sample.clone();
        params["approval_id"] = json!("a-test");
        params["approver"] = json!("test");
        params["rule"] = json!("test");
        params["reason"] = json!("ariodb plugin test");
        let answer = link.call("approve", params, timeout).await;
        report(
            "approve",
            answer.and_then(|v| match parse_verdict(&v)? {
                Verdict::Allow(note) => Ok(format!(
                    "allow{}",
                    note.map(|n| format!(" ({n})")).unwrap_or_default()
                )),
                Verdict::Deny(note) => Ok(format!(
                    "deny{}",
                    note.map(|n| format!(" ({n})")).unwrap_or_default()
                )),
            }),
        );
    }
    if caps.facts {
        let answer = link.call("facts", sample.clone(), timeout).await;
        report(
            "facts",
            answer.and_then(|v| {
                if v.is_object() {
                    Ok(v.to_string())
                } else {
                    Err("the answer must be a JSON object".to_string())
                }
            }),
        );
    }
    if caps.notifier {
        let event =
            json!({ "event": "test", "at_ms": store::now_ms(), "details": { "test": true } });
        let sent = link
            .outbox
            .send(Out::Line(notification("event", event)))
            .await
            .map(|_| "sent a test event (notifications get no answer)".to_string())
            .map_err(|_| "the plugin is not running".to_string());
        report("notifier", sent);
    }
    if caps.audit_sink {
        let entry = json!({
            "id": 0, "at_ms": store::now_ms(), "session": "test", "agent": "ariodb-plugin-test",
            "sql": "SELECT 1", "kind": "read", "tables": [], "outcome": "allowed", "rows": 1,
            "reason": null, "rule": null, "latency_ms": 1, "engine": "postgres", "database": "test",
            "prev": "", "hash": "",
        });
        let answer = link
            .call(
                "audit",
                json!({ "test": true, "entries": [entry] }),
                timeout,
            )
            .await;
        report(
            "audit",
            answer.and_then(|v| match v.get("ack").and_then(Value::as_i64) {
                Some(0) => Ok("acknowledged".to_string()),
                _ => Err(format!("expected {{\"ack\": 0}}, got {v}")),
            }),
        );
    }
    session.close().await;
    if failures > 0 {
        return Err(format!("{failures} check(s) failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames(input: &[u8], cap: usize) -> Vec<Frame> {
        let mut r = BufReader::with_capacity(4, input);
        let mut out = Vec::new();
        // As the stderr relay does: after a long line, skip the rest of it.
        while let Some(f) = read_frame(&mut r, cap).await.unwrap() {
            if f == Frame::TooLong {
                skip_line(&mut r).await.unwrap();
            }
            out.push(f);
        }
        out
    }

    #[tokio::test]
    async fn frames_are_lines_with_a_length_cap() {
        let line = |s: &str| Frame::Line(s.as_bytes().to_vec());
        assert_eq!(
            frames(b"{\"a\":1}\n{\"b\":2}\r\n\nlast", 64).await,
            vec![line("{\"a\":1}"), line("{\"b\":2}"), line(""), line("last")]
        );
        // A line over the cap is reported once it passes the cap; after
        // skipping the rest, the next line is read normally. Memory never
        // holds more than the cap.
        assert_eq!(
            frames(b"0123456789abcdef\nok\n", 8).await,
            vec![Frame::TooLong, line("ok")]
        );
        assert_eq!(frames(b"12345678\n", 8).await, vec![line("12345678")]);
        assert_eq!(frames(b"123456789", 8).await, vec![Frame::TooLong]);
        assert!(frames(b"", 8).await.is_empty());
    }

    #[test]
    fn reads_answers_requests_and_rubbish() {
        assert_eq!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":7,"result":{"verdict":"allow"}}"#),
            Incoming::Answer {
                id: 7,
                result: Ok(json!({"verdict": "allow"}))
            }
        );
        assert!(matches!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"boom\u001b[31m"}}"#),
            Incoming::Answer { id: 7, result: Err(e) } if e == "plugin error -32000: boom[31m"
        ));
        assert!(matches!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":7,"result":1,"error":{}}"#),
            Incoming::Answer {
                id: 7,
                result: Err(_)
            }
        ));
        // A string id is not one of ariodb's.
        assert!(matches!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":"7","result":1}"#),
            Incoming::Malformed(_)
        ));
        assert!(matches!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":1,"method":"sampling"}"#),
            Incoming::Request { .. }
        ));
        assert!(matches!(
            parse_incoming(br#"{"jsonrpc":"2.0","method":"log"}"#),
            Incoming::Notification { .. }
        ));
        assert!(matches!(
            parse_incoming(b"debug: hello"),
            Incoming::Malformed(_)
        ));
        assert!(matches!(parse_incoming(b"[1,2]"), Incoming::Malformed(_)));
        assert!(matches!(
            parse_incoming(br#"{"id":1,"result":1}"#),
            Incoming::Malformed(_)
        ));
    }

    #[test]
    fn checks_handshakes_and_verdicts() {
        let hello = parse_hello(&json!({
            "name": "clock", "version": "1.0", "protocol_version": 1,
            "capabilities": { "approver": true, "facts": true, "future_thing": true }
        }))
        .unwrap();
        assert_eq!(hello.capabilities.names(), vec!["approver", "facts"]);
        assert!(
            parse_hello(
                &json!({"name": "x", "version": "1", "protocol_version": 2, "capabilities": {}})
            )
            .is_err()
        );
        assert!(parse_hello(&json!({"name": "x", "version": "1"})).is_err());
        assert!(
            parse_hello(&json!({"name": "x", "version": "1", "capabilities": {"approver": "yes"}}))
                .is_err()
        );

        assert_eq!(
            parse_verdict(&json!({"verdict": "allow"})),
            Ok(Verdict::Allow(None))
        );
        assert_eq!(
            parse_verdict(&json!({"verdict": "deny", "note": "after hours"})),
            Ok(Verdict::Deny(Some("after hours".into())))
        );
        for bad in [
            json!({"verdict": "ALLOW"}),
            json!({"verdict": true}),
            json!({}),
            json!("allow"),
            json!({"verdict": "allow", "note": 3}),
        ] {
            assert!(parse_verdict(&bad).is_err(), "{bad}");
        }
        assert_eq!(clean(&"x".repeat(5), 3), "xxx…");
        assert_eq!(clean("a\nb\u{1b}c", 10), "abc");
    }

    #[test]
    fn requests_are_single_lines() {
        let (outbox, mut rx) = mpsc::channel(4);
        let link = Link {
            name: "t".into(),
            outbox,
            pending: Pending::default(),
            next_id: AtomicU64::new(1),
            hello: OnceLock::new(),
        };
        let sql = "SELECT 1;\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"verdict\":\"allow\"}}\n";
        let (id, _rx) = link.request("approve", json!({ "sql": sql })).unwrap();
        let Ok(Out::Line(line)) = rx.try_recv() else {
            panic!("no line")
        };
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], id);
        assert_eq!(v["params"]["sql"], sql);
        // Calls before the handshake, or for undeclared capabilities, fail.
        assert!(link.capable(Cap::Approver).is_err());
        let _ = link.hello.set(Hello {
            name: "t".into(),
            version: "1".into(),
            capabilities: Capabilities {
                facts: true,
                ..Default::default()
            },
        });
        assert!(link.capable(Cap::Facts).is_ok());
        assert!(
            link.capable(Cap::Approver)
                .unwrap_err()
                .contains("did not declare the approver")
        );
        // A full outbox (a plugin that stopped reading) fails the call at once.
        for _ in 0..4 {
            link.request("facts", json!({})).unwrap();
        }
        assert!(
            link.request("facts", json!({}))
                .unwrap_err()
                .contains("not reading")
        );
    }

    #[tokio::test]
    async fn answers_reach_only_the_request_they_name() {
        let (outbox, _rx) = mpsc::channel(4);
        let pending = Pending::default();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        pending.lock().unwrap().insert(1, tx1);
        pending.lock().unwrap().insert(2, tx2);
        let output = concat!(
            "not json, ignored\n",
            r#"{"jsonrpc":"2.0","id":99,"result":{"verdict":"allow"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"result":{"verdict":"deny"}}"#,
            "\n",
        );
        let why = read_loop(
            "t".into(),
            BufReader::new(output.as_bytes()),
            pending.clone(),
            outbox,
        )
        .await;
        assert_eq!(why, "closed its output");
        assert_eq!(rx2.await.unwrap(), Ok(json!({"verdict": "deny"})));
        // Request 1 got no answer; it hears so as soon as the output ends.
        assert!(rx1.await.is_err());
        assert!(pending.lock().unwrap().is_empty());
    }

    fn have_python() -> bool {
        std::process::Command::new("python3")
            .arg("-V")
            .output()
            .is_ok()
    }

    /// A plugin in Python: allows unless the SQL says otherwise.
    const SCRIPT: &str = r#"
import json, os, sys, time
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method, params = msg["method"], msg.get("params", {})
    if method == "initialize":
        result = {"name": "unit", "version": "0.1", "protocol_version": 1,
                  "capabilities": {"approver": True, "facts": True}}
    elif method == "approve":
        sql = params["statements"][0]["sql"]
        if "crash" in sql:
            os._exit(3)
        if "slow" in sql:
            time.sleep(3)
        if "bad" in sql:
            result = {"verdict": "maybe"}
        else:
            result = {"verdict": "deny" if "deny" in sql else "allow", "note": "from unit"}
    elif method == "facts":
        result = {"env": os.environ.get("UNIT_ENV"), "leaked": os.environ.get("UNIT_SECRET_LEAK")}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"#;

    fn config(dir: &Path) -> PluginConfig {
        let script = dir.join("unit_plugin.py");
        std::fs::write(&script, SCRIPT).unwrap();
        PluginConfig {
            name: "unit".into(),
            command: vec!["python3".into(), "-I".into(), script.display().to_string()],
            env: HashMap::from([("UNIT_ENV".to_string(), "set".to_string())]),
            pass_env: Vec::new(),
            secret_env: HashMap::new(),
            timeout_ms: Some(2_000),
            facts_cache_ms: 0,
        }
    }

    fn approve_params(sql: &str) -> Value {
        json!({ "approval_id": "a-unit", "statements": [{ "sql": sql }] })
    }

    #[tokio::test]
    async fn supervised_plugins_answer_fail_closed_and_restart() {
        if !have_python() {
            eprintln!("skipped: python3 is not installed");
            return;
        }
        // SAFETY: only this test reads this variable.
        unsafe { std::env::set_var("UNIT_SECRET_LEAK", "not-a-real-secret") };
        let dir = std::env::temp_dir().join(format!("ariodb-plugins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let host = Host::start(&[config(&dir)], &dir, Roles { audit_sink: false });
        host.settle(Duration::from_secs(10)).await;
        let p = host.get("unit").unwrap().clone();
        let t = Duration::from_secs(2);
        assert!(
            matches!(p.approve(approve_params("SELECT 1"), t, None).await, Approved::Allow(Some(n)) if n == "from unit")
        );
        assert!(matches!(
            p.approve(approve_params("SELECT 'deny'"), t, None).await,
            Approved::Deny(_)
        ));
        assert!(
            matches!(p.approve(approve_params("SELECT 'bad'"), t, None).await, Approved::Failed(e) if e.contains("answered approve wrongly"))
        );
        // Only the given environment reaches the plugin.
        let facts = p.facts(json!({"statements": []})).await.unwrap();
        assert_eq!(facts, json!({"env": "set", "leaked": null}));
        assert!(
            matches!(p.approve(approve_params("SELECT 'slow'"), Duration::from_secs(1), None).await, Approved::Failed(e) if e.contains("within 1 seconds"))
        );
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        // An agent that leaves withdraws its request.
        let live = Liveness::default();
        live.gone.store(true, Ordering::SeqCst);
        assert!(matches!(
            p.approve(approve_params("SELECT 'slow'"), t, Some(&live))
                .await,
            Approved::Withdrawn(_)
        ));
        // A crash refuses the request in flight, and the plugin is down
        // (refusing) until it has restarted.
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        assert!(
            matches!(p.approve(approve_params("SELECT 'crash'"), t, None).await, Approved::Failed(e) if e.contains("stopped before answering"))
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            matches!(p.approve(approve_params("SELECT 1"), t, None).await, Approved::Failed(e) if e.contains("restarting"))
        );
        for _ in 0..50 {
            if p.link().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(matches!(
            p.approve(approve_params("SELECT 1"), t, None).await,
            Approved::Allow(_)
        ));
        assert_eq!(host.statuses()[0].restarts, 1);
        let pid = host.statuses()[0].pid.unwrap();
        host.stop().await;
        assert_eq!(host.statuses()[0].state, "stopped");
        // SAFETY: kill(2) with signal 0 only checks the process exists.
        assert_ne!(
            unsafe { libc::kill(pid as i32, 0) },
            0,
            "plugin outlived stop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_endless_line_ends_the_session_at_the_cap() {
        // A plugin stuck writing one line that never ends is a protocol
        // error as soon as the line passes the cap, so it is restarted
        // rather than left wedged with every call timing out.
        let (mut w, r) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            let chunk = vec![b'x'; 64 * 1024];
            while w.write_all(&chunk).await.is_ok() {}
        });
        let (outbox, _rx) = mpsc::channel(4);
        let read = read_loop("t".into(), BufReader::new(r), Pending::default(), outbox);
        let why = tokio::time::timeout(Duration::from_secs(5), read).await;
        writer.abort();
        assert!(why.expect("still reading").contains("longer than"));
    }

    #[test]
    fn the_facts_cache_stays_bounded() {
        // Every distinct statement is a new key, and agents choose their
        // statements: however many arrive within the TTL, the cache holds
        // at most FACTS_CACHE_SWEEP answers.
        let mut cache = HashMap::new();
        let ttl = Duration::from_secs(600);
        for i in 0..FACTS_CACHE_SWEEP * 3 {
            remember(&mut cache, format!("k{i}"), json!({}), ttl);
            assert!(cache.len() <= FACTS_CACHE_SWEEP, "{} entries", cache.len());
        }
        // The newest answer is always kept.
        assert!(cache.contains_key(&format!("k{}", FACTS_CACHE_SWEEP * 3 - 1)));
    }

    /// Approval events honour `[audit] redact_literals`, as statement events do.
    #[tokio::test]
    async fn approval_events_are_redacted_like_the_decisions_log() {
        if !have_python() {
            eprintln!("skipped: python3 is not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("ariodb-plugins-ev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("notifier.py");
        std::fs::write(
            &script,
            r#"
import json, os, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "event":
        with open(os.environ["EVENTS"], "a") as f:
            f.write(json.dumps(msg["params"]) + "\n")
        continue
    if msg["method"] == "initialize":
        result = {"name": "n", "version": "0", "capabilities": {"approver": True, "notifier": True}}
    else:
        result = {"verdict": "allow"}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"#,
        )
        .unwrap();
        let events = dir.join("events.jsonl");
        let toml = format!(
            r#"
            [database]
            url = "postgres://localhost/app"
            [journal]
            dir = "{dir}"
            [audit]
            redact_literals = true
            [[agents]]
            name = "bot"
            access = "read_write"
            tables = ["t"]
            token_env = "ARIODB_TOKEN_TEST"
            [[plugins]]
            name = "n"
            command = ["python3", "-I", "{script}"]
            env = {{ EVENTS = "{events}" }}
            [[approvers]]
            name = "np"
            type = "plugin"
            plugin = "n"
            timeout_seconds = 5
            "#,
            dir = dir.display(),
            script = script.display(),
            events = events.display(),
        );
        let config = crate::config::Config::from_toml(&toml).unwrap();
        let audit = Arc::new(crate::audit::AuditLog::open(&dir, &config.audit).unwrap());
        let host = Host::start(&config.plugins, &dir, Roles { audit_sink: false });
        host.settle(Duration::from_secs(10)).await;
        install(host.clone());
        let state = State::new(
            crate::config::Config::from_toml(&toml).unwrap(),
            dir.join("ariodb.toml"),
            audit,
        )
        .unwrap();
        let statements =
            crate::classify::classify("UPDATE t SET card = 'not-a-real-card-4242' WHERE id = 7")
                .unwrap();
        let ctx = Ctx {
            agent: &config.agents[0],
            session: "s-test",
            database: "app",
            live: None,
        };
        let need = ApprovalNeed {
            rule: "r".into(),
            approvers: vec!["np".into()],
            reason: "held".into(),
        };
        let verdict = crate::approvals::require(&state, &ctx, &statements, &need).await;
        let mut text = String::new();
        for _ in 0..100 {
            text = std::fs::read_to_string(&events).unwrap_or_default();
            if text.contains("approval_decided") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        uninstall();
        host.stop().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            verdict.as_ref().ok(),
            Some(&vec!["plugin:n".to_string()]),
            "{verdict:?}"
        );
        assert!(text.contains("approval_requested"), "{text}");
        assert!(!text.contains("not-a-real-card-4242"), "{text}");
    }

    #[test]
    fn validates_plugin_references() {
        let base = r#"
            [database]
            url = "postgres://localhost/app"

            [[plugins]]
            name = "clock"
            command = ["python3", "clock.py"]
        "#;
        let load =
            |extra: &str| crate::config::Config::from_toml(&format!("{base}\n{extra}")).map(|_| ());
        assert!(load("").is_ok());
        let ok = r#"
            [[approvers]]
            name = "after-hours"
            type = "plugin"
            plugin = "clock"

            [[rules]]
            name = "freeze"
            condition = "plugin.clock.freeze"
            verdict = "approve"
            approve = ["after-hours"]
        "#;
        assert!(load(ok).is_ok());
        let err = |extra: &str| load(extra).unwrap_err().to_string();
        assert!(
            err(&ok.replace("plugin = \"clock\"", "plugin = \"nope\""))
                .contains("uses plugin 'nope'")
        );
        assert!(
            err(&ok.replace("plugin.clock.freeze", "plugin.other.freeze"))
                .contains("reads facts from plugin 'other'")
        );
        assert!(err("[[plugins]]\nname = \"clock\"\ncommand = [\"x\"]").contains("listed twice"));
        assert!(
            err("[[plugins]]\nname = \"my-plugin\"\ncommand = [\"x\"]")
                .contains("letters, digits and underscores")
        );
        assert!(err("[[plugins]]\nname = \"empty\"\ncommand = []").contains("needs a command"));
        assert!(
            err("[[plugins]]\nname = \"t\"\ncommand = [\"x\"]\ntimeout_ms = 0")
                .contains("at least 1")
        );
        assert!(
            err("[[plugins]]\nname = \"e\"\ncommand = [\"x\"]\nenv = { \"A=B\" = \"c\" }")
                .contains("not an environment variable")
        );
    }
}
