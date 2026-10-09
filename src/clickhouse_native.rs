//! ClickHouse's native TCP protocol (what clickhouse-client speaks).
//!
//! ariodb terminates the handshake on both sides: the agent logs in with
//! its name and token, and ariodb logs in to ClickHouse with its own
//! credentials. Both sides are held to the same protocol revision (capped at
//! one ariodb fully understands), so after the handshake the server's
//! replies are relayed byte for byte.
//!
//! Each Query packet is parsed, judged like any other statement, and
//! forwarded with a time limit added to its settings, and reads with
//! `readonly = 2`. An INSERT's rows follow the query as data blocks: ariodb
//! reads every block (`clickhouse_blocks`), counts the rows against the
//! write limit, and holds the blocks back until the last has arrived, so an
//! insert over the limit is stopped before ClickHouse has any of it.
//! External tables are refused.

use crate::chsql;
use crate::clickhouse_blocks::{Frames, MAX_HELD, Problem, read_data};
use crate::classify::Kind;
use crate::gate::{self, Ctx, State};
use crate::limits::{Admission, Limiter};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// The highest protocol revision ariodb speaks.
const MAX_REVISION: u64 = 54470;

const REV_CLIENT_INFO: u64 = 54032;
const REV_TIMEZONE: u64 = 54058;
const REV_QUOTA_KEY_IN_CLIENT_INFO: u64 = 54060;
const REV_DISPLAY_NAME: u64 = 54372;
const REV_VERSION_PATCH: u64 = 54401;
const REV_SETTINGS_AS_STRINGS: u64 = 54429;
const REV_INTERSERVER_SECRET: u64 = 54441;
const REV_OPENTELEMETRY: u64 = 54442;
const REV_FORWARDED_FOR: u64 = 54443;
const REV_REFERER: u64 = 54447;
const REV_DISTRIBUTED_DEPTH: u64 = 54448;
const REV_INITIAL_QUERY_START_TIME: u64 = 54449;
const REV_PARALLEL_REPLICAS: u64 = 54453;
const REV_ADDENDUM: u64 = 54458;
const REV_PARAMETERS: u64 = 54459;
const REV_PASSWORD_RULES: u64 = 54461;
const REV_NONCE: u64 = 54462;
const REV_CHUNKED: u64 = 54470;

pub async fn serve(state: Arc<State>) -> Result<(), String> {
    let config = state.config();
    if config.clickhouse.native_listen.is_empty() {
        return Ok(());
    }
    let listener = TcpListener::bind(&config.clickhouse.native_listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.clickhouse.native_listen))?;
    println!(
        "ariodb: clickhouse-client can connect to {}",
        config.clickhouse.native_listen
    );
    let acceptor = config.clickhouse_tls()?;
    let limiter = Limiter::new("ClickHouse native", &config.limits);
    loop {
        let (socket, _) = crate::limits::accept(&listener, &limiter).await;
        limiter.update(&state.config().limits);
        let admission = limiter.admit();
        if let Admission::Drop = admission {
            continue;
        }
        // TLS, the client's Hello and its login share one deadline.
        let deadline = tokio::time::Instant::now() + limiter.handshake_timeout();
        let (state, acceptor) = (state.clone(), acceptor.clone());
        tokio::spawn(async move {
            let result = match acceptor {
                // TLS only when configured, like ClickHouse's own secure port.
                Some(acc) => match tokio::time::timeout_at(deadline, acc.accept(socket)).await {
                    Ok(Ok(tls)) => handle(tls, state, admission, deadline).await,
                    _ => Ok(()),
                },
                None => handle(socket, state, admission, deadline).await,
            };
            if let Err(e) = result
                && !e.contains("early eof")
                && !e.contains("connection reset")
            {
                eprintln!("ariodb: ClickHouse native connection ended: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Reading and writing ClickHouse's basic encodings.

pub(crate) struct Rd<R> {
    pub(crate) inner: R,
    /// Every byte read since the last `take`, so a packet can be forwarded
    /// as read.
    pub(crate) taken: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> Rd<R> {
    pub(crate) async fn u8(&mut self) -> Result<u8, String> {
        let b = self.inner.read_u8().await.map_err(|e| e.to_string())?;
        self.taken.push(b);
        Ok(b)
    }
    pub(crate) async fn bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        if n > 64 << 20 {
            return Err("field too large".into());
        }
        let mut buf = vec![0u8; n];
        self.inner
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        self.taken.extend_from_slice(&buf);
        Ok(buf)
    }
    /// At most nine bytes, all any client sends. A longer one is refused
    /// rather than risk reading it differently from ClickHouse.
    async fn varint(&mut self) -> Result<u64, String> {
        let mut out = 0u64;
        for shift in (0..63).step_by(7) {
            let b = self.u8().await?;
            out |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(out);
            }
        }
        Err("varint too long".into())
    }
    async fn string(&mut self) -> Result<String, String> {
        let n = self.varint().await? as usize;
        Ok(String::from_utf8_lossy(&self.bytes(n).await?).into_owned())
    }
    /// A string from before the client has logged in: at most 64 KiB.
    pub(crate) async fn short_string(&mut self) -> Result<String, String> {
        let n = self.varint().await? as usize;
        if n > 64 << 10 {
            return Err("login field too large".into());
        }
        Ok(String::from_utf8_lossy(&self.bytes(n).await?).into_owned())
    }
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.taken)
    }
}

pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// The exception code for a connection over a limit; see clickhouse.rs.
const TOO_MANY_CONNECTIONS: i32 = crate::clickhouse::TOO_MANY_CONNECTIONS as i32;

/// A server Exception packet, as the client expects to read one.
fn exception_packet(code: i32, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, 2); // Exception
    out.extend_from_slice(&code.to_le_bytes());
    put_string(&mut out, "DB::Exception");
    put_string(&mut out, &format!("ariodb: {message}"));
    put_string(&mut out, "");
    out.push(0); // no nested exception
    out
}

// ---------------------------------------------------------------------------
// The connection.

struct Hello {
    client_name: String,
    major: u64,
    minor: u64,
    revision: u64,
    database: String,
    user: String,
    password: String,
}

async fn read_hello<R: tokio::io::AsyncRead + Unpin>(c: &mut Rd<R>) -> Result<Hello, String> {
    if c.varint().await? != 0 {
        return Err("expected Hello".into());
    }
    // Nothing is known about the client yet, so its Hello may not make
    // ariodb allocate much.
    Ok(Hello {
        client_name: c.short_string().await?,
        major: c.varint().await?,
        minor: c.varint().await?,
        revision: c.varint().await?,
        database: c.short_string().await?,
        user: c.short_string().await?,
        password: c.short_string().await?,
    })
}

async fn handle<S>(
    socket: S,
    state: Arc<State>,
    admission: Admission,
    deadline: tokio::time::Instant,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = state.config();
    let (client_read, client_write) = tokio::io::split(socket);
    let client_write = Arc::new(Mutex::new(client_write));
    let mut c = Rd {
        inner: BufReader::new(client_read),
        taken: Vec::new(),
    };

    // 1. The client's Hello, in time. Over the limit, the client is told
    // so in answer to it; quietly, as refusals are logged per burst.
    let hello = tokio::time::timeout_at(deadline, read_hello(&mut c)).await;
    let mut slot = match admission {
        Admission::Admitted(slot) => slot,
        _ => {
            if let Ok(Ok(_)) = hello {
                let refusal = exception_packet(TOO_MANY_CONNECTIONS, "too many connections");
                let mut w = client_write.lock().await;
                let _ = tokio::time::timeout_at(deadline, async {
                    let _ = w.write_all(&refusal).await;
                    let _ = w.shutdown().await;
                })
                .await;
            }
            return Ok(());
        }
    };
    let mut hello = match hello {
        Err(_) => return Ok(()), // too slow: cut off
        Ok(hello) => hello?,
    };
    // Name the database even when the client does not, so ClickHouse
    // resolves table names in the database ariodb judges them in.
    if hello.database.is_empty() {
        hello.database = "default".to_string();
    }
    c.take();
    let send = |bytes: Vec<u8>| {
        let w = client_write.clone();
        async move {
            w.lock()
                .await
                .write_all(&bytes)
                .await
                .map_err(|e| e.to_string())
        }
    };

    let agent = match crate::clickhouse::clickhouse_agent(&config, &hello.user, &hello.password) {
        Ok(a) => a,
        Err(why) => {
            send(exception_packet(516, &format!("{}: {why}", hello.user))).await?;
            return Ok(());
        }
    };
    if let Err(limit) = slot.agent(&agent.name) {
        let message = format!(
            "agent '{}' already has {limit} connections open, the most it may",
            agent.name
        );
        send(exception_packet(TOO_MANY_CONNECTIONS, &message)).await?;
        return Ok(());
    }

    // 2. Log in to ClickHouse at a revision both sides can share.
    let our_revision = hello.revision.min(MAX_REVISION);
    let native_addr = config.clickhouse_native_addr()?;
    let upstream = TcpStream::connect(&native_addr)
        .await
        .map_err(|e| format!("cannot reach ClickHouse at {native_addr}: {e}"))?;
    let _ = upstream.set_nodelay(true);
    let (up_read, mut up_write) = upstream.into_split();
    let mut u = Rd {
        inner: BufReader::new(up_read),
        taken: Vec::new(),
    };
    let password = config.clickhouse_password()?;
    let mut out = Vec::new();
    put_varint(&mut out, 0);
    put_string(&mut out, &format!("ariodb for {}", hello.client_name));
    put_varint(&mut out, hello.major);
    put_varint(&mut out, hello.minor);
    put_varint(&mut out, our_revision);
    put_string(&mut out, &hello.database);
    put_string(&mut out, &config.clickhouse.user);
    put_string(&mut out, &password);
    up_write.write_all(&out).await.map_err(|e| e.to_string())?;

    let packet = u.varint().await?;
    if packet == 2 {
        // ClickHouse refused ariodb's login. Pass the exception on.
        let mut rest = u.take();
        let mut tail = vec![0u8; 4096];
        let n = u.inner.read(&mut tail).await.unwrap_or(0);
        rest.extend_from_slice(&tail[..n]);
        send(rest).await?;
        return Ok(());
    }
    if packet != 0 {
        return Err(format!(
            "unexpected packet {packet} from ClickHouse during login"
        ));
    }
    let server_name = u.string().await?;
    let server_major = u.varint().await?;
    let server_minor = u.varint().await?;
    let server_revision = u.varint().await?;
    let shared = our_revision.min(server_revision);
    let timezone = if shared >= REV_TIMEZONE {
        u.string().await?
    } else {
        String::new()
    };
    let display_name = if shared >= REV_DISPLAY_NAME {
        u.string().await?
    } else {
        String::new()
    };
    let patch = if shared >= REV_VERSION_PATCH {
        u.varint().await?
    } else {
        0
    };
    if shared >= REV_CHUNKED {
        let _send = u.string().await?;
        let _recv = u.string().await?;
    }
    if shared >= REV_PASSWORD_RULES {
        let n = u.varint().await?;
        for _ in 0..n {
            u.string().await?;
            u.string().await?;
        }
    }
    if shared >= REV_NONCE {
        u.bytes(8).await?;
    }
    u.take();
    // Our addendum to ClickHouse, matching the revision we announced.
    if our_revision >= REV_ADDENDUM {
        let mut add = Vec::new();
        put_string(&mut add, ""); // quota key
        if our_revision >= REV_CHUNKED {
            put_string(&mut add, "notchunked");
            put_string(&mut add, "notchunked");
        }
        up_write.write_all(&add).await.map_err(|e| e.to_string())?;
    }

    // 3. Our Hello to the client, at the shared revision.
    let advertised = server_revision.min(MAX_REVISION);
    let mut out = Vec::new();
    put_varint(&mut out, 0);
    put_string(&mut out, &format!("{server_name} via ariodb"));
    put_varint(&mut out, server_major);
    put_varint(&mut out, server_minor);
    put_varint(&mut out, advertised);
    if shared >= REV_TIMEZONE {
        put_string(&mut out, &timezone);
    }
    if shared >= REV_DISPLAY_NAME {
        put_string(&mut out, &display_name);
    }
    if shared >= REV_VERSION_PATCH {
        put_varint(&mut out, patch);
    }
    if shared >= REV_CHUNKED {
        put_string(&mut out, "notchunked");
        put_string(&mut out, "notchunked");
    }
    if shared >= REV_PASSWORD_RULES {
        put_varint(&mut out, 0);
    }
    if shared >= REV_NONCE {
        out.extend_from_slice(&rand::random::<u64>().to_le_bytes());
    }
    send(out).await?;
    // The client's addendum.
    if shared >= REV_ADDENDUM {
        c.string().await?; // quota key
        if shared >= REV_CHUNKED {
            let send_mode = c.string().await?;
            let recv_mode = c.string().await?;
            if send_mode.starts_with("chunked") || recv_mode.starts_with("chunked") {
                send(exception_packet(
                    10,
                    "ariodb speaks the not-chunked protocol only",
                ))
                .await?;
                return Ok(());
            }
        }
        c.take();
    }

    // 4. Server replies flow straight to the client from here on.
    let relay_to = client_write.clone();
    let relay = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match u.inner.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if relay_to.lock().await.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    let session = format!("ch-{}", agent.name);
    let result = client_loop(
        &mut c,
        &mut up_write,
        &send,
        &state,
        &agent,
        &session,
        &hello.database,
        shared,
    )
    .await;
    relay.abort();
    let _ = relay.await;
    drop(up_write); // abandons any insert at ClickHouse
    match result? {
        Some(message) => {
            // An insert was stopped: tell the client, then let it read that
            // before the connection closes.
            send(exception_packet(497, &message)).await?;
            let _ = client_write.lock().await.shutdown().await;
            let mut sink = vec![0u8; 64 << 10];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while let Ok(n) = c.inner.read(&mut sink).await {
                    if n == 0 {
                        break;
                    }
                }
            })
            .await;
            Ok(())
        }
        None => Ok(()),
    }
}

/// Judge and relay the client's packets. Returns the message to refuse an
/// insert with, when one is stopped part way; the connection then closes.
#[allow(clippy::too_many_arguments)]
async fn client_loop<R, F, Fut>(
    c: &mut Rd<R>,
    up: &mut tokio::net::tcp::OwnedWriteHalf,
    send: &F,
    state: &Arc<State>,
    agent: &crate::config::Agent,
    session: &str,
    database: &str,
    rev: u64,
) -> Result<Option<String>, String>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    // A packet already read (its bytes still in `c.taken`) by an insert
    // that ended without data.
    let mut next: Option<u64> = None;
    loop {
        let packet = match next.take() {
            Some(p) => p,
            None => {
                c.take();
                match c.varint().await {
                    Ok(p) => p,
                    Err(_) => return Ok(None), // client went away
                }
            }
        };
        match packet {
            1 => {
                let started = Instant::now();
                let q = read_query(c, rev).await?;
                // The external-tables terminator always follows a Query. The
                // decompression state carries on into an insert's data.
                let mut frames = Frames::new(q.compression == 1);
                let data = read_terminator(c, &mut frames, rev).await;
                let stmt = chsql::classify(&q.sql).map(|mut s| {
                    chsql::scope_to_database(&mut s, database);
                    s
                });
                // "unsupported" marks what this transport cannot carry, as
                // opposed to what the policy refuses, so recorded decisions
                // replay cleanly with `ariodb test`.
                let decision = match (&stmt, &data) {
                    (_, Err(e)) => Err((None, e.clone(), "unsupported", Vec::new())),
                    (Err(e), _) => Err((None, e.clone(), "refused", Vec::new())),
                    (Ok(s), _) => {
                        let countable = match s.kind {
                            Kind::Write => chsql::insert_from_client(&q.sql),
                            _ => Ok(()),
                        };
                        match countable {
                            Err(e) => Err((None, e, "unsupported", Vec::new())),
                            Ok(()) => {
                                let ctx = Ctx { agent, session, database, live: None };
                                gate::check_detailed(state, &ctx, std::slice::from_ref(s))
                                    .await
                                    .map_err(|r| (r.rule.clone(), r.message, "refused", r.decided_by))
                            }
                        }
                    }
                };
                let kind = stmt
                    .as_ref()
                    .map(|s| s.kind.to_string())
                    .unwrap_or_else(|_| "unknown".into());
                let tables = stmt.as_ref().map(|s| s.tables.clone()).unwrap_or_default();
                let record = |outcome: &str,
                              rows: Option<u64>,
                              reason: Option<&str>,
                              rule: Option<&str>,
                              decided_by: &[String]| {
                    state.audit.record(&crate::audit::Entry {
                        session,
                        agent: &agent.name,
                        sql: &q.sql,
                        kind: kind.clone(),
                        tables: &tables,
                        outcome,
                        rows,
                        reason,
                        rule,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        engine: "clickhouse",
                        database,
                        decided_by,
                    });
                };
                let (_, approved) = match decision {
                    Err((rule, message, outcome, by)) => {
                        record(outcome, None, Some(&message), rule.as_deref(), &by);
                        send(exception_packet(497, &message)).await?;
                        continue;
                    }
                    Ok(d) => d,
                };
                let config = state.config();
                let timeout = config.limits.statement_timeout_ms.div_ceil(1000).max(1);
                let insert = matches!(&stmt, Ok(s) if s.kind == Kind::Write);
                let mut out = rebuild_query(&q, timeout, !insert);
                out.extend_from_slice(&data.expect("checked above"));
                up.write_all(&out).await.map_err(|e| e.to_string())?;
                if !insert {
                    record("allowed", None, None, approved.rule.as_deref(), &approved.by);
                    continue;
                }
                let limit = agent
                    .max_rows_per_write
                    .unwrap_or(config.limits.max_rows_per_write);
                match relay_insert(c, up, &mut frames, rev, limit).await {
                    Insert::Sent(rows) => {
                        record("allowed", Some(rows), None, approved.rule.as_deref(), &approved.by)
                    }
                    Insert::Abandoned { reason, next: after } => {
                        record("failed", None, Some(reason), approved.rule.as_deref(), &approved.by);
                        match after {
                            Some(p) => next = Some(p),
                            None => return Ok(None),
                        }
                    }
                    Insert::Stopped { outcome, message, rows } => {
                        record(outcome, rows, Some(&message), approved.rule.as_deref(), &approved.by);
                        return Ok(Some(message));
                    }
                }
            }
            // Cancel and Ping are a single varint: pass them on.
            3 | 4 => {
                let raw = c.take();
                up.write_all(&raw).await.map_err(|e| e.to_string())?;
            }
            2 => {
                send(exception_packet(
                    48,
                    "data outside a query is not supported through ariodb",
                ))
                .await?;
                return Ok(None);
            }
            other => {
                send(exception_packet(
                    48,
                    &format!("client packet {other} is not supported through ariodb"),
                ))
                .await?;
                return Ok(None);
            }
        }
    }
}

/// How an insert's data ended.
enum Insert {
    /// All of it went to ClickHouse: this many rows.
    Sent(u64),
    /// None of it did, and the client stopped sending: ClickHouse refused
    /// the insert, or the client cancelled it or left. `next` is the packet
    /// the client sent instead, if any.
    Abandoned {
        reason: &'static str,
        next: Option<u64>,
    },
    /// ariodb refused it part way. None of it went to ClickHouse.
    Stopped {
        outcome: &'static str,
        message: String,
        rows: Option<u64>,
    },
}

/// Hold back an insert's data blocks, counting their rows, and send them to
/// ClickHouse only once the last has arrived and the total is within the
/// limit. ClickHouse writes each block as it arrives and cannot roll back,
/// so holding them is what makes a stopped insert insert nothing.
async fn relay_insert<R: tokio::io::AsyncRead + Unpin>(
    c: &mut Rd<R>,
    up: &mut tokio::net::tcp::OwnedWriteHalf,
    frames: &mut Frames,
    rev: u64,
    limit: u64,
) -> Insert {
    let mut held = Vec::new();
    let mut rows = 0u64;
    loop {
        c.take();
        let packet = match c.varint().await {
            Ok(p) => p,
            Err(_) => {
                return Insert::Abandoned {
                    reason: "the agent disconnected during the insert; nothing was inserted",
                    next: None,
                };
            }
        };
        match packet {
            2 => {}
            // The client gave up: pass the Cancel on, as nothing was sent.
            3 => {
                return Insert::Abandoned {
                    reason: "the agent cancelled the insert; nothing was inserted",
                    next: Some(3),
                };
            }
            // ClickHouse refused the insert before asking for data, and the
            // client moved on.
            p if held.is_empty() => {
                return Insert::Abandoned {
                    reason: "no data was sent; ClickHouse refused the insert",
                    next: Some(p),
                };
            }
            p => {
                return Insert::Stopped {
                    outcome: "unsupported",
                    message: format!("client packet {p} arrived in the middle of an insert"),
                    rows: None,
                };
            }
        }
        match read_data(c, frames, rev, limit - rows, MAX_HELD - held.len()).await {
            Ok(block) => {
                held.extend(c.take());
                if block.columns == 0 {
                    break;
                }
                rows += block.rows;
            }
            Err(Problem::TooManyRows(n)) => {
                let total = rows + n;
                return Insert::Stopped {
                    outcome: "rolled_back",
                    message: format!(
                        "nothing was inserted: the insert sends at least {total} rows; the limit is {limit}"
                    ),
                    rows: Some(total),
                };
            }
            Err(Problem::Unreadable(e)) => {
                return Insert::Stopped {
                    outcome: "unsupported",
                    message: format!("nothing was inserted: {e}"),
                    rows: None,
                };
            }
        }
    }
    if let Err(e) = up.write_all(&held).await {
        return Insert::Stopped {
            outcome: "failed",
            message: format!("cannot reach ClickHouse: {e}"),
            rows: None,
        };
    }
    Insert::Sent(rows)
}

/// A parsed Query packet, kept as raw pieces so it can be rebuilt with
/// different settings.
struct Query {
    /// Packet type through the end of client info.
    head: Vec<u8>,
    settings: Vec<(String, u64, String)>,
    /// Interserver hash through the end of the packet.
    tail: Vec<u8>,
    sql: String,
    compression: u64,
}

async fn read_settings<R: tokio::io::AsyncRead + Unpin>(
    c: &mut Rd<R>,
    rev: u64,
) -> Result<Vec<(String, u64, String)>, String> {
    if rev < REV_SETTINGS_AS_STRINGS {
        return Err("client protocol too old: settings must be sent as strings".into());
    }
    let mut out = Vec::new();
    loop {
        let name = c.string().await?;
        if name.is_empty() {
            return Ok(out);
        }
        let flags = c.varint().await?;
        let value = c.string().await?;
        out.push((name, flags, value));
    }
}

async fn read_query<R: tokio::io::AsyncRead + Unpin>(
    c: &mut Rd<R>,
    rev: u64,
) -> Result<Query, String> {
    c.string().await?; // query id
    if rev >= REV_CLIENT_INFO {
        let kind = c.u8().await?;
        if kind != 0 {
            c.string().await?; // initial user
            c.string().await?; // initial query id
            c.string().await?; // initial address
            if rev >= REV_INITIAL_QUERY_START_TIME {
                c.bytes(8).await?;
            }
            let interface = c.u8().await?;
            if interface == 1 {
                c.string().await?; // os user
                c.string().await?; // hostname
                c.string().await?; // client name
                c.varint().await?;
                c.varint().await?;
                c.varint().await?;
            } else if interface == 2 {
                c.u8().await?;
                c.string().await?;
                if rev >= REV_FORWARDED_FOR {
                    c.string().await?;
                }
                if rev >= REV_REFERER {
                    c.string().await?;
                }
            }
            if rev >= REV_QUOTA_KEY_IN_CLIENT_INFO {
                c.string().await?;
            }
            if rev >= REV_DISTRIBUTED_DEPTH {
                c.varint().await?;
            }
            if interface == 1 && rev >= REV_VERSION_PATCH {
                c.varint().await?;
            }
            if rev >= REV_OPENTELEMETRY && c.u8().await? != 0 {
                c.bytes(16).await?; // trace id
                c.bytes(8).await?; // span id
                c.string().await?; // tracestate
                c.u8().await?; // flags
            }
            if rev >= REV_PARALLEL_REPLICAS {
                c.varint().await?;
                c.varint().await?;
                c.varint().await?;
            }
        }
    }
    let head = c.take();
    let settings = read_settings(c, rev).await?;
    c.take();
    if rev >= REV_INTERSERVER_SECRET {
        c.string().await?;
    }
    c.varint().await?; // stage
    let compression = c.varint().await?;
    let sql = c.string().await?;
    if rev >= REV_PARAMETERS {
        read_settings(c, rev).await?;
    }
    let tail = c.take();
    Ok(Query {
        head,
        settings,
        tail,
        sql,
        compression,
    })
}

/// The Query packet to send upstream: the client's own settings, minus any
/// that could widen access or change how ariodb and ClickHouse read data
/// blocks, plus a time limit and, for reads, read-only mode.
fn rebuild_query(q: &Query, timeout_seconds: u64, read_only: bool) -> Vec<u8> {
    let mut out = q.head.clone();
    for (name, flags, value) in &q.settings {
        let lower = name.to_lowercase();
        if lower == "readonly"
            || lower.starts_with("allow_")
            || lower == "max_execution_time"
            || lower.starts_with("input_format_native_")
        {
            continue;
        }
        put_string(&mut out, name);
        put_varint(&mut out, *flags);
        put_string(&mut out, value);
    }
    let mut ours = vec![("max_execution_time", timeout_seconds.to_string(), 1)];
    if read_only {
        ours.push(("readonly", "2".to_string(), 1));
    } else {
        // Type names as text, as ariodb reads them. Not marked important,
        // so servers without the setting ignore it.
        ours.push(("input_format_native_decode_types_in_binary_format", "0".to_string(), 0));
    }
    for (name, value, flags) in ours {
        put_string(&mut out, name);
        put_varint(&mut out, flags);
        put_string(&mut out, &value);
    }
    put_string(&mut out, ""); // end of settings
    out.extend_from_slice(&q.tail);
    out
}

/// Read the Data packet that ends the external tables after a Query, and
/// check it is empty. Returns its raw bytes.
async fn read_terminator<R: tokio::io::AsyncRead + Unpin>(
    c: &mut Rd<R>,
    frames: &mut Frames,
    rev: u64,
) -> Result<Vec<u8>, String> {
    let packet = c.varint().await?;
    if packet != 2 {
        return Err(format!(
            "expected a Data packet after the query, got {packet}"
        ));
    }
    match read_data(c, frames, rev, 0, MAX_HELD).await {
        Ok(block) if block.columns == 0 => Ok(c.take()),
        Ok(_) | Err(Problem::TooManyRows(_)) => {
            Err("external tables are not supported through ariodb".into())
        }
        Err(Problem::Unreadable(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_fields_are_capped_before_authentication() {
        let mut huge = Vec::new();
        put_varint(&mut huge, 50 << 20); // claims a 50 MiB client name
        let mut c = Rd {
            inner: &huge[..],
            taken: Vec::new(),
        };
        assert_eq!(c.short_string().await.unwrap_err(), "login field too large");

        let mut ok = Vec::new();
        put_string(&mut ok, "clickhouse-client");
        let mut c = Rd {
            inner: &ok[..],
            taken: Vec::new(),
        };
        assert_eq!(c.short_string().await.unwrap(), "clickhouse-client");
    }
}
