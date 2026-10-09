//! ClickHouse's native TCP protocol (what clickhouse-client speaks), for
//! reads.
//!
//! ariodb terminates the handshake on both sides: the agent logs in with
//! its name and token, and ariodb logs in to ClickHouse with its own
//! credentials. Both sides are held to the same protocol revision (capped at
//! one ariodb fully understands), so after the handshake the server's
//! replies are relayed byte for byte.
//!
//! Each Query packet is parsed, judged like any other statement, and
//! forwarded with `readonly = 2` and a time limit added to its settings.
//! Native INSERTs and external tables are refused: their data blocks would
//! have to be decoded to be relayed safely. Use the HTTP interface for
//! inserts.

use crate::chsql;
use crate::classify::Kind;
use crate::gate::{self, Ctx, State};
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
    loop {
        let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, state).await {
                if !e.contains("early eof") && !e.contains("connection reset") {
                    eprintln!("ariodb: ClickHouse native connection ended: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Reading and writing ClickHouse's basic encodings.

struct Rd<R> {
    inner: R,
    /// Every byte read since `mark`, so a packet can be forwarded as read.
    taken: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> Rd<R> {
    async fn u8(&mut self) -> Result<u8, String> {
        let b = self.inner.read_u8().await.map_err(|e| e.to_string())?;
        self.taken.push(b);
        Ok(b)
    }
    async fn bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
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
    async fn varint(&mut self) -> Result<u64, String> {
        let mut out = 0u64;
        for shift in (0..64).step_by(7) {
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
    fn mark(&mut self) -> usize {
        self.taken.len()
    }
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.taken)
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
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

fn put_string(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

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

async fn handle(socket: TcpStream, state: Arc<State>) -> Result<(), String> {
    let _ = socket.set_nodelay(true);
    let config = state.config();
    let (client_read, client_write) = socket.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let mut c = Rd {
        inner: BufReader::new(client_read),
        taken: Vec::new(),
    };

    // 1. The client's Hello.
    if c.varint().await? != 0 {
        return Err("expected Hello".into());
    }
    let hello = Hello {
        client_name: c.string().await?,
        major: c.varint().await?,
        minor: c.varint().await?,
        revision: c.varint().await?,
        database: c.string().await?,
        user: c.string().await?,
        password: c.string().await?,
    };
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
    result
}

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
) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    loop {
        c.take();
        let packet = match c.varint().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // client went away
        };
        match packet {
            1 => {
                let started = Instant::now();
                let q = read_query(c, rev).await?;
                // The external-tables terminator always follows a Query.
                let data = read_empty_data(c, q.compression).await;
                let stmt = chsql::classify(&q.sql);
                let decision = match (&stmt, &data) {
                    (_, Err(e)) => Err((None, e.clone())),
                    (Err(e), _) => Err((None, e.clone())),
                    (Ok(s), _) if s.kind == Kind::Write => {
                        Err((None, "native-protocol INSERTs are not supported; use ariodb's ClickHouse HTTP interface".to_string()))
                    }
                    (Ok(s), _) => {
                        let ctx = Ctx { agent, session, database };
                        gate::check_detailed(state, &ctx, std::slice::from_ref(s))
                            .await
                            .map_err(|r| (r.rule.clone(), r.message))
                    }
                };
                let kind = stmt
                    .as_ref()
                    .map(|s| s.kind.to_string())
                    .unwrap_or_else(|_| "unknown".into());
                let tables = stmt.as_ref().map(|s| s.tables.clone()).unwrap_or_default();
                let record = |outcome: &str, reason: Option<&str>, rule: Option<&str>| {
                    state.audit.record(&crate::audit::Entry {
                        session,
                        agent: &agent.name,
                        sql: &q.sql,
                        kind: kind.clone(),
                        tables: &tables,
                        outcome,
                        rows: None,
                        reason,
                        rule,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                    });
                };
                match decision {
                    Err((rule, message)) => {
                        record("refused", Some(&message), rule.as_deref());
                        send(exception_packet(497, &message)).await?;
                    }
                    Ok((_, approved)) => {
                        record("allowed", None, approved.as_deref());
                        let timeout = state
                            .config()
                            .limits
                            .statement_timeout_ms
                            .div_ceil(1000)
                            .max(1);
                        let packet = rebuild_query(&q, rev, timeout);
                        let mut out = packet;
                        out.extend_from_slice(&data.expect("checked above"));
                        up.write_all(&out).await.map_err(|e| e.to_string())?;
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
                return Ok(());
            }
            other => {
                send(exception_packet(
                    48,
                    &format!("client packet {other} is not supported through ariodb"),
                ))
                .await?;
                return Ok(());
            }
        }
    }
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
/// that could widen access, plus read-only mode and a time limit.
fn rebuild_query(q: &Query, _rev: u64, timeout_seconds: u64) -> Vec<u8> {
    let mut out = q.head.clone();
    for (name, flags, value) in &q.settings {
        let lower = name.to_lowercase();
        if lower == "readonly" || lower.starts_with("allow_") || lower == "max_execution_time" {
            continue;
        }
        put_string(&mut out, name);
        put_varint(&mut out, *flags);
        put_string(&mut out, value);
    }
    for (name, value) in [
        ("readonly", "2".to_string()),
        ("max_execution_time", timeout_seconds.to_string()),
    ] {
        put_string(&mut out, name);
        put_varint(&mut out, 1); // important
        put_string(&mut out, &value);
    }
    put_string(&mut out, ""); // end of settings
    out.extend_from_slice(&q.tail);
    out
}

/// Read the Data packet that ends the external tables after a Query, and
/// check it is empty. Returns its raw bytes.
async fn read_empty_data<R: tokio::io::AsyncRead + Unpin>(
    c: &mut Rd<R>,
    compression: u64,
) -> Result<Vec<u8>, String> {
    let start = c.mark();
    let packet = c.varint().await?;
    if packet != 2 {
        return Err(format!(
            "expected a Data packet after the query, got {packet}"
        ));
    }
    c.string().await?; // table name
    if compression == 1 {
        c.bytes(16).await?; // checksum
        let _method = c.u8().await?;
        let compressed = u32::from_le_bytes(c.bytes(4).await?.try_into().unwrap()) as usize;
        let decompressed = u32::from_le_bytes(c.bytes(4).await?.try_into().unwrap());
        if compressed < 9 {
            return Err("malformed compressed block".into());
        }
        c.bytes(compressed - 9).await?;
        if decompressed > 64 {
            return Err("external tables are not supported through ariodb".into());
        }
    } else {
        // Block info: numbered fields until 0, then column and row counts.
        loop {
            match c.varint().await? {
                0 => break,
                1 => {
                    c.u8().await?;
                }
                2 => {
                    c.bytes(4).await?;
                }
                other => return Err(format!("unknown block info field {other}")),
            }
        }
        let columns = c.varint().await?;
        let rows = c.varint().await?;
        if columns != 0 || rows != 0 {
            return Err("external tables are not supported through ariodb".into());
        }
    }
    let raw = c.taken[start..].to_vec();
    Ok(raw)
}
