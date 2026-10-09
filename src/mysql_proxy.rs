//! The MySQL front door: agents connect with any MySQL client and their
//! token; ariodb judges each statement and relays it to the real server as
//! its own login.
//!
//! ariodb ends the handshake on both sides. Agents log in with their name
//! and token (caching_sha2_password or mysql_native_password; ariodb knows
//! the token, so it checks either scramble itself), and each agent
//! connection gets one connection to the server as `[mysql] user`. The
//! capabilities that shape the server's replies are the same on both
//! sides, so replies are relayed packet by packet.
//!
//! Every statement runs in a transaction ariodb opens: `START TRANSACTION
//! READ ONLY` for reads, `START TRANSACTION` for writes. A write's reply is
//! held until the write is judged by the rows it changed: the OK packets'
//! count, raised to InnoDB's own count for the transaction (which includes
//! triggers and cascades). A refused write is rolled back and the agent
//! sees only the error.

use crate::classify::Statement;
use crate::config::{Agent, Config};
use crate::gate::{self, Ctx, Liveness, Plan, Refusal, State};
use crate::mysql_wire::{self as w, Seen, ServerError, Upstream, WireError};
use crate::tls::Io;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, BufReader, BufWriter, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// How long an agent has to log in.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest command ariodb reads from an agent.
const MAX_COMMAND: usize = 16 << 20;
/// The largest SQL text ariodb will judge, as for Postgres.
const MAX_SQL: usize = 1 << 20;
/// The most of a write's reply ariodb holds while the write is judged.
const MAX_HELD: usize = 64 << 20;
/// InnoDB refreshes `information_schema.innodb_trx` from a cache, and only
/// when nobody has read it for 100 ms. ariodb spaces its own reads further
/// apart than that, so each one sees the transaction as it is now.
const TRX_CACHE_IDLE: Duration = Duration::from_millis(110);
const TRX_ROWS_SQL: &str = "SELECT trx_rows_modified FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = CONNECTION_ID()";

/// Errors for refused statements: access denied, as MySQL reports it.
const ER_REFUSED: u16 = 1142;
const ER_ACCESS_DENIED: u16 = 1045;
const ER_DB_ACCESS_DENIED: u16 = 1044;
const ER_NO_SUCH_THREAD: u16 = 1094;
const ER_UNKNOWN_STMT_HANDLER: u16 = 1243;
const ER_NET_PACKET_TOO_LARGE: u16 = 1153;
const ER_SECURE_TRANSPORT_REQUIRED: u16 = 3159;
const ER_HANDSHAKE_ERROR: u16 = 1043;
const ER_UNKNOWN_ERROR: u16 = 1105;

/// Shared by every MySQL connection.
struct Shared {
    next_id: AtomicU32,
    conns: Mutex<HashMap<u32, Entry>>,
    /// The server's version string, shown to agents in the handshake.
    version: Mutex<String>,
    /// When ariodb last read `innodb_trx`; see `TRX_CACHE_IDLE`.
    trx_read: tokio::sync::Mutex<Option<Instant>>,
    warned_no_trx: AtomicBool,
}

/// A live agent connection, so KILL can find it.
#[derive(Clone)]
struct Entry {
    agent: String,
    live: Arc<Liveness>,
    upstream_thread: u32,
    /// Whether a statement is running on the server right now.
    running: Arc<AtomicBool>,
    /// Ends the connection (KILL CONNECTION).
    kill: Arc<Notify>,
}

/// Accept agents on `[mysql] listen`. Returns only on error; pending forever
/// when the listener is off.
pub async fn serve(state: Arc<State>) -> Result<(), String> {
    let config = state.config();
    if config.mysql.listen.is_empty() {
        return std::future::pending().await;
    }
    let acceptor = config.mysql_listener_tls()?;
    if config.mysql.require_tls && acceptor.is_none() {
        return Err("mysql.require_tls needs mysql.tls_cert and mysql.tls_key".to_string());
    }
    let shared = Arc::new(Shared {
        next_id: AtomicU32::new(1),
        conns: Mutex::new(HashMap::new()),
        version: Mutex::new("8.4.0".to_string()),
        trx_read: tokio::sync::Mutex::new(None),
        warned_no_trx: AtomicBool::new(false),
    });
    // Learn the server's version first, so agents' clients see the real one.
    match connect_upstream(&config, w::RELAYED_CAPS, 45).await {
        Ok(up) => *shared.version.lock().expect("version lock") = up.version.clone(),
        Err(e) => eprintln!("ariodb: MySQL is not reachable yet: {e}"),
    }
    let listener = TcpListener::bind(&config.mysql.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.mysql.listen))?;
    let tls_note = match (&acceptor, config.mysql.require_tls) {
        (Some(_), true) => " (TLS required)",
        (Some(_), false) => " (TLS available)",
        _ => "",
    };
    println!(
        "ariodb: MySQL agents can connect to {}{tls_note}",
        config.mysql.listen
    );
    loop {
        let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let _ = socket.set_nodelay(true);
        let (state, acceptor, shared) = (state.clone(), acceptor.clone(), shared.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(socket, state, acceptor, shared).await {
                eprintln!("ariodb: MySQL connection ended: {e}");
            }
        });
    }
}

/// Log in to the server as ariodb, and set the session up for agents.
async fn connect_upstream(config: &Config, caps: u32, charset: u8) -> Result<Upstream, String> {
    let password = config.mysql_password()?;
    let addr = config.mysql_dial_addr()?;
    let host = host_of(&config.mysql.addr);
    let mut up = Upstream::connect(&w::Login {
        addr: &addr,
        tls: config.mysql_tls_mode(),
        ca_file: config.mysql.ca_file.as_deref(),
        tls_host: &host,
        user: &config.mysql.user,
        password: &password,
        database: &config.mysql.database,
        caps,
        charset,
    })
    .await?;
    prepare_session(&mut up, config).await?;
    Ok(up)
}

/// The host part of host:port, without IPv6 brackets.
fn host_of(addr: &str) -> String {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host.trim_start_matches('[').trim_end_matches(']').to_string()
}

/// The session settings every agent connection runs under: the statement
/// timeout, and an sql_mode in which quotes mean what ariodb's parser
/// thinks they mean.
async fn prepare_session(up: &mut Upstream, config: &Config) -> Result<(), String> {
    let mode = up
        .query("SELECT @@SESSION.sql_mode")
        .await?
        .map_err(|e| format!("cannot read sql_mode: {}", e.message))?;
    let current = mode
        .rows
        .first()
        .and_then(|r| r.first().cloned().flatten())
        .unwrap_or_default();
    let ms = config.limits.statement_timeout_ms;
    // MySQL's max_execution_time covers SELECT only; MariaDB's
    // max_statement_time covers every statement. Lock waits are capped too.
    let timeout = if up.is_mariadb() {
        format!("max_statement_time = {}", ms as f64 / 1000.0)
    } else {
        format!("max_execution_time = {ms}")
    };
    let sql = format!(
        "SET SESSION {timeout}, innodb_lock_wait_timeout = {}, sql_mode = {}",
        ms.div_ceil(1000).max(1),
        w::quote_str(&safe_sql_mode(&current))
    );
    up.query(&sql)
        .await?
        .map_err(|e| format!("cannot set up the MySQL session: {}", e.message))?;
    Ok(())
}

/// The session's sql_mode without the modes that change how quotes and
/// backslashes are read (ANSI_QUOTES makes "x" a name, NO_BACKSLASH_ESCAPES
/// makes \' end a string), or that switch them on as part of a group.
fn safe_sql_mode(mode: &str) -> String {
    const CHANGES_QUOTING: &[&str] = &[
        "ANSI_QUOTES",
        "NO_BACKSLASH_ESCAPES",
        "ANSI",
        "ORACLE",
        "MSSQL",
        "DB2",
        "POSTGRESQL",
        "MAXDB",
    ];
    mode.split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty() && !CHANGES_QUOTING.contains(&m.to_ascii_uppercase().as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Logging in.

struct LoggedIn {
    io: Box<dyn Io>,
    agent: Agent,
    caps: u32,
    charset: u8,
    /// The next sequence id to send.
    seq: u8,
    /// caching_sha2_password expects to hear that its fast path succeeded.
    sha2: bool,
}

async fn handle(
    socket: TcpStream,
    state: Arc<State>,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    shared: Arc<Shared>,
) -> Result<(), String> {
    let id = shared.next_id.fetch_add(1, SeqCst);
    let login = match tokio::time::timeout(LOGIN_TIMEOUT, login(socket, &state, acceptor, id, &shared)).await {
        Err(_) => return Ok(()), // too slow to log in
        Ok(Err(e)) => return Err(e),
        Ok(Ok(None)) => return Ok(()),
        Ok(Ok(Some(l))) => l,
    };
    let LoggedIn {
        mut io,
        agent,
        caps,
        charset,
        mut seq,
        sha2,
    } = login;
    let config = state.config();
    let up = match connect_upstream(&config, caps & w::RELAYED_CAPS, w::safe_collation(charset)).await {
        Ok(up) => up,
        Err(e) => {
            let msg = format!("ariodb: cannot connect to MySQL: {e}");
            let _ = w::write_packet(&mut io, &mut seq, &w::err_packet(ER_UNKNOWN_ERROR, "08S01", &msg)).await;
            return Ok(());
        }
    };
    *shared.version.lock().expect("version lock") = up.version.clone();
    if sha2 {
        w::write_packet(&mut io, &mut seq, &[0x01, 0x03]).await?;
    }
    w::write_packet(&mut io, &mut seq, &w::ok_packet(w::SERVER_STATUS_AUTOCOMMIT)).await?;

    let live = Arc::new(Liveness::default());
    let kill = Arc::new(Notify::new());
    let running = Arc::new(AtomicBool::new(false));
    shared.conns.lock().expect("conns lock").insert(
        id,
        Entry {
            agent: agent.name.clone(),
            live: live.clone(),
            upstream_thread: up.thread_id,
            running: running.clone(),
            kill: kill.clone(),
        },
    );

    // A reader task watches the agent's socket the whole time, so a
    // disconnect is noticed even while a statement waits for approval.
    let (reader, writer) = tokio::io::split(io);
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let reader_live = live.clone();
    let reader_task = tokio::spawn(read_commands(BufReader::new(reader), tx, reader_live));

    let conn = Conn {
        session: format!("s-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]),
        database: config.mysql.database.clone(),
        tagging: config.mysql.journal,
        agent,
        state: state.clone(),
        shared: shared.clone(),
        up,
        out: Out {
            w: BufWriter::new(writer),
            seq: 0,
        },
        live,
        running,
        statements: HashMap::new(),
        next_statement: 1,
    };
    let result = conn.run(rx, kill).await;
    reader_task.abort();
    shared.conns.lock().expect("conns lock").remove(&id);
    result
}

async fn read_commands(
    mut r: BufReader<ReadHalf<Box<dyn Io>>>,
    tx: tokio::sync::mpsc::Sender<Result<(u8, Vec<u8>), WireError>>,
    live: Arc<Liveness>,
) {
    loop {
        match w::read_logical(&mut r, MAX_COMMAND).await {
            Ok(c) => {
                if tx.send(Ok(c)).await.is_err() {
                    break;
                }
            }
            Err(WireError::TooLarge(n)) => {
                if tx.send(Err(WireError::TooLarge(n))).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                live.gone.store(true, SeqCst);
                let _ = tx.send(Err(e)).await;
                break;
            }
        }
    }
}

/// The handshake with an agent. `None` when the agent was refused (and told
/// why) or went away.
async fn login(
    mut socket: TcpStream,
    state: &State,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    id: u32,
    shared: &Shared,
) -> Result<Option<LoggedIn>, String> {
    let config = state.config();
    let nonce = w::nonce();
    let version = shared.version.lock().expect("version lock").clone();
    let mut caps = w::AGENT_CAPS;
    if acceptor.is_some() {
        caps |= w::CLIENT_SSL;
    }
    // utf8mb4: MySQL 8's default collation, or MariaDB's, which MySQL lacks.
    let charset = if version.contains("MariaDB") { 45 } else { 255 };
    let mut seq = 0u8;
    let hello = w::handshake_packet(&w::ServerHello {
        version: &version,
        connection_id: id,
        nonce: &nonce,
        caps,
        charset,
    });
    w::write_packet(&mut socket, &mut seq, &hello).await?;
    let (s, first) = match w::read_logical(&mut socket, w::MAX_LOGIN_PACKET).await {
        Ok(p) => p,
        // Port checks connect and hang up; that is not an error.
        Err(WireError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let (mut io, s, payload, tls): (Box<dyn Io>, u8, Vec<u8>, bool) = if w::is_ssl_request(&first) {
        let Some(acc) = acceptor else {
            return Err("the client asked for TLS, which was not offered".into());
        };
        let tls = acc.accept(socket).await.map_err(|e| format!("TLS: {e}"))?;
        let mut io: Box<dyn Io> = Box::new(tls);
        let (s, p) = w::read_logical(&mut io, w::MAX_LOGIN_PACKET).await?;
        (io, s, p, true)
    } else {
        (Box::new(socket), s, first, false)
    };
    seq = s.wrapping_add(1);
    let refuse = |code: u16, sqlstate: &str, msg: &str| w::err_packet(code, sqlstate, &format!("ariodb: {msg}"));
    if config.mysql.require_tls && !tls {
        let p = refuse(ER_SECURE_TRANSPORT_REQUIRED, "HY000", "connections must use TLS (for example --ssl-mode=REQUIRED)");
        let _ = w::write_packet(&mut io, &mut seq, &p).await;
        return Ok(None);
    }
    let hello = match w::parse_client_hello(&payload) {
        Ok(h) => h,
        Err(e) => {
            let _ = w::write_packet(&mut io, &mut seq, &refuse(ER_HANDSHAKE_ERROR, "08S01", &e.to_string())).await;
            return Ok(None);
        }
    };

    // The scramble, for a plugin ariodb can check. Clients without plugin
    // support send a mysql_native_password scramble.
    let mut plugin = hello.plugin.clone();
    let mut auth = hello.auth.clone();
    if hello.caps & w::CLIENT_PLUGIN_AUTH == 0 {
        plugin = w::NATIVE.to_string();
    } else if plugin != w::CACHING_SHA2 && plugin != w::NATIVE {
        w::write_packet(&mut io, &mut seq, &w::auth_switch_packet(w::CACHING_SHA2, &nonce)).await?;
        let (s, p) = w::read_logical(&mut io, w::MAX_LOGIN_PACKET).await?;
        seq = s.wrapping_add(1);
        plugin = w::CACHING_SHA2.to_string();
        auth = p;
    }

    let user = hello.user.clone();
    let token = config.agent(&user).and_then(|a| config.agent_token(a));
    let verdict = match token {
        None => Err("unknown agent"),
        Some(t) if !w::check_scramble(&plugin, t.as_bytes(), &nonce, &auth) => Err("wrong token"),
        Some(t) => config.engine_agent("mysql", &user, &t),
    };
    let agent = match verdict {
        Ok(a) => a,
        Err(why) => {
            let p = refuse(ER_ACCESS_DENIED, "28000", &format!("access denied for agent '{user}': {why}"));
            let _ = w::write_packet(&mut io, &mut seq, &p).await;
            return Ok(None);
        }
    };
    if !hello.database.is_empty() && hello.database != config.mysql.database {
        let msg = format!("agents may only use database '{}'", config.mysql.database);
        let _ = w::write_packet(&mut io, &mut seq, &refuse(ER_DB_ACCESS_DENIED, "42000", &msg)).await;
        return Ok(None);
    }
    Ok(Some(LoggedIn {
        io,
        agent,
        caps: hello.caps & caps,
        charset: hello.charset,
        seq,
        sha2: plugin == w::CACHING_SHA2,
    }))
}

// ---------------------------------------------------------------------------
// The connection.

/// Packets to the agent, numbered within the current command.
struct Out {
    w: BufWriter<WriteHalf<Box<dyn Io>>>,
    seq: u8,
}

impl Out {
    async fn packet(&mut self, payload: &[u8]) -> Result<(), WireError> {
        let mut buf = Vec::with_capacity(payload.len() + 4);
        w::put_packets(&mut buf, &mut self.seq, payload);
        self.w.write_all(&buf).await?;
        Ok(())
    }

    /// Relay one packet from the server, renumbered.
    async fn physical(&mut self, p: &[u8]) -> Result<(), WireError> {
        let len = (p.len() as u32).to_le_bytes();
        self.w.write_all(&[len[0], len[1], len[2], self.seq]).await?;
        self.w.write_all(p).await?;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }

    async fn error(&mut self, code: u16, state: &str, message: &str) -> Result<(), WireError> {
        self.packet(&w::err_packet(code, state, &format!("ariodb: {message}")))
            .await
    }

    async fn server_error(&mut self, e: &ServerError) -> Result<(), WireError> {
        self.packet(&w::err_packet(e.code, &e.state, &e.message)).await
    }

    async fn flush(&mut self) -> Result<(), WireError> {
        self.w.flush().await?;
        Ok(())
    }
}

struct Prepared {
    upstream: u32,
    sql: String,
    statements: Vec<Statement>,
}

struct Conn {
    session: String,
    agent: Agent,
    database: String,
    /// Whether writes are tagged for the journal; fixed when the session opens.
    tagging: bool,
    state: Arc<State>,
    shared: Arc<Shared>,
    up: Upstream,
    out: Out,
    live: Arc<Liveness>,
    running: Arc<AtomicBool>,
    /// The agent's prepared statement ids, mapped to the server's.
    statements: HashMap<u32, Prepared>,
    next_statement: u32,
}

impl Conn {
    async fn run(
        mut self,
        mut rx: tokio::sync::mpsc::Receiver<Result<(u8, Vec<u8>), WireError>>,
        kill: Arc<Notify>,
    ) -> Result<(), String> {
        loop {
            let next = tokio::select! {
                next = rx.recv() => next,
                _ = kill.notified() => return Ok(()),
            };
            let (seq, cmd) = match next {
                None | Some(Err(WireError::Io(_))) | Some(Err(WireError::Protocol(_))) => {
                    return Ok(());
                }
                Some(Err(WireError::TooLarge(n))) => {
                    // The reply follows the last of the packets the command took.
                    self.out.seq = (n / w::MAX_PHYSICAL + 1) as u8;
                    self.audit("<too large>", &[], "refused", None, Some("command over 16 MiB"), None, Instant::now());
                    let msg = format!("command of {n} bytes is over the {} MiB limit", MAX_COMMAND >> 20);
                    self.out.error(ER_NET_PACKET_TOO_LARGE, "08S01", &msg).await?;
                    self.out.flush().await?;
                    continue;
                }
                Some(Ok(c)) => c,
            };
            // A cancel only applies to the statement in flight.
            self.live.cancelled.store(false, SeqCst);
            self.out.seq = seq.wrapping_add(1);
            if cmd.first() == Some(&w::COM_QUIT) {
                let _ = self.up.command(&[w::COM_QUIT]).await;
                return Ok(());
            }
            if let Err(e) = self.command(&cmd).await {
                // The server connection broke; tell the agent if it is listening.
                let _ = self
                    .out
                    .error(ER_UNKNOWN_ERROR, "08S01", &format!("lost the connection to MySQL: {e}"))
                    .await;
                let _ = self.out.flush().await;
                return Err(e.to_string());
            }
            self.out.flush().await?;
        }
    }

    async fn command(&mut self, cmd: &[u8]) -> Result<(), WireError> {
        let Some(&code) = cmd.first() else {
            return self.out.error(ER_UNKNOWN_ERROR, "08S01", "empty command").await;
        };
        let body = &cmd[1..];
        match code {
            w::COM_QUERY => self.query(body).await,
            w::COM_STMT_PREPARE => self.prepare(body).await,
            w::COM_STMT_EXECUTE => self.execute(cmd).await,
            w::COM_STMT_SEND_LONG_DATA => {
                // No reply. Unknown ids are dropped, as the server would.
                if let Some(up) = self.upstream_id(cmd) {
                    let mut c = cmd.to_vec();
                    c[1..5].copy_from_slice(&up.to_le_bytes());
                    self.up.command(&c).await?;
                }
                Ok(())
            }
            w::COM_STMT_CLOSE => {
                if let Some(up) = self.upstream_id(cmd) {
                    let mut c = cmd.to_vec();
                    c[1..5].copy_from_slice(&up.to_le_bytes());
                    self.up.command(&c).await?;
                    let id = u32::from_le_bytes(cmd[1..5].try_into().expect("4 bytes"));
                    self.statements.remove(&id);
                }
                Ok(())
            }
            w::COM_STMT_RESET => match self.upstream_id(cmd) {
                Some(up) => {
                    let mut c = cmd.to_vec();
                    c[1..5].copy_from_slice(&up.to_le_bytes());
                    self.relay_single(&c).await
                }
                None => self.unknown_statement().await,
            },
            w::COM_PING => self.relay_single(cmd).await,
            w::COM_INIT_DB => {
                if body == self.database.as_bytes() {
                    self.out.packet(&w::ok_packet(w::SERVER_STATUS_AUTOCOMMIT)).await
                } else {
                    let msg = format!("agents may only use database '{}'", self.database);
                    self.out.error(ER_DB_ACCESS_DENIED, "42000", &msg).await
                }
            }
            w::COM_SET_OPTION => {
                // 1 is MYSQL_OPTION_MULTI_STATEMENTS_OFF, which changes nothing.
                if body.len() == 2 && u16::from_le_bytes([body[0], body[1]]) == 1 {
                    self.relay_single(cmd).await
                } else {
                    self.out
                        .error(ER_REFUSED, "42000", "multiple statements per query are not supported through ariodb")
                        .await
                }
            }
            w::COM_RESET_CONNECTION => {
                self.up.command(cmd).await?;
                let (_, p) = self.up.read().await?;
                if p.first() == Some(&0x00) {
                    // The server forgot its prepared statements and session
                    // settings; put ariodb's settings back.
                    self.statements.clear();
                    let config = self.state.config();
                    prepare_session(&mut self.up, &config)
                        .await
                        .map_err(WireError::Protocol)?;
                }
                self.out.physical(&p).await
            }
            other => {
                let msg = format!("{} is not supported through ariodb", command_name(other));
                self.out.error(ER_REFUSED, "42000", &msg).await
            }
        }
    }

    /// Relay a command whose reply is one packet (OK, ERR or EOF).
    async fn relay_single(&mut self, cmd: &[u8]) -> Result<(), WireError> {
        self.up.command(cmd).await?;
        let (_, p) = self.up.read().await?;
        self.out.physical(&p).await
    }

    fn upstream_id(&self, cmd: &[u8]) -> Option<u32> {
        let id = u32::from_le_bytes(cmd.get(1..5)?.try_into().ok()?);
        self.statements.get(&id).map(|p| p.upstream)
    }

    async fn unknown_statement(&mut self) -> Result<(), WireError> {
        self.out
            .error(ER_UNKNOWN_STMT_HANDLER, "HY000", "unknown prepared statement")
            .await
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            agent: &self.agent,
            session: &self.session,
            database: &self.database,
            live: Some(&self.live),
        }
    }

    /// Read SQL text from a command, refusing what ariodb will not judge.
    async fn sql_text(&mut self, body: &[u8], started: Instant) -> Result<Option<String>, WireError> {
        let reason = if body.len() > MAX_SQL {
            "statement over the 1 MiB inspection limit"
        } else {
            match std::str::from_utf8(body) {
                Ok(s) => return Ok(Some(s.to_string())),
                Err(_) => "statements must be UTF-8",
            }
        };
        let sql = if body.len() > MAX_SQL {
            "<too large>".to_string()
        } else {
            String::from_utf8_lossy(body).into_owned()
        };
        self.audit(&sql, &[], "refused", None, Some(reason), None, started);
        self.out.error(ER_REFUSED, "42000", reason).await?;
        Ok(None)
    }

    /// Classify one statement, scoped to the session's database.
    fn classify(&self, sql: &str) -> Result<Vec<Statement>, String> {
        let mut statements = crate::mysql_sql::classify(sql).map_err(|e| e.to_string())?;
        crate::mysql_sql::scope_to_database(&mut statements, &self.database);
        match statements.len() {
            0 => Err("the query was empty".to_string()),
            1 => Ok(statements),
            n => Err(format!(
                "send one statement at a time: this query has {n}, and ariodb does not run several statements in one query"
            )),
        }
    }

    async fn refuse(
        &mut self,
        sql: &str,
        statements: &[Statement],
        r: &Refusal,
        started: Instant,
    ) -> Result<(), WireError> {
        self.audit(sql, statements, "refused", None, Some(&r.message), r.rule.as_deref(), started);
        self.out.error(ER_REFUSED, "42000", &r.message).await
    }

    async fn query(&mut self, body: &[u8]) -> Result<(), WireError> {
        let started = Instant::now();
        let Some(sql) = self.sql_text(body, started).await? else {
            return Ok(());
        };
        if let Some(kill) = parse_kill(&sql) {
            return self.kill(&sql, kill, started).await;
        }
        let statements = match self.classify(&sql) {
            Ok(s) => s,
            Err(e) => return self.refuse(&sql, &[], &Refusal::new(e), started).await,
        };
        let (plan, approved) = match gate::check_detailed(&self.state, &self.ctx(), &statements).await {
            Ok(p) => p,
            Err(r) => return self.refuse(&sql, &statements, &r, started).await,
        };
        let mut cmd = vec![w::COM_QUERY];
        cmd.extend_from_slice(body);
        self.run_statement(&cmd, &sql, &statements, plan, approved, started).await
    }

    async fn prepare(&mut self, body: &[u8]) -> Result<(), WireError> {
        let started = Instant::now();
        let Some(sql) = self.sql_text(body, started).await? else {
            return Ok(());
        };
        let statements = match self.classify(&sql) {
            Ok(s) => s,
            Err(e) => return self.refuse(&sql, &[], &Refusal::new(e), started).await,
        };
        // Refuse now what could never run. Approvals wait for EXECUTE,
        // where the whole check runs again.
        if let Err(r) = self.precheck(&statements) {
            return self.refuse(&sql, &statements, &r, started).await;
        }
        let mut cmd = vec![w::COM_STMT_PREPARE];
        cmd.extend_from_slice(body);
        self.up.command(&cmd).await?;
        let (_, mut first) = self.up.read().await?;
        if first.first() != Some(&0x00) {
            let e = w::parse_err(&first);
            self.audit(&sql, &statements, "failed", None, Some(&e.message), None, started);
            return self.out.physical(&first).await;
        }
        let (upstream, _, _, tail) = w::prepare_ok_tail(&first, self.up.deprecate_eof())?;
        let id = self.next_statement;
        self.next_statement = self.next_statement.wrapping_add(1).max(1);
        first[1..5].copy_from_slice(&id.to_le_bytes());
        self.out.physical(&first).await?;
        for _ in 0..tail {
            let (_, p) = self.up.read().await?;
            self.out.physical(&p).await?;
        }
        self.statements.insert(
            id,
            Prepared {
                upstream,
                sql,
                statements,
            },
        );
        Ok(())
    }

    /// The built-in policy and before-stage rules, without approvals.
    fn precheck(&self, statements: &[Statement]) -> Result<(), Refusal> {
        let rules = self.state.rules();
        for s in statements {
            if let crate::policy::Decision::Deny(reason) = crate::policy::decide(&self.agent, s) {
                return Err(Refusal::new(reason));
            }
            let facts = crate::rules::Facts {
                agent: &self.agent,
                statement: s,
                database: &self.database,
            };
            if let crate::rules::Outcome::Deny { rule, reason } = rules.evaluate(&facts) {
                return Err(Refusal::by_rule(&rule, reason));
            }
        }
        Ok(())
    }

    async fn execute(&mut self, cmd: &[u8]) -> Result<(), WireError> {
        let started = Instant::now();
        let Some(id) = cmd.get(1..5).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes"))) else {
            return self.unknown_statement().await;
        };
        let Some(p) = self.statements.get(&id) else {
            return self.unknown_statement().await;
        };
        let (upstream, sql, statements) = (p.upstream, p.sql.clone(), p.statements.clone());
        // Cursors would outlive ariodb's transaction.
        if cmd.get(5).copied().unwrap_or(0) != 0 {
            let r = Refusal::new("cursors (COM_STMT_FETCH) are not supported through ariodb");
            return self.refuse(&sql, &statements, &r, started).await;
        }
        let (plan, approved) = match gate::check_detailed(&self.state, &self.ctx(), &statements).await {
            Ok(p) => p,
            Err(r) => return self.refuse(&sql, &statements, &r, started).await,
        };
        let mut c = cmd.to_vec();
        c[1..5].copy_from_slice(&upstream.to_le_bytes());
        self.run_statement(&c, &sql, &statements, plan, approved, started).await
    }

    /// Run one allowed statement in ariodb's own transaction.
    async fn run_statement(
        &mut self,
        command: &[u8],
        sql: &str,
        statements: &[Statement],
        plan: Plan,
        approved: Option<String>,
        started: Instant,
    ) -> Result<(), WireError> {
        let begin = match plan {
            Plan::Read => "START TRANSACTION READ ONLY",
            Plan::Write => "START TRANSACTION",
        };
        if let Err(e) = self.up.query(begin).await? {
            self.audit(sql, statements, "failed", None, Some(&e.message), None, started);
            return self.out.server_error(&e).await;
        }
        if plan == Plan::Write && self.tagging {
            let config = self.state.config();
            let tag = format!(
                "INSERT INTO {} (session, agent) VALUES ({}, {})",
                w::quote_name(&config.mysql.tag_table),
                w::quote_str(&self.session),
                w::quote_str(&self.agent.name)
            );
            if let Err(e) = self.up.query(&tag).await? {
                self.end(false).await?;
                let why = format!("cannot record the session for the journal: {}", e.message);
                self.audit(sql, statements, "failed", None, Some(&why), None, started);
                return self.out.error(ER_UNKNOWN_ERROR, "HY000", &why).await;
            }
        }

        self.running.store(true, SeqCst);
        let relayed = self.relay_reply(command, plan == Plan::Read).await;
        self.running.store(false, SeqCst);
        let r = relayed?;

        if r.infile {
            self.end(false).await?;
            let why = Refusal::new("LOAD DATA LOCAL is not allowed through ariodb");
            return self.refuse(sql, statements, &why, started).await;
        }
        if r.too_big {
            self.end(false).await?;
            let why = format!(
                "rolled back: the write's reply is over {} MiB, and ariodb holds a write's reply until it is judged",
                MAX_HELD >> 20
            );
            self.audit(sql, statements, "failed", None, Some(&why), None, started);
            return self.out.error(ER_REFUSED, "42000", &why).await;
        }
        if let Some(e) = &r.failed {
            self.end(false).await?;
            self.audit(sql, statements, "failed", None, Some(&e.message), None, started);
            for p in &r.held {
                self.out.physical(p).await?;
            }
            return Ok(());
        }
        if plan == Plan::Read {
            self.end(true).await?;
            self.audit(sql, statements, "allowed", None, None, approved.as_deref(), started);
            return Ok(());
        }

        let rows = self.rows_changed(r.reported).await?;
        let judged = {
            let ctx = Ctx {
                agent: &self.agent,
                session: &self.session,
                database: &self.database,
                live: Some(&self.live),
            };
            gate::judge_write(&self.state, &ctx, statements, &[], rows, false).await
        };
        if let Err(refusal) = judged {
            self.end(false).await?;
            self.audit(
                sql,
                statements,
                "rolled_back",
                Some(rows),
                Some(&refusal.message),
                refusal.rule.as_deref(),
                started,
            );
            return self.out.error(ER_REFUSED, "42000", &refusal.message).await;
        }
        if let Err(e) = self.up.query("COMMIT").await? {
            self.audit(sql, statements, "failed", Some(rows), Some(&e.message), None, started);
            return self.out.server_error(&e).await;
        }
        self.audit(sql, statements, "allowed", Some(rows), None, approved.as_deref(), started);
        for p in &r.held {
            self.out.physical(p).await?;
        }
        Ok(())
    }

    /// Send a statement and follow its reply: straight to the agent for a
    /// read, held back for a write.
    async fn relay_reply(&mut self, command: &[u8], stream: bool) -> Result<Relayed, WireError> {
        self.up.command(command).await?;
        let mut reply = w::Reply::new(self.up.deprecate_eof());
        let mut r = Relayed::default();
        let mut held_bytes = 0usize;
        while !reply.done() {
            let (seq, mut p) = self.up.read().await?;
            match reply.feed(&p)? {
                Seen::LocalInfile => {
                    // The server wants a file from the agent's machine.
                    // Send none; the agent never hears of it.
                    self.up.send_at(seq.wrapping_add(1), &[]).await?;
                    r.infile = true;
                    continue;
                }
                Seen::Err => {
                    r.failed.get_or_insert_with(|| w::parse_err(&p));
                }
                Seen::End { affected, status_at } => {
                    r.reported += affected;
                    w::clear_trans_status(&mut p, status_at);
                }
                Seen::Data => {}
            }
            if r.infile {
                continue;
            }
            if stream {
                self.out.physical(&p).await?;
            } else if !r.too_big {
                held_bytes += p.len();
                if held_bytes > MAX_HELD {
                    r.too_big = true;
                    r.held.clear();
                } else {
                    r.held.push(p);
                }
            }
        }
        Ok(r)
    }

    async fn end(&mut self, commit: bool) -> Result<(), WireError> {
        let _ = self.up.query(if commit { "COMMIT" } else { "ROLLBACK" }).await?;
        Ok(())
    }

    /// The rows a write changed: what the OK packets said, raised to
    /// InnoDB's count for the transaction (which includes rows changed by
    /// triggers and cascades), less ariodb's own tag row.
    async fn rows_changed(&mut self, reported: u64) -> Result<u64, WireError> {
        let tag = self.tagging as u64;
        // A count below this predates the statement: a stale cache.
        let at_least = tag + (reported > 0) as u64;
        let mut last_read = self.shared.trx_read.lock().await;
        let mut counted = None;
        for _ in 0..3 {
            if let Some(t) = *last_read {
                let wait = TRX_CACHE_IDLE.saturating_sub(t.elapsed());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            let result = self.up.query(TRX_ROWS_SQL).await?;
            *last_read = Some(Instant::now());
            match result {
                Err(e) => {
                    if !self.shared.warned_no_trx.swap(true, SeqCst) {
                        eprintln!(
                            "ariodb: cannot read information_schema.innodb_trx ({}); MySQL writes are judged by the rows the server reports, which leave out triggers. Grant the PROCESS privilege to [mysql] user",
                            e.message
                        );
                    }
                    break;
                }
                Ok(rows) => {
                    counted = rows
                        .rows
                        .first()
                        .and_then(|r| r.first().cloned().flatten())
                        .and_then(|v| v.parse::<u64>().ok());
                    if counted.is_some_and(|n| n >= at_least) {
                        break;
                    }
                }
            }
        }
        Ok(reported.max(counted.unwrap_or(0).saturating_sub(tag)))
    }

    async fn kill(&mut self, sql: &str, kill: Kill, started: Instant) -> Result<(), WireError> {
        let (target, query) = match kill {
            Kill::Query(n) => (n, true),
            Kill::Connection(n) => (n, false),
            Kill::Other => {
                let r = Refusal::new("only KILL QUERY <id> and KILL <id> are allowed, for the agent's own connections");
                return self.refuse(sql, &[], &r, started).await;
            }
        };
        let entry = u32::try_from(target).ok().and_then(|id| {
            self.shared
                .conns
                .lock()
                .expect("conns lock")
                .get(&id)
                .filter(|e| e.agent == self.agent.name)
                .cloned()
        });
        let Some(entry) = entry else {
            // Other agents' connections look the same as ones that do not exist.
            self.audit(sql, &[], "refused", None, Some("no such connection of this agent"), None, started);
            return self
                .out
                .error(ER_NO_SUCH_THREAD, "HY000", &format!("unknown thread id: {target}"))
                .await;
        };
        // A statement waiting for approval is withdrawn; one running on the
        // server is stopped there.
        entry.live.cancelled.store(true, SeqCst);
        if !query {
            entry.kill.notify_one();
        }
        if !query || entry.running.load(SeqCst) {
            let config = self.state.config();
            let thread = entry.upstream_thread;
            let what = if query { "KILL QUERY" } else { "KILL" };
            match connect_upstream(&config, 0, 45).await {
                Ok(mut up) => {
                    if let Ok(Err(e)) = up.query(&format!("{what} {thread}")).await
                        && e.code != ER_NO_SUCH_THREAD
                    {
                        eprintln!("ariodb: could not stop MySQL thread {thread}: {}", e.message);
                    }
                }
                Err(e) => eprintln!("ariodb: could not stop MySQL thread {thread}: {e}"),
            }
        }
        self.audit(sql, &[], "allowed", None, None, None, started);
        self.out.packet(&w::ok_packet(w::SERVER_STATUS_AUTOCOMMIT)).await
    }

    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        sql: &str,
        statements: &[Statement],
        outcome: &str,
        rows: Option<u64>,
        reason: Option<&str>,
        rule: Option<&str>,
        started: Instant,
    ) {
        let tables = gate::tables(statements);
        let kind = if statements.is_empty() && sql.trim_start().to_ascii_lowercase().starts_with("kill") {
            "session".to_string()
        } else {
            gate::kinds(statements)
        };
        self.state.audit.record(&crate::audit::Entry {
            session: &self.session,
            agent: &self.agent.name,
            sql,
            kind,
            tables: &tables,
            outcome,
            rows,
            reason,
            rule,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            engine: "mysql",
            database: &self.database,
        });
    }
}

#[derive(Default)]
struct Relayed {
    held: Vec<Vec<u8>>,
    reported: u64,
    failed: Option<ServerError>,
    infile: bool,
    too_big: bool,
}

/// `KILL [QUERY | CONNECTION] <id>`, which ariodb answers itself: ids are
/// ariodb's, not the server's.
#[derive(Debug, PartialEq)]
enum Kill {
    Query(u64),
    Connection(u64),
    /// Some other use of KILL, which is refused.
    Other,
}

fn parse_kill(sql: &str) -> Option<Kill> {
    let text = sql.trim().trim_end_matches(';').trim();
    let words: Vec<&str> = text.split_whitespace().collect();
    if !words.first()?.eq_ignore_ascii_case("kill") {
        return None;
    }
    let id = |s: &str| s.parse::<u64>().ok();
    Some(match &words[1..] {
        [n] => id(n).map(Kill::Connection).unwrap_or(Kill::Other),
        [q, n] if q.eq_ignore_ascii_case("query") => id(n).map(Kill::Query).unwrap_or(Kill::Other),
        [c, n] if c.eq_ignore_ascii_case("connection") => {
            id(n).map(Kill::Connection).unwrap_or(Kill::Other)
        }
        _ => Kill::Other,
    })
}

fn command_name(code: u8) -> String {
    let name = match code {
        0x00 => "COM_SLEEP",
        0x04 => "COM_FIELD_LIST",
        0x05 => "COM_CREATE_DB",
        0x06 => "COM_DROP_DB",
        0x07 => "COM_REFRESH",
        0x08 => "COM_SHUTDOWN",
        0x09 => "COM_STATISTICS",
        0x0a => "COM_PROCESS_INFO",
        0x0c => "COM_PROCESS_KILL",
        0x0d => "COM_DEBUG",
        0x11 => "COM_CHANGE_USER",
        0x12 => "COM_BINLOG_DUMP",
        0x13 => "COM_TABLE_DUMP",
        0x15 => "COM_REGISTER_SLAVE",
        0x1c => "COM_STMT_FETCH",
        0x1d => "COM_DAEMON",
        0x1e => "COM_BINLOG_DUMP_GTID",
        0x20 => "COM_CLONE",
        _ => return format!("command 0x{code:02x}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_is_recognised() {
        assert_eq!(parse_kill("KILL QUERY 12"), Some(Kill::Query(12)));
        assert_eq!(parse_kill("  kill   query 7 ; "), Some(Kill::Query(7)));
        assert_eq!(parse_kill("KILL 3"), Some(Kill::Connection(3)));
        assert_eq!(parse_kill("kill connection 3"), Some(Kill::Connection(3)));
        assert_eq!(parse_kill("KILL QUERY (SELECT 1)"), Some(Kill::Other));
        assert_eq!(parse_kill("KILL USER x"), Some(Kill::Other));
        assert_eq!(parse_kill("KILL"), Some(Kill::Other));
        assert_eq!(parse_kill("SELECT 'KILL 3'"), None);
        assert_eq!(parse_kill("killer"), None);
    }

    #[test]
    fn quoting_modes_are_removed_from_sql_mode() {
        assert_eq!(
            safe_sql_mode("ONLY_FULL_GROUP_BY,ANSI_QUOTES,STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES"),
            "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES"
        );
        assert_eq!(
            safe_sql_mode("REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY,ANSI"),
            "REAL_AS_FLOAT,PIPES_AS_CONCAT,IGNORE_SPACE,ONLY_FULL_GROUP_BY"
        );
        assert_eq!(safe_sql_mode(""), "");
        assert_eq!(safe_sql_mode("ansi_quotes"), "");
    }

    #[test]
    fn host_names_for_tls() {
        assert_eq!(host_of("db.internal:3306"), "db.internal");
        assert_eq!(host_of("[::1]:3306"), "::1");
        assert_eq!(host_of("127.0.0.1:3306"), "127.0.0.1");
    }

    #[test]
    fn command_names() {
        assert_eq!(command_name(0x11), "COM_CHANGE_USER");
        assert_eq!(command_name(0x7f), "command 0x7f");
    }
}
