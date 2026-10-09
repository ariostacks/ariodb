//! The Postgres-compatible front door. Agents connect with psql or any
//! driver, using their agent name as the user and their token as the
//! password. Both the simple and the extended (prepared statement) protocol
//! are supported, with TLS on both sides.
//!
//! For the extended protocol, ariodb opens and closes its own transaction
//! with hidden named statements (`__ariodb_*`) slipped into the agent's
//! message stream, and filters their responses out. It never sends a
//! simple query mid-stream, so the agent's own prepared statements and
//! portals are untouched.

use crate::classify::{self, Statement};
use crate::exec::{Session, Sink};
use crate::config::Agent;
use crate::gate::{self, Plan, Refusal, State};
use crate::limits::{Admission, Limiter};
use crate::tls::Io;
use crate::upstream::{self, Target};
use crate::wire::{self, Frame, WireError};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

/// Our cancel key to: where the real query runs, its cancel key, and the
/// session's liveness (a cancel also withdraws a waiting approval).
type CancelMap = Arc<Mutex<HashMap<(i32, i32), (Target, (i32, i32), Arc<crate::gate::Liveness>)>>>;

pub async fn serve(state: Arc<State>) -> Result<(), String> {
    let config = state.config();
    if config.proxy.listen.is_empty() {
        // The Postgres proxy is switched off (for example a ClickHouse-only
        // setup). Keep running until ariodb is asked to stop.
        std::future::pending::<()>().await;
    }
    let acceptor = match (&config.proxy.tls_cert, &config.proxy.tls_key) {
        (Some(c), Some(k)) => Some(crate::tls::server_acceptor(c, k)?),
        (None, None) => None,
        _ => return Err("proxy.tls_cert and proxy.tls_key must be set together".to_string()),
    };
    if config.proxy.require_tls && acceptor.is_none() {
        return Err("proxy.require_tls needs proxy.tls_cert and proxy.tls_key".to_string());
    }
    let listener = TcpListener::bind(&config.proxy.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.proxy.listen))?;
    let tls_note = if acceptor.is_some() {
        " (TLS available)"
    } else {
        ""
    };
    println!(
        "ariodb: agents can connect to postgres://<agent>@{}{tls_note}",
        config.proxy.listen
    );

    let cancels: CancelMap = Arc::new(Mutex::new(HashMap::new()));
    let limiter = Limiter::new("Postgres proxy", &config.limits);
    loop {
        let (socket, _) = crate::limits::accept(&listener, &limiter).await;
        limiter.update(&state.config().limits);
        let admission = limiter.admit();
        if let Admission::Drop = admission {
            continue;
        }
        let timeout = limiter.handshake_timeout();
        let (state, acceptor, cancels) = (state.clone(), acceptor.clone(), cancels.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(socket, state, acceptor, cancels, admission, timeout).await {
                eprintln!("ariodb: connection ended: {e}");
            }
        });
    }
}

/// Postgres's own message for a server with no room for another client.
const TOO_MANY_CLIENTS: &str = "sorry, too many clients already";

async fn handle(
    socket: TcpStream,
    state: Arc<State>,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    cancels: CancelMap,
    admission: Admission,
    timeout: Duration,
) -> Result<(), String> {
    let e = |e: WireError| e.to_string();
    let mut slot = match admission {
        Admission::Admitted(slot) => slot,
        // Over the limit: answer the startup with 53300 (cancel requests
        // are still served). Quietly: refusals are logged per burst.
        _ => {
            let greeting = greet(socket, &state, acceptor, &cancels, true);
            let _ = tokio::time::timeout(timeout, greeting).await;
            return Ok(());
        }
    };
    // TLS, startup and the token must all arrive in time; a client that
    // stops part way is cut off.
    let greeting = greet(socket, &state, acceptor, &cancels, false);
    let (mut io, agent) = match tokio::time::timeout(timeout, greeting).await {
        Err(_) => return Ok(()),
        Ok(greeted) => match greeted? {
            Some(logged_in) => logged_in,
            None => return Ok(()),
        },
    };
    if let Err(limit) = slot.agent(&agent.name) {
        let msg = wire::fatal_response(
            "53300",
            &format!(
                "ariodb: too many connections for agent \"{}\": it has {limit} open, the most it may",
                agent.name
            ),
        );
        let _ = wire::write_all(&mut io, &msg).await;
        return Ok(());
    }

    let mut session = match Session::open(state.clone(), agent).await {
        Ok(s) => s,
        Err(message) => {
            let _ = wire::write_all(
                &mut io,
                &wire::fatal_response("08006", &format!("ariodb: {message}")),
            )
            .await;
            return Ok(());
        }
    };
    if let Err(message) = prepare_internal(&mut session).await {
        let _ = wire::write_all(
            &mut io,
            &wire::fatal_response("08006", &format!("ariodb: {message}")),
        )
        .await;
        return Ok(());
    }

    let our_key = (rand::random::<i32>().abs(), rand::random::<i32>());
    let target = state.config().target_for(&session.agent)?;
    cancels.lock().expect("cancel map").insert(
        our_key,
        (target, session.up.cancel_key, session.live.clone()),
    );

    let mut hello = vec![wire::auth_ok()];
    hello.extend(session.up.parameter_frames.iter().cloned());
    hello.push(wire::backend_key(our_key.0, our_key.1));
    hello.push(wire::ready(b'I'));
    for f in &hello {
        io.write_all_frame(f).await.map_err(e)?;
    }
    io.flush_all().await.map_err(e)?;

    // A reader task watches the agent's socket the whole time, so a
    // disconnect is noticed even while a statement waits for approval.
    let live = session.live.clone();
    let (mut reader, writer) = tokio::io::split(io);
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let reader_task = tokio::spawn(async move {
        loop {
            match wire::read_frame(&mut reader).await {
                Ok(f) => {
                    if tx.send(Ok(f)).await.is_err() {
                        break;
                    }
                }
                Err(WireError::TooLarge(n)) => {
                    if tx.send(Err(WireError::TooLarge(n))).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    live.gone.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx.send(Err(err)).await;
                    break;
                }
            }
        }
    });
    let result = Connection::new(session, writer, rx).run().await;
    reader_task.abort();
    cancels.lock().expect("cancel map").remove(&our_key);
    result
}

/// A new connection up to a logged-in agent: TLS, the startup message and
/// the token. `None` when the client went away or was refused (and told
/// why), or the connection was a cancel request. With `over_limit`, the
/// listener is full, and the client is told so once its startup arrives.
async fn greet(
    mut socket: TcpStream,
    state: &State,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    cancels: &CancelMap,
    over_limit: bool,
) -> Result<Option<(Box<dyn Io>, Agent)>, String> {
    let config = state.config();
    let e = |e: WireError| e.to_string();

    // Startup: TLS negotiation first, on the raw socket. Clients may ask
    // for GSS encryption, then TLS, before the real startup message.
    let mut first = match wire::read_startup(&mut socket).await {
        Ok(f) => f,
        // Port checks and load balancers connect and hang up; that is not an error.
        Err(WireError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(err) => return Err(err.to_string()),
    };
    loop {
        match first.code {
            wire::GSSENC_REQUEST => {}
            wire::SSL_REQUEST if acceptor.is_none() => {}
            _ => break,
        }
        wire::write_all(&mut socket, b"N").await.map_err(e)?;
        first = wire::read_startup(&mut socket).await.map_err(e)?;
    }
    let (mut io, first): (Box<dyn Io>, wire::Startup) = if first.code == wire::SSL_REQUEST {
        let acc = acceptor.expect("checked above");
        wire::write_all(&mut socket, b"S").await.map_err(e)?;
        let tls = acc.accept(socket).await.map_err(|e| format!("TLS: {e}"))?;
        let mut io: Box<dyn Io> = Box::new(tls);
        let next = wire::read_startup(&mut io).await.map_err(e)?;
        (io, next)
    } else {
        if config.proxy.require_tls && first.code == wire::PROTOCOL_3 {
            let msg =
                wire::fatal_response("28000", "ariodb requires TLS; connect with sslmode=require");
            let _ = wire::write_all(&mut socket, &msg).await;
            return Ok(None);
        }
        (Box::new(socket), first)
    };
    if first.code == wire::CANCEL_REQUEST {
        handle_cancel(&first.body, cancels).await;
        return Ok(None);
    }
    if first.code != wire::PROTOCOL_3 {
        let msg = wire::fatal_response("08P01", "unsupported protocol version");
        let _ = wire::write_all(&mut io, &msg).await;
        return Ok(None);
    }
    if over_limit {
        let msg = wire::fatal_response("53300", &format!("ariodb: {TOO_MANY_CLIENTS}"));
        let _ = wire::write_all(&mut io, &msg).await;
        return Ok(None);
    }

    let params = wire::startup_params(&first.body);
    let user = params
        .iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    // Agents prove who they are with their token, sent as the password.
    wire::write_all(&mut io, &wire::auth_cleartext())
        .await
        .map_err(e)?;
    let reply = wire::read_frame(&mut io).await.map_err(e)?;
    let given = reply
        .body
        .strip_suffix(&[0])
        .unwrap_or(&reply.body)
        .to_vec();
    let agent = config.agent(&user).cloned();
    let token = agent.as_ref().and_then(|a| config.agent_token(a));
    let ok = reply.tag == b'p' && token.is_some_and(|t| constant_time_eq(t.as_bytes(), &given));
    let Some(agent) = agent.filter(|_| ok) else {
        let msg = wire::fatal_response(
            "28P01",
            &format!("password authentication failed for user \"{user}\""),
        );
        let _ = wire::write_all(&mut io, &msg).await;
        return Ok(None);
    };
    Ok(Some((io, agent)))
}

async fn handle_cancel(body: &[u8], cancels: &CancelMap) {
    if body.len() < 8 {
        return;
    }
    let key = (
        i32::from_be_bytes(body[0..4].try_into().unwrap()),
        i32::from_be_bytes(body[4..8].try_into().unwrap()),
    );
    let found = cancels.lock().expect("cancel map").get(&key).cloned();
    if let Some((target, upstream_key, live)) = found {
        live.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        upstream::cancel(&target, upstream_key).await;
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Small extension so a boxed stream can write frames and flush.
trait FrameIo {
    async fn write_all_frame(&mut self, f: &[u8]) -> Result<(), WireError>;
    async fn flush_all(&mut self) -> Result<(), WireError>;
}

impl<T: tokio::io::AsyncWrite + Unpin + Send> FrameIo for T {
    async fn write_all_frame(&mut self, f: &[u8]) -> Result<(), WireError> {
        tokio::io::AsyncWriteExt::write_all(self, f).await?;
        Ok(())
    }
    async fn flush_all(&mut self) -> Result<(), WireError> {
        tokio::io::AsyncWriteExt::flush(self).await?;
        Ok(())
    }
}

type ClientWriter = tokio::io::WriteHalf<Box<dyn Io>>;

struct ClientSink<'a>(&'a mut ClientWriter);

impl Sink for ClientSink<'_> {
    async fn send(&mut self, frame: Bytes) -> Result<(), WireError> {
        self.0.write_all_frame(&frame).await
    }
}

// ---------------------------------------------------------------------------
// Hidden statements ariodb uses to run its own transaction control.

const BEGIN_RO: &str = "__ariodb_begin_ro";
const BEGIN_RW: &str = "__ariodb_begin_rw";
const TIMEOUT: &str = "__ariodb_timeout";
const TAG: &str = "__ariodb_tag";
const EFFECTS: &str = "__ariodb_effects";
const EFFECTS_BASE: &str = "__ariodb_effects_base";
const COMMIT: &str = "__ariodb_commit";
const ROLLBACK: &str = "__ariodb_rollback";

async fn prepare_internal(session: &mut Session) -> Result<(), String> {
    let check = if session.measured {
        crate::config::WriteCheck::Measured
    } else {
        crate::config::WriteCheck::Reported
    };
    let mut statements = vec![
        (BEGIN_RO, "BEGIN READ ONLY"),
        (BEGIN_RW, "BEGIN"),
        (TIMEOUT, "SELECT set_config('statement_timeout', $1, true)"),
        (EFFECTS_BASE, gate::effects_base_sql(check)),
        (EFFECTS, gate::effects_sql(check)),
        (COMMIT, "COMMIT"),
        (ROLLBACK, "ROLLBACK"),
    ];
    if session.tagging {
        statements.push((
            TAG,
            "SELECT pg_logical_emit_message(true, 'ariodb', $1::text)",
        ));
    }
    let mut out = Vec::new();
    for (name, sql) in statements {
        out.extend_from_slice(&wire::parse_message(name, sql));
    }
    out.extend_from_slice(&wire::sync_message());
    let up = &mut session.up;
    up.send(&out).await.map_err(|e| e.to_string())?;
    loop {
        let f = up.recv().await.map_err(|e| e.to_string())?;
        match f.tag {
            b'E' => {
                return Err(format!(
                    "cannot prepare internal statements: {}",
                    wire::parse_error(&f.body).message
                ));
            }
            b'Z' => return Ok(()),
            _ => {}
        }
    }
}

/// Statement and portal names starting with this belong to ariodb. If an
/// agent could close `__ariodb_rollback` and parse something else under its
/// name, ariodb's own transaction control would stop doing what it says, so
/// any message naming one is refused.
const RESERVED_PREFIX: &str = "__ariodb";

/// The first reserved statement or portal name a message uses, if any.
fn reserved_name(f: &Frame) -> Result<Option<String>, WireError> {
    let names = match f.tag {
        b'P' => vec![wire::parse_parse(&f.body)?.0],
        b'B' => {
            let (portal, statement) = wire::parse_bind(&f.body)?;
            vec![portal, statement]
        }
        b'E' => vec![wire::parse_execute(&f.body)?],
        // Close and Describe share a layout: a kind byte, then the name.
        b'C' | b'D' => vec![wire::parse_close(&f.body)?.1],
        _ => Vec::new(),
    };
    Ok(names
        .into_iter()
        .find(|n| n.to_ascii_lowercase().starts_with(RESERVED_PREFIX)))
}

/// An internal operation: Bind and Execute one hidden statement.
fn internal_op(statement: &str, params: &[&str]) -> Vec<Out> {
    let portal = format!("{statement}_p");
    vec![
        Out::Internal(
            wire::bind_with_params(&portal, statement, params),
            Expect::Bind,
        ),
        Out::Internal(wire::execute_message(&portal), Expect::Execute),
    ]
}

/// Run one hidden statement, then Sync.
fn end_with(statement: &str) -> Vec<Out> {
    let mut out = internal_op(statement, &[]);
    out.push(Out::Internal(wire::sync_message(), Expect::Sync));
    out
}

// ---------------------------------------------------------------------------
// The per-connection loop.

/// What a forwarded message will produce in response.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    Parse,
    Bind,
    Close,
    DescribeStatement,
    DescribePortal,
    Execute,
    Sync,
    Nothing,
}

impl Expect {
    fn of(f: &Frame) -> Expect {
        match f.tag {
            b'P' => Expect::Parse,
            b'B' => Expect::Bind,
            b'C' => Expect::Close,
            b'D' if f.body.first() == Some(&b'S') => Expect::DescribeStatement,
            b'D' => Expect::DescribePortal,
            b'E' => Expect::Execute,
            b'S' => Expect::Sync,
            _ => Expect::Nothing,
        }
    }

    /// Is this response the last one for the message?
    fn done_by(self, tag: u8) -> bool {
        match self {
            Expect::Parse => tag == b'1',
            Expect::Bind => tag == b'2',
            Expect::Close => tag == b'3',
            Expect::DescribeStatement | Expect::DescribePortal => tag == b'T' || tag == b'n',
            Expect::Execute => matches!(tag, b'C' | b'I' | b's'),
            Expect::Sync => tag == b'Z',
            Expect::Nothing => true,
        }
    }
}

enum Out {
    Client(Frame),
    Internal(Bytes, Expect),
}

impl Out {
    fn bytes(&self) -> &[u8] {
        match self {
            Out::Client(f) => &f.raw,
            Out::Internal(b, _) => b,
        }
    }
    fn expect(&self) -> Expect {
        match self {
            Out::Client(f) => Expect::of(f),
            Out::Internal(_, e) => *e,
        }
    }
    fn is_internal(&self) -> bool {
        matches!(self, Out::Internal(..))
    }
}

struct Prepared {
    statements: Vec<Statement>,
}

struct Connection {
    session: Session,
    client: ClientWriter,
    /// Frames from the agent, read by a separate task.
    frames: tokio::sync::mpsc::Receiver<Result<Frame, WireError>>,
    prepared: HashMap<String, Prepared>,
    portals: HashMap<String, String>,
    batch: Vec<Frame>,
    /// After an error mid-batch, ignore messages until Sync.
    skipping: bool,
    /// A Flush ran the batch early; the next Sync only needs ReadyForQuery.
    ran_early: bool,
}

impl Connection {
    fn new(
        session: Session,
        client: ClientWriter,
        frames: tokio::sync::mpsc::Receiver<Result<Frame, WireError>>,
    ) -> Connection {
        Connection {
            session,
            client,
            frames,
            prepared: HashMap::new(),
            portals: HashMap::new(),
            batch: Vec::new(),
            skipping: false,
            ran_early: false,
        }
    }

    async fn run(mut self) -> Result<(), String> {
        let e = |e: WireError| e.to_string();
        loop {
            let next = match self.frames.recv().await {
                Some(next) => next,
                None => return Ok(()),
            };
            let f = match next {
                Ok(f) => f,
                Err(WireError::TooLarge(n)) => {
                    self.session.audit(
                        "<too large>",
                        &[],
                        "refused",
                        None,
                        Some("statement over 1 MiB"),
                        Instant::now(),
                    );
                    let msg =
                        format!("ariodb: message of {n} bytes is over the 1 MiB inspection limit");
                    self.client
                        .write_all_frame(&wire::error_response("54000", &msg))
                        .await
                        .map_err(e)?;
                    self.batch.clear();
                    self.skipping = true;
                    self.client.flush_all().await.map_err(e)?;
                    continue;
                }
                Err(WireError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(err) => return Err(err.to_string()),
            };
            if matches!(f.tag, b'Q' | b'S' | b'H') {
                // A cancel only applies to the statement in flight.
                self.session
                    .live
                    .cancelled
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            match f.tag {
                b'Q' => {
                    let sql = wire::take_cstr(&mut f.body.clone()).map_err(e)?;
                    self.skipping = false;
                    self.session
                        .simple(&sql, &mut ClientSink(&mut self.client))
                        .await
                        .map_err(e)?;
                    self.client
                        .write_all_frame(&wire::ready(b'I'))
                        .await
                        .map_err(e)?;
                    self.client.flush_all().await.map_err(e)?;
                }
                b'P' | b'B' | b'D' | b'E' | b'C' => {
                    if !self.skipping {
                        self.batch.push(f);
                    }
                }
                b'H' => {
                    if !self.skipping && !self.batch.is_empty() {
                        self.run_batch(false).await.map_err(e)?;
                        self.ran_early = true;
                    }
                    self.client.flush_all().await.map_err(e)?;
                }
                b'S' => {
                    if self.skipping || (self.ran_early && self.batch.is_empty()) {
                        self.skipping = false;
                        self.ran_early = false;
                        self.client
                            .write_all_frame(&wire::ready(b'I'))
                            .await
                            .map_err(e)?;
                    } else {
                        self.ran_early = false;
                        self.run_batch(true).await.map_err(e)?;
                    }
                    self.client.flush_all().await.map_err(e)?;
                }
                b'X' => return Ok(()),
                b'F' => {
                    let msg = "ariodb: the function-call protocol is not supported";
                    self.client
                        .write_all_frame(&wire::error_response("0A000", msg))
                        .await
                        .map_err(e)?;
                    self.client
                        .write_all_frame(&wire::ready(b'I'))
                        .await
                        .map_err(e)?;
                    self.client.flush_all().await.map_err(e)?;
                }
                _ => {} // stray COPY data and the like
            }
        }
    }

    /// Refuse the current batch: error, then (at Sync) ReadyForQuery.
    async fn refuse(
        &mut self,
        r: &Refusal,
        sql: &str,
        statements: &[Statement],
        final_sync: bool,
    ) -> Result<(), WireError> {
        self.session.audit_rule(
            sql,
            statements,
            "refused",
            None,
            Some(&r.message),
            None,
            &r.decided_by,
            Instant::now(),
        );
        self.batch.clear();
        self.client
            .write_all_frame(&wire::error_response(
                r.code,
                &format!("ariodb: {}", r.message),
            ))
            .await?;
        if final_sync {
            self.client.write_all_frame(&wire::ready(b'I')).await?;
        } else {
            self.skipping = true;
        }
        Ok(())
    }

    async fn run_batch(&mut self, final_sync: bool) -> Result<(), WireError> {
        let started = Instant::now();
        let batch = std::mem::take(&mut self.batch);

        // 0. ariodb's own statements and portals are off limits.
        for f in &batch {
            if let Some(name) = reserved_name(f)? {
                let r = Refusal::new(format!(
                    "the name '{name}' is reserved for ariodb's own statements"
                ));
                return self.refuse(&r, "", &[], final_sync).await;
            }
        }

        // 1. Understand every statement the batch prepares or runs.
        let mut parsed_here: HashMap<String, Vec<Statement>> = HashMap::new();
        let mut portals = self.portals.clone();
        let mut executed: Vec<Statement> = Vec::new();
        let mut closed: Vec<String> = Vec::new();
        let mut sql_text = Vec::new();
        for f in &batch {
            match f.tag {
                b'P' => {
                    let (name, sql) = wire::parse_parse(&f.body)?;
                    match classify::classify(&sql) {
                        Ok(stmts) => {
                            parsed_here.insert(name, stmts);
                        }
                        Err(err) => {
                            let r = Refusal::new(err.to_string());
                            return self.refuse(&r, &sql, &[], final_sync).await;
                        }
                    }
                }
                b'B' => {
                    let (portal, statement) = wire::parse_bind(&f.body)?;
                    portals.insert(portal, statement);
                }
                b'C' => {
                    let (kind, name) = wire::parse_close(&f.body)?;
                    if kind == b'S' {
                        closed.push(name);
                    } else {
                        portals.remove(&name);
                    }
                }
                b'E' => {
                    let portal = wire::parse_execute(&f.body)?;
                    let stmts = portals.get(&portal).and_then(|s| {
                        parsed_here
                            .get(s)
                            .or_else(|| self.prepared.get(s).map(|p| &p.statements))
                    });
                    match stmts {
                        Some(s) => {
                            sql_text.extend(s.iter().map(|x| x.sql.clone()));
                            executed.extend(s.iter().cloned());
                        }
                        None => {
                            let r =
                                Refusal::new(format!("ariodb has no record of portal '{portal}'"));
                            return self.refuse(&r, "", &[], final_sync).await;
                        }
                    }
                }
                _ => {}
            }
        }
        let sql = sql_text.join("; ");

        // Statements prepared but not run are still checked, so a refused
        // statement fails at Parse, as an agent would expect.
        for stmts in parsed_here.values() {
            if let Err(r) = gate::check(&self.session.state, &self.session.ctx(), stmts).await {
                let text = stmts
                    .iter()
                    .map(|s| s.sql.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                return self.refuse(&r, &text, stmts, final_sync).await;
            }
        }
        let (plan, approved) =
            match gate::check_detailed(&self.session.state, &self.session.ctx(), &executed).await {
                Ok(p) => p,
                Err(r) => return self.refuse(&r, &sql, &executed, final_sync).await,
            };

        // 2. Build what goes to the database.
        let has_execute = batch.iter().any(|f| f.tag == b'E');
        let config = self.session.state.config();
        let mut out: Vec<Out> = Vec::new();
        let mut opened = false;
        for f in batch {
            if f.tag == b'E' && !opened {
                opened = true;
                let begin = if plan == Plan::Write {
                    BEGIN_RW
                } else {
                    BEGIN_RO
                };
                out.extend(internal_op(begin, &[]));
                let timeout = config.limits.statement_timeout_ms.to_string();
                out.extend(internal_op(TIMEOUT, &[&timeout]));
                if plan == Plan::Write && self.session.tagging {
                    let tag = serde_json::json!({ "session": self.session.id, "agent": self.session.agent.name }).to_string();
                    out.extend(internal_op(TAG, &[&tag]));
                }
                if plan == Plan::Write {
                    out.extend(internal_op(EFFECTS_BASE, &[]));
                }
            }
            out.push(Out::Client(f));
        }

        // 3. Send, read back, decide.
        let outcome = if !has_execute {
            out.push(Out::Internal(wire::sync_message(), Expect::Sync));
            self.exchange(&out, Hold::Stream).await?
        } else if plan == Plan::Read {
            out.extend(internal_op(COMMIT, &[]));
            out.push(Out::Internal(wire::sync_message(), Expect::Sync));
            self.exchange(&out, Hold::Stream).await?
        } else {
            out.extend(internal_op(EFFECTS, &[]));
            out.push(Out::Internal(wire::flush_message(), Expect::Nothing));
            self.exchange(&out, Hold::All).await?
        };

        let mut status = outcome.status;
        let mut audit_outcome = if outcome.error.is_some() {
            "failed"
        } else {
            "allowed"
        };
        let mut reason = outcome.error.clone();
        let mut rows = None;
        let mut send = outcome.held;
        let mut decided_by = approved.by.clone();

        if has_execute && plan == Plan::Write {
            if outcome.error.is_some() {
                // The database is skipping to Sync; finish and roll back.
                let tail = [Out::Internal(wire::sync_message(), Expect::Sync)];
                self.exchange(&tail, Hold::All).await?;
                let tail = end_with(ROLLBACK);
                status = self.exchange(&tail, Hold::All).await?.status;
            } else {
                let effects = gate::effects_since(&outcome.internal_rows);
                let reported = wire::reported_rows(&send);
                rows = Some(if self.session.measured {
                    gate::total_rows(&effects)
                } else {
                    reported
                });
                let verdict = gate::judge_write(
                    &self.session.state,
                    &self.session.ctx(),
                    &executed,
                    &effects,
                    reported,
                    self.session.measured,
                )
                .await;
                match &verdict {
                    Ok(after) => decided_by.extend(after.iter().cloned()),
                    Err(r) => decided_by.extend(r.decided_by.iter().cloned()),
                }
                let end = if verdict.is_ok() { COMMIT } else { ROLLBACK };
                let tail = end_with(end);
                let finish = self.exchange(&tail, Hold::All).await?;
                status = finish.status;
                if let Some(err) = finish.error {
                    audit_outcome = "failed";
                    reason = Some(err);
                    send.extend(finish.held);
                } else if let Err(r) = verdict {
                    audit_outcome = "rolled_back";
                    reason = Some(r.message.clone());
                    send = outcome.before_execute;
                    send.push(wire::error_response(
                        r.code,
                        &format!("ariodb: {}", r.message),
                    ));
                }
            }
        }
        if status == b'E' || status == b'T' {
            // A transaction is still open (an error in a read batch). Close it.
            let tail = end_with(ROLLBACK);
            self.exchange(&tail, Hold::All).await?;
        }

        for f in send {
            self.client.write_all_frame(&f).await?;
        }
        if final_sync {
            self.client.write_all_frame(&wire::ready(b'I')).await?;
        }
        if has_execute {
            let rule = if audit_outcome == "allowed" {
                approved.rule.as_deref()
            } else {
                None
            };
            self.session.audit_rule(
                &sql,
                &executed,
                audit_outcome,
                rows,
                reason.as_deref(),
                rule,
                &decided_by,
                started,
            );
        }

        // 4. Remember what was prepared; portals end with the transaction.
        if outcome.error.is_none() {
            for (name, statements) in parsed_here {
                self.prepared.insert(name, Prepared { statements });
            }
            for name in closed {
                self.prepared.remove(&name);
            }
            self.portals = if has_execute || final_sync {
                HashMap::new()
            } else {
                portals
            };
        } else {
            // The database may have kept some of this batch's statements and
            // not others, so ariodb no longer knows what these names hold.
            // Forgetting them means a later Bind to one is refused, rather
            // than judged as whatever the name used to mean.
            for name in parsed_here.keys().chain(closed.iter()) {
                self.prepared.remove(name);
            }
            self.portals = HashMap::new();
        }
        Ok(())
    }

    /// Send messages and read every response they produce. Responses to the
    /// agent's messages are streamed or held; responses to ariodb's own
    /// messages are consumed.
    async fn exchange(&mut self, out: &[Out], hold: Hold) -> Result<Exchange, WireError> {
        let mut bytes = Vec::new();
        for o in out {
            bytes.extend_from_slice(o.bytes());
        }
        self.session.up.send(&bytes).await?;

        let mut ex = Exchange {
            status: b'I',
            error: None,
            held: Vec::new(),
            before_execute: Vec::new(),
            internal_rows: Vec::new(),
        };
        let mut i = 0;
        let skip_to_sync = |i: &mut usize| {
            while *i < out.len() && out[*i].expect() != Expect::Sync {
                *i += 1;
            }
        };
        // Messages that produce no response are passed over.
        let advance = |i: &mut usize| {
            while *i < out.len() && out[*i].expect() == Expect::Nothing {
                *i += 1;
            }
        };
        advance(&mut i);
        while i < out.len() {
            let f = self.session.up.recv().await?;
            // Notices and notifications can arrive at any time.
            if matches!(f.tag, b'N' | b'A' | b'S') {
                if !out[i].is_internal() {
                    self.forward(&f, hold, &mut ex, false).await?;
                }
                continue;
            }
            let current = &out[i];
            if f.tag == b'E' {
                ex.error.get_or_insert(wire::parse_error(&f.body).message);
                self.forward(&f, hold, &mut ex, false).await?;
                skip_to_sync(&mut i);
                if i >= out.len() {
                    break; // no Sync in this exchange; the database waits for one
                }
                continue;
            }
            if f.tag == b'Z' {
                ex.status = f.body.first().copied().unwrap_or(b'I');
                i += 1;
                advance(&mut i);
                continue;
            }
            if current.is_internal() {
                if f.tag == b'D' {
                    ex.internal_rows.push(wire::parse_data_row(&f.body));
                }
            } else {
                let before_execute = current.expect() != Expect::Execute;
                self.forward(&f, hold, &mut ex, before_execute).await?;
            }
            if current.expect().done_by(f.tag) {
                i += 1;
                advance(&mut i);
            }
        }
        if hold == Hold::Stream {
            self.client.flush_all().await?;
        }
        Ok(ex)
    }

    async fn forward(
        &mut self,
        f: &Frame,
        hold: Hold,
        ex: &mut Exchange,
        before_execute: bool,
    ) -> Result<(), WireError> {
        match hold {
            Hold::Stream => self.client.write_all_frame(&f.raw).await,
            Hold::All => {
                ex.held.push(f.raw.clone());
                if before_execute {
                    ex.before_execute.push(f.raw.clone());
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Hold {
    /// Send to the agent as it arrives (reads).
    Stream,
    /// Keep until ariodb decides (writes).
    All,
}

struct Exchange {
    status: u8,
    error: Option<String>,
    held: Vec<Bytes>,
    /// Held responses from before the first Execute (ParseComplete and so on).
    before_execute: Vec<Bytes>,
    internal_rows: Vec<Vec<Option<String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Send a startup message and, when asked, the token; return the
    /// SQLSTATE and message of the error that ends the connection.
    async fn startup(port: u16, user: &str, token: Option<&str>) -> (String, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(&wire::startup_message(&[("user", user), ("database", "app")]))
            .await
            .unwrap();
        loop {
            let f = match wire::read_frame(&mut s).await {
                Ok(f) => f,
                Err(e) => return ("closed".into(), e.to_string()),
            };
            match f.tag {
                b'R' => {
                    let t = token.expect("asked for the token");
                    let mut body = t.as_bytes().to_vec();
                    body.push(0);
                    s.write_all(&wire::frame(b'p', &body)).await.unwrap();
                }
                b'E' => {
                    let fields: Vec<&[u8]> = f.body.split(|b| *b == 0).collect();
                    let field = |c: u8| {
                        fields
                            .iter()
                            .find(|x| x.first() == Some(&c))
                            .map(|x| String::from_utf8_lossy(&x[1..]).to_string())
                            .unwrap_or_default()
                    };
                    return (field(b'C'), field(b'M'));
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn connections_over_the_limits_are_refused_with_53300() {
        // A database that accepts connections and never answers, so a
        // logged-in agent's session stays open, waiting for it.
        let db = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let db_addr = db.local_addr().unwrap();
        let _db = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = db.accept().await {
                held.push(s);
            }
        });
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = std::env::temp_dir().join(format!("ariodb-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let toml = format!(
            r#"
            [database]
            url = "postgres://gw:not-a-real-password@{db_addr}/app"
            tls = "disable"
            [limits]
            max_connections = 2
            max_connections_per_agent = 1
            handshake_timeout_ms = 400
            [proxy]
            listen = "127.0.0.1:{port}"
            [journal]
            enabled = false
            dir = "{dir}"
            [dashboard]
            listen = ""
            [[agents]]
            name = "bot"
            access = "read_only"
            tables = ["t"]
            token_env = "ARIODB_LIMITS_TEST_TOKEN"
            "#,
            dir = dir.display(),
        );
        // SAFETY: no other test reads or writes this variable.
        unsafe { std::env::set_var("ARIODB_LIMITS_TEST_TOKEN", "agent-token-local-test-only") };
        let config = crate::config::Config::from_toml(&toml).unwrap();
        let audit = Arc::new(crate::audit::AuditLog::open(&dir, &config.audit).unwrap());
        let state = State::new(config, dir.join("ariodb.toml"), audit).unwrap();
        let server = tokio::spawn(serve(state));
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let token = Some("agent-token-local-test-only");

        // The agent's first connection logs in and waits on the database...
        let first = tokio::spawn(startup(port, "bot", token));
        tokio::time::sleep(Duration::from_millis(100)).await;
        // ...so its second is over its own limit.
        let (code, message) = startup(port, "bot", token).await;
        assert_eq!(code, "53300", "{message}");
        assert!(message.contains("too many connections for agent \"bot\""), "{message}");

        // A silent client takes the listener's last place, so the next
        // client is refused once its startup arrives...
        let mut silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (code, message) = startup(port, "bot", None).await;
        assert_eq!(code, "53300", "{message}");
        assert!(message.contains("too many clients"), "{message}");

        // ...until the handshake timeout cuts the silent one off.
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
            .await
            .expect("the silent client was not cut off");
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // A wrong token is still told so: the place is free again.
        let (code, _) = startup(port, "bot", Some("wrong")).await;
        assert_eq!(code, "28P01");

        first.abort();
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn frame_of(raw: Bytes) -> Frame {
        Frame {
            tag: raw[0],
            body: raw.slice(5..),
            raw,
        }
    }

    #[test]
    fn internal_names_are_reserved() {
        let reserved = |raw: Bytes| reserved_name(&frame_of(raw)).unwrap();
        // Closing or describing ariodb's own statements is refused.
        assert_eq!(
            reserved(wire::frame(b'C', b"S__ariodb_rollback\0")).as_deref(),
            Some("__ariodb_rollback")
        );
        assert!(reserved(wire::frame(b'D', b"P__ariodb_commit_p\0")).is_some());
        // So is reusing their names, in any case.
        assert!(reserved(wire::parse_message("__ARIODB_effects", "SELECT 1")).is_some());
        assert!(reserved(wire::bind_with_params("", "__ariodb_begin_ro", &[])).is_some());
        assert!(reserved(wire::bind_with_params("__ariodb_tag_p", "s1", &[])).is_some());
        assert!(reserved(wire::execute_message("__ariodb_begin_rw_p")).is_some());
        // The agent's own names are fine.
        assert_eq!(reserved(wire::parse_message("s1", "SELECT 1")), None);
        assert_eq!(reserved(wire::bind_with_params("", "", &[])), None);
        assert_eq!(reserved(wire::frame(b'C', b"Ss1\0")), None);
    }
}
