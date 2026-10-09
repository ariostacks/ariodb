//! Connection limits and handshake timeouts, the same for every listener:
//! the Postgres and MySQL proxies, the ClickHouse HTTP and native
//! listeners, and the dashboard.
//!
//! Each listener holds at most `[limits] max_connections` connections at
//! once, logged in or not, and each agent at most
//! `max_connections_per_agent` of them once it has logged in. A new
//! connection has `handshake_timeout_ms` for TLS, startup and logging in
//! (for HTTP, for each request's headers); one that takes longer is closed,
//! so silent or slow clients cannot hold places for ever.
//!
//! Over a limit, a client hears its own protocol's error rather than a
//! silent close: Postgres `53300 too_many_connections`, MySQL 1040 (or 1203
//! for one agent), a ClickHouse exception, HTTP 503. Telling it takes a
//! little work (reading a Postgres startup message, say), so at most
//! `MAX_REFUSING` clients are told at once and any more are closed at once.
//! Refusals are logged once per burst, not once per connection.
//!
//! The limits are read from the current config at each new connection, so
//! a config reload changes them without a restart.

use crate::config::Limits;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// At most this many over-the-limit clients are told so at once, each
/// within the handshake timeout.
const MAX_REFUSING: usize = 64;
/// Refusals less than this far apart belong to one burst, logged once.
const BURST_GAP: Duration = Duration::from_secs(10);

/// One listener's connections.
pub struct Limiter {
    /// The listener, as the log names it.
    name: &'static str,
    max: AtomicUsize,
    per_agent: AtomicUsize,
    handshake_ms: AtomicU64,
    open: AtomicUsize,
    refusing: AtomicUsize,
    agents: Mutex<HashMap<String, usize>>,
    /// The current burst of refusals for the listener (key "") and for
    /// each agent at its own limit.
    bursts: Mutex<HashMap<String, Burst>>,
}

#[derive(Default)]
struct Burst {
    last: Option<Instant>,
    /// Refusals since the burst was logged.
    unlogged: u64,
}

/// What to do with a connection just accepted.
pub enum Admission {
    /// Within the limit: serve it. Dropping the slot frees its place.
    Admitted(Slot),
    /// Over the limit: tell the client in its own protocol, then close.
    Refuse(Refusing),
    /// Over the limit with too many refusals under way: close at once.
    Drop,
}

/// A place on a listener, given back when dropped.
pub struct Slot {
    limiter: Arc<Limiter>,
    agent: Option<AgentClaim>,
}

/// One of an agent's places on a listener, given back when dropped.
pub struct AgentClaim {
    limiter: Arc<Limiter>,
    name: String,
}

/// A refusal under way, counted against `MAX_REFUSING` until dropped.
pub struct Refusing(Arc<Limiter>);

impl Limiter {
    pub fn new(name: &'static str, limits: &Limits) -> Arc<Limiter> {
        let limiter = Limiter {
            name,
            max: AtomicUsize::new(0),
            per_agent: AtomicUsize::new(0),
            handshake_ms: AtomicU64::new(0),
            open: AtomicUsize::new(0),
            refusing: AtomicUsize::new(0),
            agents: Mutex::new(HashMap::new()),
            bursts: Mutex::new(HashMap::new()),
        };
        limiter.update(limits);
        Arc::new(limiter)
    }

    /// Take up the limits of a reloaded config. Connections already open
    /// keep their places.
    pub fn update(&self, limits: &Limits) {
        self.max.store(limits.max_connections.max(1), SeqCst);
        self.per_agent
            .store(limits.max_connections_per_agent.max(1), SeqCst);
        self.handshake_ms
            .store(limits.handshake_timeout_ms.max(1), SeqCst);
    }

    /// How long a new connection has to become a logged-in agent.
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_ms.load(SeqCst))
    }

    /// Connections open now, logged in or not.
    #[cfg(test)]
    pub fn open(&self) -> usize {
        self.open.load(SeqCst)
    }

    /// Decide on a connection just accepted.
    pub fn admit(self: &Arc<Self>) -> Admission {
        let max = self.max.load(SeqCst);
        // Take the place first, so two connections cannot both get the last.
        if self.open.fetch_add(1, SeqCst) < max {
            return Admission::Admitted(Slot {
                limiter: self.clone(),
                agent: None,
            });
        }
        self.open.fetch_sub(1, SeqCst);
        self.note_refusal("", || {
            format!("refusing new connections: {max} are open, the limit ([limits] max_connections)")
        });
        if self.refusing.fetch_add(1, SeqCst) < MAX_REFUSING {
            Admission::Refuse(Refusing(self.clone()))
        } else {
            self.refusing.fetch_sub(1, SeqCst);
            Admission::Drop
        }
    }

    /// Log the first refusal (or accept error) of a burst, with how many
    /// more the previous burst had. `what` is only called to log.
    fn note_refusal(&self, key: &str, what: impl FnOnce() -> String) {
        let mut bursts = self.bursts.lock().expect("bursts lock");
        let burst = bursts.entry(key.to_string()).or_default();
        let now = Instant::now();
        let new_burst = burst.last.is_none_or(|last| now - last > BURST_GAP);
        burst.last = Some(now);
        if !new_burst {
            burst.unlogged += 1;
            return;
        }
        let before = match burst.unlogged {
            0 => String::new(),
            n => format!(" ({n} more in the previous burst)"),
        };
        burst.unlogged = 0;
        eprintln!(
            "ariodb: {}: {}; not logged again until {} s pass without one{before}",
            self.name,
            what(),
            BURST_GAP.as_secs()
        );
    }
}

impl Limiter {
    /// Count one more connection (for HTTP, one more request in flight)
    /// against an agent's limit, once the agent has logged in. `Err` holds
    /// the limit it is over, and the agent should be refused.
    pub fn claim(self: &Arc<Self>, name: &str) -> Result<AgentClaim, usize> {
        let limit = self.per_agent.load(SeqCst);
        {
            let mut agents = self.agents.lock().expect("agents lock");
            let count = agents.entry(name.to_string()).or_default();
            if *count < limit {
                *count += 1;
                return Ok(AgentClaim {
                    limiter: self.clone(),
                    name: name.to_string(),
                });
            }
        }
        self.note_refusal(name, || {
            format!(
                "refusing agent '{name}': it has {limit} connections open, the limit ([limits] max_connections_per_agent)"
            )
        });
        Err(limit)
    }
}

impl Slot {
    /// Count this connection against its agent's limit; see `claim`.
    pub fn agent(&mut self, name: &str) -> Result<(), usize> {
        self.agent = Some(self.limiter.claim(name)?);
        Ok(())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.agent = None;
        self.limiter.open.fetch_sub(1, SeqCst);
    }
}

impl Drop for AgentClaim {
    fn drop(&mut self) {
        let mut agents = self.limiter.agents.lock().expect("agents lock");
        if let Some(count) = agents.get_mut(&self.name) {
            *count -= 1;
            if *count == 0 {
                agents.remove(&self.name);
            }
        }
    }
}

impl Drop for Refusing {
    fn drop(&mut self) {
        self.0.refusing.fetch_sub(1, SeqCst);
    }
}

/// Accept the next connection. Errors such as running out of file handles
/// are waited out rather than ending the listener, and logged once per
/// burst.
pub async fn accept(listener: &TcpListener, limiter: &Limiter) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let _ = socket.set_nodelay(true);
                return (socket, addr);
            }
            Err(e) => {
                limiter.note_refusal("accept", || format!("cannot accept connections: {e}"));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP listeners (ClickHouse HTTP and the dashboard).

/// Serve an axum app within the limits: TLS (when given) and each
/// request's headers must arrive within the handshake timeout, a request's
/// body must keep arriving (see `BodyDeadline`), and the client must keep
/// reading what it is sent (see `WriteDeadline`), so no client, signed in
/// or not, can hold a place by going slow. A connection over
/// `max_connections` is answered with `refused()` (a 503) and closed.
/// `limits` gives the current config's limits. Handlers can extract
/// `ConnectInfo<SocketAddr>`.
pub async fn serve_http(
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    app: axum::Router,
    limiter: Arc<Limiter>,
    limits: impl Fn() -> Limits,
    refused: fn() -> axum::response::Response,
) {
    loop {
        let (socket, addr) = accept(&listener, &limiter).await;
        limiter.update(&limits());
        let admission = limiter.admit();
        if let Admission::Drop = admission {
            continue;
        }
        let (tls, app, timeout) = (tls.clone(), app.clone(), limiter.handshake_timeout());
        tokio::spawn(async move {
            let io: Box<dyn crate::tls::Io> = match tls {
                Some(acceptor) => match tokio::time::timeout(timeout, acceptor.accept(socket)).await {
                    Ok(Ok(stream)) => Box::new(stream),
                    _ => return,
                },
                None => Box::new(socket),
            };
            let io = hyper_util::rt::TokioIo::new(WriteDeadline::new(io, timeout));
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(timeout);
            match admission {
                Admission::Admitted(slot) => {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut req = req.map(|body| BodyDeadline::new(body, timeout));
                            req.extensions_mut()
                                .insert(axum::extract::ConnectInfo(addr));
                            tower::ServiceExt::oneshot(app.clone(), req)
                        },
                    );
                    let _ = http.serve_connection(io, service).await;
                    drop(slot);
                }
                Admission::Refuse(refusing) => {
                    http.keep_alive(false);
                    let service = hyper::service::service_fn(|_req| async move {
                        Ok::<_, std::convert::Infallible>(refused())
                    });
                    let _ = http.serve_connection(io, service).await;
                    drop(refusing);
                }
                Admission::Drop => {}
            }
        });
    }
}

/// A request body gets the handshake timeout for each `BODY_ALLOWANCE`
/// bytes of it, counted from when the request arrived.
const BODY_ALLOWANCE: u64 = 64 << 10;

/// A request body that must keep arriving: `BODY_ALLOWANCE` bytes per
/// handshake timeout at least, so a client cannot hold its place by
/// sending a byte now and then. Handlers that read the body see an error
/// once it falls behind, and the connection is closed.
struct BodyDeadline {
    inner: hyper::body::Incoming,
    timeout: Duration,
    started: tokio::time::Instant,
    received: u64,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl BodyDeadline {
    fn new(inner: hyper::body::Incoming, timeout: Duration) -> BodyDeadline {
        let started = tokio::time::Instant::now();
        BodyDeadline {
            inner,
            timeout,
            started,
            received: 0,
            deadline: Box::pin(tokio::time::sleep_until(started + timeout)),
        }
    }
}

impl hyper::body::Body for BodyDeadline {
    type Data = bytes::Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.received += data.len() as u64;
                    // At most 65536 allowances: about a week at the default.
                    let allowances = (1 + this.received / BODY_ALLOWANCE).min(1 << 16) as u32;
                    let deadline = this.started + this.timeout * allowances;
                    this.deadline.as_mut().reset(deadline);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(other) => Poll::Ready(other.map(|r| r.map_err(Into::into))),
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err(
                    "the request body arrived too slowly ([limits] handshake_timeout_ms)".into(),
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// A connection whose client must keep reading: a write that cannot go
/// out for the handshake timeout (the client has stopped reading, and its
/// buffers are full) fails, and the connection is closed. Reads are not
/// timed here: while a request waits on the database or an approval, the
/// client rightly sends nothing.
struct WriteDeadline<T> {
    inner: T,
    timeout: Duration,
    /// Running while a write waits.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> WriteDeadline<T> {
    fn new(inner: T, timeout: Duration) -> WriteDeadline<T> {
        WriteDeadline {
            inner,
            timeout,
            stalled: None,
        }
    }

    /// What a write returned, unless it has waited too long.
    fn check<R>(&mut self, cx: &mut Context<'_>, polled: Poll<std::io::Result<R>>) -> Poll<std::io::Result<R>> {
        if polled.is_ready() {
            self.stalled = None;
            return polled;
        }
        let timeout = self.timeout;
        let stalled = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match stalled.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the client stopped reading ([limits] handshake_timeout_ms)",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteDeadline<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.check(cx, polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.check(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.check(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.check(cx, polled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn limits(max: usize, per_agent: usize, handshake_ms: u64) -> Limits {
        Limits {
            max_connections: max,
            max_connections_per_agent: per_agent,
            handshake_timeout_ms: handshake_ms,
            ..Limits::default()
        }
    }

    #[test]
    fn places_are_counted_and_given_back() {
        let l = Limiter::new("test", &limits(2, 1, 1000));
        let a = l.admit();
        let b = l.admit();
        assert!(matches!(a, Admission::Admitted(_)));
        assert!(matches!(b, Admission::Admitted(_)));
        assert!(matches!(l.admit(), Admission::Refuse(_)));
        assert_eq!(l.open(), 2);
        drop(a);
        assert_eq!(l.open(), 1);
        assert!(matches!(l.admit(), Admission::Admitted(_)));
        // A reloaded config applies to the next connection.
        l.update(&limits(5, 1, 1000));
        assert!(matches!(l.admit(), Admission::Admitted(_)));
        assert_eq!(l.handshake_timeout(), Duration::from_millis(1000));
    }

    #[test]
    fn agents_are_limited_once_logged_in() {
        let l = Limiter::new("test", &limits(10, 2, 1000));
        let slot = |l: &Arc<Limiter>| match l.admit() {
            Admission::Admitted(s) => s,
            _ => panic!("not admitted"),
        };
        let (mut a, mut b, mut c, mut d) = (slot(&l), slot(&l), slot(&l), slot(&l));
        assert_eq!(a.agent("bot"), Ok(()));
        assert_eq!(b.agent("bot"), Ok(()));
        assert_eq!(c.agent("bot"), Err(2));
        // Another agent has its own count.
        assert_eq!(d.agent("other"), Ok(()));
        drop(c);
        drop(a);
        let mut e = slot(&l);
        assert_eq!(e.agent("bot"), Ok(()));
        drop((b, d, e));
        assert_eq!(l.open(), 0);
        assert!(l.agents.lock().unwrap().is_empty());
    }

    #[test]
    fn refusals_beyond_the_cap_are_dropped() {
        let l = Limiter::new("test", &limits(1, 1, 1000));
        let _held = l.admit();
        let refusing: Vec<_> = (0..MAX_REFUSING).map(|_| l.admit()).collect();
        assert!(refusing.iter().all(|a| matches!(a, Admission::Refuse(_))));
        assert!(matches!(l.admit(), Admission::Drop));
        drop(refusing);
        assert!(matches!(l.admit(), Admission::Refuse(_)));
    }

    #[test]
    fn a_burst_of_refusals_is_logged_once() {
        let l = Limiter::new("test", &limits(1, 1, 1000));
        let mut logged = 0;
        for _ in 0..50 {
            l.note_refusal("", || {
                logged += 1;
                String::new()
            });
        }
        assert_eq!(logged, 1);
        assert_eq!(l.bursts.lock().unwrap()[""].unlogged, 49);
        // An agent's refusals are a burst of their own.
        l.note_refusal("bot", || {
            logged += 1;
            String::new()
        });
        assert_eq!(logged, 2);
        // After a quiet spell, the next refusal starts a new burst.
        l.bursts.lock().unwrap().get_mut("").unwrap().last =
            Some(Instant::now() - BURST_GAP - Duration::from_secs(1));
        l.note_refusal("", || {
            logged += 1;
            String::new()
        });
        assert_eq!(logged, 3);
    }

    async fn http_get(addr: SocketAddr) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out).await;
        out
    }

    #[tokio::test]
    async fn http_listeners_refuse_with_503_and_cut_off_slow_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(
                |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>| async move {
                    format!("hello {}", peer.ip())
                },
            ),
        );
        let limiter = Limiter::new("test", &limits(1, 1, 300));
        let refused = || {
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "too many connections",
            ))
        };
        let server = tokio::spawn(serve_http(
            listener,
            None,
            app,
            limiter.clone(),
            || limits(1, 1, 300),
            refused,
        ));
        assert!(http_get(addr).await.contains("hello 127.0.0.1"));
        // A silent client holds the only place...
        let mut silent = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let busy = http_get(addr).await;
        assert!(busy.starts_with("HTTP/1.1 503"), "{busy}");
        assert!(busy.contains("too many connections"), "{busy}");
        // ...until the handshake timeout cuts it off.
        let started = Instant::now();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
            .await
            .expect("the silent client was not cut off")
            .unwrap_or(0);
        assert!(started.elapsed() < Duration::from_secs(2));
        let _ = n;
        for _ in 0..50 {
            if limiter.open() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(http_get(addr).await.contains("hello 127.0.0.1"));
        server.abort();
    }

    /// Serve `app` with room for one connection and a 300 ms timeout.
    async fn one_place(app: axum::Router) -> (SocketAddr, Arc<Limiter>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limiter = Limiter::new("test", &limits(1, 1, 300));
        let refused = || {
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "too many connections",
            ))
        };
        let server = tokio::spawn(serve_http(
            listener,
            None,
            app,
            limiter.clone(),
            || limits(1, 1, 300),
            refused,
        ));
        (addr, limiter, server)
    }

    /// Wait for the listener's place to be taken, then up to two seconds
    /// for it to be given back.
    async fn place_given_back(limiter: &Limiter) -> bool {
        while limiter.open() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for _ in 0..100 {
            if limiter.open() == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_request_body_that_stops_arriving_is_cut_off() {
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(|body: String| async move { format!("got {}", body.len()) }),
        );
        let (addr, limiter, server) = one_place(app).await;
        // The headers arrive in time, the body promised never does: no
        // client, signed in or not, may hold the place that way.
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\nSELECT")
            .await
            .unwrap();
        assert!(place_given_back(&limiter).await, "the slow body still holds the place");
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi")
            .await
            .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out).await;
        assert!(out.contains("got 2"), "{out}");
        // A body sent in pieces, within its time, is read whole...
        let post = b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 4\r\nconnection: close\r\n\r\n";
        let mut steady = TcpStream::connect(addr).await.unwrap();
        steady.write_all(post).await.unwrap();
        for b in b"abcd" {
            tokio::time::sleep(Duration::from_millis(50)).await;
            steady.write_all(&[*b]).await.unwrap();
        }
        let mut out = String::new();
        let _ = steady.read_to_string(&mut out).await;
        assert!(out.contains("got 4"), "{out}");
        // ...but a byte now and then, each in time on its own, is too slow.
        let mut trickle = TcpStream::connect(addr).await.unwrap();
        trickle.write_all(post).await.unwrap();
        let started = Instant::now();
        for b in b"abcd" {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if trickle.write_all(&[*b]).await.is_err() {
                break;
            }
        }
        let mut out = String::new();
        let _ = trickle.read_to_string(&mut out).await;
        assert!(!out.contains("got 4"), "{out}");
        assert!(started.elapsed() < Duration::from_secs(2));
        server.abort();
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_its_answer_is_cut_off() {
        let big = "x".repeat(32 << 20);
        let app = axum::Router::new()
            .route("/big", axum::routing::get(move || async move { big.clone() }))
            .route("/", axum::routing::get(|| async { "small" }));
        let (addr, limiter, server) = one_place(app).await;
        // Asks for a large answer and never reads it.
        let mut stuck = TcpStream::connect(addr).await.unwrap();
        stuck
            .write_all(b"GET /big HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        assert!(place_given_back(&limiter).await, "the unread answer still holds the place");
        assert!(http_get(addr).await.contains("small"));
        drop(stuck);
        server.abort();
    }
}
