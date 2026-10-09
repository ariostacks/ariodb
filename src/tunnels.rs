//! Tunnels: side processes that carry ariodb's connections to a database,
//! such as cloud-sql-proxy, an IAP tunnel or an SSH port-forward.
//!
//! ariodb starts each one, waits until its local port accepts connections,
//! restarts it with backoff when it exits, and stops it on shutdown. A
//! connection that names a tunnel dials the tunnel's `listen` address
//! instead of the host and port in its URL; everything else in the URL
//! (user, password, database, TLS) is kept, so TLS is still checked against
//! the real database's name.

use serde::Deserialize;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

/// One `[[tunnels]]` entry.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TunnelConfig {
    pub name: String,
    /// The program and its arguments. Run directly, not through a shell.
    pub command: Vec<String>,
    /// The local address the process listens on, such as `127.0.0.1:5433`.
    pub listen: String,
    /// How ariodb knows the tunnel is up. Only `tcp` (a connection succeeds) for now.
    #[serde(default)]
    pub ready_probe: Probe,
    #[serde(default = "default_ready_timeout")]
    pub ready_timeout_seconds: u64,
    /// Start it again when it exits.
    #[serde(default = "default_restart")]
    pub restart: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    #[default]
    Tcp,
}

fn default_ready_timeout() -> u64 {
    30
}

fn default_restart() -> bool {
    true
}

impl TunnelConfig {
    /// The listen address. `validate` has already checked it parses.
    pub fn addr(&self) -> Result<SocketAddr, String> {
        self.listen.parse().map_err(|_| {
            format!(
                "tunnel '{}': listen = \"{}\" must be an IP address and port, such as 127.0.0.1:5433",
                self.name, self.listen
            )
        })
    }
}

/// Checks TOML alone cannot express.
pub fn validate(tunnels: &[TunnelConfig]) -> Result<(), String> {
    let mut names = std::collections::HashSet::new();
    let mut addrs = std::collections::HashMap::new();
    for t in tunnels {
        if t.name.trim().is_empty() {
            return Err("every tunnel needs a name".to_string());
        }
        if !names.insert(t.name.as_str()) {
            return Err(format!("tunnel '{}' is listed twice", t.name));
        }
        if t.command
            .first()
            .is_none_or(|program| program.trim().is_empty())
        {
            return Err(format!(
                "tunnel '{}' needs a command, such as [\"cloud-sql-proxy\", \"--port\", \"5433\", \"project:region:instance\"]",
                t.name
            ));
        }
        let addr = t.addr()?;
        if let Some(other) = addrs.insert(addr, t.name.as_str()) {
            return Err(format!(
                "tunnels '{other}' and '{}' both listen on {addr}",
                t.name
            ));
        }
        if t.ready_timeout_seconds == 0 {
            return Err(format!(
                "tunnel '{}': ready_timeout_seconds must be at least 1",
                t.name
            ));
        }
    }
    Ok(())
}

/// Look up a tunnel a connection refers to.
pub fn find<'a>(tunnels: &'a [TunnelConfig], name: &str) -> Result<&'a TunnelConfig, String> {
    tunnels
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| format!("tunnel '{name}' is not defined in [[tunnels]]"))
}

/// The running tunnels. Dropping it kills them; `stop` ends them politely.
pub struct Supervisor {
    running: Vec<Running>,
}

struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Supervisor {
    /// Start every tunnel and wait until each accepts connections.
    ///
    /// With `reuse_running`, a tunnel whose port already answers is left
    /// alone: a one-off command such as `ariodb undo` can then use the
    /// tunnel `ariodb serve` is supervising. Without it, a busy port is an
    /// error, because ariodb could not tell its own tunnel from a stranger.
    pub async fn start(
        tunnels: &[TunnelConfig],
        reuse_running: bool,
    ) -> Result<Supervisor, String> {
        let mut supervisor = Supervisor {
            running: Vec::new(),
        };
        let mut waiting = Vec::new();
        for t in tunnels {
            let addr = t.addr()?;
            if accepts(addr).await {
                if reuse_running {
                    continue;
                }
                supervisor.stop().await;
                return Err(format!(
                    "tunnel '{}': {addr} is already in use; stop whatever is listening there (another ariodb?) or pick another listen address",
                    t.name
                ));
            }
            let (stop_tx, stop_rx) = watch::channel(false);
            let (ready_tx, ready_rx) = oneshot::channel();
            let task = tokio::spawn(supervise(t.clone(), addr, stop_rx, ready_tx));
            supervisor.running.push(Running {
                stop: stop_tx,
                task,
            });
            waiting.push((t.name.clone(), ready_rx));
        }
        for (name, ready) in waiting {
            let outcome = ready
                .await
                .unwrap_or_else(|_| Err(format!("tunnel '{name}' stopped unexpectedly")));
            if let Err(e) = outcome {
                supervisor.stop().await;
                return Err(e);
            }
        }
        Ok(supervisor)
    }

    /// Stop every tunnel and wait for the processes to exit.
    pub async fn stop(&mut self) {
        for r in &self.running {
            let _ = r.stop.send(true);
        }
        for r in self.running.drain(..) {
            let _ = r.task.await;
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Tasks hold their children with kill_on_drop, so aborting them
        // kills the processes even if `stop` was never called.
        for r in &self.running {
            r.task.abort();
        }
    }
}

/// Does something accept TCP connections at this address right now?
async fn accepts(addr: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Restart delays: 1 s, doubling to 30 s. A run that lasted a minute
/// resets it, so a tunnel that drops once a day restarts at once.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_AFTER: Duration = Duration::from_secs(60);

/// Run one tunnel until told to stop. The first readiness result goes to
/// `ready`; a failure there ends the tunnel instead of retrying, so a
/// misconfigured tunnel stops `ariodb serve` with a clear error.
async fn supervise(
    t: TunnelConfig,
    addr: SocketAddr,
    mut stop: watch::Receiver<bool>,
    ready: oneshot::Sender<Result<(), String>>,
) {
    let mut ready = Some(ready);
    let mut backoff = FIRST_BACKOFF;
    loop {
        let started = Instant::now();
        let mut child = match spawn(&t) {
            Ok(c) => c,
            Err(e) => {
                if let Some(r) = ready.take() {
                    let _ = r.send(Err(e));
                    return;
                }
                eprintln!("ariodb: {e}");
                if !t.restart || !pause(&mut stop, &mut backoff).await {
                    return;
                }
                continue;
            }
        };
        let pid = child.id().unwrap_or(0);
        eprintln!(
            "ariodb: tunnel '{}' started (pid {pid}), waiting for {addr}",
            t.name
        );

        match wait_ready(&t, addr, &mut child, &mut stop).await {
            Readiness::Ready => {
                eprintln!("ariodb: tunnel '{}' is ready on {addr}", t.name);
                if let Some(r) = ready.take() {
                    let _ = r.send(Ok(()));
                }
            }
            Readiness::Stopped => {
                terminate(&mut child).await;
                return;
            }
            Readiness::Failed(why) => {
                terminate(&mut child).await;
                if let Some(r) = ready.take() {
                    let _ = r.send(Err(why));
                    return;
                }
                eprintln!("ariodb: {why}");
                if !t.restart || !pause(&mut stop, &mut backoff).await {
                    return;
                }
                continue;
            }
        }

        tokio::select! {
            status = child.wait() => {
                let how = match status {
                    Ok(s) => describe(s),
                    Err(e) => e.to_string(),
                };
                if !t.restart {
                    eprintln!("ariodb: tunnel '{}' {how}; not restarting it (restart = false)", t.name);
                    return;
                }
                if started.elapsed() >= STABLE_AFTER {
                    backoff = FIRST_BACKOFF;
                }
                eprintln!(
                    "ariodb: tunnel '{}' {how}; restarting in {} s",
                    t.name,
                    backoff.as_secs()
                );
                if !pause(&mut stop, &mut backoff).await {
                    return;
                }
            }
            _ = stop.changed() => {
                terminate(&mut child).await;
                return;
            }
        }
    }
}

/// Sleep for the backoff, then double it. False if told to stop meanwhile.
async fn pause(stop: &mut watch::Receiver<bool>, backoff: &mut Duration) -> bool {
    let delay = *backoff;
    *backoff = (*backoff * 2).min(MAX_BACKOFF);
    tokio::select! {
        _ = tokio::time::sleep(delay) => !*stop.borrow(),
        _ = stop.changed() => false,
    }
}

fn spawn(t: &TunnelConfig) -> Result<Child, String> {
    let mut cmd = Command::new(&t.command[0]);
    cmd.args(&t.command[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Its own process group, so stopping it also stops anything it started
    // (a shell wrapper's children, say), and a Ctrl-C at ariodb's terminal
    // reaches ariodb first, which then shuts the tunnel down in order.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("tunnel '{}': cannot start {}: {e}", t.name, t.command[0]))?;
    if let Some(out) = child.stdout.take() {
        tokio::spawn(relay(t.name.clone(), out));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(relay(t.name.clone(), err));
    }
    Ok(child)
}

/// Copy the tunnel's output into ariodb's log, one line at a time, with
/// the tunnel's name in front so it can be told apart from ariodb's own.
async fn relay(name: String, from: impl AsyncRead + Unpin) {
    let mut lines = BufReader::new(from).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        eprintln!("tunnel {name}: {line}");
    }
}

enum Readiness {
    Ready,
    Failed(String),
    Stopped,
}

async fn wait_ready(
    t: &TunnelConfig,
    addr: SocketAddr,
    child: &mut Child,
    stop: &mut watch::Receiver<bool>,
) -> Readiness {
    let deadline = Instant::now() + Duration::from_secs(t.ready_timeout_seconds);
    loop {
        match t.ready_probe {
            Probe::Tcp => {
                if accepts(addr).await {
                    return Readiness::Ready;
                }
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Readiness::Failed(format!(
                "tunnel '{}' {} before it accepted connections on {addr}",
                t.name,
                describe(status)
            ));
        }
        if Instant::now() >= deadline {
            return Readiness::Failed(format!(
                "tunnel '{}' did not accept connections on {addr} within {} s (ready_timeout_seconds)",
                t.name, t.ready_timeout_seconds
            ));
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = stop.changed() => return Readiness::Stopped,
        }
    }
}

pub(crate) fn describe(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exited with status {code}"),
        None => format!("was stopped ({status})"),
    }
}

/// Ask the tunnel's process group to stop, then insist after five seconds.
pub(crate) async fn terminate(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        let group = -(pid as i32);
        // SAFETY: kill(2) with a negative pid signals that process group;
        // it has no memory-safety preconditions.
        unsafe { libc::kill(group, libc::SIGTERM) };
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_ok()
        {
            // Stragglers in the group (a shell's children) go too.
            unsafe { libc::kill(group, libc::SIGKILL) };
            return;
        }
        unsafe { libc::kill(group, libc::SIGKILL) };
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(name: &str, listen: &str, command: &[&str]) -> TunnelConfig {
        TunnelConfig {
            name: name.into(),
            command: command.iter().map(|s| s.to_string()).collect(),
            listen: listen.into(),
            ready_probe: Probe::Tcp,
            ready_timeout_seconds: 5,
            restart: true,
        }
    }

    #[test]
    fn validates_names_commands_and_addresses() {
        assert!(validate(&[tunnel("a", "127.0.0.1:5433", &["x"])]).is_ok());
        let twice = validate(&[
            tunnel("a", "127.0.0.1:5433", &["x"]),
            tunnel("a", "127.0.0.1:5434", &["x"]),
        ]);
        assert!(twice.unwrap_err().contains("listed twice"));
        let empty = validate(&[tunnel("a", "127.0.0.1:5433", &[])]);
        assert!(empty.unwrap_err().contains("needs a command"));
        let blank = validate(&[tunnel("a", "127.0.0.1:5433", &[" "])]);
        assert!(blank.unwrap_err().contains("needs a command"));
        let host = validate(&[tunnel("a", "localhost:5433", &["x"])]);
        assert!(host.unwrap_err().contains("IP address and port"));
        let same_port = validate(&[
            tunnel("a", "127.0.0.1:5433", &["x"]),
            tunnel("b", "127.0.0.1:5433", &["x"]),
        ]);
        assert!(same_port.unwrap_err().contains("both listen"));
    }

    /// A free local port, found by binding to port 0 and letting go.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn python_listener(port: u16) -> Vec<&'static str> {
        // Leaked so the test helper can hand out &'static str; tests only.
        let script: &'static str = Box::leak(
            format!(
                "import socket,time\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind(('127.0.0.1',{port}))\ns.listen()\nprint('listening',flush=True)\ntime.sleep(60)"
            )
            .into_boxed_str(),
        );
        vec!["python3", "-I", "-c", script]
    }

    #[tokio::test]
    async fn starts_waits_for_the_port_and_stops() {
        if std::process::Command::new("python3")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("skipped: python3 is not installed");
            return;
        }
        let port = free_port();
        let listen = format!("127.0.0.1:{port}");
        let t = tunnel("unit", &listen, &python_listener(port));
        let mut sup = Supervisor::start(std::slice::from_ref(&t), false)
            .await
            .expect("tunnel should become ready");
        assert!(accepts(listen.parse().unwrap()).await);
        // A second, strict start must refuse the busy port.
        let busy = Supervisor::start(std::slice::from_ref(&t), false).await;
        assert!(busy.err().unwrap().contains("already in use"));
        // A lenient start reuses it and starts nothing.
        let reused = Supervisor::start(std::slice::from_ref(&t), true)
            .await
            .unwrap();
        assert!(reused.running.is_empty());
        sup.stop().await;
        assert!(!accepts(listen.parse().unwrap()).await);
    }

    #[tokio::test]
    async fn reports_a_process_that_never_listens() {
        let port = free_port();
        let mut t = tunnel("never", &format!("127.0.0.1:{port}"), &["sleep", "30"]);
        t.ready_timeout_seconds = 1;
        let err = Supervisor::start(&[t], false).await.err().unwrap();
        assert!(err.contains("did not accept connections"), "{err}");

        let t = tunnel("dies", &format!("127.0.0.1:{port}"), &["false"]);
        let err = Supervisor::start(&[t], false).await.err().unwrap();
        assert!(err.contains("exited with status 1"), "{err}");

        let t = tunnel(
            "missing",
            &format!("127.0.0.1:{port}"),
            &["/no/such/program"],
        );
        let err = Supervisor::start(&[t], false).await.err().unwrap();
        assert!(err.contains("cannot start /no/such/program"), "{err}");
    }
}
