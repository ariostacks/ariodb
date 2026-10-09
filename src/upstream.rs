//! ariodb's own connection to the database, speaking the wire protocol
//! directly so responses can be relayed to agents byte for byte.

use crate::tls::{self, Io, TlsMode};
use crate::wire::{self, Frame, WireError};
use bytes::{Buf, Bytes};
use postgres_protocol::authentication::sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256};
use std::str::FromStr;
use tokio::net::TcpStream;

/// Where and how to connect, parsed from a postgres:// URL.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: String,
    pub tls: TlsMode,
    pub ca_file: Option<String>,
    /// Set when the connection goes through a tunnel: dial this instead of
    /// `host:port`. `host` is still used for TLS, so the certificate is
    /// checked against the real database's name.
    pub via: Option<Via>,
}

/// A tunnel a connection goes through.
#[derive(Debug, Clone)]
pub struct Via {
    pub tunnel: String,
    pub addr: std::net::SocketAddr,
}

impl Target {
    pub fn from_url(
        url: &str,
        tls: Option<TlsMode>,
        ca_file: Option<String>,
    ) -> Result<Target, String> {
        let config =
            tokio_postgres::Config::from_str(url).map_err(|e| format!("bad database URL: {e}"))?;
        let host = match config.get_hosts().first() {
            Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
            _ => return Err("database URL needs a TCP host".to_string()),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        let user = config
            .get_user()
            .ok_or("database URL needs a user")?
            .to_string();
        let password = config
            .get_password()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let database = config.get_dbname().unwrap_or(&user).to_string();
        let local = host == "localhost" || host.starts_with("127.") || host == "::1";
        let tls = tls.unwrap_or(if local {
            TlsMode::Disable
        } else {
            TlsMode::Verify
        });
        Ok(Target {
            host,
            port,
            user,
            password,
            database,
            tls,
            ca_file,
            via: None,
        })
    }

    /// Send this connection through a tunnel's local address.
    pub fn through(mut self, tunnel: &crate::tunnels::TunnelConfig) -> Result<Target, String> {
        self.via = Some(Via {
            tunnel: tunnel.name.clone(),
            addr: tunnel.addr()?,
        });
        Ok(self)
    }

    /// The address to open a TCP connection to.
    pub fn dial_addr(&self) -> String {
        match &self.via {
            Some(via) => via.addr.to_string(),
            None => format!("{}:{}", self.host, self.port),
        }
    }

    /// The address for error messages, naming the tunnel if there is one.
    pub fn describe(&self) -> String {
        match &self.via {
            Some(via) => format!(
                "{}:{} through tunnel '{}' ({})",
                self.host, self.port, via.tunnel, via.addr
            ),
            None => format!("{}:{}", self.host, self.port),
        }
    }
}

pub struct Upstream {
    io: Box<dyn Io>,
    /// ParameterStatus frames to replay to the agent after login.
    pub parameter_frames: Vec<Bytes>,
    /// The database's cancel key for this connection.
    pub cancel_key: (i32, i32),
}

/// The result of a query ariodb runs for itself.
pub struct Internal {
    pub rows: Vec<Vec<Option<String>>>,
}

pub struct DbError {
    pub code: String,
    pub message: String,
}

impl Upstream {
    pub async fn connect(target: &Target, application_name: &str) -> Result<Upstream, String> {
        let addr = target.describe();
        let mut stream = TcpStream::connect(target.dial_addr())
            .await
            .map_err(|e| format!("cannot reach {addr}: {e}"))?;
        let _ = stream.set_nodelay(true);

        let mut io: Box<dyn Io> = if target.tls == TlsMode::Disable {
            Box::new(stream)
        } else {
            wire::write_all(&mut stream, &wire::ssl_request())
                .await
                .map_err(|e| e.to_string())?;
            let mut answer = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut answer)
                .await
                .map_err(|e| e.to_string())?;
            if answer[0] != b'S' {
                return Err(format!(
                    "{addr} does not accept TLS (set tls = \"disable\" to connect without it)"
                ));
            }
            let config = tls::client_config(target.tls, target.ca_file.as_deref())?;
            Box::new(tls::connect(stream, &target.host, config).await?)
        };

        let startup = wire::startup_message(&[
            ("user", &target.user),
            ("database", &target.database),
            ("application_name", application_name),
        ]);
        wire::write_all(&mut io, &startup)
            .await
            .map_err(|e| e.to_string())?;
        authenticate(&mut io, target).await?;

        let mut parameter_frames = Vec::new();
        let mut cancel_key = (0, 0);
        loop {
            let f = wire::read_frame(&mut io).await.map_err(|e| e.to_string())?;
            match f.tag {
                b'S' => parameter_frames.push(f.raw.clone()),
                b'K' => {
                    let mut b = f.body.clone();
                    cancel_key = (b.get_i32(), b.get_i32());
                }
                b'Z' => break,
                b'E' => {
                    return Err(format!(
                        "database refused login: {}",
                        wire::parse_error(&f.body).message
                    ));
                }
                _ => {}
            }
        }
        Ok(Upstream {
            io,
            parameter_frames,
            cancel_key,
        })
    }

    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        wire::write_all(&mut self.io, bytes).await
    }

    pub async fn recv(&mut self) -> Result<Frame, WireError> {
        wire::read_frame(&mut self.io).await
    }

    /// Run SQL for ariodb itself and collect the rows. Stops at ReadyForQuery.
    pub async fn internal(&mut self, sql: &str) -> Result<Result<Internal, DbError>, WireError> {
        self.send(&wire::query(sql)).await?;
        let mut rows = Vec::new();
        let mut error = None;
        loop {
            let f = self.recv().await?;
            match f.tag {
                b'D' => rows.push(wire::parse_data_row(&f.body)),
                b'E' => {
                    let e = wire::parse_error(&f.body);
                    error.get_or_insert(DbError {
                        code: e.code,
                        message: e.message,
                    });
                }
                b'Z' => {
                    return Ok(match error {
                        Some(e) => Err(e),
                        None => Ok(Internal { rows }),
                    });
                }
                _ => {}
            }
        }
    }
}

async fn authenticate(io: &mut Box<dyn Io>, target: &Target) -> Result<(), String> {
    let password = || {
        target
            .password
            .clone()
            .ok_or("the database asked for a password but the URL has none")
    };
    let mut scram: Option<ScramSha256> = None;
    loop {
        let f = wire::read_frame(io).await.map_err(|e| e.to_string())?;
        match f.tag {
            b'R' => {
                let mut b = f.body.clone();
                match b.get_i32() {
                    0 => return Ok(()),
                    3 => {
                        let p = password()?;
                        wire::write_all(io, &wire::password(p.as_bytes()))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    5 => {
                        let mut salt = [0u8; 4];
                        b.copy_to_slice(&mut salt);
                        let p = password()?;
                        let hash = postgres_protocol::authentication::md5_hash(
                            target.user.as_bytes(),
                            p.as_bytes(),
                            salt,
                        );
                        wire::write_all(io, &wire::password(hash.as_bytes()))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    10 => {
                        let mechanisms = String::from_utf8_lossy(&b).to_string();
                        if !mechanisms.contains(SCRAM_SHA_256) {
                            return Err(format!("unsupported SASL mechanisms: {mechanisms}"));
                        }
                        let p = password()?;
                        let s = ScramSha256::new(p.as_bytes(), ChannelBinding::unsupported());
                        let msg = wire::sasl_initial(SCRAM_SHA_256, s.message());
                        wire::write_all(io, &msg).await.map_err(|e| e.to_string())?;
                        scram = Some(s);
                    }
                    11 => {
                        let s = scram.as_mut().ok_or("SASL continue without start")?;
                        s.update(&b).map_err(|e| format!("SCRAM: {e}"))?;
                        let msg = wire::sasl_response(s.message());
                        wire::write_all(io, &msg).await.map_err(|e| e.to_string())?;
                    }
                    12 => {
                        let s = scram.as_mut().ok_or("SASL final without start")?;
                        s.finish(&b).map_err(|e| format!("SCRAM: {e}"))?;
                    }
                    other => return Err(format!("unsupported authentication method {other}")),
                }
            }
            b'E' => {
                return Err(format!(
                    "database refused login: {}",
                    wire::parse_error(&f.body).message
                ));
            }
            _ => {}
        }
    }
}

/// Ask the database to cancel a running query.
pub async fn cancel(target: &Target, key: (i32, i32)) {
    if let Ok(mut s) = TcpStream::connect(target.dial_addr()).await {
        let mut msg = Vec::with_capacity(16);
        msg.extend(16i32.to_be_bytes());
        msg.extend(wire::CANCEL_REQUEST.to_be_bytes());
        msg.extend(key.0.to_be_bytes());
        msg.extend(key.1.to_be_bytes());
        let _ = wire::write_all(&mut s, &msg).await;
    }
}

/// A tokio-postgres client for ariodb's admin work (setup, journal, undo),
/// using the same TLS settings (and tunnel) as the agents' connections.
pub async fn admin_client(target: &Target, url: &str) -> Result<tokio_postgres::Client, String> {
    let target_tls = target.tls;
    let mut config =
        tokio_postgres::Config::from_str(url).map_err(|e| format!("bad database URL: {e}"))?;
    if let Some(via) = &target.via {
        config = reroute(&config, target, via);
    }
    let err = |e: tokio_postgres::Error| format!("cannot connect: {e}");
    if target_tls == TlsMode::Disable {
        config.ssl_mode(tokio_postgres::config::SslMode::Disable);
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.map_err(err)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    } else {
        config.ssl_mode(tokio_postgres::config::SslMode::Require);
        let tls = tls::postgres_connector(target_tls, target.ca_file.as_deref())?;
        let (client, connection) = config.connect(tls).await.map_err(err)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }
}

/// The same login, dialled at the tunnel. `hostaddr` is where the socket
/// goes; `host` stays the real name, which TLS verifies.
fn reroute(from: &tokio_postgres::Config, target: &Target, via: &Via) -> tokio_postgres::Config {
    let mut to = tokio_postgres::Config::new();
    to.host(&target.host)
        .hostaddr(via.addr.ip())
        .port(via.addr.port())
        .dbname(&target.database);
    if let Some(user) = from.get_user() {
        to.user(user);
    }
    if let Some(password) = from.get_password() {
        to.password(password);
    }
    if let Some(options) = from.get_options() {
        to.options(options);
    }
    if let Some(name) = from.get_application_name() {
        to.application_name(name);
    }
    if let Some(timeout) = from.get_connect_timeout() {
        to.connect_timeout(*timeout);
    }
    to
}
