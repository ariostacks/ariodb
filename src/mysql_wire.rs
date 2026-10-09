//! The MySQL client/server protocol, as much of it as ariodb needs: packets,
//! the handshake and authentication on both sides, and enough of the
//! server's replies to know where each one ends.
//!
//! Replies are relayed packet by packet as the server sent them; only the
//! sequence ids are renumbered and, at the end of a reply, the
//! transaction bits in the status flags are cleared, because the
//! transaction is ariodb's and not the agent's.

use crate::tls::{Io, TlsMode};
use sha1::Sha1;
use sha2::Sha256;
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// The largest physical packet; a longer payload continues in the next one.
pub const MAX_PHYSICAL: usize = 0xFF_FFFF;
/// What a client may send before it has logged in.
pub const MAX_LOGIN_PACKET: usize = 64 << 10;

pub const CLIENT_LONG_PASSWORD: u32 = 1;
pub const CLIENT_FOUND_ROWS: u32 = 1 << 1;
pub const CLIENT_LONG_FLAG: u32 = 1 << 2;
pub const CLIENT_CONNECT_WITH_DB: u32 = 1 << 3;
pub const CLIENT_LOCAL_FILES: u32 = 1 << 7;
pub const CLIENT_PROTOCOL_41: u32 = 1 << 9;
pub const CLIENT_SSL: u32 = 1 << 11;
pub const CLIENT_TRANSACTIONS: u32 = 1 << 13;
pub const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
pub const CLIENT_MULTI_STATEMENTS: u32 = 1 << 16;
pub const CLIENT_MULTI_RESULTS: u32 = 1 << 17;
pub const CLIENT_PS_MULTI_RESULTS: u32 = 1 << 18;
pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
pub const CLIENT_CONNECT_ATTRS: u32 = 1 << 20;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
pub const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;

/// What ariodb offers agents. Never LOCAL_FILES or MULTI_STATEMENTS, and
/// nothing that changes the shape of replies beyond what is relayed
/// (compression, query attributes, optional metadata, session tracking).
pub const AGENT_CAPS: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_FOUND_ROWS
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_DEPRECATE_EOF;

const _: () = assert!(AGENT_CAPS & (CLIENT_LOCAL_FILES | CLIENT_MULTI_STATEMENTS) == 0);

/// The agent's choices that change what the server sends back, so they are
/// asked for upstream too.
pub const RELAYED_CAPS: u32 =
    CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG | CLIENT_MULTI_RESULTS | CLIENT_PS_MULTI_RESULTS | CLIENT_DEPRECATE_EOF;

pub const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
pub const SERVER_STATUS_IN_TRANS_READONLY: u16 = 0x2000;

pub const COM_QUIT: u8 = 0x01;
pub const COM_INIT_DB: u8 = 0x02;
pub const COM_QUERY: u8 = 0x03;
pub const COM_PING: u8 = 0x0e;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_STMT_EXECUTE: u8 = 0x17;
pub const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
pub const COM_STMT_CLOSE: u8 = 0x19;
pub const COM_STMT_RESET: u8 = 0x1a;
pub const COM_SET_OPTION: u8 = 0x1b;
pub const COM_RESET_CONNECTION: u8 = 0x1f;

pub const CACHING_SHA2: &str = "caching_sha2_password";
pub const NATIVE: &str = "mysql_native_password";

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    /// A packet over the limit, already skipped. Holds its size.
    TooLarge(usize),
    Protocol(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "{e}"),
            WireError::TooLarge(n) => write!(f, "packet of {n} bytes is over the limit"),
            WireError::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

impl From<WireError> for String {
    fn from(e: WireError) -> String {
        e.to_string()
    }
}

fn protocol(m: impl Into<String>) -> WireError {
    WireError::Protocol(m.into())
}

// ---------------------------------------------------------------------------
// Packets.

/// One physical packet: its sequence id and payload.
pub async fn read_physical<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>), WireError> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], 0]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((head[3], payload))
}

/// One logical packet (physical packets joined), refusing anything over
/// `max` bytes. An oversized packet is read to its end and dropped, so the
/// connection stays in step, and reported as `TooLarge`. Returns the
/// sequence id of the last physical packet.
pub async fn read_logical<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<(u8, Vec<u8>), WireError> {
    let mut payload = Vec::new();
    let mut total = 0usize;
    loop {
        let mut head = [0u8; 4];
        r.read_exact(&mut head).await?;
        let len = u32::from_le_bytes([head[0], head[1], head[2], 0]) as usize;
        total += len;
        if total > max {
            tokio::io::copy(&mut r.take(len as u64), &mut tokio::io::sink()).await?;
        } else {
            let start = payload.len();
            payload.resize(start + len, 0);
            r.read_exact(&mut payload[start..]).await?;
        }
        if len < MAX_PHYSICAL {
            if total > max {
                return Err(WireError::TooLarge(total));
            }
            return Ok((head[3], payload));
        }
    }
}

/// Append `payload` as packets numbered from `seq`, split where it must be.
pub fn put_packets(out: &mut Vec<u8>, seq: &mut u8, payload: &[u8]) {
    let mut rest = payload;
    loop {
        let n = rest.len().min(MAX_PHYSICAL);
        put_physical(out, *seq, &rest[..n]);
        *seq = seq.wrapping_add(1);
        rest = &rest[n..];
        if n < MAX_PHYSICAL {
            return;
        }
    }
}

/// Append one physical packet as it is.
pub fn put_physical(out: &mut Vec<u8>, seq: u8, payload: &[u8]) {
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_le_bytes()[..3]);
    out.push(seq);
    out.extend_from_slice(payload);
}

pub async fn write_packet<W: AsyncWrite + Unpin>(
    w: &mut W,
    seq: &mut u8,
    payload: &[u8],
) -> Result<(), WireError> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_packets(&mut out, seq, payload);
    w.write_all(&out).await?;
    w.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Basic encodings.

pub fn put_lenenc(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=250 => out.push(v as u8),
        251..=0xFFFF => {
            out.push(0xFC);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x1_0000..=0xFF_FFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xFE);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// A cursor over a payload.
pub struct Buf<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Buf<'a> {
    pub fn new(data: &'a [u8]) -> Buf<'a> {
        Buf { data, pos: 0 }
    }
    pub fn left(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.left() < n {
            return Err(protocol("packet too short"));
        }
        let b = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// A length-encoded integer; `None` for the NULL marker (0xFB).
    pub fn lenenc(&mut self) -> Result<Option<u64>, WireError> {
        Ok(Some(match self.u8()? {
            0xFB => return Ok(None),
            0xFC => self.u16()? as u64,
            0xFD => {
                let b = self.bytes(3)?;
                u32::from_le_bytes([b[0], b[1], b[2], 0]) as u64
            }
            0xFE => u64::from_le_bytes(self.bytes(8)?.try_into().expect("8 bytes")),
            0xFF => return Err(protocol("bad length-encoded integer")),
            n => n as u64,
        }))
    }
    pub fn lenenc_bytes(&mut self) -> Result<Option<&'a [u8]>, WireError> {
        match self.lenenc()? {
            None => Ok(None),
            Some(n) => self.bytes(usize::try_from(n).map_err(|_| protocol("field too long"))?).map(Some),
        }
    }
    /// Bytes up to a NUL (or the end), without the NUL.
    pub fn cstr(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        match rest.iter().position(|&b| b == 0) {
            Some(i) => {
                self.pos += i + 1;
                &rest[..i]
            }
            None => {
                self.pos = self.data.len();
                rest
            }
        }
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let r = &self.data[self.pos..];
        self.pos = self.data.len();
        r
    }
}

// ---------------------------------------------------------------------------
// Packets ariodb makes itself.

/// An error packet. `message` is sent as given.
pub fn err_packet(code: u16, state: &str, message: &str) -> Vec<u8> {
    let mut out = vec![0xFF];
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    out.extend_from_slice(&state.as_bytes()[..5]);
    out.extend_from_slice(message.as_bytes());
    out
}

pub fn ok_packet(status: u16) -> Vec<u8> {
    let mut out = vec![0x00, 0, 0];
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A server error, as ERR packets carry it.
#[derive(Debug, Clone)]
pub struct ServerError {
    pub code: u16,
    pub state: String,
    pub message: String,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

pub fn parse_err(payload: &[u8]) -> ServerError {
    let mut b = Buf::new(payload);
    let _ = b.u8();
    let code = b.u16().unwrap_or(0);
    let mut state = "HY000".to_string();
    if b.data.get(b.pos) == Some(&b'#') && b.left() >= 6 {
        b.pos += 1;
        state = String::from_utf8_lossy(b.bytes(5).unwrap_or(b"HY000")).into_owned();
    }
    ServerError {
        code,
        state,
        message: String::from_utf8_lossy(b.rest()).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Following a server's reply.

/// Where a reply to COM_QUERY or COM_STMT_EXECUTE has got to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Stage {
    /// Expecting OK, ERR, a LOCAL INFILE request or a column count.
    Start,
    Columns(u64),
    ColumnsEof,
    Rows,
    Done,
}

/// What one packet of a reply was.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Seen {
    /// Part of a result set (or the rest of a long packet).
    Data,
    /// An OK packet, or the OK or EOF that ends a result set. `status_at`
    /// is where its two status bytes are.
    End { affected: u64, status_at: usize },
    Err,
    LocalInfile,
}

/// Follows a reply packet by packet, to know where it ends.
pub struct Reply {
    deprecate_eof: bool,
    stage: Stage,
    /// The previous packet was full length, so this one continues it.
    continued: bool,
}

impl Reply {
    pub fn new(deprecate_eof: bool) -> Reply {
        Reply {
            deprecate_eof,
            stage: Stage::Start,
            continued: false,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == Stage::Done
    }

    pub fn feed(&mut self, p: &[u8]) -> Result<Seen, WireError> {
        let continued = self.continued;
        self.continued = p.len() == MAX_PHYSICAL;
        if continued {
            return Ok(Seen::Data);
        }
        let first = p.first().copied();
        match self.stage {
            Stage::Done => Err(protocol("packet after the end of a reply")),
            Stage::Start => match first {
                Some(0x00) => self.end(p, true),
                Some(0xFF) => {
                    self.stage = Stage::Done;
                    Ok(Seen::Err)
                }
                Some(0xFB) => Ok(Seen::LocalInfile),
                _ => {
                    let n = Buf::new(p)
                        .lenenc()?
                        .ok_or_else(|| protocol("bad column count"))?;
                    if n == 0 {
                        return Err(protocol("bad column count"));
                    }
                    self.stage = Stage::Columns(n);
                    Ok(Seen::Data)
                }
            },
            Stage::Columns(n) => {
                self.stage = match (n - 1, self.deprecate_eof) {
                    (0, true) => Stage::Rows,
                    (0, false) => Stage::ColumnsEof,
                    (left, _) => Stage::Columns(left),
                };
                Ok(Seen::Data)
            }
            Stage::ColumnsEof => {
                if first != Some(0xFE) {
                    return Err(protocol("expected EOF after the column definitions"));
                }
                self.stage = Stage::Rows;
                Ok(Seen::Data)
            }
            Stage::Rows => match first {
                Some(0xFE) if p.len() < MAX_PHYSICAL => self.end(p, self.deprecate_eof),
                Some(0xFF) => {
                    self.stage = Stage::Done;
                    Ok(Seen::Err)
                }
                _ => Ok(Seen::Data),
            },
        }
    }

    /// An OK packet (`ok`) or a classic EOF packet ends a result.
    fn end(&mut self, p: &[u8], ok: bool) -> Result<Seen, WireError> {
        let (affected, status_at) = if ok {
            let mut b = Buf::new(p);
            b.u8()?;
            let affected = b.lenenc()?.unwrap_or(0);
            b.lenenc()?; // last insert id
            (affected, b.pos)
        } else {
            (0, 3)
        };
        if p.len() < status_at + 2 {
            return Err(protocol("short OK or EOF packet"));
        }
        let status = u16::from_le_bytes([p[status_at], p[status_at + 1]]);
        self.stage = if status & SERVER_MORE_RESULTS_EXISTS != 0 {
            Stage::Start
        } else {
            Stage::Done
        };
        Ok(Seen::End {
            affected,
            status_at,
        })
    }
}

/// Clear the transaction bits from a packet's status flags: the agent
/// never has a transaction of its own open.
pub fn clear_trans_status(p: &mut [u8], at: usize) {
    if let Some(s) = p.get_mut(at..at + 2) {
        let status = u16::from_le_bytes([s[0], s[1]])
            & !(SERVER_STATUS_IN_TRANS | SERVER_STATUS_IN_TRANS_READONLY);
        s.copy_from_slice(&status.to_le_bytes());
    }
}

/// How many packets follow a COM_STMT_PREPARE OK: the parameter and column
/// definitions, each list ended by EOF unless CLIENT_DEPRECATE_EOF.
pub fn prepare_ok_tail(p: &[u8], deprecate_eof: bool) -> Result<(u32, u16, u16, usize), WireError> {
    let mut b = Buf::new(p);
    b.u8()?;
    let id = b.u32()?;
    let columns = b.u16()?;
    let params = b.u16()?;
    let eof = |n: u16| if n > 0 && !deprecate_eof { 1 } else { 0 };
    let tail = params as usize + eof(params) + columns as usize + eof(columns);
    Ok((id, columns, params, tail))
}

// ---------------------------------------------------------------------------
// Authentication.

/// A random scramble of printable characters, as MySQL makes them.
pub fn nonce() -> [u8; 20] {
    let mut n = [0u8; 20];
    for b in &mut n {
        *b = 33 + rand::random::<u8>() % 94;
    }
    n
}

/// What a mysql_native_password client sends:
/// SHA1(password) XOR SHA1(nonce + SHA1(SHA1(password))).
pub fn native_scramble(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha1::digest(password);
    let h2 = Sha1::digest(h1);
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(h2);
    let h3 = h.finalize();
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// What a caching_sha2_password client sends:
/// SHA256(password) XOR SHA256(SHA256(SHA256(password)) + nonce).
pub fn sha2_scramble(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha256::digest(password);
    let h2 = Sha256::digest(h1);
    let mut h = Sha256::new();
    h.update(h2);
    h.update(nonce);
    let h3 = h.finalize();
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// caching_sha2_password full authentication without TLS: the password
/// (NUL-terminated, XORed with the nonce) encrypted to the server's RSA key
/// with OAEP padding.
pub fn rsa_encrypt_password(password: &[u8], nonce: &[u8], pem: &[u8]) -> Result<Vec<u8>, String> {
    use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey};
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("the server's RSA key is not valid PEM: {e}"))?;
    let key = PublicEncryptingKey::from_der(&der)
        .map_err(|e| format!("the server's RSA key was rejected: {e}"))?;
    let key = OaepPublicEncryptingKey::new(key).map_err(|_| "unusable RSA key".to_string())?;
    let mut plain = password.to_vec();
    plain.push(0);
    if nonce.is_empty() {
        return Err("no nonce to encrypt the password with".into());
    }
    for (i, b) in plain.iter_mut().enumerate() {
        *b ^= nonce[i % nonce.len()];
    }
    let mut out = vec![0u8; key.ciphertext_size()];
    let n = key
        .encrypt(&OAEP_SHA1_MGF1SHA1, &plain, &mut out, None)
        .map_err(|_| "RSA encryption failed".to_string())?
        .len();
    out.truncate(n);
    Ok(out)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Does `response` prove the client knows `password`, for this plugin?
pub fn check_scramble(plugin: &str, password: &[u8], nonce: &[u8], response: &[u8]) -> bool {
    let expected = match plugin {
        CACHING_SHA2 => sha2_scramble(password, nonce),
        NATIVE => native_scramble(password, nonce),
        _ => return false,
    };
    !expected.is_empty() && constant_time_eq(&expected, response)
}

// ---------------------------------------------------------------------------
// The handshake ariodb sends agents, and what they answer.

pub struct ServerHello<'a> {
    pub version: &'a str,
    pub connection_id: u32,
    pub nonce: &'a [u8; 20],
    pub caps: u32,
    pub charset: u8,
}

pub fn handshake_packet(h: &ServerHello) -> Vec<u8> {
    let mut out = vec![10];
    out.extend_from_slice(h.version.as_bytes());
    out.push(0);
    out.extend_from_slice(&h.connection_id.to_le_bytes());
    out.extend_from_slice(&h.nonce[..8]);
    out.push(0);
    out.extend_from_slice(&(h.caps as u16).to_le_bytes());
    out.push(h.charset);
    out.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    out.extend_from_slice(&((h.caps >> 16) as u16).to_le_bytes());
    out.push(21);
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(&h.nonce[8..]);
    out.push(0);
    out.extend_from_slice(CACHING_SHA2.as_bytes());
    out.push(0);
    out
}

/// An SSLRequest is the first 32 bytes of a handshake response, with
/// CLIENT_SSL set and nothing after.
pub fn is_ssl_request(p: &[u8]) -> bool {
    p.len() == 32 && u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & CLIENT_SSL != 0
}

#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    pub caps: u32,
    pub charset: u8,
    pub user: String,
    pub auth: Vec<u8>,
    pub database: String,
    /// Empty when the client did not name one.
    pub plugin: String,
}

pub fn parse_client_hello(p: &[u8]) -> Result<ClientHello, WireError> {
    let mut b = Buf::new(p);
    let caps = b.u32()?;
    if caps & CLIENT_PROTOCOL_41 == 0 {
        return Err(protocol("client too old: it does not speak protocol 4.1"));
    }
    b.u32()?; // max packet size
    let charset = b.u8()?;
    b.bytes(23)?;
    let user = String::from_utf8_lossy(b.cstr()).into_owned();
    let auth = if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        b.lenenc_bytes()?.unwrap_or_default().to_vec()
    } else if caps & CLIENT_SECURE_CONNECTION != 0 {
        let n = b.u8()? as usize;
        b.bytes(n)?.to_vec()
    } else {
        b.cstr().to_vec()
    };
    let database = if caps & CLIENT_CONNECT_WITH_DB != 0 {
        String::from_utf8_lossy(b.cstr()).into_owned()
    } else {
        String::new()
    };
    let plugin = if caps & CLIENT_PLUGIN_AUTH != 0 {
        String::from_utf8_lossy(b.cstr()).into_owned()
    } else {
        String::new()
    };
    // Connection attributes follow; ariodb has no use for them.
    Ok(ClientHello {
        caps,
        charset,
        user,
        auth,
        database,
        plugin,
    })
}

pub fn auth_switch_packet(plugin: &str, nonce: &[u8]) -> Vec<u8> {
    let mut out = vec![0xFE];
    out.extend_from_slice(plugin.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce);
    out.push(0);
    out
}

// ---------------------------------------------------------------------------
// ariodb as a client of the real server.

pub struct Login<'a> {
    pub addr: &'a str,
    pub tls: TlsMode,
    pub ca_file: Option<&'a str>,
    /// The name the server's certificate must carry.
    pub tls_host: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    pub database: &'a str,
    /// The agent's choices from RELAYED_CAPS.
    pub caps: u32,
    pub charset: u8,
}

/// A logged-in connection to the server.
pub struct Upstream {
    io: BufReader<Box<dyn Io>>,
    pub thread_id: u32,
    pub version: String,
    pub caps: u32,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

impl Upstream {
    pub async fn connect(login: &Login<'_>) -> Result<Upstream, String> {
        tokio::time::timeout(CONNECT_TIMEOUT, Self::connect_inner(login))
            .await
            .map_err(|_| format!("no answer from MySQL at {} within 10 seconds", login.addr))?
    }

    async fn connect_inner(login: &Login<'_>) -> Result<Upstream, String> {
        let mut tcp = TcpStream::connect(login.addr)
            .await
            .map_err(|e| format!("cannot reach MySQL at {}: {e}", login.addr))?;
        let _ = tcp.set_nodelay(true);
        let (seq, hello) = read_logical(&mut tcp, MAX_LOGIN_PACKET).await?;
        if hello.first() == Some(&0xFF) {
            return Err(format!("MySQL refused the connection: {}", parse_err(&hello).message));
        }
        let mut b = Buf::new(&hello);
        if b.u8()? != 10 {
            return Err("MySQL sent an unknown handshake version".into());
        }
        let version = String::from_utf8_lossy(b.cstr()).into_owned();
        let thread_id = b.u32()?;
        let mut nonce = b.bytes(8)?.to_vec();
        b.u8()?;
        let mut server_caps = b.u16()? as u32;
        let mut plugin = NATIVE.to_string();
        if b.left() > 0 {
            b.u8()?; // charset
            b.u16()?; // status
            server_caps |= (b.u16()? as u32) << 16;
            let auth_len = b.u8()? as usize;
            b.bytes(10)?;
            if server_caps & CLIENT_SECURE_CONNECTION != 0 {
                let n = auth_len.saturating_sub(8).max(13);
                let part = b.bytes(n.min(b.left()))?;
                nonce.extend_from_slice(part.strip_suffix(&[0]).unwrap_or(part));
            }
            if server_caps & CLIENT_PLUGIN_AUTH != 0 {
                plugin = String::from_utf8_lossy(b.cstr()).into_owned();
            }
        }
        for (cap, name) in [
            (CLIENT_PROTOCOL_41, "protocol 4.1"),
            (CLIENT_SECURE_CONNECTION, "secure authentication"),
            (CLIENT_PLUGIN_AUTH, "authentication plugins"),
        ] {
            if server_caps & cap == 0 {
                return Err(format!("the MySQL server does not support {name}"));
            }
        }
        if login.caps & CLIENT_DEPRECATE_EOF != 0 && server_caps & CLIENT_DEPRECATE_EOF == 0 {
            return Err("the MySQL server does not support CLIENT_DEPRECATE_EOF, which the client asked for".into());
        }
        let mut caps = (login.caps & RELAYED_CAPS & server_caps)
            | CLIENT_LONG_PASSWORD
            | CLIENT_PROTOCOL_41
            | CLIENT_TRANSACTIONS
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | (server_caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA);
        if !login.database.is_empty() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }

        let mut seq = seq.wrapping_add(1);
        let encrypted = login.tls != TlsMode::Disable;
        let io: Box<dyn Io> = if encrypted {
            if server_caps & CLIENT_SSL == 0 {
                return Err("the MySQL server does not offer TLS (set [mysql] tls = \"disable\" to connect without it)".into());
            }
            caps |= CLIENT_SSL;
            let mut req = Vec::new();
            req.extend_from_slice(&caps.to_le_bytes());
            req.extend_from_slice(&(1u32 << 24).to_le_bytes());
            req.push(login.charset);
            req.extend_from_slice(&[0u8; 23]);
            write_packet(&mut tcp, &mut seq, &req).await?;
            let config = crate::tls::client_config(login.tls, login.ca_file)?;
            Box::new(crate::tls::connect(tcp, login.tls_host, config).await?)
        } else {
            Box::new(tcp)
        };
        let mut io = BufReader::new(io);

        let password = login.password.as_bytes();
        let (mut plugin, first) = match plugin.as_str() {
            CACHING_SHA2 => (plugin.clone(), sha2_scramble(password, &nonce)),
            _ => (NATIVE.to_string(), native_scramble(password, &nonce)),
        };
        let mut resp = Vec::new();
        resp.extend_from_slice(&caps.to_le_bytes());
        resp.extend_from_slice(&(1u32 << 24).to_le_bytes());
        resp.push(login.charset);
        resp.extend_from_slice(&[0u8; 23]);
        resp.extend_from_slice(login.user.as_bytes());
        resp.push(0);
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            put_lenenc(&mut resp, first.len() as u64);
        } else {
            resp.push(first.len() as u8);
        }
        resp.extend_from_slice(&first);
        if caps & CLIENT_CONNECT_WITH_DB != 0 {
            resp.extend_from_slice(login.database.as_bytes());
            resp.push(0);
        }
        resp.extend_from_slice(plugin.as_bytes());
        resp.push(0);
        write_packet(&mut io, &mut seq, &resp).await?;

        loop {
            let (s, p) = read_logical(&mut io, MAX_LOGIN_PACKET).await?;
            seq = s.wrapping_add(1);
            match p.first() {
                Some(0x00) => break,
                Some(0xFF) => {
                    return Err(format!("MySQL refused ariodb's login: {}", parse_err(&p).message));
                }
                Some(0xFE) => {
                    // AuthSwitchRequest: another plugin, and a fresh nonce.
                    let mut b = Buf::new(&p[1..]);
                    plugin = String::from_utf8_lossy(b.cstr()).into_owned();
                    let data = b.rest();
                    nonce = data.strip_suffix(&[0]).unwrap_or(data).to_vec();
                    let answer = match plugin.as_str() {
                        CACHING_SHA2 => sha2_scramble(password, &nonce),
                        NATIVE => native_scramble(password, &nonce),
                        "mysql_clear_password" if encrypted => {
                            let mut v = password.to_vec();
                            v.push(0);
                            v
                        }
                        other => {
                            return Err(format!(
                                "the MySQL login uses the '{other}' authentication plugin, which ariodb does not support"
                            ));
                        }
                    };
                    write_packet(&mut io, &mut seq, &answer).await?;
                }
                Some(0x01) if plugin == CACHING_SHA2 => match p.get(1) {
                    Some(3) => {} // fast authentication succeeded; OK follows
                    Some(4) => {
                        // Full authentication: the password itself, over TLS
                        // in the clear, otherwise encrypted to the server's key.
                        if encrypted {
                            let mut v = password.to_vec();
                            v.push(0);
                            write_packet(&mut io, &mut seq, &v).await?;
                        } else {
                            write_packet(&mut io, &mut seq, &[0x02]).await?;
                            let (s, key) = read_logical(&mut io, MAX_LOGIN_PACKET).await?;
                            seq = s.wrapping_add(1);
                            if key.first() != Some(&0x01) {
                                return Err("MySQL did not send its public key".into());
                            }
                            let secret = rsa_encrypt_password(password, &nonce, &key[1..])?;
                            write_packet(&mut io, &mut seq, &secret).await?;
                        }
                    }
                    _ => return Err("unexpected caching_sha2_password message from MySQL".into()),
                },
                _ => return Err("unexpected packet from MySQL during login".into()),
            }
        }
        Ok(Upstream {
            io,
            thread_id,
            version,
            caps,
        })
    }

    pub fn is_mariadb(&self) -> bool {
        self.version.contains("MariaDB")
    }

    pub fn deprecate_eof(&self) -> bool {
        self.caps & CLIENT_DEPRECATE_EOF != 0
    }

    /// Send a command (sequence id 0).
    pub async fn command(&mut self, payload: &[u8]) -> Result<(), WireError> {
        let mut seq = 0;
        write_packet(&mut self.io, &mut seq, payload).await
    }

    /// Send a packet with a given sequence id, inside a command's exchange.
    pub async fn send_at(&mut self, seq: u8, payload: &[u8]) -> Result<(), WireError> {
        let mut seq = seq;
        write_packet(&mut self.io, &mut seq, payload).await
    }

    pub async fn read(&mut self) -> Result<(u8, Vec<u8>), WireError> {
        read_physical(&mut self.io).await
    }

    /// Run ariodb's own statement and read its whole reply: the rows of a
    /// result set (text values), or the affected-row count of an OK.
    pub async fn query(&mut self, sql: &str) -> Result<Result<Rows, ServerError>, WireError> {
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(sql.as_bytes());
        self.command(&cmd).await?;
        let mut reply = Reply::new(self.deprecate_eof());
        let mut rows = Rows::default();
        let mut columns_left: Option<u64> = None;
        let mut error = None;
        while !reply.done() {
            let (seq, p) = self.read().await?;
            if p.len() == MAX_PHYSICAL {
                // ariodb never asks for values this long.
                return Err(protocol("unexpectedly long reply to ariodb's own statement"));
            }
            match reply.feed(&p)? {
                Seen::Err => error = Some(parse_err(&p)),
                Seen::End { affected, .. } => rows.affected += affected,
                Seen::LocalInfile => {
                    // ariodb never asks for this; refuse it.
                    self.send_at(seq.wrapping_add(1), &[]).await?;
                }
                Seen::Data => match columns_left {
                    None => {
                        columns_left = Some(Buf::new(&p).lenenc()?.unwrap_or(0));
                    }
                    Some(n) if n > 0 => columns_left = Some(n - 1),
                    Some(_) => {
                        if p.first() == Some(&0xFE) {
                            continue; // the EOF after the column definitions
                        }
                        let mut b = Buf::new(&p);
                        let mut row = Vec::new();
                        while b.left() > 0 {
                            row.push(
                                b.lenenc_bytes()?
                                    .map(|v| String::from_utf8_lossy(v).into_owned()),
                            );
                        }
                        rows.rows.push(row);
                    }
                },
            }
        }
        Ok(match error {
            Some(e) => Err(e),
            None => Ok(rows),
        })
    }
}

#[derive(Debug, Default)]
pub struct Rows {
    pub rows: Vec<Vec<Option<String>>>,
    pub affected: u64,
}

/// Quote a name for MySQL: `a.b` becomes `` `a`.`b` ``.
pub fn quote_name(name: &str) -> String {
    name.split('.')
        .map(|part| format!("`{}`", part.replace('`', "``")))
        .collect::<Vec<_>>()
        .join(".")
}

/// Quote a string literal. ariodb removes NO_BACKSLASH_ESCAPES from every
/// session, so backslashes are escapes.
pub fn quote_str(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrambles_match_known_values() {
        // mysql_native_password with an all-zero nonce: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw))).
        let nonce = [0u8; 20];
        let s = native_scramble(b"local-test-only-pw", &nonce);
        assert_eq!(s.len(), 20);
        assert!(check_scramble(NATIVE, b"local-test-only-pw", &nonce, &s));
        assert!(!check_scramble(NATIVE, b"other-test-only-pw", &nonce, &s));
        let s2 = sha2_scramble(b"local-test-only-pw", b"abcdefghijklmnopqrst");
        assert_eq!(s2.len(), 32);
        assert!(check_scramble(CACHING_SHA2, b"local-test-only-pw", b"abcdefghijklmnopqrst", &s2));
        assert!(!check_scramble(CACHING_SHA2, b"local-test-only-pw", b"abcdefghijklmnopqrsu", &s2));
        // An empty password never matches anything.
        assert!(!check_scramble(NATIVE, b"", &nonce, &[]));
        assert!(!check_scramble("client_ed25519", b"x", &nonce, &s));
    }

    #[test]
    fn native_scramble_matches_the_reference() {
        // From MySQL's own algorithm, computed independently:
        // password "agent-token-test-only", nonce "0123456789abcdefghij".
        use sha1::Digest;
        let pw = b"agent-token-test-only";
        let nonce = b"0123456789abcdefghij";
        let h1 = Sha1::digest(pw);
        let stored = Sha1::digest(h1);
        let got = native_scramble(pw, nonce);
        // The server's check: SHA1(got XOR SHA1(nonce + stored)) == stored.
        let mut h = Sha1::new();
        h.update(nonce);
        h.update(stored);
        let mix = h.finalize();
        let recovered: Vec<u8> = got.iter().zip(mix.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(Sha1::digest(&recovered).as_slice(), stored.as_slice());
    }

    #[tokio::test]
    async fn long_packets_are_joined_and_oversized_ones_skipped() {
        let mut wire = Vec::new();
        let mut seq = 0;
        let big = vec![b'x'; MAX_PHYSICAL + 10];
        put_packets(&mut wire, &mut seq, &big);
        assert_eq!(seq, 2);
        put_packets(&mut wire, &mut seq, b"next");
        let mut r = &wire[..];
        let (s, p) = read_logical(&mut r, 32 << 20).await.unwrap();
        assert_eq!((s, p.len()), (1, MAX_PHYSICAL + 10));
        let (s, p) = read_logical(&mut r, 1024).await.unwrap();
        assert_eq!((s, &p[..]), (2, &b"next"[..]));

        // Over the cap: reported, and the stream stays in step.
        let mut r = &wire[..];
        match read_logical(&mut r, 1024).await {
            Err(WireError::TooLarge(n)) => assert_eq!(n, MAX_PHYSICAL + 10),
            other => panic!("{other:?}"),
        }
        let (_, p) = read_logical(&mut r, 1024).await.unwrap();
        assert_eq!(p, b"next");

        // A payload of exactly the physical maximum needs an empty packet after it.
        let mut wire = Vec::new();
        let mut seq = 0;
        put_packets(&mut wire, &mut seq, &vec![0u8; MAX_PHYSICAL]);
        assert_eq!(seq, 2);
        assert_eq!(wire.len(), MAX_PHYSICAL + 8);
    }

    #[test]
    fn replies_are_followed_to_their_end() {
        // A result set with two columns, classic EOFs.
        let mut r = Reply::new(false);
        assert_eq!(r.feed(&[2]).unwrap(), Seen::Data);
        assert_eq!(r.feed(b"\x03defcol1").unwrap(), Seen::Data);
        assert_eq!(r.feed(b"\x03defcol2").unwrap(), Seen::Data);
        assert_eq!(r.feed(&[0xFE, 0, 0, 0x22, 0]).unwrap(), Seen::Data);
        assert_eq!(r.feed(b"\x01a\x01b").unwrap(), Seen::Data);
        assert!(!r.done());
        let end = r.feed(&[0xFE, 0, 0, 0x01, 0]).unwrap();
        assert_eq!(end, Seen::End { affected: 0, status_at: 3 });
        assert!(r.done());

        // CLIENT_DEPRECATE_EOF: no EOF after columns; an OK with 0xFE ends it.
        let mut r = Reply::new(true);
        r.feed(&[1]).unwrap();
        r.feed(b"\x03def").unwrap();
        // A row whose first value is the NULL marker is not an end.
        assert_eq!(r.feed(&[0xFB]).unwrap(), Seen::Data);
        let mut ok = vec![0xFE, 0, 0];
        ok.extend_from_slice(&(SERVER_STATUS_IN_TRANS | SERVER_STATUS_AUTOCOMMIT).to_le_bytes());
        ok.extend_from_slice(&[0, 0]);
        assert_eq!(r.feed(&ok).unwrap(), Seen::End { affected: 0, status_at: 3 });
        clear_trans_status(&mut ok, 3);
        assert_eq!(u16::from_le_bytes([ok[3], ok[4]]), SERVER_STATUS_AUTOCOMMIT);
        assert!(r.done());

        // An OK for a write, with its affected rows.
        let mut r = Reply::new(true);
        assert_eq!(
            r.feed(&[0x00, 0xFC, 0x2C, 0x01, 0x00, 0x02, 0x00, 0, 0]).unwrap(),
            Seen::End { affected: 300, status_at: 5 }
        );
        assert!(r.done());

        // More results follow when the status says so.
        let mut r = Reply::new(true);
        r.feed(&[0x00, 1, 0, 0x08, 0x00, 0, 0]).unwrap();
        assert!(!r.done());
        assert_eq!(r.feed(&err_packet(1142, "42000", "no")).unwrap(), Seen::Err);
        assert!(r.done());

        // LOCAL INFILE requests are recognised.
        let mut r = Reply::new(true);
        assert_eq!(r.feed(b"\xFB/etc/passwd").unwrap(), Seen::LocalInfile);
    }

    #[test]
    fn client_hello_round_trip() {
        let mut p = Vec::new();
        let caps = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | CLIENT_CONNECT_WITH_DB;
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&(1u32 << 24).to_le_bytes());
        p.push(255);
        p.extend_from_slice(&[0; 23]);
        p.extend_from_slice(b"coding-agent\0");
        p.push(3);
        p.extend_from_slice(b"abc");
        p.extend_from_slice(b"app\0caching_sha2_password\0");
        let h = parse_client_hello(&p).unwrap();
        assert_eq!(h.user, "coding-agent");
        assert_eq!(h.auth, b"abc");
        assert_eq!(h.database, "app");
        assert_eq!(h.plugin, CACHING_SHA2);
        assert!(!is_ssl_request(&p));
        assert!(is_ssl_request(&{
            let mut s = (caps | CLIENT_SSL).to_le_bytes().to_vec();
            s.resize(32, 0);
            s
        }));
        // Pre-4.1 clients are refused.
        let mut old = p.clone();
        old[1] &= !((CLIENT_PROTOCOL_41 >> 8) as u8);
        assert!(parse_client_hello(&old).is_err());
    }

    #[test]
    fn prepare_ok_counts_what_follows() {
        let mut p = vec![0x00];
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(&2u16.to_le_bytes()); // columns
        p.extend_from_slice(&1u16.to_le_bytes()); // params
        p.extend_from_slice(&[0, 0, 0]);
        assert_eq!(prepare_ok_tail(&p, false).unwrap(), (7, 2, 1, 5));
        assert_eq!(prepare_ok_tail(&p, true).unwrap(), (7, 2, 1, 3));
    }

    #[test]
    fn names_and_strings_are_quoted() {
        assert_eq!(quote_name("ariodb.session_tags"), "`ariodb`.`session_tags`");
        assert_eq!(quote_name("we`ird"), "`we``ird`");
        assert_eq!(quote_str(r"it's a \ test"), r"'it''s a \\ test'");
    }

    #[test]
    fn handshake_carries_the_nonce_and_plugin() {
        let n = nonce();
        assert!(n.iter().all(|b| (33..127).contains(b)));
        let p = handshake_packet(&ServerHello {
            version: "8.4.0",
            connection_id: 42,
            nonce: &n,
            caps: AGENT_CAPS,
            charset: 255,
        });
        let mut b = Buf::new(&p);
        assert_eq!(b.u8().unwrap(), 10);
        assert_eq!(b.cstr(), b"8.4.0");
        assert_eq!(b.u32().unwrap(), 42);
        assert_eq!(b.bytes(8).unwrap(), &n[..8]);
        assert!(p.ends_with(b"caching_sha2_password\0"));
        assert_eq!(AGENT_CAPS & (CLIENT_LOCAL_FILES | CLIENT_MULTI_STATEMENTS), 0);
    }
}
