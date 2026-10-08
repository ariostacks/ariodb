//! The Postgres wire protocol, version 3: reading and writing frames.
//!
//! A frame is one tag byte, a 4-byte length (which counts itself), and a
//! body. Startup messages have no tag. Only the messages ariodb needs to
//! look inside are parsed; everything else is relayed as raw bytes.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame ariodb accepts. Statements above this are refused rather
/// than inspected partially.
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB

pub const SSL_REQUEST: i32 = 80877103;
pub const GSSENC_REQUEST: i32 = 80877104;
pub const CANCEL_REQUEST: i32 = 80877102;
pub const PROTOCOL_3: i32 = 196608;

/// One tagged frame. `raw` is the complete frame, ready to forward.
#[derive(Debug, Clone)]
pub struct Frame {
    pub tag: u8,
    pub body: Bytes,
    pub raw: Bytes,
}

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    TooLarge(usize),
    Malformed(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "{e}"),
            WireError::TooLarge(n) => {
                write!(f, "message of {n} bytes is over the {MAX_FRAME} byte limit")
            }
            WireError::Malformed(m) => write!(f, "malformed message: {m}"),
        }
    }
}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, WireError> {
    let tag = r.read_u8().await?;
    let len = r.read_i32().await?;
    if len < 4 {
        return Err(WireError::Malformed(format!("length {len}")));
    }
    let body_len = len as usize - 4;
    if body_len > MAX_FRAME {
        // Drain it so the connection stays in sync, then report.
        let mut left = body_len;
        let mut sink = [0u8; 8192];
        while left > 0 {
            let n = r.read(&mut sink[..left.min(8192)]).await?;
            if n == 0 {
                break;
            }
            left -= n;
        }
        return Err(WireError::TooLarge(body_len));
    }
    let mut buf = BytesMut::with_capacity(body_len + 5);
    buf.put_u8(tag);
    buf.put_i32(len);
    buf.resize(body_len + 5, 0);
    r.read_exact(&mut buf[5..]).await?;
    let raw = buf.freeze();
    Ok(Frame {
        tag,
        body: raw.slice(5..),
        raw,
    })
}

/// A startup-phase message: length, then a code, then a body.
pub struct Startup {
    pub code: i32,
    pub body: Bytes,
}

pub async fn read_startup<R: AsyncRead + Unpin>(r: &mut R) -> Result<Startup, WireError> {
    let len = r.read_i32().await?;
    if !(8..=10_000).contains(&len) {
        return Err(WireError::Malformed(format!("startup length {len}")));
    }
    let code = r.read_i32().await?;
    let mut body = vec![0u8; len as usize - 8];
    r.read_exact(&mut body).await?;
    Ok(Startup {
        code,
        body: Bytes::from(body),
    })
}

/// Startup parameters: user, database, application_name and so on.
pub fn startup_params(body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut parts = body.split(|&b| b == 0);
    while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
        if k.is_empty() {
            break;
        }
        out.push((
            String::from_utf8_lossy(k).into_owned(),
            String::from_utf8_lossy(v).into_owned(),
        ));
    }
    out
}

pub async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), WireError> {
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Build a tagged frame from a body.
pub fn frame(tag: u8, body: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(body.len() + 5);
    b.put_u8(tag);
    b.put_i32(body.len() as i32 + 4);
    b.put_slice(body);
    b.freeze()
}

fn cstr(b: &mut BytesMut, s: &str) {
    b.put_slice(s.as_bytes());
    b.put_u8(0);
}

pub fn startup_message(params: &[(&str, &str)]) -> Bytes {
    let mut body = BytesMut::new();
    body.put_i32(PROTOCOL_3);
    for (k, v) in params {
        cstr(&mut body, k);
        cstr(&mut body, v);
    }
    body.put_u8(0);
    let mut b = BytesMut::new();
    b.put_i32(body.len() as i32 + 4);
    b.put_slice(&body);
    b.freeze()
}

pub fn ssl_request() -> Bytes {
    let mut b = BytesMut::new();
    b.put_i32(8);
    b.put_i32(SSL_REQUEST);
    b.freeze()
}

pub fn query(sql: &str) -> Bytes {
    let mut body = BytesMut::new();
    cstr(&mut body, sql);
    frame(b'Q', &body)
}

pub fn password(p: &[u8]) -> Bytes {
    let mut body = BytesMut::from(p);
    body.put_u8(0);
    frame(b'p', &body)
}

pub fn sasl_initial(mechanism: &str, data: &[u8]) -> Bytes {
    let mut body = BytesMut::new();
    cstr(&mut body, mechanism);
    body.put_i32(data.len() as i32);
    body.put_slice(data);
    frame(b'p', &body)
}

pub fn sasl_response(data: &[u8]) -> Bytes {
    frame(b'p', data)
}

pub fn parse_message(statement: &str, sql: &str) -> Bytes {
    let mut body = BytesMut::new();
    cstr(&mut body, statement);
    cstr(&mut body, sql);
    body.put_i16(0);
    frame(b'P', &body)
}

/// Bind with text-format parameters.
pub fn bind_with_params(portal: &str, statement: &str, params: &[&str]) -> Bytes {
    let mut body = BytesMut::new();
    cstr(&mut body, portal);
    cstr(&mut body, statement);
    body.put_i16(0); // all parameters in text format
    body.put_i16(params.len() as i16);
    for p in params {
        body.put_i32(p.len() as i32);
        body.put_slice(p.as_bytes());
    }
    body.put_i16(0);
    frame(b'B', &body)
}

pub fn execute_message(portal: &str) -> Bytes {
    let mut body = BytesMut::new();
    cstr(&mut body, portal);
    body.put_i32(0);
    frame(b'E', &body)
}

pub fn sync_message() -> Bytes {
    frame(b'S', &[])
}

pub fn flush_message() -> Bytes {
    frame(b'H', &[])
}

pub fn auth_ok() -> Bytes {
    frame(b'R', &0i32.to_be_bytes())
}

pub fn auth_cleartext() -> Bytes {
    frame(b'R', &3i32.to_be_bytes())
}

pub fn backend_key(pid: i32, secret: i32) -> Bytes {
    let mut body = BytesMut::new();
    body.put_i32(pid);
    body.put_i32(secret);
    frame(b'K', &body)
}

pub fn ready(status: u8) -> Bytes {
    frame(b'Z', &[status])
}

pub fn error_response(code: &str, message: &str) -> Bytes {
    let mut body = BytesMut::new();
    for (field, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', code),
        (b'M', message),
    ] {
        body.put_u8(field);
        cstr(&mut body, value);
    }
    body.put_u8(0);
    frame(b'E', &body)
}

pub fn fatal_response(code: &str, message: &str) -> Bytes {
    let mut body = BytesMut::new();
    for (field, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', code),
        (b'M', message),
    ] {
        body.put_u8(field);
        cstr(&mut body, value);
    }
    body.put_u8(0);
    frame(b'E', &body)
}

/// Read a null-terminated string from the front of a buffer.
pub fn take_cstr(buf: &mut Bytes) -> Result<String, WireError> {
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| WireError::Malformed("string without terminator".into()))?;
    let s = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.advance(end + 1);
    Ok(s)
}

/// Fields of an ErrorResponse or NoticeResponse.
pub struct ErrorFields {
    pub code: String,
    pub message: String,
}

pub fn parse_error(body: &Bytes) -> ErrorFields {
    let mut b = body.clone();
    let mut code = String::new();
    let mut message = String::new();
    while b.has_remaining() {
        let field = b.get_u8();
        if field == 0 {
            break;
        }
        let Ok(value) = take_cstr(&mut b) else { break };
        match field {
            b'C' => code = value,
            b'M' => message = value,
            _ => {}
        }
    }
    ErrorFields { code, message }
}

/// The columns of a DataRow, as text.
pub fn parse_data_row(body: &Bytes) -> Vec<Option<String>> {
    let mut b = body.clone();
    if b.remaining() < 2 {
        return Vec::new();
    }
    let n = b.get_i16();
    let mut out = Vec::new();
    for _ in 0..n {
        if b.remaining() < 4 {
            break;
        }
        let len = b.get_i32();
        if len < 0 {
            out.push(None);
        } else {
            let len = (len as usize).min(b.remaining());
            out.push(Some(String::from_utf8_lossy(&b[..len]).into_owned()));
            b.advance(len);
        }
    }
    out
}

/// Column names from a RowDescription.
pub fn parse_row_description(body: &Bytes) -> Vec<String> {
    let mut b = body.clone();
    if b.remaining() < 2 {
        return Vec::new();
    }
    let n = b.get_i16();
    let mut names = Vec::new();
    for _ in 0..n {
        let Ok(name) = take_cstr(&mut b) else { break };
        if b.remaining() < 18 {
            break;
        }
        b.advance(18); // table oid, column, type oid, size, modifier, format
        names.push(name);
    }
    names
}

/// A Parse message: statement name and SQL.
pub fn parse_parse(body: &Bytes) -> Result<(String, String), WireError> {
    let mut b = body.clone();
    let name = take_cstr(&mut b)?;
    let sql = take_cstr(&mut b)?;
    Ok((name, sql))
}

/// A Bind message: portal name and statement name.
pub fn parse_bind(body: &Bytes) -> Result<(String, String), WireError> {
    let mut b = body.clone();
    let portal = take_cstr(&mut b)?;
    let statement = take_cstr(&mut b)?;
    Ok((portal, statement))
}

/// The name an Execute message runs.
pub fn parse_execute(body: &Bytes) -> Result<String, WireError> {
    let mut b = body.clone();
    take_cstr(&mut b)
}

/// A Close message: 'S' (statement) or 'P' (portal), and the name.
pub fn parse_close(body: &Bytes) -> Result<(u8, String), WireError> {
    let mut b = body.clone();
    if !b.has_remaining() {
        return Err(WireError::Malformed("empty close".into()));
    }
    let kind = b.get_u8();
    Ok((kind, take_cstr(&mut b)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_frame() {
        let q = query("SELECT 1");
        let mut reader = &q[..];
        let f = read_frame(&mut reader).await.unwrap();
        assert_eq!(f.tag, b'Q');
        assert_eq!(&f.body[..], b"SELECT 1\0");
        assert_eq!(f.raw, q);
    }

    #[tokio::test]
    async fn refuses_huge_frames() {
        let mut big = BytesMut::new();
        big.put_u8(b'Q');
        big.put_i32((MAX_FRAME + 10) as i32);
        big.resize(MAX_FRAME + 11, b'a');
        let mut reader = &big[..];
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(WireError::TooLarge(_))
        ));
    }

    #[test]
    fn parses_startup_params_and_errors() {
        let params = startup_params(b"user\0bot\0database\0app\0\0");
        assert_eq!(
            params,
            vec![
                ("user".into(), "bot".into()),
                ("database".into(), "app".into())
            ]
        );
        let e = error_response("42501", "no");
        let fields = parse_error(&e.slice(5..));
        assert_eq!(
            (fields.code.as_str(), fields.message.as_str()),
            ("42501", "no")
        );
    }

    #[test]
    fn parses_extended_messages() {
        let p = parse_message("s1", "SELECT $1");
        assert_eq!(
            parse_parse(&p.slice(5..)).unwrap(),
            ("s1".into(), "SELECT $1".into())
        );
        let b = bind_with_params("p1", "s1", &["x"]);
        assert_eq!(
            parse_bind(&b.slice(5..)).unwrap(),
            ("p1".into(), "s1".into())
        );
        let e = execute_message("p1");
        assert_eq!(parse_execute(&e.slice(5..)).unwrap(), "p1");
    }
}
