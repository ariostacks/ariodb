//! The data blocks a native client sends, read well enough to count their
//! rows and to know exactly where each one ends.
//!
//! ariodb relays the client's bytes unchanged, so it has to agree with
//! ClickHouse about every block boundary: a block ariodb measured wrongly
//! could hide another block, and its rows, from the count. So each column
//! is walked by its type, the way ClickHouse reads it, and an insert ariodb
//! cannot walk (an unknown type, a custom serialization, an unknown
//! compression method) is refused rather than guessed at. With compression
//! on, every block must also end where a compressed frame ends, as real
//! clients' blocks do, so the two readers cannot drift apart unnoticed.

use crate::clickhouse_native::Rd;
use tokio::io::AsyncRead;

/// The most raw bytes ariodb holds back for one insert.
pub const MAX_HELD: usize = 64 << 20;
/// The largest decompressed frame ariodb accepts. Clients send 1 MiB.
const MAX_FRAME: usize = 64 << 20;
/// The most decompressed bytes one insert may expand to.
const MAX_PLAIN: usize = 256 << 20;

const REV_CUSTOM_SERIALIZATION: u64 = 54454;

/// How a column's values are laid out in a block.
#[derive(Debug, Clone, PartialEq)]
pub enum Column {
    /// The same number of bytes for every value.
    Fixed(usize),
    String,
    Nullable(Box<Column>),
    Array(Box<Column>),
    Tuple(Vec<Column>),
    LowCardinality(Box<Column>),
}

impl Column {
    /// LowCardinality columns inside this one, each of which starts the
    /// column's data with a version number.
    fn dictionaries(&self) -> usize {
        match self {
            Column::Fixed(_) | Column::String => 0,
            Column::Nullable(c) | Column::Array(c) => c.dictionaries(),
            Column::Tuple(items) => items.iter().map(Column::dictionaries).sum(),
            Column::LowCardinality(_) => 1,
        }
    }
}

/// Understand a type as a client names it in a block (its canonical name,
/// such as `Array(Nullable(String))`). Anything else is refused.
pub fn parse_type(text: &str) -> Result<Column, String> {
    let unsupported = || format!("ariodb cannot check inserts into columns of type {text}");
    let text = text.trim();
    let (name, args) = match text.find('(') {
        None => (text, Vec::new()),
        Some(open) => {
            let inner = text[open + 1..].strip_suffix(')').ok_or_else(unsupported)?;
            (
                text[..open].trim_end(),
                split_args(inner).ok_or_else(unsupported)?,
            )
        }
    };
    let number = |s: &str| s.trim().parse::<u64>().map_err(|_| unsupported());
    let column = match (name, args.len()) {
        ("UInt8" | "Int8" | "Bool", 0) => Column::Fixed(1),
        ("UInt16" | "Int16" | "Date" | "BFloat16", 0) => Column::Fixed(2),
        ("UInt32" | "Int32" | "Float32" | "Date32" | "IPv4", 0) => Column::Fixed(4),
        ("UInt64" | "Int64" | "Float64", 0) => Column::Fixed(8),
        ("UInt128" | "Int128" | "UUID" | "IPv6", 0) => Column::Fixed(16),
        ("UInt256" | "Int256", 0) => Column::Fixed(32),
        ("DateTime", 0 | 1) => Column::Fixed(4),
        ("DateTime64", 1 | 2) => Column::Fixed(8),
        ("Enum8", n) if n > 0 => Column::Fixed(1),
        ("Enum16", n) if n > 0 => Column::Fixed(2),
        ("FixedString", 1) => match number(args[0])? {
            n @ 1..=0xFF_FFFF => Column::Fixed(n as usize),
            _ => return Err(unsupported()),
        },
        ("Decimal", 2) => match number(args[0])? {
            1..=9 => Column::Fixed(4),
            10..=18 => Column::Fixed(8),
            19..=38 => Column::Fixed(16),
            39..=76 => Column::Fixed(32),
            _ => return Err(unsupported()),
        },
        ("String", 0) => Column::String,
        ("Nullable", 1) => Column::Nullable(Box::new(parse_type(args[0])?)),
        ("Array", 1) => Column::Array(Box::new(parse_type(args[0])?)),
        // Stored as an array of (key, value) tuples.
        ("Map", 2) => Column::Array(Box::new(Column::Tuple(vec![
            parse_type(args[0])?,
            parse_type(args[1])?,
        ]))),
        ("Tuple", n) if n > 0 => Column::Tuple(
            args.iter()
                .map(|a| tuple_element(a))
                .collect::<Result<_, _>>()?,
        ),
        ("LowCardinality", 1) => {
            let inner = parse_type(args[0])?;
            let keys = match &inner {
                Column::Nullable(k) => k.as_ref(),
                k => k,
            };
            if !matches!(keys, Column::Fixed(_) | Column::String) {
                return Err(unsupported());
            }
            Column::LowCardinality(Box::new(inner))
        }
        // Stored as its value type.
        ("SimpleAggregateFunction", 2) => parse_type(args[1])?,
        _ => return Err(unsupported()),
    };
    Ok(column)
}

/// A tuple element: a type, or a name and a type (`a UInt8`).
fn tuple_element(text: &str) -> Result<Column, String> {
    if let Ok(c) = parse_type(text) {
        return Ok(c);
    }
    let text = text.trim();
    let rest = if let Some(quoted) = text.strip_prefix('`') {
        let mut chars = quoted.char_indices();
        let mut end = None;
        while let Some((i, ch)) = chars.next() {
            match ch {
                '\\' => {
                    chars.next();
                }
                '`' => {
                    end = Some(i + 1);
                    break;
                }
                _ => {}
            }
        }
        end.map(|e| &quoted[e..])
    } else {
        text.find(char::is_whitespace).map(|i| &text[i..])
    };
    match rest {
        Some(rest) if rest.starts_with(char::is_whitespace) => parse_type(rest),
        _ => Err(format!(
            "ariodb cannot check inserts into columns of type {text}"
        )),
    }
}

/// Split type arguments at top-level commas, minding quotes and brackets.
fn split_args(text: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0;
    let mut chars = text.char_indices();
    while let Some((i, ch)) = chars.next() {
        match (quote, ch) {
            (Some(_), '\\') => {
                chars.next();
            }
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '`' | '"') => quote = Some(ch),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            (None, ',') if depth == 0 => {
                out.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || quote.is_some() {
        return None;
    }
    out.push(text[start..].trim());
    if out.iter().any(|a| a.is_empty()) {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Reading blocks.

/// Decompressed bytes not yet read. ClickHouse keeps the same state for a
/// whole query, so this lives as long as the query does.
pub struct Frames {
    compressed: bool,
    plain: Vec<u8>,
    pos: usize,
    total: usize,
}

impl Frames {
    pub fn new(compressed: bool) -> Frames {
        Frames {
            compressed,
            plain: Vec::new(),
            pos: 0,
            total: 0,
        }
    }
}

/// What a Data packet held. No columns marks the end of the data.
#[derive(Debug, PartialEq)]
pub struct Block {
    pub columns: u64,
    pub rows: u64,
}

#[derive(Debug, PartialEq)]
pub enum Problem {
    /// The block holds more rows than the insert has room for.
    TooManyRows(u64),
    /// The block cannot be read, or not safely.
    Unreadable(String),
}

impl From<String> for Problem {
    fn from(e: String) -> Problem {
        Problem::Unreadable(e)
    }
}

/// Where column bytes come from: the client's stream, or the frames
/// decompressed from it. Raw bytes are kept in `c.taken` for relaying.
struct Src<'a, R> {
    c: &'a mut Rd<R>,
    frames: &'a mut Frames,
    /// The most raw bytes this packet may take.
    budget: usize,
}

impl<R: AsyncRead + Unpin> Src<'_, R> {
    fn room(&self, n: usize) -> Result<(), String> {
        if self.c.taken.len().saturating_add(n) > self.budget {
            return Err(format!(
                "the insert is larger than ariodb can hold to check ({} MiB); send it in smaller parts",
                MAX_HELD >> 20
            ));
        }
        Ok(())
    }

    /// Decompress the next frame onto the unread bytes.
    async fn pull(&mut self) -> Result<(), String> {
        let f = &mut *self.frames;
        f.plain.drain(..f.pos);
        f.pos = 0;
        self.room(25)?;
        self.c.bytes(16).await?; // checksum, which ClickHouse checks
        let method = self.c.u8().await?;
        let size = u32::from_le_bytes(self.c.bytes(4).await?.try_into().expect("4 bytes")) as usize;
        let plain =
            u32::from_le_bytes(self.c.bytes(4).await?.try_into().expect("4 bytes")) as usize;
        if size < 9 || plain > MAX_FRAME {
            return Err("malformed compressed block".into());
        }
        self.room(size - 9)?;
        let data = self.c.bytes(size - 9).await?;
        let out = match method {
            0x02 => data,
            0x82 => lz4_flex::block::decompress(&data, plain)
                .map_err(|e| format!("cannot decompress an LZ4 block: {e}"))?,
            0x90 => zstd::bulk::decompress(&data, plain)
                .map_err(|e| format!("cannot decompress a ZSTD block: {e}"))?,
            other => {
                return Err(format!(
                    "compression method {other:#04x} is not supported through ariodb; use LZ4 or ZSTD"
                ));
            }
        };
        if out.len() != plain {
            return Err("malformed compressed block".into());
        }
        let f = &mut *self.frames;
        f.total += plain;
        if f.total > MAX_PLAIN {
            return Err(format!(
                "the insert decompresses to more than ariodb can check ({} MiB); send it in smaller parts",
                MAX_PLAIN >> 20
            ));
        }
        f.plain.extend_from_slice(&out);
        Ok(())
    }

    /// A few bytes (at most a varint's worth or a fixed field).
    async fn read(&mut self, n: usize) -> Result<Vec<u8>, String> {
        if !self.frames.compressed {
            self.room(n)?;
            return self.c.bytes(n).await;
        }
        while self.frames.plain.len() - self.frames.pos < n {
            self.pull().await?;
        }
        let f = &mut *self.frames;
        let out = f.plain[f.pos..f.pos + n].to_vec();
        f.pos += n;
        Ok(out)
    }

    async fn skip(&mut self, mut n: u64) -> Result<(), String> {
        while n > 0 {
            if self.frames.compressed {
                if self.frames.plain.len() == self.frames.pos {
                    self.pull().await?;
                }
                let f = &mut *self.frames;
                let k = n.min((f.plain.len() - f.pos) as u64);
                f.pos += k as usize;
                n -= k;
            } else {
                let k = n.min(1 << 20) as usize;
                self.room(k)?;
                self.c.bytes(k).await?;
                n -= k as u64;
            }
        }
        Ok(())
    }

    async fn u8(&mut self) -> Result<u8, String> {
        Ok(self.read(1).await?[0])
    }

    async fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.read(8).await?.try_into().expect("8 bytes"),
        ))
    }

    /// At most nine bytes, as `Rd::varint`.
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

    async fn name(&mut self) -> Result<String, String> {
        let n = self.varint().await?;
        if n > 64 << 10 {
            return Err("column name or type too long".into());
        }
        Ok(String::from_utf8_lossy(&self.read(n as usize).await?).into_owned())
    }
}

/// Read the rest of a Data packet after its type: the table name and one
/// block. `room` is how many more rows the insert may send; `budget` how
/// many raw bytes this packet may take. The raw bytes stay in `c.taken`.
pub async fn read_data<R: AsyncRead + Unpin>(
    c: &mut Rd<R>,
    frames: &mut Frames,
    rev: u64,
    room: u64,
    budget: usize,
) -> Result<Block, Problem> {
    c.short_string().await?; // external table name
    let mut src = Src { c, frames, budget };
    // Block info: numbered fields until 0.
    loop {
        match src.varint().await? {
            0 => break,
            1 => {
                src.u8().await?;
            }
            2 => {
                src.read(4).await?;
            }
            other => return Err(format!("unknown block info field {other}").into()),
        }
    }
    let columns = src.varint().await?;
    let rows = src.varint().await?;
    if columns > 0 && rows > room {
        return Err(Problem::TooManyRows(rows));
    }
    if columns > 100_000 {
        return Err("too many columns".to_string().into());
    }
    for _ in 0..columns {
        src.name().await?;
        let type_name = src.name().await?;
        if rev >= REV_CUSTOM_SERIALIZATION && src.u8().await? != 0 {
            return Err(
                "a column with a custom (sparse) serialization cannot be checked by ariodb"
                    .to_string()
                    .into(),
            );
        }
        let column = parse_type(&type_name)?;
        // An empty block carries no column data at all.
        if rows > 0 {
            skip_column(&mut src, &column, rows).await?;
        }
    }
    if src.frames.pos != src.frames.plain.len() {
        return Err("a data block does not end where its compressed frame does"
            .to_string()
            .into());
    }
    Ok(Block { columns, rows })
}

/// Read past one column's values, as ClickHouse's Native reader does.
async fn skip_column<R: AsyncRead + Unpin>(
    src: &mut Src<'_, R>,
    column: &Column,
    rows: u64,
) -> Result<(), String> {
    for _ in 0..column.dictionaries() {
        if src.u64().await? != 1 {
            return Err("unknown LowCardinality version".into());
        }
    }
    let too_big = || "a column is larger than ariodb can check".to_string();
    // Depth first: nested values follow their sizes or null map.
    let mut stack = vec![(column, rows)];
    while let Some((column, n)) = stack.pop() {
        match column {
            Column::Fixed(size) => {
                src.skip(n.checked_mul(*size as u64).ok_or_else(too_big)?)
                    .await?
            }
            Column::String => {
                for _ in 0..n {
                    let len = src.varint().await?;
                    src.skip(len).await?;
                }
            }
            Column::Nullable(inner) => {
                src.skip(n).await?;
                stack.push((inner, n));
            }
            Column::Array(inner) => {
                // Offsets: the last says how many nested values follow.
                let nested = if n == 0 {
                    0
                } else {
                    src.skip((n - 1).checked_mul(8).ok_or_else(too_big)?)
                        .await?;
                    src.u64().await?
                };
                stack.push((inner, nested));
            }
            Column::Tuple(items) => stack.extend(items.iter().rev().map(|c| (c, n))),
            Column::LowCardinality(inner) => skip_low_cardinality(src, inner, n).await?,
        }
    }
    Ok(())
}

const NEED_GLOBAL_DICTIONARY: u64 = 1 << 8;
const HAS_ADDITIONAL_KEYS: u64 = 1 << 9;
const NEED_UPDATE_DICTIONARY: u64 = 1 << 10;

/// LowCardinality values: groups of (index type, dictionary keys, index
/// count, indexes), read until `rows` indexes have been read.
async fn skip_low_cardinality<R: AsyncRead + Unpin>(
    src: &mut Src<'_, R>,
    inner: &Column,
    mut rows: u64,
) -> Result<(), String> {
    // Keys are stored without their Nullable.
    let keys = match inner {
        Column::Nullable(k) => k.as_ref(),
        k => k,
    };
    let (mut pending, mut width) = (0u64, 0u64);
    let mut have_dictionary = false;
    while rows > 0 {
        if pending == 0 {
            let flags = src.u64().await?;
            width = match flags
                & !(NEED_GLOBAL_DICTIONARY | HAS_ADDITIONAL_KEYS | NEED_UPDATE_DICTIONARY)
            {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => return Err("unknown LowCardinality index type".into()),
            };
            if flags & NEED_GLOBAL_DICTIONARY != 0
                && (!have_dictionary || flags & NEED_UPDATE_DICTIONARY != 0)
            {
                skip_keys(src, keys).await?;
                have_dictionary = true;
            }
            if flags & HAS_ADDITIONAL_KEYS != 0 {
                skip_keys(src, keys).await?;
            }
            pending = src.u64().await?;
        }
        let take = rows.min(pending);
        src.skip(
            take.checked_mul(width)
                .ok_or("a column is larger than ariodb can check")?,
        )
        .await?;
        rows -= take;
        pending -= take;
    }
    Ok(())
}

/// A LowCardinality dictionary: a count, then the keys.
async fn skip_keys<R: AsyncRead + Unpin>(
    src: &mut Src<'_, R>,
    keys: &Column,
) -> Result<(), String> {
    let n = src.u64().await?;
    match keys {
        Column::Fixed(size) => {
            let bytes = n
                .checked_mul(*size as u64)
                .ok_or("a dictionary is larger than ariodb can check")?;
            src.skip(bytes).await
        }
        _ => {
            for _ in 0..n {
                let len = src.varint().await?;
                src.skip(len).await?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse_native::{put_string, put_varint};

    #[test]
    fn types_are_understood_or_refused() {
        assert_eq!(parse_type("UInt32"), Ok(Column::Fixed(4)));
        assert_eq!(
            parse_type("DateTime64(3, 'Europe/London')"),
            Ok(Column::Fixed(8))
        );
        assert_eq!(parse_type("Decimal(18, 4)"), Ok(Column::Fixed(8)));
        assert_eq!(
            parse_type("Enum8('a, (b)' = 1, 'c\\'' = 2)"),
            Ok(Column::Fixed(1))
        );
        assert_eq!(
            parse_type("Map(LowCardinality(String), Array(Nullable(UInt8)))"),
            Ok(Column::Array(Box::new(Column::Tuple(vec![
                Column::LowCardinality(Box::new(Column::String)),
                Column::Array(Box::new(Column::Nullable(Box::new(Column::Fixed(1))))),
            ]))))
        );
        assert_eq!(
            parse_type("Tuple(a UInt8, `b c` String, FixedString(3))"),
            Ok(Column::Tuple(vec![
                Column::Fixed(1),
                Column::String,
                Column::Fixed(3)
            ]))
        );
        assert_eq!(
            parse_type("SimpleAggregateFunction(sum, UInt64)"),
            Ok(Column::Fixed(8))
        );
        for bad in [
            "JSON",
            "Dynamic",
            "Variant(String, UInt8)",
            "Object('json')",
            "AggregateFunction(sum, UInt64)",
            "Nothing",
            "string",
            "INT UNSIGNED",
            "Tuple()",
            "Array(UInt8",
            "Array(UInt8))",
            "LowCardinality(Array(String))",
            "Decimal(80, 2)",
            "FixedString(0)",
        ] {
            assert!(parse_type(bad).is_err(), "{bad}");
        }
    }

    /// A Data packet body (after its type), uncompressed.
    fn block(columns: &[(&str, &[u8])], rows: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, ""); // table name
        out.extend_from_slice(&[1, 0, 2, 0xff, 0xff, 0xff, 0xff, 0]); // block info
        put_varint(&mut out, columns.len() as u64);
        put_varint(&mut out, rows);
        for (ty, data) in columns {
            put_string(&mut out, "c");
            put_string(&mut out, ty);
            out.push(0); // no custom serialization
            out.extend_from_slice(data);
        }
        out
    }

    async fn read(bytes: &[u8], compressed: bool, room: u64) -> (Result<Block, Problem>, usize) {
        let mut c = Rd {
            inner: bytes,
            taken: Vec::new(),
        };
        let mut frames = Frames::new(compressed);
        let r = read_data(&mut c, &mut frames, 54470, room, MAX_HELD).await;
        (r, c.taken.len())
    }

    fn le(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[tokio::test]
    async fn blocks_are_measured_exactly() {
        // Two rows: strings, nullable numbers, arrays and a LowCardinality.
        let mut strings = Vec::new();
        put_string(&mut strings, "ab");
        put_string(&mut strings, "");
        let nullable = [0u8, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut arrays = le(&[1, 3]); // offsets: one value, then two more
        put_string(&mut arrays, "x");
        put_string(&mut arrays, "y");
        put_string(&mut arrays, "z");
        let mut lc = le(&[1, HAS_ADDITIONAL_KEYS]); // version, then index type UInt8
        lc.extend(le(&[2])); // two keys
        put_string(&mut lc, "");
        put_string(&mut lc, "k");
        lc.extend(le(&[2]));
        lc.extend([1u8, 1]);
        let body = block(
            &[
                ("String", &strings),
                ("Nullable(UInt64)", &nullable),
                ("Array(String)", &arrays),
                ("LowCardinality(String)", &lc),
            ],
            2,
        );
        let mut bytes = body.clone();
        bytes.extend_from_slice(&[2, 0]); // the next packet, which must be left alone
        let (r, taken) = read(&bytes, false, 10).await;
        assert_eq!(
            r,
            Ok(Block {
                columns: 4,
                rows: 2
            })
        );
        assert_eq!(taken, body.len());

        // Over the room left: refused before its data is read.
        assert_eq!(read(&bytes, false, 1).await.0, Err(Problem::TooManyRows(2)));
        // A varint longer than any client writes is refused.
        let mut long = block(&[], 0);
        long.truncate(long.len() - 2);
        long.extend_from_slice(&[0xff; 9]);
        long.push(0);
        assert!(matches!(
            read(&long, false, 10).await.0,
            Err(Problem::Unreadable(_))
        ));
        // Unknown types are refused.
        let odd = block(&[("JSON", b"")], 1);
        assert!(matches!(
            read(&odd, false, 10).await.0,
            Err(Problem::Unreadable(_))
        ));
    }

    fn frame(method: u8, plain: &[u8]) -> Vec<u8> {
        let payload = match method {
            0x82 => lz4_flex::block::compress(plain),
            0x90 => zstd::bulk::compress(plain, 1).unwrap(),
            _ => plain.to_vec(),
        };
        let mut out = vec![0u8; 16];
        out.push(method);
        out.extend_from_slice(&((payload.len() + 9) as u32).to_le_bytes());
        out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    #[tokio::test]
    async fn compressed_blocks_must_end_with_their_frame() {
        let mut data = Vec::new();
        put_string(&mut data, "hello");
        let plain = block(&[("String", &data)], 1)[1..].to_vec(); // without the table name
        for method in [0x02, 0x82, 0x90] {
            let mut bytes = vec![0u8]; // table name
            // Split over two frames, as a large block would be.
            bytes.extend(frame(method, &plain[..5]));
            bytes.extend(frame(method, &plain[5..]));
            let (r, taken) = read(&bytes, true, 10).await;
            assert_eq!(
                r,
                Ok(Block {
                    columns: 1,
                    rows: 1
                }),
                "method {method:#x}"
            );
            assert_eq!(taken, bytes.len());
        }
        // A second block hidden in the same frame is refused.
        let mut doubled = plain.clone();
        doubled.extend_from_slice(&plain);
        let mut bytes = vec![0u8];
        bytes.extend(frame(0x82, &doubled));
        assert!(matches!(
            read(&bytes, true, 10).await.0,
            Err(Problem::Unreadable(_))
        ));
        // So is an unknown codec.
        let mut bytes = vec![0u8];
        bytes.extend(frame(0x93, &plain));
        assert!(
            matches!(read(&bytes, true, 10).await.0, Err(Problem::Unreadable(e)) if e.contains("0x93"))
        );
    }
}
