//! Turning MySQL and MariaDB binlog row events into journal changes.
//!
//! # How values are recorded
//!
//! Every value is stored as text (`Cell::Text`), chosen so that undo can
//! turn it back into exactly the value that was there. What the text means
//! follows from the column's type, which undo reads from
//! `information_schema`, just as the Postgres undo reads its column types:
//!
//! | Column type | Recorded text |
//! |---|---|
//! | integer types, `BIT` | the number in decimal, unsigned where the column is (`18446744073709551615`) |
//! | `YEAR` | four digits (`2026`, `0000`) |
//! | `DECIMAL` | the exact decimal, all its scale digits (`12.50`) |
//! | `FLOAT`, `DOUBLE` | the shortest decimal that reads back as the same binary value (`0.1`) |
//! | `DATE` | `YYYY-MM-DD` |
//! | `DATETIME(n)` | `YYYY-MM-DD HH:MM:SS` with `n` fraction digits |
//! | `TIMESTAMP(n)` | the same, in UTC |
//! | `TIME(n)` | `[-]HH:MM:SS` with `n` fraction digits; hours may exceed 24 |
//! | `CHAR`, `VARCHAR`, `TEXT` in utf8mb3, utf8mb4 or ascii | the text itself |
//! | `ENUM`, `SET` | the member name; for `SET`, names joined by commas |
//! | `JSON` (MySQL) | the document as JSON text |
//! | `BINARY`, `VARBINARY`, `BLOB`, spatial types, and text in any other character set | `\x` and the stored bytes in lowercase hex |
//!
//! NULL is recorded as JSON `null`. A value the binlog does not carry in
//! full (a partial JSON update, or JSON holding MySQL-only scalar types) is
//! recorded as `{"unchanged": true}`; undo refuses rows that need one.

use crate::journal::{Cell, Change, Op};
use mysql_async::Value;
use mysql_async::binlog::events::{OptionalMetadataField, RowsEventData, TableMapEvent};
use mysql_async::binlog::row::BinlogRow;
use mysql_async::binlog::value::BinlogValue;
use mysql_async::consts::ColumnType;

/// A column as `information_schema.COLUMNS` describes it.
#[derive(Debug, Clone, Default)]
pub struct InfoColumn {
    pub name: String,
    /// `DATA_TYPE`, lower case: `int`, `varchar`, `json`, ...
    pub data_type: String,
    /// `COLUMN_TYPE`, lower case: `int unsigned`, `enum('a','b')`, ...
    pub column_type: String,
    /// `CHARACTER_SET_NAME`; `None` for binary and non-text columns.
    pub charset: Option<String>,
}

/// How a string column's bytes are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text {
    /// utf8mb3, utf8mb4 or ascii: recorded as the text.
    Utf8,
    /// Binary data, or text in another character set: recorded as hex.
    Bytes,
}

/// What the journal needs to know about one column to record its values.
#[derive(Debug, Clone)]
pub struct ColumnShape {
    pub name: String,
    pub unsigned: bool,
    pub text: Text,
    /// Member names of an ENUM or SET column, in order.
    pub members: Vec<String>,
    /// A BINARY(n) column: the binlog drops trailing zero bytes, which the
    /// column keeps, so they are put back.
    pub fixed_binary: bool,
}

/// A table as of one table-map event.
#[derive(Debug, Clone)]
pub struct TableShape {
    pub schema: String,
    pub table: String,
    pub columns: Vec<ColumnShape>,
}

/// Whether text in this character set is recorded as text.
pub fn is_utf8(charset: &str) -> bool {
    matches!(charset, "utf8" | "utf8mb3" | "utf8mb4" | "ascii")
}

/// Combine what the binlog says about a table with `information_schema`,
/// which fills in what `binlog_row_metadata = MINIMAL` (or MariaDB's
/// `NO_LOG`) leaves out: names, unsignedness, character sets and members.
pub fn shape(tme: &TableMapEvent<'_>, info: &[InfoColumn]) -> TableShape {
    let count = tme.columns_count() as usize;
    let mut names: Vec<String> = Vec::new();
    let mut enum_members: Vec<Vec<String>> = Vec::new();
    let mut set_members: Vec<Vec<String>> = Vec::new();
    for field in tme.iter_optional_meta().flatten() {
        match field {
            OptionalMetadataField::ColumnName(n) => {
                names = n
                    .iter_names()
                    .flatten()
                    .map(|c| c.name().to_string())
                    .collect();
            }
            OptionalMetadataField::EnumStrValue(v) => {
                enum_members = v
                    .iter_values()
                    .flatten()
                    .map(|e| e.values().iter().map(|m| m.value().to_string()).collect())
                    .collect();
            }
            OptionalMetadataField::SetStrValue(v) => {
                set_members = v
                    .iter_values()
                    .flatten()
                    .map(|e| e.values().iter().map(|m| m.value().to_string()).collect())
                    .collect();
            }
            _ => {}
        }
    }
    let names_from_binlog = names.len() == count;
    let (mut enums, mut sets) = (enum_members.into_iter(), set_members.into_iter());
    let mut columns = Vec::with_capacity(count);
    for i in 0..count {
        let ty = tme.get_column_type(i).ok().flatten();
        let name = if let Some(n) = names.get(i).filter(|_| names_from_binlog) {
            n.clone()
        } else {
            info.get(i)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("@{}", i + 1))
        };
        // Match by name when the binlog names columns; otherwise by position.
        let found = if names_from_binlog {
            info.iter().find(|c| c.name == name)
        } else if info.len() == count {
            info.get(i)
        } else {
            None
        };
        let mut members = match ty {
            Some(ColumnType::MYSQL_TYPE_ENUM) => enums.next().unwrap_or_default(),
            Some(ColumnType::MYSQL_TYPE_SET) => sets.next().unwrap_or_default(),
            _ => Vec::new(),
        };
        if members.is_empty()
            && let Some(c) = found
        {
            members = members_of(&c.column_type);
        }
        let text = match found {
            Some(c) => match &c.charset {
                Some(cs) if is_utf8(cs) => Text::Utf8,
                Some(_) => Text::Bytes,
                None if is_textual(&c.data_type) => Text::Utf8,
                None => Text::Bytes,
            },
            // The table is gone or changed: binary blobs are recorded as
            // hex and anything else as text when it is valid UTF-8.
            None => Text::Utf8,
        };
        columns.push(ColumnShape {
            name,
            unsigned: found.is_some_and(|c| {
                !matches!(c.data_type.as_str(), "enum" | "set")
                    && c.column_type.to_lowercase().contains(" unsigned")
            }),
            text,
            members,
            fixed_binary: found.is_some_and(|c| c.data_type == "binary"),
        });
    }
    TableShape {
        schema: tme.database_name().to_string(),
        table: tme.table_name().to_string(),
        columns,
    }
}

/// Types that hold text without a character set in `information_schema`
/// (MariaDB's JSON is `longtext` with one, so is not here).
fn is_textual(data_type: &str) -> bool {
    matches!(data_type, "enum" | "set")
}

/// The members of `enum('a','it''s')` or `set(...)`.
pub fn members_of(column_type: &str) -> Vec<String> {
    let Some(start) = column_type.find('(') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut chars = column_type[start + 1..].chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\'' {
            continue;
        }
        let mut member = String::new();
        loop {
            match chars.next() {
                Some('\'') if chars.peek() == Some(&'\'') => {
                    chars.next();
                    member.push('\'');
                }
                Some('\'') | None => break,
                Some('\\') => {
                    if let Some(n) = chars.next() {
                        member.push(n);
                    }
                }
                Some(c) => member.push(c),
            }
        }
        out.push(member);
    }
    out
}

/// The changes in one rows event.
pub fn changes(
    event: &RowsEventData<'_>,
    tme: &TableMapEvent<'_>,
    shape: &TableShape,
) -> Result<Vec<Change>, String> {
    let op = match event {
        RowsEventData::WriteRowsEventV1(_) | RowsEventData::WriteRowsEvent(_) => Op::Insert,
        RowsEventData::UpdateRowsEventV1(_)
        | RowsEventData::UpdateRowsEvent(_)
        | RowsEventData::PartialUpdateRowsEvent(_) => Op::Update,
        RowsEventData::DeleteRowsEventV1(_) | RowsEventData::DeleteRowsEvent(_) => Op::Delete,
    };
    let columns: Vec<String> = shape.columns.iter().map(|c| c.name.clone()).collect();
    let count = shape.columns.len();
    // Which columns each image carries. With binlog_row_image = FULL that
    // is all of them, except that MariaDB leaves out generated columns.
    let before_cols: Vec<bool> = match event.columns_before_image() {
        Some(bits) => (0..count)
            .map(|i| bits.get(i).is_some_and(|b| *b))
            .collect(),
        None => vec![true; count],
    };
    let after_cols: Vec<bool> = match event.columns_after_image() {
        Some(bits) => (0..count)
            .map(|i| bits.get(i).is_some_and(|b| *b))
            .collect(),
        None => vec![true; count],
    };
    let mut out = Vec::new();
    for row in event.rows(tme) {
        let (before, after) = row.map_err(|e| {
            format!(
                "cannot decode a change to {}.{}: {e}",
                shape.schema, shape.table
            )
        })?;
        // A column the image leaves out is recorded as not carried in full.
        let image = |row: Option<BinlogRow>, present: &[bool]| -> Option<Vec<Option<Cell>>> {
            let row = row?;
            let mut cells = Vec::with_capacity(count);
            let mut k = 0;
            for (i, col) in shape.columns.iter().enumerate() {
                if !present[i] {
                    cells.push(Some(unrecorded()));
                    continue;
                }
                let ty = tme
                    .get_column_type(i)
                    .ok()
                    .flatten()
                    .unwrap_or(ColumnType::MYSQL_TYPE_NULL);
                let meta = tme.get_column_metadata(i).unwrap_or(&[]);
                cells.push(match row.as_ref(k) {
                    None => Some(unrecorded()),
                    Some(v) => encode(v, ty, meta, col),
                });
                k += 1;
            }
            Some(cells)
        };
        let (old, new) = match op {
            Op::Insert => (None, image(after, &after_cols)),
            Op::Delete => (image(before, &before_cols), None),
            _ => (image(before, &before_cols), image(after, &after_cols)),
        };
        out.push(Change {
            schema: shape.schema.clone(),
            table: shape.table.clone(),
            op,
            columns: columns.clone(),
            old,
            new,
        });
    }
    Ok(out)
}

fn unrecorded() -> Cell {
    Cell::Unchanged { unchanged: true }
}

fn hex(bytes: &[u8]) -> String {
    format!("\\x{}", ::hex::encode(bytes))
}

/// One binlog value as journal text (see the module comment). `None` is NULL.
pub fn encode(
    value: &BinlogValue<'_>,
    ty: ColumnType,
    meta: &[u8],
    col: &ColumnShape,
) -> Option<Cell> {
    use ColumnType::*;
    let text = match value {
        BinlogValue::Value(Value::NULL) => return None,
        BinlogValue::Jsonb(j) => match serde_json::Value::try_from(j.clone()) {
            Ok(v) => v.to_string(),
            Err(_) => return Some(unrecorded()),
        },
        BinlogValue::JsonDiff(_) => return Some(unrecorded()),
        BinlogValue::Value(v) => {
            let fsp = meta.first().copied().unwrap_or(0).min(6) as usize;
            match (ty, v) {
                (
                    MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG
                    | MYSQL_TYPE_LONGLONG,
                    Value::Int(n),
                ) => {
                    if col.unsigned && *n < 0 {
                        // Without signedness in the binlog the value was
                        // read as signed; reread it as the column's width.
                        let bits = match ty {
                            MYSQL_TYPE_TINY => 8,
                            MYSQL_TYPE_SHORT => 16,
                            MYSQL_TYPE_INT24 => 24,
                            MYSQL_TYPE_LONG => 32,
                            _ => 64,
                        };
                        let mask = if bits == 64 {
                            u64::MAX
                        } else {
                            (1u64 << bits) - 1
                        };
                        ((*n as u64) & mask).to_string()
                    } else {
                        n.to_string()
                    }
                }
                (_, Value::UInt(n)) => n.to_string(),
                (MYSQL_TYPE_ENUM, Value::Int(n)) => {
                    // 0 is MySQL's empty "error" member.
                    let i = *n as usize;
                    if i == 0 {
                        String::new()
                    } else {
                        match col.members.get(i - 1) {
                            Some(m) => m.clone(),
                            None => return Some(unrecorded()),
                        }
                    }
                }
                (MYSQL_TYPE_SET, Value::Bytes(b)) => {
                    let mut bits: u64 = 0;
                    for (i, byte) in b.iter().enumerate().take(8) {
                        bits |= (*byte as u64) << (8 * i);
                    }
                    let mut names = Vec::new();
                    for (i, m) in col.members.iter().enumerate() {
                        if bits & (1 << i) != 0 {
                            names.push(m.as_str());
                        }
                    }
                    if bits >> col.members.len().min(63) != 0 && col.members.len() < 64 {
                        return Some(unrecorded());
                    }
                    names.join(",")
                }
                (MYSQL_TYPE_BIT, Value::Bytes(b)) => b
                    .iter()
                    .fold(0u64, |acc, x| (acc << 8) | *x as u64)
                    .to_string(),
                (MYSQL_TYPE_YEAR, Value::Bytes(b)) => {
                    let y = String::from_utf8_lossy(b);
                    // mysql_common adds 1900 to the stored byte; 0 means 0000.
                    if y == "1900" {
                        "0000".to_string()
                    } else {
                        y.to_string()
                    }
                }
                (MYSQL_TYPE_NEWDECIMAL | MYSQL_TYPE_DECIMAL, Value::Bytes(b)) => {
                    String::from_utf8_lossy(b).to_string()
                }
                (_, Value::Float(f)) => f.to_string(),
                (_, Value::Double(f)) => f.to_string(),
                (MYSQL_TYPE_TIMESTAMP2 | MYSQL_TYPE_TIMESTAMP, Value::Bytes(b)) => {
                    let s = String::from_utf8_lossy(b);
                    let (secs, micros) = match s.split_once('.') {
                        Some((a, f)) => (a.parse::<i64>().ok()?, f.parse::<u32>().ok()?),
                        None => (s.parse::<i64>().ok()?, 0),
                    };
                    timestamp_text(secs, micros, fsp)
                }
                (MYSQL_TYPE_TIMESTAMP, Value::Int(secs)) => timestamp_text(*secs, 0, 0),
                (MYSQL_TYPE_NEWDATE | MYSQL_TYPE_DATE, Value::Date(y, m, d, ..)) => {
                    format!("{y:04}-{m:02}-{d:02}")
                }
                (_, Value::Date(y, mo, d, h, mi, s, us)) => {
                    let fsp = if ty == MYSQL_TYPE_DATETIME2 { fsp } else { 0 };
                    format!(
                        "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}{}",
                        fraction(*us, fsp)
                    )
                }
                (_, Value::Time(neg, days, h, m, s, us)) => {
                    let fsp = if ty == MYSQL_TYPE_TIME2 { fsp } else { 0 };
                    let hours = *days as u64 * 24 + *h as u64;
                    format!(
                        "{}{hours:02}:{m:02}:{s:02}{}",
                        if *neg { "-" } else { "" },
                        fraction(*us, fsp)
                    )
                }
                (MYSQL_TYPE_GEOMETRY | MYSQL_TYPE_VECTOR, Value::Bytes(b)) => hex(b),
                (MYSQL_TYPE_STRING, Value::Bytes(b)) if col.fixed_binary => {
                    let mut b = b.clone();
                    b.resize(b.len().max(string_length(meta)), 0);
                    hex(&b)
                }
                (_, Value::Bytes(b)) => match col.text {
                    Text::Bytes => hex(b),
                    Text::Utf8 => match std::str::from_utf8(b) {
                        Ok(s) => s.to_string(),
                        Err(_) => return Some(unrecorded()),
                    },
                },
                (_, Value::Int(n)) => n.to_string(),
                _ => return Some(unrecorded()),
            }
        }
    };
    Some(Cell::Text(text))
}

/// The declared length in bytes of a CHAR or BINARY column, from its
/// table-map metadata (as mysql_common reads it).
fn string_length(meta: &[u8]) -> usize {
    match meta {
        [b0, b1, ..] if (*b0 as usize & 0x30) != 0x30 => {
            *b1 as usize | (((*b0 as usize & 0x30) ^ 0x30) << 4)
        }
        [_, b1, ..] => *b1 as usize,
        _ => 0,
    }
}

/// `.123` for 123000 microseconds at 3 digits; empty at 0 digits.
fn fraction(micros: u32, digits: usize) -> String {
    if digits == 0 {
        return String::new();
    }
    let all = format!("{micros:06}");
    format!(".{}", &all[..digits])
}

/// Seconds since 1970 (UTC) as `YYYY-MM-DD HH:MM:SS[.f]`. Zero is MySQL's
/// zero timestamp.
pub fn timestamp_text(secs: i64, micros: u32, digits: usize) -> String {
    if secs == 0 && micros == 0 {
        return format!("0000-00-00 00:00:00{}", fraction(0, digits));
    }
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}{}",
        t / 3600,
        (t % 3600) / 60,
        t % 60,
        fraction(micros, digits)
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// A total order over binlog positions across files: the file's number in
/// the high bits, the offset in the low 32. `binlog.000012` at 345 is
/// `12 << 32 | 345`.
pub fn lsn(file: &str, pos: u64) -> u64 {
    let seq: u64 = file
        .rsplit('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (seq << 32) | (pos & 0xffff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(text: Text, unsigned: bool) -> ColumnShape {
        ColumnShape {
            name: "c".into(),
            unsigned,
            text,
            members: vec!["small".into(), "it's".into(), "large".into()],
            fixed_binary: false,
        }
    }

    fn enc(v: Value, ty: ColumnType, meta: &[u8], c: &ColumnShape) -> String {
        match encode(&BinlogValue::Value(v), ty, meta, c) {
            Some(Cell::Text(t)) => t,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn numbers_are_exact() {
        use ColumnType::*;
        let signed = col(Text::Utf8, false);
        let unsigned = col(Text::Utf8, true);
        assert_eq!(enc(Value::Int(-5), MYSQL_TYPE_LONG, &[], &signed), "-5");
        // Read as signed when the binlog has no signedness.
        assert_eq!(
            enc(Value::Int(-1), MYSQL_TYPE_LONG, &[], &unsigned),
            "4294967295"
        );
        assert_eq!(enc(Value::Int(-1), MYSQL_TYPE_TINY, &[], &unsigned), "255");
        assert_eq!(
            enc(Value::Int(-1), MYSQL_TYPE_LONGLONG, &[], &unsigned),
            "18446744073709551615"
        );
        assert_eq!(
            enc(Value::UInt(u64::MAX), MYSQL_TYPE_LONGLONG, &[], &unsigned),
            "18446744073709551615"
        );
        assert_eq!(
            enc(Value::Float(0.1), MYSQL_TYPE_FLOAT, &[], &signed),
            "0.1"
        );
        assert_eq!(
            enc(Value::Double(1.0 / 3.0), MYSQL_TYPE_DOUBLE, &[], &signed),
            "0.3333333333333333"
        );
        assert_eq!(
            enc(
                Value::Bytes(b"12.50".to_vec()),
                MYSQL_TYPE_NEWDECIMAL,
                &[10, 2],
                &signed
            ),
            "12.50"
        );
        assert_eq!(
            enc(Value::Bytes(vec![1, 2]), MYSQL_TYPE_BIT, &[0, 2], &signed),
            "258"
        );
        assert_eq!(
            enc(
                Value::Bytes(b"1900".to_vec()),
                MYSQL_TYPE_YEAR,
                &[],
                &signed
            ),
            "0000"
        );
    }

    #[test]
    fn times_keep_their_precision() {
        use ColumnType::*;
        let c = col(Text::Utf8, false);
        assert_eq!(
            enc(
                Value::Date(2026, 10, 9, 8, 7, 6, 123_456),
                MYSQL_TYPE_DATETIME2,
                &[6],
                &c
            ),
            "2026-10-09 08:07:06.123456"
        );
        assert_eq!(
            enc(
                Value::Date(2026, 10, 9, 8, 7, 6, 120_000),
                MYSQL_TYPE_DATETIME2,
                &[2],
                &c
            ),
            "2026-10-09 08:07:06.12"
        );
        assert_eq!(
            enc(
                Value::Date(2026, 1, 2, 0, 0, 0, 0),
                MYSQL_TYPE_NEWDATE,
                &[],
                &c
            ),
            "2026-01-02"
        );
        // 2026-10-09 08:07:06 UTC
        assert_eq!(
            enc(
                Value::Bytes(b"1791533226.500000".to_vec()),
                MYSQL_TYPE_TIMESTAMP2,
                &[3],
                &c
            ),
            "2026-10-09 08:07:06.500"
        );
        assert_eq!(
            enc(Value::Bytes(b"0".to_vec()), MYSQL_TYPE_TIMESTAMP2, &[0], &c),
            "0000-00-00 00:00:00"
        );
        assert_eq!(
            enc(
                Value::Time(true, 34, 22, 59, 59, 0),
                MYSQL_TYPE_TIME2,
                &[0],
                &c
            ),
            "-838:59:59"
        );
        assert_eq!(
            enc(
                Value::Time(false, 0, 1, 2, 3, 400_000),
                MYSQL_TYPE_TIME2,
                &[1],
                &c
            ),
            "01:02:03.4"
        );
    }

    #[test]
    fn strings_are_text_or_hex_by_column() {
        use ColumnType::*;
        let text = col(Text::Utf8, false);
        let bytes = col(Text::Bytes, false);
        assert_eq!(
            enc(Value::Bytes("café".into()), MYSQL_TYPE_VARCHAR, &[], &text),
            "café"
        );
        assert_eq!(
            enc(Value::Bytes(vec![0, 255]), MYSQL_TYPE_BLOB, &[], &bytes),
            "\\x00ff"
        );
        // BINARY(4): 0xfe is the real type (string), 4 the length.
        let fixed = ColumnShape {
            fixed_binary: true,
            ..col(Text::Bytes, false)
        };
        assert_eq!(
            enc(
                Value::Bytes(vec![255]),
                MYSQL_TYPE_STRING,
                &[0xfe, 4],
                &fixed
            ),
            "\\xff000000"
        );
        assert_eq!(enc(Value::Int(2), MYSQL_TYPE_ENUM, &[], &text), "it's");
        assert_eq!(enc(Value::Int(0), MYSQL_TYPE_ENUM, &[], &text), "");
        assert_eq!(
            enc(Value::Bytes(vec![0b101]), MYSQL_TYPE_SET, &[], &text),
            "small,large"
        );
        // Text that is not UTF-8 cannot be recorded faithfully as text.
        assert_eq!(
            encode(
                &BinlogValue::Value(Value::Bytes(vec![0xe9])),
                MYSQL_TYPE_VARCHAR,
                &[],
                &text
            ),
            Some(Cell::Unchanged { unchanged: true })
        );
        assert_eq!(
            encode(
                &BinlogValue::Value(Value::NULL),
                MYSQL_TYPE_VARCHAR,
                &[],
                &text
            ),
            None
        );
    }

    #[test]
    fn members_parse_from_column_type() {
        assert_eq!(
            members_of("enum('a','it''s','b,c')"),
            vec!["a", "it's", "b,c"]
        );
        assert_eq!(members_of("set('x')"), vec!["x"]);
        assert!(members_of("int").is_empty());
    }

    #[test]
    fn positions_order_across_files() {
        assert!(lsn("binlog.000002", 4) > lsn("binlog.000001", 900_000));
        assert!(lsn("binlog.000001", 500) > lsn("binlog.000001", 400));
        assert_eq!(lsn("mysql-bin.000012", 345), (12 << 32) | 345);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(20_735), (2026, 10, 9));
        assert_eq!(timestamp_text(951_782_400, 0, 0), "2000-02-29 00:00:00");
    }
}
