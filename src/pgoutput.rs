//! Decoding Postgres's logical replication messages (the `pgoutput` format,
//! protocol version 1). See "Logical Replication Message Formats" in the
//! Postgres docs.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    /// A large (TOASTed) value that did not change and was not sent.
    Unchanged,
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    Begin {
        xid: u32,
        commit_time_us: i64,
    },
    Commit {
        end_lsn: u64,
    },
    Relation {
        id: u32,
        schema: String,
        name: String,
        columns: Vec<Column>,
    },
    Insert {
        relation: u32,
        new: Vec<Value>,
    },
    Update {
        relation: u32,
        old: Option<Vec<Value>>,
        new: Vec<Value>,
    },
    Delete {
        relation: u32,
        old: Vec<Value>,
    },
    Truncate {
        relations: Vec<u32>,
    },
    Logical {
        prefix: String,
        content: Vec<u8>,
    },
    /// Origin, type and other messages ariodb does not need.
    Other,
}

#[derive(Debug)]
pub struct DecodeError(pub String);

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        let end =
            end.ok_or_else(|| DecodeError(format!("message ends early at byte {}", self.pos)))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// A null-terminated string.
    fn cstr(&mut self) -> Result<String, DecodeError> {
        let rest = &self.buf[self.pos..];
        let len = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| DecodeError("string without terminator".into()))?;
        let s = String::from_utf8_lossy(&rest[..len]).into_owned();
        self.pos += len + 1;
        Ok(s)
    }
    fn tuple(&mut self) -> Result<Vec<Value>, DecodeError> {
        let n = self.i16()?;
        let mut values = Vec::with_capacity(n.max(0) as usize);
        for _ in 0..n {
            values.push(match self.u8()? {
                b'n' => Value::Null,
                b'u' => Value::Unchanged,
                b't' | b'b' => {
                    let len = self.i32()?;
                    let bytes = self.take(len.max(0) as usize)?;
                    Value::Text(String::from_utf8_lossy(bytes).into_owned())
                }
                other => return Err(DecodeError(format!("unknown tuple value kind {other}"))),
            });
        }
        Ok(values)
    }
}

pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
    let mut r = Reader { buf, pos: 0 };
    let message = match r.u8()? {
        b'B' => {
            let _final_lsn = r.u64()?;
            let commit_time_us = r.i64()?;
            let xid = r.u32()?;
            Message::Begin {
                xid,
                commit_time_us,
            }
        }
        b'C' => {
            let _flags = r.u8()?;
            let _commit_lsn = r.u64()?;
            let end_lsn = r.u64()?;
            Message::Commit { end_lsn }
        }
        b'R' => {
            let id = r.u32()?;
            let schema = r.cstr()?;
            let name = r.cstr()?;
            let _replica_identity = r.u8()?;
            let n = r.i16()?;
            let mut columns = Vec::new();
            for _ in 0..n {
                let _flags = r.u8()?;
                let name = r.cstr()?;
                let _type_oid = r.u32()?;
                let _typmod = r.i32()?;
                columns.push(Column { name });
            }
            Message::Relation {
                id,
                schema,
                name,
                columns,
            }
        }
        b'I' => {
            let relation = r.u32()?;
            expect(&mut r, b'N')?;
            Message::Insert {
                relation,
                new: r.tuple()?,
            }
        }
        b'U' => {
            let relation = r.u32()?;
            let mut old = None;
            let mut marker = r.u8()?;
            if marker == b'K' || marker == b'O' {
                old = Some(r.tuple()?);
                marker = r.u8()?;
            }
            if marker != b'N' {
                return Err(DecodeError(format!(
                    "update without new tuple (got {marker})"
                )));
            }
            Message::Update {
                relation,
                old,
                new: r.tuple()?,
            }
        }
        b'D' => {
            let relation = r.u32()?;
            let _marker = r.u8()?; // 'K' or 'O'
            Message::Delete {
                relation,
                old: r.tuple()?,
            }
        }
        b'T' => {
            let n = r.i32()?;
            let _options = r.u8()?;
            let mut relations = Vec::new();
            for _ in 0..n {
                relations.push(r.u32()?);
            }
            Message::Truncate { relations }
        }
        b'M' => {
            let _flags = r.u8()?;
            let _lsn = r.u64()?;
            let prefix = r.cstr()?;
            let len = r.i32()?;
            let content = r.take(len.max(0) as usize)?.to_vec();
            Message::Logical { prefix, content }
        }
        _ => Message::Other,
    };
    Ok(message)
}

fn expect(r: &mut Reader, byte: u8) -> Result<(), DecodeError> {
    let got = r.u8()?;
    if got == byte {
        Ok(())
    } else {
        Err(DecodeError(format!(
            "expected '{}', got '{}'",
            byte as char, got as char
        )))
    }
}

/// Postgres prints LSNs as two hex halves, such as `0/16B3748`.
pub fn format_lsn(lsn: u64) -> String {
    format!("{:X}/{:X}", lsn >> 32, lsn & 0xFFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_an_insert() {
        // 'I', relation 16384, 'N', 2 columns: text "7", null
        let mut buf = vec![b'I'];
        buf.extend(16384u32.to_be_bytes());
        buf.push(b'N');
        buf.extend(2i16.to_be_bytes());
        buf.push(b't');
        buf.extend(1i32.to_be_bytes());
        buf.push(b'7');
        buf.push(b'n');
        match decode(&buf).unwrap() {
            Message::Insert { relation, new } => {
                assert_eq!(relation, 16384);
                assert_eq!(new, vec![Value::Text("7".into()), Value::Null]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn short_messages_are_errors_not_panics() {
        assert!(decode(&[b'I', 0, 0]).is_err());
        assert!(decode(&[b'B', 1, 2, 3]).is_err());
    }

    #[test]
    fn formats_lsns_like_postgres() {
        assert_eq!(format_lsn(0x0000_0001_016B_3748), "1/16B3748");
    }
}
