//! Property tests for the parsers that stand between agents and the
//! database. Random and generated input must never crash ariodb, and the
//! guarantees the policy relies on must hold for every input, not just the
//! examples in each module's own tests.
//!
//! proptest picks fresh cases each run and prints a minimal failing case
//! (and its seed, in `proptest-regressions/`) when one breaks.

use crate::classify::{self, Kind};
use crate::{chsql, pgoutput, wire};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    ProptestConfig {
        // PROPTEST_CASES=100000 for a longer hunt.
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512),
        // Failures are reported with a minimal example; no need to keep files.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------- Postgres

/// Write statements in several spellings. Each returns rows when asked, so
/// it can sit inside a CTE or COPY.
fn pg_write() -> impl Strategy<Value = String> {
    let table = prop::sample::select(vec!["orders", "public.orders", "\"Orders\"", "customers"]);
    let id = 0..1000i32;
    prop_oneof![
        (table.clone(), id.clone())
            .prop_map(|(t, n)| format!("INSERT INTO {t} (id, status) VALUES ({n}, 'x')")),
        (table.clone(), id.clone()).prop_map(|(t, n)| {
            format!("INSERT INTO {t} SELECT {n}, status FROM {t} WHERE id = {n}")
        }),
        (table.clone(), id.clone())
            .prop_map(|(t, n)| format!("UPDATE {t} SET status = 'void' WHERE id = {n}")),
        (table.clone(), id.clone()).prop_map(|(t, n)| format!("DELETE FROM {t} WHERE id > {n}")),
        (table.clone()).prop_map(|t| format!("DELETE FROM {t}")),
        (table.clone()).prop_map(|t| format!("UPDATE {t} SET status = 'all'")),
    ]
}

/// Wrap a write the ways an agent might hide it: inside zero to three
/// data-modifying CTEs, then optionally inside EXPLAIN ANALYZE, PREPARE,
/// DECLARE CURSOR or COPY (which Postgres only accepts on the outside).
fn wrapped_write() -> impl Strategy<Value = String> {
    let ctes = prop::collection::vec(0..3usize, 0..4);
    (pg_write(), ctes, 0..10usize).prop_map(|(write, ctes, outer)| {
        let mut sql = write;
        let mut is_select = false;
        for how in ctes {
            let body = if is_select {
                sql.clone()
            } else {
                format!("{sql} RETURNING *")
            };
            sql = match how {
                0 => format!("WITH x AS ({body}) SELECT * FROM x"),
                1 => format!("WITH a AS (SELECT 1), b AS ({body}) SELECT count(*) FROM a, b"),
                _ => format!("WITH RECURSIVE x AS ({body}) SELECT 1 FROM x LIMIT 1"),
            };
            is_select = true;
        }
        let rows = if is_select {
            sql.clone()
        } else {
            format!("{sql} RETURNING *")
        };
        match outer {
            0 => format!("EXPLAIN ANALYZE {sql}"),
            1 => format!("EXPLAIN (ANALYZE) {sql}"),
            2 => format!("EXPLAIN (ANALYZE true, BUFFERS) {sql}"),
            3 => format!("EXPLAIN (FORMAT JSON, ANALYZE on) {sql}"),
            4 => format!("EXPLAIN ANALYZE VERBOSE {sql}"),
            5 => format!("PREPARE p AS {sql}"),
            6 => format!("COPY ({rows}) TO STDOUT"),
            7 if is_select => format!("DECLARE c CURSOR FOR {sql}"),
            _ => sql,
        }
    })
}

/// Change keyword case and spacing without changing meaning.
fn respell(sql: &str, upper: Vec<bool>, comment: bool) -> String {
    let mut out: String = sql
        .split(' ')
        .zip(upper.iter().cycle())
        .map(|(word, up)| {
            if *up {
                word.to_uppercase()
            } else {
                word.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(if comment { " /* c */ " } else { "\n  " });
    if comment {
        out.insert_str(0, "-- leading comment\n");
    }
    out
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn classify_never_panics_on_any_text(sql in ".{0,200}") {
        let _ = classify::classify(&sql);
    }

    #[test]
    fn classify_never_panics_on_sql_like_text(
        words in prop::collection::vec(prop::sample::select(vec![
            "SELECT", "INSERT", "INTO", "UPDATE", "DELETE", "FROM", "WHERE", "WITH", "AS",
            "EXPLAIN", "ANALYZE", "PREPARE", "COPY", "TO", "STDOUT", "(", ")", ",", ";",
            "RETURNING", "*", "orders", "1", "'x'", "$1", "DO", "$$", "BEGIN", "SET", "=",
        ]), 0..40)
    ) {
        let _ = classify::classify(&words.join(" "));
    }

    /// The guarantee the read-only policy depends on: however a write is
    /// wrapped, it is never mistaken for a read.
    #[test]
    fn a_wrapped_write_is_never_a_read(
        sql in wrapped_write(),
        upper in prop::collection::vec(any::<bool>(), 1..8),
        comment in any::<bool>(),
    ) {
        let sql = respell(&sql, upper, comment);
        let statements = classify::classify(&sql)
            .map_err(|e| TestCaseError::fail(format!("generated SQL should parse: {e}\n{sql}")))?;
        prop_assert_eq!(statements.len(), 1, "{}", sql);
        prop_assert!(
            statements[0].kind >= Kind::Write,
            "{} was classified as {} ({})", sql, statements[0].kind, statements[0].reason
        );
    }

    /// Several statements in one query: a write anywhere makes it a write.
    #[test]
    fn a_write_among_reads_is_found(
        before in 0..3usize,
        after in 0..3usize,
        write in wrapped_write(),
    ) {
        let mut parts = vec!["SELECT 1".to_string(); before];
        parts.push(write.clone());
        parts.extend(vec!["SELECT * FROM orders".to_string(); after]);
        let statements = classify::classify(&parts.join("; ")).unwrap();
        prop_assert!(statements.iter().any(|s| s.kind >= Kind::Write), "{}", write);
    }
}

// -------------------------------------------------------------- ClickHouse

fn ch_table_function() -> impl Strategy<Value = String> {
    let name = prop::sample::select(vec![
        "url",
        "URL",
        "Url",
        "file",
        "FILE",
        "s3",
        "S3",
        "s3Cluster",
        "remote",
        "`url`",
        "\"s3\"",
        "`file`",
    ]);
    let gap = prop::sample::select(vec!["", " ", "\n", " /* x */ ", "/**/"]);
    (name, gap).prop_map(|(n, g)| format!("{n}{g}('http://example.test/data.csv', 'CSV')"))
}

/// Queries that call an outside-reaching table function somewhere.
fn ch_reaching_query() -> impl Strategy<Value = String> {
    (ch_table_function(), 0..9usize).prop_map(|(f, how)| match how {
        0 => format!("SELECT * FROM {f}"),
        1 => format!("select count() from {f} where 1 = 1"),
        2 => format!("SELECT * FROM events JOIN {f} AS u ON events.id = u.id"),
        3 => format!("SELECT * FROM (SELECT * FROM {f})"),
        4 => format!("SELECT * FROM events WHERE id IN (SELECT id FROM {f})"),
        5 => format!("WITH x AS (SELECT * FROM {f}) SELECT * FROM x"),
        6 => format!("INSERT INTO TABLE FUNCTION {f} SELECT * FROM events"),
        7 => format!("SELECT * FROM {f} FORMAT JSON"),
        _ => format!("DESCRIBE TABLE {f}"),
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn clickhouse_classify_never_panics_on_any_text(sql in ".{0,200}") {
        let _ = chsql::classify(&sql);
    }

    #[test]
    fn clickhouse_classify_never_panics_on_tricky_text(
        parts in prop::collection::vec(prop::sample::select(vec![
            "SELECT", "FROM", "url", "(", ")", ".", "'", "\\", "`", "\"", "/*", "*/", "--",
            "#", "# ", "\n", ";", "db", "TABLE", "FUNCTION", "INSERT", "INTO", "1",
        ]), 0..40)
    ) {
        let _ = chsql::classify(&parts.concat());
        let _ = chsql::classify(&parts.join(" "));
    }

    /// Table functions that reach outside the server are never allowed as reads.
    #[test]
    fn outside_table_functions_are_never_reads(sql in ch_reaching_query()) {
        if let Ok(s) = chsql::classify(&sql) {
            prop_assert_ne!(s.kind, Kind::Read, "{} ({})", sql, s.reason);
        }
    }
}

// ----------------------------------------------------- Replication messages

proptest! {
    #![proptest_config(config())]

    #[test]
    fn pgoutput_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = pgoutput::decode(&bytes);
    }

    /// Start with a real message tag so decoding gets past the first byte.
    #[test]
    fn pgoutput_decode_never_panics_past_the_tag(
        tag in prop::sample::select(b"BCRIUDTMKON".to_vec()),
        rest in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut bytes = vec![tag];
        bytes.extend(rest);
        let _ = pgoutput::decode(&bytes);
    }

    /// Huge counts and lengths must fail cleanly, not allocate or loop forever.
    #[test]
    fn pgoutput_decode_survives_huge_counts(
        tag in prop::sample::select(b"IUDT".to_vec()),
        count in any::<i32>(),
        tail in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut bytes = vec![tag, 0, 0, 0, 1, b'N'];
        bytes.extend((count as i16).to_be_bytes());
        bytes.extend(count.to_be_bytes());
        bytes.extend(tail);
        let _ = pgoutput::decode(&bytes);
    }
}

// --------------------------------------------------------------- Wire frames

fn read(bytes: &[u8]) -> Result<wire::Frame, wire::WireError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let mut reader = bytes;
    runtime.block_on(wire::read_frame(&mut reader))
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn read_frame_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = read(&bytes);
    }

    /// Any length over the cap is refused before it is read into memory.
    #[test]
    fn oversize_frames_are_refused(
        tag in any::<u8>(),
        len in (wire::MAX_FRAME as i32 + 5)..=i32::MAX,
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut bytes = vec![tag];
        bytes.extend(len.to_be_bytes());
        bytes.extend(body);
        prop_assert!(matches!(read(&bytes), Err(wire::WireError::TooLarge(n)) if n == len as usize - 4));
    }

    /// Lengths that cannot even cover themselves are malformed.
    #[test]
    fn impossible_lengths_are_refused(tag in any::<u8>(), len in i32::MIN..4) {
        let mut bytes = vec![tag];
        bytes.extend(len.to_be_bytes());
        prop_assert!(matches!(read(&bytes), Err(wire::WireError::Malformed(_))));
    }

    /// A well-formed frame comes back exactly as it was built.
    #[test]
    fn frames_round_trip(
        tag in any::<u8>(),
        body in prop::collection::vec(any::<u8>(), 0..2048),
        trailing in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut bytes = wire::frame(tag, &body).to_vec();
        bytes.extend(&trailing);
        let frame = read(&bytes).expect("a built frame should read back");
        prop_assert_eq!(frame.tag, tag);
        prop_assert_eq!(&frame.body[..], &body[..]);
        prop_assert_eq!(frame.raw.len(), body.len() + 5);
    }
}
