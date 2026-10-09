//! Property tests for the parsers that stand between agents and the
//! database. Random and generated input must never crash ariodb, and the
//! guarantees the policy relies on must hold for every input, not just the
//! examples in each module's own tests.
//!
//! proptest picks fresh cases each run and prints a minimal failing case
//! (and its seed, in `proptest-regressions/`) when one breaks.

use crate::classify::{self, Kind};
use crate::{chsql, mysql_sql, pgoutput, wire};
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

// ------------------------------------------------------------------- MySQL

/// Table spellings and what each must be reported as.
fn my_table() -> impl Strategy<Value = (&'static str, &'static str)> {
    prop::sample::select(vec![
        ("orders", "orders"),
        ("Orders", "orders"),
        ("`orders`", "orders"),
        ("app.orders", "app.orders"),
        ("`App`.`Orders`", "app.orders"),
        ("app . orders", "app.orders"),
        ("secrets", "secrets"),
        ("`Secrets`", "secrets"),
        ("db2.secrets", "db2.secrets"),
        ("`weird-name`", "weird-name"),
        ("`ünïcode`", "ünïcode"),
        ("`it's`", "it's"),
        ("`a\"b`", "a\"b"),
        ("`back``tick`", "back`tick"),
        ("`--x`", "--x"),
    ])
}

/// Queries naming two tables in the places tables hide, each with the
/// tables it must be seen to name.
fn my_query() -> impl Strategy<Value = (String, Vec<&'static str>)> {
    (my_table(), my_table(), 0..19usize).prop_map(|((a, ra), (b, rb), how)| {
        let sql = match how {
            0 => format!("SELECT * FROM {a}, {b}"),
            1 => format!("SELECT * FROM {a} JOIN {b} ON 1 = 1"),
            2 => format!("SELECT * FROM {a} WHERE id IN (SELECT id FROM {b})"),
            3 => format!("SELECT (SELECT max(x) FROM {b}) FROM {a}"),
            4 => format!("SELECT * FROM {a} WHERE EXISTS (SELECT 1 FROM {b})"),
            5 => format!("SELECT * FROM {a} UNION ALL SELECT * FROM {b}"),
            6 => format!("WITH c AS (SELECT * FROM {b}) SELECT * FROM {a}, c"),
            7 => format!("INSERT INTO {a} SELECT * FROM {b}"),
            8 => format!("INSERT INTO {a} (x) VALUES ((SELECT x FROM {b} LIMIT 1))"),
            9 => format!("UPDATE {a} SET x = (SELECT x FROM {b} LIMIT 1) WHERE id = 1"),
            10 => format!("UPDATE {a} JOIN {b} ON 1 = 1 SET x = 1 WHERE id = 1"),
            11 => format!("DELETE FROM {a} WHERE id IN (SELECT id FROM {b})"),
            12 => format!("DELETE {a} FROM {a} JOIN {b} ON 1 = 1 WHERE 1 = 1"),
            13 => format!("REPLACE INTO {a} SELECT * FROM {b}"),
            14 => format!("EXPLAIN SELECT * FROM {a} JOIN {b} ON 1 = 1"),
            15 => format!("SET @x = (SELECT max(id) FROM {a} JOIN {b} ON 1 = 1)"),
            16 => format!("SHOW TABLES WHERE (SELECT 1 FROM {a}, {b} LIMIT 1) = 1"),
            17 => format!("SELECT * FROM {a} LEFT JOIN ({b} CROSS JOIN dual_t) ON 1 = 1"),
            _ => format!("SELECT * FROM {a} FOR UPDATE; TABLE {b}"),
        };
        let mut expected = vec![ra, rb];
        if how == 17 {
            expected.push("dual_t");
        }
        (sql, expected)
    })
}

/// Separators that change nothing for the server: spaces, newlines and
/// comments full of quotes and semicolons.
fn my_gap() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        " ",
        "\n  ",
        "\t",
        " /* ' ; \" ` */ ",
        "/**/",
        " /*+ hint */ ",
        "\n-- ' ; DROP TABLE x\n",
        "\n# \" ; DELETE FROM x\n",
        " -- `\n",
    ])
}

/// Join a query's words with harmless separators.
fn my_respell(sql: &str, gaps: &[&str]) -> String {
    let mut out = String::new();
    for (i, word) in sql.split(' ').enumerate() {
        if i > 0 {
            out.push_str(gaps[i % gaps.len()]);
        }
        out.push_str(word);
    }
    out
}

/// A MySQL string literal holding exactly `text`, quoted one of the ways the
/// server accepts.
fn my_quote(text: &str, double: bool, doubling: bool) -> String {
    let q = if double { '"' } else { '\'' };
    let mut out = String::from(q);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == q && doubling => {
                out.push(q);
                out.push(q);
            }
            c if c == q => {
                out.push('\\');
                out.push(q);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn mysql_classify_never_panics_on_any_text(sql in ".{0,200}") {
        let _ = mysql_sql::classify(&sql);
    }

    #[test]
    fn mysql_classify_never_panics_on_tricky_text(
        parts in prop::collection::vec(prop::sample::select(vec![
            "SELECT", "FROM", "orders", "(", ")", ".", "'", "\\", "`", "\"", "/*", "*/", "/*!",
            "/*M!", "/*+", "--", "-- ", "#", "\n", ";", "@", "@@", "SET", "SHOW", "EXPLAIN",
            "ANALYZE", "WITH", "x", "AS", "INTO", "UPDATE", "DELETE", "WHERE", "=", ":=", ",",
            "1", "0x1F", "x'", "N'", "_utf8mb4'", "\u{a0}", "KILL", "USE", "TABLE",
        ]), 0..40)
    ) {
        let _ = mysql_sql::classify(&parts.concat());
        let _ = mysql_sql::classify(&parts.join(" "));
    }

    /// The allow-list depends on this: every table a query names is found,
    /// however it is spelt and whatever comments sit between the words.
    #[test]
    fn mysql_never_finds_fewer_tables_than_named(
        (sql, expected) in my_query(),
        gaps in prop::collection::vec(my_gap(), 1..6),
    ) {
        let sql = my_respell(&sql, &gaps);
        let statements = mysql_sql::classify(&sql)
            .map_err(|e| TestCaseError::fail(format!("generated SQL should parse: {e}\n{sql}")))?;
        let found: Vec<&String> = statements.iter().flat_map(|s| &s.tables).collect();
        for table in expected {
            prop_assert!(
                found.iter().any(|t| *t == table),
                "{} not found in {:?}\n{}", table, found, sql
            );
        }
    }

    /// Whatever a string literal holds, it hides neither a statement nor a
    /// table: quoted properly, it is one value and nothing more.
    #[test]
    fn mysql_a_string_hides_nothing(
        text in ".{0,40}",
        double in any::<bool>(),
        doubling in any::<bool>(),
    ) {
        let sql = format!(
            "SELECT {} FROM orders; DELETE FROM secrets",
            my_quote(&text, double, doubling)
        );
        let statements = mysql_sql::classify(&sql)
            .map_err(|e| TestCaseError::fail(format!("should parse: {e}\n{sql}")))?;
        prop_assert_eq!(statements.len(), 2, "{}", sql);
        prop_assert_eq!(&statements[0].tables, &vec!["orders".to_string()], "{}", sql);
        prop_assert_eq!(statements[0].kind, Kind::Read, "{}", sql);
        prop_assert_eq!(statements[1].kind, Kind::Destructive, "{}", sql);
    }

    /// A quoted name is one table, whatever it holds; one with a dot in it
    /// is refused rather than read as database.table.
    #[test]
    fn mysql_a_quoted_name_is_one_table(text in "[^\u{0}]{1,30}") {
        let quoted = format!("`{}`", text.replace('`', "``"));
        let sql = format!("SELECT * FROM {quoted} WHERE 1 = 1; DELETE FROM secrets");
        match mysql_sql::classify(&sql) {
            Ok(statements) => {
                prop_assert!(!text.contains('.'), "{}", sql);
                prop_assert_eq!(statements.len(), 2, "{}", sql);
                prop_assert_eq!(&statements[0].tables, &vec![text.to_lowercase()], "{}", sql);
            }
            Err(_) => prop_assert!(text.contains('.') || text.trim().is_empty(), "{}", sql),
        }
    }

    /// However a write is wrapped or spelt, it is never mistaken for a read.
    #[test]
    fn mysql_a_wrapped_write_is_never_a_read(
        (table, _) in my_table(),
        how in 0..6usize,
        outer in 0..5usize,
        gaps in prop::collection::vec(my_gap(), 1..6),
    ) {
        let write = match how {
            0 => format!("DELETE FROM {table} WHERE id = 1"),
            1 => format!("UPDATE {table} SET a = 1"),
            2 => format!("INSERT INTO {table} (a) VALUES ('x;SELECT/*1*/')"),
            3 => format!("WITH c AS (SELECT 1 AS id) DELETE FROM {table} WHERE id IN (SELECT id FROM c)"),
            4 => format!("SELECT * FROM {table} LOCK IN SHARE MODE"),
            _ => format!("REPLACE INTO {table} SET a = 1"),
        };
        let sql = match outer {
            0 => format!("EXPLAIN ANALYZE {write}"),
            1 => format!("ANALYZE {write}"),
            2 => format!("SELECT 1; {write}"),
            // An escaped backslash: the string ends before the write.
            3 => format!("SELECT 'a\\\\' AS x; {write}"),
            _ => write,
        };
        let sql = my_respell(&sql, &gaps);
        let statements = mysql_sql::classify(&sql)
            .map_err(|e| TestCaseError::fail(format!("generated SQL should parse: {e}\n{sql}")))?;
        prop_assert!(
            statements.iter().any(|s| s.kind >= Kind::Write),
            "{} was read as {:?}", sql, statements.iter().map(|s| s.kind).collect::<Vec<_>>()
        );
    }

    /// An executable comment anywhere makes its statement Unknown.
    #[test]
    fn mysql_executable_comments_are_never_trusted(
        body in "[^*]{0,30}",
        prefix in prop::sample::select(vec!["/*!", "/*!50000", "/*M!", "/*M!100100"]),
        at in 0..3usize,
    ) {
        let comment = format!("{prefix}{body}*/");
        let sql = match at {
            0 => format!("{comment} SELECT 1"),
            1 => format!("SELECT {comment} 1 FROM orders"),
            _ => format!("SELECT 1 FROM orders {comment}"),
        };
        if let Ok(statements) = mysql_sql::classify(&sql) {
            prop_assert!(statements.iter().any(|s| s.kind == Kind::Unknown), "{}", sql);
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
