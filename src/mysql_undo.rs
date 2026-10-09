//! Undoing one agent session's MySQL changes, with the same rules as the
//! Postgres undo: newest first, and a row someone else changed since is a
//! conflict, never silently overwritten.
//!
//! Each row the session changed gets one step, from what the session left
//! back to what was there before it. A row is a conflict when the journal
//! shows a later change to it by anyone else, or when its live values are
//! no longer what the session left (which also covers changes the journal
//! has not read yet). Values go back as typed parameters, never spliced into
//! SQL; see `mysql_binlog` for how they were recorded.

use crate::config::Config;
use crate::journal::{Cell, Change, Op, TxnRecord};
use crate::mysql_journal::{self, code, message, quote_ident, quote_table};
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Value};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

/// The session settings undo runs with: TIMESTAMP values were recorded in
/// UTC, and a re-inserted row must keep its own AUTO_INCREMENT id (even 0)
/// and any zero date it held.
const SESSION_SETTINGS: &str = "SET SESSION time_zone = '+00:00', \
     sql_mode = 'STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO,NO_ENGINE_SUBSTITUTION'";

/// A row: its table (`db.table`) and primary key values as recorded.
type Key = (String, Vec<Option<String>>);

/// One column, as information_schema describes it.
#[derive(Debug, Clone)]
struct Column {
    name: String,
    data_type: String,
    unsigned: bool,
    /// Text in this character set is recorded as hex; `None` for utf8 and
    /// non-text columns.
    other_charset: Option<String>,
    generated: bool,
    precision: Option<u64>,
    scale: Option<u64>,
}

#[derive(Debug, Clone)]
struct TableInfo {
    db: String,
    table: String,
    columns: Vec<Column>,
    primary_key: Vec<String>,
}

impl TableInfo {
    fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// One inverse operation, ready to run.
#[derive(Debug)]
pub struct Step {
    pub description: String,
    key: Key,
    /// `(database, table)`.
    table: (String, String),
    sql: String,
    params: Vec<Value>,
    /// Reads the row as it is now: one row holding 1 when it is exactly
    /// what the session left, 0 when it differs, no row when it is gone.
    check_sql: String,
    check_params: Vec<Value>,
    /// The session left the row in place (else it deleted it).
    expect_present: bool,
    /// Rows the step changes itself; more were changed by a cascade or a
    /// trigger.
    own_changes: i64,
}

pub struct Conflict {
    key: Key,
    pub text: String,
}

pub struct Plan {
    pub session: String,
    pub steps: Vec<Step>,
    /// Rows someone else changed after this session did.
    pub conflicts: Vec<Conflict>,
    /// Changes undo cannot reverse.
    pub blocked: Vec<String>,
    /// What undo will not see or restore, though it can run.
    pub warnings: Vec<String>,
    pub already_undone: bool,
}

/// Connect with the journal login, set up for undo.
pub async fn connect(config: &Config) -> Result<Conn, String> {
    let mut conn = mysql_journal::connect(config).await?;
    conn.query_drop(SESSION_SETTINGS)
        .await
        .map_err(|e| message(&e))?;
    Ok(conn)
}

/// Show the plan for undoing `session`, and with `apply`, carry it out.
/// Returns the text to print; with `apply`, the plan is printed first.
pub async fn undo(
    config: &Config,
    records: &[TxnRecord],
    session: &str,
    apply: bool,
    skip_conflicts: bool,
) -> Result<String, String> {
    let mut conn = connect(config).await?;
    let plan = plan(&mut conn, config, records, session).await?;
    let mut text = String::new();
    if plan.already_undone {
        text.push_str("note: this session was already undone\n");
    }
    let _ = writeln!(text, "undo plan for {session}: {} steps", plan.steps.len());
    for step in &plan.steps {
        let _ = writeln!(text, "  {}", step.description);
    }
    for c in &plan.conflicts {
        let _ = writeln!(text, "  conflict: {}", c.text);
    }
    for b in &plan.blocked {
        let _ = writeln!(text, "  cannot undo: {b}");
    }
    for w in &plan.warnings {
        let _ = writeln!(text, "  warning: {w}");
    }
    if !apply {
        text.push_str("\nnothing changed. Run again with --apply to undo.\n");
        return Ok(text);
    }
    print!("{text}");
    let done = apply_plan(&mut conn, config, &plan, skip_conflicts).await?;
    Ok(format!(
        "\nundone: {done} rows restored in one transaction\n"
    ))
}

/// A row one session changed: its first and last change to it.
struct Touch<'a> {
    first: &'a Change,
    last: &'a Change,
    last_seen: usize,
}

pub async fn plan(
    conn: &mut Conn,
    config: &Config,
    records: &[TxnRecord],
    session: &str,
) -> Result<Plan, String> {
    let mine: Vec<&TxnRecord> = records
        .iter()
        .filter(|r| r.session.as_deref() == Some(session))
        .collect();
    if mine.is_empty() {
        return Err(format!("no recorded changes for session '{session}'"));
    }
    let undo_tag = format!("undo:{session}");
    // The journal may not have read a recent undo yet; the tag table has it.
    let (tag_db, tag_table) = mysql_journal::tag_table(config);
    let tagged: Option<u8> = conn
        .exec_first(
            format!(
                "SELECT 1 FROM {} WHERE session = ? LIMIT 1",
                quote_table(&tag_db, &tag_table)
            ),
            (&undo_tag,),
        )
        .await
        .unwrap_or(None);
    let already_undone = tagged.is_some()
        || records
            .iter()
            .any(|r| r.session.as_deref() == Some(undo_tag.as_str()));

    let mut infos: HashMap<String, TableInfo> = HashMap::new();
    let mut blocked = Vec::new();
    let mut touched: Vec<Touch> = Vec::new();
    let mut by_key: HashMap<Key, usize> = HashMap::new();
    let mut first_touch: HashMap<Key, u64> = HashMap::new();
    let mut seen = 0;

    for txn in &mine {
        for change in &txn.changes {
            let table = change.qualified_table();
            if change.op == Op::Truncate {
                blocked.push(format!("TRUNCATE of {table} cannot be undone row by row"));
                continue;
            }
            if !infos.contains_key(&table) {
                let info = table_info(conn, &change.schema, &change.table).await?;
                infos.insert(table.clone(), info);
            }
            let info = &infos[&table];
            if info.columns.is_empty() {
                blocked.push(format!("{table} no longer exists"));
                continue;
            }
            if info.primary_key.is_empty() {
                blocked.push(format!(
                    "{table} has no primary key, so its rows cannot be found again"
                ));
                continue;
            }
            let Some(values) = change.new.as_ref().or(change.old.as_ref()) else {
                blocked.push(format!("{table}: a change without values"));
                continue;
            };
            let key = (table, key_of(change, values, &info.primary_key));
            first_touch.entry(key.clone()).or_insert(txn.lsn);
            seen += 1;
            match by_key.get(&key) {
                Some(&i) => {
                    touched[i].last = change;
                    touched[i].last_seen = seen;
                }
                None => {
                    by_key.insert(key, touched.len());
                    touched.push(Touch {
                        first: change,
                        last: change,
                        last_seen: seen,
                    });
                }
            }
        }
    }

    // Latest rows first, as that is usually the order foreign keys need.
    touched.sort_by_key(|t| std::cmp::Reverse(t.last_seen));
    let mut steps = Vec::new();
    for t in &touched {
        let info = &infos[&t.first.qualified_table()];
        match net_inverse(t.first, t.last, info) {
            Ok(Some(step)) => steps.push(step),
            Ok(None) => {}
            Err(reason) => blocked.push(format!("{}: {reason}", t.first.qualified_table())),
        }
    }

    // Did anyone else touch these rows after this session first did?
    let mut conflicts: Vec<Conflict> = Vec::new();
    for txn in records
        .iter()
        .filter(|r| r.session.as_deref() != Some(session))
    {
        for change in &txn.changes {
            let table = change.qualified_table();
            let Some(info) = infos.get(&table) else {
                continue;
            };
            for values in [&change.old, &change.new].into_iter().flatten() {
                let key = (table.clone(), key_of(change, values, &info.primary_key));
                if let Some(&mine_at) = first_touch.get(&key)
                    && txn.lsn > mine_at
                    && !conflicts.iter().any(|c| c.key == key)
                {
                    let who = txn
                        .session
                        .clone()
                        .unwrap_or_else(|| "someone outside ariodb".into());
                    let text = format!(
                        "{table} row {} was changed later by {who}",
                        show_key(&key.1)
                    );
                    conflicts.push(Conflict { key, text });
                }
            }
        }
    }

    // And is each row still as the session left it?
    for step in &steps {
        if conflicts.iter().any(|c| c.key == step.key) {
            continue;
        }
        if let Some(why) = live_difference(conn, step, false).await? {
            conflicts.push(Conflict {
                key: step.key.clone(),
                text: format!("{} row {} {why}", step.key.0, show_key(&step.key.1)),
            });
        }
    }

    let warnings = cascade_warnings(conn, &touched).await;
    Ok(Plan {
        session: session.to_string(),
        steps,
        conflicts,
        blocked,
        warnings,
        already_undone,
    })
}

/// How a row differs now from what the session left, if it does.
async fn live_difference(
    conn: &mut Conn,
    step: &Step,
    lock: bool,
) -> Result<Option<String>, String> {
    let sql = if lock {
        format!("{} FOR UPDATE", step.check_sql)
    } else {
        step.check_sql.clone()
    };
    let same: Option<Option<i64>> = conn
        .exec_first(sql, step.check_params.clone())
        .await
        .map_err(|e| {
            format!(
                "cannot read {} row {}: {}",
                step.key.0,
                show_key(&step.key.1),
                message(&e)
            )
        })?;
    Ok(match (step.expect_present, same) {
        (true, Some(Some(1))) | (false, None) => None,
        (true, None) => Some("was deleted since the session changed it".to_string()),
        (true, Some(_)) => Some(
            "has changed since the session left it (by someone outside ariodb, or not yet in the journal)"
                .to_string(),
        ),
        (false, Some(_)) => Some("was inserted again since the session deleted it".to_string()),
    })
}

/// MySQL and MariaDB do not write rows changed by a foreign key's ON DELETE
/// or ON UPDATE action to the binlog, so undo cannot restore them. Say so
/// where the session's deletes or updates could have reached such rows.
async fn cascade_warnings(conn: &mut Conn, touched: &[Touch<'_>]) -> Vec<String> {
    let mut out = Vec::new();
    let mut done: Vec<(String, String, Op)> = Vec::new();
    for t in touched {
        for change in [t.first, t.last] {
            if !matches!(change.op, Op::Delete | Op::Update) {
                continue;
            }
            let id = (change.schema.clone(), change.table.clone(), change.op);
            if done.contains(&id) {
                continue;
            }
            done.push(id);
            let rule = if change.op == Op::Delete {
                "DELETE_RULE"
            } else {
                "UPDATE_RULE"
            };
            let rows: Vec<(String, String, String)> = conn
                .exec(
                    format!(
                        "SELECT CONSTRAINT_SCHEMA, TABLE_NAME, {rule} FROM information_schema.REFERENTIAL_CONSTRAINTS
                         WHERE UNIQUE_CONSTRAINT_SCHEMA = ? AND REFERENCED_TABLE_NAME = ? AND {rule} <> 'RESTRICT' AND {rule} <> 'NO ACTION'"
                    ),
                    (&change.schema, &change.table),
                )
                .await
                .unwrap_or_default();
            for (db, child, action) in rows {
                out.push(format!(
                    "{}s on {}.{} may have changed rows in {db}.{child} (ON {} {action}); MySQL does not write those to the binlog, so undo cannot restore them",
                    if change.op == Op::Delete { "delete" } else { "update" },
                    change.schema,
                    change.table,
                    if change.op == Op::Delete { "DELETE" } else { "UPDATE" },
                ));
            }
        }
    }
    out
}

/// Apply a plan in one transaction that starts with its own tag row. Rows
/// with conflicts are skipped only if `skip_conflicts` is set; otherwise
/// nothing is changed.
pub async fn apply_plan(
    conn: &mut Conn,
    config: &Config,
    plan: &Plan,
    skip_conflicts: bool,
) -> Result<usize, String> {
    if plan.already_undone {
        return Err(format!("session '{}' was already undone", plan.session));
    }
    if !plan.blocked.is_empty() {
        return Err(format!(
            "some changes cannot be undone:\n  {}",
            plan.blocked.join("\n  ")
        ));
    }
    if !plan.conflicts.is_empty() && !skip_conflicts {
        let list: Vec<&str> = plan.conflicts.iter().map(|c| c.text.as_str()).collect();
        return Err(format!(
            "rows were changed by others since; nothing was undone. Use --skip-conflicts to undo the rest.\n  {}",
            list.join("\n  ")
        ));
    }
    conn.query_drop("START TRANSACTION")
        .await
        .map_err(|e| message(&e))?;
    let result = apply_in_transaction(conn, config, plan, skip_conflicts).await;
    match result {
        Ok(done) => {
            conn.query_drop("COMMIT").await.map_err(|e| message(&e))?;
            Ok(done)
        }
        Err(e) => {
            let _ = conn.query_drop("ROLLBACK").await;
            Err(e)
        }
    }
}

async fn apply_in_transaction(
    conn: &mut Conn,
    config: &Config,
    plan: &Plan,
    skip_conflicts: bool,
) -> Result<usize, String> {
    let (tag_db, tag_table) = mysql_journal::tag_table(config);
    conn.exec_drop(
        format!(
            "INSERT INTO {} (session, agent) VALUES (?, ?)",
            quote_table(&tag_db, &tag_table)
        ),
        (format!("undo:{}", plan.session), "ariodb-undo"),
    )
    .await
    .map_err(|e| format!("cannot tag the undo for the journal: {}", message(&e)))?;

    // Lock each row and check again that it is as the session left it.
    let mut pending: Vec<&Step> = Vec::new();
    let mut late = Vec::new();
    for step in plan
        .steps
        .iter()
        .filter(|s| !plan.conflicts.iter().any(|c| c.key == s.key))
    {
        match live_difference(conn, step, true).await? {
            None => pending.push(step),
            Some(why) => late.push(format!(
                "{} row {} {why}",
                step.key.0,
                show_key(&step.key.1)
            )),
        }
    }
    if !late.is_empty() && !skip_conflicts {
        return Err(format!(
            "rows were changed by others since; nothing was undone. Use --skip-conflicts to undo the rest.\n  {}",
            late.join("\n  ")
        ));
    }

    // Steps on tables with triggers, or that foreign keys cascade from, can
    // change rows the session never touched. Those steps are measured.
    let mut measured: HashSet<(String, String)> = HashSet::new();
    for step in &pending {
        if !measured.contains(&step.table) && reaches_other_rows(conn, &step.table).await? {
            measured.insert(step.table.clone());
        }
    }
    let can_count = measured.is_empty() || rows_changed(conn).await.is_ok();

    // Foreign keys can make the right order hard to know in advance. Retry
    // steps that fail on a foreign key, or that would change rows the
    // session never touched, until no more progress is made.
    let mut done = 0;
    loop {
        let before = pending.len();
        let mut retry = Vec::new();
        let mut last_error = String::new();
        for step in pending {
            let measure = measured.contains(&step.table);
            if measure && !can_count {
                return Err(format!(
                    "{}: {}.{} has triggers or foreign keys that cascade, and undo cannot see what they change without the PROCESS privilege; nothing was undone",
                    step.description, step.table.0, step.table.1
                ));
            }
            conn.query_drop("SAVEPOINT ariodb_step")
                .await
                .map_err(|e| message(&e))?;
            let changed_before = if measure {
                rows_changed(conn).await?
            } else {
                0
            };
            match conn.exec_drop(step.sql.as_str(), step.params.clone()).await {
                Ok(()) if conn.affected_rows() == 1 => {
                    let extra = if measure {
                        rows_changed(conn).await? - changed_before - step.own_changes
                    } else {
                        0
                    };
                    if extra > 0 {
                        conn.query_drop("ROLLBACK TO SAVEPOINT ariodb_step")
                            .await
                            .map_err(|e| message(&e))?;
                        last_error = format!(
                            "{} would also change {extra} other rows (a foreign key cascade or a trigger), which undo leaves alone",
                            step.description
                        );
                        retry.push(step);
                        continue;
                    }
                    conn.query_drop("RELEASE SAVEPOINT ariodb_step")
                        .await
                        .map_err(|e| message(&e))?;
                    done += 1;
                }
                Ok(()) => {
                    return Err(format!(
                        "{} affected {} rows instead of 1; nothing was undone",
                        step.description,
                        conn.affected_rows()
                    ));
                }
                // A statement-level foreign key failure; the transaction goes on.
                Err(e) if matches!(code(&e), Some(1216 | 1217 | 1451 | 1452)) => {
                    conn.query_drop("ROLLBACK TO SAVEPOINT ariodb_step")
                        .await
                        .map_err(|e| message(&e))?;
                    last_error = message(&e);
                    retry.push(step);
                }
                Err(e) => {
                    return Err(format!(
                        "{} failed: {}; nothing was undone",
                        step.description,
                        message(&e)
                    ));
                }
            }
        }
        if retry.is_empty() {
            break;
        }
        if retry.len() == before {
            return Err(format!(
                "could not undo without touching other rows: {last_error}; nothing was undone"
            ));
        }
        pending = retry;
    }
    Ok(done)
}

/// Can changing a row of this table change others: does it have triggers,
/// or foreign keys that cascade or set null from it?
async fn reaches_other_rows(
    conn: &mut Conn,
    (db, table): &(String, String),
) -> Result<bool, String> {
    let n: Option<i64> = conn
        .exec_first(
            "SELECT (SELECT COUNT(*) FROM information_schema.TRIGGERS
                     WHERE EVENT_OBJECT_SCHEMA = ? AND EVENT_OBJECT_TABLE = ?)
                  + (SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
                     WHERE UNIQUE_CONSTRAINT_SCHEMA = ? AND REFERENCED_TABLE_NAME = ?
                       AND (DELETE_RULE NOT IN ('RESTRICT', 'NO ACTION')
                            OR UPDATE_RULE NOT IN ('RESTRICT', 'NO ACTION')))",
            (db, table, db, table),
        )
        .await
        .map_err(|e| format!("{db}.{table}: {}", message(&e)))?;
    Ok(n.unwrap_or(0) > 0)
}

/// Rows this transaction has changed so far, by InnoDB's count (includes
/// cascades and triggers). InnoDB refreshes `innodb_trx` at most every 0.1
/// seconds after it was last read, so wait that long first.
async fn rows_changed(conn: &mut Conn) -> Result<i64, String> {
    tokio::time::sleep(Duration::from_millis(110)).await;
    let n: Option<i64> = conn
        .query_first(
            "SELECT CAST(trx_rows_modified AS SIGNED) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = CONNECTION_ID()",
        )
        .await
        .map_err(|e| message(&e))?;
    Ok(n.unwrap_or(0))
}

async fn table_info(conn: &mut Conn, db: &str, table: &str) -> Result<TableInfo, String> {
    let err = |e: mysql_async::Error| format!("{db}.{table}: {}", message(&e));
    type Row = (
        String,
        String,
        String,
        Option<String>,
        String,
        Option<u64>,
        Option<u64>,
    );
    let rows: Vec<Row> = conn
        .exec(
            "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, CHARACTER_SET_NAME, EXTRA,
                    NUMERIC_PRECISION, NUMERIC_SCALE
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
             ORDER BY ORDINAL_POSITION",
            (db, table),
        )
        .await
        .map_err(err)?;
    let primary_key: Vec<String> = conn
        .exec(
            "SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'
             ORDER BY ORDINAL_POSITION",
            (db, table),
        )
        .await
        .map_err(err)?;
    let columns = rows
        .into_iter()
        .map(
            |(name, data_type, column_type, charset, extra, precision, scale)| {
                let data_type = data_type.to_lowercase();
                let column_type = column_type.to_lowercase();
                let extra = extra.to_uppercase();
                Column {
                    unsigned: !matches!(data_type.as_str(), "enum" | "set")
                        && column_type.contains(" unsigned"),
                    other_charset: charset
                        .map(|c| c.to_lowercase())
                        .filter(|c| !crate::mysql_binlog::is_utf8(c)),
                    generated: extra.contains("VIRTUAL GENERATED")
                        || extra.contains("STORED GENERATED")
                        || extra.contains("PERSISTENT GENERATED"),
                    name,
                    data_type,
                    precision,
                    scale,
                }
            },
        )
        .collect();
    Ok(TableInfo {
        db: db.to_string(),
        table: table.to_string(),
        columns,
        primary_key,
    })
}

fn key_of(change: &Change, values: &[Option<Cell>], pk: &[String]) -> Vec<Option<String>> {
    pk.iter()
        .map(|col| {
            let i = change.columns.iter().position(|c| c == col)?;
            match values.get(i)? {
                Some(Cell::Text(t)) => Some(t.clone()),
                _ => None,
            }
        })
        .collect()
}

fn show_key(key: &[Option<String>]) -> String {
    let parts: Vec<String> = key
        .iter()
        .map(|v| v.clone().unwrap_or_else(|| "NULL".into()))
        .collect();
    format!("({})", parts.join(", "))
}

fn is_bytes_type(data_type: &str) -> bool {
    matches!(
        data_type,
        "binary"
            | "varbinary"
            | "tinyblob"
            | "blob"
            | "mediumblob"
            | "longblob"
            | "geometry"
            | "point"
            | "linestring"
            | "polygon"
            | "multipoint"
            | "multilinestring"
            | "multipolygon"
            | "geometrycollection"
            | "geomcollection"
            | "vector"
    )
}

fn is_string_type(data_type: &str) -> bool {
    is_bytes_type(data_type)
        || matches!(
            data_type,
            "char" | "varchar" | "tinytext" | "text" | "mediumtext" | "longtext" | "enum" | "set"
        )
}

/// Values recorded as hex: binary data, and text in a character set other
/// than utf8. They are sent as hex too, since a server may refuse bytes that
/// are not valid in the connection's character set.
fn is_hex(col: &Column) -> bool {
    is_bytes_type(&col.data_type) || (is_string_type(&col.data_type) && col.other_charset.is_some())
}

/// The placeholder for a value written to `col`.
fn write_expr(col: &Column) -> String {
    if col.data_type == "json" {
        "CAST(? AS JSON)".to_string()
    } else if let (Some(cs), false) = (&col.other_charset, is_bytes_type(&col.data_type)) {
        // The recorded bytes are already in the column's character set.
        format!("CONVERT(UNHEX(?) USING {})", safe_word(cs))
    } else if is_hex(col) {
        "UNHEX(?)".to_string()
    } else if matches!(col.data_type.as_str(), "decimal" | "numeric") {
        decimal_cast(col)
    } else {
        "?".to_string()
    }
}

fn decimal_cast(col: &Column) -> String {
    format!(
        "CAST(? AS DECIMAL({}, {}))",
        col.precision.unwrap_or(65).clamp(1, 65),
        col.scale.unwrap_or(0).min(30)
    )
}

/// A character set name from information_schema, safe to put in SQL.
fn safe_word(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// True when `col` holds exactly the bound value: compared as bytes for
/// strings (so case and trailing spaces count), as JSON for JSON, and as
/// the column's own type otherwise.
fn same_expr(col: &Column) -> String {
    let c = quote_ident(&col.name);
    if col.data_type == "json" {
        format!("{c} <=> CAST(? AS JSON)")
    } else if is_hex(col) {
        format!("CAST({c} AS BINARY) <=> UNHEX(?)")
    } else if is_string_type(&col.data_type) {
        format!("CAST({c} AS BINARY) <=> CAST(? AS BINARY)")
    } else if matches!(col.data_type.as_str(), "decimal" | "numeric") {
        format!("{c} <=> {}", decimal_cast(col))
    } else {
        format!("{c} <=> ?")
    }
}

/// A recorded value as a parameter for `col` (see `mysql_binlog` for the
/// text each type was recorded as).
fn param(col: &Column, cell: &Option<Cell>) -> Result<Value, String> {
    let text = match cell {
        None => return Ok(Value::NULL),
        Some(Cell::Unchanged { .. }) => {
            return Err(format!("the binlog did not carry {} in full", col.name));
        }
        Some(Cell::Text(t)) => t,
    };
    let bad = || format!("{}: cannot read back the recorded value {text:?}", col.name);
    Ok(match col.data_type.as_str() {
        "tinyint" | "smallint" | "mediumint" | "int" | "integer" | "bigint" => {
            if col.unsigned {
                Value::UInt(text.parse().map_err(|_| bad())?)
            } else {
                Value::Int(text.parse().map_err(|_| bad())?)
            }
        }
        "bit" => Value::UInt(text.parse().map_err(|_| bad())?),
        "year" => Value::Int(text.parse().map_err(|_| bad())?),
        "float" => Value::Float(text.parse().map_err(|_| bad())?),
        "double" | "real" => Value::Double(text.parse().map_err(|_| bad())?),
        "date" | "datetime" | "timestamp" => parse_datetime(text).ok_or_else(bad)?,
        "time" => parse_time(text).ok_or_else(bad)?,
        _ if is_hex(col) => {
            let hex = text.strip_prefix("\\x").ok_or_else(bad)?;
            if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad());
            }
            Value::Bytes(hex.as_bytes().to_vec())
        }
        _ => Value::Bytes(text.clone().into_bytes()),
    })
}

/// `YYYY-MM-DD[ HH:MM:SS[.ffffff]]` as a DATETIME value.
fn parse_datetime(text: &str) -> Option<Value> {
    let (date, time) = text.split_once(' ').unwrap_or((text, "00:00:00"));
    let mut d = date.split('-');
    let (y, mo, da) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':');
    let (h, mi, s) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    Some(Value::Date(y, mo, da, h, mi, s, micros(frac)?))
}

/// `[-]H:MM:SS[.ffffff]` as a TIME value.
fn parse_time(text: &str) -> Option<Value> {
    let (neg, rest) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text),
    };
    let (hms, frac) = rest.split_once('.').unwrap_or((rest, ""));
    let mut t = hms.split(':');
    let hours: u32 = t.next()?.parse().ok()?;
    let (m, s) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    Some(Value::Time(
        neg,
        hours / 24,
        (hours % 24) as u8,
        m,
        s,
        micros(frac)?,
    ))
}

/// `"5"` (tenths) to 500000 microseconds.
fn micros(frac: &str) -> Option<u32> {
    if frac.is_empty() {
        return Some(0);
    }
    if frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    format!("{frac:0<6}").parse().ok()
}

/// Every recorded column that can be written (generated ones cannot).
fn writable<'c>(change: &'c Change, info: &TableInfo) -> Vec<&'c String> {
    change
        .columns
        .iter()
        .filter(|c| info.column(c).is_some_and(|col| !col.generated))
        .collect()
}

/// The single step that takes a row from the session's last change back to
/// how it was before the session's first change. `None` when there is
/// nothing to do: the session inserted the row and deleted it again.
fn net_inverse(first: &Change, last: &Change, info: &TableInfo) -> Result<Option<Step>, String> {
    let table = first.qualified_table();
    let qt = quote_table(&info.db, &info.table);
    let column = |name: &str| {
        info.column(name)
            .ok_or_else(|| format!("column {name} no longer exists"))
    };
    let value_of =
        |change: &Change, values: &[Option<Cell>], name: &str| -> Result<Value, String> {
            let i = change
                .columns
                .iter()
                .position(|c| c == name)
                .ok_or_else(|| format!("column {name} was not recorded"))?;
            param(column(name)?, &values[i])
        };
    // `pk = ?` for each primary key column, with the row's values.
    let where_pk =
        |change: &Change, values: &[Option<Cell>]| -> Result<(String, Vec<Value>), String> {
            let mut parts = Vec::new();
            let mut params = Vec::new();
            for name in &info.primary_key {
                let col = column(name)?;
                let expr = if matches!(col.data_type.as_str(), "decimal" | "numeric") {
                    decimal_cast(col)
                } else {
                    write_expr(col)
                };
                parts.push(format!("{} = {expr}", quote_ident(name)));
                params.push(value_of(change, values, name)?);
            }
            Ok((parts.join(" AND "), params))
        };

    let before = match first.op {
        Op::Insert => None,
        Op::Update | Op::Delete => Some(
            first
                .old
                .as_ref()
                .ok_or("a change without its before-image")?,
        ),
        Op::Truncate => return Err("TRUNCATE cannot be undone".to_string()),
    };
    let after = match last.op {
        Op::Insert | Op::Update => Some(last.new.as_ref().ok_or("a change without values")?),
        Op::Delete => None,
        Op::Truncate => return Err("TRUNCATE cannot be undone".to_string()),
    };

    // How to check the row is as the session left it.
    let (check_sql, check_params, expect_present) = match after {
        Some(new) => {
            let (w, mut params) = where_pk(last, new)?;
            let mut same = Vec::new();
            let mut values = Vec::new();
            for name in writable(last, info) {
                same.push(same_expr(column(name)?));
                values.push(value_of(last, new, name)?);
            }
            values.append(&mut params);
            let test = if same.is_empty() {
                "1".to_string()
            } else {
                same.join(" AND ")
            };
            (
                format!("SELECT ({test}) + 0 FROM {qt} WHERE {w}"),
                values,
                true,
            )
        }
        None => {
            let old = last
                .old
                .as_ref()
                .ok_or("a delete without its before-image")?;
            let (w, params) = where_pk(last, old)?;
            (format!("SELECT 1 FROM {qt} WHERE {w}"), params, false)
        }
    };

    let (sql, params, description, key, own_changes) = match (before, after) {
        (None, None) => return Ok(None),
        (None, Some(new)) => {
            let (w, params) = where_pk(last, new)?;
            let key = key_of(last, new, &info.primary_key);
            (
                format!("DELETE FROM {qt} WHERE {w}"),
                params,
                format!("delete inserted {table} row {}", show_key(&key)),
                key,
                1,
            )
        }
        (Some(old), Some(new)) => {
            let mut sets = Vec::new();
            let mut params = Vec::new();
            for name in writable(first, info) {
                sets.push(format!(
                    "{} = {}",
                    quote_ident(name),
                    write_expr(column(name)?)
                ));
                params.push(value_of(first, old, name)?);
            }
            let (w, mut where_params) = where_pk(last, new)?;
            params.append(&mut where_params);
            let key = key_of(last, new, &info.primary_key);
            // Changing a primary key back is a delete and an insert to InnoDB.
            let own = if key_of(first, old, &info.primary_key) == key {
                1
            } else {
                2
            };
            (
                format!("UPDATE {qt} SET {} WHERE {w}", sets.join(", ")),
                params,
                format!("restore {table} row {}", show_key(&key)),
                key,
                own,
            )
        }
        (Some(old), None) => {
            let mut cols = Vec::new();
            let mut exprs = Vec::new();
            let mut params = Vec::new();
            for name in writable(first, info) {
                cols.push(quote_ident(name));
                exprs.push(write_expr(column(name)?));
                params.push(value_of(first, old, name)?);
            }
            let key = key_of(first, old, &info.primary_key);
            (
                format!(
                    "INSERT INTO {qt} ({}) VALUES ({})",
                    cols.join(", "),
                    exprs.join(", ")
                ),
                params,
                format!("re-insert deleted {table} row {}", show_key(&key)),
                key,
                1,
            )
        }
    };
    Ok(Some(Step {
        description,
        key: (table, key),
        table: (info.db.clone(), info.table.clone()),
        sql,
        params,
        check_sql,
        check_params,
        expect_present,
        own_changes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, data_type: &str) -> Column {
        Column {
            name: name.into(),
            data_type: data_type.into(),
            unsigned: false,
            other_charset: None,
            generated: false,
            precision: Some(10),
            scale: Some(2),
        }
    }

    fn info() -> TableInfo {
        let mut total = col("total", "decimal");
        total.precision = Some(10);
        let mut doubled = col("doubled", "decimal");
        doubled.generated = true;
        TableInfo {
            db: "shop".into(),
            table: "orders".into(),
            columns: vec![
                col("id", "bigint"),
                col("status", "varchar"),
                total,
                doubled,
            ],
            primary_key: vec!["id".into()],
        }
    }

    fn change(op: Op, old: Option<[&str; 3]>, new: Option<[&str; 3]>) -> Change {
        let cells = |v: [&str; 3]| -> Vec<Option<Cell>> {
            let mut out: Vec<Option<Cell>> =
                v.iter().map(|s| Some(Cell::Text(s.to_string()))).collect();
            out.push(Some(Cell::Text("0".into())));
            out
        };
        Change {
            schema: "shop".into(),
            table: "orders".into(),
            op,
            columns: vec![
                "id".into(),
                "status".into(),
                "total".into(),
                "doubled".into(),
            ],
            old: old.map(cells),
            new: new.map(cells),
        }
    }

    fn step(first: &Change, last: &Change) -> Step {
        net_inverse(first, last, &info()).unwrap().expect("a step")
    }

    #[test]
    fn inverts_each_kind_of_change_with_parameters() {
        let i = change(Op::Insert, None, Some(["7", "new", "1.00"]));
        let s = step(&i, &i);
        assert_eq!(s.sql, "DELETE FROM `shop`.`orders` WHERE `id` = ?");
        assert_eq!(s.params, vec![Value::Int(7)]);
        assert!(s.expect_present);

        let u = change(
            Op::Update,
            Some(["7", "o'ld", "2.50"]),
            Some(["7", "void", "0.00"]),
        );
        let s = step(&u, &u);
        assert_eq!(
            s.sql,
            "UPDATE `shop`.`orders` SET `id` = ?, `status` = ?, `total` = CAST(? AS DECIMAL(10, 2)) WHERE `id` = ?"
        );
        assert_eq!(
            s.params,
            vec![
                Value::Int(7),
                Value::Bytes(b"o'ld".to_vec()),
                Value::Bytes(b"2.50".to_vec()),
                Value::Int(7)
            ]
        );
        assert_eq!(
            s.check_sql,
            "SELECT (`id` <=> ? AND CAST(`status` AS BINARY) <=> CAST(? AS BINARY) AND `total` <=> CAST(? AS DECIMAL(10, 2))) + 0 FROM `shop`.`orders` WHERE `id` = ?"
        );

        let d = change(Op::Delete, Some(["7", "paid", "3.00"]), None);
        let s = step(&d, &d);
        assert_eq!(
            s.sql,
            "INSERT INTO `shop`.`orders` (`id`, `status`, `total`) VALUES (?, ?, CAST(? AS DECIMAL(10, 2)))"
        );
        assert!(!s.expect_present);
        assert_eq!(s.check_sql, "SELECT 1 FROM `shop`.`orders` WHERE `id` = ?");
    }

    #[test]
    fn several_changes_to_one_row_become_one_step() {
        let insert = change(Op::Insert, None, Some(["7", "new", "1.00"]));
        let update = change(
            Op::Update,
            Some(["7", "new", "1.00"]),
            Some(["7", "newer", "1.00"]),
        );
        let delete = change(Op::Delete, Some(["7", "newer", "1.00"]), None);
        let paid = change(
            Op::Update,
            Some(["7", "paid", "1.00"]),
            Some(["7", "void", "1.00"]),
        );
        assert!(net_inverse(&insert, &delete, &info()).unwrap().is_none());
        assert!(step(&insert, &update).sql.starts_with("DELETE FROM"));
        let s = step(&paid, &delete);
        assert!(s.sql.starts_with("INSERT INTO"));
        assert_eq!(s.params[1], Value::Bytes(b"paid".to_vec()));
        let s = step(&paid, &update);
        assert_eq!(s.params[1], Value::Bytes(b"paid".to_vec()));
    }

    #[test]
    fn values_read_back_as_their_types() {
        let mut u = col("n", "bigint");
        u.unsigned = true;
        let t = |s: &str| Some(Cell::Text(s.into()));
        assert_eq!(
            param(&u, &t("18446744073709551615")).unwrap(),
            Value::UInt(u64::MAX)
        );
        assert_eq!(
            param(&col("f", "float"), &t("0.1")).unwrap(),
            Value::Float(0.1)
        );
        assert_eq!(
            param(&col("b", "blob"), &t("\\x00ff")).unwrap(),
            Value::Bytes(b"00ff".to_vec())
        );
        assert!(param(&col("b", "blob"), &t("\\x0g")).is_err());
        assert!(param(&col("b", "blob"), &t("00ff")).is_err());
        assert_eq!(
            param(&col("d", "datetime"), &t("2026-10-09 08:07:06.12")).unwrap(),
            Value::Date(2026, 10, 9, 8, 7, 6, 120_000)
        );
        assert_eq!(
            param(&col("d", "date"), &t("2026-10-09")).unwrap(),
            Value::Date(2026, 10, 9, 0, 0, 0, 0)
        );
        assert_eq!(
            param(&col("t", "time"), &t("-838:59:59")).unwrap(),
            Value::Time(true, 34, 22, 59, 59, 0)
        );
        assert_eq!(
            param(&col("j", "json"), &t("{\"a\":1}")).unwrap(),
            Value::Bytes(b"{\"a\":1}".to_vec())
        );
        assert_eq!(param(&col("x", "varchar"), &None).unwrap(), Value::NULL);
        assert!(
            param(
                &col("x", "varchar"),
                &Some(Cell::Unchanged { unchanged: true })
            )
            .is_err()
        );
        let mut latin = col("l", "varchar");
        latin.other_charset = Some("latin1".into());
        assert_eq!(
            param(&latin, &t("\\xe9")).unwrap(),
            Value::Bytes(b"e9".to_vec())
        );
        assert_eq!(write_expr(&latin), "CONVERT(UNHEX(?) USING latin1)");
        assert_eq!(same_expr(&latin), "CAST(`l` AS BINARY) <=> UNHEX(?)");
        assert_eq!(write_expr(&col("b", "varbinary")), "UNHEX(?)");
    }

    #[test]
    fn identifiers_are_quoted_and_values_never_spliced() {
        let hostile = "x'); DROP TABLE orders; --";
        let d = change(Op::Delete, Some(["7", hostile, "1.00"]), None);
        let s = step(&d, &d);
        assert!(!s.sql.contains("DROP"), "{}", s.sql);
        assert!(
            s.params
                .contains(&Value::Bytes(hostile.as_bytes().to_vec()))
        );
    }
}
