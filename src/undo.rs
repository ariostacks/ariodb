//! Undoing exactly what one session changed, and nothing else.
//!
//! Each recorded change is reversed in the opposite order: an insert becomes
//! a delete, an update restores the old values, a delete re-inserts the row.
//! If anyone else changed the same row afterwards, that row is a conflict and
//! is never silently overwritten.

use crate::config::Config;
use crate::journal::{Cell, Change, Op, TxnRecord, quote_ident, quote_table};
use std::collections::{BTreeMap, HashMap};
use tokio_postgres::Client;

/// A summary line for `ariodb sessions`.
pub struct SessionSummary {
    pub session: String,
    pub agent: String,
    pub transactions: usize,
    pub rows: usize,
    pub tables: Vec<String>,
    pub last_at_ms: i64,
    pub undone: bool,
}

pub fn sessions(records: &[TxnRecord]) -> Vec<SessionSummary> {
    let mut map: BTreeMap<String, SessionSummary> = BTreeMap::new();
    for r in records {
        let Some(session) = &r.session else { continue };
        if session.starts_with("undo:") {
            continue;
        }
        let entry = map
            .entry(session.clone())
            .or_insert_with(|| SessionSummary {
                session: session.clone(),
                agent: r.agent.clone().unwrap_or_default(),
                transactions: 0,
                rows: 0,
                tables: Vec::new(),
                last_at_ms: 0,
                undone: false,
            });
        entry.transactions += 1;
        entry.rows += r.changes.len();
        entry.last_at_ms = entry.last_at_ms.max(r.at_ms);
        for c in &r.changes {
            if !entry.tables.contains(&c.table) {
                entry.tables.push(c.table.clone());
            }
        }
    }
    for r in records {
        if let Some(s) = r.session.as_deref().and_then(|s| s.strip_prefix("undo:"))
            && let Some(entry) = map.get_mut(s)
        {
            entry.undone = true;
        }
    }
    let mut out: Vec<_> = map.into_values().collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.last_at_ms));
    out
}

/// Facts about a table that undo needs from the live database.
struct TableInfo {
    primary_key: Vec<String>,
    /// Column name to its SQL type, such as `numeric(10,2)`.
    types: HashMap<String, String>,
    /// Generated columns cannot be written; Postgres recomputes them.
    generated: Vec<String>,
}

/// One inverse operation.
#[derive(Debug)]
pub struct Step {
    pub description: String,
    pub sql: String,
    /// Identifies the row, for conflict detection.
    key: (String, Vec<Option<String>>),
    /// Rows the step updates or deletes itself: 1, or 0 for a re-insert.
    /// Anything more was done by a cascade or trigger.
    own_changes: i64,
}

pub struct Conflict {
    key: (String, Vec<Option<String>>),
    pub text: String,
}

pub struct Plan {
    pub session: String,
    pub steps: Vec<Step>,
    /// Rows someone else changed after this session did.
    pub conflicts: Vec<Conflict>,
    /// Changes undo cannot reverse, such as TRUNCATE.
    pub blocked: Vec<String>,
    pub already_undone: bool,
}

pub async fn connect(config: &Config) -> Result<Client, String> {
    let url = match std::env::var("ARIODB_ADMIN_URL") {
        Ok(url) => url,
        Err(_) => config.database_url()?,
    };
    let target = config.admin_target(&url)?;
    crate::upstream::admin_client(&target, &url).await
}

/// A row one session changed: its first and last change to it.
struct Touch<'a> {
    first: &'a Change,
    last: &'a Change,
    /// The position of the session's last change to the row, counting
    /// all its changes in commit order.
    last_seen: usize,
}

pub async fn plan(client: &Client, records: &[TxnRecord], session: &str) -> Result<Plan, String> {
    let mine: Vec<&TxnRecord> = records
        .iter()
        .filter(|r| r.session.as_deref() == Some(session))
        .collect();
    if mine.is_empty() {
        return Err(format!("no recorded changes for session '{session}'"));
    }
    let undo_tag = format!("undo:{session}");
    let already_undone = records
        .iter()
        .any(|r| r.session.as_deref() == Some(undo_tag.as_str()));

    let mut infos: HashMap<String, TableInfo> = HashMap::new();
    let mut blocked = Vec::new();
    // Each row this session changed, in the order it first changed them.
    let mut touched: Vec<Touch> = Vec::new();
    let mut by_key: HashMap<(String, Vec<Option<String>>), usize> = HashMap::new();
    // Where this session first changed each row.
    let mut first_touch: HashMap<(String, Vec<Option<String>>), u64> = HashMap::new();
    let mut seen = 0;

    for txn in &mine {
        for change in &txn.changes {
            let table = change.qualified_table();
            if change.op == Op::Truncate {
                blocked.push(format!("TRUNCATE of {table} cannot be undone row by row"));
                continue;
            }
            if !infos.contains_key(&table) {
                infos.insert(table.clone(), table_info(client, &table).await?);
            }
            let info = &infos[&table];
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

    // One step per row, from what the session left back to what was there
    // before it first changed the row. Replaying every change backwards
    // would give a row several steps that must run in order, and the
    // foreign-key retry in `apply` reorders steps. Latest rows first, as
    // that is usually the order foreign keys need.
    touched.sort_by_key(|t| std::cmp::Reverse(t.last_seen));
    let mut steps = Vec::new();
    for t in &touched {
        let info = &infos[&t.first.qualified_table()];
        match net_inverse(t.first, t.last, info) {
            Ok(Some(step)) => steps.push(step),
            Ok(None) => {} // inserted and deleted again: nothing to undo
            Err(reason) => blocked.push(format!("{}: {reason}", t.first.qualified_table())),
        }
    }

    // Did anyone else touch these rows after this session first did?
    // Restoring the session's before-image would overwrite their change,
    // even when the session changed the row again afterwards. Includes
    // earlier undo runs.
    let mut conflicts = Vec::new();
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
                {
                    let who = txn
                        .session
                        .clone()
                        .unwrap_or_else(|| "someone outside ariodb".into());
                    if !conflicts.iter().any(|c: &Conflict| c.key == key) {
                        let text = format!(
                            "{table} row {} was changed later by {who}",
                            show_key(&key.1)
                        );
                        conflicts.push(Conflict { key, text });
                    }
                }
            }
        }
    }

    Ok(Plan {
        session: session.to_string(),
        steps,
        conflicts,
        blocked,
        already_undone,
    })
}

/// Apply a plan in one transaction. Rows with conflicts are skipped only if
/// `skip_conflicts` is set; otherwise nothing is changed.
pub async fn apply(
    client: &mut Client,
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

    let err = |e: tokio_postgres::Error| {
        e.as_db_error()
            .map(|d| d.message().to_string())
            .unwrap_or(e.to_string())
    };
    let tx = client.transaction().await.map_err(err)?;
    let tag =
        serde_json::json!({ "session": format!("undo:{}", plan.session), "agent": "ariodb-undo" })
            .to_string();
    tx.execute(
        "SELECT pg_logical_emit_message(true, 'ariodb', $1::text)",
        &[&tag],
    )
    .await
    .map_err(err)?;

    // Foreign keys can make the right order hard to know in advance (a child
    // row needs its parent back first, and a parent must not go before its
    // children, or deleting it cascades). Retry steps that fail on a
    // foreign key, or that would change rows the session never touched,
    // until no more progress is made.
    let mut pending: Vec<&Step> = plan
        .steps
        .iter()
        .filter(|s| !plan.conflicts.iter().any(|c| c.key == s.key))
        .collect();
    let mut done = 0;
    loop {
        let before = pending.len();
        let mut retry = Vec::new();
        let mut last_error = String::new();
        for step in pending {
            tx.batch_execute("SAVEPOINT ariodb_step")
                .await
                .map_err(err)?;
            let changed_before = rows_changed(&tx).await.map_err(err)?;
            match tx.execute(step.sql.as_str(), &[]).await {
                Ok(1) => {
                    let extra =
                        rows_changed(&tx).await.map_err(err)? - changed_before - step.own_changes;
                    if extra > 0 {
                        // An ON DELETE CASCADE or SET NULL, or a trigger,
                        // reached rows that are not this session's to undo.
                        tx.batch_execute("ROLLBACK TO SAVEPOINT ariodb_step")
                            .await
                            .map_err(err)?;
                        last_error = format!(
                            "{} would also change {extra} other rows (a foreign key cascade or a trigger), which undo leaves alone",
                            step.description
                        );
                        retry.push(step);
                        continue;
                    }
                    tx.batch_execute("RELEASE SAVEPOINT ariodb_step")
                        .await
                        .map_err(err)?;
                    done += 1;
                }
                Ok(n) => {
                    tx.batch_execute("ROLLBACK TO SAVEPOINT ariodb_step")
                        .await
                        .map_err(err)?;
                    return Err(format!(
                        "{} affected {n} rows instead of 1; nothing was undone",
                        step.description
                    ));
                }
                Err(e) if e.code().map(|c| c.code()) == Some("23503") => {
                    tx.batch_execute("ROLLBACK TO SAVEPOINT ariodb_step")
                        .await
                        .map_err(err)?;
                    last_error = err(e);
                    retry.push(step);
                }
                Err(e) => {
                    return Err(format!(
                        "{} failed: {}; nothing was undone",
                        step.description,
                        err(e)
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
    tx.commit().await.map_err(err)?;
    Ok(done)
}

/// Rows updated or deleted so far in this transaction, in every table,
/// including attempts rolled back to a savepoint (only differences are used).
async fn rows_changed(tx: &tokio_postgres::Transaction<'_>) -> Result<i64, tokio_postgres::Error> {
    tx.query_one(
        "SELECT coalesce(sum(n_tup_upd + n_tup_del), 0)::bigint FROM pg_stat_xact_user_tables",
        &[],
    )
    .await
    .map(|r| r.get(0))
}

async fn table_info(client: &Client, table: &str) -> Result<TableInfo, String> {
    let quoted = quote_table(table);
    let err = |e: tokio_postgres::Error| {
        format!(
            "{table}: {}",
            e.as_db_error()
                .map(|d| d.message().to_string())
                .unwrap_or(e.to_string())
        )
    };
    let pk_rows = client
        .query(
            "SELECT a.attname::text
             FROM pg_index i
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
             WHERE i.indrelid = $1::text::regclass AND i.indisprimary
             ORDER BY array_position(i.indkey, a.attnum)",
            &[&quoted],
        )
        .await
        .map_err(err)?;
    let col_rows = client
        .query(
            "SELECT attname::text, format_type(atttypid, atttypmod), attgenerated::text
             FROM pg_attribute
             WHERE attrelid = $1::text::regclass AND attnum > 0 AND NOT attisdropped",
            &[&quoted],
        )
        .await
        .map_err(err)?;
    let mut types = HashMap::new();
    let mut generated = Vec::new();
    for r in &col_rows {
        let name: String = r.get(0);
        let generated_flag: String = r.get(2);
        if !generated_flag.is_empty() {
            generated.push(name.clone());
        }
        types.insert(name, r.get(1));
    }
    Ok(TableInfo {
        primary_key: pk_rows.iter().map(|r| r.get(0)).collect(),
        types,
        generated,
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

/// A recorded value as SQL. The values are whatever the agent wrote, and
/// undo runs them with the admin login, so the quoting must hold whatever
/// the server's `standard_conforming_strings` is: a value with a backslash
/// is written as an `E'...'` string, where backslashes mean the same either
/// way.
fn literal(cell: &Option<Cell>, sql_type: &str) -> Result<String, String> {
    match cell {
        None => Ok("NULL".to_string()),
        Some(Cell::Text(t)) if t.contains('\\') => Ok(format!(
            "E'{}'::{sql_type}",
            t.replace('\\', "\\\\").replace('\'', "''")
        )),
        Some(Cell::Text(t)) => Ok(format!("'{}'::{sql_type}", t.replace('\'', "''"))),
        Some(Cell::Unchanged { .. }) => Err("a large value was not recorded".to_string()),
    }
}

/// The single step that takes a row from the session's last change back to
/// how it was before the session's first change. `None` when there is
/// nothing to do: the session inserted the row and deleted it again.
fn net_inverse(first: &Change, last: &Change, info: &TableInfo) -> Result<Option<Step>, String> {
    let table = first.qualified_table();
    let qt = quote_table(&table);
    let type_of = |col: &str| {
        info.types
            .get(col)
            .cloned()
            .unwrap_or_else(|| "text".into())
    };

    let where_clause = |change: &Change, values: &[Option<Cell>]| -> Result<String, String> {
        let mut parts = Vec::new();
        for col in &info.primary_key {
            let i = change
                .columns
                .iter()
                .position(|c| c == col)
                .ok_or("primary key column missing")?;
            parts.push(format!(
                "{} = {}",
                quote_ident(col),
                literal(&values[i], &type_of(col))?
            ));
        }
        Ok(parts.join(" AND "))
    };

    // What was there before the session, and what it left.
    let before = match first.op {
        Op::Insert => None,
        Op::Update => Some(
            first
                .old
                .as_ref()
                .ok_or("update without before-image; run `ariodb setup`")?,
        ),
        Op::Delete => Some(
            first
                .old
                .as_ref()
                .ok_or("delete without before-image; run `ariodb setup`")?,
        ),
        Op::Truncate => return Err("TRUNCATE cannot be undone".to_string()),
    };
    let after = match last.op {
        Op::Insert | Op::Update => Some(last.new.as_ref().ok_or("change without values")?),
        Op::Delete => None,
        Op::Truncate => return Err("TRUNCATE cannot be undone".to_string()),
    };
    // Generated columns cannot be written; Postgres recomputes them.
    let writable = |old: &[Option<Cell>]| -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        for (i, col) in first.columns.iter().enumerate() {
            if !info.generated.contains(col) {
                out.push((quote_ident(col), literal(&old[i], &type_of(col))?));
            }
        }
        Ok(out)
    };

    Ok(match (before, after) {
        (None, None) => None,
        (None, Some(new)) => {
            let key = key_of(last, new, &info.primary_key);
            Some(Step {
                description: format!("delete inserted {table} row {}", show_key(&key)),
                sql: format!("DELETE FROM {qt} WHERE {}", where_clause(last, new)?),
                key: (table, key),
                own_changes: 1,
            })
        }
        (Some(old), Some(new)) => {
            let sets: Vec<String> = writable(old)?
                .into_iter()
                .map(|(col, value)| format!("{col} = {value}"))
                .collect();
            let key = key_of(last, new, &info.primary_key);
            Some(Step {
                description: format!("restore {table} row {}", show_key(&key)),
                sql: format!(
                    "UPDATE {qt} SET {} WHERE {}",
                    sets.join(", "),
                    where_clause(last, new)?
                ),
                key: (table, key),
                own_changes: 1,
            })
        }
        (Some(old), None) => {
            let (cols, vals): (Vec<String>, Vec<String>) = writable(old)?.into_iter().unzip();
            let key = key_of(first, old, &info.primary_key);
            Some(Step {
                description: format!("re-insert deleted {table} row {}", show_key(&key)),
                sql: format!(
                    "INSERT INTO {qt} ({}) OVERRIDING SYSTEM VALUE VALUES ({})",
                    cols.join(", "),
                    vals.join(", ")
                ),
                key: (table, key),
                own_changes: 0,
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TableInfo {
        TableInfo {
            primary_key: vec!["id".into()],
            types: HashMap::from([
                ("id".into(), "integer".into()),
                ("status".into(), "text".into()),
            ]),
            generated: vec![],
        }
    }

    fn change(op: Op, old: Option<(&str, &str)>, new: Option<(&str, &str)>) -> Change {
        let cells = |(id, status): (&str, &str)| {
            vec![Some(Cell::Text(id.into())), Some(Cell::Text(status.into()))]
        };
        Change {
            schema: "public".into(),
            table: "orders".into(),
            op,
            columns: vec!["id".into(), "status".into()],
            old: old.map(cells),
            new: new.map(cells),
        }
    }

    /// One change undone on its own.
    fn inverse(c: &Change, info: &TableInfo) -> Result<Step, String> {
        net_inverse(c, c, info).map(|s| s.expect("a step"))
    }

    #[test]
    fn inverts_each_kind_of_change() {
        let i = inverse(&change(Op::Insert, None, Some(("7", "new"))), &info()).unwrap();
        assert_eq!(
            i.sql,
            r#"DELETE FROM "public"."orders" WHERE "id" = '7'::integer"#
        );

        let u = inverse(
            &change(Op::Update, Some(("7", "o'ld")), Some(("7", "void"))),
            &info(),
        )
        .unwrap();
        assert_eq!(
            u.sql,
            r#"UPDATE "public"."orders" SET "id" = '7'::integer, "status" = 'o''ld'::text WHERE "id" = '7'::integer"#
        );

        let d = inverse(&change(Op::Delete, Some(("7", "paid")), None), &info()).unwrap();
        assert_eq!(
            d.sql,
            r#"INSERT INTO "public"."orders" ("id", "status") OVERRIDING SYSTEM VALUE VALUES ('7'::integer, 'paid'::text)"#
        );
    }

    #[test]
    fn backslashes_are_quoted_for_either_string_setting() {
        // With standard_conforming_strings off, '\' would end a plain
        // string early and the rest of the value would run as SQL.
        let value = r"x\'; DROP TABLE orders; --";
        let d = inverse(&change(Op::Delete, Some(("7", value)), None), &info()).unwrap();
        assert!(
            d.sql
                .ends_with(r"VALUES ('7'::integer, E'x\\''; DROP TABLE orders; --'::text)"),
            "{}",
            d.sql
        );
    }

    #[test]
    fn missing_large_values_block_the_step() {
        let mut c = change(Op::Delete, Some(("7", "paid")), None);
        c.old.as_mut().unwrap()[1] = Some(Cell::Unchanged { unchanged: true });
        assert!(inverse(&c, &info()).is_err());
    }

    #[test]
    fn several_changes_to_one_row_become_one_step() {
        let insert = change(Op::Insert, None, Some(("7", "new")));
        let update = change(Op::Update, Some(("7", "new")), Some(("7", "newer")));
        let delete = change(Op::Delete, Some(("7", "newer")), None);
        let paid = change(Op::Update, Some(("7", "paid")), Some(("7", "void")));

        // Inserted, then deleted: nothing to do, whatever happened between.
        assert!(net_inverse(&insert, &delete, &info()).unwrap().is_none());
        // Inserted, then changed: delete it.
        let s = net_inverse(&insert, &update, &info()).unwrap().unwrap();
        assert!(s.sql.starts_with("DELETE FROM"), "{}", s.sql);
        // Changed, then deleted: put the original back.
        let s = net_inverse(&paid, &delete, &info()).unwrap().unwrap();
        assert!(
            s.sql.contains("VALUES ('7'::integer, 'paid'::text)"),
            "{}",
            s.sql
        );
        // Changed twice: back to the first before-image.
        let s = net_inverse(&paid, &update, &info()).unwrap().unwrap();
        assert!(s.sql.contains(r#""status" = 'paid'::text"#), "{}", s.sql);
    }
}
