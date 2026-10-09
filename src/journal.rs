//! The change journal: every committed change to a protected table, with the
//! session that made it. Undo is built from this.
//!
//! It reads Postgres's change log through a logical replication slot and
//! appends one JSON line per transaction to `<journal dir>/journal.jsonl`.
//! The slot only advances after a line is safely on disk, so a crash never
//! loses a change.

use crate::config::Config;
use crate::pgoutput::{self, Column, Message, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio_postgres::Client;

/// One committed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnRecord {
    pub xid: u32,
    /// Commit position in the change log; orders transactions.
    pub lsn: u64,
    pub lsn_text: String,
    /// Commit time, Unix milliseconds.
    pub at_ms: i64,
    /// The ariodb session that made the change, if any.
    pub session: Option<String>,
    pub agent: Option<String>,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub schema: String,
    pub table: String,
    pub op: Op,
    pub columns: Vec<String>,
    /// Values before the change. `None` means NULL. Missing for inserts.
    pub old: Option<Vec<Option<Cell>>>,
    /// Values after the change. Missing for deletes.
    pub new: Option<Vec<Option<Cell>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Insert,
    Update,
    Delete,
    Truncate,
}

/// One column value. `Unchanged` marks a large value Postgres did not resend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cell {
    Text(String),
    Unchanged { unchanged: bool },
}

impl Change {
    pub fn qualified_table(&self) -> String {
        format!("{}.{}", self.schema, self.table)
    }
}

fn cells(values: Vec<Value>) -> Vec<Option<Cell>> {
    values
        .into_iter()
        .map(|v| match v {
            Value::Null => None,
            Value::Unchanged => Some(Cell::Unchanged { unchanged: true }),
            Value::Text(t) => Some(Cell::Text(t)),
        })
        .collect()
}

pub fn journal_path(config: &Config) -> PathBuf {
    Path::new(&config.journal.dir).join("journal.jsonl")
}

pub fn read_all(config: &Config) -> Result<Vec<TxnRecord>, String> {
    let path = journal_path(config);
    let Ok(file) = File::open(&path) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let record: TxnRecord = serde_json::from_str(&line)
            .map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))?;
        out.push(record);
    }
    out.sort_by_key(|r| r.lsn);
    Ok(out)
}

/// The connection the journal uses. It needs the REPLICATION attribute.
fn journal_url(config: &Config) -> String {
    std::env::var("ARIODB_JOURNAL_URL").unwrap_or_else(|_| config.database_url())
}

async fn connect(config: &Config, url: &str) -> Result<Client, String> {
    let target = config.admin_target(url)?;
    crate::upstream::admin_client(&target, url).await
}

/// Prepare the database: full before-images on protected tables, a
/// publication listing them, and a replication slot. Safe to run again.
pub async fn setup(config: &Config) -> Result<(), String> {
    let client = connect(config, &journal_url(config)).await?;
    let err = |e: tokio_postgres::Error| {
        e.as_db_error()
            .map(|d| d.message().to_string())
            .unwrap_or(e.to_string())
    };

    let wal_level: String = client
        .query_one("SHOW wal_level", &[])
        .await
        .map_err(err)?
        .get(0);
    if wal_level != "logical" {
        return Err(format!(
            "wal_level is '{wal_level}'; set it to 'logical' and restart Postgres (on managed services, enable logical replication)"
        ));
    }
    println!("ok   wal_level is logical");

    let mut tables = config.protected_tables();
    let wildcard = config
        .agents
        .iter()
        .any(|a| a.access == crate::config::Access::ReadWrite && a.tables.iter().any(|t| t == "*"));
    if wildcard {
        // An agent may write to any table, so protect every user table.
        let rows = client
            .query(
                "SELECT table_schema || '.' || table_name FROM information_schema.tables
                 WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')",
                &[],
            )
            .await
            .map_err(err)?;
        tables.extend(
            rows.iter()
                .map(|r| crate::classify::normalise_table(&r.get::<_, String>(0))),
        );
        tables.sort();
        tables.dedup();
    }
    if tables.is_empty() {
        return Err("no agent has write access, so there is nothing to protect".to_string());
    }
    let quoted: Vec<String> = tables.iter().map(|t| quote_table(t)).collect();
    for (name, q) in tables.iter().zip(&quoted) {
        client
            .batch_execute(&format!("ALTER TABLE {q} REPLICA IDENTITY FULL"))
            .await
            .map_err(|e| format!("{name}: {}", err(e)))?;
        println!("ok   {name}: changes will carry full before-images");
    }

    let publication = &config.journal.publication;
    let exists = client
        .query_opt(
            "SELECT 1 FROM pg_publication WHERE pubname = $1",
            &[publication],
        )
        .await
        .map_err(err)?
        .is_some();
    let verb = if exists {
        "ALTER PUBLICATION"
    } else {
        "CREATE PUBLICATION"
    };
    let action = if exists { "SET TABLE" } else { "FOR TABLE" };
    client
        .batch_execute(&format!(
            "{verb} {} {action} {}",
            quote_ident(publication),
            quoted.join(", ")
        ))
        .await
        .map_err(err)?;
    println!(
        "ok   publication '{publication}' covers {}",
        tables.join(", ")
    );

    let slot = &config.journal.slot;
    let slot_exists = client
        .query_opt(
            "SELECT 1 FROM pg_replication_slots WHERE slot_name = $1",
            &[slot],
        )
        .await
        .map_err(err)?
        .is_some();
    if !slot_exists {
        client
            .execute(
                "SELECT pg_create_logical_replication_slot($1, 'pgoutput')",
                &[slot],
            )
            .await
            .map_err(err)?;
    }
    println!("ok   replication slot '{slot}' is ready");
    Ok(())
}

/// Read changes forever, appending to the journal.
pub async fn run(config: &Config) -> Result<(), String> {
    fs::create_dir_all(&config.journal.dir).map_err(|e| e.to_string())?;
    let client = connect(config, &journal_url(config)).await?;
    let path = journal_path(config);
    let mut relations: HashMap<u32, (String, String, Vec<Column>)> = HashMap::new();
    println!("ariodb: journal is recording changes to {}", path.display());

    loop {
        match poll_once(&client, config, &path, &mut relations).await {
            Ok(0) => tokio::time::sleep(Duration::from_millis(500)).await,
            Ok(_) => {}
            Err(e) => {
                eprintln!("ariodb journal: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Read one batch of whole transactions. Returns how many were recorded.
pub async fn poll_once(
    client: &Client,
    config: &Config,
    path: &Path,
    relations: &mut HashMap<u32, (String, String, Vec<Column>)>,
) -> Result<usize, String> {
    let rows = client
        .query(
            "SELECT data FROM pg_logical_slot_peek_binary_changes(
                 $1, NULL, 1000,
                 'proto_version', '1', 'publication_names', $2, 'messages', 'true')",
            &[&config.journal.slot, &config.journal.publication],
        )
        .await
        .map_err(|e| {
            e.as_db_error()
                .map(|d| d.message().to_string())
                .unwrap_or(e.to_string())
        })?;

    let mut current: Option<TxnRecord> = None;
    let mut finished: Vec<TxnRecord> = Vec::new();
    let mut advance_to: Option<u64> = None;

    for row in &rows {
        let data: Vec<u8> = row.get(0);
        let message = pgoutput::decode(&data).map_err(|e| e.0)?;
        match message {
            Message::Begin {
                xid,
                commit_time_us,
            } => {
                current = Some(TxnRecord {
                    xid,
                    lsn: 0,
                    lsn_text: String::new(),
                    // Postgres counts from 2000-01-01; Unix from 1970-01-01.
                    at_ms: commit_time_us / 1000 + 946_684_800_000,
                    session: None,
                    agent: None,
                    changes: Vec::new(),
                });
            }
            Message::Relation {
                id,
                schema,
                name,
                columns,
            } => {
                relations.insert(id, (schema, name, columns));
            }
            Message::Logical { prefix, content } if prefix == "ariodb" => {
                if let (Some(txn), Ok(tag)) = (
                    current.as_mut(),
                    serde_json::from_slice::<serde_json::Value>(&content),
                ) {
                    txn.session = tag["session"].as_str().map(str::to_string);
                    txn.agent = tag["agent"].as_str().map(str::to_string);
                }
            }
            Message::Insert { relation, new } => {
                push(
                    &mut current,
                    relations,
                    relation,
                    Op::Insert,
                    None,
                    Some(new),
                )?;
            }
            Message::Update { relation, old, new } => {
                push(
                    &mut current,
                    relations,
                    relation,
                    Op::Update,
                    old,
                    Some(new),
                )?;
            }
            Message::Delete { relation, old } => {
                push(
                    &mut current,
                    relations,
                    relation,
                    Op::Delete,
                    Some(old),
                    None,
                )?;
            }
            Message::Truncate { relations: ids } => {
                for id in ids {
                    push(&mut current, relations, id, Op::Truncate, None, None)?;
                }
            }
            Message::Commit { end_lsn } => {
                if let Some(mut txn) = current.take() {
                    txn.lsn = end_lsn;
                    txn.lsn_text = pgoutput::format_lsn(end_lsn);
                    if !txn.changes.is_empty() {
                        finished.push(txn);
                    }
                }
                advance_to = Some(end_lsn);
            }
            _ => {}
        }
    }

    if !finished.is_empty() {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        for txn in &finished {
            let line = serde_json::to_string(txn).map_err(|e| e.to_string())?;
            writeln!(file, "{line}").map_err(|e| e.to_string())?;
        }
        file.sync_data().map_err(|e| e.to_string())?;
    }

    // Only now is it safe to let Postgres forget these changes.
    if let Some(lsn) = advance_to {
        client
            .execute(
                "SELECT pg_replication_slot_advance($1, $2::text::pg_lsn)",
                &[&config.journal.slot, &pgoutput::format_lsn(lsn)],
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(finished.len())
}

fn push(
    current: &mut Option<TxnRecord>,
    relations: &HashMap<u32, (String, String, Vec<Column>)>,
    relation: u32,
    op: Op,
    old: Option<Vec<Value>>,
    new: Option<Vec<Value>>,
) -> Result<(), String> {
    let txn = current.as_mut().ok_or("change outside a transaction")?;
    let (schema, table, columns) = relations
        .get(&relation)
        .ok_or_else(|| format!("unknown relation {relation}"))?;
    txn.changes.push(Change {
        schema: schema.clone(),
        table: table.clone(),
        op,
        columns: columns.iter().map(|c| c.name.clone()).collect(),
        old: old.map(cells),
        new: new.map(cells),
    });
    Ok(())
}

/// `orders` → `"orders"`, `sales.orders` → `"sales"."orders"`.
pub fn quote_table(name: &str) -> String {
    name.split('.')
        .map(quote_ident)
        .collect::<Vec<_>>()
        .join(".")
}

pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
