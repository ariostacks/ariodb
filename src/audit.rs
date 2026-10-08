//! The decisions log: every statement an agent sent, what ariodb decided,
//! why, how long it took and how many rows it changed.
//!
//! Stored in the state directory's SQLite database. Each entry carries the
//! hash of the one before it, so editing or deleting a past entry breaks the
//! chain and `ariodb audit` reports where. Writers in different processes
//! (the proxy and MCP servers) take an immediate lock, so the chain stays
//! single even then. Old entries can be pruned by a retention window; the
//! chain is then checked from the oldest remaining entry.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Delete entries older than this many days. 0 keeps everything.
    pub retention_days: u64,
    /// Store statements with literal values replaced by `$1`, `$2`, ... so
    /// customer data in WHERE clauses or VALUES never reaches the log.
    pub redact_literals: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            retention_days: 30,
            redact_literals: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Entry<'a> {
    pub session: &'a str,
    pub agent: &'a str,
    pub sql: &'a str,
    pub kind: String,
    pub tables: &'a [String],
    /// "allowed", "refused", "rolled_back" or "failed".
    pub outcome: &'a str,
    pub rows: Option<u64>,
    pub reason: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub latency_ms: Option<u64>,
}

/// A stored entry, as the dashboard and fixture export read it.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub id: i64,
    pub at_ms: i64,
    pub session: String,
    pub agent: String,
    pub sql: String,
    pub kind: String,
    pub tables: Vec<String>,
    pub outcome: String,
    pub rows: Option<i64>,
    pub reason: Option<String>,
    pub rule: Option<String>,
    pub latency_ms: Option<i64>,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
    redact: bool,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    session TEXT NOT NULL,
    agent TEXT NOT NULL,
    sql TEXT NOT NULL,
    kind TEXT NOT NULL,
    tables TEXT NOT NULL,
    outcome TEXT NOT NULL,
    rows INTEGER,
    reason TEXT,
    rule TEXT,
    latency_ms INTEGER,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_at ON decisions(at_ms);
CREATE INDEX IF NOT EXISTS decisions_agent ON decisions(agent, id);";

fn open_conn(dir: &Path) -> Result<Connection, String> {
    crate::secrets::ensure_private_dir(dir)?;
    let path = dir.join("ariodb.db");
    let conn = Connection::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA journal_mode = WAL;")
        .map_err(|e| e.to_string())?;
    conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// The text that is hashed for one entry.
fn chain_text(at_ms: i64, prev: &str, d: &Decision) -> String {
    serde_json::json!({
        "at_ms": at_ms,
        "prev": prev,
        "session": d.session,
        "agent": d.agent,
        "sql": d.sql,
        "kind": d.kind,
        "tables": d.tables,
        "outcome": d.outcome,
        "rows": d.rows,
        "reason": d.reason,
        "rule": d.rule,
        "latency_ms": d.latency_ms,
    })
    .to_string()
}

impl AuditLog {
    pub fn open(dir: &Path, settings: &Settings) -> Result<AuditLog, String> {
        Ok(AuditLog {
            conn: Mutex::new(open_conn(dir)?),
            redact: settings.redact_literals,
        })
    }

    pub fn record(&self, entry: &Entry) {
        if let Err(e) = self.try_record(entry) {
            eprintln!("ariodb: could not write the decisions log: {e}");
        }
    }

    fn try_record(&self, entry: &Entry) -> Result<(), String> {
        let sql = if self.redact {
            pg_query::normalize(entry.sql).unwrap_or_else(|_| "<unparseable statement>".into())
        } else {
            entry.sql.to_string()
        };
        let d = Decision {
            id: 0,
            at_ms: now_ms() as i64,
            session: entry.session.to_string(),
            agent: entry.agent.to_string(),
            sql,
            kind: entry.kind.clone(),
            tables: entry.tables.to_vec(),
            outcome: entry.outcome.to_string(),
            rows: entry.rows.map(|r| r as i64),
            reason: entry.reason.map(str::to_string),
            rule: entry.rule.map(str::to_string),
            latency_ms: entry.latency_ms.map(|l| l as i64),
        };
        let mut conn = self.conn.lock().expect("audit lock");
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let prev: String = tx
            .query_row(
                "SELECT hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let hash = hex::encode(Sha256::digest(chain_text(d.at_ms, &prev, &d).as_bytes()));
        tx.execute(
            "INSERT INTO decisions (at_ms, session, agent, sql, kind, tables, outcome, rows, reason, rule, latency_ms, prev, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                d.at_ms,
                d.session,
                d.agent,
                d.sql,
                d.kind,
                serde_json::to_string(&d.tables).unwrap_or_default(),
                d.outcome,
                d.rows,
                d.reason,
                d.rule,
                d.latency_ms,
                prev,
                hash
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
}

fn row_to_decision(r: &rusqlite::Row) -> rusqlite::Result<Decision> {
    let tables: String = r.get("tables")?;
    Ok(Decision {
        id: r.get("id")?,
        at_ms: r.get("at_ms")?,
        session: r.get("session")?,
        agent: r.get("agent")?,
        sql: r.get("sql")?,
        kind: r.get("kind")?,
        tables: serde_json::from_str(&tables).unwrap_or_default(),
        outcome: r.get("outcome")?,
        rows: r.get("rows")?,
        reason: r.get("reason")?,
        rule: r.get("rule")?,
        latency_ms: r.get("latency_ms")?,
    })
}

/// Filters for reading decisions.
#[derive(Debug, Default, Deserialize)]
pub struct Filter {
    pub agent: Option<String>,
    pub outcome: Option<String>,
    pub rule: Option<String>,
    pub session: Option<String>,
    /// Text that must appear in the statement.
    pub q: Option<String>,
    /// Only entries older than this id (for paging).
    pub before: Option<i64>,
    pub limit: Option<i64>,
}

pub fn query(dir: &Path, f: &Filter) -> Result<Vec<Decision>, String> {
    let conn = open_conn(dir)?;
    let mut sql = "SELECT * FROM decisions WHERE 1 = 1".to_string();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    // Each condition is a template where `?` becomes the next parameter.
    let mut conditions: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();
    if let Some(v) = &f.agent {
        conditions.push(("agent = ?", Box::new(v.clone())));
    }
    if let Some(v) = &f.outcome {
        conditions.push(("outcome = ?", Box::new(v.clone())));
    }
    if let Some(v) = &f.rule {
        conditions.push(("rule = ?", Box::new(v.clone())));
    }
    if let Some(v) = &f.session {
        conditions.push(("session = ?", Box::new(v.clone())));
    }
    if let Some(v) = &f.q {
        conditions.push(("instr(lower(sql), lower(?)) > 0", Box::new(v.clone())));
    }
    if let Some(v) = f.before {
        conditions.push(("id < ?", Box::new(v)));
    }
    for (template, value) in conditions {
        args.push(value);
        sql.push_str(&format!(
            " AND {}",
            template.replace('?', &format!("?{}", args.len()))
        ));
    }
    sql.push_str(&format!(
        " ORDER BY id DESC LIMIT {}",
        f.limit.unwrap_or(100).clamp(1, 1000)
    ));
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a.as_ref()).collect();
    let rows = stmt
        .query_map(refs.as_slice(), row_to_decision)
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn get(dir: &Path, id: i64) -> Result<Option<Decision>, String> {
    let conn = open_conn(dir)?;
    conn.query_row(
        "SELECT * FROM decisions WHERE id = ?1",
        [id],
        row_to_decision,
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Counts by outcome since a time, for the overview.
pub fn counts_since(dir: &Path, since_ms: i64) -> Result<Vec<(String, i64)>, String> {
    let conn = open_conn(dir)?;
    let mut stmt = conn
        .prepare("SELECT outcome, count(*) FROM decisions WHERE at_ms >= ?1 GROUP BY outcome ORDER BY 2 DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([since_ms], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// Check every link in the chain, from the oldest remaining entry. Returns
/// the number of entries checked, or where the chain breaks.
pub fn verify(dir: &Path) -> Result<usize, String> {
    let conn = open_conn(dir)?;
    let mut stmt = conn
        .prepare("SELECT *, prev AS p, hash AS h FROM decisions ORDER BY id")
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut expected_prev: Option<String> = None;
    let mut count = 0;
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let d = row_to_decision(r).map_err(|e| e.to_string())?;
        let prev: String = r.get("p").map_err(|e| e.to_string())?;
        let hash: String = r.get("h").map_err(|e| e.to_string())?;
        // The oldest remaining entry's predecessor may have been pruned.
        if let Some(exp) = &expected_prev
            && *exp != prev
        {
            return Err(format!(
                "chain broken at entry {} (an entry before it was removed or changed)",
                d.id
            ));
        }
        let actual = hex::encode(Sha256::digest(chain_text(d.at_ms, &prev, &d).as_bytes()));
        if actual != hash {
            return Err(format!("chain broken at entry {} (it was edited)", d.id));
        }
        expected_prev = Some(hash);
        count += 1;
    }
    Ok(count)
}

/// Delete entries older than the retention window.
pub fn prune(dir: &Path, settings: &Settings) -> Result<usize, String> {
    if settings.retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now_ms() as i64 - settings.retention_days as i64 * 86_400_000;
    let conn = open_conn(dir)?;
    conn.execute("DELETE FROM decisions WHERE at_ms < ?1", [cutoff])
        .map_err(|e| e.to_string())
}

/// Write recorded decisions as `ariodb test` fixtures, so today's verdicts
/// become regression tests for tomorrow's policy.
pub fn export_fixtures(dir: &Path, out: &Path, limit: i64) -> Result<usize, String> {
    let decisions = query(
        dir,
        &Filter {
            limit: Some(limit),
            ..Default::default()
        },
    )?;
    let mut fixtures = Vec::new();
    for d in decisions {
        let verdict = match d.outcome.as_str() {
            "allowed" => "allow",
            "refused" => "deny",
            _ => continue, // rollbacks and failures depend on data, not policy
        };
        let mut expect = serde_json::json!({ "verdict": verdict });
        if let Some(rule) = &d.rule {
            expect["rule"] = serde_json::json!(rule);
        } else if verdict == "deny" {
            expect["rule"] = serde_json::json!("policy");
        }
        fixtures.push(serde_json::json!({
            "name": format!("decision {} ({})", d.id, d.agent),
            "action": { "agent": d.agent, "sql": { "statement": d.sql } },
            "match": expect,
        }));
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let path = out.join("recorded.json");
    let text = serde_json::to_string_pretty(&fixtures).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(fixtures.len())
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(sql: &'a str, tables: &'a [String]) -> Entry<'a> {
        Entry {
            session: "s1",
            agent: "bot",
            sql,
            kind: "read".into(),
            tables,
            outcome: "allowed",
            rows: Some(1),
            reason: None,
            rule: None,
            latency_ms: Some(2),
        }
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("ariodb-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tables = vec!["orders".to_string()];
        let log = AuditLog::open(&dir, &Settings::default()).unwrap();
        for sql in ["SELECT 1", "SELECT 2", "SELECT 3"] {
            log.record(&entry(sql, &tables));
        }
        assert_eq!(verify(&dir), Ok(3));

        let conn = open_conn(&dir).unwrap();
        conn.execute(
            "UPDATE decisions SET sql = 'SELECT 9' WHERE sql = 'SELECT 2'",
            [],
        )
        .unwrap();
        assert!(verify(&dir).unwrap_err().contains("edited"));
        conn.execute(
            "UPDATE decisions SET sql = 'SELECT 2' WHERE sql = 'SELECT 9'",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM decisions WHERE sql = 'SELECT 2'", [])
            .unwrap();
        assert!(verify(&dir).unwrap_err().contains("removed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redaction_hides_literals() {
        let dir = std::env::temp_dir().join(format!("ariodb-audit-r-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = AuditLog::open(
            &dir,
            &Settings {
                retention_days: 0,
                redact_literals: true,
            },
        )
        .unwrap();
        log.record(&entry(
            "SELECT * FROM users WHERE email = 'pat@example.test'",
            &[],
        ));
        let d = query(&dir, &Filter::default()).unwrap();
        assert_eq!(d[0].sql, "SELECT * FROM users WHERE email = $1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
