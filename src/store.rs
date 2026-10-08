//! ariodb's own SQLite database in the state directory. It holds pending
//! approvals (shared between the proxy, MCP processes and the dashboard),
//! dashboard logins, and the decisions log.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Approval {
    pub id: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub agent: String,
    pub session: String,
    pub sql: String,
    pub rule: String,
    pub approver: String,
    pub reason: String,
    /// pending, allowed, denied or expired
    pub status: String,
    pub decided_by: Option<String>,
    pub note: Option<String>,
    pub decided_ms: Option<i64>,
}

impl Db {
    pub fn open(state_dir: &Path) -> Result<Db, String> {
        crate::secrets::ensure_private_dir(state_dir)?;
        let path = state_dir.join("ariodb.db");
        let conn = Connection::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS approvals (
                 id TEXT PRIMARY KEY,
                 created_ms INTEGER NOT NULL,
                 expires_ms INTEGER NOT NULL,
                 agent TEXT NOT NULL,
                 session TEXT NOT NULL,
                 sql TEXT NOT NULL,
                 rule TEXT NOT NULL,
                 approver TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 status TEXT NOT NULL,
                 decided_by TEXT,
                 note TEXT,
                 decided_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status, created_ms);
             CREATE TABLE IF NOT EXISTS dashboard_users (
                 name TEXT PRIMARY KEY,
                 password_hash TEXT NOT NULL,
                 created_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS dashboard_sessions (
                 token_hash TEXT PRIMARY KEY,
                 user TEXT NOT NULL,
                 csrf TEXT NOT NULL,
                 expires_ms INTEGER NOT NULL
             );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T, String> {
        let conn = self.conn.lock().expect("db lock");
        f(&conn).map_err(|e| e.to_string())
    }

    pub fn insert_approval(&self, a: &Approval) -> Result<(), String> {
        self.with(|c| {
            c.execute(
                "INSERT INTO approvals (id, created_ms, expires_ms, agent, session, sql, rule, approver, reason, status, decided_by, note, decided_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![a.id, a.created_ms, a.expires_ms, a.agent, a.session, a.sql, a.rule, a.approver, a.reason, a.status, a.decided_by, a.note, a.decided_ms],
            )
            .map(|_| ())
        })
    }

    pub fn approval(&self, id: &str) -> Result<Option<Approval>, String> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM approvals WHERE id = ?1",
                [id],
                row_to_approval,
            )
            .optional()
        })
    }

    /// Record a decision. Only a pending approval can be decided; returns
    /// false if it was already decided or expired.
    pub fn decide(
        &self,
        id: &str,
        allow: bool,
        by: &str,
        note: Option<&str>,
    ) -> Result<bool, String> {
        let status = if allow { "allowed" } else { "denied" };
        self.with(|c| {
            c.execute(
                "UPDATE approvals SET status = ?2, decided_by = ?3, note = ?4, decided_ms = ?5
                 WHERE id = ?1 AND status = 'pending'",
                params![id, status, by, note, now_ms()],
            )
            .map(|n| n == 1)
        })
    }

    pub fn expire(&self, id: &str) -> Result<(), String> {
        self.with(|c| {
            c.execute(
                "UPDATE approvals SET status = 'expired', decided_ms = ?2 WHERE id = ?1 AND status = 'pending'",
                params![id, now_ms()],
            )
            .map(|_| ())
        })
    }

    pub fn approvals(&self, only_pending: bool, limit: i64) -> Result<Vec<Approval>, String> {
        let sql = if only_pending {
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_ms DESC LIMIT ?1"
        } else {
            "SELECT * FROM approvals ORDER BY created_ms DESC LIMIT ?1"
        };
        self.with(|c| {
            let mut stmt = c.prepare(sql)?;
            let rows = stmt.query_map([limit], row_to_approval)?;
            rows.collect()
        })
    }
}

fn row_to_approval(r: &rusqlite::Row) -> rusqlite::Result<Approval> {
    Ok(Approval {
        id: r.get("id")?,
        created_ms: r.get("created_ms")?,
        expires_ms: r.get("expires_ms")?,
        agent: r.get("agent")?,
        session: r.get("session")?,
        sql: r.get("sql")?,
        rule: r.get("rule")?,
        approver: r.get("approver")?,
        reason: r.get("reason")?,
        status: r.get("status")?,
        decided_by: r.get("decided_by")?,
        note: r.get("note")?,
        decided_ms: r.get("decided_ms")?,
    })
}

pub fn now_ms() -> i64 {
    crate::audit::now_ms() as i64
}
