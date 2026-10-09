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
             );
             CREATE INDEX IF NOT EXISTS approvals_session ON approvals(session, created_ms);",
        )
        .map_err(|e| e.to_string())?;
        // Columns added after the first release. Users from before roles
        // existed could do everything, so they stay admins.
        for column in [
            "ALTER TABLE dashboard_users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'",
            "ALTER TABLE dashboard_sessions ADD COLUMN method TEXT NOT NULL DEFAULT 'password'",
            "ALTER TABLE dashboard_sessions ADD COLUMN subject TEXT",
            "ALTER TABLE dashboard_sessions ADD COLUMN email TEXT",
            "ALTER TABLE dashboard_sessions ADD COLUMN groups TEXT NOT NULL DEFAULT '[]'",
        ] {
            if let Err(e) = conn.execute_batch(column)
                && !e.to_string().contains("duplicate column")
            {
                return Err(e.to_string());
            }
        }
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

    /// Mark a pending approval expired because the agent stopped waiting.
    pub fn withdraw(&self, id: &str, why: &str) -> Result<(), String> {
        self.with(|c| {
            c.execute(
                "UPDATE approvals SET status = 'expired', decided_by = 'ariodb', note = ?2, decided_ms = ?3
                 WHERE id = ?1 AND status = 'pending'",
                params![id, why, now_ms()],
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

/// What a dashboard user may do. Each role can do everything the one
/// before it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read every page.
    Viewer,
    /// Also decide approvals.
    Approver,
    /// Also edit the config, block requests, undo sessions, and manage
    /// users and secrets.
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "approver" => Some(Role::Approver),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Approver => "approver",
            Role::Admin => "admin",
        }
    }
}

/// A dashboard session as read back: who, how they signed in, and (for
/// single sign-on) what the identity provider said about them. The
/// provider's subject is stored too, for whoever reads the table later.
#[derive(Debug, Clone)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    /// `password` or `sso`.
    pub method: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    /// For password sessions, the user's role now; None for single sign-on,
    /// whose role follows from the groups and the current config.
    pub local_role: Option<Role>,
}

/// What to record when a session starts.
pub struct NewSession<'a> {
    pub token_hash: &'a str,
    pub user: &'a str,
    pub csrf: &'a str,
    pub expires_ms: i64,
    pub method: &'a str,
    pub subject: Option<&'a str>,
    pub email: Option<&'a str>,
    pub groups: &'a [String],
}

impl Db {
    pub fn insert_session(&self, s: &NewSession) -> Result<(), String> {
        let groups = serde_json::to_string(s.groups).map_err(|e| e.to_string())?;
        self.with(|c| {
            c.execute(
                "DELETE FROM dashboard_sessions WHERE expires_ms < ?1",
                [now_ms()],
            )?;
            c.execute(
                "INSERT INTO dashboard_sessions (token_hash, user, csrf, expires_ms, method, subject, email, groups)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![s.token_hash, s.user, s.csrf, s.expires_ms, s.method, s.subject, s.email, groups],
            )
            .map(|_| ())
        })
    }

    /// The live session with this token hash. A password session whose
    /// user has since been removed is no session.
    pub fn session(&self, token_hash: &str) -> Result<Option<Session>, String> {
        self.with(|c| {
            c.query_row(
                "SELECT s.user, s.csrf, s.method, s.email, s.groups, u.role
                 FROM dashboard_sessions s
                 LEFT JOIN dashboard_users u ON s.method = 'password' AND u.name = s.user
                 WHERE s.token_hash = ?1 AND s.expires_ms > ?2",
                params![token_hash, now_ms()],
                |r| {
                    let groups: String = r.get(4)?;
                    let role: Option<String> = r.get(5)?;
                    Ok(Session {
                        user: r.get(0)?,
                        csrf: r.get(1)?,
                        method: r.get(2)?,
                        email: r.get(3)?,
                        groups: serde_json::from_str(&groups).unwrap_or_default(),
                        local_role: role.as_deref().and_then(Role::parse),
                    })
                },
            )
            .optional()
        })
        .map(|s| s.filter(|s| s.method != "password" || s.local_role.is_some()))
    }

    pub fn end_session(&self, token_hash: &str) -> Result<(), String> {
        self.with(|c| {
            c.execute(
                "DELETE FROM dashboard_sessions WHERE token_hash = ?1",
                [token_hash],
            )
            .map(|_| ())
        })
    }

    /// Local dashboard users and their roles, by name.
    pub fn users(&self) -> Result<Vec<(String, Role)>, String> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT name, role FROM dashboard_users ORDER BY name")?;
            let rows = stmt.query_map([], |r| {
                let role: String = r.get(1)?;
                Ok((r.get(0)?, Role::parse(&role).unwrap_or(Role::Viewer)))
            })?;
            rows.collect()
        })
    }

    /// Change a local user's role. Returns false if there is no such user.
    pub fn set_role(&self, user: &str, role: Role) -> Result<bool, String> {
        self.with(|c| {
            c.execute(
                "UPDATE dashboard_users SET role = ?2 WHERE name = ?1",
                params![user, role.as_str()],
            )
            .map(|n| n == 1)
        })
    }

    /// Remove a local user and end their sessions. Returns false if there
    /// is no such user.
    pub fn remove_user(&self, user: &str) -> Result<bool, String> {
        self.with(|c| {
            c.execute(
                "DELETE FROM dashboard_sessions WHERE user = ?1 AND method = 'password'",
                [user],
            )?;
            c.execute("DELETE FROM dashboard_users WHERE name = ?1", [user])
                .map(|n| n == 1)
        })
    }

    /// Everyone and everything that has decided an approval, most frequent
    /// first, for the decisions filter.
    pub fn deciders(&self) -> Result<Vec<String>, String> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT decided_by FROM approvals WHERE decided_by IS NOT NULL AND decided_by != 'ariodb'
                 GROUP BY decided_by ORDER BY count(*) DESC LIMIT 200",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect()
        })
    }
}

pub fn now_ms() -> i64 {
    crate::audit::now_ms() as i64
}
