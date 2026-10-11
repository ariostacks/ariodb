//! What compliance reports need that the rest of ariodb does not keep: each
//! version of the config file that was in force, and who undid which
//! session.
//!
//! Both live in `ariodb.db` beside the decisions log. Config versions are
//! stored with every password, token and secret masked, so the history is
//! safe to put in a report. Each row carries a hash over the one before
//! it, as the decisions log does, so an edited or removed row shows. Old
//! rows are pruned by `[audit] retention_days`, except the config version
//! in force at the cut-off, so the oldest period kept still has a baseline.

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS config_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    path TEXT NOT NULL,
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    text TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS undo_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    session TEXT NOT NULL,
    engine TEXT NOT NULL,
    rows INTEGER NOT NULL,
    by TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);";

/// What masked values are replaced with, as the dashboard's config view does.
pub const MASK: &str = "***";

fn open(dir: &Path) -> Result<Connection, String> {
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

/// The link hash of one row: its fields and the link before it.
pub fn link(prev: &str, fields: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    for f in fields {
        h.update(b"\n");
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Append a row to a chained table inside one immediate transaction, so
/// writers in several processes keep a single chain.
fn append(
    conn: &mut Connection,
    table: &str,
    insert: &str,
    fields: &[&str],
    values: &[&dyn rusqlite::ToSql],
) -> Result<(), String> {
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let prev: String = tx
        .query_row(
            &format!("SELECT hash FROM {table} ORDER BY id DESC LIMIT 1"),
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let hash = link(&prev, fields);
    let mut all: Vec<&dyn rusqlite::ToSql> = values.to_vec();
    all.push(&prev);
    all.push(&hash);
    tx.execute(insert, all.as_slice())
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

/// Record the config file as it is now, if it differs from the version
/// last recorded. `source` says why: `startup`, `reload` or
/// `dashboard:<user>`. Failing to record is logged, never fatal: it must
/// not stop ariodb from serving.
pub fn record_config(dir: &Path, path: &Path, source: &str) {
    if let Err(e) = try_record_config(dir, path, source) {
        eprintln!("ariodb: could not record the config version: {e}");
    }
}

fn try_record_config(dir: &Path, path: &Path, source: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = mask(&raw);
    let sha = sha256_hex(text.as_bytes());
    let mut conn = open(dir)?;
    let last: Option<String> = conn
        .query_row(
            "SELECT sha256 FROM config_versions ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if last.as_deref() == Some(sha.as_str()) {
        return Ok(());
    }
    let at = crate::store::now_ms();
    let at_text = at.to_string();
    let shown = path.display().to_string();
    append(
        &mut conn,
        "config_versions",
        "INSERT INTO config_versions (at_ms, path, source, sha256, text, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[&at_text, &shown, source, &sha],
        &[&at, &shown, &source, &sha, &text],
    )
}

/// Record an applied undo: which session, how many rows, and who.
pub fn record_undo(dir: &Path, session: &str, engine: &str, rows: usize, by: &str) {
    let result = open(dir).and_then(|mut conn| {
        let at = crate::store::now_ms();
        let (at_text, rows_text) = (at.to_string(), rows.to_string());
        append(
            &mut conn,
            "undo_records",
            "INSERT INTO undo_records (at_ms, session, engine, rows, by, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[&at_text, session, engine, &rows_text, by],
            &[&at, &session, &engine, &(rows as i64), &by],
        )
    });
    if let Err(e) = result {
        eprintln!("ariodb: could not record the undo of {session}: {e}");
    }
}

/// Remove rows older than the retention window, keeping the config version
/// in force at the cut-off.
pub fn prune(dir: &Path, settings: &crate::audit::Settings) -> Result<usize, String> {
    if settings.retention_days == 0 {
        return Ok(0);
    }
    let cutoff = crate::store::now_ms() - settings.retention_days as i64 * 86_400_000;
    let conn = open(dir)?;
    let configs = conn
        .execute(
            "DELETE FROM config_versions WHERE at_ms < ?1
             AND id < (SELECT max(id) FROM config_versions WHERE at_ms < ?1)",
            [cutoff],
        )
        .map_err(|e| e.to_string())?;
    let undos = conn
        .execute("DELETE FROM undo_records WHERE at_ms < ?1", [cutoff])
        .map_err(|e| e.to_string())?;
    Ok(configs + undos)
}

/// One recorded config version, and whether its row is as written.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigVersion {
    pub id: i64,
    pub at_ms: i64,
    pub path: String,
    pub source: String,
    pub sha256: String,
    pub text: String,
    /// False when the text no longer matches its hash, the row's link
    /// hash does not match its fields, or it does not follow the row
    /// before it.
    pub intact: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UndoRecord {
    pub id: i64,
    pub at_ms: i64,
    pub session: String,
    pub engine: String,
    pub rows: i64,
    pub by: String,
    pub intact: bool,
}

fn has_table(conn: &Connection, name: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(|e| e.to_string())
}

/// Every config version recorded before `before_ms`, oldest first, each
/// checked against its hash and the one before it. `conn` may be read-only.
pub fn config_versions(conn: &Connection, before_ms: i64) -> Result<Vec<ConfigVersion>, String> {
    if !has_table(conn, "config_versions")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn
        .prepare("SELECT id, at_ms, path, source, sha256, text, prev, hash FROM config_versions ORDER BY id")
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut expected: Option<String> = None;
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let get = |i| r.get::<_, String>(i).map_err(|e| e.to_string());
        let (id, at_ms): (i64, i64) = (
            r.get(0).map_err(|e| e.to_string())?,
            r.get(1).map_err(|e| e.to_string())?,
        );
        let (path, source, sha, text, prev, hash) =
            (get(2)?, get(3)?, get(4)?, get(5)?, get(6)?, get(7)?);
        let intact = sha256_hex(text.as_bytes()) == sha
            && link(&prev, &[&at_ms.to_string(), &path, &source, &sha]) == hash
            && expected.as_ref().is_none_or(|e| *e == prev);
        expected = Some(hash);
        if at_ms < before_ms {
            out.push(ConfigVersion {
                id,
                at_ms,
                path,
                source,
                sha256: sha,
                text,
                intact,
            });
        }
    }
    Ok(out)
}

/// Undo records from `from_ms` up to `to_ms`, checked as above.
pub fn undo_records(
    conn: &Connection,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<UndoRecord>, String> {
    if !has_table(conn, "undo_records")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn
        .prepare(
            "SELECT id, at_ms, session, engine, rows, by, prev, hash FROM undo_records ORDER BY id",
        )
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut expected: Option<String> = None;
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let e = |e: rusqlite::Error| e.to_string();
        let rec = UndoRecord {
            id: r.get(0).map_err(e)?,
            at_ms: r.get(1).map_err(e)?,
            session: r.get(2).map_err(e)?,
            engine: r.get(3).map_err(e)?,
            rows: r.get(4).map_err(e)?,
            by: r.get(5).map_err(e)?,
            intact: false,
        };
        let (prev, hash): (String, String) = (r.get(6).map_err(e)?, r.get(7).map_err(e)?);
        let fields = [
            rec.at_ms.to_string(),
            rec.session.clone(),
            rec.engine.clone(),
            rec.rows.to_string(),
            rec.by.clone(),
        ];
        let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
        let intact = link(&prev, &fields) == hash && expected.as_ref().is_none_or(|x| *x == prev);
        expected = Some(hash);
        if rec.at_ms >= from_ms && rec.at_ms < to_ms {
            out.push(UndoRecord { intact, ..rec });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Masking.

/// Key names whose values are credentials. Keys ending in `_env` or
/// `_secret`, and `secret` itself, name an environment variable or a
/// stored secret instead, and are kept so policy changes stay readable.
fn secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if k == "secret" || k.ends_with("_env") || k.ends_with("_secret") {
        return false;
    }
    [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "routing_key",
        "credentials",
    ]
    .iter()
    .any(|w| k.contains(w))
}

/// Plugin `env` values are passed to the plugin as they are, so any whose
/// name suggests a credential is one.
fn secret_env_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "KEY",
        "AUTH",
        "CREDENTIAL",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// Whether the string at `key`, in a table named `parent`, is a
/// credential. Tables named `*_env` (`secret_env`, `pass_env`) hold names.
fn credential(key: &str, parent: &str) -> bool {
    if parent == "env" {
        secret_env_name(key)
    } else {
        !parent.ends_with("_env") && secret_key(key)
    }
}

/// Webhook services whose addresses carry their credential in the path.
const PATH_TOKEN_HOSTS: &[&str] = &[
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "webhook.office.com",
    "api.telegram.org",
];

/// Query parameters that carry credentials in webhook and API addresses.
fn secret_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "sig",
        "signature",
        "password",
        "pass",
        "auth",
        "code",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// The credentials inside one string value: a URL's password and any
/// credential query parameters.
fn url_secrets(value: &str, out: &mut Vec<String>) {
    let mut from = 0;
    while let Some(i) = value[from..].find("://") {
        let start = from + i + 3;
        let rest = &value[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        let url = &rest[..end];
        let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let authority = &url[..authority_end];
        if let Some(at) = authority.rfind('@')
            && let Some(colon) = authority[..at].find(':')
        {
            out.push(authority[colon + 1..at].to_string());
        }
        let host = authority.rsplit('@').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
        if PATH_TOKEN_HOSTS
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")))
        {
            let path = url[authority_end..].split(['?', '#']).next().unwrap_or("");
            if path.len() > 1 {
                out.push(path[1..].to_string());
            }
        }
        if let Some(q) = url.find('?') {
            let query = url[q + 1..].split('#').next().unwrap_or("");
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=')
                    && secret_param(k)
                {
                    out.push(v.to_string());
                }
            }
        }
        from = start;
    }
}

fn collect(value: &toml::Value, key: &str, parent: &str, out: &mut Vec<String>) {
    match value {
        toml::Value::String(s) => {
            if credential(key, parent) {
                out.push(s.clone());
            }
            url_secrets(s, out);
        }
        toml::Value::Array(items) => {
            for item in items {
                collect(item, key, parent, out);
            }
        }
        toml::Value::Table(t) => {
            for (k, v) in t {
                collect(v, k, key, out);
            }
        }
        _ => {}
    }
}

/// The config text with every password, token and secret replaced by
/// `***`: values of credential keys, plugin `env` values with credential
/// names, URL passwords (any scheme, as the dashboard does for database
/// URLs) and credential query parameters. Each value is removed wherever
/// it appears, comments included. Text that is not TOML is masked as far
/// as its URLs go.
pub fn mask(text: &str) -> String {
    let mut secrets = Vec::new();
    match text.parse::<toml::Table>() {
        Ok(table) => {
            for (k, v) in &table {
                collect(v, k, "", &mut secrets);
            }
        }
        Err(_) => url_secrets(text, &mut secrets),
    }
    secrets.retain(|s| !s.is_empty() && s != MASK);
    // Longest first, so a secret that contains another is replaced whole.
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets.dedup();
    let mut out = text.to_string();
    for s in &secrets {
        // Short values could match ordinary words; replace them only as
        // whole quoted strings or as a URL's password.
        if s.chars().count() >= 4 {
            out = out.replace(s.as_str(), MASK);
        } else {
            for (a, b) in [
                ("\"", "\""),
                ("'", "'"),
                (":", "@"),
                ("=", "&"),
                ("=", "\""),
            ] {
                out = out.replace(&format!("{a}{s}{b}"), &format!("{a}{MASK}{b}"));
            }
        }
    }
    // A value TOML wrote with escapes does not appear as parsed. If any
    // secret survives in the parsed form, keep the structure without the
    // file's own formatting rather than keep the secret.
    if let Ok(mut table) = out.parse::<toml::Table>() {
        let mut left = Vec::new();
        for (k, v) in &table {
            collect(v, k, "", &mut left);
        }
        if left.iter().any(|s| !s.is_empty() && !s.contains(MASK)) {
            for (k, v) in table.iter_mut() {
                scrub(v, k, "");
            }
            return toml::to_string(&table).unwrap_or_default();
        }
    }
    out
}

/// Replace credential values in place (the fallback above).
fn scrub(value: &mut toml::Value, key: &str, parent: &str) {
    match value {
        toml::Value::String(s) => {
            if credential(key, parent) {
                *s = MASK.to_string();
                return;
            }
            let mut found = Vec::new();
            url_secrets(s, &mut found);
            for f in found.iter().filter(|f| !f.is_empty()) {
                *s = s.replace(f.as_str(), MASK);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                scrub(item, key, parent);
            }
        }
        toml::Value::Table(t) => {
            for (k, v) in t.iter_mut() {
                scrub(v, k, key);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
# The gateway login.
[database]
url = "postgres://ariodb_gw:gw-pw-not-real@db:5432/app"
secret = "database-url"

[mysql]
listen = "127.0.0.1:3307"
password_env = "MYSQL_PASSWORD"

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders"]
token_secret = "coding-agent-token"
credential = "pg-readonly"

[[approvers]]
name = "pager"
type = "webhook"
url = "https://hooks.example.test/in?team=ops&token=hook-token-not-real"
hmac_secret_env = "HOOK_KEY"

[[approvers]]
name = "slack-hook"
type = "webhook"
url = "https://hooks.slack.com/services/T0/B0/slack-path-not-real"

[[plugins]]
name = "sink"
command = ["sink"]
env = { LOG_LEVEL = "debug", SINK_TOKEN = "sink-token-not-real", "API_KEY" = 'k-not-real' }
secret_env = { OTHER_TOKEN = "other-secret-name" }

[clickhouse]
http_url = "http://default:ch-pw-not-real@127.0.0.1:8123"
password = "inline-pw-not-real" # was inline-pw-not-real before
"#;

    #[test]
    fn masks_every_credential_and_keeps_the_rest() {
        let masked = mask(CONFIG);
        for secret in [
            "gw-pw-not-real",
            "hook-token-not-real",
            "sink-token-not-real",
            "k-not-real",
            "ch-pw-not-real",
            "inline-pw-not-real",
            "slack-path-not-real",
        ] {
            assert!(!masked.contains(secret), "{secret} leaked:\n{masked}");
        }
        // Names of secrets and variables, and ordinary settings, stay.
        for kept in [
            "postgres://ariodb_gw:***@db:5432/app",
            "secret = \"database-url\"",
            "password_env = \"MYSQL_PASSWORD\"",
            "token_secret = \"coding-agent-token\"",
            "credential = \"pg-readonly\"",
            "team=ops&token=***",
            "LOG_LEVEL = \"debug\"",
            "OTHER_TOKEN = \"other-secret-name\"",
            "# The gateway login.",
            "hmac_secret_env = \"HOOK_KEY\"",
        ] {
            assert!(masked.contains(kept), "{kept} missing:\n{masked}");
        }
        // Masking twice changes nothing more.
        assert_eq!(mask(&masked), masked);
    }

    #[test]
    fn escaped_secrets_fall_back_to_rewritten_toml() {
        // TOML reads A as A, so the parsed secret is not in the text.
        let text = "[database]\nurl = \"postgres://u:p\\u0041ss-not-real@db/app\"\n";
        let masked = mask(text);
        assert!(!masked.contains("pAss-not-real") && !masked.contains("\\u0041ss"));
        assert!(masked.contains("postgres://u:***@db/app"), "{masked}");
    }

    #[test]
    fn versions_are_recorded_once_chained_and_pruned_with_a_baseline() {
        let dir = std::env::temp_dir().join(format!("ariodb-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ariodb.toml");
        std::fs::write(&file, CONFIG).unwrap();
        record_config(&dir, &file, "startup");
        record_config(&dir, &file, "reload");
        std::fs::write(&file, format!("{CONFIG}\n[audit]\nretention_days = 7\n")).unwrap();
        record_config(&dir, &file, "dashboard:root");
        let conn = Connection::open(dir.join("ariodb.db")).unwrap();
        let versions = config_versions(&conn, i64::MAX).unwrap();
        assert_eq!(versions.len(), 2, "an unchanged file is recorded once");
        assert_eq!(versions[1].source, "dashboard:root");
        assert!(versions.iter().all(|v| v.intact));
        assert!(versions.iter().all(|v| !v.text.contains("gw-pw-not-real")));

        // Editing the stored text, or removing a row, shows.
        conn.execute(
            "UPDATE config_versions SET text = replace(text, 'orders', 'everything') WHERE id = 1",
            [],
        )
        .unwrap();
        assert!(!config_versions(&conn, i64::MAX).unwrap()[0].intact);

        record_undo(&dir, "s-1", "postgres", 3, "cli:pat");
        record_undo(&dir, "s-2", "mysql", 1, "dashboard:root");
        record_undo(&dir, "s-3", "postgres", 2, "cli:pat");
        let all = undo_records(&conn, 0, i64::MAX).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|u| u.intact));
        // Removing one from the middle breaks the next one's link; removing
        // the oldest looks like pruning, as for the decisions log.
        conn.execute("DELETE FROM undo_records WHERE session = 's-2'", [])
            .unwrap();
        let undos = undo_records(&conn, 0, i64::MAX).unwrap();
        assert!(undos[0].intact && !undos[1].intact);
        conn.execute(
            "UPDATE undo_records SET by = 'cli:mallory' WHERE session = 's-1'",
            [],
        )
        .unwrap();
        assert!(!undo_records(&conn, 0, i64::MAX).unwrap()[0].intact);

        // Pruning keeps the version in force at the cut-off.
        conn.execute(
            "UPDATE config_versions SET at_ms = at_ms - 400 * 86400000",
            [],
        )
        .unwrap();
        let settings = crate::audit::Settings {
            retention_days: 30,
            ..Default::default()
        };
        prune(&dir, &settings).unwrap();
        let left = config_versions(&conn, i64::MAX).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].source, "dashboard:root");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
