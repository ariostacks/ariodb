//! An append-only audit log. Each line carries the hash of the line before
//! it, so editing or deleting a past entry breaks the chain and shows.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub latency_ms: Option<u64>,
}

pub struct AuditLog {
    path: PathBuf,
    /// Hash of the last line written. The mutex also serialises writers.
    last_hash: Mutex<String>,
}

impl AuditLog {
    pub fn open(dir: &Path) -> std::io::Result<AuditLog> {
        fs::create_dir_all(dir)?;
        let path = dir.join("audit.jsonl");
        let last_hash = last_hash_in(&path)?;
        Ok(AuditLog {
            path,
            last_hash: Mutex::new(last_hash),
        })
    }

    pub fn record(&self, entry: &Entry) {
        let mut last = self.last_hash.lock().expect("audit lock poisoned");
        let body = serde_json::to_value(entry).expect("audit entry serialises");
        let line = serde_json::json!({
            "at_ms": now_ms(),
            "prev": *last,
            "entry": body,
        })
        .to_string();
        let hash = hex::encode(Sha256::digest(line.as_bytes()));
        let full = format!("{{\"hash\":\"{hash}\",\"line\":{line}}}\n");

        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(full.as_bytes()).and_then(|_| f.sync_data()));
        match result {
            Ok(()) => *last = hash,
            Err(err) => eprintln!("ariodb: could not write audit log: {err}"),
        }
    }
}

/// Check every link in the chain. Returns the number of entries, or the
/// line number where the chain breaks.
pub fn verify(dir: &Path) -> Result<usize, String> {
    let path = dir.join("audit.jsonl");
    let file = File::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut prev = String::new();
    let mut count = 0;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| format!("line {} is not JSON", i + 1))?;
        let inner = value["line"].to_string();
        let hash = hex::encode(Sha256::digest(inner.as_bytes()));
        if value["hash"] != hash.as_str() || value["line"]["prev"] != prev.as_str() {
            return Err(format!("chain broken at line {}", i + 1));
        }
        prev = hash;
        count += 1;
    }
    Ok(count)
}

fn last_hash_in(path: &Path) -> std::io::Result<String> {
    let Ok(file) = File::open(path) else {
        return Ok(String::new());
    };
    let mut last = String::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
            && let Some(h) = v["hash"].as_str()
        {
            last = h.to_string();
        }
    }
    Ok(last)
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ariodb-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

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
            latency_ms: None,
        }
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = temp_dir("audit");
        let tables = vec!["orders".to_string()];
        let log = AuditLog::open(&dir).unwrap();
        log.record(&entry("SELECT 1", &tables));
        log.record(&entry("SELECT 2", &tables));
        // Reopening continues the same chain.
        let log = AuditLog::open(&dir).unwrap();
        log.record(&entry("SELECT 3", &tables));
        assert_eq!(verify(&dir), Ok(3));

        let path = dir.join("audit.jsonl");
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("SELECT 2", "SELECT 9");
        fs::write(&path, text).unwrap();
        assert_eq!(verify(&dir), Err("chain broken at line 2".to_string()));
    }
}
