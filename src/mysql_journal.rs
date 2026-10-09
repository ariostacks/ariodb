//! The MySQL change journal: agents' committed changes read from the binlog,
//! tied to their sessions through `[mysql] tag_table`, and written to
//! `<journal dir>/mysql-journal.jsonl` in the same record format as the
//! Postgres journal.

use crate::config::Config;
use crate::journal::TxnRecord;

/// Prepare the server: check binlog settings, create the tag table, and say
/// what is missing. Safe to run again.
pub async fn setup(_config: &Config) -> Result<(), String> {
    Err("the MySQL journal is not built yet".to_string())
}

/// Read the binlog forever, appending agents' transactions to the journal.
pub async fn run(_config: &Config) -> Result<(), String> {
    Err("the MySQL journal is not built yet".to_string())
}

/// Every recorded MySQL transaction, oldest first.
pub fn read_all(_config: &Config) -> Result<Vec<TxnRecord>, String> {
    Ok(Vec::new())
}

/// `ariodb doctor` for MySQL: the findings, and whether undo works.
pub async fn doctor(_config: &Config) -> crate::doctor::Section {
    crate::doctor::Section {
        title: "mysql".to_string(),
        findings: vec![],
    }
}
