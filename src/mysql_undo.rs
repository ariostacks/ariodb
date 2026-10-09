//! Undoing one agent session's MySQL changes, with the same rules as the
//! Postgres undo: newest first, and a row someone else changed since is a
//! conflict, never silently overwritten.

use crate::config::Config;
use crate::journal::TxnRecord;

/// Show the plan for undoing `session`, and with `apply`, carry it out.
/// Returns the text to print.
pub async fn undo(
    _config: &Config,
    _records: &[TxnRecord],
    _session: &str,
    _apply: bool,
    _skip_conflicts: bool,
) -> Result<String, String> {
    Err("MySQL undo is not built yet".to_string())
}
