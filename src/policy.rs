//! Deciding whether an agent may run a statement, before it runs.
//!
//! Default deny: a statement is allowed only if a rule below says so. The
//! effect check after a write runs lives in `exec.rs`.

use crate::classify::{Kind, Statement};
use crate::config::{Access, Agent};

/// How an allowed statement must run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Inside a READ ONLY transaction, so Postgres itself blocks any hidden write.
    ReadOnly,
    /// Inside a transaction that is checked for its effect before commit.
    CheckedWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Mode),
    Deny(String),
}

pub fn decide(agent: &Agent, stmt: &Statement) -> Decision {
    let mode = match stmt.kind {
        Kind::Read => Mode::ReadOnly,
        Kind::Write => match agent.access {
            Access::ReadWrite => Mode::CheckedWrite,
            Access::ReadOnly => {
                return Decision::Deny(format!("agent '{}' is read only", agent.name));
            }
        },
        Kind::Destructive => {
            return Decision::Deny(format!(
                "destructive statements are never allowed for agents: {}",
                stmt.reason
            ));
        }
        Kind::SchemaChange => {
            return Decision::Deny(
                "schema changes are not allowed for agents; make them on a branch and review"
                    .to_string(),
            );
        }
        Kind::Transaction => {
            return Decision::Deny(
                "ariodb runs every statement in its own transaction; send statements without BEGIN or COMMIT"
                    .to_string(),
            );
        }
        Kind::Session => match stmt.setting.as_deref() {
            // Settings drivers send when they connect. They change formatting,
            // not what data is reachable.
            Some(name) if SAFE_SETTINGS.contains(&name) => Mode::ReadOnly,
            Some(name) => {
                return Decision::Deny(format!("agents may not change the '{name}' setting"));
            }
            None => {
                return Decision::Deny("session settings are not allowed for agents".to_string());
            }
        },
        Kind::Unknown => {
            return Decision::Deny(format!(
                "ariodb cannot check this statement: {}",
                stmt.reason
            ));
        }
    };

    if let Some(f) = blocked_function(stmt) {
        return Decision::Deny(format!(
            "the function '{f}' is never allowed for agents: it would get round ariodb's checks"
        ));
    }

    if stmt.copy_in {
        return Decision::Deny(
            "COPY ... FROM STDIN is not supported through ariodb; use INSERT".to_string(),
        );
    }

    let blocked = stmt.tables.iter().find(|t| {
        !agent.allows_table(t) && !(mode == Mode::ReadOnly && is_catalog(stmt.engine, t))
    });
    if let Some(table) = blocked {
        return Decision::Deny(format!(
            "agent '{}' may not use table '{}'",
            agent.name, table
        ));
    }

    Decision::Allow(mode)
}

/// Postgres functions refused for every agent, whatever the rules say,
/// because they defeat ariodb's own checks rather than merely reach data:
/// they run SQL ariodb never sees (dblink, the `*_to_xml` family, `ts_stat`),
/// change session state that outlives the statement (`set_config`, which
/// would undo the refusal of `SET search_path`), write where the effect
/// check cannot measure (large objects), forge entries in the change journal
/// (`pg_logical_emit_message`), or reach other sessions on the shared gateway
/// login. Server file access (`pg_read_file` and so on) is a privilege
/// question: refuse it with database grants and, if wanted, a rule.
const BLOCKED_FUNCTIONS: &[&str] = &[
    "set_config",
    "ts_stat",
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "pg_logical_emit_message",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "loread",
    "lowrite",
];

/// Whole families, by name prefix.
const BLOCKED_PREFIXES: &[&str] = &["dblink", "lo_", "pg_logical_slot_", "pg_replication_"];

fn blocked_function(stmt: &Statement) -> Option<&str> {
    if stmt.engine != "postgres" {
        return None;
    }
    stmt.functions.iter().map(String::as_str).find(|f| {
        // `pg_catalog.set_config` is the same function.
        let name = f.rsplit('.').next().unwrap_or(f);
        BLOCKED_FUNCTIONS.contains(&name)
            || BLOCKED_PREFIXES.iter().any(|p| name.starts_with(p))
            || name.contains("replication_slot")
    })
}

/// Settings that only change how results are formatted or reported.
/// `search_path` is deliberately absent: it changes which table a name means.
const SAFE_SETTINGS: &[&str] = &[
    "application_name",
    "extra_float_digits",
    "client_encoding",
    "datestyle",
    "timezone",
    "intervalstyle",
    "bytea_output",
    "client_min_messages",
    "lock_timeout",
    "statement_timeout",
    "standard_conforming_strings",
];

/// Postgres's own catalogue. Agents may read it to discover the schema.
/// Unqualified `pg_*` names resolve to the catalogue first, because Postgres
/// always searches `pg_catalog` before other schemas.
fn is_catalog(engine: &str, table: &str) -> bool {
    if engine == "clickhouse" {
        // Schema discovery only; not query_log, users or other servers' data.
        return matches!(
            table,
            "system.tables" | "system.columns" | "system.databases" | "system.functions"
        ) || table.starts_with("information_schema.");
    }
    table.starts_with("pg_catalog.")
        || table.starts_with("information_schema.")
        || (table.starts_with("pg_") && !table.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify;

    fn agent(access: Access) -> Agent {
        Agent {
            name: "bot".into(),
            access,
            tables: vec!["orders".into()],
            token_env: Some("UNUSED".into()),
            token_secret: None,
            clickhouse: None,
            mysql: None,
            max_rows_per_write: None,
            credential: None,
        }
    }

    fn decide_sql(access: Access, sql: &str) -> Decision {
        let stmt = classify(sql).unwrap().remove(0);
        decide(&agent(access), &stmt)
    }

    #[test]
    fn reads_run_read_only() {
        assert_eq!(
            decide_sql(Access::ReadWrite, "SELECT * FROM orders"),
            Decision::Allow(Mode::ReadOnly)
        );
    }

    #[test]
    fn writes_need_write_access() {
        let sql = "UPDATE orders SET status = 'x' WHERE id = 1";
        assert_eq!(
            decide_sql(Access::ReadWrite, sql),
            Decision::Allow(Mode::CheckedWrite)
        );
        assert!(matches!(
            decide_sql(Access::ReadOnly, sql),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn other_tables_are_refused() {
        assert!(matches!(
            decide_sql(
                Access::ReadWrite,
                "SELECT * FROM orders JOIN secrets USING (id)"
            ),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn driver_settings_are_allowed() {
        assert_eq!(
            decide_sql(Access::ReadOnly, "SET extra_float_digits = 3"),
            Decision::Allow(Mode::ReadOnly)
        );
    }

    #[test]
    fn catalogue_is_readable_not_writable() {
        assert_eq!(
            decide_sql(Access::ReadOnly, "SELECT relname FROM pg_catalog.pg_class"),
            Decision::Allow(Mode::ReadOnly)
        );
        assert!(matches!(
            decide_sql(
                Access::ReadWrite,
                "UPDATE pg_catalog.pg_class SET relname = 'x' WHERE oid = 1"
            ),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn functions_that_get_round_the_checks_are_refused() {
        for sql in [
            "SELECT dblink_exec('dbname=app', 'DELETE FROM secrets')",
            "SELECT * FROM public.dblink('dbname=app', 'SELECT 1') AS t(x int)",
            "SELECT query_to_xml('SELECT * FROM secrets', true, false, '')",
            "SELECT table_to_xml('secrets', true, false, '')",
            "SELECT pg_catalog.set_config('search_path', 'private', false)",
            "SELECT pg_logical_emit_message(true, 'ariodb', '{}')",
            "SELECT lo_import('/etc/hosts')",
            "SELECT pg_drop_replication_slot('ariodb')",
            "SELECT * FROM orders WHERE id IN (SELECT pg_terminate_backend(1))",
            "UPDATE orders SET status = set_config('role', 'x', false) WHERE id = 1",
            "DECLARE c CURSOR WITH HOLD FOR SELECT dblink('a', 'b')",
        ] {
            assert!(
                matches!(decide_sql(Access::ReadWrite, sql), Decision::Deny(r) if r.contains("never allowed")),
                "{sql}"
            );
        }
        // Ordinary functions are fine.
        assert_eq!(
            decide_sql(Access::ReadOnly, "SELECT lower(status), now() FROM orders"),
            Decision::Allow(Mode::ReadOnly)
        );
    }

    #[test]
    fn dangerous_kinds_are_refused() {
        for sql in [
            "SET search_path = private",
            "COPY orders FROM STDIN",
            "DELETE FROM orders",
            "DROP TABLE orders",
            "BEGIN",
            "DO $$ BEGIN END $$",
        ] {
            assert!(
                matches!(decide_sql(Access::ReadWrite, sql), Decision::Deny(_)),
                "{sql}"
            );
        }
    }
}
