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
        Kind::Session if stmt.engine == "mysql" => match mysql_session(stmt) {
            Ok(()) => Mode::ReadOnly,
            Err(reason) => return Decision::Deny(reason),
        },
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

/// MySQL and MariaDB functions refused for every agent: they read server
/// files or run shell commands (`load_file` and the lib_mysqludf_sys UDFs),
/// hold or test named locks that outlive the statement and reach other
/// sessions on the shared login (`get_lock` and friends), or wait on
/// replication. Functions in the server's own schemas (`sys.*`, `mysql.*`,
/// `performance_schema.*`) read what the catalogue rule keeps from agents.
const MYSQL_BLOCKED_FUNCTIONS: &[&str] = &[
    "load_file",
    "sys_exec",
    "sys_eval",
    "sys_get",
    "sys_set",
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
    "master_pos_wait",
    "source_pos_wait",
    "wait_for_executed_gtid_set",
    "wait_until_sql_thread_after_gtids",
    // MariaDB's replication wait.
    "master_gtid_wait",
];

const MYSQL_BLOCKED_PREFIXES: &[&str] = &["lib_mysqludf_"];

const MYSQL_SERVER_SCHEMAS: &[&str] = &["sys", "mysql", "performance_schema"];

fn blocked_function(stmt: &Statement) -> Option<&str> {
    let mut functions = stmt.functions.iter().map(String::as_str);
    match stmt.engine {
        "postgres" => functions.find(|f| {
            // `pg_catalog.set_config` is the same function.
            let name = f.rsplit('.').next().unwrap_or(f);
            BLOCKED_FUNCTIONS.contains(&name)
                || BLOCKED_PREFIXES.iter().any(|p| name.starts_with(p))
                || name.contains("replication_slot")
        }),
        "mysql" => functions.find(|f| {
            let (schema, name) = f.rsplit_once('.').unwrap_or(("", f));
            MYSQL_BLOCKED_FUNCTIONS.contains(&name)
                || MYSQL_BLOCKED_PREFIXES.iter().any(|p| name.starts_with(p))
                || MYSQL_SERVER_SCHEMAS.contains(&schema)
        }),
        _ => None,
    }
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

/// MySQL session variables agents may set: the ones drivers send when they
/// connect, which change formatting, character sets and timeouts, not what
/// data is reachable or how ariodb's checks work. `autocommit` is only ever
/// `1` here (setting it to 0 is transaction control) and is a no-op under
/// ariodb. `sql_mode` reaches here only with modes that leave quoting and
/// escapes as ariodb reads them. User variables (`@name`) are the agent's
/// own. Refused, among others: `sql_log_bin`, `foreign_key_checks` and
/// `unique_checks` (they would hide or allow changes), `max_execution_time`
/// and `max_statement_time` (ariodb's timeout), `transaction_read_only` and
/// `tx_read_only` (ariodb's read-only transactions), `sql_safe_updates`, and
/// anything GLOBAL or PERSIST.
const MYSQL_SAFE_SETTINGS: &[&str] = &[
    "names",
    "character set",
    "character_set_client",
    "character_set_connection",
    "character_set_results",
    "collation_connection",
    "time_zone",
    "autocommit",
    "transaction_isolation",
    "tx_isolation",
    "sql_select_limit",
    "net_read_timeout",
    "net_write_timeout",
    "wait_timeout",
    "interactive_timeout",
    "group_concat_max_len",
    "lc_time_names",
    "sql_mode",
];

/// A MySQL session statement: SET of safe settings only. KILL and USE are
/// refused here; the MySQL proxy deliberately intercepts both before the
/// policy (KILL of the agent's own query becomes a cancel, and USE of the
/// configured database is answered without reaching the server), because
/// connection ids and the current database are the proxy's to manage.
fn mysql_session(stmt: &Statement) -> Result<(), String> {
    match stmt.command {
        "KILL" => {
            return Err(
                "agents may not KILL connections or queries; cancel the agent's own query from its client"
                    .to_string(),
            );
        }
        "USE" => {
            return Err(
                "agents stay in the database ariodb is configured for; name other databases' tables in full"
                    .to_string(),
            );
        }
        _ => {}
    }
    let Some(names) = stmt.setting.as_deref() else {
        return Err("session settings are not allowed for agents".to_string());
    };
    for name in names.split(", ") {
        let user_variable = name.starts_with('@') && !name.starts_with("@@");
        if !user_variable && !MYSQL_SAFE_SETTINGS.contains(&name) {
            return Err(format!("agents may not change the '{name}' setting"));
        }
        // READ UNCOMMITTED would let an agent read another agent's write
        // before ariodb has judged it, and perhaps rolled it back.
        if name == "transaction_isolation"
            && stmt.sql.to_uppercase().replace(['-', '_'], " ").contains("UNCOMMITTED")
        {
            return Err("agents may not read uncommitted data (READ UNCOMMITTED)".to_string());
        }
    }
    Ok(())
}

/// MySQL's `information_schema` views about structure. Runtime views
/// (`processlist`, `innodb_trx`, `user_privileges`, ...) describe other
/// sessions and the server, and `mysql`, `performance_schema` and `sys`
/// never count as catalogue.
const MYSQL_CATALOGUE: &[&str] = &[
    "tables",
    "columns",
    "schemata",
    "statistics",
    "key_column_usage",
    "table_constraints",
    "referential_constraints",
    "views",
    "routines",
    "character_sets",
    "collations",
    "engines",
    "columns_extensions",
];

/// The engine's own catalogue. Agents may read it to discover the schema.
/// On Postgres, unqualified `pg_*` names resolve to the catalogue first,
/// because Postgres always searches `pg_catalog` before other schemas.
fn is_catalog(engine: &str, table: &str) -> bool {
    if engine == "mysql" {
        return table
            .strip_prefix("information_schema.")
            .is_some_and(|view| MYSQL_CATALOGUE.contains(&view));
    }
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

    fn decide_mysql(access: Access, sql: &str) -> Decision {
        let mut stmts = crate::mysql_sql::classify(sql).unwrap();
        crate::mysql_sql::scope_to_database(&mut stmts, "app");
        assert_eq!(stmts.len(), 1, "{sql}");
        decide(&agent(access), &stmts[0])
    }

    fn denied(d: Decision) -> bool {
        matches!(d, Decision::Deny(_))
    }

    #[test]
    fn mysql_reads_writes_and_tables() {
        assert_eq!(
            decide_mysql(Access::ReadOnly, "SELECT * FROM app.orders"),
            Decision::Allow(Mode::ReadOnly)
        );
        assert_eq!(
            decide_mysql(Access::ReadWrite, "UPDATE orders SET a = 1 WHERE id = 1"),
            Decision::Allow(Mode::CheckedWrite)
        );
        assert_eq!(
            decide_mysql(Access::ReadWrite, "SELECT * FROM orders FOR UPDATE"),
            Decision::Allow(Mode::CheckedWrite)
        );
        for sql in [
            "UPDATE orders SET a = 1 WHERE id = 1",
            "SELECT * FROM other.orders",
            "SELECT * FROM orders JOIN secrets USING (id)",
            "DELETE FROM orders",
            "DROP TABLE orders",
            "START TRANSACTION",
            "LOCK TABLES orders READ",
            "CALL p()",
            "SELECT 1 /*!, 2 */",
            "SET @x = (SELECT note FROM secrets LIMIT 1)",
        ] {
            assert!(denied(decide_mysql(Access::ReadOnly, sql)), "{sql}");
        }
        // A MariaDB sequence is a table; SETVAL's change survives a rollback.
        for sql in [
            "UPDATE orders SET a = NEXTVAL(secret_seq) WHERE id = 1",
            "SELECT SETVAL(secret_seq, 1) FROM orders WHERE id = 1 FOR UPDATE",
            "UPDATE IGNORE secrets SET a = 1 WHERE id = 1",
        ] {
            assert!(denied(decide_mysql(Access::ReadWrite, sql)), "{sql}");
        }
    }

    #[test]
    fn mysql_functions_that_get_round_the_checks_are_refused() {
        for sql in [
            "SELECT LOAD_FILE('/etc/passwd')",
            "SELECT sys_exec('id')",
            "SELECT lib_mysqludf_sys_info()",
            "SELECT GET_LOCK('ariodb', 10)",
            "SELECT release_all_locks()",
            "SELECT is_used_lock('x')",
            "SELECT source_pos_wait('binlog.000001', 4)",
            "SELECT wait_for_executed_gtid_set('x')",
            "SELECT master_gtid_wait('0-1-1', 10)",
            "SELECT sys.ps_thread_id(1)",
            "UPDATE orders SET a = release_lock('x') WHERE id = 1",
            "SET @x = get_lock('x', 1)",
        ] {
            assert!(
                matches!(decide_mysql(Access::ReadWrite, sql), Decision::Deny(r) if r.contains("never allowed")),
                "{sql}"
            );
        }
        assert_eq!(
            decide_mysql(Access::ReadOnly, "SELECT lower(status), now() FROM orders"),
            Decision::Allow(Mode::ReadOnly)
        );
    }

    #[test]
    fn mysql_catalogue_is_structure_only() {
        for sql in [
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'app'",
            "SELECT * FROM INFORMATION_SCHEMA.COLUMNS",
            "SELECT * FROM information_schema.key_column_usage",
            "SELECT * FROM information_schema.statistics",
        ] {
            assert_eq!(
                decide_mysql(Access::ReadOnly, sql),
                Decision::Allow(Mode::ReadOnly),
                "{sql}"
            );
        }
        for sql in [
            "SELECT * FROM information_schema.processlist",
            "SELECT * FROM information_schema.innodb_trx",
            "SELECT * FROM information_schema.user_privileges",
            "SELECT * FROM mysql.user",
            "SELECT * FROM performance_schema.events_statements_history",
            "SELECT * FROM sys.session",
            "UPDATE information_schema.tables SET table_name = 'x' WHERE 1 = 1",
        ] {
            assert!(denied(decide_mysql(Access::ReadWrite, sql)), "{sql}");
        }
    }

    #[test]
    fn mysql_show() {
        for sql in [
            "SHOW TABLES",
            "SHOW FULL COLUMNS FROM orders",
            "SHOW INDEX FROM app.orders",
            "SHOW CREATE TABLE orders",
            "SHOW DATABASES",
            "SHOW VARIABLES LIKE 'version'",
            "SHOW SESSION STATUS",
            "SHOW WARNINGS",
            "SHOW COLLATION",
            "SHOW CHARACTER SET",
            "SHOW ENGINES",
        ] {
            assert_eq!(
                decide_mysql(Access::ReadOnly, sql),
                Decision::Allow(Mode::ReadOnly),
                "{sql}"
            );
        }
        for sql in [
            "SHOW CREATE TABLE secrets",
            "SHOW COLUMNS FROM secrets",
            "SHOW PROCESSLIST",
            "SHOW GRANTS",
            "SHOW BINARY LOGS",
            "SHOW REPLICA STATUS",
            "SHOW CREATE USER root",
            "SHOW TABLES WHERE (SELECT note FROM secrets LIMIT 1) = 'x'",
        ] {
            assert!(denied(decide_mysql(Access::ReadWrite, sql)), "{sql}");
        }
    }

    #[test]
    fn mysql_settings() {
        for sql in [
            "SET NAMES utf8mb4",
            "SET CHARACTER SET utf8mb4",
            "SET character_set_results = NULL",
            "SET collation_connection = utf8mb4_bin",
            "SET time_zone = '+00:00'",
            "SET autocommit = 1",
            "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET @@session.transaction_isolation = 'READ-COMMITTED'",
            "SET @x = 1",
            "SET sql_select_limit = 100",
            "SET net_read_timeout = 60, net_write_timeout = 60",
            "SET wait_timeout = 60, interactive_timeout = 60",
            "SET group_concat_max_len = 100000",
            "SET lc_time_names = 'en_GB'",
            "SET sql_mode = 'STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY'",
            "SET @x = (SELECT max(id) FROM orders)",
        ] {
            assert_eq!(
                decide_mysql(Access::ReadOnly, sql),
                Decision::Allow(Mode::ReadOnly),
                "{sql}"
            );
        }
        for sql in [
            "SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED",
            "SET @@session.transaction_isolation = 'READ-UNCOMMITTED'",
            "SET GLOBAL wait_timeout = 1",
            "SET @@global.time_zone = '+00:00'",
            "SET PERSIST wait_timeout = 1",
            "SET PERSIST_ONLY wait_timeout = 1",
            "SET NAMES utf8mb4, GLOBAL wait_timeout = 1",
            "SET PASSWORD = 'local-test-only-pw'",
            "SET ROLE ALL",
            "SET DEFAULT ROLE ALL TO u",
            "SET sql_log_bin = 0",
            "SET foreign_key_checks = 0",
            "SET unique_checks = 0",
            "SET max_execution_time = 0",
            "SET max_statement_time = 0",
            "SET transaction_read_only = 0",
            "SET tx_read_only = 0",
            "SET SESSION TRANSACTION READ WRITE",
            "SET sql_safe_updates = 0",
            "SET autocommit = 0",
            "SET sql_mode = 'ANSI_QUOTES'",
            "SET sql_mode = 'NO_BACKSLASH_ESCAPES'",
            "SET @@session.sql_mode = 'ANSI'",
            "SET optimizer_switch = 'x=on'",
            "KILL 12",
            "KILL QUERY 12",
            "USE app",
        ] {
            assert!(denied(decide_mysql(Access::ReadWrite, sql)), "{sql}");
        }
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
