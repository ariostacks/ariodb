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

    if let Some(table) = stmt.tables.iter().find(|t| never_allowed(stmt.engine, t)) {
        return Decision::Deny(format!(
            "agents may not use '{table}', whatever their tables say: it shows other sessions' statements or data, or belongs to the server or to ariodb"
        ));
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
/// Whether a statement sets the isolation level to exactly one of the
/// levels that never show uncommitted data.
fn safe_isolation(sql: &str) -> bool {
    let sql = sql.trim().trim_end_matches(';').trim();
    let upper = sql.to_uppercase();
    let value = match (upper.find('='), upper.rfind(" LEVEL ")) {
        (Some(i), _) if upper.matches('=').count() == 1 => &sql[i + 1..],
        (None, Some(i)) => &sql[i + " LEVEL ".len()..],
        _ => return false,
    };
    let value = value.trim();
    let unquoted = match value.as_bytes() {
        [q @ (b'\'' | b'"'), .., last] if q == last && value.len() >= 2 => &value[1..value.len() - 1],
        _ => value,
    };
    let level = unquoted.to_uppercase().replace(['-', '_'], " ");
    let level = level.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(level.as_str(), "READ COMMITTED" | "REPEATABLE READ" | "SERIALIZABLE")
}

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
        // before ariodb has judged it, and perhaps rolled it back. It can be
        // asked for in many spellings (0, CONCAT(...), tx_isolation), so
        // only a plain safe level is accepted, set on its own.
        if (name == "transaction_isolation" || name == "tx_isolation")
            && !(names.split(", ").count() == 1 && safe_isolation(&stmt.sql))
        {
            return Err(
                "agents may only choose READ COMMITTED, REPEATABLE READ or SERIALIZABLE, one setting at a time"
                    .to_string(),
            );
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

/// Postgres catalogue relations that describe the schema, which read-only
/// agents may read to discover it. Left out on purpose: statistics views
/// (`pg_stats` holds sample values from every table the gateway can read),
/// activity and lock views (other sessions' statements), replication,
/// subscription, authentication and file views, and `pg_sequences`
/// (current sequence values).
const PG_CATALOGUE: &[&str] = &[
    "pg_aggregate", "pg_am", "pg_amop", "pg_amproc", "pg_attrdef", "pg_attribute",
    "pg_auth_members", "pg_available_extension_versions", "pg_available_extensions",
    "pg_cast", "pg_class", "pg_collation", "pg_constraint", "pg_conversion", "pg_cursors",
    "pg_database", "pg_default_acl", "pg_depend", "pg_description", "pg_enum",
    "pg_extension", "pg_index", "pg_indexes", "pg_inherits", "pg_language", "pg_matviews",
    "pg_namespace", "pg_opclass", "pg_operator", "pg_opfamily", "pg_partitioned_table",
    "pg_policies", "pg_policy", "pg_prepared_statements", "pg_proc", "pg_range",
    "pg_rewrite", "pg_roles", "pg_rules", "pg_sequence", "pg_settings", "pg_shdescription",
    "pg_statistic_ext", "pg_tables", "pg_tablespace", "pg_timezone_abbrevs",
    "pg_timezone_names", "pg_transform", "pg_trigger", "pg_ts_config", "pg_ts_config_map",
    "pg_ts_dict", "pg_ts_parser", "pg_ts_template", "pg_type", "pg_user", "pg_views",
];

/// System tables refused even to an agent with `tables = ["*"]`, which
/// means every user table, not the server's own: on Postgres the parts of
/// the catalogue outside `PG_CATALOGUE`, on ClickHouse `system.*` beyond
/// its catalogue, and on MySQL the server's schemas, the runtime views the
/// gateway's PROCESS privilege opens, and ariodb's own `ariodb` database
/// (where the journal's tag table lives by default).
fn never_allowed(engine: &str, table: &str) -> bool {
    match engine {
        "mysql" => {
            ["mysql.", "sys.", "performance_schema.", "ariodb."]
                .iter()
                .any(|s| table.starts_with(s))
                || table == "information_schema.processlist"
                || table.starts_with("information_schema.innodb_")
        }
        "clickhouse" => table.starts_with("system.") && !is_catalog(engine, table),
        _ => {
            let catalogue_name = table.starts_with("pg_catalog.")
                || (table.starts_with("pg_") && !table.contains('.'));
            catalogue_name && !is_catalog(engine, table)
        }
    }
}

/// The engine's own catalogue. Agents may read the parts that describe the
/// schema. On Postgres, unqualified catalogue names resolve to `pg_catalog`
/// first, because Postgres searches it before other schemas.
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
    if table.starts_with("information_schema.") {
        return true;
    }
    let name = table.strip_prefix("pg_catalog.").unwrap_or(table);
    !name.contains('.') && PG_CATALOGUE.contains(&name)
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
            literal_names: false,
            max_rows_per_write: None,
            credential: None,
        }
    }

    fn decide_sql(access: Access, sql: &str) -> Decision {
        let stmt = classify(sql).unwrap().remove(0);
        decide(&agent(access), &stmt)
    }

    #[test]
    fn the_statement_timeout_cannot_be_lifted() {
        assert!(matches!(
            decide_sql(Access::ReadWrite, "SET statement_timeout = 0"),
            Decision::Deny(_)
        ));
        assert_eq!(
            decide_sql(Access::ReadOnly, "SET lock_timeout = '1s'"),
            Decision::Allow(Mode::ReadOnly)
        );
    }

    #[test]
    fn only_schema_parts_of_the_catalogue_are_readable() {
        for sql in [
            "SELECT relname FROM pg_class",
            "SELECT * FROM pg_catalog.pg_attribute",
            "SELECT * FROM information_schema.columns",
            "SELECT typname FROM pg_type",
        ] {
            assert_eq!(decide_sql(Access::ReadOnly, sql), Decision::Allow(Mode::ReadOnly), "{sql}");
        }
        for sql in [
            "SELECT * FROM pg_stats",
            "SELECT query FROM pg_stat_activity",
            "SELECT * FROM pg_catalog.pg_stat_activity",
            "SELECT * FROM pg_statistic",
            "SELECT * FROM pg_locks",
            "SELECT * FROM pg_subscription",
            "SELECT last_value FROM pg_sequences",
            // A user table that only looks like the catalogue.
            "SELECT * FROM pg_secret_notes",
            "SELECT * FROM public.pg_class",
        ] {
            assert!(matches!(decide_sql(Access::ReadOnly, sql), Decision::Deny(_)), "{sql}");
        }
    }

    #[test]
    fn rules_see_catalogue_functions_without_their_schema() {
        let stmt = classify("SELECT pg_catalog.pg_read_file('/etc/passwd')").unwrap().remove(0);
        assert_eq!(stmt.functions, vec!["pg_read_file".to_string()]);
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
    fn a_wildcard_agent_still_cannot_reach_system_tables() {
        let mut wide = agent(Access::ReadWrite);
        wide.tables = vec!["*".into()];
        let pg = |sql: &str| decide(&wide, &classify(sql).unwrap().remove(0));
        assert!(denied(pg("SELECT query FROM pg_stat_activity")), "pg_stat_activity");
        assert!(denied(pg("SELECT * FROM pg_catalog.pg_stats")), "pg_stats");
        assert_eq!(pg("SELECT * FROM anything_at_all"), Decision::Allow(Mode::ReadOnly));
        let my = |sql: &str| {
            let mut stmts = crate::mysql_sql::classify(sql).unwrap();
            crate::mysql_sql::scope_to_database(&mut stmts, "app");
            decide(&wide, &stmts[0])
        };
        for sql in [
            "SELECT * FROM mysql.user",
            "SELECT * FROM performance_schema.threads",
            "SELECT info FROM information_schema.processlist",
            "INSERT INTO ariodb.session_tags (session, agent) VALUES ('s-forged', 'x')",
        ] {
            assert!(denied(my(sql)), "{sql}");
        }
    }

    #[test]
    fn a_database_named_public_is_not_postgres_s_default_schema() {
        let mut view = agent(Access::ReadOnly);
        view.literal_names = true;
        assert!(view.allows_table("orders"));
        assert!(!view.allows_table("public.orders"));
        // On Postgres `public.orders` is `orders`.
        assert!(agent(Access::ReadOnly).allows_table("public.orders"));
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
            "SET tx_isolation = 'READ-UNCOMMITTED'",
            "SET transaction_isolation = 0",
            "SET transaction_isolation = CONCAT('READ-UNCOMM', 'ITTED')",
            "SET transaction_isolation = 0 + 'SERIALIZABLE'",
            "SET @x = 'SERIALIZABLE', transaction_isolation = 0",
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
