//! Understanding SQL: parse with Postgres's own parser and decide what a
//! statement would do.
//!
//! Rule: when in doubt, call it `Unknown`. Unknown statements are refused.

use pg_query::NodeEnum;
use pg_query::protobuf::{Node, WithClause};
use serde::Serialize;
use std::fmt;

/// What a statement does, from least to most dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Only reads data.
    Read,
    /// Inserts, updates or deletes rows, with a WHERE clause where one applies.
    Write,
    /// Creates or changes tables, indexes, roles and other objects.
    SchemaChange,
    /// Drops or truncates, or updates or deletes every row in a table.
    Destructive,
    /// BEGIN, COMMIT, ROLLBACK, SAVEPOINT. ariodb manages transactions itself.
    Transaction,
    /// SET, RESET and similar session settings.
    Session,
    /// Anything ariodb cannot see inside, such as DO blocks or EXECUTE.
    Unknown,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::SchemaChange => "schema change",
            Kind::Destructive => "destructive",
            Kind::Transaction => "transaction control",
            Kind::Session => "session setting",
            Kind::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

/// One classified statement.
#[derive(Debug, Clone, Serialize)]
pub struct Statement {
    pub sql: String,
    pub kind: Kind,
    /// The command name Postgres reports back, such as "UPDATE".
    pub command: &'static str,
    /// Tables the statement names, lower case, without the `public.` prefix.
    pub tables: Vec<String>,
    /// Why the statement got this kind, for people reading logs.
    pub reason: String,
    /// For SET and RESET: the setting's name, lower case.
    pub setting: Option<String>,
    /// COPY ... FROM STDIN, which streams data in a sub-protocol.
    pub copy_in: bool,
    /// Functions the statement calls, lower case.
    pub functions: Vec<String>,
    /// `postgres` or `clickhouse`.
    pub engine: &'static str,
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot parse SQL: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Split a query string into statements and classify each one.
pub fn classify(sql: &str) -> Result<Vec<Statement>, ParseError> {
    let pieces = pg_query::split_with_parser(sql).map_err(|e| ParseError(e.to_string()))?;
    let mut out = Vec::new();
    for piece in pieces {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        out.push(classify_one(piece)?);
    }
    Ok(out)
}

fn classify_one(sql: &str) -> Result<Statement, ParseError> {
    let parsed = pg_query::parse(sql).map_err(|e| ParseError(e.to_string()))?;
    let top = parsed
        .protobuf
        .stmts
        .first()
        .and_then(|raw| raw.stmt.as_deref());
    let (kind, reason) = match top {
        Some(node) => judge(node),
        None => (Kind::Unknown, "empty statement".to_string()),
    };
    let command = top.map(command_of).unwrap_or("OK");
    let (setting, copy_in) = match top.and_then(|n| n.node.as_ref()) {
        Some(NodeEnum::VariableSetStmt(v)) => (Some(v.name.to_lowercase()), false),
        Some(NodeEnum::CopyStmt(c)) => (None, c.is_from && c.filename.is_empty() && !c.is_program),
        _ => (None, false),
    };
    let mut tables: Vec<String> = parsed.tables().iter().map(|t| normalise_table(t)).collect();
    let mut functions: Vec<String> = parsed
        .functions()
        .iter()
        .map(|f| normalise_function(f))
        .collect();
    // The parser's table and function lists stop at PREPARE and DECLARE
    // CURSOR, so a table or function named only in there would pass the
    // allow-list and the rules unseen. Print the wrapped query back to SQL
    // and read it on its own; if that fails, refuse.
    if let Some(inner) = top.and_then(wrapped_query) {
        let text = inner
            .deparse()
            .map_err(|e| ParseError(format!("cannot read the wrapped query: {e}")))?;
        let inner = pg_query::parse(&text).map_err(|e| ParseError(e.to_string()))?;
        tables.extend(inner.tables().iter().map(|t| normalise_table(t)));
        functions.extend(inner.functions().iter().map(|f| normalise_function(f)));
    }
    tables.sort();
    tables.dedup();
    functions.sort();
    functions.dedup();
    Ok(Statement {
        sql: sql.to_string(),
        kind,
        command,
        tables,
        reason,
        setting,
        copy_in,
        functions,
        engine: "postgres",
    })
}

/// The query inside a PREPARE or DECLARE CURSOR, which the parser's own
/// table and function lists do not look into.
fn wrapped_query(node: &Node) -> Option<&NodeEnum> {
    let inner = match node.node.as_ref()? {
        NodeEnum::PrepareStmt(s) => s.query.as_deref()?,
        NodeEnum::DeclareCursorStmt(s) => s.query.as_deref()?,
        _ => return None,
    };
    inner.node.as_ref()
}

fn command_of(node: &Node) -> &'static str {
    match node.node.as_ref() {
        Some(NodeEnum::SelectStmt(_)) => "SELECT",
        Some(NodeEnum::InsertStmt(_)) => "INSERT",
        Some(NodeEnum::UpdateStmt(_)) => "UPDATE",
        Some(NodeEnum::DeleteStmt(_)) => "DELETE",
        Some(NodeEnum::MergeStmt(_)) => "MERGE",
        Some(NodeEnum::CopyStmt(_)) => "COPY",
        Some(NodeEnum::ExplainStmt(_)) => "EXPLAIN",
        Some(NodeEnum::VariableShowStmt(_)) => "SHOW",
        _ => "OK",
    }
}

/// `public.Orders` and `orders` are the same table to a policy.
pub fn normalise_table(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.strip_prefix("public.") {
        // `public.pg_x` must not become `pg_x`, which names the catalogue.
        Some(rest) if !rest.starts_with("pg_") => rest.to_string(),
        _ => lower,
    }
}

/// Function names as rules see them: lower case, and without `pg_catalog.`,
/// which names the same built-in function (`pg_catalog.pg_read_file` is
/// `pg_read_file`).
pub fn normalise_function(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.strip_prefix("pg_catalog.") {
        Some(rest) => rest.to_string(),
        None => lower,
    }
}

/// Decide the kind of one parsed statement, looking inside wrappers.
fn judge(node: &Node) -> (Kind, String) {
    let Some(inner) = node.node.as_ref() else {
        return (Kind::Unknown, "empty node".into());
    };

    match inner {
        NodeEnum::SelectStmt(s) => {
            let mut kind = Kind::Read;
            let mut reason = "select".to_string();
            if s.into_clause.is_some() {
                return (Kind::SchemaChange, "SELECT INTO creates a table".into());
            }
            if !s.locking_clause.is_empty() {
                kind = Kind::Write;
                reason = "SELECT ... FOR UPDATE locks rows".into();
            }
            worst_of((kind, reason), judge_with(s.with_clause.as_ref()))
        }

        NodeEnum::InsertStmt(s) => worst_of(
            (Kind::Write, "insert".into()),
            judge_with(s.with_clause.as_ref()),
        ),
        NodeEnum::UpdateStmt(s) => {
            let own = if s.where_clause.is_none() {
                (
                    Kind::Destructive,
                    "UPDATE without WHERE changes every row".into(),
                )
            } else {
                (Kind::Write, "update".into())
            };
            worst_of(own, judge_with(s.with_clause.as_ref()))
        }
        NodeEnum::DeleteStmt(s) => {
            let own = if s.where_clause.is_none() {
                (
                    Kind::Destructive,
                    "DELETE without WHERE removes every row".into(),
                )
            } else {
                (Kind::Write, "delete".into())
            };
            worst_of(own, judge_with(s.with_clause.as_ref()))
        }
        NodeEnum::MergeStmt(s) => worst_of(
            (Kind::Write, "merge".into()),
            judge_with(s.with_clause.as_ref()),
        ),

        // Wrappers: judge what runs inside them.
        NodeEnum::ExplainStmt(s) => {
            if explain_runs_query(&s.options) {
                match s.query.as_deref() {
                    Some(q) => label(judge(q), "inside EXPLAIN ANALYZE"),
                    None => (Kind::Unknown, "EXPLAIN ANALYZE with no query".into()),
                }
            } else {
                (Kind::Read, "EXPLAIN plans without running".into())
            }
        }
        NodeEnum::PrepareStmt(s) => match s.query.as_deref() {
            Some(q) => label(judge(q), "inside PREPARE"),
            None => (Kind::Unknown, "PREPARE with no query".into()),
        },
        NodeEnum::DeclareCursorStmt(s) => match s.query.as_deref() {
            Some(q) => label(judge(q), "inside DECLARE CURSOR"),
            None => (Kind::Unknown, "cursor with no query".into()),
        },
        NodeEnum::CopyStmt(s) => {
            if s.is_program {
                (
                    Kind::Destructive,
                    "COPY ... PROGRAM runs a shell command".into(),
                )
            } else if !s.filename.is_empty() {
                (Kind::Destructive, "COPY to or from a server file".into())
            } else if let Some(q) = s.query.as_deref() {
                label(judge(q), "inside COPY")
            } else if s.is_from {
                (Kind::Write, "COPY FROM loads rows".into())
            } else {
                (Kind::Read, "COPY TO exports rows".into())
            }
        }

        // Things ariodb cannot see inside.
        NodeEnum::ExecuteStmt(_) => (Kind::Unknown, "EXECUTE hides the statement it runs".into()),
        NodeEnum::DoStmt(_) => (Kind::Unknown, "DO blocks run arbitrary code".into()),
        NodeEnum::CallStmt(_) => (Kind::Unknown, "CALL runs a procedure".into()),
        NodeEnum::FetchStmt(_) => (Kind::Unknown, "FETCH reads from a cursor".into()),

        NodeEnum::VariableShowStmt(_) => (Kind::Read, "show setting".into()),
        NodeEnum::VariableSetStmt(_) | NodeEnum::DiscardStmt(_) => {
            (Kind::Session, "session setting".into())
        }
        NodeEnum::TransactionStmt(_) => (Kind::Transaction, "transaction control".into()),

        NodeEnum::TruncateStmt(_) => (Kind::Destructive, "TRUNCATE removes every row".into()),
        NodeEnum::DropStmt(_)
        | NodeEnum::DropdbStmt(_)
        | NodeEnum::DropRoleStmt(_)
        | NodeEnum::DropOwnedStmt(_)
        | NodeEnum::DropTableSpaceStmt(_)
        | NodeEnum::DropSubscriptionStmt(_)
        | NodeEnum::DropUserMappingStmt(_) => (Kind::Destructive, "drop".into()),

        NodeEnum::CreateStmt(_)
        | NodeEnum::CreateTableAsStmt(_)
        | NodeEnum::AlterTableStmt(_)
        | NodeEnum::IndexStmt(_)
        | NodeEnum::ViewStmt(_)
        | NodeEnum::RenameStmt(_)
        | NodeEnum::CreateSchemaStmt(_)
        | NodeEnum::CreateSeqStmt(_)
        | NodeEnum::AlterSeqStmt(_)
        | NodeEnum::CreateFunctionStmt(_)
        | NodeEnum::CreateTrigStmt(_)
        | NodeEnum::CreateEnumStmt(_)
        | NodeEnum::CreateExtensionStmt(_)
        | NodeEnum::GrantStmt(_)
        | NodeEnum::GrantRoleStmt(_)
        | NodeEnum::CreateRoleStmt(_)
        | NodeEnum::AlterRoleStmt(_)
        | NodeEnum::CommentStmt(_)
        | NodeEnum::RefreshMatViewStmt(_)
        | NodeEnum::CreatePolicyStmt(_)
        | NodeEnum::AlterPolicyStmt(_)
        | NodeEnum::ReplicaIdentityStmt(_)
        | NodeEnum::AlterOwnerStmt(_)
        | NodeEnum::AlterObjectSchemaStmt(_)
        | NodeEnum::CreatePublicationStmt(_)
        | NodeEnum::AlterPublicationStmt(_)
        | NodeEnum::AlterSystemStmt(_)
        | NodeEnum::VacuumStmt(_)
        | NodeEnum::ReindexStmt(_)
        | NodeEnum::ClusterStmt(_)
        | NodeEnum::LockStmt(_) => (Kind::SchemaChange, "changes database objects".into()),

        _ => (
            Kind::Unknown,
            "statement type ariodb does not handle yet".into(),
        ),
    }
}

/// Data-modifying CTEs (`WITH x AS (DELETE ...) SELECT ...`) count too.
fn judge_with(with: Option<&WithClause>) -> (Kind, String) {
    let mut worst = (Kind::Read, "no CTEs".to_string());
    if let Some(with) = with {
        for cte in &with.ctes {
            if let Some(NodeEnum::CommonTableExpr(c)) = cte.node.as_ref()
                && let Some(q) = c.ctequery.as_deref()
            {
                worst = worst_of(worst, label(judge(q), "inside a WITH clause"));
            }
        }
    }
    worst
}

/// `EXPLAIN ANALYZE` (in any spelling) runs the statement; plain EXPLAIN does not.
fn explain_runs_query(options: &[Node]) -> bool {
    options.iter().any(|opt| match opt.node.as_ref() {
        Some(NodeEnum::DefElem(d)) if d.defname.eq_ignore_ascii_case("analyze") => {
            option_is_true(d.arg.as_deref())
        }
        _ => false,
    })
}

/// Read an option value the way Postgres does: no value means true.
fn option_is_true(arg: Option<&Node>) -> bool {
    let Some(node) = arg.and_then(|n| n.node.as_ref()) else {
        return true;
    };
    let text = match node {
        NodeEnum::Boolean(b) => return b.boolval,
        NodeEnum::Integer(i) => return i.ival != 0,
        NodeEnum::String(s) => s.sval.to_lowercase(),
        NodeEnum::AConst(c) => match &c.val {
            Some(pg_query::protobuf::a_const::Val::Boolval(b)) => return b.boolval,
            Some(pg_query::protobuf::a_const::Val::Ival(i)) => return i.ival != 0,
            Some(pg_query::protobuf::a_const::Val::Sval(s)) => s.sval.to_lowercase(),
            _ => return true,
        },
        _ => return true,
    };
    !matches!(text.as_str(), "false" | "off" | "0" | "no")
}

fn worst_of(a: (Kind, String), b: (Kind, String)) -> (Kind, String) {
    if b.0 > a.0 { b } else { a }
}

fn label((kind, reason): (Kind, String), place: &str) -> (Kind, String) {
    (kind, format!("{reason} ({place})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_of(sql: &str) -> Kind {
        let stmts = classify(sql).expect("should parse");
        assert_eq!(stmts.len(), 1, "expected one statement in {sql}");
        stmts[0].kind
    }

    #[test]
    fn plain_statements() {
        assert_eq!(kind_of("SELECT * FROM orders"), Kind::Read);
        assert_eq!(kind_of("INSERT INTO orders (id) VALUES (1)"), Kind::Write);
        assert_eq!(
            kind_of("UPDATE orders SET status = 'x' WHERE id = 1"),
            Kind::Write
        );
        assert_eq!(kind_of("DELETE FROM orders WHERE id = 1"), Kind::Write);
        assert_eq!(kind_of("CREATE TABLE t (id int)"), Kind::SchemaChange);
        assert_eq!(kind_of("BEGIN"), Kind::Transaction);
        assert_eq!(kind_of("SET search_path = x"), Kind::Session);
    }

    #[test]
    fn destructive_statements() {
        assert_eq!(kind_of("DELETE FROM orders"), Kind::Destructive);
        assert_eq!(
            kind_of("UPDATE orders SET status = 'void'"),
            Kind::Destructive
        );
        assert_eq!(kind_of("TRUNCATE orders"), Kind::Destructive);
        assert_eq!(kind_of("DROP TABLE orders"), Kind::Destructive);
        assert_eq!(
            kind_of("COPY orders FROM PROGRAM 'curl x'"),
            Kind::Destructive
        );
    }

    // The tricks that hide a write inside something that looks like a read.
    #[test]
    fn wrapped_writes_are_seen() {
        assert_eq!(
            kind_of("EXPLAIN ANALYZE DELETE FROM users"),
            Kind::Destructive
        );
        assert_eq!(
            kind_of("EXPLAIN (ANALYZE) DELETE FROM users WHERE id = 1"),
            Kind::Write
        );
        assert_eq!(
            kind_of("EXPLAIN (ANALYZE true) UPDATE users SET a = 1"),
            Kind::Destructive
        );
        assert_eq!(
            kind_of("EXPLAIN (ANALYZE off) DELETE FROM users"),
            Kind::Read
        );
        assert_eq!(kind_of("EXPLAIN DELETE FROM users"), Kind::Read);
        assert_eq!(kind_of("PREPARE p AS DELETE FROM users"), Kind::Destructive);
        assert_eq!(
            kind_of("WITH gone AS (DELETE FROM users RETURNING id) SELECT count(*) FROM gone"),
            Kind::Destructive
        );
        assert_eq!(
            kind_of("COPY (DELETE FROM users WHERE id = 1 RETURNING *) TO STDOUT"),
            Kind::Write
        );
        assert_eq!(kind_of("SELECT * FROM orders FOR UPDATE"), Kind::Write);
    }

    #[test]
    fn opaque_statements_are_unknown() {
        assert_eq!(
            kind_of("DO $$ BEGIN DELETE FROM users; END $$"),
            Kind::Unknown
        );
        assert_eq!(kind_of("EXECUTE p"), Kind::Unknown);
        assert_eq!(kind_of("CALL cleanup()"), Kind::Unknown);
    }

    #[test]
    fn splits_and_finds_tables() {
        let stmts = classify("SELECT 1 FROM Public.Orders; DELETE FROM customers WHERE id = 2;")
            .expect("should parse");
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].tables, vec!["orders"]);
        assert_eq!(stmts[1].tables, vec!["customers"]);
    }

    #[test]
    fn finds_functions() {
        let stmts = classify("SELECT pg_read_file('/etc/x'), lower(name) FROM t").unwrap();
        assert_eq!(stmts[0].functions, vec!["lower", "pg_read_file"]);
    }

    #[test]
    fn sees_tables_and_functions_inside_prepare_and_cursors() {
        let s = &classify("DECLARE c CURSOR WITH HOLD FOR SELECT * FROM secrets").unwrap()[0];
        assert_eq!(s.tables, vec!["secrets"]);
        let s = &classify("PREPARE p AS SELECT note, lower(note) FROM private.notes").unwrap()[0];
        assert_eq!(s.tables, vec!["private.notes"]);
        assert_eq!(s.functions, vec!["lower"]);
    }

    #[test]
    fn bad_sql_is_an_error() {
        assert!(classify("SELEC * FORM x").is_err());
    }
}
