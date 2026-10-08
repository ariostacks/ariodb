//! Understanding ClickHouse SQL well enough to judge it.
//!
//! ClickHouse's dialect is not Postgres's, so this is a careful tokenizer
//! rather than a full parser. It finds the verb, the tables and the
//! functions, and it errs towards refusing: anything it cannot place is
//! `Unknown`, and more than one statement per request is refused.
//!
//! Table functions that reach outside the server (url, s3, file, remote and
//! so on) are refused outright, because they can read local files or send
//! data to other machines.

use crate::classify::{Kind, Statement};

/// Table functions that read or write outside the ClickHouse server.
pub const EXTERNAL_TABLE_FUNCTIONS: &[&str] = &[
    "file",
    "url",
    "urlcluster",
    "s3",
    "s3cluster",
    "gcs",
    "azureblobstorage",
    "azureblobstoragecluster",
    "hdfs",
    "hdfscluster",
    "remote",
    "remotesecure",
    "cluster",
    "clusterallreplicas",
    "mysql",
    "postgresql",
    "mongodb",
    "redis",
    "jdbc",
    "odbc",
    "executable",
    "sqlite",
    "iceberg",
    "icebergs3",
    "deltalake",
    "hudi",
    "input",
];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Str,
    Num,
    Punct(char),
}

fn tokenize(sql: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '-' && chars.get(i + 1) == Some(&'-')
            || c == '#'
                && (i == 0 || chars[i - 1].is_whitespace())
                && chars.get(i + 1) == Some(&' ')
        {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            loop {
                if i + 1 >= chars.len() {
                    return Err("unterminated comment".into());
                }
                if chars[i] == '/' && chars[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '\'' {
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("unterminated string".into()),
                    Some('\\') => i += 2,
                    Some('\'') if chars.get(i + 1) == Some(&'\'') => i += 2,
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            out.push(Tok::Str);
        } else if c == '`' || c == '"' {
            let quote = c;
            i += 1;
            let mut name = String::new();
            loop {
                match chars.get(i) {
                    None => return Err("unterminated identifier".into()),
                    Some('\\') => {
                        if let Some(n) = chars.get(i + 1) {
                            name.push(*n);
                        }
                        i += 2;
                    }
                    Some(q) if *q == quote && chars.get(i + 1) == Some(&quote) => {
                        name.push(quote);
                        i += 2;
                    }
                    Some(q) if *q == quote => {
                        i += 1;
                        break;
                    }
                    Some(other) => {
                        name.push(*other);
                        i += 1;
                    }
                }
            }
            out.push(Tok::Quoted(name));
        } else if c.is_ascii_digit() {
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == '_')
            {
                i += 1;
            }
            out.push(Tok::Num);
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            out.push(Tok::Word(chars[start..i].iter().collect()));
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    Ok(out)
}

fn word(t: &Tok) -> Option<String> {
    match t {
        Tok::Word(w) => Some(w.to_lowercase()),
        _ => None,
    }
}

fn name(t: &Tok) -> Option<String> {
    match t {
        Tok::Word(w) => Some(w.to_lowercase()),
        Tok::Quoted(q) => Some(q.to_lowercase()),
        _ => None,
    }
}

/// Read `db.table` or `table` starting at `i`. Returns the name and the
/// index after it.
fn table_name(toks: &[Tok], i: usize) -> Option<(String, usize)> {
    let first = name(toks.get(i)?)?;
    if toks.get(i + 1) == Some(&Tok::Punct('.')) {
        if let Some(second) = toks.get(i + 2).and_then(name) {
            return Some((format!("{first}.{second}"), i + 3));
        }
    }
    Some((first, i + 1))
}

const NOT_FUNCTIONS: &[&str] = &[
    "in", "values", "as", "and", "or", "not", "exists", "from", "join", "select", "where", "on",
    "using", "over", "filter", "array", "tuple", "if", "case", "when", "then", "else", "with",
    "settings", "format", "interval", "table", "into", "by", "limit", "having", "union", "all",
    "distinct", "any", "is", "null", "like", "ilike",
];

/// Classify one ClickHouse request. Refuses more than one statement.
pub fn classify(sql: &str) -> Result<Statement, String> {
    let toks = tokenize(sql)?;
    // One statement only: a semicolon may only end the text.
    if let Some(pos) = toks.iter().position(|t| *t == Tok::Punct(';')) {
        if toks[pos + 1..].iter().any(|t| *t != Tok::Punct(';')) {
            return Err("send one statement per request".to_string());
        }
    }
    let toks: Vec<Tok> = toks.into_iter().filter(|t| *t != Tok::Punct(';')).collect();
    let words: Vec<Option<String>> = toks.iter().map(word).collect();

    // The verb: the first keyword, skipping a leading WITH ... clause.
    let mut verb = words.first().cloned().flatten().unwrap_or_default();
    if verb == "with" {
        let mut depth = 0;
        for (t, w) in toks.iter().zip(&words) {
            match t {
                Tok::Punct('(') => depth += 1,
                Tok::Punct(')') => depth -= 1,
                _ if depth == 0 && matches!(w.as_deref(), Some("select" | "insert")) => {
                    verb = w.clone().unwrap_or_default();
                    break;
                }
                _ => {}
            }
        }
    }

    // Tables and functions.
    let mut tables = Vec::new();
    let mut functions = Vec::new();
    for i in 0..toks.len() {
        let w = words[i].as_deref();
        if matches!(w, Some("from" | "join" | "into" | "table" | "update"))
            || (w == Some("describe") || w == Some("desc"))
        {
            let mut j = i + 1;
            // Skip modifiers such as `TABLE` after INSERT INTO or DESCRIBE.
            if matches!(
                words.get(j).cloned().flatten().as_deref(),
                Some("table" | "function")
            ) {
                j += 1;
            }
            if toks.get(j) == Some(&Tok::Punct('(')) {
                continue; // subquery
            }
            if let Some((t, next)) = table_name(&toks, j) {
                if toks.get(next) == Some(&Tok::Punct('(')) {
                    functions.push(t); // a table function such as url(...)
                } else if !NOT_FUNCTIONS.contains(&t.as_str()) {
                    tables.push(t);
                }
            }
        }
        if let (Some(f), Some(Tok::Punct('('))) = (name(&toks[i]), toks.get(i + 1)) {
            let after_dot = i > 0 && toks[i - 1] == Tok::Punct('.');
            if !after_dot && !NOT_FUNCTIONS.contains(&f.as_str()) && !functions.contains(&f) {
                functions.push(f);
            }
        }
    }
    tables.sort();
    tables.dedup();
    functions.sort();
    functions.dedup();

    let has = |kw: &str| words.iter().any(|w| w.as_deref() == Some(kw));
    let (kind, reason): (Kind, String) = match verb.as_str() {
        "select" | "show" | "describe" | "desc" | "exists" => (Kind::Read, "read".into()),
        "explain" => {
            // EXPLAIN plans; it does not run the query, but some forms read data.
            (Kind::Read, "explain".into())
        }
        "insert" => (Kind::Write, "insert".into()),
        "delete" => (
            Kind::Destructive,
            "DELETE in ClickHouse rewrites data and cannot be undone".into(),
        ),
        "alter" if has("delete") || has("update") => (
            Kind::Destructive,
            "ALTER ... DELETE/UPDATE mutations rewrite data and cannot be undone".into(),
        ),
        "drop" | "truncate" | "detach" | "rename" | "exchange" => {
            (Kind::Destructive, "drops or moves data".into())
        }
        "create" | "alter" | "attach" | "optimize" | "system" | "grant" | "revoke" | "kill"
        | "move" => (
            Kind::SchemaChange,
            "changes database objects or the server".into(),
        ),
        "set" | "use" => (Kind::Session, "session setting".into()),
        "" => (Kind::Unknown, "empty statement".into()),
        other => (
            Kind::Unknown,
            format!("'{other}' statements are not handled yet"),
        ),
    };
    let command = match verb.as_str() {
        "select" | "show" | "describe" | "desc" | "exists" | "explain" => "SELECT",
        "insert" => "INSERT",
        _ => "OK",
    };

    // Table functions that leave the server are refused, whatever the agent.
    let (kind, reason) = match functions
        .iter()
        .find(|f| EXTERNAL_TABLE_FUNCTIONS.contains(&f.as_str()))
    {
        Some(f) => (
            Kind::Destructive,
            format!("the '{f}' table function reaches outside the server"),
        ),
        None => (kind, reason),
    };
    // A SETTINGS clause could switch off read-only mode.
    let (kind, reason) = if has("settings")
        && words
            .iter()
            .any(|w| matches!(w.as_deref(), Some("readonly" | "allow_ddl")))
    {
        (
            Kind::Unknown,
            "queries may not change readonly or allow_ddl".to_string(),
        )
    } else {
        (kind, reason)
    };

    Ok(Statement {
        sql: sql.to_string(),
        kind,
        command,
        tables,
        reason,
        setting: None,
        copy_in: false,
        functions,
        engine: "clickhouse",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(sql: &str) -> Kind {
        classify(sql).unwrap().kind
    }

    #[test]
    fn kinds() {
        assert_eq!(
            kind("SELECT count() FROM events WHERE day = today()"),
            Kind::Read
        );
        assert_eq!(kind("WITH x AS (SELECT 1) SELECT * FROM x"), Kind::Read);
        assert_eq!(kind("INSERT INTO events (a) VALUES (1)"), Kind::Write);
        assert_eq!(
            kind("ALTER TABLE events DELETE WHERE a = 1"),
            Kind::Destructive
        );
        assert_eq!(kind("DROP TABLE events"), Kind::Destructive);
        assert_eq!(kind("TRUNCATE TABLE events"), Kind::Destructive);
        assert_eq!(
            kind("CREATE TABLE t (a Int8) ENGINE = Memory"),
            Kind::SchemaChange
        );
        assert_eq!(kind("SYSTEM DROP DNS CACHE"), Kind::SchemaChange);
        assert_eq!(kind("SET max_threads = 1"), Kind::Session);
    }

    #[test]
    fn tables_and_functions() {
        let s = classify(
            "SELECT uniq(user_id) FROM analytics.events AS e JOIN `users` u ON e.uid = u.id",
        )
        .unwrap();
        assert_eq!(s.tables, vec!["analytics.events", "users"]);
        assert_eq!(s.functions, vec!["uniq"]);
        let s = classify("SELECT * FROM (SELECT 1) WHERE 1").unwrap();
        assert!(s.tables.is_empty());
        let s = classify("INSERT INTO TABLE logs FORMAT JSONEachRow").unwrap();
        assert_eq!(s.tables, vec!["logs"]);
    }

    #[test]
    fn external_table_functions_are_refused() {
        assert_eq!(
            kind("SELECT * FROM url('http://evil.example/x', CSV)"),
            Kind::Destructive
        );
        assert_eq!(
            kind("INSERT INTO FUNCTION s3('https://x/y') SELECT * FROM events"),
            Kind::Destructive
        );
        assert_eq!(
            kind("SELECT * FROM file('/etc/passwd', 'LineAsString')"),
            Kind::Destructive
        );
        assert_eq!(
            kind("SELECT * FROM remote('10.0.0.1', db.t)"),
            Kind::Destructive
        );
    }

    #[test]
    fn tricks_are_caught() {
        assert!(classify("SELECT 1; DROP TABLE events").is_err());
        assert_eq!(kind("SELECT 1;"), Kind::Read);
        assert_eq!(
            kind("SELECT * FROM events SETTINGS readonly = 0"),
            Kind::Unknown
        );
        // Keywords inside strings and comments are not statements.
        assert_eq!(
            kind("SELECT 'DROP TABLE x' /* ; DROP */ FROM events"),
            Kind::Read
        );
        assert!(classify("SELECT 'unterminated").is_err());
    }
}
