//! MySQL and MariaDB SQL, understood well enough to judge it.
//!
//! Produces the same `Statement` the Postgres classifier does, with
//! `engine = "mysql"`, so the policy, rules, approvals and audit log work
//! unchanged.
//!
//! Two readers look at every query. A small lexer that follows the server's
//! own rules finds the statement boundaries, the comments and where each
//! string and quoted name starts. sqlparser then parses each statement with
//! its comments blanked out. If the two disagree about where a string or a
//! quoted name starts, or sqlparser finds a comment the server would not,
//! the statement is refused: a string literal must never hide SQL that the
//! server would run.
//!
//! The lexer assumes the session's `sql_mode` has neither `ANSI_QUOTES` (so
//! double quotes delimit strings, not names) nor `NO_BACKSLASH_ESCAPES` (so
//! a backslash escapes the next character in a string). The proxy turns
//! both off and the policy refuses agents' attempts to turn them back on.
//!
//! Rule: when in doubt, call it `Unknown`. Unknown statements are refused.

use crate::classify::{Kind, ParseError, Statement};
use sqlparser::ast::{
    Expr, ObjectName, ObjectNamePart, ObjectType, Query, Select, SetExpr, Statement as Ast,
    TableFactor, TableWithJoins, Visit, Visitor,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};
use std::ops::ControlFlow;

/// Split a query string into statements and classify each one.
pub fn classify(sql: &str) -> Result<Vec<Statement>, ParseError> {
    // The server ends a `#` or `--` comment at a NUL byte, then reads what
    // follows as SQL. Drivers escape NULs in strings, so none are needed.
    if sql.contains('\0') {
        return Err(ParseError(
            "NUL bytes are not allowed in statements; escape them as \\0".into(),
        ));
    }
    let lexemes = lex(sql)?;
    let blanked = blank_comments(sql, &lexemes);
    let mut out = Vec::new();
    let mut start = 0;
    let mut piece: Vec<Lexeme> = Vec::new();
    for lexeme in lexemes {
        if lexeme.tok == Tok::Punct(';') {
            let end = lexeme.start;
            if let Some(s) = statement(sql, &blanked, start, end, std::mem::take(&mut piece))? {
                out.push(s);
            }
            start = lexeme.end;
        } else {
            piece.push(lexeme);
        }
    }
    if let Some(s) = statement(sql, &blanked, start, sql.len(), piece)? {
        out.push(s);
    }
    Ok(out)
}

/// Make table names relative to the session's database: names in
/// `database` become unqualified (`app.orders` becomes `orders`), names in
/// other databases stay qualified, so `[agents.mysql] tables = ["orders"]`
/// means `orders` in `database` only.
pub fn scope_to_database(statements: &mut [Statement], database: &str) {
    if database.is_empty() {
        return;
    }
    let prefix = format!("{}.", database.to_lowercase());
    for stmt in statements {
        for t in &mut stmt.tables {
            if let Some(rest) = t.strip_prefix(&prefix) {
                *t = rest.to_string();
            }
        }
        stmt.tables.sort();
        stmt.tables.dedup();
    }
}

// ------------------------------------------------------------------ Lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// A keyword, an unquoted name or a number, as written.
    Word(String),
    /// A name in backticks, without them.
    Name(String),
    /// A string literal's contents.
    Str(String),
    Punct(char),
    /// A comment; `true` for one the server runs (`/*! ... */`, `/*M! ... */`).
    Comment(bool),
}

#[derive(Debug, Clone)]
struct Lexeme {
    tok: Tok,
    /// Byte offsets in the text that was lexed.
    start: usize,
    end: usize,
}

/// MySQL's whitespace: ASCII space, tab, newline, vertical tab, form feed and
/// carriage return. Other spaces (such as U+00A0) are part of a name to
/// the server, so they must be part of a name here too.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || !c.is_ascii()
}

/// Read SQL the way the MySQL server does.
fn lex(sql: &str) -> Result<Vec<Lexeme>, ParseError> {
    let chars: Vec<(usize, char)> = sql.char_indices().collect();
    let at = |i: usize| chars.get(i).map(|c| c.1);
    let offset = |i: usize| chars.get(i).map(|c| c.0).unwrap_or(sql.len());
    let err = |what: &str| Err(ParseError(what.to_string()));
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = at(i) {
        let start = i;
        if is_space(c) {
            i += 1;
            continue;
        }
        // `--` starts a comment only when a space or control character (or
        // the end) follows; `--1` is minus minus one.
        let dash_comment = c == '-'
            && at(i + 1) == Some('-')
            && at(i + 2).is_none_or(|n| n == ' ' || n.is_ascii_control());
        let tok = if c == '#' || dash_comment {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
            Tok::Comment(false)
        } else if c == '/' && at(i + 1) == Some('*') {
            let runs = at(i + 2) == Some('!')
                || (matches!(at(i + 2), Some('M' | 'm')) && at(i + 3) == Some('!'));
            i += 2;
            // Comments do not nest: the first `*/` ends one.
            loop {
                match at(i) {
                    None => return err("unterminated comment"),
                    Some('*') if at(i + 1) == Some('/') => {
                        i += 2;
                        break;
                    }
                    _ => i += 1,
                }
            }
            Tok::Comment(runs)
        } else if matches!(c, 'x' | 'X' | 'b' | 'B') && at(i + 1) == Some('\'') {
            // Hex and bit literals: no escapes inside.
            i += 2;
            let mut s = String::new();
            loop {
                match at(i) {
                    None => return err("unterminated string"),
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some(o) => {
                        s.push(o);
                        i += 1;
                    }
                }
            }
            Tok::Str(s)
        } else if c == '\'' || c == '"' || (matches!(c, 'n' | 'N') && at(i + 1) == Some('\'')) {
            // A backslash escapes the next character; a doubled quote is one.
            if c != '\'' && c != '"' {
                i += 1;
            }
            let quote = at(i).unwrap_or('\'');
            i += 1;
            let mut s = String::new();
            loop {
                match at(i) {
                    None => return err("unterminated string"),
                    Some('\\') => {
                        if let Some(n) = at(i + 1) {
                            s.push(n);
                        }
                        i += 2;
                    }
                    Some(q) if q == quote && at(i + 1) == Some(quote) => {
                        s.push(quote);
                        i += 2;
                    }
                    Some(q) if q == quote => {
                        i += 1;
                        break;
                    }
                    Some(o) => {
                        s.push(o);
                        i += 1;
                    }
                }
            }
            Tok::Str(s)
        } else if c == '`' {
            // Only a doubled backtick escapes; backslashes are ordinary.
            i += 1;
            let mut s = String::new();
            loop {
                match at(i) {
                    None => return err("unterminated quoted name"),
                    Some('`') if at(i + 1) == Some('`') => {
                        s.push('`');
                        i += 2;
                    }
                    Some('`') => {
                        i += 1;
                        break;
                    }
                    Some(o) => {
                        s.push(o);
                        i += 1;
                    }
                }
            }
            Tok::Name(s)
        } else if is_word_char(c) {
            while at(i).is_some_and(is_word_char) {
                i += 1;
            }
            Tok::Word(chars[start..i].iter().map(|c| c.1).collect())
        } else {
            i += 1;
            Tok::Punct(c)
        };
        out.push(Lexeme {
            tok,
            start: offset(start),
            end: offset(i),
        });
    }
    Ok(out)
}

/// The text with every comment replaced by spaces (newlines kept), byte for
/// byte, so offsets and line numbers stay the same.
fn blank_comments(sql: &str, lexemes: &[Lexeme]) -> String {
    let mut bytes = sql.as_bytes().to_vec();
    for l in lexemes {
        if matches!(l.tok, Tok::Comment(_)) {
            for b in &mut bytes[l.start..l.end] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
    }
    // Whole characters were replaced by ASCII spaces, so this cannot fail.
    String::from_utf8(bytes).unwrap_or_default()
}

/// Where each string and quoted name starts, as (line, column) counted the
/// way sqlparser counts them: both from 1, columns in characters. sqlparser
/// reads `0x1F` as a hex string, so those count too.
fn quote_positions(sql: &str, lexemes: &[Lexeme]) -> Vec<(u64, u64)> {
    let mut starts: Vec<usize> = lexemes
        .iter()
        .filter(|l| match &l.tok {
            Tok::Str(_) | Tok::Name(_) => true,
            Tok::Word(w) => w.starts_with("0x"),
            _ => false,
        })
        .map(|l| l.start)
        .collect();
    starts.sort();
    let mut out = Vec::new();
    let mut next = starts.iter().peekable();
    let (mut line, mut col) = (1, 1);
    for (offset, c) in sql.char_indices() {
        while next.peek().is_some_and(|s| **s == offset) {
            out.push((line, col));
            next.next();
        }
        if c == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    out
}

// ----------------------------------------------------------- Statements

/// What one statement turned out to be, before it becomes a `Statement`.
struct Judged {
    kind: Kind,
    reason: String,
    command: &'static str,
    tables: Vec<String>,
    functions: Vec<String>,
    setting: Option<String>,
}

impl Judged {
    fn new(kind: Kind, reason: impl Into<String>, command: &'static str) -> Judged {
        Judged {
            kind,
            reason: reason.into(),
            command,
            tables: Vec::new(),
            functions: Vec::new(),
            setting: None,
        }
    }

    fn with_names(mut self, names: Names) -> Judged {
        self.tables.extend(names.tables);
        self.functions.extend(names.functions);
        self
    }
}

/// Classify the statement between byte offsets `start` and `end`, or `None`
/// when there is nothing there but comments.
fn statement(
    sql: &str,
    blanked: &str,
    start: usize,
    end: usize,
    lexemes: Vec<Lexeme>,
) -> Result<Option<Statement>, ParseError> {
    let runs_comment = lexemes.iter().any(|l| l.tok == Tok::Comment(true));
    // Optimizer hints are harmless, except SET_VAR, which sets session
    // variables (some the policy refuses) for the statement.
    let sets_variables = lexemes.iter().any(|l| {
        let text = &sql[l.start..l.end];
        l.tok == Tok::Comment(false)
            && text.starts_with("/*+")
            && text.to_lowercase().contains("set_var")
    });
    let toks: Vec<Lexeme> = lexemes
        .into_iter()
        .filter(|l| !matches!(l.tok, Tok::Comment(_)))
        .collect();
    if toks.is_empty() && !runs_comment {
        return Ok(None);
    }
    if operator_depth(&toks) > MAX_OPERATOR_DEPTH {
        return Err(ParseError(
            "this expression is too long for ariodb to check; use IN (...) for long lists".into(),
        ));
    }
    let mut judged = if runs_comment {
        Judged::new(
            Kind::Unknown,
            "executable comments (/*! ... */) run SQL ariodb cannot see",
            command_for(&word(&toks, 0)),
        )
    } else if sets_variables {
        Judged::new(
            Kind::Unknown,
            "SET_VAR hints change settings ariodb does not check",
            command_for(&word(&toks, 0)),
        )
    } else {
        judge(blanked, &toks, 0)?
    };
    judged.tables.sort();
    judged.tables.dedup();
    judged.functions.sort();
    judged.functions.dedup();
    Ok(Some(Statement {
        sql: sql[start..end].trim().to_string(),
        kind: judged.kind,
        command: judged.command,
        tables: judged.tables,
        reason: judged.reason,
        setting: judged.setting,
        copy_in: false,
        functions: judged.functions,
        engine: "mysql",
    }))
}

/// sqlparser reads `a + b + c ...` and `x = 1 OR x = 2 ...` iteratively but
/// builds a tree as deep as the chain, and walking or dropping that tree
/// recurses once per level. A few thousand levels would overflow a thread's
/// stack and take the proxy down, so chains are capped well below that.
const MAX_OPERATOR_DEPTH: usize = 1000;

/// An upper bound on how deep operator chains could nest a parsed tree:
/// operators counted since the last comma at each level of parentheses,
/// summed over the levels open at once. Every punctuation character but
/// parentheses, commas and dots counts, because sqlparser chains more of them
/// than MySQL has (`a::int::int...` and `a:b:c...` nest as deeply as `+`),
/// and so does every keyword sqlparser reads as an infix operator.
fn operator_depth(toks: &[Lexeme]) -> usize {
    const OPERATOR_WORDS: &[&str] = &[
        "and", "or", "xor", "not", "div", "mod", "like", "ilike", "regexp", "rlike", "glob",
        "match", "similar", "between", "is", "in", "overlaps", "operator", "at", "notnull",
        "collate", "member", "sounds", "escape",
    ];
    let mut levels = vec![0usize];
    let (mut open, mut max) = (0usize, 0usize);
    for t in toks {
        let operator = match &t.tok {
            Tok::Punct('(') => {
                levels.push(0);
                false
            }
            Tok::Punct(')') => {
                open -= levels.pop().unwrap_or(0);
                if levels.is_empty() {
                    levels.push(0);
                }
                false
            }
            Tok::Punct(',') => {
                if let Some(top) = levels.last_mut() {
                    open -= *top;
                    *top = 0;
                }
                false
            }
            Tok::Punct('.') => false,
            Tok::Punct(_) => true,
            Tok::Word(w) => OPERATOR_WORDS.iter().any(|o| w.eq_ignore_ascii_case(o)),
            _ => false,
        };
        if operator && let Some(top) = levels.last_mut() {
            *top += 1;
            open += 1;
            max = max.max(open);
        }
    }
    max
}

/// The `i`th token as a lower-case keyword, or "" if it is not a bare word.
fn word(toks: &[Lexeme], i: usize) -> String {
    match toks.get(i).map(|l| &l.tok) {
        Some(Tok::Word(w)) => w.to_lowercase(),
        _ => String::new(),
    }
}

fn punct(toks: &[Lexeme], i: usize, c: char) -> bool {
    toks.get(i).is_some_and(|l| l.tok == Tok::Punct(c))
}

/// The text the tokens cover.
fn text_of<'a>(text: &'a str, toks: &[Lexeme]) -> &'a str {
    match (toks.first(), toks.last()) {
        (Some(a), Some(b)) => &text[a.start..b.end],
        _ => "",
    }
}

/// The command name for a statement starting with `verb`, as MySQL names it.
fn command_for(verb: &str) -> &'static str {
    const VERBS: &[&str] = &[
        "SELECT",
        "INSERT",
        "REPLACE",
        "UPDATE",
        "DELETE",
        "SHOW",
        "DESCRIBE",
        "EXPLAIN",
        "ANALYZE",
        "SET",
        "USE",
        "KILL",
        "BEGIN",
        "START",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "XA",
        "LOCK",
        "UNLOCK",
        "CALL",
        "PREPARE",
        "EXECUTE",
        "DEALLOCATE",
        "DO",
        "HANDLER",
        "LOAD",
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "RENAME",
        "GRANT",
        "REVOKE",
        "OPTIMIZE",
        "REPAIR",
        "CHECK",
        "CHECKSUM",
        "FLUSH",
        "RESET",
        "PURGE",
        "INSTALL",
        "UNINSTALL",
    ];
    match verb {
        "desc" => "DESCRIBE",
        "table" | "values" => "SELECT",
        _ => VERBS
            .iter()
            .find(|v| v.eq_ignore_ascii_case(verb))
            .copied()
            .unwrap_or("OK"),
    }
}

/// Statements nested in EXPLAIN or ANALYZE, at most this deep.
const MAX_NESTING: usize = 3;

fn judge(text: &str, toks: &[Lexeme], depth: usize) -> Result<Judged, ParseError> {
    if depth > MAX_NESTING {
        return Err(ParseError("statements nested too deeply".into()));
    }
    let verb = word(toks, 0);
    let command = command_for(&verb);
    let unknown = |reason: &str| Ok(Judged::new(Kind::Unknown, reason, command));
    let transaction = || {
        Ok(Judged::new(
            Kind::Transaction,
            "transaction control",
            command,
        ))
    };
    match verb.as_str() {
        "select" | "with" | "table" | "values" | "insert" | "replace" | "update" | "delete"
        | "" => parsed(text, toks),
        "explain" | "describe" | "desc" => explain(text, toks, depth),
        "analyze" => match word(toks, 1).as_str() {
            "table" | "tables" | "no_write_to_binlog" | "local" => {
                Ok(ddl(text, toks, Kind::SchemaChange, "maintains tables"))
            }
            // MariaDB's ANALYZE <statement> runs the statement.
            _ => {
                let mut i = 1;
                if word(toks, i) == "format" && punct(toks, i + 1, '=') {
                    i += 3;
                }
                let mut inner = judge(text, toks.get(i..).unwrap_or_default(), depth + 1)?;
                inner.reason = format!("{} (inside ANALYZE)", inner.reason);
                inner.command = "ANALYZE";
                Ok(inner)
            }
        },
        "show" => show(text, toks),
        "set" => set(text, toks),
        "use" => match toks.get(1..) {
            Some([name]) => match &name.tok {
                Tok::Word(n) | Tok::Name(n) => {
                    let mut j = Judged::new(Kind::Session, "changes the default database", "USE");
                    j.setting = Some(n.clone());
                    Ok(j)
                }
                _ => Err(ParseError("USE takes a database name".into())),
            },
            _ => Err(ParseError("USE takes a database name".into())),
        },
        // KILL is Session with the connection id in `setting`, and the
        // built-in policy refuses it. The MySQL proxy intercepts KILL before
        // the policy on purpose: agents' connection ids are the proxy's,
        // not the server's.
        "kill" => {
            let mut i = 1;
            while matches!(
                word(toks, i).as_str(),
                "connection" | "query" | "hard" | "soft" | "id"
            ) {
                i += 1;
            }
            let id = word(toks, i);
            if i + 1 == toks.len() && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
                let mut j = Judged::new(Kind::Session, "stops a connection or its query", "KILL");
                j.setting = Some(id);
                Ok(j)
            } else {
                unknown("KILL of anything but a connection id")
            }
        }
        "begin" if word(toks, 1) == "not" => {
            unknown("BEGIN NOT ATOMIC runs a block of code ariodb cannot see inside")
        }
        "start" if word(toks, 1) != "transaction" => {
            unknown("START controls replication or the server")
        }
        "lock" | "unlock" if !matches!(word(toks, 1).as_str(), "table" | "tables") => {
            unknown("LOCK and UNLOCK INSTANCE control the server")
        }
        "begin" | "start" | "commit" | "rollback" | "savepoint" | "release" | "xa" | "lock"
        | "unlock" => transaction(),
        "call" => unknown("CALL runs a procedure"),
        "prepare" | "execute" | "deallocate" => {
            unknown("prepared statements hide the statement they run")
        }
        "drop" if word(toks, 1) == "prepare" => {
            unknown("prepared statements hide the statement they run")
        }
        "do" => unknown("DO runs expressions ariodb does not check"),
        "handler" => unknown("HANDLER reads tables outside the usual checks"),
        "load" => unknown("LOAD reads a file"),
        "drop" => Ok(ddl(text, toks, Kind::Destructive, "drop")),
        "truncate" => Ok(ddl(
            text,
            toks,
            Kind::Destructive,
            "TRUNCATE removes every row",
        )),
        "create" | "alter" | "rename" | "grant" | "revoke" | "optimize" | "repair" | "check"
        | "checksum" => Ok(ddl(
            text,
            toks,
            Kind::SchemaChange,
            "changes database objects",
        )),
        "flush" | "reset" | "purge" | "change" | "stop" | "install" | "uninstall" | "shutdown"
        | "restart" | "clone" | "import" | "binlog" | "cache" | "help" | "get" | "signal"
        | "resignal" | "backup" => Ok(Judged::new(
            Kind::Unknown,
            format!("{} statements control the server", verb.to_uppercase()),
            command,
        )),
        other => Err(ParseError(format!(
            "'{other}' is not a statement ariodb knows"
        ))),
    }
}

/// A statement whose kind is clear from its verb; its tables are read when
/// sqlparser understands it, and left out when not (it is refused anyway).
fn ddl(text: &str, toks: &[Lexeme], kind: Kind, reason: &str) -> Judged {
    let command = command_for(&word(toks, 0));
    let j = Judged::new(kind, reason, command);
    let Ok(ast) = parse_one(text_of(text, toks)) else {
        return j;
    };
    let mut names = match Names::of(&ast) {
        Ok(names) => names,
        Err(_) => return j,
    };
    // DROP's names are not relations to the visitor.
    if let Ast::Drop {
        object_type: ObjectType::Table | ObjectType::View,
        names: dropped,
        ..
    } = &ast
    {
        for name in dropped {
            names.add_table(name);
        }
    }
    j.with_names(names)
}

/// EXPLAIN, DESCRIBE and DESC: of a table, or of a statement.
fn explain(text: &str, toks: &[Lexeme], depth: usize) -> Result<Judged, ParseError> {
    let command = command_for(&word(toks, 0));
    let mut i = 1;
    let mut analyze = false;
    loop {
        match word(toks, i).as_str() {
            "analyze" => {
                analyze = true;
                i += 1;
            }
            "extended" | "partitions" => i += 1,
            "format" if punct(toks, i + 1, '=') => i += 3,
            _ => break,
        }
    }
    let rest = toks.get(i..).unwrap_or_default();
    let starts_statement = matches!(
        word(rest, 0).as_str(),
        "select" | "with" | "table" | "values" | "insert" | "replace" | "update" | "delete"
    ) || punct(rest, 0, '(');
    if word(rest, 0) == "for" {
        return Ok(Judged::new(
            Kind::Unknown,
            "EXPLAIN FOR CONNECTION looks at another connection",
            command,
        ));
    }
    if starts_statement {
        let mut inner = judge(text, rest, depth + 1)?;
        inner.command = command;
        if analyze {
            // EXPLAIN ANALYZE runs the statement.
            inner.reason = format!("{} (inside EXPLAIN ANALYZE)", inner.reason);
        } else if inner.kind != Kind::Unknown {
            // Only a statement ariodb understood becomes a read: an Unknown
            // one may not have had its tables read (INTO OUTFILE is refused
            // before they are), so it stays Unknown even when not run.
            inner.kind = Kind::Read;
            inner.reason = "EXPLAIN plans without running".into();
            inner.setting = None;
        }
        return Ok(inner);
    }
    // EXPLAIN t [column]: describes a table.
    let Some((table, next)) = table_at(rest, 0)? else {
        return Err(ParseError(format!(
            "{command} of something ariodb cannot read"
        )));
    };
    let column_ok = match rest.get(next..) {
        Some([]) => true,
        Some([c]) => matches!(c.tok, Tok::Word(_) | Tok::Name(_) | Tok::Str(_)),
        _ => false,
    };
    if !column_ok {
        return Err(ParseError(format!(
            "{command} of something ariodb cannot read"
        )));
    }
    let mut j = Judged::new(Kind::Read, "describes a table", command);
    j.tables.push(table);
    Ok(j)
}

/// `name` or `db.name` at `i`: the lower-case name and the index after it.
fn table_at(toks: &[Lexeme], i: usize) -> Result<Option<(String, usize)>, ParseError> {
    let part = |i: usize| match toks.get(i).map(|l| &l.tok) {
        Some(Tok::Word(w) | Tok::Name(w)) => Some(w.to_lowercase()),
        _ => None,
    };
    let Some(first) = part(i) else {
        return Ok(None);
    };
    let (name, next) = match (punct(toks, i + 1, '.'), part(i + 2)) {
        (true, Some(second)) => (vec![first, second], i + 3),
        _ => (vec![first], i + 1),
    };
    Ok(Some((dotted(&name)?, next)))
}

/// Join name parts with dots. A part that itself contains a dot would make
/// a table in this database look like one in another, so it is refused.
fn dotted(parts: &[String]) -> Result<String, ParseError> {
    if parts.iter().any(|p| p.contains('.')) {
        return Err(ParseError(
            "names containing a dot are not supported through ariodb".into(),
        ));
    }
    Ok(parts.join("."))
}

// ------------------------------------------------------- Parsed statements

/// SELECT, INSERT, REPLACE, UPDATE and DELETE, read by sqlparser.
fn parsed(text: &str, toks: &[Lexeme]) -> Result<Judged, ParseError> {
    if toks.is_empty() {
        return Err(ParseError("empty statement".into()));
    }
    let words: Vec<String> = (0..toks.len()).map(|i| word(toks, i)).collect();
    if words
        .windows(2)
        .any(|w| w[0] == "into" && matches!(w[1].as_str(), "outfile" | "dumpfile"))
    {
        return Ok(Judged::new(
            Kind::Unknown,
            "SELECT ... INTO OUTFILE writes a file on the server",
            command_for(&words[0]),
        ));
    }
    // sqlparser does not know the old spelling of FOR SHARE; say it the new
    // way, padded so positions stay put.
    let mut sql = text_of(text, toks).to_string();
    let base = toks.first().map(|t| t.start).unwrap_or(0);
    let mut share_mode = false;
    for (i, w) in words.windows(4).enumerate() {
        if w == ["lock", "in", "share", "mode"] {
            share_mode = true;
            let (a, b) = (toks[i].start - base, toks[i + 3].end - base);
            let mut with = "FOR SHARE".to_string();
            with.push_str(&" ".repeat(b - a - with.len()));
            sql.replace_range(a..b, &with);
        }
    }
    // sqlparser reads `UPDATE IGNORE t` as the table `ignore` aliased `t`.
    // These modifiers change neither the tables nor the kind, and
    // LOW_PRIORITY and IGNORE are reserved words, never names, so they are
    // blanked, positions kept. QUICK is not reserved and is blanked only
    // after DELETE: were it a target table there, it would also have to
    // follow FROM, where it is reported.
    for (i, w) in words.iter().enumerate() {
        if !matches!(w.as_str(), "update" | "delete") {
            continue;
        }
        let mut k = i + 1;
        while let Some(m) = words.get(k)
            && (matches!(m.as_str(), "low_priority" | "ignore") || (w == "delete" && m == "quick"))
        {
            let (a, b) = (toks[k].start - base, toks[k].end - base);
            sql.replace_range(a..b, &" ".repeat(b - a));
            k += 1;
        }
    }
    // MySQL's TABLE t is SELECT * FROM t, which sqlparser reads only inside
    // a query.
    if words[0] == "table" {
        sql = format!("SELECT * FROM{}", &sql[toks[0].end - base..]);
    }
    let ast = parse_one(&sql)?;
    let (kind, reason, command) = judge_ast(&ast);
    let names = Names::of(&ast)?;
    let mut j = Judged::new(kind, reason, command);
    if let Some(why) = &names.into {
        j.kind = Kind::Unknown;
        j.reason = why.clone();
    } else if (names.locks || share_mode) && j.kind < Kind::Write {
        // As on Postgres: locking rows is a write.
        j.kind = Kind::Write;
        j.reason = "SELECT ... FOR UPDATE locks rows".into();
    }
    Ok(j.with_names(names))
}

fn judge_ast(ast: &Ast) -> (Kind, String, &'static str) {
    match ast {
        Ast::Query(q) => match q.body.as_ref() {
            // WITH ... UPDATE / DELETE.
            SetExpr::Insert(s) | SetExpr::Update(s) | SetExpr::Delete(s) => judge_ast(s),
            _ => (Kind::Read, "select".into(), "SELECT"),
        },
        Ast::Insert(i) if i.replace_into => (Kind::Write, "replace".into(), "REPLACE"),
        Ast::Insert(_) => (Kind::Write, "insert".into(), "INSERT"),
        Ast::Update(u) if u.selection.is_none() => (
            Kind::Destructive,
            "UPDATE without WHERE changes every row".into(),
            "UPDATE",
        ),
        Ast::Update(_) => (Kind::Write, "update".into(), "UPDATE"),
        Ast::Delete(d) if d.selection.is_none() => (
            Kind::Destructive,
            "DELETE without WHERE removes every row".into(),
            "DELETE",
        ),
        Ast::Delete(_) => (Kind::Write, "delete".into(), "DELETE"),
        _ => (
            Kind::Unknown,
            "statement type ariodb does not handle yet".into(),
            "OK",
        ),
    }
}

/// Parse text that must hold exactly one statement.
fn parse_one(sql: &str) -> Result<Ast, ParseError> {
    let mut statements = parse_checked(sql)?;
    match statements.len() {
        1 => Ok(statements.remove(0)),
        0 => Err(ParseError("empty statement".into())),
        _ => Err(ParseError("one statement was read as several".into())),
    }
}

/// Parse with sqlparser, after checking that it reads the quoting exactly
/// as the server would. The text has no comments: they were blanked.
fn parse_checked(sql: &str) -> Result<Vec<Ast>, ParseError> {
    let dialect = MySqlDialect {};
    let theirs = Tokenizer::new(&dialect, sql)
        .tokenize_with_location()
        .map_err(|e| ParseError(e.to_string()))?;
    let mut their_quotes = Vec::new();
    for t in &theirs {
        let quoted = match &t.token {
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => {
                return Err(ParseError(
                    "ariodb and the server would read the comments in this statement differently"
                        .into(),
                ));
            }
            Token::Word(w) => w.quote_style.is_some(),
            Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedByteStringLiteral(_)
            | Token::TripleDoubleQuotedByteStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_)
            | Token::TripleSingleQuotedRawStringLiteral(_)
            | Token::TripleDoubleQuotedRawStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::QuoteDelimitedStringLiteral(_)
            | Token::NationalQuoteDelimitedStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_) => true,
            _ => false,
        };
        if quoted {
            their_quotes.push((t.span.start.line, t.span.start.column));
        }
    }
    let ours = lex(sql)?;
    if ours.iter().any(|l| matches!(l.tok, Tok::Comment(_))) {
        return Err(ParseError("unexpected comment".into()));
    }
    if quote_positions(sql, &ours) != their_quotes {
        return Err(ParseError(
            "ariodb cannot be sure the server would read the quoting in this statement the same way"
                .into(),
        ));
    }
    Parser::new(&dialect)
        .with_tokens_with_locations(theirs)
        .parse_statements()
        .map_err(|e| ParseError(e.to_string()))
}

/// Tables and functions a parsed statement names.
#[derive(Default)]
struct Names {
    tables: Vec<String>,
    functions: Vec<String>,
    /// One `Scope` per query being visited, innermost last.
    scopes: Vec<Scope>,
    /// How many SELECTs the visitor is inside.
    selects: usize,
    /// Some query locks rows (FOR UPDATE, FOR SHARE).
    locks: bool,
    /// Why a SELECT ... INTO is not allowed, if one is not.
    into: Option<String>,
    error: Option<String>,
}

/// The common table expressions a query can see. A CTE hides a table of the
/// same name, but only in its own scope: `WITH t AS (SELECT * FROM t)` reads
/// the real table `t` inside, because a CTE that is not RECURSIVE cannot
/// see itself, and only CTEs defined earlier in the list. Names that might
/// be a table are reported as tables.
struct Scope {
    /// CTE names a table reference in this query's body may mean.
    visible: Vec<String>,
    /// Each CTE's query, and the names visible inside it.
    ctes: Vec<(*const Query, Vec<String>)>,
}

impl Names {
    fn of(ast: &Ast) -> Result<Names, ParseError> {
        let mut names = Names::default();
        let _ = ast.visit(&mut names);
        if let Ast::Delete(d) = ast {
            // Multi-table DELETE names its targets by table or by alias.
            let mut aliases = Vec::new();
            let from = match &d.from {
                sqlparser::ast::FromTable::WithFromKeyword(f)
                | sqlparser::ast::FromTable::WithoutKeyword(f) => f,
            };
            for t in from.iter().chain(d.using.iter().flatten()) {
                aliases_in(t, &mut aliases);
            }
            for target in &d.tables {
                let alias = match target.0.as_slice() {
                    [ObjectNamePart::Identifier(i)] => aliases.contains(&i.value.to_lowercase()),
                    _ => false,
                };
                if !alias {
                    names.add_table(target);
                }
            }
        }
        match names.error.take() {
            Some(e) => Err(ParseError(e)),
            None => Ok(names),
        }
    }

    fn add_table(&mut self, name: &ObjectName) {
        match name_parts(name)
            .map_err(|e| e.0)
            .and_then(|p| dotted(&p).map_err(|e| e.0))
        {
            Ok(n) => self.tables.push(n),
            Err(e) => self.error = Some(e),
        }
    }

    fn add_function(&mut self, name: &ObjectName) {
        match name_parts(name) {
            Ok(p) => self.functions.push(p.join(".")),
            Err(e) => self.error = Some(e.0),
        }
    }

    /// MariaDB's NEXTVAL(s), LASTVAL(s) and SETVAL(s, n) name a sequence,
    /// which is a table, and SETVAL and NEXTVAL change it outside the
    /// transaction. The sequence is reported as a table so the agent's
    /// tables decide. On MySQL these would be stored functions, and their
    /// argument is still reported: stricter, never looser.
    fn sequence(&mut self, f: &sqlparser::ast::Function) {
        use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
        let is_sequence = match f.name.0.as_slice() {
            [ObjectNamePart::Identifier(i)] => {
                matches!(
                    i.value.to_lowercase().as_str(),
                    "nextval" | "lastval" | "setval"
                )
            }
            _ => false,
        };
        if !is_sequence {
            return;
        }
        let first = match &f.args {
            FunctionArguments::List(list) => list.args.first(),
            _ => None,
        };
        let parts: Vec<String> = match first {
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(i)))) => {
                vec![i.value.to_lowercase()]
            }
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::CompoundIdentifier(ids)))) => {
                ids.iter().map(|i| i.value.to_lowercase()).collect()
            }
            _ => {
                self.error = Some(format!(
                    "ariodb cannot tell which sequence {}() names",
                    f.name
                ));
                return;
            }
        };
        match dotted(&parts) {
            Ok(n) => self.tables.push(n),
            Err(e) => self.error = Some(e.0),
        }
    }

    /// `TABLE t`, MySQL's short SELECT, which the relation visitor misses.
    fn table_statements(&mut self, body: &SetExpr, visible: &[String]) {
        match body {
            SetExpr::Table(t) => {
                let Some(table) = &t.table_name else {
                    return;
                };
                let parts = match &t.schema_name {
                    Some(s) => vec![s.to_lowercase(), table.to_lowercase()],
                    None if visible.contains(table) => return,
                    None => vec![table.to_lowercase()],
                };
                match dotted(&parts) {
                    Ok(n) => self.tables.push(n),
                    Err(e) => self.error = Some(e.0),
                }
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.table_statements(left, visible);
                self.table_statements(right, visible);
            }
            _ => {}
        }
    }
}

fn name_parts(name: &ObjectName) -> Result<Vec<String>, ParseError> {
    name.0
        .iter()
        .map(|p| match p {
            ObjectNamePart::Identifier(i) => Ok(i.value.to_lowercase()),
            ObjectNamePart::Function(_) => Err(ParseError("a computed name".into())),
        })
        .collect()
}

fn aliases_in(t: &TableWithJoins, out: &mut Vec<String>) {
    for factor in std::iter::once(&t.relation).chain(t.joins.iter().map(|j| &j.relation)) {
        if let TableFactor::Table {
            alias: Some(alias), ..
        } = factor
        {
            out.push(alias.name.value.to_lowercase());
        }
    }
}

fn is_user_variable(e: &Expr) -> bool {
    matches!(e, Expr::Identifier(i) if i.quote_style.is_none() && i.value.starts_with('@') && !i.value.starts_with("@@"))
}

impl Visitor for Names {
    type Break = ();

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        let mut visible = match self.scopes.last() {
            Some(s) => s
                .ctes
                .iter()
                .find(|(p, _)| std::ptr::eq(*p, q))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| s.visible.clone()),
            None => Vec::new(),
        };
        let mut ctes = Vec::new();
        if let Some(with) = &q.with {
            for cte in &with.cte_tables {
                let name = cte.alias.name.value.clone();
                let mut inside = visible.clone();
                if with.recursive {
                    inside.push(name.clone());
                }
                ctes.push((&*cte.query as *const Query, inside));
                visible.push(name);
            }
        }
        if !q.locks.is_empty() {
            self.locks = true;
        }
        self.table_statements(&q.body, &visible);
        self.scopes.push(Scope { visible, ctes });
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _q: &Query) -> ControlFlow<()> {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> ControlFlow<()> {
        self.selects += 1;
        if let Some(into) = &s.into
            && (into.table || into.temporary || !into.targets.iter().all(is_user_variable))
        {
            self.into = Some("SELECT ... INTO may only set user variables".into());
        }
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _s: &Select) -> ControlFlow<()> {
        self.selects -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<()> {
        // Only a reference inside a SELECT can mean a CTE; the target of an
        // INSERT, UPDATE or DELETE is always reported. Unquoted DUAL is no
        // table at all.
        let not_table = self.selects > 0
            && match name.0.as_slice() {
                [ObjectNamePart::Identifier(i)] => {
                    (i.quote_style.is_none() && i.value.eq_ignore_ascii_case("dual"))
                        || self
                            .scopes
                            .last()
                            .is_some_and(|s| s.visible.contains(&i.value))
                }
                _ => false,
            };
        if !not_table {
            self.add_table(name);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        match factor {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            } => self.add_function(name),
            TableFactor::Function { name, .. } => self.add_function(name),
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> ControlFlow<()> {
        if let Expr::Function(f) = e {
            self.add_function(&f.name);
            self.sequence(f);
        }
        ControlFlow::Continue(())
    }
}

/// Read an expression on its own, as `SELECT <expr>`, for its tables and
/// functions.
fn expression(text: &str, toks: &[Lexeme]) -> Result<Names, ParseError> {
    let ast = parse_one(&format!("SELECT {}", text_of(text, toks)))?;
    let names = Names::of(&ast)?;
    if names.locks || names.into.is_some() {
        return Err(ParseError("unexpected clause in an expression".into()));
    }
    Ok(names)
}

// -------------------------------------------------------------------- SHOW

/// SHOW: only the forms that describe structure or the agent's own session
/// are reads. The rest (PROCESSLIST, GRANTS, binary logs, replication,
/// CREATE USER, ...) describe other sessions or the server and are refused.
fn show(text: &str, toks: &[Lexeme]) -> Result<Judged, ParseError> {
    let w = |i: usize| word(toks, i);
    let mut i = 1;
    while matches!(w(i).as_str(), "full" | "extended") {
        i += 1;
    }
    let mut j = Judged::new(Kind::Read, "show", "SHOW");
    let table_from = |i: usize| -> Result<Option<(String, usize)>, ParseError> {
        if !matches!(w(i).as_str(), "from" | "in") {
            return Ok(None);
        }
        let Some((table, mut next)) = table_at(toks, i + 1)? else {
            return Ok(None);
        };
        // SHOW COLUMNS FROM t FROM db
        let mut table = table;
        if matches!(w(next).as_str(), "from" | "in")
            && !table.contains('.')
            && let Some((db, after)) = table_at(toks, next + 1)?
            && !db.contains('.')
        {
            table = format!("{db}.{table}");
            next = after;
        }
        Ok(Some((table, next)))
    };
    match (w(i).as_str(), w(i + 1).as_str()) {
        ("tables", _) => {
            i += 1;
            if matches!(w(i).as_str(), "from" | "in") {
                match toks.get(i + 1).map(|l| &l.tok) {
                    Some(Tok::Word(_) | Tok::Name(_)) => i += 2,
                    _ => return Err(ParseError("SHOW TABLES FROM what?".into())),
                }
            }
        }
        ("columns" | "fields" | "index" | "indexes" | "keys", _) => {
            let Some((table, next)) = table_from(i + 1)? else {
                return Err(ParseError(
                    "SHOW COLUMNS or INDEX needs FROM a table".into(),
                ));
            };
            j.tables.push(table);
            i = next;
        }
        ("create", "table") => {
            let Some((table, next)) = table_at(toks, i + 2)? else {
                return Err(ParseError("SHOW CREATE TABLE needs a table".into()));
            };
            j.tables.push(table);
            i = next;
        }
        ("databases" | "schemas" | "collation" | "charset" | "engines", _)
        | ("variables" | "status", _) => i += 1,
        ("character", "set") | ("storage", "engines") => i += 2,
        ("session" | "local", "variables" | "status") => i += 2,
        ("warnings" | "errors", _) => {
            i += 1;
            // LIMIT n, LIMIT n, m or LIMIT n OFFSET m: numbers only.
            let number = |k: usize| match toks.get(k).map(|l| &l.tok) {
                Some(Tok::Word(n)) => n.bytes().all(|b| b.is_ascii_digit()),
                _ => false,
            };
            if w(i) == "limit" {
                if !number(i + 1) {
                    return Err(ParseError("SHOW ... LIMIT takes numbers".into()));
                }
                i += 2;
                if (punct(toks, i, ',') || w(i) == "offset") && number(i + 1) {
                    i += 2;
                }
            }
        }
        ("count", _)
            if punct(toks, i + 1, '(')
                && punct(toks, i + 2, '*')
                && punct(toks, i + 3, ')')
                && matches!(w(i + 4).as_str(), "warnings" | "errors") =>
        {
            i += 5
        }
        _ => {
            let what: Vec<String> = (1..toks.len().min(4))
                .map(|k| text_of(text, &toks[k..=k]).to_uppercase())
                .collect();
            return Ok(Judged::new(
                Kind::Unknown,
                format!(
                    "SHOW {} is not one of the SHOW statements agents may use",
                    what.join(" ")
                ),
                "SHOW",
            ));
        }
    }
    // LIKE 'pattern' or WHERE <expression>, read like any other expression.
    let rest = toks.get(i..).unwrap_or_default();
    match (word(rest, 0).as_str(), rest.get(1).map(|l| &l.tok)) {
        ("", None) => Ok(j),
        ("like", Some(Tok::Str(_))) if rest.len() == 2 => Ok(j),
        ("where", Some(_)) => Ok(j.with_names(expression(text, &rest[1..])?)),
        _ => Err(ParseError("ariodb cannot read the end of this SHOW".into())),
    }
}

// --------------------------------------------------------------------- SET

/// `sql_mode` values that leave quoting and escapes as ariodb reads them.
/// ANSI_QUOTES makes double quotes delimit names, NO_BACKSLASH_ESCAPES makes
/// a backslash an ordinary character, and the combination modes (ANSI,
/// ORACLE, ...) include one or the other or change the grammar itself.
const SAFE_SQL_MODES: &[&str] = &[
    "allow_invalid_dates",
    "error_for_division_by_zero",
    "high_not_precedence",
    "ignore_space",
    "no_auto_create_user",
    "no_auto_value_on_zero",
    "no_dir_in_create",
    "no_engine_substitution",
    "no_unsigned_subtraction",
    "no_zero_date",
    "no_zero_in_date",
    "only_full_group_by",
    "pad_char_to_full_length",
    "pipes_as_concat",
    "real_as_float",
    "strict_all_tables",
    "strict_trans_tables",
    "time_truncate_fractional",
    "traditional",
    "empty_string_is_null",
    "no_field_options",
    "no_key_options",
    "no_table_options",
    "simultaneous_assignment",
    "time_round_fractional",
];

/// Character sets in which every byte below 0x80 is that ASCII character.
/// In GBK, Big5, SJIS, CP932 and GB18030 a backslash or quote byte can be
/// the second half of a character, so the server would see a string end
/// where ariodb does not.
const SAFE_CHARSETS: &[&str] = &["utf8mb4", "utf8mb3", "utf8", "latin1", "ascii", "binary"];

/// SET. `setting` lists every variable the statement sets, comma separated,
/// as `name` for the session, `@name` for a user variable and
/// `global.name` (or `persist.name`, `persist_only.name`) for the server.
/// The policy decides which may be set.
fn set(text: &str, toks: &[Lexeme]) -> Result<Judged, ParseError> {
    let rest = toks.get(1..).unwrap_or_default();
    if rest.is_empty() {
        return Err(ParseError("SET what?".into()));
    }
    let mut j = Judged::new(Kind::Session, "session setting", "SET");
    let fixed = match (word(rest, 0).as_str(), word(rest, 1).as_str()) {
        ("statement", _) => {
            return Ok(Judged::new(
                Kind::Unknown,
                "SET STATEMENT ... FOR runs a statement with other settings",
                "SET",
            ));
        }
        ("password", _) => Some("password"),
        ("role", _) => Some("role"),
        ("default", "role") => Some("default role"),
        ("resource", "group") => Some("resource group"),
        _ => None,
    };
    if let Some(name) = fixed {
        j.setting = Some(name.to_string());
        return Ok(j);
    }

    // SET [GLOBAL | SESSION] TRANSACTION characteristic, ...
    let (scope, after) = match scope_word(&word(rest, 0)) {
        Some(s) => (s, 1),
        None => ("", 0),
    };
    if word(rest, after) == "transaction" {
        let words: Vec<String> = (after + 1..rest.len()).map(|i| word(rest, i)).collect();
        let mut names = Vec::new();
        if words.iter().any(|w| w == "isolation") {
            names.push(scoped(scope, "transaction_isolation"));
        }
        if words
            .windows(2)
            .any(|w| w[0] == "read" && matches!(w[1].as_str(), "only" | "write"))
        {
            names.push(scoped(scope, "transaction_read_only"));
        }
        if names.is_empty() {
            return Err(ParseError("SET TRANSACTION what?".into()));
        }
        j.setting = Some(names.join(", "));
        return Ok(j);
    }

    let mut names = Vec::new();
    let mut scope = "";
    for item in split_commas(rest) {
        let (name, value) = assignment(item, &mut scope)?;
        if value.is_empty() {
            return Err(ParseError(format!("SET {name} to what?")));
        }
        let single = match value {
            [v] => Some(&v.tok),
            _ => None,
        };
        match name.as_str() {
            "autocommit" => {
                let on = matches!(single, Some(Tok::Word(v)) if matches!(v.to_lowercase().as_str(), "1" | "on" | "true"));
                if !on && j.kind != Kind::Unknown {
                    j.kind = Kind::Transaction;
                    j.reason =
                        "SET autocommit = 0 starts transactions ariodb does not manage".into();
                }
            }
            "names" | "character set" | "character_set_client" => {
                let charset = match value.first().map(|v| &v.tok) {
                    Some(Tok::Str(c) | Tok::Word(c) | Tok::Name(c)) => c.to_lowercase(),
                    _ => String::new(),
                };
                // NAMES x COLLATE y is fine; DEFAULT means the server's.
                let rest_ok = value.len() == 1 || (value.len() == 3 && word(value, 1) == "collate");
                if !SAFE_CHARSETS.contains(&charset.as_str()) || !rest_ok {
                    j.kind = Kind::Unknown;
                    j.reason = format!(
                        "the client character set may only be {}: in others a quote or backslash can hide inside a character",
                        SAFE_CHARSETS.join(", ")
                    );
                }
            }
            "sql_mode" => {
                let modes = match single {
                    Some(Tok::Str(s)) => Some(s.clone()),
                    Some(Tok::Word(w)) if !w.eq_ignore_ascii_case("default") => Some(w.clone()),
                    _ => None,
                };
                let safe = modes.is_some_and(|m| {
                    m.split(',')
                        .map(|x| x.trim().to_lowercase())
                        .all(|x| x.is_empty() || SAFE_SQL_MODES.contains(&x.as_str()))
                });
                if !safe {
                    j.kind = Kind::Unknown;
                    j.reason = "sql_mode may not include ANSI_QUOTES, NO_BACKSLASH_ESCAPES or modes that imply them, which would make the server read statements differently from ariodb".into();
                }
            }
            _ => {}
        }
        if single.is_none() && !matches!(name.as_str(), "names" | "character set") {
            j = j.with_names(expression(text, value)?);
        }
        names.push(name);
    }
    j.setting = Some(names.join(", "));
    Ok(j)
}

/// GLOBAL, PERSIST and PERSIST_ONLY reach the server; SESSION and LOCAL
/// (returned as "") the session.
fn scope_word(w: &str) -> Option<&'static str> {
    match w {
        "global" => Some("global"),
        "persist" => Some("persist"),
        "persist_only" => Some("persist_only"),
        "session" | "local" => Some(""),
        _ => None,
    }
}

fn scoped(scope: &str, name: &str) -> String {
    if scope.is_empty() {
        name.to_string()
    } else {
        format!("{scope}.{name}")
    }
}

/// Split at commas outside parentheses.
fn split_commas(toks: &[Lexeme]) -> Vec<&[Lexeme]> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, t) in toks.iter().enumerate() {
        match t.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth -= 1,
            Tok::Punct(',') if depth == 0 => {
                out.push(&toks[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&toks[start..]);
    out
}

/// One `[scope] name = value` of a SET: the normalised name and the value's
/// tokens. A scope keyword carries on to later assignments without one.
fn assignment<'a>(
    item: &'a [Lexeme],
    scope: &mut &'static str,
) -> Result<(String, &'a [Lexeme]), ParseError> {
    let bad = || ParseError("ariodb cannot read this SET".into());
    let part = |i: usize| match item.get(i).map(|l| &l.tok) {
        Some(Tok::Word(w) | Tok::Name(w) | Tok::Str(w)) => Some(w.to_lowercase()),
        _ => None,
    };
    let mut i = 0;
    if let Some(s) = scope_word(&word(item, 0)) {
        *scope = s;
        i = 1;
    }
    // SET NAMES and SET CHARACTER SET take a value without `=`.
    match (word(item, i).as_str(), word(item, i + 1).as_str()) {
        ("names", _) => return Ok(("names".into(), &item[i + 1..])),
        ("charset", _) => return Ok(("character set".into(), &item[i + 1..])),
        ("character", "set") => return Ok(("character set".into(), &item[i + 2..])),
        _ => {}
    }
    let name = if punct(item, i, '@') && punct(item, i + 1, '@') {
        // @@name, @@session.name, @@global.name, ...
        let first = part(i + 2).ok_or_else(bad)?;
        i += 3;
        let mut this_scope = "";
        let mut name = first.clone();
        if punct(item, i, '.') {
            let second = part(i + 1).ok_or_else(bad)?;
            i += 2;
            match scope_word(&first) {
                Some(s) => {
                    this_scope = s;
                    name = second;
                }
                None => name = format!("{first}.{second}"),
            }
        }
        scoped(this_scope, &name)
    } else if punct(item, i, '@') {
        let name = part(i + 1).ok_or_else(bad)?;
        i += 2;
        format!("@{name}")
    } else {
        let mut name = part(i).ok_or_else(bad)?;
        i += 1;
        if punct(item, i, '.') {
            name = format!("{name}.{}", part(i + 1).ok_or_else(bad)?);
            i += 2;
        }
        scoped(scope, &name)
    };
    if punct(item, i, ':') && punct(item, i + 1, '=') {
        i += 2;
    } else if punct(item, i, '=') {
        i += 1;
    } else {
        return Err(bad());
    }
    Ok((name, &item[i..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(sql: &str) -> Statement {
        let mut stmts = classify(sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
        assert_eq!(stmts.len(), 1, "expected one statement in {sql}");
        stmts.remove(0)
    }

    fn kind_of(sql: &str) -> Kind {
        one(sql).kind
    }

    fn tables(sql: &str) -> Vec<String> {
        one(sql).tables
    }

    #[test]
    fn plain_statements() {
        let s = one("SELECT * FROM orders WHERE id = 1");
        assert_eq!(
            (s.kind, s.command, s.engine),
            (Kind::Read, "SELECT", "mysql")
        );
        assert_eq!(s.tables, vec!["orders"]);
        let s = one("INSERT INTO orders (id) VALUES (1)");
        assert_eq!((s.kind, s.command), (Kind::Write, "INSERT"));
        assert_eq!(s.tables, vec!["orders"]);
        let s = one("UPDATE orders SET status = 'x' WHERE id = 1");
        assert_eq!((s.kind, s.command), (Kind::Write, "UPDATE"));
        let s = one("DELETE FROM orders WHERE id = 1");
        assert_eq!((s.kind, s.command), (Kind::Write, "DELETE"));
        assert_eq!(s.tables, vec!["orders"]);
    }

    #[test]
    fn table_names_are_lower_case_and_unquoted() {
        assert_eq!(
            tables("SELECT * FROM `App`.`Orders` o JOIN Customers c ON o.c = c.id"),
            vec!["app.orders", "customers"]
        );
        assert_eq!(tables("SELECT * FROM `odd``name`"), vec!["odd`name"]);
        assert!(classify("SELECT * FROM `app.orders`").is_err());
    }

    #[test]
    fn writes() {
        for sql in [
            "REPLACE INTO orders (id) VALUES (1)",
            "INSERT INTO orders (id) VALUES (1) ON DUPLICATE KEY UPDATE id = id + 1",
            "INSERT IGNORE INTO orders SET id = 1",
            "INSERT INTO orders SELECT * FROM staging WHERE id > 3",
            "UPDATE orders o JOIN customers c ON o.c = c.id SET o.x = 1 WHERE c.id = 2",
            "DELETE o FROM orders o JOIN customers c ON o.c = c.id WHERE c.id = 2",
            "DELETE FROM orders WHERE id = 1 ORDER BY id LIMIT 1",
        ] {
            assert_eq!(kind_of(sql), Kind::Write, "{sql}");
        }
        assert_eq!(
            one("REPLACE INTO orders (id) VALUES (1)").command,
            "REPLACE"
        );
        assert_eq!(
            tables("INSERT INTO orders SELECT * FROM staging WHERE id > 3"),
            vec!["orders", "staging"]
        );
        assert_eq!(
            tables("UPDATE orders o JOIN customers c ON o.c = c.id SET o.x = 1 WHERE c.id = 2"),
            vec!["customers", "orders"]
        );
        // Targets named by alias are the aliased tables.
        assert_eq!(
            tables("DELETE o, c FROM orders o JOIN customers AS c ON o.c = c.id WHERE c.id = 2"),
            vec!["customers", "orders"]
        );
        assert_eq!(
            tables("DELETE orders, archive FROM orders JOIN archive USING (id) WHERE id = 2"),
            vec!["archive", "orders"]
        );
        assert_eq!(
            tables("DELETE FROM orders, archive USING orders JOIN archive WHERE orders.id = 2"),
            vec!["archive", "orders"]
        );
    }

    #[test]
    fn destructive_statements() {
        for sql in [
            "DELETE FROM orders",
            "UPDATE orders SET status = 'void'",
            "UPDATE orders SET status = 'void' LIMIT 10",
            "DELETE o FROM orders o JOIN customers c ON o.c = c.id",
            "TRUNCATE orders",
            "TRUNCATE TABLE orders",
            "DROP TABLE orders",
            "DROP DATABASE app",
            "DROP INDEX i ON orders",
            "DROP PROCEDURE p",
        ] {
            assert_eq!(kind_of(sql), Kind::Destructive, "{sql}");
        }
        assert_eq!(
            tables("DROP TABLE orders, app.customers"),
            vec!["app.customers", "orders"]
        );
    }

    #[test]
    fn schema_changes() {
        for sql in [
            "CREATE TABLE t (id INT PRIMARY KEY) ENGINE=InnoDB",
            "CREATE TEMPORARY TABLE t (id INT)",
            "CREATE TABLE t AS SELECT * FROM orders",
            "CREATE INDEX i ON orders (id)",
            "CREATE VIEW v AS SELECT * FROM orders",
            "ALTER TABLE orders ADD COLUMN x INT",
            "ALTER TABLE orders DROP COLUMN x",
            "RENAME TABLE orders TO old_orders",
            "GRANT SELECT ON app.* TO 'u'@'%'",
            "OPTIMIZE TABLE orders",
            "ANALYZE TABLE orders",
            "CREATE PROCEDURE p() SELECT 1",
        ] {
            assert_eq!(kind_of(sql), Kind::SchemaChange, "{sql}");
        }
        assert_eq!(
            tables("CREATE TABLE t AS SELECT * FROM orders"),
            vec!["orders", "t"]
        );
    }

    #[test]
    fn transaction_control() {
        for sql in [
            "BEGIN",
            "BEGIN WORK",
            "START TRANSACTION",
            "START TRANSACTION READ WRITE",
            "COMMIT",
            "ROLLBACK",
            "ROLLBACK TO SAVEPOINT a",
            "SAVEPOINT a",
            "RELEASE SAVEPOINT a",
            "XA START 'x'",
            "LOCK TABLES orders WRITE",
            "UNLOCK TABLES",
            "SET autocommit = 0",
            "SET autocommit = OFF",
            "SET @@session.autocommit = 0",
            "SET autocommit = @x",
            "SET NAMES utf8mb4, autocommit = 0",
        ] {
            assert_eq!(kind_of(sql), Kind::Transaction, "{sql}");
        }
        // MariaDB's anonymous blocks: refused either way.
        assert_eq!(kind_of("BEGIN NOT ATOMIC SELECT 1"), Kind::Unknown);
        assert!(classify("BEGIN NOT ATOMIC DELETE FROM orders; END").is_err());
    }

    #[test]
    fn opaque_statements_are_unknown() {
        for sql in [
            "CALL cleanup()",
            "PREPARE p FROM 'DELETE FROM orders'",
            "EXECUTE p",
            "DEALLOCATE PREPARE p",
            "DROP PREPARE p",
            "DO sleep(1)",
            "HANDLER orders OPEN",
            "LOAD DATA INFILE '/tmp/x' INTO TABLE orders",
            "LOAD DATA LOCAL INFILE '/tmp/x' INTO TABLE orders",
            "LOAD XML INFILE '/tmp/x' INTO TABLE orders",
            "SELECT * FROM orders INTO OUTFILE '/tmp/x'",
            "SELECT * INTO DUMPFILE '/tmp/x' FROM orders",
            "SELECT 1 /*! , (SELECT secret FROM secrets) */",
            "SELECT 1 /*!50000 , secret */ FROM orders",
            "SELECT 1 /*M! , secret */ FROM orders",
            "/*!DROP TABLE orders*/",
            "START SLAVE",
            "FLUSH PRIVILEGES",
            "LOCK INSTANCE FOR BACKUP",
            "SET STATEMENT max_statement_time = 1 FOR DELETE FROM orders",
            "EXPLAIN FOR CONNECTION 12",
            "SHUTDOWN",
        ] {
            assert_eq!(kind_of(sql), Kind::Unknown, "{sql}");
        }
    }

    #[test]
    fn optimizer_hints_are_harmless() {
        let s = one("SELECT /*+ MAX_EXECUTION_TIME(1000) */ * FROM orders");
        assert_eq!((s.kind, s.tables), (Kind::Read, vec!["orders".to_string()]));
        assert_eq!(
            kind_of("UPDATE /*+ NO_RANGE_OPTIMIZATION(orders) */ orders SET a = 1 WHERE id = 1"),
            Kind::Write
        );
        assert_eq!(
            kind_of(
                "UPDATE /*+ SET_VAR(foreign_key_checks = OFF) */ orders SET a = 1 WHERE id = 1"
            ),
            Kind::Unknown
        );
    }

    #[test]
    fn reads() {
        for sql in [
            "SELECT 1",
            "(SELECT 1)",
            "SELECT 1 UNION SELECT 2",
            "TABLE orders",
            "VALUES ROW(1, 2)",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SELECT id INTO @x FROM orders LIMIT 1",
            "SELECT id, status INTO @a, @b FROM orders LIMIT 1",
            "DESCRIBE orders",
            "DESC orders",
            "EXPLAIN orders",
            "DESCRIBE orders status",
            "EXPLAIN SELECT * FROM orders",
            "EXPLAIN FORMAT=JSON SELECT * FROM orders",
            "EXPLAIN DELETE FROM orders",
            "DESCRIBE UPDATE orders SET a = 1",
        ] {
            assert_eq!(kind_of(sql), Kind::Read, "{sql}");
        }
        assert_eq!(tables("TABLE app.orders"), vec!["app.orders"]);
        assert_eq!(
            tables("TABLE orders ORDER BY id LIMIT 2 OFFSET 1"),
            vec!["orders"]
        );
        assert_eq!(
            tables("TABLE orders UNION TABLE secrets"),
            vec!["orders", "secrets"]
        );
        assert_eq!(kind_of("TABLE orders INTO OUTFILE '/tmp/x'"), Kind::Unknown);
        assert_eq!(tables("DESCRIBE app.orders"), vec!["app.orders"]);
        assert_eq!(tables("EXPLAIN DELETE FROM secrets"), vec!["secrets"]);
        assert_eq!(one("DESC orders").command, "DESCRIBE");
    }

    #[test]
    fn row_locks_are_writes_as_on_postgres() {
        for sql in [
            "SELECT * FROM orders FOR UPDATE",
            "SELECT * FROM orders FOR SHARE",
            "SELECT * FROM orders WHERE id = 1 LOCK IN SHARE MODE",
            "SELECT * FROM orders WHERE id IN (SELECT id FROM customers FOR UPDATE)",
        ] {
            assert_eq!(kind_of(sql), Kind::Write, "{sql}");
        }
    }

    #[test]
    fn explain_analyze_judges_what_it_runs() {
        assert_eq!(kind_of("EXPLAIN ANALYZE SELECT * FROM orders"), Kind::Read);
        assert_eq!(
            kind_of("EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1"),
            Kind::Write
        );
        assert_eq!(
            kind_of("EXPLAIN ANALYZE DELETE FROM orders"),
            Kind::Destructive
        );
        assert_eq!(
            kind_of("EXPLAIN ANALYZE FORMAT=TREE UPDATE orders SET a = 1"),
            Kind::Destructive
        );
        // MariaDB's ANALYZE <statement> runs it too.
        assert_eq!(kind_of("ANALYZE DELETE FROM orders"), Kind::Destructive);
        assert_eq!(
            kind_of("ANALYZE FORMAT=JSON UPDATE orders SET a = 1 WHERE id = 2"),
            Kind::Write
        );
        assert!(classify(&"EXPLAIN ".repeat(10)).is_err());
        for sql in [
            "EXPLAIN",
            "ANALYZE",
            "EXPLAIN ANALYZE",
            "ANALYZE FORMAT=JSON",
        ] {
            assert!(classify(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn writes_behind_with_are_seen() {
        assert_eq!(
            kind_of("WITH x AS (SELECT 1 AS id) DELETE FROM orders WHERE id IN (SELECT id FROM x)"),
            Kind::Write
        );
        assert_eq!(
            kind_of("WITH x AS (SELECT 1) UPDATE orders SET a = 1"),
            Kind::Destructive
        );
    }

    #[test]
    fn ctes_hide_tables_only_in_their_scope() {
        assert_eq!(
            tables("WITH recent AS (SELECT * FROM orders) SELECT * FROM recent"),
            vec!["orders"]
        );
        // A CTE that is not recursive cannot see itself: this reads the real table.
        assert_eq!(
            tables("WITH secrets AS (SELECT * FROM secrets) SELECT * FROM secrets"),
            vec!["secrets"]
        );
        // A later CTE is not visible to an earlier one.
        assert_eq!(
            tables("WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a"),
            vec!["b"]
        );
        // Outside the WITH, the name is the table again.
        assert_eq!(
            tables("SELECT * FROM (WITH secrets AS (SELECT 1) SELECT * FROM secrets) x, secrets"),
            vec!["secrets"]
        );
        // Names differing in case might be different tables.
        assert_eq!(
            tables("WITH Secrets AS (SELECT 1) SELECT * FROM secrets"),
            vec!["secrets"]
        );
        assert_eq!(
            tables(
                "WITH RECURSIVE n AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM n WHERE i < 3) SELECT * FROM n"
            ),
            Vec::<String>::new()
        );
        assert_eq!(tables("WITH x AS (SELECT 1) TABLE x"), Vec::<String>::new());
        // The target of a write is always a table.
        assert_eq!(
            tables("WITH orders AS (SELECT 1) UPDATE orders SET a = 1 WHERE id = 1"),
            vec!["orders"]
        );
    }

    #[test]
    fn every_table_reference_is_found() {
        assert_eq!(
            tables("SELECT * FROM orders, secrets"),
            vec!["orders", "secrets"]
        );
        assert_eq!(
            tables("SELECT * FROM orders WHERE id IN (SELECT id FROM secrets)"),
            vec!["orders", "secrets"]
        );
        assert_eq!(
            tables("SELECT (SELECT max(x) FROM secrets) FROM orders"),
            vec!["orders", "secrets"]
        );
        assert_eq!(
            tables(
                "SELECT * FROM orders WHERE EXISTS (SELECT 1 FROM db2.secrets s WHERE s.id = orders.id)"
            ),
            vec!["db2.secrets", "orders"]
        );
        assert_eq!(
            tables("SELECT * FROM orders o LEFT JOIN (customers c CROSS JOIN secrets) ON 1 = 1"),
            vec!["customers", "orders", "secrets"]
        );
        assert_eq!(
            tables("SELECT * FROM orders UNION TABLE secrets"),
            vec!["orders", "secrets"]
        );
        // Read, or refused as unreadable: never read without the table.
        for sql in [
            "SELECT * FROM (TABLE secrets) x",
            "SELECT * FROM orders WHERE id IN (TABLE secrets)",
            "INSERT INTO orders TABLE secrets",
            "UPDATE orders, secrets SET orders.a = secrets.b WHERE orders.id = secrets.id",
            "SELECT * FROM orders o, LATERAL (SELECT * FROM secrets s WHERE s.id = o.id) x",
            "VALUES ROW((SELECT max(x) FROM secrets))",
            "SELECT * FROM orders WHERE a = ANY (SELECT b FROM secrets)",
            "SELECT * FROM orders o JOIN secrets s USING (id)",
            "SELECT * FROM orders WHERE (SELECT 1 FROM secrets) = 1 LIMIT 1",
        ] {
            if let Ok(stmts) = classify(sql) {
                assert!(stmts[0].tables.contains(&"secrets".to_string()), "{sql}");
            }
        }
        assert_eq!(
            tables("INSERT INTO orders (a) VALUES ((SELECT x FROM secrets LIMIT 1))"),
            vec!["orders", "secrets"]
        );
        assert_eq!(
            tables("UPDATE orders SET a = (SELECT x FROM secrets LIMIT 1) WHERE id = 1"),
            vec!["orders", "secrets"]
        );
    }

    #[test]
    fn finds_functions() {
        let s = one("SELECT LOAD_FILE('/etc/passwd'), lower(name), app.f(1) FROM orders");
        assert_eq!(s.functions, vec!["app.f", "load_file", "lower"]);
        let s = one("UPDATE orders SET a = GET_LOCK('x', 10) WHERE id = 1");
        assert_eq!(s.functions, vec!["get_lock"]);
    }

    // A string literal must never hide a statement or a table.
    #[test]
    fn strings_and_comments_hide_nothing() {
        let stmts =
            classify("SELECT 'x; DROP TABLE orders' FROM orders; SELECT \"a;b\" FROM t").unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].tables, vec!["orders"]);
        assert_eq!(stmts[1].tables, vec!["t"]);

        // A backslash escapes the quote, so the string goes on.
        let stmts = classify(r"SELECT 'a\'; DROP TABLE orders; -- ' FROM t").unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].kind, Kind::Read);
        let stmts = classify(r"SELECT 'a\\'; DROP TABLE orders; -- ' FROM t").unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[1].kind, Kind::Destructive);
        // Double quotes are strings, not names.
        assert_eq!(
            kind_of(r#"SELECT "it\"s; DROP TABLE x" FROM t"#),
            Kind::Read
        );
        assert!(tables(r#"SELECT "secrets" FROM orders"#) == vec!["orders"]);

        // Comments as the server reads them.
        let stmts = classify("SELECT 1 FROM orders # ; DROP TABLE x\n; DELETE FROM t").unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[1].kind, Kind::Destructive);
        // `--` without a space is not a comment: this reads secrets.
        let s = one("SELECT * FROM orders WHERE id = 1 --(SELECT 1) UNION SELECT * FROM secrets");
        assert_eq!(s.tables, vec!["orders", "secrets"]);
        // `-- ` is.
        assert_eq!(tables("SELECT * FROM orders -- , secrets"), vec!["orders"]);
        // Comments do not nest.
        let stmts = classify("SELECT 1 /* /* */ ; DROP TABLE orders; /* */").unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[1].kind, Kind::Destructive);
        // Quotes in comments, comment markers in strings.
        assert_eq!(
            classify("SELECT 1 /* ' */ ; DELETE FROM t").unwrap().len(),
            2
        );
        assert_eq!(
            classify("SELECT '/*' ; DELETE FROM t; SELECT '*/'")
                .unwrap()
                .len(),
            3
        );
        assert_eq!(classify("SELECT '--' ; DELETE FROM t").unwrap().len(), 2);
        // An executable comment inside a string is just text.
        assert_eq!(kind_of("SELECT '/*! DROP TABLE x */' FROM t"), Kind::Read);
        // Backticks hold names; a quote inside one is part of the name.
        assert_eq!(
            tables("SELECT * FROM `it's`, secrets"),
            vec!["it's", "secrets"]
        );
        // Prefixed literals.
        assert_eq!(
            tables("SELECT x'41', b'01', N'x', _utf8mb4'y' FROM orders"),
            vec!["orders"]
        );
        // Unterminated things are errors.
        for sql in ["SELECT 'x", "SELECT \"x", "SELECT `x", "SELECT 1 /* x"] {
            assert!(classify(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn non_ascii_spaces_are_not_spaces() {
        // The server reads U+00A0 as part of a name, so must ariodb.
        assert!(
            classify("SELECT 1\u{a0}FROM orders").is_err()
                || tables("SELECT 1\u{a0}FROM orders").is_empty()
        );
    }

    #[test]
    fn show_statements() {
        for sql in [
            "SHOW TABLES",
            "SHOW FULL TABLES FROM app LIKE 'o%'",
            "SHOW DATABASES",
            "SHOW VARIABLES LIKE 'version%'",
            "SHOW SESSION VARIABLES",
            "SHOW SESSION STATUS",
            "SHOW STATUS LIKE 'Threads%'",
            "SHOW WARNINGS",
            "SHOW WARNINGS LIMIT 10",
            "SHOW ERRORS",
            "SHOW COUNT(*) WARNINGS",
            "SHOW COLLATION",
            "SHOW CHARACTER SET",
            "SHOW CHARSET",
            "SHOW ENGINES",
            "SHOW STORAGE ENGINES",
            "SHOW VARIABLES WHERE Variable_name IN ('a', 'b')",
        ] {
            let s = one(sql);
            assert_eq!((s.kind, s.command), (Kind::Read, "SHOW"), "{sql}");
            assert!(s.tables.is_empty(), "{sql}");
        }
        for (sql, table) in [
            ("SHOW COLUMNS FROM orders", "orders"),
            ("SHOW FULL COLUMNS FROM orders", "orders"),
            ("SHOW FIELDS IN app.orders", "app.orders"),
            ("SHOW COLUMNS FROM orders FROM app LIKE 'x'", "app.orders"),
            ("SHOW INDEX FROM `Orders`", "orders"),
            ("SHOW KEYS FROM orders IN app", "app.orders"),
            ("SHOW CREATE TABLE secrets", "secrets"),
        ] {
            let s = one(sql);
            assert_eq!(
                (s.kind, s.tables),
                (Kind::Read, vec![table.to_string()]),
                "{sql}"
            );
        }
        // A WHERE clause is read like any other expression.
        assert_eq!(
            tables("SHOW TABLES WHERE (SELECT secret FROM secrets LIMIT 1) = 'x'"),
            vec!["secrets"]
        );
        for sql in [
            "SHOW PROCESSLIST",
            "SHOW FULL PROCESSLIST",
            "SHOW GRANTS",
            "SHOW GRANTS FOR root",
            "SHOW BINARY LOGS",
            "SHOW BINLOG EVENTS",
            "SHOW MASTER STATUS",
            "SHOW REPLICA STATUS",
            "SHOW SLAVE HOSTS",
            "SHOW CREATE USER root",
            "SHOW GLOBAL STATUS",
            "SHOW GLOBAL VARIABLES",
            "SHOW ENGINE INNODB STATUS",
            "SHOW OPEN TABLES",
            "SHOW TABLE STATUS",
            "SHOW CREATE VIEW v",
        ] {
            assert_eq!(kind_of(sql), Kind::Unknown, "{sql}");
        }
        assert!(one("SHOW PROCESSLIST").reason.contains("PROCESSLIST"));
    }

    #[test]
    fn settings() {
        let setting = |sql: &str| {
            let s = one(sql);
            assert_eq!((s.kind, s.command), (Kind::Session, "SET"), "{sql}");
            s.setting.unwrap()
        };
        assert_eq!(setting("SET NAMES utf8mb4"), "names");
        assert_eq!(
            setting("SET NAMES 'utf8mb4' COLLATE 'utf8mb4_0900_ai_ci'"),
            "names"
        );
        assert_eq!(setting("SET NAMES latin1"), "names");
        assert_eq!(
            setting("SET character_set_client = utf8mb4"),
            "character_set_client"
        );
        assert_eq!(setting("SET CHARACTER SET utf8mb4"), "character set");
        assert_eq!(setting("SET CHARSET utf8mb4"), "character set");
        assert_eq!(setting("SET time_zone = '+00:00'"), "time_zone");
        assert_eq!(setting("SET @@session.time_zone = 'UTC'"), "time_zone");
        assert_eq!(setting("SET SESSION wait_timeout = 60"), "wait_timeout");
        assert_eq!(
            setting("SET LOCAL net_read_timeout = 60"),
            "net_read_timeout"
        );
        assert_eq!(
            setting("SET @@SQL_SELECT_LIMIT = DEFAULT"),
            "sql_select_limit"
        );
        assert_eq!(setting("SET autocommit = 1"), "autocommit");
        assert_eq!(setting("SET @x = 1, @Y := 'two'"), "@x, @y");
        assert_eq!(
            setting("SET character_set_client = utf8mb4, collation_connection = utf8mb4_bin"),
            "character_set_client, collation_connection"
        );
        assert_eq!(
            setting("SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE'"),
            "sql_mode"
        );
        assert_eq!(setting("SET SESSION sql_mode = ''"), "sql_mode");
        assert_eq!(setting("SET sql_mode = TRADITIONAL"), "sql_mode");
        assert_eq!(
            setting("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED"),
            "transaction_isolation"
        );
        assert_eq!(
            setting("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED, READ ONLY"),
            "transaction_isolation, transaction_read_only"
        );
        assert_eq!(
            setting("SET @@transaction_isolation = 'READ-COMMITTED'"),
            "transaction_isolation"
        );
        // Server-wide scopes are named as such, for the policy to refuse.
        assert_eq!(
            setting("SET GLOBAL wait_timeout = 1"),
            "global.wait_timeout"
        );
        assert_eq!(
            setting("SET @@global.wait_timeout = 1"),
            "global.wait_timeout"
        );
        assert_eq!(
            setting("SET PERSIST wait_timeout = 1"),
            "persist.wait_timeout"
        );
        assert_eq!(
            setting("SET @@persist_only.wait_timeout = 1"),
            "persist_only.wait_timeout"
        );
        assert_eq!(setting("SET GLOBAL a = 1, b = 2"), "global.a, global.b");
        assert_eq!(
            setting("SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE"),
            "global.transaction_isolation"
        );
        assert_eq!(setting("SET PASSWORD = 'local-test-only-pw'"), "password");
        assert_eq!(
            setting("SET PASSWORD FOR u = 'local-test-only-pw'"),
            "password"
        );
        assert_eq!(setting("SET ROLE ALL"), "role");
        assert_eq!(setting("SET DEFAULT ROLE ALL TO u"), "default role");
        assert_eq!(setting("SET sql_log_bin = 0"), "sql_log_bin");
        assert_eq!(setting("SET foreign_key_checks = 0"), "foreign_key_checks");
        // Values are read for tables and functions.
        let s = one("SET @x = (SELECT secret FROM secrets LIMIT 1)");
        assert_eq!(s.tables, vec!["secrets"]);
        let s = one("SET @x = GET_LOCK('a', 1)");
        assert_eq!(s.functions, vec!["get_lock"]);
        // sql_mode values that change how statements read.
        for sql in [
            "SET sql_mode = 'ANSI_QUOTES'",
            "SET sql_mode = 'STRICT_TRANS_TABLES,no_backslash_escapes'",
            "SET sql_mode = 'ANSI'",
            "SET sql_mode = ORACLE",
            "SET sql_mode = DEFAULT",
            "SET sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')",
            "SET @@session.sql_mode = @m",
            // Character sets whose characters can swallow a backslash.
            "SET NAMES gbk",
            "SET NAMES 'sjis'",
            "SET NAMES DEFAULT",
            "SET CHARACTER SET big5",
            "SET character_set_client = cp932",
            "SET @@character_set_client = @cs",
            "SET NAMES utf8mb4, character_set_client = gb18030",
        ] {
            assert_eq!(kind_of(sql), Kind::Unknown, "{sql}");
        }
    }

    #[test]
    fn kill_and_use() {
        let s = one("KILL 42");
        assert_eq!(
            (s.kind, s.command, s.setting.as_deref()),
            (Kind::Session, "KILL", Some("42"))
        );
        let s = one("KILL QUERY 42");
        assert_eq!(s.setting.as_deref(), Some("42"));
        assert_eq!(one("KILL CONNECTION 7").setting.as_deref(), Some("7"));
        assert_eq!(kind_of("KILL CONNECTION_ID()"), Kind::Unknown);
        assert_eq!(kind_of("KILL USER root"), Kind::Unknown);
        let s = one("USE `App`");
        assert_eq!(
            (s.kind, s.command, s.setting.as_deref()),
            (Kind::Session, "USE", Some("App"))
        );
        assert!(classify("USE a b").is_err());
    }

    #[test]
    fn splits_statements() {
        let stmts = classify("SELECT 1; ; DELETE FROM t WHERE id = 2;  -- trailing\n").unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].sql, "SELECT 1");
        assert_eq!(stmts[1].sql, "DELETE FROM t WHERE id = 2");
        assert!(classify("").unwrap().is_empty());
        assert!(classify("-- nothing\n/* at all */").unwrap().is_empty());
    }

    // Deep trees would overflow the stack when walked or dropped.
    #[test]
    fn long_operator_chains_are_refused_not_crashed_on() {
        assert!(classify(&format!("SELECT {}1 FROM t", "1+".repeat(500))).is_ok());
        for sql in [
            format!("SELECT {}1 FROM t", "1+".repeat(100_000)),
            format!("SELECT * FROM t WHERE {}1", "a = 1 OR ".repeat(100_000)),
            format!("SELECT {}1{}", "(1+".repeat(100_000), ")".repeat(100_000)),
            format!("SELECT {}1", "NOT ".repeat(100_000)),
            format!(
                "SELECT {}1{}",
                "(SELECT ".repeat(10_000),
                ")".repeat(10_000)
            ),
        ] {
            assert!(classify(&sql).is_err());
        }
        // Long lists are not chains.
        let values = vec!["(-1, 'x')"; 5000].join(", ");
        assert_eq!(
            kind_of(&format!("INSERT INTO t VALUES {values}")),
            Kind::Write
        );
    }

    /// sqlparser chains operators MySQL does not have, such as `::` casts,
    /// `:` access and AT TIME ZONE. Each of these, repeated, used to
    /// overflow the stack and abort the process.
    #[test]
    fn every_operator_sqlparser_chains_is_bounded() {
        for op in [
            "::int",
            ":b",
            " AT TIME ZONE 'UTC'",
            " COLLATE utf8mb4_bin",
            " ILIKE 'x'",
            " SIMILAR TO 'x'",
            " OVERLAPS b",
            " -> '$.a'",
            " ->> '$.a'",
            " <=> 1",
            " := 1",
            "[1]",
            "!",
        ] {
            let sql = format!("SELECT a{} FROM t", op.repeat(20_000));
            assert!(classify(&sql).is_err(), "{op}");
        }
        // Within the limit these still parse (or fail) without crashing.
        let _ = classify(&format!("SELECT 1{} FROM t", "::int".repeat(450)));
        let _ = classify(&format!(
            "SELECT now(){} FROM t",
            " AT TIME ZONE 'UTC'".repeat(900)
        ));
    }

    /// LOW_PRIORITY, IGNORE and QUICK made sqlparser read the modifier as
    /// the table and the real table as its alias.
    #[test]
    fn update_and_delete_modifiers_hide_no_table() {
        let s = one("UPDATE IGNORE secrets SET a = 1 WHERE id = 1");
        assert_eq!(
            (s.kind, s.tables),
            (Kind::Write, vec!["secrets".to_string()])
        );
        assert_eq!(
            tables("UPDATE LOW_PRIORITY IGNORE other.secrets SET a = 1 WHERE id = 1"),
            vec!["other.secrets"]
        );
        assert_eq!(
            tables(
                "UPDATE IGNORE secrets s JOIN orders o ON s.id = o.id SET s.a = 1 WHERE o.id = 1"
            ),
            vec!["orders", "secrets"]
        );
        assert_eq!(
            kind_of("UPDATE IGNORE secrets SET a = 1"),
            Kind::Destructive
        );
        let s = one("DELETE IGNORE FROM secrets");
        assert_eq!(
            (s.kind, s.tables),
            (Kind::Destructive, vec!["secrets".to_string()])
        );
        assert_eq!(
            tables("DELETE LOW_PRIORITY QUICK IGNORE FROM secrets WHERE id = 1"),
            vec!["secrets"]
        );
        assert_eq!(
            tables("DELETE QUICK FROM secrets WHERE id = 1"),
            vec!["secrets"]
        );
        assert_eq!(
            tables("EXPLAIN UPDATE IGNORE secrets SET a = 1 WHERE id = 1"),
            vec!["secrets"]
        );
        assert!(
            tables(
                "WITH x AS (SELECT 1 AS id) UPDATE IGNORE secrets SET a = 1 WHERE id IN (SELECT id FROM x)"
            )
            .contains(&"secrets".to_string())
        );
        // A quoted name is a name.
        assert_eq!(
            tables("UPDATE `ignore` SET a = 1 WHERE id = 1"),
            vec!["ignore"]
        );
    }

    #[test]
    fn explain_of_a_statement_ariodb_cannot_judge_is_not_a_read() {
        assert_eq!(
            kind_of("EXPLAIN SELECT * FROM secrets INTO OUTFILE '/tmp/x'"),
            Kind::Unknown
        );
        assert_eq!(
            kind_of("DESCRIBE SELECT 1 FROM secrets INTO DUMPFILE '/tmp/x'"),
            Kind::Unknown
        );
        assert_eq!(kind_of("EXPLAIN SELECT * FROM secrets"), Kind::Read);
    }

    #[test]
    fn show_limit_takes_only_numbers() {
        for sql in [
            "SHOW WARNINGS LIMIT 10",
            "SHOW WARNINGS LIMIT 1, 2",
            "SHOW ERRORS LIMIT 2 OFFSET 1",
        ] {
            assert_eq!(kind_of(sql), Kind::Read, "{sql}");
        }
        for sql in [
            "SHOW WARNINGS LIMIT (SELECT 1 FROM secrets)",
            "SHOW WARNINGS LIMIT 1 garbage",
            "SHOW ERRORS LIMIT",
        ] {
            assert!(classify(sql).is_err(), "{sql}");
        }
    }

    /// The server ends a `#` or `--` comment at a NUL and reads on.
    #[test]
    fn nul_bytes_are_refused() {
        for sql in [
            "DELETE FROM orders # x\0\nWHERE id = 1",
            "DELETE FROM orders -- x\0\nWHERE id = 1",
            "SELECT 'a\0b'",
            "SELECT 1\0",
        ] {
            assert!(classify(sql).is_err(), "{sql:?}");
        }
    }

    /// MariaDB's sequence functions name a table, and SETVAL's change
    /// survives a rollback.
    #[test]
    fn sequences_are_tables() {
        assert_eq!(tables("SELECT NEXTVAL(secret_seq)"), vec!["secret_seq"]);
        let s = one("SELECT SETVAL(App.`Secret_Seq`, 5) FROM orders WHERE id = 1 FOR UPDATE");
        assert_eq!(s.tables, vec!["app.secret_seq", "orders"]);
        assert_eq!(
            tables("UPDATE orders SET a = lastval(s) WHERE id = 1"),
            vec!["orders", "s"]
        );
        assert!(classify("SELECT NEXTVAL(1)").is_err());
        assert!(classify("SELECT setval((SELECT 's'), 1)").is_err());
        // A qualified name is a stored function, not MariaDB's.
        assert_eq!(tables("SELECT app.nextval(1) FROM orders"), vec!["orders"]);
    }

    #[test]
    fn bad_sql_is_an_error() {
        assert!(classify("SELEC * FORM x").is_err());
        assert!(classify("SELECT * FROM").is_err());
        assert!(classify("FROBNICATE orders").is_err());
    }

    #[test]
    fn common_driver_and_agent_queries() {
        for sql in [
            "SELECT * FROM orders WHERE id = ?",
            "SELECT @@version, @@session.autocommit, DATABASE(), CONNECTION_ID()",
            "SELECT 1 FROM DUAL",
            "SELECT CAST(x AS CHAR), CONVERT(x USING utf8mb4) FROM orders",
            "SELECT doc->'$.a', doc->>'$.b' FROM orders",
            "SELECT GROUP_CONCAT(x ORDER BY x SEPARATOR ',') FROM orders",
            "SELECT * FROM orders USE INDEX (i) WHERE a = 1 LIMIT 1, 2",
            "SELECT a, ROW_NUMBER() OVER (PARTITION BY b ORDER BY c) FROM orders",
            "SELECT 0x1F, 1e5, .5, b'01', x'4F', N'x', 'it''s', \"a\"\"b\"",
        ] {
            assert_eq!(kind_of(sql), Kind::Read, "{sql}");
        }
        assert_eq!(tables("SELECT 1 FROM DUAL"), Vec::<String>::new());
        assert_eq!(tables("SELECT 1 FROM `dual`"), vec!["dual"]);
        assert_eq!(
            kind_of("INSERT INTO orders (a) VALUES (1) AS new ON DUPLICATE KEY UPDATE a = new.a"),
            Kind::Write
        );
    }

    #[test]
    fn scoping_to_the_database() {
        let mut stmts = classify("SELECT * FROM App.orders JOIN other.t JOIN customers").unwrap();
        scope_to_database(&mut stmts, "app");
        assert_eq!(stmts[0].tables, vec!["customers", "orders", "other.t"]);
        let mut stmts = classify("SELECT * FROM app.orders").unwrap();
        scope_to_database(&mut stmts, "APP");
        assert_eq!(stmts[0].tables, vec!["orders"]);
        let mut stmts = classify("SELECT * FROM application.orders").unwrap();
        scope_to_database(&mut stmts, "app");
        assert_eq!(stmts[0].tables, vec!["application.orders"]);
    }
}
