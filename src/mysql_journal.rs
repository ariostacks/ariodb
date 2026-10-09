//! The MySQL change journal: agents' committed changes read from the binlog,
//! tied to their sessions through `[mysql] tag_table`, and written to
//! `<journal dir>/mysql-journal.jsonl` in the same record format as the
//! Postgres journal.
//!
//! ariodb reads the binlog as a replica would, with `[mysql] server_id`.
//! Every write transaction an agent makes starts with a row in the tag table
//! naming its session, so the journal records that transaction's other row
//! changes under that session. Changes by anyone else to tables agents may
//! write are recorded too, without a session: undo uses them to see that
//! someone changed a row after the agent did. Values are recorded as text;
//! see `mysql_binlog` for the encoding.
//!
//! The position read up to is kept in `<journal dir>/mysql-binlog-position.json`
//! and only moves past a transaction once its line is safely on disk, so a
//! crash never loses a change. (A crash between the two can repeat a
//! transaction; its position is then seen to be recorded already.)

use crate::config::{Access, Config};
use crate::doctor::{Finding, Section, Status};
use crate::journal::{Change, TxnRecord};
use crate::mysql_binlog::{self, InfoColumn, TableShape};
use crate::tls::TlsMode;
use futures::StreamExt;
use mysql_async::binlog::events::{EventData, RotateEvent};
use mysql_async::binlog::{BinlogChecksumAlg, EventType};
use mysql_async::prelude::Queryable;
use mysql_async::{BinlogStream, BinlogStreamRequest, Conn, OptsBuilder, SslOpts};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// MariaDB's own event types, which mysql_common does not name.
const MARIADB_ANNOTATE_ROWS: u8 = 160;
const MARIADB_GTID: u8 = 162;
const MARIADB_FIRST_COMPRESSED: u8 = 165;
const MARIADB_LAST_COMPRESSED: u8 = 171;
/// MySQL's heartbeat v2, also unnamed in mysql_common.
const HEARTBEAT_V2: u8 = 41;

pub fn journal_path(config: &Config) -> PathBuf {
    Path::new(&config.journal.dir).join("mysql-journal.jsonl")
}

fn position_path(config: &Config) -> PathBuf {
    Path::new(&config.journal.dir).join("mysql-binlog-position.json")
}

/// Where the journal has read up to: the binlog file and the offset of the
/// next event in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Position {
    pub file: String,
    pub pos: u64,
    /// Added to every record's lsn, so lsns keep growing when the binlog
    /// starts again from a lower file number (RESET BINARY LOGS, or another
    /// server after a failover) and the journal is restarted from there.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub base: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Where a journal with no saved position starts: the server's position
/// now, with a base that puts it after everything already recorded.
async fn fresh_position(config: &Config, conn: &mut Conn) -> Result<Position, String> {
    let mut p = server_position(conn).await?;
    let last = read_all(config)?.last().map(|r| r.lsn).unwrap_or(0);
    p.base = next_base(last, mysql_binlog::lsn(&p.file, p.pos));
    Ok(p)
}

/// The base that makes `raw` (a binlog position's lsn) come after `last`.
fn next_base(last: u64, raw: u64) -> u64 {
    if last >= raw { last - raw + 1 } else { 0 }
}

pub fn load_position(config: &Config) -> Result<Option<Position>, String> {
    let path = position_path(config);
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Replace the saved position atomically, and make it durable.
fn save_position(config: &Config, p: &Position) -> Result<(), String> {
    let path = position_path(config);
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string(p).map_err(|e| e.to_string())?;
    let mut f = File::create(&tmp).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    if let Ok(dir) = File::open(&config.journal.dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Every recorded MySQL transaction, oldest first.
pub fn read_all(config: &Config) -> Result<Vec<TxnRecord>, String> {
    let path = journal_path(config);
    let Ok(file) = File::open(&path) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let record: TxnRecord = serde_json::from_str(&line)
            .map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))?;
        out.push(record);
    }
    out.sort_by_key(|r| r.lsn);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Connections

/// `host:port`, `[::1]:3306` or `host` (port 3306).
fn host_port(addr: &str) -> Result<(String, u16), String> {
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && (h.starts_with('[') || !h.contains(':')) => (
            h,
            p.parse()
                .map_err(|_| format!("[mysql] addr '{addr}' has no valid port"))?,
        ),
        _ => (addr, 3306),
    };
    Ok((
        host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port,
    ))
}

/// Connect to the MySQL server as `user`, with TLS per `[mysql] tls`.
pub async fn connect_as(config: &Config, user: &str, password: &str) -> Result<Conn, String> {
    let (host, port) = host_port(&config.mysql_dial_addr()?)?;
    let ssl = match config.mysql_tls_mode() {
        TlsMode::Disable => None,
        TlsMode::Require => Some(
            SslOpts::default()
                .with_danger_accept_invalid_certs(true)
                .with_danger_skip_domain_validation(true),
        ),
        TlsMode::Verify => {
            let mut o = SslOpts::default();
            if let Some(ca) = &config.mysql.ca_file {
                o = o.with_root_certs(vec![PathBuf::from(ca).into()]);
            }
            if config.mysql.tunnel.is_some() {
                // The tunnel's local address is not the name on the certificate.
                o = o.with_danger_tls_hostname_override(Some(host_port(&config.mysql.addr)?.0));
            }
            Some(o)
        }
    };
    if ssl.is_some() {
        crate::tls::init();
    }
    let opts = OptsBuilder::default()
        .ip_or_hostname(host.clone())
        .tcp_port(port)
        .user(Some(user))
        .pass(Some(password))
        .prefer_socket(false)
        .client_found_rows(true)
        .ssl_opts(ssl);
    match tokio::time::timeout(Duration::from_secs(10), Conn::new(opts)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(format!(
            "cannot connect to MySQL at {host}:{port} as {user}: {}",
            message(&e)
        )),
        Err(_) => Err(format!(
            "cannot connect to MySQL at {host}:{port}: no answer in 10 seconds"
        )),
    }
}

/// Connect with the login the journal and undo use.
pub async fn connect(config: &Config) -> Result<Conn, String> {
    let (user, password) = config.mysql_journal_login()?;
    connect_as(config, &user, &password).await
}

/// The server's message, without the driver's wrapping.
pub fn message(e: &mysql_async::Error) -> String {
    match e {
        mysql_async::Error::Server(s) => format!("{} (error {})", s.message, s.code),
        other => other.to_string(),
    }
}

/// The server error code, if the server refused something.
pub fn code(e: &mysql_async::Error) -> Option<u16> {
    match e {
        mysql_async::Error::Server(s) => Some(s.code),
        _ => None,
    }
}

/// `(database, table)` of the tag table. An unqualified name is in
/// `[mysql] database`, where the gateway's statements run.
pub fn tag_table(config: &Config) -> (String, String) {
    match config.mysql.tag_table.split_once('.') {
        Some((d, t)) => (d.to_string(), t.to_string()),
        None => (
            config.mysql.database.clone(),
            config.mysql.tag_table.clone(),
        ),
    }
}

/// `` `db`.`table` ``.
pub fn quote_table(db: &str, table: &str) -> String {
    format!("{}.{}", quote_ident(db), quote_ident(table))
}

pub fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// The SQL string literal for an account name, for printed GRANTs.
fn account(user: &str) -> String {
    format!("'{}'@'%'", user.replace('\'', "''"))
}

pub async fn is_mariadb(conn: &mut Conn) -> bool {
    conn.query_first::<String, _>("SELECT VERSION()")
        .await
        .ok()
        .flatten()
        .is_some_and(|v| v.contains("MariaDB"))
}

/// The server's current binlog file and position.
pub async fn server_position(conn: &mut Conn) -> Result<Position, String> {
    // MySQL 8.2+ renamed SHOW MASTER STATUS; MariaDB keeps it.
    let mut last = String::new();
    for sql in ["SHOW BINARY LOG STATUS", "SHOW MASTER STATUS"] {
        match conn.query_first::<mysql_async::Row, _>(sql).await {
            Ok(Some(row)) => {
                let file: Option<String> = row.get(0);
                let pos: Option<u64> = row.get(1);
                if let (Some(file), Some(pos)) = (file, pos) {
                    return Ok(Position { file, pos, base: 0 });
                }
                last = "the binlog is off".to_string();
            }
            Ok(None) => last = "the binlog is off".to_string(),
            // A syntax error only means the other spelling is needed.
            Err(e) if code(&e) == Some(1064) && !last.is_empty() => {}
            Err(e) => last = message(&e),
        }
    }
    Err(format!("cannot read the binlog position: {last}"))
}

async fn variables(conn: &mut Conn) -> Result<HashMap<String, String>, String> {
    let rows: Vec<(String, String)> = conn
        .query(
            "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('log_bin', 'binlog_format',
             'binlog_row_image', 'binlog_row_metadata', 'binlog_row_value_options',
             'log_bin_compress', 'server_id', 'binlog_expire_logs_seconds', 'expire_logs_days')",
        )
        .await
        .map_err(|e| format!("cannot read server settings: {}", message(&e)))?;
    Ok(rows
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect())
}

/// The binlog settings the journal needs, as findings. A failure means the
/// journal cannot work.
pub async fn binlog_findings(config: &Config, conn: &mut Conn) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |status, text: String| out.push(Finding { status, text });
    let vars = match variables(conn).await {
        Ok(v) => v,
        Err(e) => {
            push(Status::Fail, e);
            return out;
        }
    };
    let mariadb = is_mariadb(conn).await;
    let get = |k: &str| vars.get(k).map(|s| s.to_uppercase()).unwrap_or_default();
    if get("log_bin") == "ON" || get("log_bin") == "1" {
        push(Status::Ok, "the binlog is on".to_string());
    } else if mariadb {
        push(
            Status::Fail,
            "the binlog is off; start MariaDB with --log-bin --binlog-format=ROW --binlog-row-metadata=FULL".to_string(),
        );
        return out;
    } else {
        push(
            Status::Fail,
            "the binlog is off; MySQL 8.4 has it on unless started with --skip-log-bin or --disable-log-bin".to_string(),
        );
        return out;
    }
    match get("binlog_format").as_str() {
        "ROW" => push(Status::Ok, "binlog_format is ROW".to_string()),
        other => push(
            Status::Fail,
            format!(
                "binlog_format is {other}; it must be ROW ({})",
                if mariadb {
                    "start MariaDB with --binlog-format=ROW"
                } else {
                    "SET PERSIST binlog_format = 'ROW'"
                }
            ),
        ),
    }
    match get("binlog_row_image").as_str() {
        "FULL" => push(Status::Ok, "binlog_row_image is FULL".to_string()),
        other => push(
            Status::Fail,
            format!("binlog_row_image is {other}; undo needs whole rows: set it to FULL"),
        ),
    }
    match get("binlog_row_metadata").as_str() {
        "FULL" => push(
            Status::Ok,
            "binlog_row_metadata is FULL: the binlog names every column".to_string(),
        ),
        other => push(
            Status::Warn,
            format!(
                "binlog_row_metadata is {}; column names will come from information_schema, which is wrong if a table changes shape before the journal reads its changes. Set it to FULL",
                if other.is_empty() {
                    "not available"
                } else {
                    other
                }
            ),
        ),
    }
    if get("binlog_row_value_options").contains("PARTIAL_JSON") {
        push(
            Status::Fail,
            "binlog_row_value_options is PARTIAL_JSON: JSON updates carry only the change, so undo cannot restore them. Set it to ''".to_string(),
        );
    }
    if get("log_bin_compress") == "ON" {
        push(
            Status::Fail,
            "log_bin_compress is ON; the journal cannot read compressed binlog events. Turn it off"
                .to_string(),
        );
    }
    if config.mysql.server_id == 0 {
        push(
            Status::Fail,
            "[mysql] server_id is 0, which servers treat as a one-off read that ends at the binlog's end; pick a number no server or replica uses".to_string(),
        );
    } else if vars.get("server_id").and_then(|s| s.parse::<u32>().ok())
        == Some(config.mysql.server_id)
    {
        push(
            Status::Fail,
            format!(
                "[mysql] server_id {} is the server's own; pick a number no server or replica uses",
                config.mysql.server_id
            ),
        );
    }
    out
}

/// The tables agents may change through MySQL: their changes by anyone are
/// recorded, so undo can see later changes to a row.
pub struct Protected {
    all: bool,
    tables: Vec<(String, String)>,
}

impl Protected {
    pub fn from_config(config: &Config) -> Protected {
        let mut p = Protected {
            all: false,
            tables: Vec::new(),
        };
        for access in config.agents.iter().filter_map(|a| a.mysql.as_ref()) {
            if access.access != Access::ReadWrite {
                continue;
            }
            for t in &access.tables {
                if t == "*" {
                    p.all = true;
                } else {
                    p.tables.push(match t.split_once('.') {
                        Some((d, t)) => (d.to_string(), t.to_string()),
                        None => (config.mysql.database.clone(), t.clone()),
                    });
                }
            }
        }
        p
    }

    pub fn covers(&self, db: &str, table: &str) -> bool {
        if matches!(
            db.to_lowercase().as_str(),
            "mysql" | "sys" | "information_schema" | "performance_schema"
        ) {
            return false;
        }
        self.all
            || self
                .tables
                .iter()
                .any(|(d, t)| d.eq_ignore_ascii_case(db) && t.eq_ignore_ascii_case(table))
    }
}

// ---------------------------------------------------------------------------
// Setup

/// Prepare the server: check binlog settings, create the tag table, and say
/// what is missing. Safe to run again.
pub async fn setup(config: &Config) -> Result<(), String> {
    let mut conn = connect(config).await?;
    let mut failed = Vec::new();
    for f in binlog_findings(config, &mut conn).await {
        match f.status {
            Status::Ok => println!("ok   {}", f.text),
            Status::Warn => println!("warn {}", f.text),
            Status::Fail => failed.push(f.text),
        }
    }
    if !failed.is_empty() {
        return Err(failed.join("\n"));
    }

    let (db, table) = tag_table(config);
    let qt = quote_table(&db, &table);
    conn.query_drop(format!(
        "CREATE DATABASE IF NOT EXISTS {}",
        quote_ident(&db)
    ))
    .await
    .map_err(|e| format!("cannot create database {db}: {}", message(&e)))?;
    conn.query_drop(format!(
        "CREATE TABLE IF NOT EXISTS {qt} (
             id BIGINT AUTO_INCREMENT PRIMARY KEY,
             session VARCHAR(64) NOT NULL,
             agent VARCHAR(255) NOT NULL,
             at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
             KEY (at)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    ))
    .await
    .map_err(|e| format!("cannot create the tag table {db}.{table}: {}", message(&e)))?;
    println!("ok   tag table {db}.{table} is ready");

    fs::create_dir_all(&config.journal.dir).map_err(|e| e.to_string())?;
    match load_position(config)? {
        Some(p) => println!("ok   the journal continues from {}:{}", p.file, p.pos),
        None => {
            let p = fresh_position(config, &mut conn).await?;
            save_position(config, &p)?;
            println!(
                "ok   the journal will record changes from {}:{}",
                p.file, p.pos
            );
        }
    }

    let gateway = account(&config.mysql.user);
    let (journal_user, _) = config.mysql_journal_login()?;
    let journal = account(&journal_user);
    println!();
    println!(
        "Grants ariodb needs (not run; run them as an administrator, with the right host instead of '%'):"
    );
    println!(
        "  -- the gateway login, for agents' queries: tagging writes, and counting the rows a write changed"
    );
    println!("  GRANT INSERT ON {qt} TO {gateway};");
    println!("  GRANT PROCESS ON *.* TO {gateway};");
    println!("  -- the journal login: reading the binlog, pruning tags, and undo");
    println!("  GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO {journal};");
    println!("  GRANT SELECT, INSERT, DELETE ON {qt} TO {journal};");
    let p = Protected::from_config(config);
    if p.all {
        println!(
            "  GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO {journal};  -- an agent may write any table"
        );
    } else {
        for (d, t) in &p.tables {
            println!(
                "  GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {journal};",
                quote_table(d, t)
            );
        }
    }
    if p.all || !p.tables.is_empty() {
        println!("  GRANT PROCESS ON *.* TO {journal};  -- lets undo see cascades and triggers");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading the binlog

/// Read the binlog forever, appending agents' transactions to the journal.
/// Failures are retried with backoff; each new error is reported once.
pub async fn run(config: &Config) -> Result<(), String> {
    fs::create_dir_all(&config.journal.dir).map_err(|e| e.to_string())?;
    let mut last_error = String::new();
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        let mut reader = Reader::new(config, &mut last_error);
        let result = reader.follow().await;
        if let Err(e) = result {
            report(&mut last_error, e);
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

fn report(last_error: &mut String, e: String) {
    if &e != last_error {
        eprintln!("ariodb: MySQL journal: {e}");
        *last_error = e;
    }
}

/// A transaction being read.
#[derive(Default)]
struct Open {
    session: Option<(String, String)>,
    changes: Vec<Change>,
    /// A rows event has been read: a tag row after this is not the
    /// gateway's, which always writes it first.
    rows_seen: bool,
}

struct Reader<'a> {
    config: &'a Config,
    last_error: &'a mut String,
    path: PathBuf,
    tag: (String, String),
    protected: Protected,
    /// Table shapes by table id, from table maps and information_schema.
    shapes: HashMap<u64, TableShape>,
    file: String,
    pos: u64,
    /// The saved position's base, added to every lsn.
    base: u64,
    saved: Position,
    saved_at: Instant,
    /// The position of the newest recorded transaction, so one repeated
    /// after a crash is not recorded twice.
    last_lsn: u64,
    open: Option<Open>,
    /// Inside a compressed transaction payload: positions are the payload's.
    in_payload: bool,
    /// A format description event has been read on this stream.
    seen_format: bool,
    pruned_at: Option<Instant>,
}

impl<'a> Reader<'a> {
    fn new(config: &'a Config, last_error: &'a mut String) -> Self {
        Reader {
            config,
            last_error,
            path: journal_path(config),
            tag: tag_table(config),
            protected: Protected::from_config(config),
            shapes: HashMap::new(),
            file: String::new(),
            pos: 0,
            saved: Position {
                file: String::new(),
                pos: 0,
                base: 0,
            },
            base: 0,
            saved_at: Instant::now(),
            last_lsn: 0,
            open: None,
            in_payload: false,
            seen_format: false,
            pruned_at: None,
        }
    }

    async fn follow(&mut self) -> Result<(), String> {
        let mut lookup = connect(self.config).await?;
        let mariadb = is_mariadb(&mut lookup).await;
        drop_torn_line(&self.path)?;
        self.last_lsn = read_all(self.config)?.last().map(|r| r.lsn).unwrap_or(0);
        let start = match load_position(self.config)? {
            Some(p) => p,
            None => {
                let p = fresh_position(self.config, &mut lookup).await?;
                save_position(self.config, &p)?;
                p
            }
        };
        self.file = start.file.clone();
        self.pos = start.pos;
        self.base = start.base;
        self.saved = start.clone();

        let mut conn = connect(self.config).await?;
        // Heartbeats every 5 seconds, so a dead connection is noticed.
        conn.query_drop("SET @master_heartbeat_period = 5000000000")
            .await
            .map_err(|e| message(&e))?;
        if mariadb {
            // Send GTID and annotate events as they are, not as fake BEGINs.
            conn.query_drop("SET @mariadb_slave_capability = 4")
                .await
                .map_err(|e| message(&e))?;
        }
        let mut stream = conn
            .get_binlog_stream(
                BinlogStreamRequest::new(self.config.mysql.server_id)
                    .with_filename(start.file.as_bytes())
                    .with_pos(start.pos),
            )
            .await
            .map_err(|e| format!("cannot read the binlog: {}", message(&e)))?;
        println!(
            "ariodb: MySQL journal is recording changes to {}, from {}:{}",
            self.path.display(),
            start.file,
            start.pos
        );
        self.last_error.clear();

        loop {
            let next = tokio::time::timeout(Duration::from_secs(30), stream.next()).await;
            let event = match next {
                Err(_) => {
                    return Err(
                        "no word from the MySQL server in 30 seconds; reconnecting".to_string()
                    );
                }
                Ok(None) => return Err("the MySQL server ended the binlog stream".to_string()),
                Ok(Some(Err(e))) => {
                    let m = message(&e);
                    // 1236 also means another reader took this server id;
                    // only a purged file calls for starting again.
                    let purged =
                        m.contains("purged") || m.contains("Could not find first log file");
                    return Err(if code(&e) == Some(1236) && purged {
                        format!(
                            "cannot read the binlog from {}:{}: {m}. If that file was purged, changes since were lost; move {} aside to start from now",
                            self.saved.file,
                            self.saved.pos,
                            position_path(self.config).display()
                        )
                    } else {
                        format!("binlog stream: {m}")
                    });
                }
                Ok(Some(Ok(event))) => event,
            };
            self.handle(&event, &stream, &mut lookup).await?;
            self.housekeeping(&mut lookup).await;
        }
    }

    async fn handle(
        &mut self,
        event: &mysql_async::binlog::events::Event,
        stream: &BinlogStream,
        lookup: &mut Conn,
    ) -> Result<(), String> {
        let header = event.header();
        let kind = header.event_type_raw();
        if kind == EventType::HEARTBEAT_EVENT as u8 || kind == HEARTBEAT_V2 {
            return Ok(());
        }
        verify_checksum(event).map_err(|e| format!("{e} at {}:{}", self.file, self.pos))?;
        if kind == EventType::ROTATE_EVENT as u8 {
            let r: RotateEvent = event.read_event().map_err(|e| e.to_string())?;
            let raw = r.name_raw();
            // MariaDB's first rotate comes before the format event that says
            // events end in a checksum, so its name still carries one.
            let name = if !self.seen_format
                && raw.len() == self.file.len() + 4
                && raw.starts_with(self.file.as_bytes())
            {
                self.file.clone()
            } else {
                r.name().to_string()
            };
            self.file = name;
            self.pos = r.position();
            self.shapes.clear();
            return Ok(());
        }
        if kind == EventType::FORMAT_DESCRIPTION_EVENT as u8 {
            self.seen_format = true;
            return Ok(());
        }
        // Positions only grow within a file; events inside a compressed
        // payload carry none of their own.
        let log_pos = header.log_pos() as u64;
        if !self.in_payload && log_pos > self.pos {
            self.pos = log_pos;
        }
        if (MARIADB_FIRST_COMPRESSED..=MARIADB_LAST_COMPRESSED).contains(&kind) {
            return Err("the binlog holds compressed events (log_bin_compress = ON), which the journal cannot read".to_string());
        }
        if kind == MARIADB_GTID
            || kind == EventType::GTID_EVENT as u8
            || kind == EventType::ANONYMOUS_GTID_EVENT as u8
            || kind == EventType::GTID_TAGGED_LOG_EVENT as u8
        {
            self.open = Some(Open::default());
            return Ok(());
        }
        if kind == MARIADB_ANNOTATE_ROWS {
            return Ok(());
        }
        if kind == EventType::TRANSACTION_PAYLOAD_EVENT as u8 {
            self.in_payload = true;
            return Ok(());
        }
        let data = match event.read_data() {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "cannot decode a binlog event at {}:{}: {e}",
                    self.file, self.pos
                ));
            }
        };
        match data {
            EventData::QueryEvent(q) => {
                let sql = q.query();
                let sql = sql.trim();
                if sql.eq_ignore_ascii_case("BEGIN") {
                    if self.open.is_none() {
                        self.open = Some(Open::default());
                    }
                } else if sql.eq_ignore_ascii_case("COMMIT") {
                    self.commit(0, header.timestamp())?;
                } else if starts_with_word(sql, "SAVEPOINT")
                    || starts_with_word(sql, "ROLLBACK TO")
                    || starts_with_word(sql, "RELEASE SAVEPOINT")
                {
                    // Inside the transaction; rolled-back rows never reach the binlog.
                } else {
                    // DDL and the like: no row changes, and table shapes may change.
                    self.open = None;
                    self.in_payload = false;
                    self.shapes.clear();
                }
            }
            EventData::XidEvent(x) => self.commit(x.xid, header.timestamp())?,
            EventData::RowsEvent(rows) => {
                let table_id = rows.table_id();
                let tme = stream.get_tme(table_id).ok_or_else(|| {
                    format!("a change to table id {table_id} without its table map")
                })?;
                let (db, table) = (
                    tme.database_name().to_string(),
                    tme.table_name().to_string(),
                );
                let is_tag = db == self.tag.0 && table == self.tag.1;
                let open = self.open.get_or_insert_with(Open::default);
                let first = !std::mem::replace(&mut open.rows_seen, true);
                // Rows are kept for protected tables, and for every table in
                // a transaction an agent tagged (the tag comes first). Only
                // the transaction's first row can be a tag: an agent allowed
                // to write the tag table could otherwise add a row naming
                // another session and have its changes recorded as that
                // session's.
                if is_tag && !first {
                    return Ok(());
                }
                if !is_tag && open.session.is_none() && !self.protected.covers(&db, &table) {
                    return Ok(());
                }
                if let std::collections::hash_map::Entry::Vacant(e) = self.shapes.entry(table_id) {
                    let info = columns_of(lookup, &db, &table).await?;
                    let shape = mysql_binlog::shape(tme, &info);
                    if shape.unnamed {
                        report(
                            self.last_error,
                            format!(
                                "{db}.{table} has changed shape since changes the journal is reading now, and the binlog does not name columns (binlog_row_metadata is not FULL), so they are recorded without column names and undo will refuse them"
                            ),
                        );
                    }
                    e.insert(shape);
                }
                let shape = &self.shapes[&table_id];
                let changes = mysql_binlog::changes(&rows, tme, shape)?;
                let open = self.open.get_or_insert_with(Open::default);
                if is_tag {
                    let col = |name: &str, fallback: usize| {
                        shape
                            .columns
                            .iter()
                            .position(|c| c.name == name)
                            .unwrap_or(fallback)
                    };
                    let (si, ai) = (col("session", 1), col("agent", 2));
                    if let Some(c) = changes
                        .first()
                        .filter(|c| c.op == crate::journal::Op::Insert)
                    {
                        let text = |i: usize| match c.new.as_ref().and_then(|v| v.get(i)) {
                            Some(Some(crate::journal::Cell::Text(t))) => t.clone(),
                            _ => String::new(),
                        };
                        open.session = Some((text(si), text(ai)));
                    }
                } else {
                    open.changes.extend(changes);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A transaction ended: record it if it matters, then move the position.
    fn commit(&mut self, xid: u64, timestamp: u32) -> Result<(), String> {
        self.in_payload = false;
        let Some(open) = self.open.take() else {
            return Ok(());
        };
        let lsn = self.base + mysql_binlog::lsn(&self.file, self.pos);
        if !open.changes.is_empty() && lsn > self.last_lsn {
            let (session, agent) = match open.session {
                Some((s, a)) => (Some(s), Some(a)),
                None => (None, None),
            };
            let record = TxnRecord {
                xid: xid as u32,
                lsn,
                lsn_text: format!("{}:{}", self.file, self.pos),
                at_ms: timestamp as i64 * 1000,
                session,
                agent,
                changes: open.changes,
            };
            let line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| format!("cannot open {}: {e}", self.path.display()))?;
            writeln!(file, "{line}")
                .and_then(|_| file.sync_data())
                .map_err(|e| format!("cannot write {}: {e}", self.path.display()))?;
            self.last_lsn = lsn;
            // Only now is it safe to move past this transaction.
            self.save()?;
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), String> {
        let p = Position {
            file: self.file.clone(),
            pos: self.pos,
            base: self.base,
        };
        if p != self.saved {
            save_position(self.config, &p)?;
            self.saved = p;
        }
        self.saved_at = Instant::now();
        Ok(())
    }

    /// Between transactions: keep the saved position near the stream (so a
    /// restart does not reread much), and delete day-old tag rows.
    async fn housekeeping(&mut self, lookup: &mut Conn) {
        if self.open.is_some() || self.in_payload {
            return;
        }
        if self.saved_at.elapsed() > Duration::from_secs(5)
            && let Err(e) = self.save()
        {
            report(self.last_error, e);
        }
        if self
            .pruned_at
            .is_none_or(|t| t.elapsed() > Duration::from_secs(3600))
        {
            self.pruned_at = Some(Instant::now());
            if let Err(e) = prune_tags(self.config, lookup).await {
                report(self.last_error, e);
            }
        }
    }
}

/// Cut off a last line left half-written by a crash or a full disk, which
/// would otherwise stop every later read of the journal. Its transaction's
/// position was never saved, so it is read again.
fn drop_torn_line(path: &Path) -> Result<(), String> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(());
    };
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(());
    }
    let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let err = |e: std::io::Error| format!("cannot repair {}: {e}", path.display());
    let file = OpenOptions::new().write(true).open(path).map_err(err)?;
    file.set_len(keep as u64).map_err(err)?;
    file.sync_all().map_err(err)?;
    eprintln!(
        "ariodb: MySQL journal: dropped a half-written last line from {}; its transaction will be read again",
        path.display()
    );
    Ok(())
}

fn starts_with_word(sql: &str, word: &str) -> bool {
    sql.get(..word.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(word))
}

/// Check an event's CRC32, when the server sends one.
fn verify_checksum(event: &mysql_async::binlog::events::Event) -> Result<(), String> {
    let footer = event.footer();
    if !footer.get_checksum_enabled() {
        return Ok(());
    }
    if let (Ok(Some(BinlogChecksumAlg::BINLOG_CHECKSUM_ALG_CRC32)), Some(sum)) =
        (footer.get_checksum_alg(), event.checksum())
        && u32::from_le_bytes(sum)
            != event.calc_checksum(BinlogChecksumAlg::BINLOG_CHECKSUM_ALG_CRC32)
    {
        return Err("a binlog event failed its checksum".to_string());
    }
    Ok(())
}

/// A table's columns from information_schema, in order.
pub async fn columns_of(conn: &mut Conn, db: &str, table: &str) -> Result<Vec<InfoColumn>, String> {
    let rows: Vec<(String, String, String, Option<String>)> = conn
        .exec(
            "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, CHARACTER_SET_NAME
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
             ORDER BY ORDINAL_POSITION",
            (db, table),
        )
        .await
        .map_err(|e| format!("cannot read the columns of {db}.{table}: {}", message(&e)))?;
    Ok(rows
        .into_iter()
        .map(|(name, data_type, column_type, charset)| InfoColumn {
            name,
            data_type: data_type.to_lowercase(),
            column_type,
            charset: charset.map(|c| c.to_lowercase()),
        })
        .collect())
}

/// Delete tag rows older than a day, a batch at a time. They only matter
/// until the journal has read their transactions.
async fn prune_tags(config: &Config, conn: &mut Conn) -> Result<(), String> {
    let (db, table) = tag_table(config);
    let sql = format!(
        "DELETE FROM {} WHERE at < NOW(3) - INTERVAL 1 DAY LIMIT 1000",
        quote_table(&db, &table)
    );
    for _ in 0..100 {
        conn.query_drop(&sql)
            .await
            .map_err(|e| format!("cannot prune old tags from {db}.{table}: {}", message(&e)))?;
        if conn.affected_rows() < 1000 {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Doctor

/// `ariodb doctor` for the journal side: binlog settings, replication
/// privileges, the tag table, and reading the binlog. Returns the section
/// and whether undo works.
pub async fn doctor(config: &Config) -> (Section, Result<(), String>) {
    let mut findings = Vec::new();
    let login = config.mysql_journal_login();
    let title = match &login {
        Ok((user, _)) => format!("mysql journal: {user}@{}", config.mysql.addr),
        Err(_) => "mysql journal".to_string(),
    };
    let work = doctor_checks(config, &mut findings);
    let undo = match tokio::time::timeout(Duration::from_secs(30), work).await {
        Ok(r) => r,
        Err(_) => {
            findings.push(Finding {
                status: Status::Fail,
                text: "the checks took longer than 30 seconds".to_string(),
            });
            Err("the journal checks timed out".to_string())
        }
    };
    (Section { title, findings }, undo)
}

async fn doctor_checks(config: &Config, findings: &mut Vec<Finding>) -> Result<(), String> {
    let mut undo: Result<(), String> = Ok(());
    let fail =
        |findings: &mut Vec<Finding>, undo: &mut Result<(), String>, text: String, short: &str| {
            findings.push(Finding {
                status: Status::Fail,
                text,
            });
            if undo.is_ok() {
                *undo = Err(short.to_string());
            }
        };
    let mut conn = match connect(config).await {
        Ok(c) => c,
        Err(e) => {
            fail(
                findings,
                &mut undo,
                e.clone(),
                "the journal login cannot connect",
            );
            return undo;
        }
    };
    findings.push(Finding {
        status: Status::Ok,
        text: "connected".to_string(),
    });
    let settings = binlog_findings(config, &mut conn).await;
    let settings_ok = !settings.iter().any(|f| f.status == Status::Fail);
    findings.extend(settings);
    if !settings_ok {
        fail(
            findings,
            &mut undo,
            "the binlog settings above must change before undo can work".to_string(),
            "the binlog settings do not allow it",
        );
        return undo;
    }

    let (db, table) = tag_table(config);
    let exists: Option<u8> = conn
        .exec_first(
            "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
            (&db, &table),
        )
        .await
        .unwrap_or(None);
    if exists.is_some() {
        findings.push(Finding {
            status: Status::Ok,
            text: format!("tag table {db}.{table} exists"),
        });
    } else {
        fail(
            findings,
            &mut undo,
            format!("tag table {db}.{table} does not exist; run `ariodb setup`"),
            "not set up (run ariodb setup)",
        );
    }

    let logs: Result<Vec<mysql_async::Row>, _> = conn.query("SHOW BINARY LOGS").await;
    let logs: Vec<String> = match logs {
        Ok(rows) => {
            findings.push(Finding {
                status: Status::Ok,
                text: "can list binlogs (REPLICATION CLIENT)".to_string(),
            });
            rows.iter().filter_map(|r| r.get::<String, _>(0)).collect()
        }
        Err(e) => {
            fail(
                findings,
                &mut undo,
                format!(
                    "cannot list binlogs ({}); GRANT REPLICATION CLIENT ON *.* to the journal login",
                    message(&e)
                ),
                "the journal login lacks REPLICATION CLIENT",
            );
            Vec::new()
        }
    };

    let saved = load_position(config).ok().flatten();
    match &saved {
        Some(p) if !logs.is_empty() && !logs.contains(&p.file) => fail(
            findings,
            &mut undo,
            format!(
                "the journal stopped at {}:{}, but that binlog is gone: changes since were not recorded. Move {} aside to start from now",
                p.file,
                p.pos,
                position_path(config).display()
            ),
            "the binlog the journal needs was purged",
        ),
        Some(p) => {
            if let Ok(now) = server_position(&mut conn).await {
                let behind = mysql_binlog::lsn(&now.file, now.pos)
                    .saturating_sub(mysql_binlog::lsn(&p.file, p.pos));
                let text = if behind == 0 {
                    "the journal has read the whole binlog".to_string()
                } else if now.file == p.file {
                    format!("the journal is {behind} bytes behind the binlog")
                } else {
                    format!("the journal is at {}:{}; the binlog is at {}:{}", p.file, p.pos, now.file, now.pos)
                };
                let status = if now.file == p.file || behind == 0 { Status::Ok } else { Status::Warn };
                findings.push(Finding { status, text: if status == Status::Warn { format!("{text}; is `ariodb serve` running?") } else { text } });
            }
        }
        None => findings.push(Finding {
            status: Status::Warn,
            text: "the journal has not started; it records changes from when `ariodb setup` or `ariodb serve` first runs".to_string(),
        }),
    }

    // Read the binlog the way the journal does, without waiting for more.
    if undo.is_ok() {
        let start = match saved {
            Some(p) => Ok(p),
            None => server_position(&mut conn).await,
        };
        match start {
            Ok(p) => match read_some(config, &p).await {
                Ok(()) => findings.push(Finding {
                    status: Status::Ok,
                    text: "the binlog can be read (REPLICATION SLAVE)".to_string(),
                }),
                Err(e) => fail(
                    findings,
                    &mut undo,
                    format!(
                        "the binlog cannot be read: {e}; GRANT REPLICATION SLAVE ON *.* to the journal login"
                    ),
                    "the binlog cannot be read",
                ),
            },
            Err(e) => fail(findings, &mut undo, e, "the binlog position cannot be read"),
        }
    }

    let process: Result<Option<u64>, _> = conn
        .query_first("SELECT COUNT(*) FROM information_schema.innodb_trx")
        .await;
    match process {
        Ok(_) => findings.push(Finding {
            status: Status::Ok,
            text: "undo can count rows a step changes, to refuse steps that cascade".to_string(),
        }),
        Err(e) => findings.push(Finding {
            status: Status::Warn,
            text: format!(
                "undo cannot count the rows each step changes ({}), so it cannot refuse a step that cascades into rows the session never touched. GRANT PROCESS ON *.* to the journal login",
                message(&e)
            ),
        }),
    }
    undo
}

/// Open a non-blocking binlog dump at `p` and read a few events.
async fn read_some(config: &Config, p: &Position) -> Result<(), String> {
    let conn = connect(config).await?;
    // Server id 0, as mysqlbinlog uses: a server disconnects any replica
    // already reading with the id a new reader gives, and 0 is nobody's.
    let mut stream = conn
        .get_binlog_stream(
            BinlogStreamRequest::new(0)
                .with_filename(p.file.as_bytes())
                .with_pos(p.pos)
                .with_non_blocking(),
        )
        .await
        .map_err(|e| message(&e))?;
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Err(e))) => return Err(message(&e)),
            Ok(Some(Ok(_))) => {}
            Ok(None) | Err(_) => break,
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.close()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        Config::from_toml(&format!(
            r#"
[database]
url = "postgres://localhost/app"

[mysql]
listen = "127.0.0.1:3307"
database = "shop"
{extra}

[[agents]]
name = "writer"
access = "read_only"
tables = ["x"]
token_env = "WRITER_TOKEN_TEST_ONLY"

[agents.mysql]
access = "read_write"
tables = ["orders", "other.items"]

[[agents]]
name = "reader"
access = "read_only"
tables = ["x"]
token_env = "READER_TOKEN_TEST_ONLY"

[agents.mysql]
access = "read_only"
tables = ["customers"]
"#
        ))
        .unwrap()
    }

    #[test]
    fn protected_tables_are_what_agents_may_write() {
        let p = Protected::from_config(&config(""));
        assert!(p.covers("shop", "orders"));
        assert!(p.covers("other", "items"));
        assert!(!p.covers("shop", "customers"), "read-only access");
        assert!(!p.covers("other", "orders"));
    }

    #[test]
    fn tag_table_defaults_to_the_agents_database() {
        assert_eq!(
            tag_table(&config("")),
            ("ariodb".into(), "session_tags".into())
        );
        assert_eq!(
            tag_table(&config("tag_table = \"tags\"")),
            ("shop".into(), "tags".into())
        );
    }

    #[test]
    fn lsns_keep_growing_when_the_binlog_starts_again() {
        let old = mysql_binlog::lsn("binlog.000120", 9_000);
        let raw = mysql_binlog::lsn("binlog.000001", 158);
        let base = next_base(old, raw);
        assert!(base + raw > old);
        assert!(base + mysql_binlog::lsn("binlog.000001", 900) > base + raw);
        // A server further on than the journal needs no base.
        assert_eq!(next_base(raw, old), 0);
        // Saved positions from before the base existed still load.
        let p: Position = serde_json::from_str(r#"{"file":"binlog.000001","pos":4}"#).unwrap();
        assert_eq!(p.base, 0);
        assert!(!serde_json::to_string(&p).unwrap().contains("base"));
    }

    #[test]
    fn a_half_written_last_line_is_dropped() {
        let dir = std::env::temp_dir().join(format!("ariodb-torn-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mysql-journal.jsonl");
        fs::write(&path, "{\"a\":1}\n{\"b\":").unwrap();
        drop_torn_line(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"a\":1}\n");
        drop_torn_line(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"a\":1}\n");
        fs::write(&path, "{\"b\":").unwrap();
        drop_torn_line(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn addresses() {
        assert_eq!(host_port("db:3307").unwrap(), ("db".into(), 3307));
        assert_eq!(host_port("[::1]:3306").unwrap(), ("::1".into(), 3306));
        assert_eq!(host_port("db").unwrap(), ("db".into(), 3306));
        assert!(host_port("db:x").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(quote_table("a`b", "c"), "`a``b`.`c`");
        assert_eq!(account("o'neil"), "'o''neil'@'%'");
    }
}
