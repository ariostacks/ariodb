//! `ariodb doctor`: what this database can do with ariodb in front of it.
//!
//! Every check is read-only or runs in a transaction that is rolled back.
//! The results say which of ariodb's guarantees hold here: reads forced
//! read-only, writes measured before commit, and undo from the journal.

use crate::config::{Access, Config, WriteCheck};
use crate::upstream::{Target, admin_client};
use std::time::Duration;
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub status: Status,
    pub text: String,
}

/// One connection's findings.
#[derive(Debug, Clone)]
pub struct Section {
    pub title: String,
    pub findings: Vec<Finding>,
}

/// What works, and why not when it does not.
#[derive(Debug, Clone)]
pub struct Report {
    pub sections: Vec<Section>,
    /// Postgres, when ariodb fronts it.
    pub postgres: Option<Guarantees>,
    /// MySQL or MariaDB, when ariodb fronts it.
    pub mysql: Option<Guarantees>,
}

/// The three guarantees, for one engine.
#[derive(Debug, Clone)]
pub struct Guarantees {
    pub reads: Result<(), String>,
    pub writes: Result<(), String>,
    pub undo: Result<(), String>,
}

impl Guarantees {
    fn lines(&self) -> [(&'static str, &Result<(), String>); 3] {
        [
            ("reads, forced read-only", &self.reads),
            ("writes, checked before commit", &self.writes),
            ("undo of agent sessions", &self.undo),
        ]
    }

    fn summary(&self) -> String {
        let show = |r: &Result<(), String>| match r {
            Ok(()) => "yes".to_string(),
            Err(why) => format!("no ({why})"),
        };
        format!(
            "reads {}; checked writes {}; undo {}",
            show(&self.reads),
            show(&self.writes),
            show(&self.undo)
        )
    }
}

impl Report {
    pub fn failed(&self) -> bool {
        self.sections
            .iter()
            .flat_map(|s| &s.findings)
            .any(|f| f.status == Status::Fail)
    }

    pub fn print(&self) {
        for section in &self.sections {
            println!("{}", section.title);
            for f in &section.findings {
                let label = match f.status {
                    Status::Ok => "ok  ",
                    Status::Warn => "warn",
                    Status::Fail => "FAIL",
                };
                println!("  {label}  {}", f.text);
            }
            println!();
        }
        println!("what works here");
        // Postgres lines keep their plain wording; MySQL's are named.
        let engines = [("", &self.postgres), ("MySQL ", &self.mysql)];
        for (engine, g) in engines {
            let Some(g) = g else { continue };
            for (name, r) in g.lines() {
                match r {
                    Ok(()) => println!("  yes  {engine}{name}"),
                    Err(why) => println!("  no   {engine}{name}: {why}"),
                }
            }
        }
        if self.postgres.is_none() && self.mysql.is_none() {
            println!("  nothing: neither Postgres nor MySQL is configured");
        }
    }

    /// One line for the log when ariodb starts.
    pub fn summary(&self) -> String {
        match (&self.postgres, &self.mysql) {
            (Some(p), Some(m)) => format!("{}; MySQL: {}", p.summary(), m.summary()),
            (Some(p), None) => p.summary(),
            (None, Some(m)) => format!("MySQL: {}", m.summary()),
            (None, None) => "neither Postgres nor MySQL is configured".to_string(),
        }
    }
}

struct Checks {
    findings: Vec<Finding>,
}

impl Checks {
    fn ok(&mut self, text: impl Into<String>) {
        self.push(Status::Ok, text);
    }
    fn warn(&mut self, text: impl Into<String>) {
        self.push(Status::Warn, text);
    }
    fn fail(&mut self, text: impl Into<String>) {
        self.push(Status::Fail, text);
    }
    fn push(&mut self, status: Status, text: impl Into<String>) {
        self.findings.push(Finding {
            status,
            text: text.into(),
        });
    }
}

/// A column, or its type's default when it is missing or of another type:
/// Postgres-compatible databases differ in the types they return.
fn col<'a, T: tokio_postgres::types::FromSql<'a> + Default>(row: &'a tokio_postgres::Row, i: usize) -> T {
    row.try_get(i).unwrap_or_default()
}

fn message(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

/// What one agent login can do.
struct LoginResult {
    reads: Result<(), String>,
    writes: Result<(), String>,
}

/// A login to check: its label, and its target and URL (or why not).
type Login = (String, Result<(Target, String), String>);

pub async fn run(config: &Config) -> Report {
    let mut sections = Vec::new();
    // Postgres is configured unless both its proxy and journal are off.
    let postgres = if !config.proxy.listen.is_empty() || config.journal.enabled {
        Some(run_postgres(config, &mut sections).await)
    } else {
        None
    };
    let mysql = if config.mysql.listen.is_empty() {
        None
    } else {
        Some(run_mysql(config, &mut sections).await)
    };
    Report {
        sections,
        postgres,
        mysql,
    }
}

async fn run_postgres(config: &Config, sections: &mut Vec<Section>) -> Guarantees {
    let mut reads = Ok(());
    let mut writes = Ok(());

    // The default login, then each credential an agent uses.
    let mut logins: Vec<Login> = vec![(
        "default login".to_string(),
        config
            .admin_target(&config.database_url())
            .map(|t| (t, config.database_url())),
    )];
    let mut used: Vec<&str> = config
        .agents
        .iter()
        .filter_map(|a| a.credential.as_deref())
        .collect();
    used.sort();
    used.dedup();
    for name in used {
        logins.push((
            format!("credential '{name}'"),
            config.credential_target(name),
        ));
    }

    let mut version = None;
    for (label, login) in logins {
        let mut checks = Checks { findings: vec![] };
        let title = match &login {
            Ok((t, _)) => format!("{label}: {}@{}/{}", t.user, t.describe(), t.database),
            Err(_) => label.clone(),
        };
        let result = match login {
            Err(e) => {
                checks.fail(e.clone());
                LoginResult {
                    reads: Err(e.clone()),
                    writes: Err(e),
                }
            }
            Ok((target, url)) => {
                let work = check_login(config, &label, &target, &url, &mut checks, &mut version);
                match tokio::time::timeout(Duration::from_secs(30), work).await {
                    Ok(r) => r,
                    Err(_) => {
                        let why = "the checks took longer than 30 seconds".to_string();
                        checks.fail(why.clone());
                        LoginResult {
                            reads: Err(why.clone()),
                            writes: Err(why),
                        }
                    }
                }
            }
        };
        if reads.is_ok() {
            reads = result.reads.map_err(|e| format!("{label}: {e}"));
        }
        if writes.is_ok() {
            writes = result.writes.map_err(|e| format!("{label}: {e}"));
        }
        sections.push(Section {
            title,
            findings: checks.findings,
        });
    }
    if !config.agents.iter().any(|a| a.access == Access::ReadWrite) && writes.is_ok() {
        writes = Err("no agent has write access".to_string());
    }

    let undo = if config.journal.enabled {
        let mut checks = Checks { findings: vec![] };
        let url = crate::journal::journal_url(config);
        let title = match config.admin_target(&url) {
            Ok(t) => format!("journal: {}@{}/{}", t.user, t.describe(), t.database),
            Err(_) => "journal".to_string(),
        };
        let work = check_journal(config, &url, &mut checks);
        let undo = match tokio::time::timeout(Duration::from_secs(30), work).await {
            Ok(r) => r,
            Err(_) => {
                checks.fail("the checks took longer than 30 seconds");
                Err("the journal checks timed out".to_string())
            }
        };
        sections.push(Section {
            title,
            findings: checks.findings,
        });
        undo
    } else {
        Err("the journal is off ([journal] enabled = false)".to_string())
    };
    // Writes are tagged for the journal, so they need the journal's checks
    // on the gateway side too; those ran per login above.
    Guarantees {
        reads,
        writes,
        undo,
    }
}

async fn check_login(
    config: &Config,
    label: &str,
    target: &Target,
    url: &str,
    checks: &mut Checks,
    version: &mut Option<String>,
) -> LoginResult {
    let client = match admin_client(target, url).await {
        Ok(c) => c,
        Err(e) => {
            checks.fail(e.clone());
            return LoginResult {
                reads: Err(e.clone()),
                writes: Err(e),
            };
        }
    };
    let _ = client.batch_execute("SET statement_timeout = 5000").await;
    let tls = client
        .query_opt(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .ok()
        .flatten()
        .map(|r| col::<bool>(&r, 0));
    match tls {
        Some(true) => checks.ok("connected over TLS"),
        Some(false) if target.host == "localhost" || target.host.starts_with("127.") => {
            checks.ok("connected (no TLS, local database)")
        }
        Some(false) => checks.warn("connected without TLS; set [database] tls = \"verify\""),
        None => checks.ok("connected"),
    }

    if version.is_none() {
        let v = describe_server(&client).await;
        checks.ok(v.clone());
        *version = Some(v);
    }

    let reads = check_read_only(&client, checks).await;
    let product = version.as_deref().unwrap_or("");
    let cannot_measure = if product.contains("-YB-") {
        Some("YugabyteDB")
    } else if product.starts_with("CockroachDB") {
        Some("CockroachDB")
    } else {
        None
    };
    let mut writes = if config.database.write_check == WriteCheck::Reported {
        checks.warn(
            "writes are judged by the row counts the database reports (write_check = \"reported\"): row limits and after-write rules apply, but changes made by triggers, cascades and functions are not seen",
        );
        Ok(())
    } else if let Some(name) = cannot_measure {
        let why = format!("{name} does not count changes to its tables in pg_stat_xact_user_tables");
        checks.fail(format!(
            "{why}, so ariodb rolls back every write. Set [database] write_check = \"reported\" to allow writes with a weaker check"
        ));
        Err(why)
    } else {
        check_effects(&client, checks).await
    };
    if config.journal.enabled {
        let tagged = check_tagging(&client, checks).await;
        if writes.is_ok() {
            writes = tagged;
        }
    }
    check_tables(config, label, &client, checks).await;
    LoginResult { reads, writes }
}

/// The server's name and version, and the product when it is not plain
/// Postgres.
async fn describe_server(client: &Client) -> String {
    let full: String = match client.query_one("SELECT version()", &[]).await {
        Ok(r) => col(&r, 0),
        Err(e) => return format!("server version unknown: {}", message(&e)),
    };
    let short = full.split(" on ").next().unwrap_or(&full).trim().to_string();
    let probe = |sql: &'static str| async move {
        client
            .query_opt(sql, &[])
            .await
            .ok()
            .flatten()
            .is_some()
    };
    let mut also = Vec::new();
    if probe("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'").await {
        also.push("TimescaleDB");
    }
    if probe("SELECT 1 FROM pg_proc WHERE proname = 'aurora_version'").await {
        also.push("Amazon Aurora");
    }
    if probe("SELECT 1 FROM pg_roles WHERE rolname = 'supabase_admin'").await {
        also.push("Supabase");
    }
    if probe("SELECT 1 FROM pg_settings WHERE name LIKE 'neon.%'").await {
        also.push("Neon");
    }
    if probe("SELECT 1 FROM pg_settings WHERE name LIKE 'alloydb.%'").await {
        also.push("AlloyDB");
    }
    if also.is_empty() {
        short
    } else {
        format!("{short} ({})", also.join(", "))
    }
}

/// Reads run in READ ONLY transactions; the database must enforce that.
async fn check_read_only(client: &Client, checks: &mut Checks) -> Result<(), String> {
    if let Err(e) = client
        .batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = 3000")
        .await
    {
        let why = format!("READ ONLY transactions are not available: {}", message(&e));
        checks.fail(why.clone());
        let _ = client.batch_execute("ROLLBACK").await;
        return Err(why);
    }
    let attempt = client
        .batch_execute("CREATE TEMP TABLE ariodb_doctor_ro (x int)")
        .await;
    let _ = client.batch_execute("ROLLBACK").await;
    match attempt {
        Err(e) if e.code() == Some(&SqlState::READ_ONLY_SQL_TRANSACTION) => {
            checks.ok("reads run in READ ONLY transactions, and the database enforces them");
            Ok(())
        }
        Err(e) => {
            // Refused for another reason, so enforcement was not shown.
            checks.warn(format!(
                "reads run in READ ONLY transactions; enforcement could not be tested ({})",
                message(&e)
            ));
            Ok(())
        }
        Ok(()) => {
            let why = "the database let a READ ONLY transaction create a table".to_string();
            checks.fail(why.clone());
            Err(why)
        }
    }
}

/// Writes are judged by `pg_stat_xact_user_tables` before commit.
async fn check_effects(client: &Client, checks: &mut Checks) -> Result<(), String> {
    let _ = client
        .batch_execute("BEGIN; SET LOCAL statement_timeout = 3000")
        .await;
    let wrote = client
        .batch_execute("CREATE TEMP TABLE ariodb_doctor (x int); INSERT INTO ariodb_doctor VALUES (1), (2), (3)")
        .await;
    if let Err(e) = &wrote {
        // No temp table rights: at least check the view answers.
        let _ = client.batch_execute("ROLLBACK").await;
        let _ = client.batch_execute("BEGIN").await;
        let probe = client.query(crate::gate::EFFECTS_SQL, &[]).await;
        let _ = client.batch_execute("ROLLBACK").await;
        return match probe {
            Ok(_) => {
                checks.warn(format!(
                    "pg_stat_xact_user_tables answers, but a test write could not confirm it counts ({}); ariodb rolls back any write whose measurement falls short of the rows the database reports",
                    message(e)
                ));
                Err("not confirmed: the test write could not run".to_string())
            }
            Err(e) => effects_unavailable(checks, &message(&e)),
        };
    }
    let rows = client.query(crate::gate::EFFECTS_SQL, &[]).await;
    let _ = client.batch_execute("ROLLBACK").await;
    match rows {
        Ok(rows) => {
            let seen = rows.iter().any(|r| {
                col::<Option<String>>(r, 0)
                    .is_some_and(|t| t.ends_with(".ariodb_doctor"))
                    && col::<Option<i64>>(r, 1) == Some(3)
            });
            if seen {
                checks.ok("writes are measured before commit (a 3-row test write counted 3)");
                Ok(())
            } else {
                let why = "pg_stat_xact_user_tables did not count a test write".to_string();
                checks.fail(format!(
                    "{why}, so ariodb cannot see what a write did and refuses every write"
                ));
                Err(why)
            }
        }
        Err(e) => effects_unavailable(checks, &message(&e)),
    }
}

fn effects_unavailable(checks: &mut Checks, why: &str) -> Result<(), String> {
    checks.fail(format!(
        "writes cannot be measured ({why}), so ariodb refuses every write; read_only agents still work. [database] write_check = \"reported\" allows writes with a weaker check"
    ));
    Err("the database cannot report what a write changed".to_string())
}

/// With the journal on, each write transaction is tagged with its session.
async fn check_tagging(client: &Client, checks: &mut Checks) -> Result<(), String> {
    let r = client
        .batch_execute(
            "BEGIN; SELECT pg_logical_emit_message(true, 'ariodb-doctor', 'test'); ROLLBACK",
        )
        .await;
    match r {
        Ok(()) => {
            checks.ok("writes can be tagged with their session for the journal");
            Ok(())
        }
        Err(e) => {
            let _ = client.batch_execute("ROLLBACK").await;
            let why = format!("writes cannot be tagged for the journal: {}", message(&e));
            checks.fail(format!(
                "{why}; every write will fail while the journal is on. Set [journal] enabled = false to write without undo"
            ));
            Err(why)
        }
    }
}

/// Each agent's tables exist and this login can use them as the agent would.
async fn check_tables(config: &Config, label: &str, client: &Client, checks: &mut Checks) {
    let mut problems = 0;
    for agent in &config.agents {
        let uses_this = match &agent.credential {
            None => label == "default login",
            Some(name) => label == format!("credential '{name}'"),
        };
        if !uses_this {
            continue;
        }
        for table in agent.tables.iter().filter(|t| *t != "*") {
            let row = client
                .query_one(
                    "SELECT to_regclass($1) IS NOT NULL,
                            CASE WHEN to_regclass($1) IS NULL THEN false ELSE has_table_privilege(to_regclass($1), 'SELECT') END,
                            CASE WHEN to_regclass($1) IS NULL THEN false ELSE has_table_privilege(to_regclass($1), 'INSERT, UPDATE, DELETE') END",
                    &[table],
                )
                .await;
            let Ok(row) = row else { continue };
            let (exists, can_read, can_write): (bool, bool, bool) = (col(&row, 0), col(&row, 1), col(&row, 2));
            if !exists {
                problems += 1;
                checks.warn(format!("agent '{}': table '{table}' does not exist", agent.name));
            } else if !can_read {
                problems += 1;
                checks.warn(format!(
                    "agent '{}': this login cannot read '{table}'",
                    agent.name
                ));
            } else if agent.access == Access::ReadWrite && !can_write {
                problems += 1;
                checks.warn(format!(
                    "agent '{}': this login cannot change '{table}'",
                    agent.name
                ));
            }
        }
    }
    if problems == 0 {
        checks.ok("every agent table exists and this login can use it");
    }
}

/// Everything undo needs: logical replication, the slot and publication
/// from `ariodb setup`, and full before-images on protected tables.
async fn check_journal(config: &Config, url: &str, checks: &mut Checks) -> Result<(), String> {
    let client = match config.admin_target(url) {
        Ok(t) => admin_client(&t, url).await,
        Err(e) => Err(e),
    };
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            checks.fail(e.clone());
            return Err(e);
        }
    };
    let _ = client.batch_execute("SET statement_timeout = 5000").await;
    let mut undo: Result<(), String> = Ok(());

    let version: i32 = match client
        .query_one("SELECT current_setting('server_version_num')", &[])
        .await
    {
        Ok(r) => col::<String>(&r, 0).parse().unwrap_or(0),
        Err(e) => {
            let why = format!("cannot read the server version: {}", message(&e));
            checks.fail(why.clone());
            return Err(why);
        }
    };
    match client.query_one("SHOW wal_level", &[]).await {
        Ok(r) if col::<String>(&r, 0) == "logical" => checks.ok("wal_level is logical"),
        Ok(r) => fail(
            checks,
            &mut undo,
            format!(
                "wal_level is '{}'; set it to 'logical' and restart (on managed services, turn on logical replication)",
                col::<String>(&r, 0)
            ),
            "logical replication is off",
        ),
        Err(e) => {
            // Not Postgres replication at all; the other checks would only repeat it.
            let why = format!(
                "this database has no Postgres logical replication ({}), so undo is not available. Set [journal] enabled = false",
                message(&e)
            );
            checks.fail(why);
            return Err("the database has no Postgres logical replication".to_string());
        }
    }

    if version < 140000 {
        fail(
            checks,
            &mut undo,
            "Postgres 14 or later is needed for undo: before 14 the change stream cannot carry the session tags. Set [journal] enabled = false".to_string(),
            "needs Postgres 14 or later",
        );
    }

    let slot = &config.journal.slot;
    let publication = &config.journal.publication;
    match client
        .query_opt(
            "SELECT plugin, database = current_database() FROM pg_replication_slots WHERE slot_name = $1",
            &[slot],
        )
        .await
    {
        Ok(Some(r)) if col::<Option<String>>(&r, 0).as_deref() == Some("pgoutput") && col::<Option<bool>>(&r, 1) == Some(true) => {
            checks.ok(format!("replication slot '{slot}' exists"))
        }
        Ok(Some(_)) => fail(
            checks,
            &mut undo,
            format!("replication slot '{slot}' belongs to another database or plugin; pick another [journal] slot name"),
            "the replication slot is not ariodb's",
        ),
        Ok(None) => fail(
            checks,
            &mut undo,
            format!("replication slot '{slot}' does not exist; run `ariodb setup`"),
            "not set up (run ariodb setup)",
        ),
        Err(e) => fail(
            checks,
            &mut undo,
            format!("cannot list replication slots: {}", message(&e)),
            "replication slots are not available",
        ),
    }

    let protected = protected_tables(config, &client).await;
    match client
        .query(
            "SELECT schemaname || '.' || tablename FROM pg_publication_tables WHERE pubname = $1",
            &[publication],
        )
        .await
    {
        Ok(rows) => {
            let listed: Vec<String> = rows
                .iter()
                .map(|r| crate::classify::normalise_table(&col::<String>(r, 0)))
                .collect();
            let missing: Vec<&String> = protected.iter().filter(|t| !listed.contains(t)).collect();
            if rows.is_empty()
                && client
                    .query_opt("SELECT 1 FROM pg_publication WHERE pubname = $1", &[publication])
                    .await
                    .ok()
                    .flatten()
                    .is_none()
            {
                fail(
                    checks,
                    &mut undo,
                    format!("publication '{publication}' does not exist; run `ariodb setup`"),
                    "not set up (run ariodb setup)",
                );
            } else if missing.is_empty() {
                checks.ok(format!("publication '{publication}' covers every table agents may change"));
            } else {
                fail(
                    checks,
                    &mut undo,
                    format!(
                        "publication '{publication}' leaves out {}; run `ariodb setup` again",
                        missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                    "some tables are not journalled (run ariodb setup)",
                );
            }
        }
        Err(e) => fail(
            checks,
            &mut undo,
            format!("cannot read publications: {}", message(&e)),
            "publications are not available",
        ),
    }

    let mut not_full = Vec::new();
    for table in &protected {
        let r = client
            .query_opt(
                "SELECT relreplident::text FROM pg_class WHERE oid = to_regclass($1)",
                &[table],
            )
            .await;
        if let Ok(Some(r)) = r
            && col::<String>(&r, 0) != "f"
        {
            not_full.push(table.clone());
        }
    }
    if not_full.is_empty() {
        if !protected.is_empty() {
            checks.ok("protected tables keep full before-images (REPLICA IDENTITY FULL)");
        }
    } else {
        fail(
            checks,
            &mut undo,
            format!(
                "tables without full before-images (REPLICA IDENTITY FULL): {}; run `ariodb setup` again",
                not_full.join(", ")
            ),
            "some tables lack full before-images (run ariodb setup)",
        );
    }

    if version >= 180000 {
        let gencols = client
            .query_opt(
                "SELECT pubgencols::text FROM pg_publication WHERE pubname = $1",
                &[publication],
            )
            .await;
        if let Ok(Some(r)) = gencols
            && col::<String>(&r, 0) != "s"
        {
            fail(
                checks,
                &mut undo,
                "Postgres 18 refuses updates to tables with generated columns until the publication includes them; run `ariodb setup` again".to_string(),
                "the publication needs generated columns (run ariodb setup)",
            );
        }
    }

    // Read the stream the way the journal does, without consuming it.
    if undo.is_ok() {
        let peek = client
            .query(
                "SELECT 1 FROM pg_logical_slot_peek_binary_changes(
                     $1, NULL, 1,
                     'proto_version', '1', 'publication_names', $2, 'messages', 'true')",
                &[slot, publication],
            )
            .await;
        match peek {
            Ok(_) => checks.ok("the change stream can be read, with session tags"),
            Err(e) => fail(
                checks,
                &mut undo,
                format!("the change stream cannot be read: {}", message(&e)),
                "the change stream cannot be read",
            ),
        }
        if let Ok(Some(r)) = client
            .query_opt(
                "SELECT pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)),
                        pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 1073741824
                 FROM pg_replication_slots WHERE slot_name = $1",
                &[slot],
            )
            .await
        {
            let (size, big): (Option<String>, Option<bool>) = (col(&r, 0), col(&r, 1));
            if let Some(size) = size {
                if big == Some(true) {
                    checks.warn(format!(
                        "the slot holds back {size} of WAL; is `ariodb serve` running?"
                    ));
                } else {
                    checks.ok(format!("the slot holds back {size} of WAL"));
                }
            }
        }
    }
    undo
}

fn fail(checks: &mut Checks, undo: &mut Result<(), String>, text: String, short: &str) {
    checks.fail(text);
    if undo.is_ok() {
        *undo = Err(short.to_string());
    }
}

/// The tables undo must cover, expanding `*` the way setup does.
async fn protected_tables(config: &Config, client: &Client) -> Vec<String> {
    let mut tables = config.protected_tables();
    let wildcard = config
        .agents
        .iter()
        .any(|a| a.access == Access::ReadWrite && a.tables.iter().any(|t| t == "*"));
    if wildcard
        && let Ok(rows) = client
            .query(
                "SELECT table_schema || '.' || table_name FROM information_schema.tables
                 WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')",
                &[],
            )
            .await
    {
        tables.extend(
            rows.iter()
                .map(|r| crate::classify::normalise_table(&col::<String>(r, 0))),
        );
        tables.sort();
        tables.dedup();
    }
    tables
}

// ---------------------------------------------------------------------------
// MySQL and MariaDB

/// The gateway login agents' queries run as, then the journal login.
async fn run_mysql(config: &Config, sections: &mut Vec<Section>) -> Guarantees {
    let mut checks = Checks { findings: vec![] };
    let title = format!(
        "mysql gateway: {}@{}/{}",
        config.mysql.user, config.mysql.addr, config.mysql.database
    );
    let work = check_mysql_gateway(config, &mut checks);
    let (reads, mut writes) = match tokio::time::timeout(Duration::from_secs(30), work).await {
        Ok(r) => r,
        Err(_) => {
            let why = "the checks took longer than 30 seconds".to_string();
            checks.fail(why.clone());
            (Err(why.clone()), Err(why))
        }
    };
    sections.push(Section {
        title,
        findings: checks.findings,
    });
    let writers = config
        .agents
        .iter()
        .filter_map(|a| a.mysql.as_ref())
        .any(|m| m.access == Access::ReadWrite);
    if !writers && writes.is_ok() {
        writes = Err("no agent has MySQL write access".to_string());
    }
    let undo = if config.mysql.journal {
        let (section, undo) = crate::mysql_journal::doctor(config).await;
        sections.push(section);
        undo
    } else {
        Err("the MySQL journal is off ([mysql] journal = false)".to_string())
    };
    Guarantees {
        reads,
        writes,
        undo,
    }
}

/// Run `sql` and expect it to fail; returns the error, or None if it ran.
async fn mysql_error(conn: &mut mysql_async::Conn, sql: &str) -> Option<mysql_async::Error> {
    use mysql_async::prelude::Queryable;
    conn.query_drop(sql).await.err()
}

async fn check_mysql_gateway(
    config: &Config,
    checks: &mut Checks,
) -> (Result<(), String>, Result<(), String>) {
    use crate::mysql_journal::{code, message, quote_table};
    use mysql_async::prelude::Queryable;
    let fail_both = |checks: &mut Checks, why: String| {
        checks.fail(why.clone());
        (Err(why.clone()), Err(why))
    };
    let password = match config.mysql_password() {
        Ok(p) => p,
        Err(e) => return fail_both(checks, e),
    };
    let mut conn = match crate::mysql_journal::connect_as(config, &config.mysql.user, &password).await {
        Ok(c) => c,
        Err(e) => return fail_both(checks, e),
    };
    let cipher: Option<(String, String)> = conn
        .query_first("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        .await
        .ok()
        .flatten();
    let host = config.mysql.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
    match cipher {
        Some((_, c)) if !c.is_empty() => checks.ok("connected over TLS"),
        _ if host == "localhost" || host.starts_with("127.") || host == "[::1]" => {
            checks.ok("connected (no TLS, local database)")
        }
        _ => checks.warn("connected without TLS; set [mysql] tls = \"verify\""),
    }
    match conn.query_first::<String, _>("SELECT VERSION()").await {
        Ok(Some(v)) if v.contains("MariaDB") => {
            checks.ok(format!("MariaDB {}", v.split('-').next().unwrap_or(&v)))
        }
        Ok(Some(v)) => checks.ok(format!("MySQL {v}")),
        Ok(None) => checks.warn("server version unknown"),
        Err(e) => checks.warn(format!("server version unknown: {}", message(&e))),
    }
    let _ = conn.query_drop("SET SESSION innodb_lock_wait_timeout = 3").await;

    let (db, table) = crate::mysql_journal::tag_table(config);
    let tag = quote_table(&db, &table);
    let insert = format!("INSERT INTO {tag} (session, agent) VALUES ('doctor', 'ariodb-doctor')");

    // Reads run in READ ONLY transactions; the server must refuse a write.
    let reads = match mysql_error(&mut conn, "START TRANSACTION READ ONLY").await {
        Some(e) => {
            let why = format!("READ ONLY transactions are not available: {}", message(&e));
            checks.fail(why.clone());
            Err(why)
        }
        None => {
            let attempt = mysql_error(&mut conn, &insert).await;
            let _ = conn.query_drop("ROLLBACK").await;
            match attempt {
                Some(e) if code(&e) == Some(1792) => {
                    checks.ok("reads run in READ ONLY transactions, and the server enforces them");
                    Ok(())
                }
                Some(e) => {
                    checks.warn(format!(
                        "reads run in READ ONLY transactions; enforcement could not be tested ({})",
                        message(&e)
                    ));
                    Ok(())
                }
                None => {
                    let why = "the server let a READ ONLY transaction insert a row".to_string();
                    checks.fail(why.clone());
                    Err(why)
                }
            }
        }
    };

    // Writes: tagged for the journal, and counted by InnoDB before commit.
    let mut writes = Ok(());
    let _ = conn.query_drop("START TRANSACTION").await;
    let wrote = if config.mysql.journal {
        match mysql_error(&mut conn, &insert).await {
            None => {
                checks.ok("writes can be tagged with their session for the journal");
                true
            }
            Some(e) => {
                let why = format!("writes cannot be tagged for the journal: {}", message(&e));
                let hint = if code(&e) == Some(1146) {
                    "run `ariodb setup`".to_string()
                } else {
                    format!("GRANT INSERT ON {tag} to this login")
                };
                checks.fail(format!(
                    "{why}; every write will fail while the journal is on. {hint}, or set [mysql] journal = false to write without undo"
                ));
                writes = Err(why);
                false
            }
        }
    } else {
        let made = mysql_error(
            &mut conn,
            "CREATE TEMPORARY TABLE ariodb_doctor (x INT) ENGINE = InnoDB",
        )
        .await
        .is_none();
        made && mysql_error(&mut conn, "INSERT INTO ariodb_doctor VALUES (1)").await.is_none()
    };
    // InnoDB refreshes innodb_trx at most every 0.1 seconds after a read.
    tokio::time::sleep(Duration::from_millis(110)).await;
    let counted: Result<Option<i64>, _> = conn
        .query_first(
            "SELECT CAST(trx_rows_modified AS SIGNED) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = CONNECTION_ID()",
        )
        .await;
    let _ = conn.query_drop("ROLLBACK").await;
    let _ = conn.query_drop("DROP TEMPORARY TABLE IF EXISTS ariodb_doctor").await;
    match counted {
        Ok(Some(n)) if wrote && n >= 1 => checks.ok(format!(
            "writes are counted before commit, triggers and cascades included (a 1-row test write counted {n})"
        )),
        Ok(_) if !wrote => checks.warn(
            "InnoDB's count of rows a write changed is readable, but a test write could not confirm it",
        ),
        Ok(_) => checks.warn(
            "InnoDB did not count a test write; writes are judged by the row counts the server reports, so rows changed by triggers and cascades are not seen",
        ),
        Err(e) => checks.warn(format!(
            "InnoDB's count of rows a write changed cannot be read ({}); writes are judged by the row counts the server reports, so rows changed by triggers and cascades are not seen. GRANT PROCESS ON *.* to this login",
            message(&e)
        )),
    }

    // Each agent's MySQL tables exist.
    let mut missing = 0;
    for agent in &config.agents {
        let Some(access) = &agent.mysql else { continue };
        for t in access.tables.iter().filter(|t| *t != "*") {
            let (d, name) = match t.split_once('.') {
                Some((d, n)) => (d.to_string(), n.to_string()),
                None => (config.mysql.database.clone(), t.clone()),
            };
            let found: Result<Option<u8>, _> = conn
                .exec_first(
                    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
                    (&d, &name),
                )
                .await;
            if let Ok(None) = found {
                missing += 1;
                checks.warn(format!(
                    "agent '{}': MySQL table '{d}.{name}' does not exist or this login cannot see it",
                    agent.name
                ));
            }
        }
    }
    if missing == 0 {
        checks.ok("every agent table exists and this login can see it");
    }
    let _ = conn.disconnect().await;
    (reads, writes)
}
