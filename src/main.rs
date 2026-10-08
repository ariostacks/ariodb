mod approvals;
mod audit;
mod chsql;
mod classify;
mod clickhouse;
mod clickhouse_native;
mod config;
mod dashboard;
mod dashboard_api;
mod dashboard_ui;
mod exec;
mod gate;
mod journal;
mod mcp;
mod pgoutput;
mod policy;
mod proxy;
mod rules;
mod secrets;
mod store;
mod testing;
mod tls;
mod undo;
mod upstream;
mod wire;

use clap::{Parser, Subcommand};
use config::{Access, Config, FailureMode};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

/// ariodb lets AI agents write to Postgres safely, and undoes what they changed.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the config file
    #[arg(short, long, global = true, default_value = "ariodb.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the config file and print what it allows
    Check,
    /// Show how ariodb understands a SQL statement
    Classify {
        /// The SQL to classify
        sql: String,
    },
    /// Prepare the database for the journal (run once, as an admin)
    Setup,
    /// Run the proxy agents connect to, and the change journal
    Serve,
    /// Run an MCP server on stdio for one agent
    Mcp {
        /// The agent name from the config file
        #[arg(long)]
        agent: String,
    },
    /// List agent sessions that changed data
    Sessions,
    /// Undo everything one session changed
    Undo {
        /// The session id, from `ariodb sessions`
        #[arg(long)]
        session: String,
        /// Make the changes. Without this, only the plan is shown.
        #[arg(long)]
        apply: bool,
        /// Undo the rows nobody else has touched, and leave conflicting rows alone
        #[arg(long)]
        skip_conflicts: bool,
    },
    /// Check the audit log has not been edited
    Audit,
    /// Replay fixtures against the policy and report verdict drift (for CI)
    Test {
        /// A fixture .json file, or a directory of them
        fixtures: PathBuf,
    },
    /// List approval requests (pending ones unless --all)
    Approvals {
        #[arg(long)]
        all: bool,
    },
    /// Write recorded decisions as test fixtures for `ariodb test`
    ExportFixtures {
        /// Directory to write recorded.json into
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 500)]
        limit: i64,
    },
    /// Approve a pending request
    Approve {
        id: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Deny a pending request
    Deny {
        id: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Set a dashboard password (read from stdin). The first user is "root".
    DashboardPassword {
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Manage encrypted secrets (database URLs, agent tokens)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Show what the policy would decide for a statement, without running it
    Explain {
        /// The agent name from the config file
        #[arg(long)]
        agent: String,
        /// The SQL to judge
        sql: String,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Store a secret. The value is read from stdin, so it stays out of shell history.
    Set { name: String },
    /// List secret names (never values)
    List,
    /// Delete a secret
    Delete { name: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Command::Classify { sql } = &cli.command {
        return classify_command(sql);
    }

    let config = match Config::load(&cli.config) {
        Ok(c) => Arc::new(c),
        Err(err) => {
            eprintln!("error: {err}");
            // `test` promises exit code 2 for config errors.
            return ExitCode::from(if matches!(cli.command, Command::Test { .. }) {
                2
            } else {
                1
            });
        }
    };

    if let Command::Test { fixtures } = &cli.command {
        return match testing::load_fixtures(fixtures).and_then(|f| testing::run(&config, &f)) {
            Ok((passed, 0)) => {
                println!("\n{passed} fixtures match");
                ExitCode::SUCCESS
            }
            Ok((passed, drifted)) => {
                println!("\n{drifted} drifted, {passed} match");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }

    let result = match cli.command {
        Command::Check => {
            print_summary(&config);
            Ok(())
        }
        Command::Classify { .. } => unreachable!("handled above"),
        Command::Setup => journal::setup(&config).await,
        Command::Serve => match make_state(&config, &cli.config) {
            Ok(state) => serve(state).await,
            Err(e) => Err(e),
        },
        Command::Mcp { agent } => match make_state(&config, &cli.config) {
            Ok(state) => mcp::serve(state, &agent).await,
            Err(e) => Err(e),
        },
        Command::Sessions => sessions_command(&config),
        Command::Undo {
            session,
            apply,
            skip_conflicts,
        } => undo_command(&config, &session, apply, skip_conflicts).await,
        Command::Test { .. } => unreachable!("handled above"),
        Command::Secret { action } => secret_command(&config, action),
        Command::Approvals { all } => approvals_command(&config, all),
        Command::ExportFixtures { out, limit } => {
            audit::export_fixtures(Path::new(&config.journal.dir), &out, limit).map(|n| {
                println!(
                    "wrote {n} fixtures to {}",
                    out.join("recorded.json").display()
                )
            })
        }
        Command::Approve { id, note } => decide_command(&config, &id, true, note),
        Command::Deny { id, note } => decide_command(&config, &id, false, note),
        Command::DashboardPassword { user } => store::Db::open(Path::new(&config.journal.dir))
            .and_then(|db| {
                let mut password = String::new();
                std::io::stdin()
                    .read_line(&mut password)
                    .map_err(|e| e.to_string())?;
                dashboard::set_password(&db, &user, password.trim_end_matches(['\n', '\r']))?;
                println!("password set for '{user}'");
                Ok(())
            }),
        Command::Explain { agent, sql } => rules::RuleSet::compile(&config.rules).map(|rules| {
            let p = testing::preview(&config, &rules, &agent, &sql, "");
            let rule = if p.rule.is_empty() {
                "-".to_string()
            } else {
                p.rule.clone()
            };
            println!("{}  (decided by: {rule})  {}", p.verdict, p.reason);
        }),
        Command::Audit => audit::verify(Path::new(&config.journal.dir))
            .map(|n| println!("decisions log intact: {n} entries checked")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(message),
    }
}

fn fail(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn open_audit(config: &Config) -> Result<Arc<audit::AuditLog>, String> {
    audit::AuditLog::open(Path::new(&config.journal.dir), &config.audit)
        .map(Arc::new)
        .map_err(|e| format!("cannot open the decisions log: {e}"))
}

fn make_state(config: &Config, path: &Path) -> Result<Arc<gate::State>, String> {
    let audit = open_audit(config)?;
    let fresh = Config::load(path).map_err(|e| e.to_string())?;
    gate::State::new(fresh, path.to_path_buf(), audit)
}

async fn serve(state: Arc<gate::State>) -> Result<(), String> {
    tokio::spawn(gate::watch_config(state.clone()));
    let prune_state = state.clone();
    tokio::spawn(async move {
        loop {
            let config = prune_state.config();
            match audit::prune(Path::new(&config.journal.dir), &config.audit) {
                Ok(0) => {}
                Ok(n) => println!(
                    "ariodb: removed {n} decisions older than {} days",
                    config.audit.retention_days
                ),
                Err(e) => eprintln!("ariodb: could not prune the decisions log: {e}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
    let ch_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = clickhouse::serve_http(ch_state).await {
            eprintln!("ariodb: ClickHouse HTTP proxy stopped: {e}");
        }
    });
    let native_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = clickhouse_native::serve(native_state).await {
            eprintln!("ariodb: ClickHouse native proxy stopped: {e}");
        }
    });
    let dashboard_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = dashboard::serve(dashboard_state).await {
            eprintln!("ariodb: dashboard stopped: {e}");
        }
    });
    let config = state.config();
    if config.journal.enabled {
        let journal_config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = journal::run(&journal_config).await {
                eprintln!("ariodb: journal stopped: {e}");
            }
        });
    }
    proxy::serve(state)
        .await
        .map_err(|e| format!("proxy stopped: {e}"))
}

fn classify_command(sql: &str) -> ExitCode {
    match classify::classify(sql) {
        Ok(statements) => {
            for s in statements {
                let tables = if s.tables.is_empty() {
                    "-".to_string()
                } else {
                    s.tables.join(", ")
                };
                println!(
                    "{:<20} tables: {:<24} {}",
                    s.kind.to_string(),
                    tables,
                    s.reason
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e.to_string()),
    }
}

fn approvals_command(config: &Config, all: bool) -> Result<(), String> {
    let db = store::Db::open(Path::new(&config.journal.dir))?;
    let items = db.approvals(!all, 100)?;
    if items.is_empty() {
        println!(
            "{}",
            if all {
                "no approval requests"
            } else {
                "nothing waiting for approval"
            }
        );
    }
    for a in items {
        let by = a
            .decided_by
            .as_deref()
            .map(|b| format!("by {b}"))
            .unwrap_or_default();
        println!(
            "{}  {:<8} agent {:<14} rule {:<16} {:<28} {}",
            a.id, a.status, a.agent, a.rule, by, a.sql
        );
    }
    Ok(())
}

fn decide_command(
    config: &Config,
    id: &str,
    allow: bool,
    note: Option<String>,
) -> Result<(), String> {
    let db = store::Db::open(Path::new(&config.journal.dir))?;
    let who = format!("cli:{}", std::env::var("USER").unwrap_or_default());
    if db.decide(id, allow, &who, note.as_deref())? {
        println!("{} {id}", if allow { "approved" } else { "denied" });
        Ok(())
    } else {
        Err(format!(
            "{id} is not pending (already decided, expired, or unknown)"
        ))
    }
}

fn secret_command(config: &Config, action: SecretAction) -> Result<(), String> {
    let store = secrets::Store::open(Path::new(&config.journal.dir))?;
    match action {
        SecretAction::Set { name } => {
            let mut value = String::new();
            std::io::stdin()
                .read_line(&mut value)
                .map_err(|e| e.to_string())?;
            let value = value.trim_end_matches(['\n', '\r']);
            if value.is_empty() {
                return Err("no value on stdin".to_string());
            }
            store.set(&name, value)?;
            println!("stored secret '{name}'");
        }
        SecretAction::List => {
            for name in store.names()? {
                println!("{name}");
            }
        }
        SecretAction::Delete { name } => {
            if store.delete(&name)? {
                println!("deleted secret '{name}'");
            } else {
                return Err(format!("no secret named '{name}'"));
            }
        }
    }
    Ok(())
}

fn sessions_command(config: &Config) -> Result<(), String> {
    let records = journal::read_all(config)?;
    let sessions = undo::sessions(&records);
    if sessions.is_empty() {
        println!("no agent changes recorded yet");
        return Ok(());
    }
    println!(
        "{:<14} {:<16} {:>6} {:>6}  {:<10} tables",
        "session", "agent", "txns", "rows", "status"
    );
    for s in sessions {
        let status = if s.undone { "undone" } else { "" };
        println!(
            "{:<14} {:<16} {:>6} {:>6}  {:<10} {}",
            s.session,
            s.agent,
            s.transactions,
            s.rows,
            status,
            s.tables.join(", ")
        );
    }
    Ok(())
}

async fn undo_command(
    config: &Config,
    session: &str,
    apply: bool,
    skip_conflicts: bool,
) -> Result<(), String> {
    let records = journal::read_all(config)?;
    let mut client = undo::connect(config).await?;
    let plan = undo::plan(&client, &records, session).await?;

    if plan.already_undone {
        println!("note: this session was already undone");
    }
    println!("undo plan for {session}: {} steps", plan.steps.len());
    for step in &plan.steps {
        println!("  {}", step.description);
    }
    for c in &plan.conflicts {
        println!("  conflict: {}", c.text);
    }
    for b in &plan.blocked {
        println!("  cannot undo: {b}");
    }

    if !apply {
        println!("\nnothing changed. Run again with --apply to undo.");
        return Ok(());
    }
    let done = undo::apply(&mut client, &plan, skip_conflicts).await?;
    println!("\nundone: {done} rows restored in one transaction");
    Ok(())
}

fn print_summary(config: &Config) {
    let on_failure = match config.on_failure {
        FailureMode::Closed => "refuse queries (fail closed)",
        FailureMode::Open => "let queries through (fail open)",
    };

    println!(
        "database      {}",
        config::redact_url(&config.database_url())
    );
    println!(
        "row limit     {} rows per write",
        config.limits.max_rows_per_write
    );
    println!("timeout       {} ms", config.limits.statement_timeout_ms);
    println!("proxy         {}", config.proxy.listen);
    let journal = if config.journal.enabled {
        config.journal.dir.as_str()
    } else {
        "off"
    };
    println!("journal       {journal}");
    println!("if checks fail, {on_failure}");
    println!();

    if config.agents.is_empty() {
        println!("no agents configured: every agent will be refused");
        return;
    }
    for agent in &config.agents {
        let access = match agent.access {
            Access::ReadOnly => "read only",
            Access::ReadWrite => "read and write",
        };
        let token = if config.agent_token(agent).is_some() {
            "token set"
        } else {
            "no token"
        };
        println!(
            "agent {:<16} {access:<15} {:<10} {}",
            agent.name,
            token,
            agent.tables.join(", ")
        );
    }
}
