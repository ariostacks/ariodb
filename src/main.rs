mod config;

use clap::{Parser, Subcommand};
use config::{Access, Config, FailureMode};
use std::path::PathBuf;
use std::process::ExitCode;

/// ariodb lets AI agents write to Postgres safely, and undoes what they changed.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a config file and print what it allows
    Check {
        /// Path to the config file
        #[arg(short, long, default_value = "ariodb.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check { config } => match Config::load(&config) {
            Ok(config) => {
                print_summary(&config);
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}

fn print_summary(config: &Config) {
    let on_failure = match config.on_failure {
        FailureMode::Closed => "refuse queries (fail closed)",
        FailureMode::Open => "let queries through (fail open)",
    };

    println!("database      {}", config::redact_url(&config.database.url));
    println!("row limit     {} rows per write", config.limits.max_rows_per_write);
    println!("timeout       {} ms", config.limits.statement_timeout_ms);
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
        println!("agent {:<16} {access:<15} {}", agent.name, agent.tables.join(", "));
    }
}
