//! Running statements for one agent session.
//!
//! Reads run in a READ ONLY transaction. Writes run in a transaction that is
//! measured before commit: if it touched more rows than allowed, or any table
//! the agent may not change (through a trigger, cascade or function), it is
//! rolled back. The check is on what actually happened, not on how the SQL
//! was written.

use crate::audit::{AuditLog, Entry};
use crate::classify::{self, Statement};
use crate::config::{Agent, Config, Limits};
use crate::policy::{self, Decision, Mode};
use std::sync::Arc;
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

/// The result of one statement, ready to send back to the agent.
#[derive(Debug)]
pub enum Outcome {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    Done {
        command: String,
        rows: u64,
    },
    /// ariodb refused the statement, or rolled it back.
    Refused {
        message: String,
    },
    /// Postgres reported an error.
    Failed {
        code: String,
        message: String,
    },
}

pub struct Session {
    pub id: String,
    agent: Agent,
    limits: Limits,
    journal: bool,
    client: Client,
    audit: Arc<AuditLog>,
}

/// One table's changes inside the current transaction.
struct Effect {
    table: String,
    rows: i64,
}

impl Session {
    pub async fn connect(
        config: &Config,
        agent: Agent,
        audit: Arc<AuditLog>,
    ) -> Result<Session, String> {
        let (client, connection) = tokio_postgres::connect(&config.database_url(), NoTls)
            .await
            .map_err(|e| format!("cannot connect to the database: {e}"))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("ariodb: database connection closed: {e}");
            }
        });
        client
            .batch_execute(&format!(
                "SET application_name = 'ariodb:{}'",
                agent.name.replace('\'', "")
            ))
            .await
            .map_err(|e| format!("cannot configure connection: {e}"))?;

        let id = format!("s-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        Ok(Session {
            id,
            agent,
            limits: config.limits.clone(),
            journal: config.journal.enabled,
            client,
            audit,
        })
    }

    pub fn agent_name(&self) -> &str {
        &self.agent.name
    }

    /// Run a query string. Like Postgres, stop at the first statement that
    /// fails or is refused.
    pub async fn run(&mut self, sql: &str) -> Vec<Outcome> {
        let statements = match classify::classify(sql) {
            Ok(s) => s,
            Err(e) => {
                let message = e.to_string();
                self.log(sql, "unknown".into(), &[], "refused", None, Some(&message));
                return vec![Outcome::Refused { message }];
            }
        };
        let mut outcomes = Vec::new();
        for stmt in &statements {
            let outcome = self.run_one(stmt).await;
            let stop = matches!(outcome, Outcome::Refused { .. } | Outcome::Failed { .. });
            outcomes.push(outcome);
            if stop {
                break;
            }
        }
        outcomes
    }

    async fn run_one(&mut self, stmt: &Statement) -> Outcome {
        match policy::decide(&self.agent, stmt) {
            Decision::Deny(reason) => {
                self.log_stmt(stmt, "refused", None, Some(&reason));
                Outcome::Refused { message: reason }
            }
            Decision::Allow(Mode::ReadOnly) => self.run_read(stmt).await,
            Decision::Allow(Mode::CheckedWrite) => self.run_write(stmt).await,
        }
    }

    async fn run_read(&mut self, stmt: &Statement) -> Outcome {
        let begin = format!(
            "BEGIN READ ONLY; SET LOCAL statement_timeout = {}",
            self.limits.statement_timeout_ms
        );
        if let Err(e) = self.client.batch_execute(&begin).await {
            return self.failed(stmt, e).await;
        }
        let result = self.client.simple_query(&stmt.sql).await;
        match result {
            Ok(messages) => {
                let _ = self.client.batch_execute("COMMIT").await;
                let outcome = to_outcome(stmt, messages);
                self.log_stmt(stmt, "allowed", Some(row_count(&outcome)), None);
                outcome
            }
            Err(e) => self.failed(stmt, e).await,
        }
    }

    async fn run_write(&mut self, stmt: &Statement) -> Outcome {
        let limit = self
            .agent
            .max_rows_per_write
            .unwrap_or(self.limits.max_rows_per_write);
        let begin = format!(
            "BEGIN; SET LOCAL statement_timeout = {}",
            self.limits.statement_timeout_ms
        );
        if let Err(e) = self.client.batch_execute(&begin).await {
            return self.failed(stmt, e).await;
        }

        // Tag the transaction so the journal knows which session made it.
        if self.journal {
            let tag =
                serde_json::json!({ "session": self.id, "agent": self.agent.name }).to_string();
            let tagged = self
                .client
                .execute(
                    "SELECT pg_logical_emit_message(true, 'ariodb', $1::text)",
                    &[&tag],
                )
                .await;
            if let Err(e) = tagged {
                return self.failed(stmt, e).await;
            }
        }

        let messages = match self.client.simple_query(&stmt.sql).await {
            Ok(m) => m,
            Err(e) => return self.failed(stmt, e).await,
        };
        let effects = match self.effects().await {
            Ok(e) => e,
            Err(e) => return self.failed(stmt, e).await,
        };

        let total: i64 = effects.iter().map(|e| e.rows).sum();
        let summary = effects
            .iter()
            .map(|e| format!("{} {}", e.rows, e.table))
            .collect::<Vec<_>>()
            .join(", ");

        if let Some(bad) = effects.iter().find(|e| !self.agent.allows_table(&e.table)) {
            let reason = format!(
                "rolled back: the statement also changed table '{}', which agent '{}' may not change ({summary})",
                bad.table, self.agent.name
            );
            return self.roll_back(stmt, total, reason).await;
        }
        if total > limit as i64 {
            let reason = format!(
                "rolled back: the statement would change {total} rows ({summary}); the limit is {limit}"
            );
            return self.roll_back(stmt, total, reason).await;
        }

        if let Err(e) = self.client.batch_execute("COMMIT").await {
            return self.failed(stmt, e).await;
        }
        let outcome = to_outcome(stmt, messages);
        self.log_stmt(stmt, "allowed", Some(total.max(0) as u64), None);
        outcome
    }

    /// Every table changed in the current transaction, with row counts.
    /// Includes changes made by triggers, cascades and functions.
    async fn effects(&self) -> Result<Vec<Effect>, tokio_postgres::Error> {
        let rows = self
            .client
            .query(
                "SELECT schemaname, relname, (n_tup_ins + n_tup_upd + n_tup_del)::bigint
                 FROM pg_stat_xact_user_tables
                 WHERE n_tup_ins + n_tup_upd + n_tup_del > 0
                 ORDER BY 1, 2",
                &[],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let schema: String = r.get(0);
                let name: String = r.get(1);
                Effect {
                    table: classify::normalise_table(&format!("{schema}.{name}")),
                    rows: r.get(2),
                }
            })
            .collect())
    }

    async fn roll_back(&mut self, stmt: &Statement, rows: i64, reason: String) -> Outcome {
        let _ = self.client.batch_execute("ROLLBACK").await;
        self.log_stmt(stmt, "rolled_back", Some(rows.max(0) as u64), Some(&reason));
        Outcome::Refused { message: reason }
    }

    async fn failed(&mut self, stmt: &Statement, e: tokio_postgres::Error) -> Outcome {
        let _ = self.client.batch_execute("ROLLBACK").await;
        let (code, message) = match e.as_db_error() {
            Some(db) => (db.code().code().to_string(), db.message().to_string()),
            None => ("08006".to_string(), e.to_string()),
        };
        self.log_stmt(stmt, "failed", None, Some(&message));
        Outcome::Failed { code, message }
    }

    fn log_stmt(&self, stmt: &Statement, outcome: &str, rows: Option<u64>, reason: Option<&str>) {
        self.log(
            &stmt.sql,
            stmt.kind.to_string(),
            &stmt.tables,
            outcome,
            rows,
            reason,
        );
    }

    fn log(
        &self,
        sql: &str,
        kind: String,
        tables: &[String],
        outcome: &str,
        rows: Option<u64>,
        reason: Option<&str>,
    ) {
        self.audit.record(&Entry {
            session: &self.id,
            agent: &self.agent.name,
            sql,
            kind,
            tables,
            outcome,
            rows,
            reason,
        });
    }
}

fn to_outcome(stmt: &Statement, messages: Vec<SimpleQueryMessage>) -> Outcome {
    let mut columns: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    let mut count = 0;
    for m in messages {
        match m {
            SimpleQueryMessage::RowDescription(cols) => {
                columns = Some(cols.iter().map(|c| c.name().to_string()).collect());
            }
            SimpleQueryMessage::Row(row) => {
                if columns.is_none() {
                    columns = Some(row.columns().iter().map(|c| c.name().to_string()).collect());
                }
                rows.push(
                    (0..row.len())
                        .map(|i| row.get(i).map(str::to_string))
                        .collect(),
                );
            }
            SimpleQueryMessage::CommandComplete(n) => count = n,
            _ => {}
        }
    }
    match columns {
        Some(columns) => Outcome::Rows { columns, rows },
        None => Outcome::Done {
            command: stmt.command.to_string(),
            rows: count,
        },
    }
}

fn row_count(outcome: &Outcome) -> u64 {
    match outcome {
        Outcome::Rows { rows, .. } => rows.len() as u64,
        Outcome::Done { rows, .. } => *rows,
        _ => 0,
    }
}
