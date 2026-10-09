//! Running SQL for one agent session over ariodb's own database connection.
//!
//! Reads run in a READ ONLY transaction. Writes run in a transaction that is
//! measured before commit, and their results are held back until the
//! decision is made, so an agent never sees success for a write that was
//! rolled back.

use crate::audit::Entry;
use crate::classify::{self, Statement};
use crate::config::Agent;
use crate::gate::{self, Ctx, Plan, Refusal, State};
use crate::upstream::{DbError, Upstream};
use crate::wire::{self, WireError};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;

/// Where result frames go: an agent's socket, or a collector for MCP.
pub trait Sink {
    fn send(
        &mut self,
        frame: Bytes,
    ) -> impl std::future::Future<Output = Result<(), WireError>> + Send;
}

/// Collects frames in memory.
#[derive(Default)]
pub struct Collect(pub Vec<Bytes>);

impl Sink for Collect {
    async fn send(&mut self, frame: Bytes) -> Result<(), WireError> {
        self.0.push(frame);
        Ok(())
    }
}

pub struct Session {
    pub id: String,
    pub agent: Agent,
    pub up: Upstream,
    pub state: Arc<State>,
    /// The database name this session's queries run in.
    pub database: String,
    /// Whether the agent is still connected; see `gate::Liveness`.
    pub live: Arc<gate::Liveness>,
    /// Whether writes are tagged for the journal. Fixed when the session
    /// opens, so a database without logical replication works with the
    /// journal off.
    pub tagging: bool,
    /// Whether writes are measured (`write_check = "measured"`). Fixed when
    /// the session opens, like `tagging`.
    pub measured: bool,
    /// Counts at the start of the current write, taken off its measurement.
    pub baseline: Vec<Vec<Option<String>>>,
}

impl Session {
    pub async fn open(state: Arc<State>, agent: Agent) -> Result<Session, String> {
        let config = state.config();
        let target = config.target_for(&agent)?;
        let up = Upstream::connect(&target, &format!("ariodb:{}", agent.name)).await?;
        let id = format!("s-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        Ok(Session {
            id,
            agent,
            up,
            state,
            database: target.database,
            live: Arc::new(gate::Liveness::default()),
            tagging: config.journal.enabled,
            measured: config.database.write_check == crate::config::WriteCheck::Measured,
            baseline: Vec::new(),
        })
    }

    /// Start a transaction for a plan: BEGIN, a statement timeout, and for
    /// writes, a tag so the journal knows which session made the change.
    pub async fn begin(&mut self, plan: Plan) -> Result<Result<(), DbError>, WireError> {
        let config = self.state.config();
        let mut sql = match plan {
            Plan::Read => "BEGIN READ ONLY".to_string(),
            Plan::Write => "BEGIN".to_string(),
        };
        sql.push_str(&format!(
            "; SET LOCAL statement_timeout = {}",
            config.limits.statement_timeout_ms
        ));
        if plan == Plan::Write && self.tagging {
            let tag =
                serde_json::json!({ "session": self.id, "agent": self.agent.name }).to_string();
            sql.push_str(&format!(
                "; SELECT pg_logical_emit_message(true, 'ariodb', '{}')",
                tag.replace('\'', "''")
            ));
        }
        if let Err(e) = self.up.internal(&sql).await? {
            return Ok(Err(e));
        }
        self.baseline.clear();
        if plan == Plan::Write && self.measured {
            match self.up.internal(gate::EFFECTS_BASE_SQL).await? {
                Ok(r) => self.baseline = r.rows,
                Err(e) => return Ok(Err(e)),
            }
        }
        Ok(Ok(()))
    }

    pub async fn effects(&mut self) -> Result<Result<Vec<gate::Effect>, DbError>, WireError> {
        let check = if self.measured {
            crate::config::WriteCheck::Measured
        } else {
            crate::config::WriteCheck::Reported
        };
        Ok(self.up.internal(gate::effects_sql(check)).await?.map(|r| {
            let mut rows = self.baseline.clone();
            rows.extend(r.rows);
            gate::effects_since(&rows)
        }))
    }

    pub async fn end(&mut self, commit: bool) -> Result<(), WireError> {
        let _ = self
            .up
            .internal(if commit { "COMMIT" } else { "ROLLBACK" })
            .await?;
        Ok(())
    }

    /// Run a simple-protocol query string. Sends result frames to `sink`,
    /// but not the final ReadyForQuery (the caller sends that).
    pub fn ctx(&self) -> Ctx<'_> {
        Ctx {
            agent: &self.agent,
            session: &self.id,
            database: &self.database,
            live: Some(&self.live),
        }
    }

    pub async fn simple<S: Sink>(&mut self, sql: &str, sink: &mut S) -> Result<(), WireError> {
        let started = Instant::now();
        let statements = match classify::classify(sql) {
            Ok(s) => s,
            Err(e) => {
                let r = Refusal::new(e.to_string());
                self.audit(sql, &[], "refused", None, Some(&r.message), started);
                return sink
                    .send(wire::error_response(
                        r.code,
                        &format!("ariodb: {}", r.message),
                    ))
                    .await;
            }
        };
        if statements.is_empty() {
            return sink.send(wire::frame(b'I', &[])).await;
        }
        let (plan, approved) =
            match gate::check_detailed(&self.state, &self.ctx(), &statements).await {
                Ok(p) => p,
                Err(r) => {
                    self.audit_rule(
                        sql,
                        &statements,
                        "refused",
                        None,
                        Some(&r.message),
                        r.rule.as_deref(),
                        started,
                    );
                    return sink
                        .send(wire::error_response(
                            r.code,
                            &format!("ariodb: {}", r.message),
                        ))
                        .await;
                }
            };

        if let Err(e) = self.begin(plan).await? {
            self.audit(sql, &statements, "failed", None, Some(&e.message), started);
            let _ = self.end(false).await;
            return sink.send(wire::error_response(&e.code, &e.message)).await;
        }

        self.up.send(&wire::query(sql)).await?;
        let mut held = Vec::new();
        let mut failed: Option<String> = None;
        let status;
        loop {
            let f = self.up.recv().await?;
            match f.tag {
                b'Z' => {
                    status = f.body.first().copied().unwrap_or(b'I');
                    break;
                }
                b'E' => {
                    failed.get_or_insert(wire::parse_error(&f.body).message);
                    held.push(f.raw);
                }
                b'G' => {
                    // COPY FROM STDIN slipped past the classifier. Abort it.
                    self.up
                        .send(&wire::frame(
                            b'f',
                            b"ariodb does not relay COPY FROM STDIN\0",
                        ))
                        .await?;
                }
                _ if plan == Plan::Read => sink.send(f.raw).await?,
                _ => held.push(f.raw),
            }
        }

        if status == b'E' || failed.is_some() {
            self.end(false).await?;
            self.audit(sql, &statements, "failed", None, failed.as_deref(), started);
            for f in held {
                sink.send(f).await?;
            }
            return Ok(());
        }

        if plan == Plan::Read {
            self.end(true).await?;
            self.audit_rule(
                sql,
                &statements,
                "allowed",
                None,
                None,
                approved.as_deref(),
                started,
            );
            return Ok(());
        }

        let effects = match self.effects().await? {
            Ok(e) => e,
            Err(e) => {
                self.end(false).await?;
                self.audit(sql, &statements, "failed", None, Some(&e.message), started);
                return sink.send(wire::error_response(&e.code, &e.message)).await;
            }
        };
        let reported = wire::reported_rows(&held);
        let rows = if self.measured {
            gate::total_rows(&effects)
        } else {
            reported
        };
        if let Err(r) = gate::judge_write(
            &self.state,
            &self.ctx(),
            &statements,
            &effects,
            reported,
            self.measured,
        )
        .await
        {
            self.end(false).await?;
            self.audit_rule(
                sql,
                &statements,
                "rolled_back",
                Some(rows),
                Some(&r.message),
                r.rule.as_deref(),
                started,
            );
            return sink
                .send(wire::error_response(
                    r.code,
                    &format!("ariodb: {}", r.message),
                ))
                .await;
        }
        self.end(true).await?;
        self.audit_rule(
            sql,
            &statements,
            "allowed",
            Some(rows),
            None,
            approved.as_deref(),
            started,
        );
        for f in held {
            sink.send(f).await?;
        }
        Ok(())
    }

    pub fn audit(
        &self,
        sql: &str,
        statements: &[Statement],
        outcome: &str,
        rows: Option<u64>,
        reason: Option<&str>,
        started: Instant,
    ) {
        self.audit_rule(sql, statements, outcome, rows, reason, None, started);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit_rule(
        &self,
        sql: &str,
        statements: &[Statement],
        outcome: &str,
        rows: Option<u64>,
        reason: Option<&str>,
        rule: Option<&str>,
        started: Instant,
    ) {
        let tables = gate::tables(statements);
        self.state.audit.record(&Entry {
            session: &self.id,
            agent: &self.agent.name,
            sql,
            kind: gate::kinds(statements),
            tables: &tables,
            outcome,
            rows,
            reason,
            rule,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            engine: "postgres",
            database: &self.database,
        });
    }
}
