//! Seeded random workload for undo, against a real Postgres behind a real
//! `ariodb serve`. `scripts/sim-undo.sh` sets both up and runs this; without
//! its environment the test does nothing.
//!
//! For each seed: reset the tables, open several agent sessions through the
//! proxy, run a random mix of agent writes and direct "human" writes
//! (inserts, updates, and deletes that cascade), then undo random sessions,
//! some twice and some skipping conflicts. Every write is bracketed by
//! snapshots of the whole database, so the test knows exactly which rows
//! each write changed without asking ariodb. From that it predicts each
//! undo and checks ariodb against the prediction:
//!
//! - rows only that session touched are restored exactly;
//! - rows anyone else changed later are reported as conflicts and left alone
//!   (and without --skip-conflicts nothing is changed at all);
//! - no other row changes, so an undo that would need to cascade into rows
//!   the session did not touch must be refused;
//! - undoing a session twice is refused.
//!
//! The same seed makes the same workload, so a failure is reproduced with
//! `SIM_SEEDS=<seed> scripts/sim-undo.sh`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

/// Small, dependency-free PRNG (SplitMix64): the same seed gives the same
/// workload on every machine and every version of every crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[self.below(items.len() as u64) as usize])
        }
    }
}

struct Env {
    proxy_port: u16,
    admin_url: String,
    bin: PathBuf,
    config: PathBuf,
    journal: PathBuf,
    token: String,
    seeds: Vec<u64>,
    ops: usize,
    sessions: usize,
}

impl Env {
    fn from_env() -> Option<Env> {
        let var = |k: &str| std::env::var(k).ok();
        Some(Env {
            proxy_port: var("SIM_PROXY_PORT")?.parse().ok()?,
            admin_url: var("SIM_ADMIN_URL")?,
            bin: var("SIM_BIN")?.into(),
            config: var("SIM_CONFIG")?.into(),
            journal: var("SIM_JOURNAL")?.into(),
            token: var("SIM_TOKEN")?,
            seeds: var("SIM_SEEDS")
                .unwrap_or_else(|| "1 2 3 4 5".into())
                .split_whitespace()
                .map(|s| s.parse().expect("SIM_SEEDS holds numbers"))
                .collect(),
            ops: var("SIM_OPS").and_then(|v| v.parse().ok()).unwrap_or(60),
            sessions: var("SIM_SESSIONS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
        })
    }
}

/// A row, named the way ariodb names it in undo plans:
/// (`public.orders`, `(5)`) or (`public.order_items`, `(5, 2)`).
type Key = (String, String);

#[derive(Debug, Clone, PartialEq)]
struct Row {
    text: String,
    /// The row this one's foreign key points at.
    parent: Option<Key>,
}

type Snapshot = BTreeMap<Key, Row>;
type Diff = BTreeMap<Key, (Option<Row>, Option<Row>)>;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Actor {
    Agent(usize),
    Human,
    /// ariodb undoing agent session N.
    Undo(usize),
}

struct Op {
    actor: Actor,
    what: String,
    changes: Diff,
    /// Whether the journal should hold a record for it.
    journaled: bool,
    /// Whether the record's change count must equal `changes.len()`. Not
    /// for writes that may change a row and change it back.
    exact_count: bool,
}

struct Sim<'a> {
    env: &'a Env,
    seed: u64,
    rng: Rng,
    admin: Client,
    agents: Vec<Client>,
    ops: Vec<Op>,
    /// Lines in the journal before this seed began.
    journal_base: usize,
    /// Journal records already matched to ops.
    aligned: usize,
    /// ariodb's session id for each agent connection, once seen.
    session_ids: Vec<Option<String>>,
    undone: Vec<bool>,
    counter: u64,
    stats: Stats,
}

#[derive(Default)]
struct Stats {
    agent_writes: usize,
    human_writes: usize,
    failed_writes: usize,
    undo_applied: usize,
    undo_partial: usize,
    refused_conflicts: usize,
    refused_twice: usize,
    refused_foreign_keys: usize,
    restored_rows: usize,
}

const SNAPSHOT: &str = "
    SELECT 'public.customers', '(' || id || ')', c::text, NULL FROM customers c
    UNION ALL
    SELECT 'public.orders', '(' || id || ')', o::text, '(' || customer_id || ')' FROM orders o
    UNION ALL
    SELECT 'public.order_items', '(' || order_id || ', ' || line || ')', i::text, '(' || order_id || ')'
    FROM order_items i";

fn parent_table(table: &str) -> Option<&'static str> {
    match table {
        "public.orders" => Some("public.customers"),
        "public.order_items" => Some("public.orders"),
        _ => None,
    }
}

fn id_of(key: &Key) -> u64 {
    key.1
        .trim_matches(|c| c == '(' || c == ')')
        .split(", ")
        .next()
        .and_then(|s| s.parse().ok())
        .expect("numeric key")
}

async fn snapshot(client: &Client) -> Result<Snapshot, String> {
    let mut out = Snapshot::new();
    for m in client
        .simple_query(SNAPSHOT)
        .await
        .map_err(|e| e.to_string())?
    {
        if let SimpleQueryMessage::Row(r) = m {
            let table = r.get(0).unwrap().to_string();
            let parent = r
                .get(3)
                .map(|p| (parent_table(&table).unwrap().to_string(), p.to_string()));
            out.insert(
                (table, r.get(1).unwrap().to_string()),
                Row {
                    text: r.get(2).unwrap().to_string(),
                    parent,
                },
            );
        }
    }
    Ok(out)
}

fn diff(before: &Snapshot, after: &Snapshot) -> Diff {
    let keys: BTreeSet<&Key> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(|k| {
            (
                (*k).clone(),
                (before.get(k).cloned(), after.get(k).cloned()),
            )
        })
        .collect()
}

/// Every foreign key in a predicted state points at a row that exists.
fn dangling(state: &Snapshot) -> Vec<String> {
    state
        .iter()
        .filter_map(|(k, row)| {
            let parent = row.parent.as_ref()?;
            (!state.contains_key(parent)).then(|| {
                format!(
                    "{} {} would point at missing {} {}",
                    k.0, k.1, parent.0, parent.1
                )
            })
        })
        .collect()
}

fn show(d: &Diff) -> String {
    d.iter()
        .map(|(k, (a, b))| {
            format!(
                "    {} {}: {} -> {}",
                k.0,
                k.1,
                a.as_ref().map_or("(none)", |r| r.text.as_str()),
                b.as_ref().map_or("(none)", |r| r.text.as_str())
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

impl<'a> Sim<'a> {
    async fn new(env: &'a Env, seed: u64) -> Result<Sim<'a>, String> {
        let (admin, conn) = tokio_postgres::connect(&env.admin_url, NoTls)
            .await
            .map_err(|e| format!("admin connection: {e}"))?;
        tokio::spawn(conn);
        Ok(Sim {
            env,
            seed,
            rng: Rng(seed),
            admin,
            agents: Vec::new(),
            ops: Vec::new(),
            journal_base: journal_records(&env.journal)?.len(),
            aligned: 0,
            session_ids: vec![None; env.sessions],
            undone: vec![false; env.sessions],
            counter: 0,
            stats: Stats::default(),
        })
    }

    /// Fresh tables, written by a "human" in one transaction.
    async fn reset(&mut self) -> Result<(), String> {
        let before = snapshot(&self.admin).await?;
        self.admin
            .batch_execute(
                "BEGIN;
                 DELETE FROM order_items; DELETE FROM orders; DELETE FROM customers;
                 INSERT INTO customers SELECT g, 'customer ' || g FROM generate_series(1, 40) g;
                 INSERT INTO orders (id, customer_id, status, total)
                   SELECT g, 1 + g % 40, 'paid', g + 0.5 FROM generate_series(1, 120) g;
                 INSERT INTO order_items SELECT 1 + g % 120, 1 + g / 120, g FROM generate_series(0, 179) g;
                 COMMIT;",
            )
            .await
            .map_err(|e| format!("reset: {e}"))?;
        let after = snapshot(&self.admin).await?;
        self.ops.push(Op {
            actor: Actor::Human,
            what: "reset".into(),
            changes: diff(&before, &after),
            journaled: true,
            exact_count: false,
        });
        self.sync_journal().await
    }

    async fn connect_agents(&mut self) -> Result<(), String> {
        for _ in 0..self.env.sessions {
            let conn = format!(
                "host=127.0.0.1 port={} user=sim-agent password={} dbname=app sslmode=disable",
                self.env.proxy_port, self.env.token
            );
            let (client, connection) = tokio_postgres::connect(&conn, NoTls)
                .await
                .map_err(|e| format!("agent connection through the proxy: {e}"))?;
            tokio::spawn(connection);
            self.agents.push(client);
        }
        Ok(())
    }

    /// A random write, chosen from what is in the database now so most of
    /// them change something. Humans favour rows agents touched, to make
    /// conflicts likely.
    fn random_write(&mut self, state: &Snapshot, human: bool) -> String {
        self.counter += 1;
        let c = self.counter;
        let keys =
            |table: &str| -> Vec<Key> { state.keys().filter(|k| k.0 == table).cloned().collect() };
        let agent_touched: Vec<Key> = self
            .ops
            .iter()
            .filter(|o| matches!(o.actor, Actor::Agent(_)))
            .flat_map(|o| o.changes.keys().cloned())
            .filter(|k| state.contains_key(k))
            .collect();
        let existing = |rng: &mut Rng, table: &str| -> Option<Key> {
            let touched: Vec<Key> = agent_touched
                .iter()
                .filter(|k| k.0 == table)
                .cloned()
                .collect();
            if human && !touched.is_empty() && rng.chance(40) {
                return rng.pick(&touched).cloned();
            }
            rng.pick(&keys(table)).cloned()
        };
        let rng = &mut self.rng;
        let customer = existing(rng, "public.customers").map_or(1 + rng.below(60), |k| id_of(&k));
        let order = existing(rng, "public.orders").map_or(1 + rng.below(200), |k| id_of(&k));
        let item = existing(rng, "public.order_items");
        match rng.below(20) {
            0 | 1 => format!(
                "INSERT INTO customers (id, name) VALUES ({}, 'n{c}')",
                1 + rng.below(60)
            ),
            2..=4 => format!(
                "INSERT INTO orders (id, customer_id, status, total) VALUES ({}, {customer}, 's{c}', {c}.25)",
                1 + rng.below(200)
            ),
            5 | 6 => format!(
                "INSERT INTO order_items (order_id, line, qty) VALUES ({order}, {}, {c})",
                1 + rng.below(3)
            ),
            7 => format!("UPDATE customers SET name = 'n{c}' WHERE id = {customer}"),
            8..=10 => {
                format!("UPDATE orders SET status = 's{c}', total = {c}.75 WHERE id = {order}")
            }
            11 => format!("UPDATE orders SET status = 'bulk{c}' WHERE customer_id = {customer}"),
            12 | 13 => match item {
                Some((_, k)) => {
                    let (o, l) = k
                        .trim_matches(|ch| ch == '(' || ch == ')')
                        .split_once(", ")
                        .unwrap();
                    format!("UPDATE order_items SET qty = {c} WHERE order_id = {o} AND line = {l}")
                }
                None => format!("UPDATE order_items SET qty = {c} WHERE order_id = {order}"),
            },
            14 | 15 => format!("DELETE FROM orders WHERE id = {order}"),
            16 => format!("DELETE FROM customers WHERE id = {customer}"),
            17 => format!("DELETE FROM order_items WHERE order_id = {order} AND line = 1"),
            _ => format!(
                "UPDATE orders SET total = {c}.5 WHERE customer_id = {customer} AND id % 2 = 0"
            ),
        }
    }

    async fn write(&mut self, actor: Actor) -> Result<(), String> {
        let before = snapshot(&self.admin).await?;
        let sql = self.random_write(&before, actor == Actor::Human);
        let result = match actor {
            Actor::Agent(n) => self.agents[n].simple_query(&sql).await.map(|_| ()),
            _ => self.admin.simple_query(&sql).await.map(|_| ()),
        };
        let after = snapshot(&self.admin).await?;
        let changes = diff(&before, &after);
        if let Err(e) = &result {
            self.stats.failed_writes += 1;
            if !changes.is_empty() {
                return Err(format!(
                    "{actor:?} write failed ({e}) but changed rows: {sql}\n{}",
                    show(&changes)
                ));
            }
        } else if actor == Actor::Human {
            self.stats.human_writes += 1;
        } else {
            self.stats.agent_writes += 1;
        }
        self.ops.push(Op {
            actor,
            journaled: !changes.is_empty(),
            exact_count: true,
            what: sql,
            changes,
        });
        Ok(())
    }

    /// Wait until the journal has a record for every write so far, then
    /// match records to writes: this both checks the journal and tells the
    /// test which ariodb session each agent connection is.
    async fn sync_journal(&mut self) -> Result<(), String> {
        let expected: Vec<usize> = (0..self.ops.len())
            .filter(|&i| self.ops[i].journaled)
            .collect();
        let deadline = Instant::now() + Duration::from_secs(30);
        let records = loop {
            let records: Vec<serde_json::Value> = journal_records(&self.env.journal)?
                .into_iter()
                .skip(self.journal_base)
                .collect();
            if records.len() > expected.len() {
                return Err(format!(
                    "the journal has {} records for this seed but only {} writes changed anything; the newest: {}",
                    records.len(),
                    expected.len(),
                    records.last().unwrap()
                ));
            }
            if records.len() == expected.len() {
                break records;
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "the journal has {} records for this seed after 30 s; expected {}",
                    records.len(),
                    expected.len()
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        for (n, record) in records.iter().enumerate().skip(self.aligned) {
            let op = &self.ops[expected[n]];
            let session = record["session"].as_str();
            let changes = record["changes"].as_array().map_or(0, Vec::len);
            let fault = |why: String| {
                format!(
                    "journal record {n} does not match write {} ({:?}: {}): {why}\n{record}",
                    expected[n], op.actor, op.what
                )
            };
            match op.actor {
                Actor::Human if session.is_some() => {
                    return Err(fault("a human write carries a session".into()));
                }
                Actor::Agent(a) => {
                    let s = session.ok_or_else(|| fault("no session".into()))?;
                    match &self.session_ids[a] {
                        None => self.session_ids[a] = Some(s.to_string()),
                        Some(known) if known != s => {
                            return Err(fault(format!("agent connection {a} was {known} before")));
                        }
                        _ => {}
                    }
                }
                Actor::Undo(a) => {
                    let want = format!("undo:{}", self.session_ids[a].as_deref().unwrap_or(""));
                    if session != Some(want.as_str()) {
                        return Err(fault(format!("expected session {want}")));
                    }
                }
                Actor::Human => {}
            }
            if op.exact_count && changes != op.changes.len() {
                return Err(fault(format!(
                    "{changes} changes recorded, {} rows changed:\n{}",
                    op.changes.len(),
                    show(&op.changes)
                )));
            }
        }
        self.aligned = records.len();
        Ok(())
    }

    /// Undo one agent session and check the outcome against the prediction.
    async fn undo(&mut self, agent: usize, skip_conflicts: bool) -> Result<(), String> {
        self.sync_journal().await?;
        let Some(session) = self.session_ids[agent].clone() else {
            return Ok(()); // this connection never changed anything
        };

        // The prediction. For each row the session touched: its value before
        // the session first touched it, and when that was.
        let mut first_before: BTreeMap<Key, Option<Row>> = BTreeMap::new();
        let mut first_touch: BTreeMap<Key, usize> = BTreeMap::new();
        for (i, op) in self.ops.iter().enumerate() {
            if op.actor == Actor::Agent(agent) {
                for (k, (before, _)) in &op.changes {
                    first_before
                        .entry(k.clone())
                        .or_insert_with(|| before.clone());
                    first_touch.entry(k.clone()).or_insert(i);
                }
            }
        }
        // Rows anyone else (other agents, humans, earlier undos) changed
        // after the session first did. Restoring the first before-image
        // would overwrite their change, even if the session wrote again later.
        let conflicts: BTreeSet<Key> = first_touch
            .iter()
            .filter(|(k, at)| {
                self.ops[**at + 1..]
                    .iter()
                    .any(|op| op.actor != Actor::Agent(agent) && op.changes.contains_key(*k))
            })
            .map(|(k, _)| k.clone())
            .collect();

        let before = snapshot(&self.admin).await?;
        let mut predicted = before.clone();
        for (k, value) in &first_before {
            if conflicts.contains(k) {
                continue;
            }
            match value {
                Some(row) => predicted.insert(k.clone(), row.clone()),
                None => predicted.remove(k),
            };
        }
        let dangling = dangling(&predicted);

        let mut args = vec!["--config".into(), self.env.config.display().to_string()];
        args.extend([
            "undo".into(),
            "--session".into(),
            session.clone(),
            "--apply".into(),
        ]);
        if skip_conflicts {
            args.push("--skip-conflicts".into());
        }
        let out = Command::new(&self.env.bin)
            .args(&args)
            .output()
            .map_err(|e| format!("cannot run ariodb: {e}"))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let after = snapshot(&self.admin).await?;
        let changed = diff(&before, &after);
        let reported: BTreeSet<Key> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("conflict: "))
            .filter_map(|l| {
                let (table, rest) = l.split_once(" row ")?;
                let (key, _) = rest.split_once(" was changed later")?;
                Some((table.to_string(), key.to_string()))
            })
            .collect();

        // Every write to the rows this session touched, oldest first.
        let history: Vec<String> = self
            .ops
            .iter()
            .enumerate()
            .filter_map(|(i, op)| {
                let rows: Diff = op
                    .changes
                    .iter()
                    .filter(|(k, _)| first_before.contains_key(*k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                (!rows.is_empty())
                    .then(|| format!("  #{i} {:?}: {}\n{}", op.actor, op.what, show(&rows)))
            })
            .collect();
        let context = || {
            format!(
                "undo of agent connection {agent} ({session}){}:\n{text}\nrows ariodb changed:\n{}\npredicted conflicts: {conflicts:?}\nhistory of the session's rows:\n{}",
                if skip_conflicts {
                    " with --skip-conflicts"
                } else {
                    ""
                },
                show(&changed),
                history.join("\n")
            )
        };
        let unchanged = |why: &str| -> Result<(), String> {
            if out.status.success() || !changed.is_empty() {
                return Err(format!(
                    "expected a refusal ({why}) that changes nothing; {}",
                    context()
                ));
            }
            Ok(())
        };

        let restored = if self.undone[agent] {
            unchanged("already undone")?;
            if !text.contains("already undone") {
                return Err(format!("expected 'already undone'; {}", context()));
            }
            self.stats.refused_twice += 1;
            0
        } else if !conflicts.is_empty() && !skip_conflicts {
            unchanged("conflicts")?;
            if !text.contains("changed by others") || reported != conflicts {
                return Err(format!(
                    "expected exactly the predicted conflicts; {}",
                    context()
                ));
            }
            self.stats.refused_conflicts += 1;
            0
        } else if !dangling.is_empty() {
            // The prediction is not a valid database: undoing would need to
            // change rows the session never touched. ariodb must refuse.
            unchanged(&dangling.join("; "))?;
            self.stats.refused_foreign_keys += 1;
            0
        } else {
            if !out.status.success() {
                return Err(format!("expected the undo to succeed; {}", context()));
            }
            if reported != conflicts {
                return Err(format!(
                    "conflicts reported differ from the prediction; {}",
                    context()
                ));
            }
            let expected = diff(&before, &predicted);
            if changed != expected {
                return Err(format!(
                    "undo changed the wrong rows; {}\npredicted changes:\n{}",
                    context(),
                    show(&expected)
                ));
            }
            let steps: usize = text
                .lines()
                .find_map(|l| l.strip_prefix("undone: "))
                .and_then(|l| l.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("no 'undone: N rows' line; {}", context()))?;
            if conflicts.is_empty() {
                self.stats.undo_applied += 1;
            } else {
                self.stats.undo_partial += 1;
            }
            self.stats.restored_rows += changed.len();
            steps
        };

        // An undo is journaled (and so remembered as done) only when it
        // ran at least one step; one that skipped everything leaves no trace.
        if restored > 0 {
            self.undone[agent] = true;
        }
        self.ops.push(Op {
            actor: Actor::Undo(agent),
            what: format!("undo {session}"),
            changes: changed,
            journaled: restored > 0,
            exact_count: false,
        });
        Ok(())
    }

    async fn run(&mut self) -> Result<(), String> {
        self.reset().await?;
        self.connect_agents().await?;
        let n = self.env.sessions as u64;

        // Phase 1: agents and humans write, interleaved.
        for _ in 0..self.env.ops {
            let actor = if self.rng.chance(70) {
                Actor::Agent(self.rng.below(n) as usize)
            } else {
                Actor::Human
            };
            self.write(actor).await?;
        }

        // Phase 2: undo random sessions while people keep working; retry
        // some that are already undone.
        for _ in 0..self.env.ops / 4 {
            let roll = self.rng.below(100);
            let agent = self.rng.below(n) as usize;
            if roll < 50 {
                let skip = self.rng.chance(50);
                self.undo(agent, skip).await?;
            } else if roll < 80 {
                self.write(Actor::Human).await?;
            } else if !self.undone[agent] {
                self.write(Actor::Agent(agent)).await?;
            }
        }

        // Phase 3: undo every session, in random order, skipping conflicts,
        // then once more to see each refused as already undone.
        let mut order: Vec<usize> = (0..self.env.sessions).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, self.rng.below(i as u64 + 1) as usize);
        }
        for &agent in order.iter().chain(order.iter()) {
            self.undo(agent, true).await?;
        }
        self.sync_journal().await
    }
}

fn journal_records(path: &std::path::Path) -> Result<Vec<serde_json::Value>, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("journal line: {e}")))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn random_sessions_undo_exactly_what_they_changed() {
    let Some(env) = Env::from_env() else {
        eprintln!("skipped: run scripts/sim-undo.sh, which starts Postgres and ariodb for this");
        return;
    };
    let mut failures = Vec::new();
    for &seed in &env.seeds {
        println!("seed {seed}: starting (reproduce with SIM_SEEDS={seed} scripts/sim-undo.sh)");
        let mut sim = match Sim::new(&env, seed).await {
            Ok(s) => s,
            Err(e) => panic!("seed {seed}: {e}"),
        };
        match sim.run().await {
            Ok(()) => {
                let s = &sim.stats;
                println!(
                    "seed {seed}: ok. {} agent and {} human writes ({} failed harmlessly); undos: {} applied, {} with conflicts skipped, {} refused for conflicts, {} refused as already undone, {} refused for foreign keys; {} rows restored",
                    s.agent_writes,
                    s.human_writes,
                    s.failed_writes,
                    s.undo_applied,
                    s.undo_partial,
                    s.refused_conflicts,
                    s.refused_twice,
                    s.refused_foreign_keys,
                    s.restored_rows
                );
            }
            Err(e) => {
                println!("seed {seed}: FAILED\n{e}");
                failures.push(sim.seed);
            }
        }
    }
    assert!(failures.is_empty(), "failing seeds: {failures:?}");
}
