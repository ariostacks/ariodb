# ariodb

Lets AI agents work on a real Postgres database without being able to wreck it,
and undoes exactly what one agent changed.

Agents connect to ariodb as if it were Postgres (psql or any driver using the
simple query protocol) or through its MCP server. ariodb checks every
statement, runs it, measures what it actually did, and records every row it
changed so a human can reverse that session later.

## What it does

- **Understands SQL with Postgres's own parser.** Looks inside `EXPLAIN ANALYZE`,
  `PREPARE`, `COPY (...)`, data-modifying `WITH` clauses and `SELECT ... FOR UPDATE`.
  Statements it cannot see inside (`DO`, `EXECUTE`, `CALL`) are refused.
- **Default deny.** Agents only touch the tables listed for them. Destructive
  statements (`DROP`, `TRUNCATE`, `DELETE` or `UPDATE` without `WHERE`), schema
  changes, session settings and transaction control are refused.
- **Judges writes by effect.** Reads run in a `READ ONLY` transaction. Writes run
  in a transaction that is measured before commit using
  `pg_stat_xact_user_tables`, so rows changed by triggers, cascades and
  functions count. Too many rows, or any table the agent may not change, and
  the transaction is rolled back.
- **Records every change.** A logical replication slot feeds a journal of
  before- and after-images, tagged with the agent session that made them.
- **Undoes one session.** Reverses that session's changes in one transaction,
  leaves everyone else's changes alone, and refuses (or skips) rows someone
  else changed since.
- **Keeps a tamper-evident audit log.** Every decision is a hash-chained line.

## Quick start

Requires Postgres 14 or later with `wal_level = logical`.

```bash
cargo build --release

# Credentials live in the environment, not the config file.
export ARIODB_DATABASE_URL='postgres://ariodb_gw:...@db:5432/app'      # what agents' queries run as
export ARIODB_JOURNAL_URL='postgres://ariodb_journal:...@db:5432/app'  # a role with REPLICATION
export ARIODB_TOKEN_CODING_AGENT='...'                                 # the agent's password

./target/release/ariodb check      # validate ariodb.toml
./target/release/ariodb setup      # once, as a table owner: replica identity, publication, slot
./target/release/ariodb serve      # proxy on 127.0.0.1:6543, plus the journal
```

Point an agent at `postgres://coding-agent:<token>@127.0.0.1:6543/app`, or add
the MCP server to a coding agent:

```bash
ARIODB_AGENT_TOKEN='...' ariodb mcp --agent coding-agent
```

Then, as a human:

```bash
ariodb sessions                                # what agents changed
ariodb undo --session s-0af3fa6954             # show the plan
ariodb undo --session s-0af3fa6954 --apply     # reverse it
ariodb audit                                   # check the audit log is intact
ariodb classify "EXPLAIN ANALYZE DELETE FROM users"
```

## Tunnels

When the database is only reachable through a side process (cloud-sql-proxy,
an IAP tunnel, an SSH port-forward), let ariodb run it:

```toml
[database]
url = "postgres://ariodb_gw:...@10.20.0.5:5432/app"
tunnel = "cloudsql"

[[tunnels]]
name = "cloudsql"
command = ["cloud-sql-proxy", "--port", "5433", "my-project:europe-west2:app-db"]
listen = "127.0.0.1:5433"     # where the process listens
ready_timeout_seconds = 30    # how long to wait for that port to accept connections
restart = true                # start it again, with backoff, if it exits
```

`ariodb serve` starts every tunnel before it accepts agents and refuses to
start if one does not come up in time. A tunnel that exits is restarted after
1 s, doubling to 30 s; its output appears in ariodb's log prefixed with
`tunnel <name>:`. Stopping ariodb (Ctrl-C or SIGTERM) stops the tunnels.

A connection that names a tunnel (`[database]`, any `[[credentials]]`, or
`[clickhouse]`) dials the tunnel's `listen` address; the user, password,
database and TLS settings still come from its URL, so TLS is checked against
the real host name. `ariodb setup`, `undo` and `mcp` use a tunnel that
`ariodb serve` is already running, or start their own for the duration.
Tunnel changes need a restart.

## Database roles

- **Gateway role** (`ARIODB_DATABASE_URL`): ordinary privileges on the tables
  agents use. No superuser needed.
- **Journal role** (`ARIODB_JOURNAL_URL`): needs the `REPLICATION` attribute.
- **Setup** needs to own the protected tables (to set `REPLICA IDENTITY FULL`).

Make sure agents can reach the database only through ariodb.

## What undo cannot reverse

| Change | Handling |
|---|---|
| Insert, update, delete, including cascades and trigger effects | Undone |
| `TRUNCATE`, `DROP`, schema changes | Refused for agents, so never need undoing |
| Rows someone else changed after the session first did | Reported as conflicts; left alone with `--skip-conflicts`, otherwise nothing is undone |
| Undo steps that would cascade (or trigger updates and deletes) into rows the session never touched | Refused; nothing is undone |
| Rows in tables without a primary key | Reported as not undoable |
| Sequence values | Not rewound; gaps in IDs are harmless |
| Anything outside the database (emails, payments) | Out of scope |

## Not built yet

Extended query protocol (prepared statements from drivers), TLS on the proxy,
Cedar policies, approval holds in Slack or Teams, column masking, guards for
provider control-plane APIs, and deterministic simulation testing. See the
roadmap in the design document.

## Testing

```bash
cargo test                      # unit and property tests (PROPTEST_CASES=100000 for a longer hunt)
./scripts/e2e.sh                # end-to-end against Postgres in Docker
./scripts/e2e-clickhouse.sh     # end-to-end against ClickHouse in Docker
./scripts/sim-undo.sh           # seeded random agent and human writes, then undo, checked against a model
SIM_SEEDS="42 7" SIM_OPS=120 ./scripts/sim-undo.sh   # other seeds, longer runs
```

The undo simulation brackets every write with a snapshot of the database,
predicts each undo from those snapshots alone, and fails with the seed, the
plan, what changed and the history of the rows involved when ariodb
disagrees. The same seed always produces the same workload.

## Licence

Apache-2.0 (to be added before the first public release).
