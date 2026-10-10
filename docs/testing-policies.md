# Testing policies

A change to `ariodb.toml` changes what agents may do to a production
database, so it deserves the same review and tests as code. This page
covers the four tools for that: `ariodb classify` (how ariodb reads a
statement), `ariodb explain` (what the policy and rules would decide for
one statement), `ariodb test` (replaying a set of expected decisions, for
CI) and `ariodb export-fixtures` (turning real decisions into test cases).
It ends with a sample GitHub Actions job and an honest list of what these
tools cannot predict. None of them connects to a database or starts a
plugin, so they are safe to run anywhere, including CI.

## The config used on this page

The examples below were run against this `ariodb.toml`:

```toml
[database]
url = "postgres://ariodb_gw:not-a-real-password@localhost:5432/app"

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders", "customers", "payments"]
token_env = "ARIODB_TOKEN_CODING_AGENT"

[agents.clickhouse]
access = "read_only"
tables = ["events"]

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["orders"]
token_env = "ARIODB_TOKEN_SUPPORT_BOT"

[[approvers]]
name = "ops"
type = "dashboard"

[[rules]]
name = "payments-freeze"
condition = "'payments' in sql.tables && sql.kind != 'read'"
verdict = "deny"
reason = "payments is frozen for the quarter-end close"

[[rules]]
name = "customer-emails-need-a-human"
condition = '''sql.engine == 'postgres' && 'customers' in sql.tables && sql.statement.matches('(?i)\\bemail\\b')'''
verdict = "approve"
approve = ["ops"]

[[rules]]
name = "clickhouse-no-raw-events"
condition = '''sql.engine == 'clickhouse' && 'events' in sql.tables && !sql.statement.matches('(?i)\\blimit\\b')'''
verdict = "deny"
reason = "reads of events on ClickHouse need a LIMIT"
```

## `ariodb classify`: how ariodb reads a statement

```bash
ariodb classify "<sql>"
```

Shows, for each statement in the string, the [kind](policy.md#statement-kinds)
ariodb gives it, the tables it found and why. It needs no config file.

```text
$ ariodb classify "SELECT 1 FROM Public.Orders; DELETE FROM customers WHERE id = 2"
read                 tables: orders                   select
write                tables: customers                delete

$ ariodb classify "EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1"
write                tables: orders                   delete (inside EXPLAIN ANALYZE)

$ ariodb classify "PREPARE p AS SELECT * FROM secrets"
read                 tables: secrets                  select (inside PREPARE)

$ ariodb classify "UPDATE orders SET status = 'x'"
destructive          tables: orders                   UPDATE without WHERE changes every row

$ ariodb classify "DO \$\$ BEGIN END \$\$"
unknown              tables: -                        DO blocks run arbitrary code

$ ariodb classify "SELEC 1"
error: cannot parse SQL: Error splitting: syntax error at or near "SELEC"
```

It exits 0, or 1 if the SQL does not parse. `classify` reads Postgres SQL
only; for ClickHouse and MySQL, use `explain --engine clickhouse` or
`explain --engine mysql`.

## `ariodb explain`: what would happen to one statement

```bash
ariodb explain --agent <name> [--engine postgres|clickhouse|mysql] "<sql>"
```

Loads the config (`--config`, default `ariodb.toml`), then judges the
statement for that agent exactly as the proxy would before running it: the
built-in policy, then the before-stage rules. It prints the verdict, what
decided it, and the reason:

```text
$ ariodb explain --agent coding-agent "SELECT * FROM orders"
allow  (decided by: -)

$ ariodb explain --agent coding-agent "SELECT name, email FROM customers"
approve  (decided by: customer-emails-need-a-human)  rule 'customer-emails-need-a-human'

$ ariodb explain --agent coding-agent "UPDATE payments SET state = 'x' WHERE id = 1"
deny  (decided by: payments-freeze)  payments is frozen for the quarter-end close

$ ariodb explain --agent coding-agent "SELECT * FROM secrets"
deny  (decided by: policy)  agent 'coding-agent' may not use table 'secrets'

$ ariodb explain --agent support-bot "UPDATE orders SET status = 'x' WHERE id = 1"
deny  (decided by: policy)  agent 'support-bot' is read only
```

- **`decided by`** is `policy` for the built-in policy, a rule's name, or
  `-` when nothing refused or held it and no `allow` rule matched.
- **`--engine clickhouse`** judges ClickHouse SQL against the agent's
  `[agents.clickhouse]` access, in the `default` database:

  ```text
  $ ariodb explain --engine clickhouse --agent coding-agent "SELECT * FROM url('http://x.example/a', CSV)"
  deny  (decided by: policy)  destructive statements are never allowed for agents: the 'url' table function reaches outside the server

  $ ariodb explain --engine clickhouse --agent coding-agent "SELECT 1; SELECT 2"
  deny  (decided by: policy)  send one statement per request
  ```

- **`--engine mysql`** judges MySQL and MariaDB SQL against the agent's
  `[agents.mysql]` access, in `[mysql] database`:

  ```text
  $ ariodb explain --engine mysql --agent coding-agent "SELECT * FROM other.notes"
  deny  (decided by: policy)  agent 'coding-agent' may not use table 'other.notes'

  $ ariodb explain --engine mysql --agent coding-agent "SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED"
  deny  (decided by: policy)  agents may not read uncommitted data (READ UNCOMMITTED)

  $ ariodb explain --engine mysql --agent support-bot "SELECT * FROM orders LOCK IN SHARE MODE"
  deny  (decided by: policy)  agent 'support-bot' is read only
  ```

  It judges the SQL only. Three things the MySQL listener does itself are
  not part of it: refusing a query with more than one statement, refusing
  the [reserved tables](mysql.md#reserved-tables) to agents whose list is
  `"*"`, and answering `KILL` for the agent's own connections (`explain`
  shows `KILL` as refused by the policy).

  Any other `--engine` value is treated as `postgres`.
- **The database** is the one in the `[database]` URL for Postgres,
  `default` for ClickHouse, and `[mysql] database` for MySQL. `explain`
  has no option to change it; use a [fixture](#fixture-format) with
  `sql.database` to test another ClickHouse or MySQL database.
- **Several statements** in one Postgres string are judged together, as
  the proxy does: any deny refuses all of them, any `approve` holds all of
  them.
- **Exit status** is 0 whatever the verdict, and 1 only if the config does
  not load. Use `ariodb test` when you need the exit status to mean
  something.

## `ariodb test`: replay expected decisions

```bash
ariodb test [--config ariodb.toml] <file.json or directory>
```

Each fixture is a statement, the agent that sends it, and the verdict you
expect. `ariodb test` judges every fixture with `explain`'s logic and
reports any that drifted.

### Fixture format

One fixture object, or an array of them, per `.json` file:

```json
[
  {
    "name": "agents cannot read secrets",
    "action": { "agent": "coding-agent", "sql": { "statement": "SELECT * FROM secrets" } },
    "match": { "verdict": "deny", "rule": "policy" }
  },
  {
    "name": "payments are frozen",
    "action": { "agent": "coding-agent", "sql": { "statement": "UPDATE payments SET state = 'void' WHERE id = 7" } },
    "match": { "verdict": "deny", "rule": "payments-freeze" }
  },
  {
    "name": "customer emails need a person",
    "action": { "agent": "coding-agent", "sql": { "statement": "SELECT email FROM customers WHERE id = 1", "database": "app" } },
    "match": { "verdict": "approve", "rule": "customer-emails-need-a-human" }
  },
  {
    "name": "ordinary reads are allowed",
    "action": { "agent": "support-bot", "sql": { "statement": "SELECT id, status FROM orders WHERE id = 42" } },
    "match": { "verdict": "allow" }
  },
  {
    "name": "ClickHouse reads of events need a LIMIT",
    "action": { "agent": "coding-agent", "engine": "clickhouse", "sql": { "statement": "SELECT count() FROM events" } },
    "match": { "verdict": "deny", "rule": "clickhouse-no-raw-events" }
  }
]
```

| Field | Required | Meaning |
|---|---|---|
| `name` | no | Shown in the output. Default: `<file name> #<position>`. |
| `action.agent` | yes | An agent name from the config. An unknown agent is a `deny` by `policy`. |
| `action.engine` | no | `postgres` (default), `clickhouse` or `mysql`. |
| `action.sql.statement` | yes | The SQL, as the agent would send it. |
| `action.sql.database` | no | Default: the `[database]` URL's database, `default` for ClickHouse, or `[mysql] database` for MySQL. Rules see it as `sql.database`; ClickHouse and MySQL table names are scoped to it. |
| `match.verdict` | yes | `allow`, `deny` or `approve`. |
| `match.rule` | no | If given, the deciding rule must match too: a rule name, or `policy` for the built-in policy. A plain allow has no deciding rule, so leave `rule` out for those unless an `allow` rule decides. |

Given a directory, `ariodb test` reads every `*.json` file directly in it
(not in subdirectories), in name order.

### Output and exit codes

With the five fixtures above in `policy-tests/core.json`, and a sixth in
`policy-tests/drift.json` that wrongly expects `support-bot` to be allowed
an `UPDATE`:

```text
$ ariodb test policy-tests
ok     agents cannot read secrets
ok     payments are frozen
ok     customer emails need a person
ok     ordinary reads are allowed
ok     ClickHouse reads of events need a LIMIT
DRIFT  support-bot may update orders: expected allow, got deny (rule policy) agent 'support-bot' is read only

1 drifted, 5 match
```

| Exit | Meaning |
|---|---|
| `0` | Every fixture matches. |
| `1` | At least one fixture drifted. |
| `2` | Usage or config error: the config does not load, a fixture file cannot be read or is not valid JSON, or a fixture lacks a required field (``bad.json item 1: missing field `agent` ``). |

An empty directory, or an empty array, passes with `0 fixtures match`;
make sure CI points at the right path.

## Recording fixtures from real decisions

Every statement an agent sends is recorded in the decisions log. `ariodb
export-fixtures` turns recent decisions into fixtures, so you can pin down
today's behaviour before changing the policy:

```bash
ariodb export-fixtures --out policy-tests --limit 500
```

```text
wrote 4 fixtures to policy-tests/recorded.json
```

It reads the newest `--limit` decisions (default 500) from
`<state dir>/ariodb.db` and writes them, newest first, to
`<out>/recorded.json`, replacing that file if it exists:

```json
[
  {
    "action": {
      "agent": "coding-agent",
      "sql": { "database": "app", "statement": "SELECT email FROM customers WHERE id = 7" }
    },
    "match": { "rule": "customer-emails-need-a-human", "verdict": "approve" },
    "name": "decision 3 (coding-agent)"
  },
  {
    "action": {
      "agent": "coding-agent",
      "sql": { "database": "app", "statement": "SELECT * FROM secrets" }
    },
    "match": { "rule": "policy", "verdict": "deny" },
    "name": "decision 2 (coding-agent)"
  }
]
```

How decisions become fixtures:

| Decision | Fixture |
|---|---|
| Allowed, with no approval | `allow`, no rule |
| Refused by the policy | `deny`, rule `policy` |
| Refused by a rule | `deny`, that rule |
| Held by an `approve` rule, whatever the approver then said | `approve`, that rule: the policy's job was to ask, and it should ask again |
| Rolled back, failed at the database, or unsupported by the transport | Skipped: these depend on data or the protocol, not the policy |

ClickHouse decisions keep `"engine": "clickhouse"` and their database,
and MySQL decisions `"engine": "mysql"` and theirs. A few MySQL decisions
come from the listener rather than the policy (a query with several
statements, a reserved table, a cursor, `KILL`), so `ariodb test` may
report them as drift; drop them from the exported file.
So fewer fixtures than `--limit` is normal.

A workflow that works:

1. Export from the production state directory.
2. Review `recorded.json`: drop duplicates, rename the fixtures that
   matter, and move anything you want to keep into a file of its own, since
   the next export replaces `recorded.json`.
3. Commit the fixtures next to `ariodb.toml`.
4. Change the policy; run `ariodb test`. Each `DRIFT` line is a decision
   that would now go the other way. Either the change is wrong, or the
   fixture needs updating in the same pull request, where a reviewer sees
   it.

With `[audit] redact_literals = true`, the decisions log stores SQL with
literal values replaced by `$1`, `$2`, ..., and exported fixtures carry
that text. It still parses and replays, but a rule that matches on a
literal value (`sql.statement.contains('admin@')`) will judge it
differently from the original.

## Running policy tests in CI

The job below runs whenever the config or the fixtures change. It builds
ariodb from source (pin the version you run in production), checks the
config, and replays the fixtures. Nothing in it needs a database, a
token or a secret: agent tokens and database URLs are only read when
ariodb connects, and `check` reports a missing token without failing.

```yaml
# .github/workflows/ariodb-policy.yml
name: ariodb policy

on:
  pull_request:
    paths:
      - "ariodb.toml"
      - "policy-tests/**"
  push:
    branches: [main]
    paths:
      - "ariodb.toml"
      - "policy-tests/**"

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - name: Check out the policy
        uses: actions/checkout@v4

      - name: Check out ariodb
        uses: actions/checkout@v4
        with:
          repository: roozjalali/ariodb
          ref: v0.1.0                   # the version you run in production
          path: ariodb-src

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache the build
        uses: Swatinem/rust-cache@v2
        with:
          workspaces: ariodb-src

      - name: Build ariodb
        run: cargo build --release --locked --manifest-path ariodb-src/Cargo.toml

      - name: Check the config
        run: ariodb-src/target/release/ariodb check --config ariodb.toml

      - name: Replay the policy fixtures
        run: ariodb-src/target/release/ariodb test --config ariodb.toml policy-tests
```

Notes:

- The build compiles Postgres's parser (libpg_query) and needs a C
  compiler and libclang. GitHub's Ubuntu runners have both; on other
  runners, install `clang` first. See [installation](installation.md).
- `ariodb check` exits 1 if the config does not load: bad TOML, a rule
  that does not compile, an approver or plugin a rule names but nobody
  defined, two agents with the same name.
- `ariodb test` exits 1 on drift and 2 on a broken fixture, so either
  fails the job.

## What `explain` and `test` cannot predict

Both judge a statement **before it runs**, without a database. That leaves
out everything that depends on running it:

- **After-stage rules.** They need `effects.rows` and `effects.tables`,
  which only exist once a write has run. A fixture cannot expect an
  after-stage verdict.
- **The effect check.** Whether a write stays within `max_rows_per_write`,
  touches a table off the allow-list through a trigger or cascade, or
  fails the measurement cross-check, is decided at run time. A write that
  `explain` allows can still be rolled back.
- **Plugin facts.** Plugins are not started, so a before-stage rule that
  reads `plugin.<name>` is unevaluable and shows as a `deny` by that rule,
  for every statement it applies to. Expect that in fixtures, or test
  such rules against a running `ariodb serve`.
- **Approvers.** An `approve` verdict says approval would be asked for,
  not what the approver would answer.
- **The database itself.** Grants, `READ ONLY` enforcement, statement
  timeouts, constraint errors, and whether a table exists.
- **The transport.** The 1 MiB message limit, reserved statement names,
  the ClickHouse native listener's insert checks (the row limit, the
  column types it can read, and the refusal of `INSERT ... SELECT`, all
  of which `explain` does not apply), and the MySQL
  listener's own checks (one statement per query, reserved tables,
  cursors, `KILL`).

For those, test against a staging database through a running ariodb, and
run [`ariodb doctor`](postgres.md#reading-ariodb-doctor) there.

## Next

- [Rules](rules.md): writing the rules these tools test.
- [Policy](policy.md): what `decided by: policy` means.
- [CLI](cli.md): every command and option.
- [Operations](operations.md): where the decisions log lives.
- [Troubleshooting](troubleshooting.md).
