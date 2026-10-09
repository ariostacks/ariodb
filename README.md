# ariodb

A safety layer between AI agents and databases. Agents connect to ariodb as
if it were Postgres (or ClickHouse), or use it as an MCP tool. ariodb checks
every statement, runs it, measures what it actually did, records every row
it changed, and lets a person undo one agent session later.

## What it does

- **Speaks Postgres.** A wire-protocol proxy for psql and any driver: simple
  and extended (prepared statement) protocol, TLS on both sides, SCRAM to the
  database, cancel requests, and a 1 MiB cap on what it will inspect.
- **Understands SQL with Postgres's own parser.** It looks inside
  `EXPLAIN ANALYZE`, `PREPARE`, `DECLARE`, `COPY (...)`, data-modifying `WITH`
  clauses and `SELECT ... FOR UPDATE`. Statements it cannot see inside (`DO`,
  `CALL`, `EXECUTE`, `FETCH`) are refused.
- **Default deny, per agent.** Each agent may only touch the tables listed
  for it, read only or read and write. Destructive statements (`DROP`,
  `TRUNCATE`, `DELETE` or `UPDATE` without `WHERE`), schema changes, session
  settings, transaction control, and functions that would get round ariodb's
  checks (`dblink`, `set_config`, `query_to_xml`, large objects and others)
  are refused.
- **Judges writes by their effect.** Reads run in a `READ ONLY` transaction.
  Writes run in a transaction that is measured before commit, so rows changed
  by triggers, cascades and functions count. Too many rows, or any table the
  agent may not change, and the write is rolled back.
- **Rules in CEL.** On top of the built-in policy, rules can refuse a
  statement or hold it for approval, before it runs or after a write has run
  but before it commits. Rules reload while ariodb runs, and `ariodb test`
  checks them in CI.
- **Approvals.** A held statement waits for a person in the dashboard, the
  CLI, Slack (with buttons) or any webhook, or for a Claude model judging it
  against a written policy.
- **Records every change.** A logical replication slot feeds a journal of
  before- and after-images, tagged with the agent session that made them.
- **Undoes one session.** Reverses that session's changes in one
  transaction, leaves everyone else's alone, and refuses (or skips) rows
  someone else changed since.
- **Keeps a decisions log.** Every statement, verdict, rule, row count and
  latency, hash-chained in SQLite, with retention, optional redaction of
  literal values, and export as test fixtures.
- **Keeps credentials away from agents.** Agents log in with their own
  tokens. Database passwords live in environment variables or an encrypted
  secret store, and each agent can run as its own database role.
- **ClickHouse too.** A proxy for ClickHouse's HTTP interface (reads and
  `INSERT`) and its native protocol (reads), with the same rules and
  approvals.
- **A dashboard.** Approvals queue, decisions, sessions and undo, rules,
  config editor, secrets and users, built into the binary.

## Quick start: the demo

Needs Docker and Rust.

```bash
./scripts/demo.sh
```

This starts Postgres 16 in Docker with sample tables (`customers`, `orders`,
`secrets`), writes a config to `.ariodb-demo/`, runs `ariodb setup` and
`ariodb serve`, and sends some good and bad agent statements so there is
something to look at. Then:

```bash
psql "postgres://coding-agent:demo-agent-token@127.0.0.1:6543/app?sslmode=disable"
```

and open the dashboard at <http://127.0.0.1:8080> (user `root`, password
`demo-dashboard-password`). Try `DELETE FROM orders` (refused),
`UPDATE orders SET status = 'void' WHERE id < 600` (rolled back: over the
row limit), and `SELECT name, email FROM customers` (waits for approval in
the dashboard). Ctrl-C stops everything.

## Real setup

Needs Postgres 14 or later with `wal_level = logical` (on managed services,
turn on logical replication).

```bash
cargo build --release
```

1. Create the database roles (see [Database roles](#database-roles)).
2. Write `ariodb.toml`. The [example](ariodb.toml) shows every section.
3. Put credentials in the environment or the secret store, not the file:

   ```bash
   export ARIODB_DATABASE_URL='postgres://ariodb_gw:...@db:5432/app'      # what agents' queries run as
   export ARIODB_JOURNAL_URL='postgres://ariodb_journal:...@db:5432/app'  # REPLICATION, owns the tables
   export ARIODB_TOKEN_CODING_AGENT="$(openssl rand -hex 32)"             # the agent's password
   ```

4. Check, prepare and run:

   ```bash
   ./target/release/ariodb check     # validate ariodb.toml and show what it allows
   ./target/release/ariodb setup     # once: replica identity, publication, replication slot
   ./target/release/ariodb serve     # proxy, journal, dashboard and any ClickHouse listeners
   ```

5. Set the first dashboard password (at least 12 characters):

   ```bash
   ariodb dashboard-password          # reads the password from stdin; user "root"
   ```

6. Point an agent at `postgres://coding-agent:<token>@127.0.0.1:6543/app`, or
   give it the MCP server:

   ```bash
   ARIODB_AGENT_TOKEN='<token>' ariodb mcp --agent coding-agent
   ```

   The MCP server offers one tool, `query`, which goes through the same
   checks as the proxy.

7. Make sure agents can reach the database only through ariodb.

### Environment variables

| Variable | Used for |
|---|---|
| `ARIODB_DATABASE_URL` | The gateway login. Wins over `[database] url`. |
| `ARIODB_JOURNAL_URL` | `setup` and the journal. Falls back to the gateway URL. |
| `ARIODB_ADMIN_URL` | `undo` (CLI and dashboard). Falls back to the gateway URL. |
| `ARIODB_AGENT_TOKEN` | The token `ariodb mcp` checks against the agent's. |
| `ARIODB_MASTER_KEY` | 32-byte base64 key for the secret store. Without it, `<state dir>/master.key` is created. |
| `ANTHROPIC_API_KEY` | Model approvers, when they name no `api_key_env` or `api_key_secret`. |
| Any `*_env` name in the config | Agent tokens, credential URLs, approver and ClickHouse secrets. |

## Configuration reference

One TOML file, `ariodb.toml` by default (`--config` to change). `ariodb
serve` reloads it when it changes: agents, rules, approvers and limits apply
to the next statement; listen addresses and tunnels need a restart. A
config that does not load is ignored and the previous one kept.

Values named `*_env` are environment variable names; values named
`*_secret` or `secret` are names in the encrypted secret store (`ariodb
secret set <name>`).

### `[database]` (required)

The Postgres database agents work on.

```toml
[database]
url = "postgres://ariodb_gw:not-a-real-password@db.internal:5432/app"
# secret = "database-url"     # use a stored URL instead
tls = "verify"                # disable | require | verify; default: disable on localhost, verify elsewhere
ca_file = "/etc/ariodb/db-ca.pem"
# tunnel = "cloudsql"         # dial a [[tunnels]] entry instead of the URL's host
```

`url` must start with `postgres://` or `postgresql://` even when the real
URL comes from `ARIODB_DATABASE_URL` or `secret`.

### `[limits]`

```toml
[limits]
max_rows_per_write = 500      # default 500; a write that changes more is rolled back
statement_timeout_ms = 5000   # default 5000; also caps ClickHouse max_execution_time
```

### `[proxy]`

Where Postgres agents connect.

```toml
[proxy]
listen = "127.0.0.1:6543"     # default; "" switches the Postgres proxy off
tls_cert = "/etc/ariodb/proxy.crt"
tls_key = "/etc/ariodb/proxy.key"
require_tls = true            # refuse agents without TLS
```

### `[journal]`

The change journal used by undo, and the state directory.

```toml
[journal]
enabled = true                # default true
dir = ".ariodb"               # state directory: journal.jsonl, ariodb.db, secrets, master.key
slot = "ariodb"               # logical replication slot
publication = "ariodb"        # publication of the protected tables
```

ariodb creates the state directory `0700` and warns if it is looser.

### `[[agents]]`

```toml
[[agents]]
name = "coding-agent"         # the user name the agent logs in with
access = "read_write"         # read_only | read_write
tables = ["orders", "customers"]   # "*" means every table
token_env = "ARIODB_TOKEN_CODING_AGENT"
# token_secret = "coding-agent-token"   # exactly one of token_env and token_secret
max_rows_per_write = 100      # optional, overrides [limits]
credential = "writer"         # optional, a [[credentials]] name; default: [database]

[agents.clickhouse]           # optional: ClickHouse access, separate from Postgres
access = "read_only"
tables = ["events", "analytics.page_views"]   # outside `default`, name the database
```

Table names ignore case and a `public.` prefix. Agents may always read the
Postgres catalogue (`pg_catalog`, `information_schema`) and, on ClickHouse,
`system.tables`, `system.columns`, `system.databases`, `system.functions`
and `information_schema`. Tables that agents may write are the ones
`ariodb setup` protects.

### `[[credentials]]`

Extra database logins, so agents can run as different roles.

```toml
[[credentials]]
name = "reporting"
url_env = "ARIODB_REPORTING_URL"   # or: secret = "reporting-url"
tls = "verify"                     # default: the [database] setting
ca_file = "/etc/ariodb/db-ca.pem"
# tunnel = "cloudsql"
```

### `[[tunnels]]`

Side processes that carry connections to a database (cloud-sql-proxy, an IAP
tunnel, an SSH port-forward).

```toml
[[tunnels]]
name = "cloudsql"
command = ["cloud-sql-proxy", "--port", "5433", "my-project:europe-west2:app-db"]
listen = "127.0.0.1:5433"     # where the process listens
ready_probe = "tcp"           # the only probe: the port accepts a connection
ready_timeout_seconds = 30    # default 30
restart = true                # default true: restart with backoff (1 s doubling to 30 s)
```

`ariodb serve` starts every tunnel before it accepts agents and refuses to
start if one does not come up in time. Its output appears in ariodb's log as
`tunnel <name>:`. Stopping ariodb stops the tunnels. A connection that names
a tunnel (`[database]`, a credential or `[clickhouse]`) dials its `listen`
address; user, password, database and TLS still come from the URL, so TLS
is checked against the real host name. `setup`, `undo` and `mcp` use a
tunnel `serve` is already running, or start their own.

### `[[rules]]`

CEL conditions on top of the built-in policy. Rules can refuse a statement
or hold it for approval; they cannot allow what the built-in policy refuses.

```toml
[[rules]]
name = "no-file-functions"
condition = "sets.intersects(sql.functions, ['pg_read_file', 'pg_ls_dir'])"
verdict = "deny"              # allow | deny | approve
reason = "functions that read server files are off-limits"

[[rules]]
name = "big-writes-need-a-human"
stage = "after"               # before (default) | after: judged on the measured effect, before commit
condition = "effects.rows > 50 || 'payments' in effects.tables"
verdict = "approve"
approve = ["ops"]             # approvers, all of which must allow
agents = ["coding-agent"]     # optional; default every agent
priority = 10                 # optional; default 0
```

How rules combine: every rule for the stage and agent is evaluated. Any
matching `deny` wins. Otherwise the highest-priority match (file order breaks
ties) decides between `allow` and `approve`. A rule with no `condition`
matches everything. A condition that fails to evaluate counts as a deny.

| Variable | Type | Meaning |
|---|---|---|
| `sql.verb` | string | First keyword, lower case: `select`, `update`, ... |
| `sql.kind` | string | ariodb's judgement: `read`, `write`, `destructive`, `schema_change`, `session`, `transaction`, `unknown` |
| `sql.tables` | list | Tables named, lower case, without `public.` |
| `sql.functions` | list | Functions called, lower case |
| `sql.statement` | string | The statement as sent |
| `sql.database` | string | The database the agent is using |
| `sql.engine` | string | `postgres` or `clickhouse` |
| `agent.name`, `agent.access` | string | Who is asking |
| `effects.rows` | int | Rows changed (after-stage only) |
| `effects.tables` | list | Tables changed, including by triggers and cascades (after-stage only) |

`intersects(a, b)` (or the CEL sets extension's spelling, `sets.intersects(a, b)`) is
true when two lists share an item.

### `[[approvers]]`

Named by rules with `verdict = "approve"`. Four types:

```toml
[[approvers]]
name = "ops"
type = "dashboard"            # decide in the dashboard or with `ariodb approve` / `deny`

[[approvers]]
name = "ops-slack"
type = "slack"                # posts to a channel
channel = "C0123456789"
bot_token_env = "ARIODB_SLACK_BOT_TOKEN"        # or bot_token_secret
interactive = true            # Approve and Deny buttons
signing_secret_env = "ARIODB_SLACK_SIGNING_SECRET"   # or signing_secret_secret; needed for buttons
timeout_seconds = 300         # optional, overrides [approvals]

[[approvers]]
name = "pager"
type = "webhook"              # POSTs a signed JSON request to any URL
url = "https://hooks.example.com/ariodb"
hmac_secret_env = "ARIODB_WEBHOOK_SECRET"       # or hmac_secret_secret

[[approvers]]
name = "model"
type = "llm"                  # a Claude model judges the statement against a policy
policy = "Allow reads of order data. Deny bulk exports of personal data."
api_key_env = "ANTHROPIC_API_KEY"   # or api_key_secret; default: ANTHROPIC_API_KEY
model = "claude-opus-5-5"     # default
effort = "low"                # default
```

- **Slack**: set the Slack app's interactivity request URL to
  `<public_url>/slack/actions`. Requests are checked against the signing
  secret and a five-minute timestamp window, and can only decide requests
  waiting on that Slack approver.
- **Webhook**: the body holds `id`, `agent`, `session`, `sql`, `rule`,
  `reason`, `expires_ms`, `approve_url`, `deny_url` and `dashboard_url`, and
  the `x-ariodb-signature` header is `sha256=<HMAC-SHA256 of the body>`. The
  approve and deny links are signed per request. Opening one shows the
  request and a button; only a POST to the link decides.
- **Model**: the SQL is passed as JSON data with an instruction not to follow
  text inside it, and the answer is limited to allow or deny. Not a security
  boundary on its own (see [SECURITY.md](SECURITY.md)).

### `[approvals]`

```toml
[approvals]
timeout_seconds = 90          # default 90; no decision in time means refused
llm_fail_mode = "closed"      # closed (default) refuses when the model is unreachable; open allows
llm_cache_seconds = 300       # default 300; reuse a model's answer to the same question
```

Agents should allow their own query timeout to be longer than the approval
timeout. An after-stage approval keeps the write's transaction open (and its
row locks held) while it waits.

### `[dashboard]`

```toml
[dashboard]
listen = "127.0.0.1:8080"     # default; "" switches it off
public_url = "https://ariodb.example.com"   # for links in Slack and webhooks; https turns on Secure cookies
config_writes = false         # default false: the config page shows the edit to copy instead of saving it
```

### `[audit]`

The decisions log, in `<state dir>/ariodb.db`.

```toml
[audit]
retention_days = 30           # default 30; 0 keeps everything; pruned hourly
redact_literals = false       # true stores SQL with literal values replaced by $1, $2, ...
```

### `[clickhouse]`

```toml
[clickhouse]
http_listen = "127.0.0.1:8124"       # HTTP interface for agents; "" (default) is off
http_url = "https://ch.internal:8443"   # the real HTTP interface; default http://127.0.0.1:8123
native_listen = "127.0.0.1:9001"     # native protocol for agents; "" (default) is off
native_addr = "127.0.0.1:9000"       # the real native port (default)
user = "ariodb"                      # ariodb's own login; default "default"
password_env = "ARIODB_CLICKHOUSE_PASSWORD"   # or password_secret
accept_invalid_certificate = false   # for https upstreams with a private CA
# tls_cert = "/etc/ariodb/ch.crt"    # with tls_key: both listeners speak TLS only
# tls_key = "/etc/ariodb/ch.key"
# tunnel = "ch"                      # must forward to whichever port is used
```

Agents log in with their name and token (HTTP Basic auth,
`X-ClickHouse-User` and `X-ClickHouse-Key`, or `user` and `password`
parameters) and need an `[agents.clickhouse]` block. Reads run with
`readonly = 2` and `max_execution_time` from `[limits]`. Client settings
other than formatting and query parameters are dropped. Table functions that
reach outside the server (`url`, `s3`, `file`, `remote` and others) and ones
that read tables named in strings (`merge`, `dictionary`, `cluster`,
`dictGet`, `joinGet`) are refused. One statement per request.

With `tls_cert` and `tls_key` set, both listeners accept TLS only, as
ClickHouse's own secure ports do: agents use `https://` and
`clickhouse-client --secure`.

### `on_failure`

ariodb always refuses a statement it cannot check. A top-level
`on_failure = "closed"` is accepted for clarity; `"open"` is refused when the
config loads, because letting statements through unchecked would defeat the
point.

## Command line

Every command takes `-c, --config <path>` (default `ariodb.toml`).

| Command | What it does |
|---|---|
| `check` | Check the config and print what it allows |
| `classify <sql>` | Show how ariodb understands a statement (no config needed) |
| `explain --agent <name> <sql>` | Show what the policy and before-stage rules would decide, without running it |
| `setup` | Prepare the database for the journal (run once, as a table owner with `REPLICATION`) |
| `serve` | Run the proxy, journal, dashboard, ClickHouse listeners and tunnels |
| `mcp --agent <name>` | Run an MCP server on stdio for one agent (token in `ARIODB_AGENT_TOKEN`) |
| `sessions` | List agent sessions that changed data |
| `undo --session <id> [--apply] [--skip-conflicts]` | Show, then apply, the undo plan for one session |
| `approvals [--all]` | List pending (or all) approval requests |
| `approve <id> [--note <text>]` | Approve a pending request |
| `deny <id> [--note <text>]` | Deny a pending request |
| `audit` | Check the decisions log's hash chain |
| `export-fixtures --out <dir> [--limit 500]` | Write recent decisions to `<dir>/recorded.json` as test fixtures |
| `test <file or dir>` | Replay fixtures against the policy; exit 0 all match, 1 drift, 2 error |
| `dashboard-password [--user root]` | Set a dashboard password, read from stdin |
| `secret set <name>` | Store a secret, read from stdin |
| `secret list` | List secret names (never values) |
| `secret delete <name>` | Delete a secret |

A fixture for `ariodb test`, one object or an array per `.json` file:

```json
{
  "name": "agents cannot read secrets",
  "action": { "agent": "coding-agent", "sql": { "statement": "SELECT * FROM secrets", "database": "app" } },
  "match":  { "verdict": "deny", "rule": "policy" }
}
```

`verdict` is `allow`, `deny` or `approve`. `rule` is optional; `policy`
means the built-in policy.

## Database roles

- **Gateway role** (`[database]`, `ARIODB_DATABASE_URL`): what agents'
  queries run as. Grant only what agents need on their tables. No superuser,
  no `REPLICATION`, no `pg_read_server_files`, no `pg_signal_backend`. Extra
  roles per agent go in `[[credentials]]`.
- **Journal role** (`ARIODB_JOURNAL_URL`): needs the `REPLICATION`
  attribute. `ariodb setup` runs as this role too, so for setup it must own
  the protected tables (to set `REPLICA IDENTITY FULL` and publish them).
- **Undo role** (`ARIODB_ADMIN_URL`, else the gateway role): needs to
  insert, update and delete on the protected tables.

The database role's privileges are the real boundary: a view or function the
gateway role can use can reach tables the allow-list does not name. See
[SECURITY.md](SECURITY.md).

## What undo can and cannot reverse

| Change | Handling |
|---|---|
| Insert, update, delete, including cascades and trigger effects | Undone, in one transaction |
| `TRUNCATE`, `DROP`, schema changes | Refused for agents, so never need undoing |
| Rows someone else changed after the session did | Reported as conflicts; with `--skip-conflicts` they are left alone and the rest undone, otherwise nothing is undone |
| Undo steps that would cascade (or fire triggers) into rows the session never touched | Refused; nothing is undone |
| Rows in tables without a primary key | Reported as not undoable; nothing is undone |
| A session already undone | Refused |
| Sequence values | Not rewound; gaps in IDs are harmless |
| ClickHouse writes | Not journaled; cannot be undone |
| Anything outside the database (emails, payments) | Out of scope |

## Dashboard

`ariodb serve` serves the dashboard on `[dashboard] listen`
(127.0.0.1:8080 by default). Sign in as `root` with the password set by
`ariodb dashboard-password`. On first run the password can also be set from
the dashboard itself, but only from the same machine.

Pages: overview; approvals (approve or deny with a note); decisions
(filter by agent, outcome, rule, session or text; turn a decision into a
test fixture; "block requests like this" builds a deny rule); sessions
(see the undo plan, then undo); rules (list, and explain a statement for an
agent); config (edit with a check before saving, database passwords
masked; saving needs `config_writes = true`); settings (secrets, users and a
decisions-log check).

Changes need a logged-in session, a CSRF token and a same-origin request.
Failed logins are limited per address and per user.

The front end is a React app (Vite, Tailwind CSS and shadcn/ui) in
`dashboard/`. Its built files in `dashboard/dist` are committed and embedded
in the binary, so `cargo build` needs no Node. After changing the front end:

```bash
./scripts/build-dashboard.sh   # npm ci and build into dashboard/dist; commit the result
```

For live reloading, run ariodb with its dashboard on 127.0.0.1:8080 (for
example `./scripts/demo.sh`), then `cd dashboard && npm run dev`; Vite passes
`/api` through to ariodb.

## Testing

```bash
cargo test                      # unit and property tests (PROPTEST_CASES=100000 for a longer hunt)
cargo build && ./scripts/e2e.sh # end to end against Postgres in Docker
./scripts/e2e-clickhouse.sh     # end to end against ClickHouse in Docker (needs cargo build)
./scripts/sim-undo.sh           # seeded random agent and human writes, then undo, checked against a model
SIM_SEEDS="42 7" SIM_OPS=120 ./scripts/sim-undo.sh   # other seeds, longer runs
```

Property tests (`src/proptests.rs`) throw random and generated input at the
SQL classifiers, the replication decoder and the wire-protocol reader. The
undo simulation (`tests/sim_undo.rs`) brackets every write with a snapshot
of the database, predicts each undo from those snapshots alone, and fails
with the seed, the plan and the history of the rows involved when ariodb
disagrees. The same seed always produces the same workload. `E2E_OFFSET`
and `E2E_NAME` keep parallel runs of the scripts apart.

## Limitations

- **ClickHouse native `INSERT` is refused** (as are external tables): use
  the HTTP interface for inserts. ClickHouse writes cannot be rolled back or
  undone; rules and approvals are the only control.
- **`COPY ... FROM STDIN` is refused**; use `INSERT`. Cursors cannot be read
  (`FETCH` is refused).
- **No undo for `TRUNCATE` or schema changes**: agents cannot run them.
- **No agent-controlled transactions.** ariodb runs each query string (or
  extended-protocol batch up to `Sync`) in its own transaction; `BEGIN`,
  `COMMIT` and savepoints from agents are refused.
- **`ariodb explain` and `ariodb test`** judge before-stage rules only; they
  cannot predict after-stage rules or the effect check, which need the write
  to run.
- **Databases only.** ariodb does not guard Kubernetes, HTTP APIs, SSH or
  other tools agents use.
- **Accepted risks** listed in [SECURITY.md](SECURITY.md): the decisions log
  is an unkeyed hash chain; tables reached through views and functions are
  not on the allow-list; model approvers can be prompt-injected; the first
  dashboard password can be set from loopback; there are no connection
  limits or handshake timeouts; agent tokens are not rate limited; ClickHouse
  agents may send their token as a URL parameter; repeated wrong passwords
  lock a dashboard user out for 15 minutes.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model, a deployment
checklist, the October 2026 review and how to report a vulnerability.

## Licence

Intended to be Apache-2.0. The licence file will be added before the first
public release; until then, no licence is granted.
