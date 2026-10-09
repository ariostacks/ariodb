# Command-line reference

This page lists every `ariodb` command and flag, with examples, exit codes,
and what each command needs: the config file, a database connection,
tunnels, the state directory or plugins. It is for engineers running
ariodb by hand, in deployment scripts or in CI. The commands are defined in
[`src/main.rs`](../src/main.rs); the help text below is what `ariodb 0.1.0`
prints.

## Synopsis

```text
$ ariodb --help
ariodb lets AI agents write to Postgres safely, and undoes what they changed

Usage: ariodb [OPTIONS] <COMMAND>

Commands:
  check               Check the config file and print what it allows
  classify            Show how ariodb understands a SQL statement
  setup               Prepare the database for the journal (run once, as an admin)
  serve               Run the proxy agents connect to, and the change journal
  doctor              Check what this database supports: read-only reads, checked writes, undo
  mcp                 Run an MCP server on stdio for one agent
  sessions            List agent sessions that changed data
  undo                Undo everything one session changed
  audit               Check the audit log has not been edited
  test                Replay fixtures against the policy and report verdict drift (for CI)
  approvals           List approval requests (pending ones unless --all)
  export-fixtures     Write recorded decisions as test fixtures for `ariodb test`
  approve             Approve a pending request
  deny                Deny a pending request
  dashboard-password  Set a dashboard password (read from stdin). The first user is "root"
  secret              Manage encrypted secrets (database URLs, agent tokens)
  plugin              List plugins, or try one out
  explain             Show what the policy would decide for a statement, without running it
  help                Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to the config file [default: ariodb.toml]
  -h, --help             Print help
  -V, --version          Print version
```

`-c, --config` works before or after the command name
(`ariodb -c /etc/ariodb/ariodb.toml check` and `ariodb check -c ...` are
the same). Every command except `classify` loads and validates the config
first, and stops with exit code 1 if it does not load (2 for `test`). See
[configuration](configuration.md#validation-errors) for those messages.

## What each command needs

| Command | Config | Database | Tunnels | State directory | Plugins |
|---|---|---|---|---|---|
| `check` | yes | no | no | only to read `token_secret` and `secret` values | no |
| `classify` | no | no | no | no | no |
| `explain` | yes | no | no | only if `[database] secret` is used | no |
| `test` | yes | no | no | only if `[database] secret` is used | no |
| `setup` | yes | yes, journal login | starts or reuses | no | no |
| `doctor` | yes | yes, every login | starts or reuses | only for secrets | no |
| `serve` | yes | yes | starts its own | yes | starts all |
| `mcp` | yes | yes | starts or reuses | yes | starts approvers and facts |
| `sessions` | yes | no | no | reads `journal.jsonl` | no |
| `undo` | yes | yes, admin login | starts or reuses | reads `journal.jsonl` | `--apply` starts them to notify |
| `approvals`, `approve`, `deny` | yes | no | no | `ariodb.db` | no |
| `audit`, `export-fixtures` | yes | no | no | `ariodb.db` | no |
| `dashboard-password` | yes | no | no | `ariodb.db` | no |
| `secret set`, `list`, `delete` | yes | no | no | `secrets.json`, `master.key` | no |
| `plugin list`, `plugin test` | yes | no | no | for `secret_env` | starts them |

"Starts or reuses" means: a tunnel whose `listen` port already answers
(because `ariodb serve` is running it) is used as it is; otherwise the
command starts the tunnel for its own run and stops it afterwards.

Commands that open the state directory create it (mode `0700`) if it is
missing, and the secret store creates `master.key` on first use. Run them
as the same user as `ariodb serve`, with the same `--config`, or they will
read and write a different state directory.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. `explain` exits 0 whatever the verdict; `doctor` exits 0 when no check failed (warnings are fine). |
| 1 | An error (printed as `error: ...` on stderr), a config that does not load, `doctor` with a failed check, `plugin test` with a failed check, `test` with drift. |
| 2 | `test` only: the config or the fixtures could not be loaded. Also any command-line usage error, such as an unknown command or a missing argument. |

## Checking and explaining

### `ariodb check`

Validate the config and print what it allows. Does not connect to anything.
Run it after every edit: unknown keys are silently ignored, so read the
summary back.

```text
$ ARIODB_TOKEN_CODING_AGENT=agent-token-local-test-only ariodb check
database      postgres://ariodb_gw:***@localhost:5432/app
row limit     500 rows per write
timeout       5000 ms
proxy         127.0.0.1:6543
journal       .ariodb
if checks fail, refuse the statement (fail closed)

agent coding-agent     read and write  token set  orders, customers
agent support-bot      read only       no token   orders
```

Tunnels, plugins and credentials that use a tunnel are listed too. `no
token` means the agent's variable or secret is empty here; set it where
`ariodb serve` runs. `no agents configured: every agent will be refused`
means the config has no `[[agents]]`.

### `ariodb classify <SQL>`

Show how ariodb's parser understands a statement: its kind, the tables it
names and the reason. Needs no config, so it works anywhere. Several
statements separated by `;` are shown one per line.

```text
$ ariodb classify "UPDATE orders SET status = 'void' WHERE id = 7"
write                tables: orders                   update

$ ariodb classify "DELETE FROM orders; SELECT * FROM customers"
destructive          tables: orders                   DELETE without WHERE removes every row
read                 tables: customers                select

$ ariodb classify 'SELECT 1; DO $$ BEGIN END $$'
read                 tables: -                        select
unknown              tables: -                        DO blocks run arbitrary code
```

SQL that does not parse exits 1:

```text
$ ariodb classify "SELEC nonsense"
error: cannot parse SQL: Error splitting: syntax error at or near "SELEC"
```

### `ariodb explain --agent <AGENT> [--engine <ENGINE>] <SQL>`

Show what the built-in policy and the before-stage rules would decide for
one agent, without running anything. `--engine` is `postgres` (default) or
`clickhouse`; with `clickhouse`, the agent's `[agents.clickhouse]` access
applies and the database is `default`.

```text
$ ariodb explain --agent coding-agent "SELECT email FROM customers"
approve  (decided by: customer-emails-need-a-human)  reading customer emails needs a person to agree

$ ariodb explain --agent coding-agent "DELETE FROM orders"
deny  (decided by: policy)  destructive statements are never allowed for agents: DELETE without WHERE removes every row

$ ariodb explain --agent support-bot "UPDATE orders SET status = 'x' WHERE id = 1"
deny  (decided by: policy)  agent 'support-bot' is read only
```

`decided by: policy` means the built-in policy; `-` means nothing objected.
`explain` cannot predict after-stage rules or the row-limit check, which
need the write to run, and it does not start plugins, so rules that read
plugin facts count as unevaluable (a deny). It exits 0 whatever the
verdict; use `ariodb test` when you need an exit code.

### `ariodb test <FIXTURES>`

Replay fixtures against the policy and report drift, for CI. `FIXTURES` is
a `.json` file or a directory of them; each file holds one fixture or an
array. The format is described in [testing policies](testing-policies.md).

```text
$ ariodb test fixtures/
DRIFT  support bot may update orders: expected allow, got deny (rule policy) agent 'support-bot' is read only
ok     agents cannot empty orders
ok     customer emails need a person

1 drifted, 2 match
```

| Exit code | Meaning |
|---|---|
| 0 | Every fixture matches (`2 fixtures match`). |
| 1 | At least one fixture drifted. |
| 2 | The config or the fixtures could not be loaded (`error: fixtures: No such file or directory (os error 2)`). |

```bash
# in CI
ariodb --config deploy/ariodb.toml test policy-fixtures/
```

### `ariodb export-fixtures --out <OUT> [--limit <LIMIT>]`

Write recent decisions from the decisions log as fixtures to
`<OUT>/recorded.json` (default limit 500), so today's verdicts become
regression tests. Decisions that depended on data rather than policy
(rollbacks, failures) are left out. Reads the state directory only.

```text
$ ariodb export-fixtures --out policy-fixtures --limit 200
wrote 143 fixtures to policy-fixtures/recorded.json
```

## Setting up and running

### `ariodb setup`

Prepare the database for the journal. Run it once before the first `serve`,
and again whenever you give an agent write access to a new table or
upgrade to Postgres 18. It is safe to run repeatedly. It does nothing when
`[journal] enabled = false`.

It connects with `ARIODB_JOURNAL_URL` (or the gateway URL), which must have
the `REPLICATION` attribute and own the protected tables. It checks
`wal_level`, sets `REPLICA IDENTITY FULL` on every protected table, creates
or updates the publication, and creates the logical replication slot.

```text
$ ARIODB_JOURNAL_URL='postgres://ariodb_journal:not-a-real-password@db.internal.example:5432/app' ariodb setup
ok   wal_level is logical
ok   orders: changes will carry full before-images
ok   customers: changes will carry full before-images
ok   publication 'ariodb' covers customers, orders
ok   replication slot 'ariodb' is ready
```

Failures stop at the first problem with exit 1; see
[troubleshooting](troubleshooting.md#setup-failures).

### `ariodb doctor`

Check what this database supports with ariodb in front of it: reads forced
read-only, writes measured before commit, and undo. It connects as the
gateway login, as every `[[credentials]]` entry an agent uses, and as the
journal login. Every check is read-only or runs in a transaction that is
rolled back; each login's checks give up after 30 seconds.

```text
$ ariodb doctor
default login: ariodb_gw@db.internal.example:5432/app
  ok    connected over TLS
  ok    PostgreSQL 16.4
  ok    reads run in READ ONLY transactions, and the database enforces them
  ok    writes are measured before commit (a 3-row test write counted 3)
  ok    writes can be tagged with their session for the journal
  ok    every agent table exists and this login can use it

journal: ariodb_journal@db.internal.example:5432/app
  ok    wal_level is logical
  ok    replication slot 'ariodb' exists
  ok    publication 'ariodb' covers every table agents may change
  ok    protected tables keep full before-images (REPLICA IDENTITY FULL)
  ok    the change stream can be read, with session tags
  ok    the slot holds back 312 kB of WAL

what works here
  yes  reads, forced read-only
  yes  writes, checked before commit
  yes  undo of agent sessions
```

Lines are marked `ok`, `warn` or `FAIL`. It exits 1 (`error: some checks
failed`) if any line is `FAIL`; warnings alone exit 0. With no database
reachable:

```text
$ ariodb doctor
default login: ariodb_gw@127.0.0.1:1/app
  FAIL  cannot connect: error connecting to server

journal: ariodb_gw@127.0.0.1:1/app
  FAIL  cannot connect: error connecting to server

what works here
  no   reads, forced read-only: default login: cannot connect: error connecting to server
  no   writes, checked before commit: default login: cannot connect: error connecting to server
  no   undo of agent sessions: cannot connect: error connecting to server
error: some checks failed
```

`ariodb serve` runs the same checks once at startup and logs a one-line
summary (see [operations](operations.md#the-startup-summary)).

### `ariodb serve`

Run everything: tunnels first, then plugins, then the Postgres proxy, the
journal, the dashboard, the ClickHouse listeners, the config watcher and
the hourly decisions-log prune. It runs in the foreground and logs to
stdout and stderr; stop it with Ctrl-C or SIGTERM, which stops plugins and
tunnels in order and exits 0.

```text
$ ariodb serve
ariodb: agents can connect to postgres://<agent>@0.0.0.0:6543 (TLS available)
ariodb: dashboard at https://ariodb.internal.example
ariodb: journal is recording changes to /var/lib/ariodb/journal.jsonl
ariodb: reads yes; checked writes yes; undo yes
```

It exits 1 if a tunnel does not come up, or if the Postgres proxy cannot
start (for example `error: cannot listen on 0.0.0.0:6543: Address already
in use (os error 98)`). A dashboard or ClickHouse listener that cannot
start is logged (`ariodb: dashboard stopped: ...`) but does not stop
`serve`. Run exactly one `serve` per journal slot; see
[operations](operations.md#high-availability).

### `ariodb mcp --agent <AGENT>`

Run an MCP server on stdin and stdout for one agent. It offers one tool,
`query`, which goes through the same checks as the proxy. The agent's token
must be in `ARIODB_AGENT_TOKEN` and match the configured one. It starts the
configured plugins for approvers and facts, but not as audit sinks, which
`ariodb serve` handles. Writes are tagged for the journal, so undo needs
`ariodb serve` running against the same slot. See [MCP](mcp.md).

```json
{
  "mcpServers": {
    "ariodb": {
      "command": "/usr/local/bin/ariodb",
      "args": ["--config", "/etc/ariodb/ariodb.toml", "mcp", "--agent", "coding-agent"],
      "env": { "ARIODB_AGENT_TOKEN": "agent-token-local-test-only" }
    }
  }
}
```

Errors before the server starts: `error: unknown agent 'x'`,
`error: agent 'coding-agent' has no token set`,
`error: ARIODB_AGENT_TOKEN does not match this agent's token`.

## Sessions and undo

### `ariodb sessions`

List agent sessions that changed data, from `journal.jsonl`. Does not
connect to the database.

```text
$ ariodb sessions
session        agent              txns   rows  status     tables
s-3f9c2a71b0   coding-agent          4     12             orders
s-81d0e6c4aa   coding-agent          1      3  undone     orders, order_items
```

With nothing recorded: `no agent changes recorded yet`.

### `ariodb undo --session <SESSION> [--apply] [--skip-conflicts]`

Show, then apply, the plan to reverse everything one session changed. It
connects with `ARIODB_ADMIN_URL` (or the gateway URL). Without `--apply`
nothing changes. The full behaviour, including conflicts and what cannot be
undone, is in [undo](undo.md).

```text
$ ariodb undo --session s-3f9c2a71b0
undo plan for s-3f9c2a71b0: 3 steps
  restore public.orders row (7)
  restore public.orders row (8)
  delete inserted public.orders row (1201)

nothing changed. Run again with --apply to undo.

$ ariodb undo --session s-3f9c2a71b0 --apply
undo plan for s-3f9c2a71b0: 3 steps
  ...

undone: 3 rows restored in one transaction
```

| Flag | What it does |
|---|---|
| `--session <SESSION>` | The session id from `ariodb sessions` or the dashboard. Required. |
| `--apply` | Make the changes, in one transaction. |
| `--skip-conflicts` | Undo the rows nobody else has touched since, and leave conflicting rows alone. Without it, any conflict means nothing is undone. |

Exit 1 with `error: rows were changed by others since; nothing was undone.
Use --skip-conflicts to undo the rest.`, `error: some changes cannot be
undone: ...`, `error: session 's-...' was already undone` or `error: no
recorded changes for session 's-...'`.

<!-- TODO: document undo of MySQL and MariaDB sessions once merged. -->

## Approvals

### `ariodb approvals [--all]`

List approval requests: pending ones, or with `--all` requests of every
status (up to 100). Reads the state directory, so it must run on the same host
and as the same user as `ariodb serve`.

```text
$ ariodb approvals
a-5d2e8f1c0b9a  pending  agent coding-agent   rule customer-emails-need-a-human                              SELECT email FROM customers WHERE id = 42
```

With nothing waiting: `nothing waiting for approval` (or `no approval
requests` with `--all`).

### `ariodb approve <ID> [--note <NOTE>]` and `ariodb deny <ID> [--note <NOTE>]`

Decide a pending request. The decision is recorded as `cli:<$USER>`, and
the waiting statement continues (or is refused) within a fraction of a
second.

```text
$ ariodb approve a-5d2e8f1c0b9a --note "checked with the account owner"
approved a-5d2e8f1c0b9a

$ ariodb deny a-5d2e8f1c0b9a
error: a-5d2e8f1c0b9a is not pending (already decided, expired, or unknown)
```

The second form exits 1.

## The decisions log

### `ariodb audit`

Check the decisions log's hash chain, from the oldest remaining entry.

```text
$ ariodb audit
decisions log intact: 1843 entries checked
```

A broken chain exits 1 with `error: chain broken at entry 912 (it was
edited)` or `error: chain broken at entry 912 (an entry before it was
removed or changed)`. The chain is unkeyed, so it detects casual edits, not
an attacker who controls the host; see [the security
model](security-model.md).

## Dashboard and secrets

### `ariodb dashboard-password [--user <USER>]`

Set a dashboard password, read from stdin (at least 12 characters). The
default user is `root`; any other name creates or updates that user.
Setting a password ends that user's existing sessions.

```bash
printf '%s\n' 'not-a-real-password-123' | ariodb dashboard-password
# password set for 'root'
```

Too short: `error: use a password of at least 12 characters`.

### `ariodb secret set <NAME>`, `secret list`, `secret delete <NAME>`

Manage the encrypted secret store. `set` reads the value from stdin, so it
stays out of shell history; `list` prints names, never values. See
[configuration](configuration.md#the-secret-store).

```text
$ openssl rand -hex 32 | ariodb secret set coding-agent-token
stored secret 'coding-agent-token'
$ ariodb secret list
coding-agent-token
database-url
$ ariodb secret delete old-token
error: no secret named 'old-token'
```

An empty stdin exits 1 with `error: no value on stdin`.

## Plugins

### `ariodb plugin list`

Start each configured plugin once, show what it declares, and stop it.

### `ariodb plugin test <NAME>`

Start one plugin and send it a sample call for each capability it
declares. Exits 1 if any check fails.

```text
$ ariodb plugin test office_hours
started: ariodb-example 1.0.0
  ok    approve: allow (within the example policy)
  ok    facts: {"freeze":false,"hour_gmt":10,"out_of_hours":false,"weekday":"fri"}
  ok    notifier: sent a test event (notifications get no answer)
  ok    audit: acknowledged
```

With no plugins configured, `plugin list` prints `no plugins configured`.
See [plugins](plugins.md#commands).

## Next

- [Configuration reference](configuration.md): every key the commands read
- [Operations](operations.md): running `serve` in production
- [Troubleshooting](troubleshooting.md): what the error messages mean
- [Testing policies](testing-policies.md): fixtures for `ariodb test`
- [Undo](undo.md) and [approvals](approvals.md): the workflows behind these commands
