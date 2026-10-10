# ariodb

[![CI](https://github.com/roozjalali/ariodb/actions/workflows/ci.yml/badge.svg)](https://github.com/roozjalali/ariodb/actions/workflows/ci.yml)

ariodb is a safety proxy between AI agents and your databases. Agents
connect to it as if it were Postgres, MySQL, MariaDB or ClickHouse, or use
it as an MCP tool. ariodb checks every statement before it runs, forces
reads to be read-only, measures what every write actually changed before
it commits, holds risky statements for a person or a model to approve,
records every row an agent changed, and lets you undo one agent's session
later without touching anyone else's work. It is a single Rust binary with
a built-in dashboard, and it is source-available under the
[Sustainable Use License](#licence).

## Why

Giving an agent a database login gives it everything that login can do, at
machine speed, with nobody reading each statement. In practice three
things go wrong:

- **Mistakes.** The agent misreads a task and runs
  `UPDATE orders SET status = 'void'` without the `WHERE` it meant.
  Nothing about the statement looks unusual to the database.
- **Manipulation.** The agent reads text it should not trust (a support
  ticket, a web page, a row in the database itself) and that text tells it
  to export or drop a table. This is prompt injection: the agent's own
  judgement is what is being attacked, so it cannot be the defence.
- **Runaway writes.** A loop meant to touch ten rows touches ten thousand,
  or a trigger or cascade quietly changes tables the agent never named.

Database grants help, but they are coarse: a role that may update `orders`
may update every row of it. ariodb adds the checks grants cannot express
(per-agent table lists, statement kinds, row limits measured after the
fact, approval for particular statements) and a way back when something
gets through anyway.

## What it does

- **Speaks your database's protocol.** Postgres 14 to 18 and
  Postgres-compatible databases (TimescaleDB, Supabase, YugabyteDB,
  CockroachDB), MySQL 8.4 and MariaDB 11.4, and ClickHouse over HTTP and
  the native protocol. Agents use `psql`, `mysql`, `clickhouse-client` or
  any driver, with TLS between agents and ariodb and from ariodb to the
  database (except ClickHouse's native port).
- **Reads the SQL, not just its text.** Postgres statements are parsed
  with Postgres's own parser, including what hides inside
  `EXPLAIN ANALYZE`, `PREPARE`, `COPY (...)` and data-modifying `WITH`.
  MySQL and MariaDB statements go through a SQL parser cross-checked by a
  lexer that follows the server's own rules, and ClickHouse statements
  through a careful tokenizer. Anything ariodb cannot see inside is
  refused.
- **Forces reads to be read-only.** Every read runs in a `READ ONLY`
  transaction (on ClickHouse, with `readonly` set), so a read that hides a
  write is refused by the database itself.
- **Checks writes before they commit.** Each write runs in a transaction
  that is measured before commit, so rows changed by triggers, cascades
  and functions count. Too many rows, or a table the agent may not change,
  and the write is rolled back before the agent sees a result.
- **Has a built-in policy.** Default deny, per agent: each agent may only
  touch the tables listed for it, read-only or read and write. Destructive
  statements, schema changes, transaction control, most session settings
  and functions that would get round ariodb's checks are refused.
- **Takes rules in CEL.** On top of the policy, rules refuse a statement or
  hold it for approval, before it runs or after a write has run but before
  it commits. Rules reload while ariodb runs, and `ariodb test` checks
  them in CI.
- **Asks for approval.** A held statement waits for people (in the
  dashboard, the CLI, Slack, Discord, Telegram, Microsoft Teams, Google
  Chat, Mattermost, PagerDuty, Opsgenie, email or any webhook), for a model
  judging it against a written policy (Anthropic, OpenAI, Gemini, Azure
  OpenAI or any OpenAI-compatible service), or for a plugin.
- **Undoes one session.** A journal of before- and after-images, tagged by
  agent session, lets you reverse one session's changes in one
  transaction. Rows someone else changed since are reported as conflicts,
  never silently overwritten.
- **Keeps a decisions log.** Every statement, verdict, rule, row count,
  latency and approver, hash-chained, with retention, optional redaction
  of literal values, and export as test fixtures.
- **Has a dashboard.** Approvals, decisions, sessions and undo, rules,
  config, secrets, users and plugins, built into the binary. Single
  sign-on with any OpenID Connect provider, with viewer, approver and
  admin roles from the provider's groups.
- **Checks your database first.** `ariodb doctor` reports what your
  database supports (read-only reads, checked writes, undo) without
  changing anything.
- **Works as an MCP server.** `ariodb mcp` gives an agent one `query` tool
  for Postgres that goes through the same checks.
- **Takes plugins.** Any program that speaks JSON-RPC over stdin and
  stdout can approve statements, supply facts for rules, receive
  notifications or receive the decisions log. Examples in Python and
  TypeScript.
- **Keeps credentials away from agents.** Agents log in with their own
  tokens; database passwords live in environment variables or an encrypted
  secret store, and each agent can run as its own database role.
  Connection limits, in total and per agent, and a handshake timeout keep
  slow or greedy clients in check.

## How it works

```mermaid
flowchart LR
    A["AI agent<br/>(driver, CLI or MCP)"] -->|"agent name + token"| C["Classify the statement"]
    C --> P{"Built-in policy<br/>and rules"}
    P -->|refused| E["Error to the agent"]
    P -->|approve| AP{"People, models<br/>or plugins"}
    AP -->|denied or timed out| E
    AP -->|allowed| X
    P -->|allowed| X{"Read or write?"}
    X -->|read| RO["READ ONLY transaction"]
    X -->|write| W["Run, then measure<br/>before commit"]
    W -->|"over the limit or<br/>after-stage rule says no"| RB["Rollback"]
    W -->|ok| CM["Commit"]
    RO --> DB[("Database")]
    CM --> DB
    DB -->|"replication stream<br/>or binlog"| J["Journal, by session"]
    J --> U["Undo one session"]
    E & RB & CM & RO --> L["Decisions log"]
    L --> D["Dashboard"]
    U --> D
```

The [overview](docs/overview.md) walks through each step. ClickHouse has no
transactions, so its writes are judged before they run and cannot be
rolled back or undone; on MySQL and MariaDB the write check is weaker than
on Postgres (see [compatibility](docs/compatibility.md)).

## Quick start

The demo needs Docker, Rust (through [rustup](https://rustup.rs)), a C
compiler with libclang, and `psql`. From a clone of this repository:

```bash
./scripts/demo.sh
```

It builds ariodb, starts Postgres 16 in Docker with sample tables
(`customers`, `orders`, `secrets`), writes a config to `.ariodb-demo/`,
runs `ariodb setup` and `ariodb serve`, and sends some good and bad agent
statements so there is something to look at. Then connect as the agent:

```bash
psql "postgres://coding-agent:demo-agent-token@127.0.0.1:6543/app?sslmode=disable"
```

and open the dashboard at <http://127.0.0.1:8080> (user `root`, password
`demo-dashboard-password`). Try:

- `DELETE FROM orders`: refused, because it has no `WHERE`.
- `UPDATE orders SET status = 'void' WHERE id < 600`: runs, is measured
  at hundreds of rows, and is rolled back because the demo's limit is 200.
- `SELECT name, email FROM customers`: waits until you approve it on the
  dashboard's Approvals page.

Ctrl-C stops everything and removes the container. Every password in the
demo is a throwaway test value.

For a real setup (database roles, the config file, secrets, `ariodb
doctor`, `ariodb setup`, then a refusal, a rollback, an approval and an
undo) follow the [quickstart](docs/quickstart.md). To run ariodb as a
service, see [installation](docs/installation.md).

## Configuration

One TOML file, `ariodb.toml` by default. This one protects a Postgres
database for one agent, holds large writes for a person, and keeps every
credential out of the file:

```toml
[database]
url = "postgres://ariodb_gw@db.internal.example:5432/app"   # the password comes from ARIODB_DATABASE_URL
tls = "verify"

[limits]
max_rows_per_write = 200      # a write that changes more is rolled back
statement_timeout_ms = 5000

[proxy]
listen = "127.0.0.1:6543"     # where agents connect

[journal]
dir = "/var/lib/ariodb"       # state: journal, decisions log, secrets

[[agents]]
name = "coding-agent"         # the user name the agent logs in with
access = "read_write"
tables = ["orders", "customers"]
token_env = "ARIODB_TOKEN_CODING_AGENT"

[[rules]]
name = "big-writes-need-a-person"
stage = "after"               # judged on what the write did, before commit
condition = "effects.rows > 50"
verdict = "approve"
approve = ["ops"]
reason = "writes over 50 rows need a person to agree"

[[rules]]
name = "no-file-functions"
condition = "sql.functions.exists(f, f.matches('(^|[.])pg_(read_file|read_binary_file|ls_dir|stat_file)$'))"
verdict = "deny"
reason = "functions that read server files are off-limits"

[[approvers]]
name = "ops"
type = "dashboard"            # decide in the dashboard or with `ariodb approve`

[dashboard]
listen = "127.0.0.1:8080"
public_url = "https://ariodb.internal.example"
```

Then, with the credentials in the environment:

```bash
export ARIODB_DATABASE_URL='postgres://ariodb_gw:not-a-real-password@db.internal.example:5432/app'
export ARIODB_JOURNAL_URL='postgres://ariodb_journal:not-a-real-password@db.internal.example:5432/app'
export ARIODB_TOKEN_CODING_AGENT="$(openssl rand -hex 32)"

ariodb check                  # validate the file and show what it allows
ariodb doctor                 # what this database supports; changes nothing
ariodb setup                  # once: replica identity, publication, replication slot
ariodb dashboard-password     # set the first dashboard password, read from stdin
ariodb serve                  # the proxy, journal and dashboard
```

The agent connects to `postgres://coding-agent:<token>@127.0.0.1:6543/app`,
or runs `ariodb mcp --agent coding-agent` with its token in
`ARIODB_AGENT_TOKEN`. Every section and key is in the
[configuration reference](docs/configuration.md); the repository's
[`ariodb.toml`](ariodb.toml) is a longer example.

## Documentation

| Page | What it covers |
|---|---|
| [Documentation index](docs/README.md) | Reading orders for new users, operators and contributors |
| [Overview](docs/overview.md) | The problem, how a statement flows through ariodb, key concepts, what it does not do |
| [Quickstart](docs/quickstart.md) | The demo, then a complete setup against Postgres in Docker |
| [Installation](docs/installation.md) | Requirements, building, systemd, containers and upgrading |
| [Configuration](docs/configuration.md) | Every section of `ariodb.toml`, environment variables and the secret store |
| [CLI](docs/cli.md) | Every `ariodb` command, its options and its output |
| [Postgres](docs/postgres.md) | Roles and grants, TLS, the wire proxy, the write check and the journal |
| [MySQL and MariaDB](docs/mysql.md) | Logins and grants, binlog settings, how writes are counted, undo and its limits |
| [ClickHouse](docs/clickhouse.md) | The HTTP and native-protocol proxies, inserts and their limits |
| [Compatibility](docs/compatibility.md) | Tested databases, managed services and `write_check = "reported"` |
| [Policy](docs/policy.md) | The built-in, default-deny policy |
| [Rules](docs/rules.md) | CEL rules, their facts, stages and how they combine, with a cookbook |
| [Testing policies](docs/testing-policies.md) | `ariodb classify`, `explain` and `test`, and fixtures in CI |
| [Approvals](docs/approvals.md) | People, chat and paging channels, email, webhooks, models and plugins |
| [Plugins](docs/plugins.md) | The plugin protocol and the Python and TypeScript examples |
| [Undo](docs/undo.md) | Sessions, undo plans, conflicts and what cannot be reversed |
| [Dashboard](docs/dashboard.md) | The pages, users and roles, single sign-on and reverse proxies |
| [MCP](docs/mcp.md) | Giving an agent ariodb as an MCP tool |
| [Operations](docs/operations.md) | Deployment shapes, logs, backups, retention, credential rotation |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms, causes and fixes |
| [Security model](docs/security-model.md) | Threats, guarantees, accepted risks, the security review and a hardening checklist |
| [Architecture](docs/architecture.md) | The module map, the request lifecycle and the tests |

## Status and compatibility

ariodb is at version 0.1.0, its first public release. Its end-to-end
suites drive real databases in Docker with real clients, but it is young:
the config format and the plugin protocol may change before 1.0, and the
[changelog](CHANGELOG.md) will say when they do.

| Database | Reads forced read-only | Writes checked before commit | Undo |
|---|---|---|---|
| PostgreSQL 14 to 18, TimescaleDB, Supabase | yes | yes | yes |
| YugabyteDB, CockroachDB | yes | with `write_check = "reported"` | no |
| MySQL 8.4, MariaDB 11.4 | yes | yes, a weaker check | yes |
| ClickHouse | yes | judged before running; no rollback | no |

Managed Postgres services (RDS, Aurora, Cloud SQL, AlloyDB, Azure, Neon
and others) are expected to work; [compatibility](docs/compatibility.md)
has the details and the settings undo needs. Run `ariodb doctor` against
your own database to be sure. ariodb runs on Linux and macOS.

## Security

ariodb's job is to stand between untrusted agents and your data, so its
own security matters. The [security model](docs/security-model.md) sets
out what it defends against, what it guarantees, what it deliberately does
not (the database role's grants remain the real boundary), the findings of
its security review, and a hardening checklist for production.

Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## Contributing

Bug reports, fixes and documentation improvements are welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to build ariodb, run each
test suite, and send a pull request, including the Developer Certificate
of Origin sign-off every commit needs. Everyone taking part is expected to
follow the [code of conduct](CODE_OF_CONDUCT.md).

## Licence

ariodb is source-available under the
[Sustainable Use License, version 1.0](LICENSE), with Rooz Jalali as the
licensor. In plain English (the licence text is what counts, and this is
not legal advice):

- **You may** use ariodb, and change it, for your own organisation's
  internal business purposes: for example, in front of your company's own
  databases, for your own agents, in production.
- **You may** use it for personal or non-commercial purposes, and share it,
  changed or not, free of charge for non-commercial purposes, as long as
  the licence goes with it and changed copies say they were changed.
- **You may not** sell ariodb, charge for distributing it, or offer it to
  others as a hosted or managed service or as part of a product you sell.
- **You may not** remove or obscure its licence, copyright or other
  notices.

If you want to use ariodb in a way the licence does not allow, ask the
maintainer. Dependencies keep their own licences.
