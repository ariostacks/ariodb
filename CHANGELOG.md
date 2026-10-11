# Changelog

All notable changes to ariodb are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and ariodb uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change the config format or the plugin protocol; such
changes are listed under "Changed" with what to do.

## [Unreleased]

### Added

- `ariodb report` and a **Report pack** download on the dashboard's
  Decisions page: compliance report packs for a period (a print-ready
  HTML report, CSV and JSON records and a SHA-256 manifest) whose sections
  name the DORA, SOC 2, ISO/IEC 27001 and EU AI Act controls they give
  evidence for. ariodb now records each config version in force (masked)
  and who applied each undo, for these reports. See
  [compliance reports](docs/reports.md).

## [0.1.0] - Unreleased

The first public release.

### Added

**Databases and protocols**

- A Postgres wire-protocol proxy for `psql` and any driver: the simple and
  extended (prepared statement) protocols, TLS on both sides, SCRAM to the
  database and cancel requests. Tested with Postgres 14 to 18,
  TimescaleDB and Supabase; YugabyteDB and CockroachDB work with
  `write_check = "reported"`.
- A MySQL and MariaDB proxy for the `mysql` client and any driver, tested
  with MySQL 8.4 and MariaDB 11.4, with TLS, prepared statements and
  cancellation.
- A ClickHouse proxy for the HTTP interface and the native protocol
  (`clickhouse-client`), for reads and `INSERT`. Native inserts are counted
  against the row limit before any row reaches ClickHouse.
- An MCP server (`ariodb mcp`) offering one `query` tool that goes through
  the same checks as the proxies.
- Tunnels: ariodb can start and supervise cloud-sql-proxy, an IAP tunnel
  or an SSH port-forward, and reach databases through it.

**Checking statements**

- A built-in, default-deny policy per agent: each agent may only touch the
  tables listed for it, read-only or read and write. Destructive
  statements, schema changes, transaction control, most session settings
  and functions that would get round ariodb's checks are refused, as is
  anything ariodb cannot parse or see inside.
- Postgres statements are read with Postgres's own parser, including what
  is inside `EXPLAIN ANALYZE`, `PREPARE`, `DECLARE`, `COPY (...)` and
  data-modifying `WITH` clauses.
- Reads run in `READ ONLY` transactions (on ClickHouse, with `readonly`
  set), so a read that hides a write is refused by the database itself.
- Writes run in a transaction that is measured before commit: rows changed
  by triggers, cascades and functions count. A write over the row limit,
  or one that touches a table the agent may not change, is rolled back
  before the agent sees a result.
- Rules in CEL that refuse a statement or hold it for approval, before it
  runs or after a write has run but before it commits. Rules reload while
  ariodb runs.
- `ariodb classify`, `ariodb explain` and `ariodb test`, so rules can be
  tried out and checked in CI against fixtures, including fixtures
  exported from real decisions (`ariodb export-fixtures`).
- Connection limits on the listeners, in total and per agent, and a
  handshake timeout (`[limits] max_connections`,
  `max_connections_per_agent` and `handshake_timeout_ms`).

**Approvals**

- Approval by people in the dashboard or the CLI (`ariodb approve`,
  `ariodb deny`), in Slack (with buttons), Discord, Telegram, Microsoft
  Teams, Google Chat and Mattermost, through PagerDuty and Opsgenie, by
  email, or through any webhook. Chat, paging and email messages carry
  signed links to a confirmation page, so none of those services needs to
  reach ariodb.
- Approval by a model judging the statement against a written policy:
  Anthropic, OpenAI, Gemini, Azure OpenAI or any OpenAI-compatible service,
  including local models. Fails closed by default.
- Approval by a plugin.

**Undo and the decisions log**

- A change journal of before- and after-images, tagged by agent session:
  from a logical replication slot on Postgres, and from the binlog on
  MySQL and MariaDB.
- Undo of one agent session in one transaction (`ariodb undo`, or from
  the dashboard), with a plan to review first. Rows someone else changed
  since are reported as conflicts and never silently overwritten.
- A hash-chained decisions log of every statement, verdict, rule, row
  count and latency, and who or what approved it, with retention and
  optional redaction of literal values. `ariodb audit` checks the chain.

**Dashboard**

- A web dashboard built into the binary: approvals, decisions, sessions
  and undo, rules, a config editor, secrets, users and plugins.
- Single sign-on with any OpenID Connect provider, with viewer, approver
  and admin roles mapped from the provider's groups, and approvers that
  only certain groups may decide. Local passwords remain for break-glass
  use.

**Running it**

- `ariodb doctor`, which reports what a database supports (read-only
  reads, checked writes, undo) without changing anything.
- `ariodb setup`, which prepares a database for the journal.
- An encrypted secret store (`ariodb secret`), so credentials stay out of
  the config file, and per-agent database credentials.
- Plugins: any program speaking JSON-RPC over stdin and stdout can approve
  statements, supply facts for rules, receive notifications or receive the
  decisions log. Examples in Python and TypeScript.
- Documentation in `docs/`: quickstart, installation, configuration and
  CLI references, per-database guides, the security model, operations and
  troubleshooting.

### Security

- The October 2026 security review's findings are fixed, each with a test
  that fails without the fix; the findings, and the risks accepted with
  reasons, are in `docs/security-model.md`.
