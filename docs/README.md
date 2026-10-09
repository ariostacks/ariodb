# ariodb documentation

ariodb is a safety proxy between AI agents and databases. It checks every
statement an agent sends, forces reads to be read-only, measures every
write before it commits, records every row an agent changes, and lets a
person undo one agent's session. This is the index of its documentation: a
suggested reading order for new users, operators and contributors, then one
line on every page. ariodb is source-available under the Sustainable Use
License.

## Where to start

**New to ariodb?** Read in this order:

1. [Overview](overview.md): what ariodb does, how a statement flows through
   it, and the vocabulary.
2. [Quickstart](quickstart.md): the demo, then a complete setup against a
   local Postgres.
3. [Policy](policy.md): what agents may and may not do before any rule is
   written.
4. [Rules](rules.md): refusing statements and holding them for approval.
5. [Approvals](approvals.md): who can approve, and how.
6. [Undo](undo.md): reversing one agent session.
7. [Dashboard](dashboard.md): the web interface.

**Deploying and running it?** Read in this order:

1. [Installation](installation.md): building, running as a service,
   containers, upgrading.
2. [Postgres](postgres.md): roles, privileges, TLS and logical replication.
   For MySQL or MariaDB, [MySQL and MariaDB](mysql.md) instead.
3. [Compatibility](compatibility.md): which databases and managed services
   support what.
4. [Configuration](configuration.md): every section of `ariodb.toml`.
5. [Security model](security-model.md): the threat model and deployment
   checklist.
6. [Operations](operations.md): monitoring, backups and day-to-day running.
7. [Troubleshooting](troubleshooting.md): what common errors mean.
8. [CLI](cli.md): every command.

**Contributing?** Read in this order:

1. [Overview](overview.md), then [Architecture](architecture.md): the
   module map and the request lifecycle.
2. [Security model](security-model.md) and [SECURITY.md](../SECURITY.md):
   what the code must keep guaranteeing.
3. [Testing policies](testing-policies.md) and the tests section of
   [Architecture](architecture.md#tests).
4. [Plugins](plugins.md): the plugin protocol, if you are extending ariodb
   from outside.

## Every page

**Getting started**

- [Overview](overview.md): the problem, the end-to-end flow, key concepts,
  and what ariodb does not do.
- [Installation](installation.md): requirements, building from source,
  systemd, containers and upgrading.
- [Quickstart](quickstart.md): the demo script and a step-by-step setup
  against Postgres in Docker.

**Configuring**

- [Configuration](configuration.md): the reference for `ariodb.toml`,
  environment variables and the secret store.
- [CLI](cli.md): every `ariodb` command, its options and its output.

**Databases**

- [Postgres](postgres.md): connecting agents, database roles, TLS, the
  journal and what the proxy supports.
- [ClickHouse](clickhouse.md): the HTTP and native-protocol proxies and
  their limits.
- [MySQL and MariaDB](mysql.md): connecting agents, the gateway and
  journal logins, binlog settings, how writes are counted, undo and its
  limits.
- [Compatibility](compatibility.md): tested databases, managed services,
  and `write_check = "reported"`.

**Deciding what agents may do**

- [Policy](policy.md): the built-in, default-deny policy.
- [Rules](rules.md): CEL rules, their variables, stages and how they
  combine.
- [Testing policies](testing-policies.md): `ariodb explain`,
  `ariodb test` and fixtures in CI.
- [Approvals](approvals.md): dashboard, CLI, Slack, webhook, model and
  plugin approvers.
- [Plugins](plugins.md): approvers, rule facts, notifiers and audit sinks
  as external programs.

**After the fact**

- [Undo](undo.md): sessions, undo plans, conflicts, and what cannot be
  reversed.
- [Dashboard](dashboard.md): approvals, decisions, sessions, rules, config
  and settings in the browser.

**Agents as tools**

- [MCP](mcp.md): giving an agent ariodb as an MCP tool instead of a
  database connection.

**Running in production**

- [Operations](operations.md): logs, monitoring, the replication slot,
  backups and retention.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes.
- [Security model](security-model.md): threats, guarantees, accepted risks
  and the deployment checklist.

**Inside ariodb**

- [Architecture](architecture.md): the module map, the request lifecycle,
  the journal, undo, the store, the dashboard, plugins and the tests.

Also in the repository: [README.md](../README.md) for a summary and
[SECURITY.md](../SECURITY.md) for the security review and how to report a
vulnerability.

## Next

- [Overview](overview.md)
- [Quickstart](quickstart.md)
- [Installation](installation.md)
