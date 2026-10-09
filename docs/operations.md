# Running ariodb in production

This page covers what it takes to run ariodb in front of a production
database: where to put it, TLS on every hop, the state directory and its
backups, what the log tells you, retention, tunnels, rotating credentials,
upgrades, performance and the limits on high availability. It is for the
engineer who deploys and looks after ariodb. It assumes you have a working
config; see [configuration](configuration.md) and the
[quick start](quickstart.md) first.

## What runs, and what it connects to

`ariodb serve` is one process. It starts any tunnels, then any plugins, then
listens for agents and reads the change journal.

```mermaid
flowchart LR
  subgraph agents[AI agents]
    pg[Postgres clients]
    ch[ClickHouse clients]
    mcp[MCP clients]
  end
  subgraph ariodb[ariodb serve]
    proxy[Postgres proxy :6543]
    chl[ClickHouse HTTP and native listeners]
    dash[Dashboard and callbacks :8080]
    journal[Journal reader]
    state[(State directory)]
  end
  mcpserver[ariodb mcp, one per agent session]
  pg --> proxy
  ch --> chl
  mcp --> mcpserver
  proxy --> db[(Postgres)]
  mcpserver --> db
  journal -- logical replication slot --> db
  chl --> click[(ClickHouse)]
  proxy --- state
  mcpserver --- state
  dash --- state
  journal --- state
```

Connections to the database:

- **One upstream connection per agent connection**, opened when the agent
  logs in and closed when it leaves. There is no pooling, so plan Postgres
  `max_connections` for the number of agent connections, plus one for the
  journal, plus short-lived ones for `doctor` at startup and for undo.
- **The journal** holds one connection (the journal login) and polls the
  replication slot every half second when idle.
- **ClickHouse HTTP** requests are relayed one for one; native-protocol
  connections get one upstream connection each.

Everything ariodb decides per statement goes to the decisions log in the
state directory, not to stdout. Use the dashboard, `ariodb audit`, or an
audit-sink [plugin](plugins.md) to read or ship it.

## Deployment shapes

ariodb only protects what goes through it. Whatever shape you choose,
firewall the database so agents can reach it only through ariodb, and give
agents no database credentials of their own.

### Beside the application

One ariodb per host or pod, next to the agents that use it, listening on
`127.0.0.1`. Agents connect over loopback, so TLS to ariodb is optional;
ariodb connects to the database over the network with TLS.

```mermaid
flowchart LR
  subgraph host[Agent host or pod]
    agent[Agent] -- 127.0.0.1:6543 --> ario[ariodb]
  end
  ario -- TLS --> db[(Postgres)]
```

Good for one team or one agent runtime. Each instance has its own state
directory, decisions log, approvals queue and dashboard. If several
instances journal the same database, each needs its own `[journal] slot`
and `publication` names (see [high availability](#high-availability)):
each slot then holds back WAL on the database, and each journal records
every change to its protected tables. Past two or three instances, prefer
the central gateway.

### Central gateway

One ariodb for many agents, on its own host, with the database reachable
only from it.

```mermaid
flowchart LR
  a1[Agent A] -- TLS :6543 --> gw[ariodb gateway]
  a2[Agent B] -- TLS :6543 --> gw
  a3[Agent C] -- TLS :8124 --> gw
  people[People] -- HTTPS --> rp[Reverse proxy] --> gw
  gw -- TLS --> db[(Postgres)]
  gw --> click[(ClickHouse)]
```

One decisions log, one approvals queue, one dashboard, and undo for every
agent. Agents connect over the network, so `require_tls = true` is
essential: agents send their token as a password.

### Running as a service

Run ariodb under its own system user, which owns the state directory and
can read the config and certificates. [Installation](installation.md#running-as-a-service-systemd)
has a complete, hardened systemd unit, the environment file for the
database URLs and tokens, and an admin wrapper for one-off commands.

Run one-off commands (`ariodb approvals`, `ariodb undo`, `ariodb secret
set`) as the same user, with the same `--config`, working directory and
environment as `serve`, so they use the same state directory: with the
wrapper from the installation page,
`sudo -u ariodb /usr/local/sbin/ariodb-admin approvals`.

In containers, mount the state directory on a persistent volume, run one
replica, and replace pods with a stop-then-start strategy (in Kubernetes,
`strategy: Recreate`), never a rolling update that runs two at once.

## TLS everywhere

Each hop is configured separately.

| Hop | How to encrypt it | Notes |
|---|---|---|
| Postgres agents to ariodb | `[proxy] tls_cert`, `tls_key`, `require_tls = true` | Agents use `sslmode=require` or `verify-full`. Without `require_tls`, an agent that does not ask for TLS gets a plain connection. |
| ClickHouse agents to ariodb | `[clickhouse] tls_cert`, `tls_key` | Both listeners then accept TLS only: `https://` and `clickhouse-client --secure`. There is no mixed mode. |
| MCP agents | Not needed | `ariodb mcp` speaks over stdin and stdout of a local process. |
| People to the dashboard | A reverse proxy in front | The dashboard speaks plain HTTP. Terminate TLS in front of it, set `public_url` to the `https://` address (which marks cookies `Secure`), and keep `listen` on `127.0.0.1`. |
| ariodb to Postgres | `[database] tls = "verify"` (default for non-local hosts) | Checked against public CA roots plus `ca_file`. See the `ca_file` limitation below. |
| ariodb to ClickHouse HTTP | `http_url = "https://..."` | For a private CA, `accept_invalid_certificate = true` (no CA-file option). |
| ariodb to ClickHouse native | Not supported directly | ariodb connects to `native_addr` in plain TCP. Keep that hop on a private network, or carry it through a tunnel (an SSH forward, for example). |
| ariodb to Slack, webhooks, chat and paging services, model providers | `https://` URLs | Model approvers and the Discord, Teams, Google Chat and Mattermost webhooks refuse plain `http` except to this machine. |
| ariodb to a mail server (email approvers) | `smtp_tls = "starttls"` (default) or `"tls"` | `"none"` is refused except for a mail server on this machine. |
| ariodb to an OpenID Connect provider | An `https://` issuer | Refused otherwise, except on this machine; the discovery document's endpoints are held to the same rule. |

Postgres agent connection with certificate checks:

```bash
psql "postgres://coding-agent@ariodb.internal.example:6543/app?sslmode=verify-full&sslrootcert=/etc/ssl/internal-ca.pem"
```

**Reverse proxy for the dashboard.** The dashboard refuses state-changing
requests whose `Origin` does not match the `Host` header, so the proxy must
pass the original `Host` through. With nginx:

```nginx
server {
    listen 443 ssl;
    server_name ariodb.internal.example;
    ssl_certificate     /etc/nginx/tls/ariodb.crt;
    ssl_certificate_key /etc/nginx/tls/ariodb.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

Behind a proxy on the same host, every request reaches ariodb from
loopback, and the first dashboard password can be set by any request from
loopback. Set it with `ariodb dashboard-password` before you expose the
dashboard.

**Limitation: `ca_file` on admin connections.** `[database] ca_file` is used
on agents' connections, but ariodb's own admin connections (`setup`,
`doctor`, the journal, `undo`) currently verify against the public roots
only. With a database certificate from a private CA and `tls = "verify"`,
those fail with `cannot connect: error performing TLS handshake`. Use a
publicly trusted certificate, `tls = "require"` (encrypted, not verified),
or a tunnel that handles TLS itself, until this is fixed.

## The state directory

`[journal] dir` (default `.ariodb`, relative to the working directory) holds
everything ariodb keeps. Set it to an absolute path in production.

| File | What it holds | Written by |
|---|---|---|
| `journal.jsonl` | One JSON line per committed transaction that changed a protected table: before- and after-images, the session and agent that made it (if an agent did). Undo reads it. | `serve` (the journal) |
| `ariodb.db` | SQLite, in WAL mode (with `ariodb.db-wal` and `ariodb.db-shm` beside it): the decisions log (hash-chained), approval requests and decisions, dashboard users (Argon2 password hashes) and sessions (token hashes), and audit-sink plugin positions. | `serve`, `mcp`, CLI commands |
| `secrets.json` | The encrypted secret store. | `ariodb secret set`, the dashboard |
| `master.key` | The secret store's key (base64), created `0600` on first use, unless `ARIODB_MASTER_KEY` is set. | first use of the store |

ariodb creates the directory with mode `0700` and logs a warning if an
existing one is looser:
`ariodb: warning: /var/lib/ariodb is readable by other users (mode 755); run chmod 700 on it`.
Anyone who can write here can rewrite the decisions log, approve requests
and read secrets (if `master.key` is here), so treat it like the database
credentials themselves.

`ariodb serve`, `ariodb mcp` processes and CLI commands on the same host
share the directory safely: SQLite serialises writers, and approvals made
with `ariodb approve` reach a statement waiting in `serve`. Do not put the
directory on a network file system shared between hosts.

## Backups, and what losing the state directory means

| If you lose | Effect | Recovery |
|---|---|---|
| `journal.jsonl` | Sessions recorded in it can no longer be undone. Conflict checks for later undos lose the history of those rows. | None for the lost period. The replication slot still holds changes ariodb had not yet read, so recording resumes from where the slot is. |
| `ariodb.db` | The decisions log (your audit trail), pending and past approvals, and dashboard users are gone. Audit-sink plugins receive entries again from the start. | Restore from backup, or start fresh and set the dashboard password again. |
| `secrets.json` | Every secret-store value. | Set them again with `ariodb secret set`. |
| `master.key` | Every secret becomes unreadable: `secret 'x' cannot be decrypted with this master key`. | Set every secret again. Avoid this by keeping the key in `ARIODB_MASTER_KEY`. |

How to back up:

- **`ariodb.db`** is in WAL mode, so copying the file while ariodb writes
  can give an inconsistent copy. Use SQLite's online backup:
  `sqlite3 /var/lib/ariodb/ariodb.db ".backup '/backup/ariodb-$(date +%F).db'"`,
  or stop `ariodb serve` and copy the directory.
- **`journal.jsonl`** is only appended to, and synced after each batch. A
  copy taken mid-write can end in a partial line, which `ariodb sessions`
  and `undo` then refuse to read (`journal.jsonl line N: ...`). Check the
  last line of a restored copy, or copy it while `serve` is stopped.
- **Keep the master key out of the same backup.** With
  `ARIODB_MASTER_KEY` set from your secrets manager, a stolen backup does
  not reveal the secrets.

## Logs and what to watch

ariodb writes plain lines to stdout (progress) and stderr (warnings and
errors), each prefixed `ariodb:`. Output from tunnels and plugins is
relayed line by line as `tunnel <name>: ...` and `plugin <name>: ...`.
There are no log levels, no JSON format and no metrics endpoint; collect
both streams with your usual log shipper.

Lines worth alerting on:

| Line | Meaning |
|---|---|
| `ariodb journal: <error>` | The journal cannot read the slot. Each distinct error is logged once, and it retries every few seconds. While it fails, changes pile up in the slot (and WAL on the database). |
| `ariodb: kept the previous config: <error>` | An edit to the config did not load; the old policy is still in force. |
| `ariodb: dashboard stopped: ...` / `ClickHouse HTTP proxy stopped: ...` / `ClickHouse native proxy stopped: ...` | That listener is down, but `serve` keeps running. |
| `ariodb: tunnel '<name>' exited with status 1; restarting in 4 s` | A tunnel is flapping; connections through it fail meanwhile. |
| `ariodb: plugin '<name>' ...; restarting it in 2 s` | A plugin is down; statements that need it are refused meanwhile. |
| `ariodb: model approver '<name>' (...) unavailable (...); failing open` | A model approver could not be reached and `llm_fail_mode = "open"` let a statement through. |
| `ariodb: could not prune the decisions log: ...` | Retention is not running. |
| `ariodb: <...> saved the config from the dashboard` / `set secret '<name>' from the dashboard` / `undid session ...` | Someone changed policy, secrets or data from the dashboard. |

Routine lines: `ariodb: reloaded <path>`, `ariodb: removed N decisions older
than 30 days`, and `ariodb: connection ended: <reason>` (an agent
connection that failed, for example during TLS).

For health checks, a TCP connection to the proxy port is enough (ariodb
treats a connect-and-hang-up as normal), and the ClickHouse HTTP listener
answers `GET /ping` with `Ok.`. Neither tells you the database is
reachable; watch the startup summary and the journal lines for that.

## The startup summary

When `serve` starts, it runs the same checks as `ariodb doctor` in the
background, logs every finding that is not `ok`, and ends with one line
saying which of ariodb's guarantees hold against this database:

```text
ariodb: reads yes; checked writes yes; undo yes
```

A degraded database says why, for example:

```text
ariodb: journal: ariodb_journal@db.internal.example:5432/app: replication slot 'ariodb' does not exist; run `ariodb setup`
ariodb: reads yes; checked writes yes; undo no (not set up (run ariodb setup))
```

`serve` keeps running whatever the summary says: reads and writes are
still checked, and statements ariodb cannot check are refused. Treat any
`no` as something to fix before relying on that guarantee, and run
`ariodb doctor` for the full report.

## Retention and growth

| What | Grows with | Pruned? |
|---|---|---|
| Decisions log (`ariodb.db`) | Every statement agents send | Yes: entries older than `[audit] retention_days` (default 30) are deleted hourly. `0` keeps everything. After pruning, `ariodb audit` checks the chain from the oldest remaining entry. |
| Approvals (`ariodb.db`) | Every held statement and every model decision | No. |
| Dashboard sessions (`ariodb.db`) | Logins | Expired sessions are removed at the next login. |
| `journal.jsonl` | Every write to a protected table, by anyone, with full before- and after-images | No. ariodb has no built-in rotation. |
| WAL held by the replication slot | Writes the journal has not read yet | Released as the journal reads them. |

**The journal file.** It records every change to the protected tables, not
just agents' changes, because undo needs other people's later changes to
detect conflicts. On a busy table it grows quickly. To trim it, stop
`ariodb serve`, move lines older than the sessions you could ever want to
undo to an archive, and start it again. Keep a copy: once a session's lines
are gone it cannot be undone.

**The replication slot.** While `ariodb serve` is stopped, or its journal
is failing, Postgres keeps every WAL segment the slot has not consumed, and
the database's disk can fill. `ariodb doctor` warns when the slot holds
back more than 1 GiB (`the slot holds back 3.2 GB of WAL; is ariodb serve
running?`). Monitor it from the database side:

```sql
SELECT slot_name, active,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS held_back
FROM pg_replication_slots
WHERE slot_name = 'ariodb';
```

As a safety net, set `max_slot_wal_keep_size` on the database. If the slot
then exceeds it, Postgres invalidates the slot: changes in the gap are
never journalled, and you must drop the slot and run `ariodb setup` again.
If you retire ariodb, drop the slot so it stops holding WAL:

```sql
SELECT pg_drop_replication_slot('ariodb');
DROP PUBLICATION ariodb;
```

**Write amplification.** `ariodb setup` sets `REPLICA IDENTITY FULL` on the
protected tables, so every update and delete writes the whole old row to
WAL. Expect more WAL on those tables.

## Tunnels in production

`[[tunnels]]` lets ariodb own the `cloud-sql-proxy`, IAP or SSH process that
carries its database connections (see
[configuration](configuration.md#tunnels)).

- `ariodb serve` refuses to start if a tunnel is not accepting connections
  within `ready_timeout_seconds`, and if its port is already in use
  (`tunnel 'pg': 127.0.0.1:5433 is already in use; stop whatever is
  listening there (another ariodb?) or pick another listen address`).
- A tunnel that exits is restarted after 1 s, doubling to 30 s, with the
  delay reset after a minute of good running. Agents' connections through
  it fail until it is back.
- The tunnel process runs as ariodb's user with ariodb's environment, so it
  can use the same cloud credentials. It is stopped with SIGTERM, then
  SIGKILL five seconds later, when ariodb stops.
- Tunnel changes need a restart of `ariodb serve`.

## Rotating credentials

### Agent tokens

The token is checked only when an agent logs in, so rotating it never cuts
off connections that are already open.

- **In the secret store** (`token_secret`): `openssl rand -hex 32 | ariodb
  secret set coding-agent-token`. The next login needs the new token; no
  restart.
- **In an environment variable** (`token_env`): change it where `ariodb
  serve` runs and restart `serve`. The restart closes every agent
  connection.

An agent has one token at a time, so give the agent its new token at the
same moment. To rotate without any failed logins, add a second
`[[agents]]` entry with a new name and the same access, move the agent to
it, then remove the old entry.

### Database passwords

Postgres keeps connections open when a role's password changes, so
existing agent sessions continue. New logins use whatever URL ariodb reads
at that moment (`ARIODB_DATABASE_URL` if set, otherwise the secret, otherwise
`url`).

The safest rotation uses two roles with the same grants (grant them through
a group role), so there is never a moment when ariodb holds a stale
password:

```sql
CREATE ROLE ariodb_gw_2 LOGIN PASSWORD 'not-a-real-password' IN ROLE ariodb_agents;
```

```bash
printf '%s\n' 'postgres://ariodb_gw_2:not-a-real-password@db.internal.example:5432/app' | ariodb secret set database-url
```

Then, once no connections use the old role (`SELECT count(*) FROM
pg_stat_activity WHERE usename = 'ariodb_gw'`), drop or disable it. With
one role, change the password in Postgres and then the secret straight
away; new agent logins in between fail with `database refused login`.

`ARIODB_DATABASE_URL`, `ARIODB_JOURNAL_URL` and `ARIODB_ADMIN_URL` are read
from ariodb's environment, so changing them needs a restart. The journal
keeps its connection until it drops, and reads the URL again when it
reconnects.

### Other secrets

The ClickHouse password, approver credentials (Slack, webhook and channel
secrets and webhook URLs), the single sign-on client secret and model API
keys are read when used, so `ariodb secret set` takes effect at once. Plugins read
`secret_env` when they start; restart `serve` to give them new values.

There is no command to re-encrypt the store under a new master key, and no
command prints secret values. Changing the key means stopping ariodb,
moving `secrets.json` aside, switching `ARIODB_MASTER_KEY` (or removing
`master.key` so a new one is made), and setting every secret again from
its source.

## Upgrades

ariodb is a single binary. An upgrade means a short outage for agents,
since they connect through it.

1. Read the release notes for anything that needs `ariodb setup` or a
   config change.
2. Check the config with the new binary before swapping:
   `./ariodb-new --config /etc/ariodb/ariodb.toml check`.
3. Back up the state directory (see [backups](#backups-and-what-losing-the-state-directory-means)).
4. Stop `ariodb serve` with SIGTERM. Agent connections close, and
   statements still waiting for approval never run; agents must resend
   them.
5. Replace the binary and start `serve`. The replication slot has kept
   every change made meanwhile, so the journal catches up. The decisions
   log's schema is upgraded in place when it opens.
6. Run `ariodb doctor` and check the startup summary. After a Postgres
   major upgrade (to 18 in particular), run `ariodb setup` again.

## Sizing and performance

ariodb does little work per statement itself; what adds latency is mostly
round trips and anything that waits.

| Adds latency | How much | What to do |
|---|---|---|
| Transaction wrapping | A few extra round trips between ariodb and the database per statement: `BEGIN` and the statement timeout, for writes the session tag and the effect measurement, then `COMMIT`. | Put ariodb close to the database. |
| Parsing and the decisions log | Postgres's own parser on each statement, and one SQLite insert. | Usually small; keep the state directory on local disk. |
| Approvals by people | As long as the person takes, up to `timeout_seconds` (default 90). | Hold only what needs a person. Agents' client timeouts must be longer than the approval timeout. An after-stage approval holds the write's row locks while it waits. |
| Model approvers | One provider call per held statement: typically seconds. With retries, a slow or failing provider can take up to about four minutes before `llm_fail_mode` decides; `timeout_seconds` does not bound it. | Use `llm_cache_seconds` (default 300) for repeated statements, a fast model, and low `effort`. |
| Plugin facts | One call per statement for each plugin a matching rule reads, up to `timeout_ms` (default 5000). | Keep facts plugins fast; set `facts_cache_ms`. |
| Plugin approvers | Up to the approver's timeout. | As for people. |

The `latency_ms` of each entry in the decisions log (and the dashboard)
includes approval waits, so it shows where time goes.

Other limits that matter for sizing:

- ariodb inspects at most 1 MiB per protocol message; larger messages are
  refused. Use several smaller statements.
- `ariodb mcp` returns at most 500 rows per query.
- Memory grows with concurrent connections and result sizes passing
  through; there are no connection limits on the listeners, so bound them
  with network controls (see [the security model](security-model.md)).

## High availability

ariodb is designed to run as **one instance per journal slot**, and today
that is the limit for high availability.

- The journal reads the replication slot, appends to its own
  `journal.jsonl`, and then advances the slot. Two instances reading the
  same slot would each record part of the stream and advance it past
  changes the other has not recorded, so undo becomes wrong. Postgres may
  also refuse one of them with `replication slot "ariodb" is active for PID
  ...`.
- Approvals, the decisions log and dashboard users live in the instance's
  SQLite file, which is not shared between hosts. A statement held for
  approval on one instance can only be decided on that instance.
- A second instance against the same database needs its own slot and
  publication names. It then keeps a complete journal of its own, but its
  own approvals, decisions log and dashboard, so it adds capacity, not
  failover for the first one's state.

What works:

- **Active and passive.** Run one `serve`. Keep a standby that can start
  with the same config and the same state directory (a persistent volume
  that moves to the standby, for example), and start it only after the
  first has stopped. The slot holds changes made in between.
- **Restart on failure.** With systemd `Restart=on-failure` or a single
  Kubernetes replica with `strategy: Recreate`, recovery takes seconds.
- **Separate databases, separate instances.** Each database (and each
  slot) can have its own ariodb.

Never run two instances with the same `[journal] slot` against the same
database, including during a rolling deploy.

## Next

- [Troubleshooting](troubleshooting.md): what the log lines and errors mean
- [Configuration reference](configuration.md): every key mentioned here
- [CLI reference](cli.md): `doctor`, `setup`, `undo` and the other commands
- [Security model](security-model.md): what ariodb defends and what it does not
- [Compatibility](compatibility.md): managed databases and what they support
