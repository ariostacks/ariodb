# Troubleshooting

This page lists the problems people meet when deploying and running ariodb,
grouped by symptom, with the exact messages ariodb prints so you can search
for them, what causes each one and how to fix it. It is for whoever is on
the hook when an agent says "ariodb refused my query" or ariodb will not
start. Messages in `monospace` are quoted from the code; names such as
`coding-agent`, `orders` and addresses are examples.

## Where to look first

```mermaid
flowchart TD
  start[Something is wrong] --> loads{Does ariodb check pass?}
  loads -- no --> cfg[Fix the config: see configuration validation errors]
  loads -- yes --> db{Does ariodb doctor pass?}
  db -- no --> conn[Connection, TLS, setup or capability problem: sections below]
  db -- yes --> one{One statement refused?}
  one -- yes --> explain[ariodb explain --agent NAME SQL, and the decisions log]
  one -- no --> logs[Read ariodb's log: journal, tunnel, plugin and listener lines]
```

1. **`ariodb check`** validates the config and shows each agent, whether its
   token is set, and the database it points at. Run it as the same user and
   with the same environment as `ariodb serve`.
2. **`ariodb doctor`** connects as every login ariodb uses and says what
   works: read-only reads, checked writes and undo, with the reason when
   not.
3. **`ariodb explain --agent <name> "<sql>"`** shows what the policy and
   before-stage rules decide for one statement, and which rule decided.
4. **The decisions log** (the dashboard's decisions page) records every
   statement with its outcome, rule, reason, rows and latency.
5. **ariodb's log** (stdout and stderr). See
   [operations](operations.md#logs-and-what-to-watch) for the lines that
   matter.

How errors reach agents:

- **Postgres clients** see refusals as `ERROR:  ariodb: <reason>` with
  SQLSTATE `42501` (insufficient privilege). Problems opening the session
  arrive as `FATAL:  ariodb: <reason>` with SQLSTATE `08006`. Errors without
  the `ariodb:` prefix come from the database itself.
- **ClickHouse clients** see `Code: 497. DB::Exception: ariodb: <reason>.
  (ARIODB)`. Errors without `ariodb:` come from ClickHouse.
- **MCP clients** get a tool result marked as an error, reading `Refused by
  ariodb: <reason>`, or `Postgres error <code>: <message>` for errors from
  the database.

## Connection and TLS failures

### Agents cannot connect to ariodb

| Message | Cause | Fix |
|---|---|---|
| `FATAL:  ariodb requires TLS; connect with sslmode=require` | `[proxy] require_tls = true` and the client did not ask for TLS. | Add `sslmode=require` (or `verify-full`) to the agent's connection string. |
| `server does not support SSL, but SSL was required` (from psql or libpq) | The client asked for TLS and `[proxy]` has no `tls_cert` and `tls_key`. | Configure the certificate and key, and restart `serve`. |
| `ariodb: connection ended: TLS: ...` in ariodb's log | The TLS handshake with the agent failed: often the client rejected ariodb's certificate (wrong name, untrusted CA). | Issue the certificate for the name agents use, and give agents the CA. |
| `connection refused` on port 6543 | `serve` is not running, `[proxy] listen` is on `127.0.0.1` while the agent connects from elsewhere, or `listen = ""`. | Check `ariodb check`'s `proxy` line; listen on a reachable address. Listen changes need a restart. |
| `ERROR:  ariodb: message of 2097152 bytes is over the 1 MiB inspection limit` (SQLSTATE `54000`) | One protocol message (a statement with its parameters) is over 1 MiB. The connection stays open. | Send smaller statements. |

### ariodb cannot reach the database (agent connections)

These arrive at the agent as `FATAL:  ariodb: ...` when it logs in.

| Message | Cause | Fix |
|---|---|---|
| `ariodb: cannot reach db.internal.example:5432: Connection refused (os error 111)` | Nothing listening at that address, or a firewall. (`os error 61` on macOS.) | Check the URL's host and port from the ariodb host (`nc -vz db.internal.example 5432`). |
| `ariodb: cannot reach db.internal.example:5432 through tunnel 'pg' (127.0.0.1:5433): Connection refused (os error 111)` | The tunnel is down or restarting. | Look for `tunnel 'pg'` lines in the log; see [tunnels](#tunnels). |
| `ariodb: db.internal.example:5432 does not accept TLS (set tls = "disable" to connect without it)` | The database does not offer TLS. TLS is required by default for any host other than `localhost`, `127.x` or `::1`, including container names such as `db`. | Turn on TLS on the database, or set `tls = "disable"` under `[database]` (or the credential) for a private network. |
| `ariodb: TLS to db.internal.example: invalid peer certificate: UnknownIssuer` | `tls = "verify"` and the database's certificate is not signed by a public CA. | Set `ca_file` to the CA certificate (PEM). Managed services publish theirs (Amazon RDS's regional bundle, for example). This fixes agents' connections only; see [ariodb's own connections](#ariodbs-own-connections-fail-setup-doctor-journal-undo) for `setup`, `doctor`, the journal and undo. |
| `ariodb: TLS to 10.20.0.5: invalid peer certificate: certificate not valid for name "10.20.0.5"; certificate is only valid for ...` | The URL's host does not match the certificate. | Use the host name on the certificate in the URL. With a tunnel, the URL keeps the real host name and only the dial address changes. |
| `ariodb: database refused login: password authentication failed for user "ariodb_gw"` | The password in ariodb's database URL is wrong. | Fix `ARIODB_DATABASE_URL`, the secret, or the credential's URL. |
| `ariodb: database refused login: no pg_hba.conf entry for host "10.0.3.7", user "ariodb_gw", database "app", no encryption` | The database does not accept this login from ariodb's address, or requires TLS. | Add a `pg_hba.conf` entry (or the managed equivalent), or turn on TLS. |
| `ariodb: the database asked for a password but the URL has none` | The URL has no password. Often `[database] secret` names a secret that is not set, so ariodb fell back to `url`. | `ariodb secret list`, then `ariodb secret set <name>`; or put the URL in `ARIODB_DATABASE_URL`. |
| `ariodb: unsupported SASL mechanisms: ...` / `unsupported authentication method 7` | The database asks for an authentication method ariodb does not speak. ariodb supports password, MD5 and SCRAM-SHA-256. | Use password or SCRAM authentication for ariodb's logins. |
| `ariodb: credential 'reporting': set ARIODB_REPORTING_URL to its postgres:// URL` | The agent uses a credential whose variable is not set where `serve` runs. | Set it and restart `serve`, or switch the credential to `secret`. |
| `ariodb: credential 'reporting': secret 'reporting-url' is not set (ariodb secret set reporting-url)` | As it says. | `ariodb secret set reporting-url`. No restart needed. |
| `ariodb: bad database URL: ...` / `database URL needs a TCP host` / `database URL needs a user` | The URL cannot be used. Unix-socket URLs are not supported. | Use `postgres://user:password@host:port/database`. |

### ariodb's own connections fail (setup, doctor, journal, undo)

These use a different client library, which reports less detail. The
database's own log usually has the full reason.

| Message | Cause | Fix |
|---|---|---|
| `cannot connect: error connecting to server` | Network: host, port, firewall, or a tunnel that is down. | As for agent connections above; `ariodb doctor` shows which login. |
| `cannot connect: error performing TLS handshake` | TLS failed. In the current code, `[database] ca_file` is not used on these connections, so a private CA fails here even when agents connect fine. | Use a publicly trusted certificate, `tls = "require"` (encrypted, not verified), or a tunnel that handles TLS. |
| `cannot connect: db error` | The database refused: wrong password, unknown database, or `pg_hba.conf`. | Check the database log for the exact reason, and `ARIODB_JOURNAL_URL` / `ARIODB_ADMIN_URL`. |

### Tunnels

| Message | Cause | Fix |
|---|---|---|
| `tunnel 'pg': cannot start cloud-sql-proxy: No such file or directory (os error 2)` | The program is not on ariodb's `PATH`. | Use an absolute path in `command`. |
| `tunnel 'pg' exited with status 1 before it accepted connections on 127.0.0.1:5433` | The tunnel program failed. Its own output is in the log as `tunnel pg: ...`. | Read those lines (credentials, instance name, permissions). |
| `tunnel 'pg' did not accept connections on 127.0.0.1:5433 within 30 s (ready_timeout_seconds)` | Slow start, or it listens on a different port than `listen`. | Match the port in `command` and `listen`; raise `ready_timeout_seconds`. |
| `tunnel 'pg': 127.0.0.1:5433 is already in use; stop whatever is listening there (another ariodb?) or pick another listen address` | `serve` found the port taken. One-off commands reuse a running tunnel; `serve` will not. | Stop the other process (often an earlier `serve`), or change the port. |
| `ariodb: tunnel 'pg' exited with status 255; restarting in 8 s` | The tunnel keeps dying while `serve` runs. | Read its `tunnel pg:` lines. The delay doubles to 30 s and resets after a minute of good running. |

### Listeners that do not start

| Message | Fix |
|---|---|
| `error: cannot listen on 0.0.0.0:6543: Address already in use (os error 98)` | Another process (often another ariodb) holds the port. `serve` exits. |
| `ariodb: dashboard stopped: dashboard cannot listen on 127.0.0.1:8080: Address already in use (os error 98)` | The dashboard is down but `serve` keeps running. Free the port or change `[dashboard] listen`, then restart. |
| `ariodb: ClickHouse HTTP proxy stopped: cannot listen on ...` / `ClickHouse native proxy stopped: ...` | As for the dashboard. |
| `error: proxy.require_tls needs proxy.tls_cert and proxy.tls_key` | Add the certificate and key. |
| `error: /etc/ariodb/proxy.key: no private key found` | The file is not a PEM private key. |

## Authentication failures

### Agents rejected at login

`FATAL:  password authentication failed for user "coding-agent"` (SQLSTATE
`28P01`) is deliberately the same for every cause, so it does not reveal
which agents exist. Check, in order:

1. **The user name is the agent's `name`**, exactly. Many tools put the
   database name or a default user here.
2. **The token is set where `ariodb serve` runs.** `ariodb check` in the
   same environment must say `token set` for that agent. With `token_env`,
   the variable must be in `serve`'s own environment (the systemd
   `EnvironmentFile`, the container's env); changing it needs a restart.
3. **The token matches exactly.** Comparison is byte for byte, so a
   trailing newline or space in the agent's copy or in the environment
   variable fails. `ariodb secret set` strips the trailing newline from
   stdin; environment files may not.
4. **The client sends a cleartext password when asked.** ariodb asks for
   the token as a cleartext password inside the (TLS) connection. Clients
   configured for client certificates only, or for Kerberos, will not send
   it.

### ClickHouse agents rejected

| Message | Cause |
|---|---|
| `Code: 516. DB::Exception: ariodb: coding-agent: unknown agent. (ARIODB)` | No agent by that name, or its token is not set. |
| `Code: 516. DB::Exception: ariodb: coding-agent: wrong token. (ARIODB)` | The token does not match. |
| `Code: 516. DB::Exception: ariodb: coding-agent: this agent has no ClickHouse access. (ARIODB)` | The agent has no `[agents.clickhouse]` block. |
| `Code: 516. ...` without `ariodb:` | ClickHouse refused ariodb's own login: check `[clickhouse] user` and its password. |

Agents send their name and token as HTTP Basic auth, `X-ClickHouse-User`
and `X-ClickHouse-Key` headers, or `user` and `password` URL parameters
(which proxies may log; prefer the others). With `clickhouse-client`, use
`--user coding-agent --password <token>`.

### MCP server will not start

| Message | Fix |
|---|---|
| `error: unknown agent 'coding-agent'` | Use an agent `name` from the config. |
| `error: agent 'coding-agent' has no token set` | Its `token_env` variable or `token_secret` is empty in the MCP process's environment or state directory. |
| `error: ARIODB_AGENT_TOKEN does not match this agent's token` | Put the agent's token in `ARIODB_AGENT_TOKEN` in the MCP client's server definition. |

### The secret store

| Message | Cause | Fix |
|---|---|---|
| `secret 'database-url' cannot be decrypted with this master key` | The store was written with a different key: `ARIODB_MASTER_KEY` changed, or `master.key` was replaced or not restored with `secrets.json`. | Restore the original key, or set the secret again. |
| `ARIODB_MASTER_KEY must be 32 bytes, base64-encoded` | The variable is malformed. | Generate one with `openssl rand -base64 32`. |
| `/var/lib/ariodb/master.key is not a valid key` | The key file was edited or truncated. | Restore it from where you keep it. |
| `secret 'slack-bot-token' is not set` | A `*_secret` key names a secret that does not exist in this state directory. | `ariodb secret list`, then `ariodb secret set`. Check that the command ran with the same `--config` (and so the same state directory) as `serve`. |
| `ariodb: warning: /var/lib/ariodb is readable by other users (mode 755); run chmod 700 on it` | The state directory is too open. | `chmod 700 /var/lib/ariodb`. |

## Setup failures

`ariodb setup` stops at the first problem. It runs as `ARIODB_JOURNAL_URL`
(or the gateway URL if that is not set), which needs the `REPLICATION`
attribute (or the managed-service equivalent, such as `rds_replication`)
and must own the protected tables.

| Message | Cause | Fix |
|---|---|---|
| `wal_level is 'replica'; set it to 'logical' and restart Postgres (on managed services, enable logical replication)` | Logical decoding is off. | Self-managed: `ALTER SYSTEM SET wal_level = logical;` and restart. Managed: see [compatibility](compatibility.md#expected-to-work-untested) for each service's setting. |
| `no agent has write access, so there is nothing to protect` | No `read_write` agent. | Nothing to do: the journal is only needed for writes. Set `[journal] enabled = false`, or add a `read_write` agent first. |
| `orders: must be owner of table orders` | The setup login does not own a protected table, so it cannot set `REPLICA IDENTITY FULL` or publish it. | Run setup as a role that owns the tables and has `REPLICATION` (on Supabase, `supabase_admin`). Both `REPLICA IDENTITY FULL` and adding a table to the publication need ownership. |
| `orders: relation "orders" does not exist` | An agent lists a table that is not there, or is in another schema. | Fix the table name; other schemas are written `schema.table`. |
| `permission denied for database app` | Creating a publication needs `CREATE` on the database. | `GRANT CREATE ON DATABASE app TO ariodb_journal;` |
| `permission denied to use replication slots` (Postgres 16 and later) or `must be superuser or replication role to use replication slots` (earlier versions) | The setup login lacks `REPLICATION`. | `ALTER ROLE ariodb_journal REPLICATION;` (`GRANT rds_replication TO ariodb_journal;` on RDS). |
| `cannot connect: ...` | See [ariodb's own connections](#ariodbs-own-connections-fail-setup-doctor-journal-undo). | |

`ariodb doctor` checks the same things afterwards and names the fix:

| Doctor line | Fix |
|---|---|
| `replication slot 'ariodb' does not exist; run `ariodb setup`` | Run setup. |
| `replication slot 'ariodb' belongs to another database or plugin; pick another [journal] slot name` | Another tool (or another database on the same server) uses that slot name. Set `[journal] slot` to something unique, then run setup. |
| `publication 'ariodb' does not exist; run `ariodb setup`` / `publication 'ariodb' leaves out orders; run `ariodb setup` again` | An agent was given a new table since setup. Run setup again after every such change. |
| `tables without full before-images (REPLICA IDENTITY FULL): orders; run `ariodb setup` again` | Without full before-images, updates and deletes cannot be undone. Run setup again. |
| `Postgres 14 or later is needed for undo: before 14 the change stream cannot carry the session tags. Set [journal] enabled = false` | Upgrade, or run without undo. |
| `Postgres 18 refuses updates to tables with generated columns until the publication includes them; run `ariodb setup` again` | Run setup again after upgrading to 18. |
| `the slot holds back 3.2 GB of WAL; is `ariodb serve` running?` | The journal is not consuming the slot. Start `serve`, or look for `ariodb journal:` errors. See [operations](operations.md#retention-and-growth). |
| `this login cannot change 'orders'` / `this login cannot read 'orders'` / `table 'orders' does not exist` | The gateway role (or the agent's credential) lacks grants. Grant only what each agent needs. |

### The journal at run time

| Message | Cause | Fix |
|---|---|---|
| `ariodb journal: <database error>` | The journal cannot read the slot (connection, permissions, slot dropped). Logged once per distinct error; it retries. | Fix the cause; the slot keeps changes meanwhile. |
| `ariodb journal: replication slot "ariodb" is active for PID 12345` | Another process is reading the same slot, usually a second ariodb. | Run one `serve` per slot. See [high availability](operations.md#high-availability). |
| `/var/lib/ariodb/journal.jsonl line 812: ...` from `sessions` or `undo` | A damaged line, often a partial last line from a backup taken mid-write. | Remove or repair that line (keep a copy). |
| `update without before-image; run `ariodb setup`` from `undo` | The table lost `REPLICA IDENTITY FULL` (or was journalled before setup). | Run setup again. Changes recorded before that cannot be undone. |

## Writes refused because they cannot be measured

By default ariodb runs each write in a transaction, asks Postgres which
tables it changed and by how many rows (`pg_stat_xact_user_tables`), and
compares that with the row counts the database reports. If it cannot see
what a write did, it rolls the write back rather than guess.

| Message the agent sees | Cause | Fix |
|---|---|---|
| `ariodb: rolled back: the database reported 5 changed rows but ariodb measured 0, so this write cannot be checked (run `ariodb doctor`)` | The database does not count changes in `pg_stat_xact_user_tables`: YugabyteDB, CockroachDB, writes to foreign tables (`postgres_fdw`), or `track_counts = off`. | Run `ariodb doctor`. For YugabyteDB and CockroachDB, set `write_check = "reported"` under `[database]` and read [what it gives up](compatibility.md#write_check--reported). Turn `track_counts` back on if it was off. |
| `ariodb: rolled back: the statement also changed table 'order_audit', which agent 'coding-agent' may not change (2 orders, 2 order_audit)` | A trigger or cascade changed a table the agent may not change. This is ariodb working as intended. | If the agent should be allowed that side effect, add the table to its `tables`. |
| `ariodb: rolled back: the statement would change 1200 rows (1200 orders); the limit is 500` | Over the row limit, including rows changed by triggers and cascades. | Narrow the statement, or raise `max_rows_per_write` for that agent. |
| `ariodb: rolled back: the statement would change 1200 rows (as counted by the database); the limit is 500` | The same, under `write_check = "reported"`. | As above. |
| An error from `pg_logical_emit_message` on every write (for example `unknown function: pg_logical_emit_message()` on CockroachDB) | The journal is on, and the database cannot tag writes with their session. Doctor says `writes cannot be tagged for the journal`. | Set `[journal] enabled = false` on that database; writes then cannot be undone. |
| `COPY ... FROM STDIN is not supported through ariodb; use INSERT` (or `ariodb does not relay COPY FROM STDIN`) | Bulk loading through `COPY` is not relayed. | Use `INSERT`. |

Doctor's matching lines: `writes cannot be measured (...), so ariodb
refuses every write; read_only agents still work. [database] write_check =
"reported" allows writes with a weaker check`, and `YugabyteDB does not
count changes to its tables in pg_stat_xact_user_tables, so ariodb rolls
back every write. Set [database] write_check = "reported" to allow writes
with a weaker check`.

## Statements refused by the policy

Most refusals are the built-in policy or a rule doing its job. Run
`ariodb explain --agent <name> "<sql>"` to see which, and read
[policy](policy.md) and [rules](rules.md). The common ones:

| Message | Meaning |
|---|---|
| `agent 'support-bot' is read only` | A write from a `read_only` agent. |
| `agent 'coding-agent' may not use table 'customers'` | The table is not in the agent's `tables`. Names ignore case and `public.`; other schemas need `schema.table`. |
| `destructive statements are never allowed for agents: DELETE without WHERE removes every row` | `DROP`, `TRUNCATE`, and `DELETE` or `UPDATE` without `WHERE` are always refused. |
| `schema changes are not allowed for agents; make them on a branch and review` | DDL is always refused. |
| `ariodb runs every statement in its own transaction; send statements without BEGIN or COMMIT` | Agents cannot control transactions. Turn off the driver's explicit transactions (autocommit on). |
| `session settings are not allowed for agents` / `agents may not change the 'search_path' setting` | `SET` is refused, except for a short list of formatting and timeout settings that drivers send when they connect (see [policy](policy.md)). If a driver sets something else on connect, turn that off or pass it as a connection parameter. |
| `the function 'dblink' is never allowed for agents: it would get round ariodb's checks` | A function on the built-in refusal list. |
| `ariodb cannot check this statement: ...` / `DO blocks run arbitrary code` | `DO`, `CALL`, `EXECUTE`, `FETCH` and similar cannot be inspected. |
| `cannot parse SQL: ...` | The statement does not parse with Postgres's parser. |
| `rule 'change-freeze' could not be evaluated: ...` | A rule's condition failed at run time, which counts as a deny. The rest of the message says why. |
| `ariodb: the function-call protocol is not supported` | A rarely used protocol feature some old drivers use. |

## Approvals timing out or failing

A held statement waits for every approver its rule lists, in order. The
agent sees the rule's reason followed by why it did not go through, for
example `ERROR:  ariodb: writes over 50 rows need a person to agree: no
decision from 'ops' within 90 seconds`.

| Message | Cause | Fix |
|---|---|---|
| `no decision from 'ops' within 90 seconds` | Nobody decided in time. | Make sure people are told (a Slack or webhook approver, or a plugin notifier), or raise `timeout_seconds` on the approver or under `[approvals]`. |
| `the agent disconnected, so the request was withdrawn` / `the agent cancelled the statement, so the request was withdrawn` | The agent gave up first, usually because its own client timeout is shorter than the approval timeout. | Raise the agent's statement or tool-call timeout above the approval timeout. |
| `the agent disconnected while the statement waited` | The approval arrived just as the agent left; the statement did not run. | As above. |
| `denied by dashboard:root (not during the freeze)` | A person denied it; the note follows. | |
| `the approval request expired` | It expired before a decision. | As for the timeout. |
| `could not reach approver 'ops-slack': Slack said: not_in_channel` | The Slack bot is not in the channel (`channel_not_found`, `invalid_auth` and the like are Slack's own codes). | Invite the bot, or fix the channel ID or token. |
| `could not reach approver 'pager': webhook answered 500 Internal Server Error` | The webhook receiver failed. | Fix the receiver; the request is refused at once rather than waiting. |
| `could not reach approver 'pager': environment variable ARIODB_WEBHOOK_SECRET is not set` | A `*_env` key names a variable missing from `serve`'s environment. | Set it and restart, or use the `*_secret` form. |

**Slack buttons do nothing**, or Slack shows an error after a click: set
the Slack app's interactivity request URL to `<public_url>/slack/actions`,
make sure Slack can reach that address over HTTPS, and check
`signing_secret_*`. A click on a request that already timed out answers
`This request was already decided or has expired.`; a signature from a
different Slack approver answers `this request is not waiting on a Slack
approver`.

**Webhook links open a page instead of deciding.** That is deliberate: a
`GET` on an approve or deny link only shows the request and a button, so
link previews cannot decide. Receivers that decide programmatically must
`POST` to the link.

**After-stage approvals and locks.** While an after-stage approval waits,
the write's transaction stays open and holds its row locks. Other sessions
that touch those rows wait too. Keep after-stage approval timeouts short.

**A request stays "pending" after a restart.** Statements waiting when
`serve` stopped never ran, because their connections closed. Their
approval records remain; ignore them, and have the agent resend.

## Model approver failures

Every model failure refuses the statement, except an outage under
`llm_fail_mode = "open"`. The message names the approver and the model as
`model:<provider>/<model>`.

| Message | Cause | Fix |
|---|---|---|
| `denied by model approver 'model' (model:anthropic/claude-opus-5-5): <reason>` | The model denied it, with its reason. | Working as intended, or adjust the `policy` text. |
| `model approver 'model' (...) is misconfigured: HTTP 401: <provider message>` | Wrong or missing API key. 403 and 404 (often an unknown model or deployment) land here too. Configuration errors always refuse. | Fix the key, `model` or `base_url`. |
| `model approver 'model' (...) is misconfigured: set api_key_secret, api_key_env or ANTHROPIC_API_KEY` | No key found. | Set one of them where `serve` runs. |
| `model approver 'model' (...) is misconfigured: HTTP 301: ...` | The address redirects. ariodb never follows redirects, so the key and statements do not go to an address you did not configure. | Use the final address in `base_url`. |
| `model approver 'model' (...) unavailable (HTTP 529); failing closed` | The provider is overloaded or down (also network errors, 408, 429, 5xx) after three tries. | Wait, or use another provider. `failing open` instead means `llm_fail_mode = "open"` let it through. |
| `... unavailable (HTTP 429; asked to wait 120 s); failing closed` | The provider asked for a longer back-off than ariodb waits (30 s). | Reduce traffic, raise your rate limit, or rely on `llm_cache_seconds`. |
| `... unavailable (response was not JSON); failing closed` | Something in between (a proxy or gateway) answered with an error page. | Check `base_url` and any HTTP proxy. |
| `the model's answer could not be read` / `the model's answer was ambiguous` / `the model gave no answer` | The answer was not exactly one JSON object with `decision` and `reason`. Common with small local models through `openai_compatible`. | Use a model that follows structured output, or a larger one. |
| `the model declined to review this request` / `the model's answer was cut short` / `the provider's content filter stopped the answer` | The provider refused, ran out of output, or filtered. | Rephrase the policy; for content filters, review the provider's settings. |

A model approver is not bounded by `timeout_seconds`. With retries, a slow
provider can hold a statement for up to about four minutes; agents with shorter
timeouts give up first.

## Plugin failures

Any plugin failure on a path that decides a statement refuses it. Plugins'
own stderr appears in ariodb's log as `plugin <name>: ...`. Use `ariodb
plugin test <name>` to exercise one outside the request path. The protocol
is in [plugins](plugins.md).

| Message | Cause | Fix |
|---|---|---|
| `plugin 'office_hours': cannot start python3: No such file or directory (os error 2)` | The program is not on the `PATH` ariodb passes. | Use an absolute path in `command`. |
| `plugin 'office_hours' is restarting: plugin 'office_hours' exited with status 1` | The plugin crashed; it is restarted with backoff (1 s doubling to 30 s). | Read its `plugin office_hours:` log lines. |
| `ariodb: plugin 'office_hours' sent a line longer than 1048576 bytes; restarting it in 1 s` | A protocol violation; the plugin is restarted. | Fix the plugin's output. |
| `no answer from plugin 'office_hours' within 5000 ms` | The plugin is slow. | Make it faster, raise `timeout_ms` (facts) or the approver's `timeout_seconds` (approvals), or set `facts_cache_ms`. |
| `plugin 'office_hours' stopped before answering` | It exited mid-call. | As for a crash. |
| `plugin 'office_hours' did not declare the approver capability` | The approver or a rule uses a capability the plugin's `initialize` answer does not list. | Declare it, or point the approver or rule at another plugin. |
| `plugin 'office_hours' has not finished starting` | A statement arrived during the plugin's handshake (up to ten seconds). | Usually transient after a restart. |
| `plugin 'office_hours': secret 'pager-key' is not set` | A `secret_env` entry names a missing secret. | `ariodb secret set pager-key`, then restart `serve`. |
| `rule 'change-freeze' could not be evaluated: plugin 'office_hours': ...` | A rule reads facts from a failing plugin, so it counts as a deny. | Fix the plugin. |
| `rule 'change-freeze' could not be evaluated: facts from plugin 'office_hours' are not available here` | Seen in `ariodb explain` and `ariodb test`, which do not start plugins. | Expected; such rules count as a deny there. |

Plugin changes in the config take effect only after `serve` restarts.

## Dashboard login and access

| Message or symptom | Cause | Fix |
|---|---|---|
| The page does not load | The dashboard listens on `127.0.0.1:8080` by default, or `[dashboard] listen = ""`, or it failed to start (`ariodb: dashboard stopped: ...` in the log). | Reach it through an SSH forward or a reverse proxy on the same host, or change `listen` and restart. |
| `wrong user name or password` | As it says. The user created by first-run setup in the browser is `root`. | Reset it on the server: `ariodb dashboard-password` (or `--user <name>`). |
| `too many failed logins; wait 15 minutes and try again` | More than 5 failures from one address, or 20 for one user, in 15 minutes. The counts reset when `serve` restarts. | Wait, or reset the password and restart `serve`. |
| `set the first password from the server itself, or run ariodb dashboard-password` | The first password can only be set from loopback. | Run `ariodb dashboard-password` on the server. |
| `a password is already set` | The first-run page was used after a password exists. | Log in, or reset with `ariodb dashboard-password`. |
| Logged out at once, or `log in first` after logging in | With `public_url` starting `https://`, the session cookie is marked `Secure`, and browsers may not keep it on a plain `http://` address. Sessions also end after 12 hours, and when that user's password changes. | Use the dashboard at its `https://` address, or match `public_url` to the address you use. |
| `cross-site request refused` | The browser's `Origin` does not match the `Host` header ariodb sees, usually because a reverse proxy rewrites `Host`. | Pass the original host through (`proxy_set_header Host $host;` in nginx). |
| `missing or wrong CSRF token` | The page is older than the session (for example after a restart or a new login elsewhere). | Reload the page. |
| `the dashboard may not change the config (dashboard.config_writes = false); copy the text into your config repository instead` | Saving the config from the dashboard is off. | Copy the edit into your config repository, or set `config_writes = true`. |

<!-- TODO: document OIDC single sign-on and dashboard role troubleshooting once merged. -->

## ClickHouse errors

Messages with `ariodb:` and `(ARIODB)` come from ariodb; anything else was
passed through from ClickHouse.

| Message | Cause | Fix |
|---|---|---|
| `Code: 497. DB::Exception: ariodb: send one statement per request. (ARIODB)` | Several statements in one request. | Send them one at a time. |
| `Code: 497. DB::Exception: ariodb: destructive statements are never allowed for agents: the 'url' table function reaches outside the server. (ARIODB)` | `url`, `s3`, `file`, `remote` and similar are refused. | Not available to agents. |
| `Code: 497. DB::Exception: ariodb: ariodb cannot check this statement: the 'merge' table function can read tables the allow-list does not see. (ARIODB)` | `merge`, `dictionary` and other table functions that read tables named in strings are refused; so are `dictGet` and `joinGet` (`... reads a dictionary or Join table, which the allow-list does not cover`). | Query the tables directly. |
| `Code: 497. DB::Exception: ariodb: ariodb cannot check this statement: queries may not change readonly or allow_ddl. (ARIODB)` | A `SETTINGS` clause tried to lift ariodb's limits. | Remove it. |
| `Code: 497. DB::Exception: ariodb: schema changes are not allowed for agents; make them on a branch and review. (ARIODB)` | DDL and `SYSTEM`, `GRANT`, `KILL` and similar statements. | Not available to agents. |
| `Code: 497. ... agent 'analytics-agent' may not use table 'secrets' ...` | Not in `[agents.clickhouse] tables`. Unqualified names mean the request's database (`default` unless set). | Add the table, as `database.table` outside `default`. |
| `Code: 62. DB::Exception: ariodb: no query. (ARIODB)` | A `GET` without a `query` parameter. | Send the query in `query` or as a `POST` body. |
| `Code: 210. DB::Exception: ariodb: cannot reach ClickHouse: ... (ARIODB)` | ariodb cannot reach `http_url`. | Check the address, TLS (`accept_invalid_certificate` for a private CA), and any tunnel. |
| `Code: 1000. DB::Exception: ariodb: ARIODB_CLICKHOUSE_PASSWORD is not set. (ARIODB)` | The password variable is missing where `serve` runs. Also `secret '...' is not set`. | Set it, or use `password_secret`. |
| `Code: 1000. ... bad clickhouse.http_url: ...` | The URL does not parse. | Fix `http_url`. |
| `external tables are not supported through ariodb` | `clickhouse-client --external` and similar. | Not supported. |
| `client protocol too old: settings must be sent as strings` / `ariodb speaks the not-chunked protocol only` | An old or unusual native client. | Use a current `clickhouse-client`, or the HTTP interface. |
| `cannot reach ClickHouse at 127.0.0.1:9000: Connection refused (os error 111)` in the log | `native_addr` is wrong or ClickHouse is down. | Check `native_addr`; ariodb connects to it without TLS. |
| Clients hang or fail with TLS errors after setting `tls_cert` | Both listeners now accept TLS only. | Use `https://` and `clickhouse-client --secure`. |

## Config changes that do not take effect

| Symptom | Cause | Fix |
|---|---|---|
| `ariodb: kept the previous config: <error>` | The edited file does not load; the old config is still in force. | Fix the error (`ariodb check`). |
| A key seems to be ignored | Unknown keys are ignored silently, so a typo leaves the default in place. | Compare with [configuration](configuration.md); `ariodb check` prints what it read. |
| A new listen address, certificate, tunnel or plugin is not used | These need a restart. | Restart `serve`. See [what reloads](configuration.md#what-reloads-while-ariodb-runs). |
| A changed environment variable is not used | ariodb reads its environment at start. | Restart, or use the secret store, which is read at each use. |

## Next

- [Configuration reference](configuration.md): every key, and the validation errors
- [CLI reference](cli.md): `check`, `doctor`, `explain` and the rest
- [Operations](operations.md): logs, the state directory and the startup summary
- [Compatibility](compatibility.md): what each database supports
- [Approvals](approvals.md) and [plugins](plugins.md): how those paths work
