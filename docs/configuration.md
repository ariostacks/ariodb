# Configuration reference

This page describes every section and key of `ariodb.toml`, the environment
variables ariodb reads, the encrypted secret store, what reloads while
ariodb runs and what needs a restart, and the validation errors you may see
when a config does not load. It is for engineers writing or reviewing the
config for a real deployment. The reference is taken from the code
([`src/config.rs`](../src/config.rs) and the modules it pulls in), so where
this page and an older example disagree, this page is right.

## How the file is read

ariodb reads one TOML file: `ariodb.toml` in the current directory, or the
path given with `-c` / `--config` (see [the CLI reference](cli.md)).

- **Only `[database]` is required.** Every other section has defaults, and
  the lists (`[[agents]]`, `[[rules]]` and the rest) default to empty. An
  empty agent list is legal but refuses every agent.
- **Unknown keys are ignored, not rejected.** A misspelt key such as
  `lisen = "0.0.0.0:6543"` under `[proxy]` loads without complaint and
  leaves the default in place. Run `ariodb check` after every edit and read
  what it prints back. The exception is
  [`[dashboard.oidc]`](#dashboardoidc), which refuses unknown keys.
- **Top-level keys come first.** `on_failure` is the only top-level key; in
  TOML it must appear before the first `[section]` header, or it belongs to
  that section instead.
- **Values ending in `_env` name an environment variable**, never the value
  itself. Values named `secret` or ending in `_secret` name an entry in the
  [secret store](#the-secret-store). Keep real credentials in one of those,
  not in the file: the config is often kept in Git.
- **Relative paths** (`[journal] dir`, `tls_cert`, `ca_file`, plugin
  commands) are relative to ariodb's working directory, not to the config
  file. Use absolute paths in production.

`ariodb check` loads the file, runs every validation described below, and
prints a summary:

```text
$ ariodb check
database      postgres://ariodb_gw:***@localhost:5432/app
row limit     500 rows per write
timeout       5000 ms
proxy         127.0.0.1:6543
journal       .ariodb
if checks fail, refuse the statement (fail closed)

agent coding-agent     read and write  token set  orders, customers
agent support-bot      read only       no token   orders
```

`no token` means the agent's environment variable or secret is empty in the
shell where you ran `check`. That agent cannot log in until it is set where
`ariodb serve` runs.

## A complete example

A production-shaped config for one Postgres database, two agents, a rule
that holds large writes for a person, and TLS on both sides. Every
credential lives in the environment or the secret store.

```toml
[database]
url = "postgres://ariodb_gw@db.internal.example:5432/app"   # password comes from ARIODB_DATABASE_URL or the secret
secret = "database-url"
tls = "verify"

[limits]
max_rows_per_write = 200
statement_timeout_ms = 10000

[proxy]
listen = "0.0.0.0:6543"
tls_cert = "/etc/ariodb/proxy.crt"
tls_key = "/etc/ariodb/proxy.key"
require_tls = true

[journal]
dir = "/var/lib/ariodb"

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders", "order_items"]
token_secret = "coding-agent-token"

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["orders", "customers"]
token_secret = "support-bot-token"
credential = "reporting"

[[credentials]]
name = "reporting"
secret = "reporting-url"

[[rules]]
name = "big-writes-need-a-person"
stage = "after"
condition = "effects.rows > 50"
verdict = "approve"
approve = ["ops"]
reason = "writes over 50 rows need a person to agree"

[[approvers]]
name = "ops"
type = "dashboard"

[approvals]
timeout_seconds = 120

[dashboard]
listen = "127.0.0.1:8080"
public_url = "https://ariodb.internal.example"

[audit]
retention_days = 90
redact_literals = true
```

Store the secrets it names before starting ariodb:

```bash
printf '%s\n' 'postgres://ariodb_gw:not-a-real-password@db.internal.example:5432/app' | ariodb secret set database-url
printf '%s\n' 'postgres://ariodb_ro:not-a-real-password@db.internal.example:5432/app'  | ariodb secret set reporting-url
openssl rand -hex 32 | ariodb secret set coding-agent-token
openssl rand -hex 32 | ariodb secret set support-bot-token
ariodb check
```

## Top level

| Key | Type | Default | What it does |
|---|---|---|---|
| `on_failure` | string | `"closed"` | What to do when ariodb's own checks cannot run. Only `"closed"` (refuse the statement) is accepted. `"open"` is refused when the config loads, because letting statements through unchecked would defeat ariodb. The key exists so a config can say so explicitly. |

```toml
on_failure = "closed"   # must come before the first [section]

[database]
url = "postgres://ariodb_gw@localhost:5432/app"
```

## `[database]`

The Postgres database agents work on, and the login their queries run as
by default (the "gateway" role). The same settings, including the tunnel,
are used by `setup`, `doctor`, the journal and undo, with the login
replaced by `ARIODB_JOURNAL_URL` or `ARIODB_ADMIN_URL` when those are set.

| Key | Type | Default | What it does |
|---|---|---|---|
| `url` | string | required | The gateway login as a `postgres://` URL. It must start with `postgres://` or `postgresql://` even when the real URL comes from `ARIODB_DATABASE_URL` or `secret`. Must include a user; the database defaults to the user name. |
| `secret` | string | none | Name of a secret holding the URL, used instead of `url`. `ARIODB_DATABASE_URL`, if set, still wins. |
| `tls` | string | see below | TLS to the database: `disable`, `require` (encrypt, accept any certificate) or `verify` (encrypt and check the certificate and host name). |
| `ca_file` | string | none | An extra trusted CA certificate (PEM) for `verify`, on top of the built-in public roots. See the limitation below. |
| `tunnel` | string | none | Name of a [`[[tunnels]]`](#tunnels) entry. ariodb dials the tunnel's `listen` address instead of the URL's host and port; user, password, database and TLS name still come from the URL. |
| `write_check` | string | `"measured"` | How a write is judged before commit. `measured` asks Postgres which tables the transaction changed and by how many rows (`pg_stat_xact_user_tables`), so triggers, cascades and functions count. `reported` trusts the row counts the database reports per statement, for Postgres-compatible databases that cannot measure (YugabyteDB, CockroachDB). See [compatibility](compatibility.md). |

**The `tls` default** depends on the host in the effective URL: `disable`
for `localhost`, any `127.x.x.x` address and `::1`; `verify` for everything
else, including container names such as `db`. A `sslmode` parameter in the
URL is ignored; only `tls` decides.

**Trusted roots.** `verify` checks against a built-in bundle of public CA
roots (the Mozilla set), not the operating system's trust store, plus
`ca_file` if given.

**Limitation: `ca_file` and admin connections.** In the current code,
`ca_file` is honoured on agents' connections but not on ariodb's own admin
connections (`ariodb setup`, `ariodb doctor`, the journal and `ariodb
undo`), which verify against the public roots only. With a private CA and
`tls = "verify"`, agents connect but those fail with `cannot connect: error
performing TLS handshake`. Until that is fixed, use a certificate from a
public CA, or `tls = "require"` (encrypted but unverified), or reach the
database through a [tunnel](#tunnels) that handles TLS itself.

```toml
[database]
url = "postgres://ariodb_gw@db.internal.example:5432/app"
secret = "database-url"
tls = "verify"
ca_file = "/etc/ariodb/db-ca.pem"
# tunnel = "cloudsql"
# write_check = "reported"   # only for databases that cannot measure writes
```

## `[limits]`

| Key | Type | Default | What it does |
|---|---|---|---|
| `max_rows_per_write` | integer | `500` | A write that changes more rows than this, counted across every table it touched (including through triggers and cascades), is rolled back. A ClickHouse insert over the native protocol that sends more rows inserts nothing. Must be at least 1. Agents can override it. |
| `statement_timeout_ms` | integer | `5000` | Set as `SET LOCAL statement_timeout` at the start of every transaction ariodb runs for an agent. On ClickHouse it becomes `max_execution_time`, rounded up to whole seconds (at least 1). On Postgres, `0` means no timeout. |
| `max_connections` | integer | `256` | The most connections each listener holds at once, logged in or not: the Postgres and MySQL listeners, the ClickHouse HTTP and native listeners, and the dashboard each have their own count. Must be at least 1. |
| `max_connections_per_agent` | integer | `32` | The most connections one agent holds at once on each listener, counted once it has logged in. Over HTTP (ClickHouse), it counts the agent's requests in flight. Must be at least 1. |
| `handshake_timeout_ms` | integer | `10000` | How long a new connection has to become a logged-in agent: the TLS handshake, the protocol's startup and the token. A connection still short of that is closed. On the HTTP listeners it is the time each request's headers have to arrive, and how long an idle kept-alive connection stays open; a request's body must arrive at 64 KiB per timeout at least, and a client that reads nothing of its answer for this long is closed. Must be at least 1. |

The timeout covers the statement running in the database, not time spent
waiting for an approval. On Postgres it is a default, not a ceiling: an
agent may send its own `SET statement_timeout` in the same query string
and lift it for that transaction. See
[statement timeouts](postgres.md#statement-timeouts) for a rule that
stops this.

A client over `max_connections` or `max_connections_per_agent` is told so
in its own protocol rather than cut off without a word:

| Listener | Over `max_connections` | Over `max_connections_per_agent` |
|---|---|---|
| Postgres | `FATAL 53300 sorry, too many clients already`, once its startup message arrives (cancel requests are still served) | `FATAL 53300 too many connections for agent "<name>"` |
| MySQL | Error 1040 (`08004`) in place of the handshake | Error 1203 (`42000`) after the login |
| ClickHouse native | Exception code 202, in answer to the client's Hello | Exception code 202 |
| ClickHouse HTTP | `503` with a ClickHouse-style exception (code 202) | `503`, code 202 |
| Dashboard | `503` with `Retry-After: 5` | Does not apply |

ariodb logs the first refusal of a burst, such as `ariodb: Postgres proxy:
refusing new connections: 256 are open, the limit ([limits]
max_connections)`, and no more until 10 seconds pass without one; the next
burst's line says how many more the previous one refused. At most 64 clients
over the limit are answered at once; beyond that, new connections are
closed at once. The three connection keys take effect for the next
connection after a reload; connections already open keep their places.
Size `max_connections` below the database's own connection limit, less
what other clients need: each logged-in agent connection holds one
database connection.

```toml
[limits]
max_rows_per_write = 500
statement_timeout_ms = 5000
max_connections = 256
max_connections_per_agent = 32
handshake_timeout_ms = 10000
```

## `[proxy]`

The Postgres wire-protocol listener agents connect to.

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen` | string | `"127.0.0.1:6543"` | Address and port to listen on. `""` switches the Postgres proxy off (for a ClickHouse-only setup). |
| `tls_cert` | string | none | Certificate chain (PEM) for TLS between agents and ariodb. Set with `tls_key`. |
| `tls_key` | string | none | Private key (PEM) for `tls_cert`. |
| `require_tls` | boolean | `false` | Refuse agents that do not use TLS. Agents send their token as a cleartext password inside the protocol, so turn this on whenever agents connect over a network. Needs `tls_cert` and `tls_key`. |

```toml
[proxy]
listen = "0.0.0.0:6543"
tls_cert = "/etc/ariodb/proxy.crt"
tls_key = "/etc/ariodb/proxy.key"
require_tls = true
```

Agents then connect with `sslmode=require` (or `verify-full` with your CA):

```bash
psql "postgres://coding-agent@ariodb.internal.example:6543/app?sslmode=verify-full&sslrootcert=/etc/ssl/ariodb-ca.pem"
```

## `[journal]`

The change journal that undo reads, and the location of ariodb's state
directory. See [operations](operations.md#the-state-directory) for what
lives there.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | boolean | `true` | Record every row agents change, for undo. When on, every agent write is tagged with its session (`pg_logical_emit_message`) and `ariodb serve` reads the logical replication slot. Turn it off on databases without logical replication (Postgres 13, YugabyteDB, CockroachDB); reads and checked writes still work, undo does not. |
| `dir` | string | `".ariodb"` | The state directory: `journal.jsonl`, `ariodb.db` (decisions log, approvals, dashboard users and sessions), `secrets.json` and `master.key`. Used even when the journal is off. Created with mode `0700`. |
| `slot` | string | `"ariodb"` | The logical replication slot `ariodb setup` creates and the journal reads. Exactly one running `ariodb serve` may use a slot; see [high availability](operations.md#high-availability). |
| `publication` | string | `"ariodb"` | The publication listing the protected tables (every table some `read_write` agent may change). `ariodb setup` replaces its table list, so give each ariodb instance on the same database its own. |

```toml
[journal]
enabled = true
dir = "/var/lib/ariodb"
slot = "ariodb"
publication = "ariodb"
```

## `[[agents]]`

One entry per agent. An agent logs in with its `name` as the user name and
its token as the password. The token is never the database password.

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | The user name the agent logs in with. Must be unique. |
| `access` | string | required | `read_only` or `read_write`. |
| `tables` | list of strings | required | Tables this agent may touch; at least one. Names ignore case and a `public.` prefix; other schemas are written `schema.table`. `["*"]` means every table. Agents may always read the Postgres catalogue (`pg_catalog`, `information_schema`). |
| `token_env` | string | none | Environment variable holding the token. |
| `token_secret` | string | none | Secret holding the token. Exactly one of `token_env` and `token_secret` is required. |
| `max_rows_per_write` | integer | `[limits]` value | Overrides the row limit for this agent. |
| `credential` | string | `[database]` | Name of a [`[[credentials]]`](#credentials) entry to run this agent's Postgres queries as. |

The tables that `read_write` agents list are the *protected tables*:
`ariodb setup` gives them full before-images and adds them to the
publication. If any `read_write` agent lists `"*"`, every user table is
protected.

Generate tokens as long random values; they are compared in constant time
but guesses are not rate limited:

```bash
openssl rand -hex 32 | ariodb secret set coding-agent-token
```

```toml
[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders", "sales.invoices"]
token_secret = "coding-agent-token"
max_rows_per_write = 100

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["orders"]
token_env = "ARIODB_TOKEN_SUPPORT_BOT"
credential = "reporting"
```

Rules can test which login an agent uses with `agent.credential`: the
`credential` name, or `""` for an agent that runs as `[database]`. For
example, a rule with `condition = "agent.credential == 'reporting' &&
sql.kind == 'write'"` refuses writes from every agent on the reporting
login, whatever their access level. See [rules](rules.md#agent-agent).

### `[agents.clickhouse]`

ClickHouse access, separate from Postgres access. In TOML,
`[agents.clickhouse]` attaches to the `[[agents]]` entry written just above
it. Without this block the agent cannot use the ClickHouse listeners.

| Key | Type | Default | What it does |
|---|---|---|---|
| `access` | string | required | `read_only` or `read_write`. |
| `tables` | list of strings | required | ClickHouse tables. Unqualified names mean the `default` database; name others as `database.table`. |

```toml
[[agents]]
name = "analytics-agent"
access = "read_only"
tables = ["orders"]
token_secret = "analytics-agent-token"

[agents.clickhouse]
access = "read_only"
tables = ["events", "analytics.page_views"]
```

### `[agents.mysql]`

MySQL and MariaDB access, separate from Postgres access. Like
`[agents.clickhouse]`, it attaches to the `[[agents]]` entry written just
above it. Without this block the agent cannot log in to the
[`[mysql]`](#mysql) listener (`this agent has no MySQL access`).

| Key | Type | Default | What it does |
|---|---|---|---|
| `access` | string | required | `read_only` or `read_write`. Writes are counted before commit and can be undone; see [MySQL and MariaDB](mysql.md#how-writes-are-checked-before-commit). |
| `tables` | list of strings | required | MySQL tables. Unqualified names mean `[mysql] database`; name tables in other databases as `database.table`. Names ignore case. `["*"]` means every table, except the ones ariodb [reserves](mysql.md#reserved-tables) (its tag table, `mysql`, `sys`, `performance_schema`, the process list and InnoDB's views). Agents may always read the `information_schema` views that describe structure. |

The agent logs in with the same `name` and token as for Postgres. Its
`max_rows_per_write` applies to MySQL writes too. The tables that
`read_write` agents list here are the MySQL protected tables: the journal
records everyone's changes to them, and undo needs write access to them.
An agent's MySQL access is read when it connects, so a change applies from
its next connection.

```toml
[[agents]]
name = "coding-agent"
access = "read_only"
tables = ["orders"]
token_secret = "coding-agent-token"

[agents.mysql]
access = "read_write"
tables = ["orders", "customers", "reporting.daily"]
```

## `[[credentials]]`

Extra database logins, so different agents can run as different Postgres
roles. Grant each role only what its agents need: the role's privileges are
the real boundary (see [the security model](security-model.md)).

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | What agents refer to with `credential = "<name>"`. |
| `url_env` | string | none | Environment variable holding the `postgres://` URL. |
| `secret` | string | none | Secret holding the URL. One of `url_env` and `secret` is needed; if both are set, `url_env` wins. |
| `tls` | string | `[database] tls` | As for `[database]`. When neither is set, the default follows the URL's host. |
| `ca_file` | string | none | As for `[database]`. |
| `tunnel` | string | none | A `[[tunnels]]` entry to dial instead of the URL's host and port. |

A missing `url_env` or `secret` is only noticed when an agent that uses the
credential connects (and by `ariodb doctor`), not when the config loads.

```toml
[[credentials]]
name = "reporting"
url_env = "ARIODB_REPORTING_URL"
tls = "verify"
```

## `[[rules]]`

CEL rules on top of each agent's built-in policy. They can refuse a
statement or hold it for approval; they cannot allow what the built-in
policy refuses. The rule language, the variables a condition can read and
how rules combine are in [rules](rules.md); this is the key reference.

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | Unique name, shown in refusals, the decisions log and the dashboard. |
| `condition` | string | none | A CEL expression. Omitted, the rule matches every statement. A condition that cannot be evaluated counts as a deny. |
| `verdict` | string | required | `allow`, `deny` or `approve`. |
| `approve` | list of strings | `[]` | Approvers for `verdict = "approve"`, all of which must allow. Required (non-empty) for `approve`. |
| `reason` | string | `rule '<name>'` | Text shown to the agent and recorded. |
| `agents` | list of strings | `[]` (every agent) | Limit the rule to these agents. |
| `priority` | integer | `0` | Among matching rules, the highest priority decides between `allow` and `approve`; ties keep file order. Any matching `deny` wins regardless. |
| `stage` | string | `"before"` | `before`: judged on the SQL before it runs. `after`: judged on what a write actually changed, before commit. Rules that read plugin facts must be `before`. |

```toml
[[rules]]
name = "no-file-functions"
# Matches pg_read_file and pg_catalog.pg_read_file alike; see rules.md.
condition = "sql.functions.exists(f, f.matches('(^|[.])pg_(read_file|read_binary_file|ls_dir|stat_file)$'))"
verdict = "deny"
reason = "functions that read server files are off-limits"

[[rules]]
name = "big-writes-need-a-person"
stage = "after"
condition = "effects.rows > 50"
verdict = "approve"
approve = ["ops"]
agents = ["coding-agent"]
priority = 10
```

## `[[approvers]]`

Who decides when a rule's verdict is `approve`. How each type behaves, and
how to set up Slack and webhooks, is in [approvals](approvals.md).

### Keys every approver takes

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | Unique; rules list it in `approve`. |
| `type` | string | required | `dashboard`, `slack`, `webhook`, `discord`, `telegram`, `teams`, `google_chat`, `mattermost`, `pagerduty`, `opsgenie`, `email`, `llm` or `plugin`. |
| `timeout_seconds` | integer | `[approvals] timeout_seconds` | How long to wait for this approver. Applies to every type except `llm`: a model approver is not bounded by it; see [model approvers](#llm-a-model). |
| `groups` | list of strings | `[]` | With [single sign-on](#dashboardoidc), the groups whose members may decide this approver's requests in the dashboard and through its links; empty means anyone with the approver role. Not allowed on `slack`, `llm` and `plugin`. On `webhook` and the channel types it needs `[dashboard] approval_links = "sign_in"`. See [approvals](approvals.md#approver-groups). |

### `dashboard`

A person decides in the dashboard, or with `ariodb approve` / `ariodb deny`.
No other keys.

```toml
[[approvers]]
name = "ops"
type = "dashboard"
timeout_seconds = 300
```

### `slack`

| Key | Type | Default | What it does |
|---|---|---|---|
| `channel` | string | required | Slack channel ID to post to. |
| `bot_token_env` / `bot_token_secret` | string | one required | The bot token (`xoxb-...`). |
| `interactive` | boolean | `false` | Add Approve and Deny buttons. Needs the signing secret, and Slack's interactivity request URL set to `<public_url>/slack/actions`. Without buttons, people decide in the dashboard from the link in the message. |
| `signing_secret_env` / `signing_secret_secret` | string | required when `interactive` | The Slack app's signing secret, used to check button callbacks. |

```toml
[[approvers]]
name = "ops-slack"
type = "slack"
channel = "C0123456789"
bot_token_secret = "slack-bot-token"
interactive = true
signing_secret_secret = "slack-signing-secret"
```

### `webhook`

| Key | Type | Default | What it does |
|---|---|---|---|
| `url` | string | required | Where ariodb POSTs the signed JSON request. |
| `hmac_secret_env` / `hmac_secret_secret` | string | one required | Key for the `x-ariodb-signature` header and the signed approve and deny links. |

```toml
[[approvers]]
name = "pager"
type = "webhook"
url = "https://hooks.internal.example/ariodb"
hmac_secret_secret = "webhook-hmac"
```

### Chat, paging and email approvers

`discord`, `telegram`, `teams`, `google_chat`, `mattermost`, `pagerduty`,
`opsgenie` and `email` post the request with signed Approve and Deny links
to the dashboard's confirmation page. How each one posts, what it shows and
how its links are signed and revoked is in
[approvals](approvals.md#chat-paging-and-email-channels).

| Key | Types | Type | Default | What it does |
|---|---|---|---|---|
| `url_env` / `url_secret` | `discord`, `teams`, `google_chat`, `mattermost` | string | one required | The incoming webhook's URL. It holds the webhook's token, so `url` is refused for these types. Must be `https`, except for this machine. |
| `channel` | `mattermost` | string | the webhook's own | Post to this channel instead. |
| `bot_token_env` / `bot_token_secret` | `telegram` | string | one required | The bot's token, from BotFather. |
| `chat_id` | `telegram` | integer or string | required | The chat to post to: a number such as `-1001234567890`, or `"@channelusername"` for a public channel. |
| `routing_key_env` / `routing_key_secret` | `pagerduty` | string | one required | An Events API v2 integration (routing) key. |
| `api_key_env` / `api_key_secret` | `opsgenie` | string | one required | An API integration key. |
| `region` | `pagerduty`, `opsgenie` | string | `"us"` | `us` or `eu`, for accounts in the EU service region. |
| `smtp_host` | `email` | string | required | The mail server. |
| `smtp_tls` | `email` | string | `"starttls"` | `starttls`, `tls` (implicit TLS) or `none`. `none` is allowed only when `smtp_host` is this machine (`localhost`, a `.localhost` name or a loopback address). |
| `smtp_port` | `email` | integer | `587`, `465` or `25` | Defaults to 587 for `starttls`, 465 for `tls` and 25 for `none`. |
| `smtp_user` | `email` | string | none | The SMTP login. Set it together with a password, or neither. |
| `smtp_password_env` / `smtp_password_secret` | `email` | string | none | The SMTP password. |
| `from` | `email` | string | required | The sender, such as `"ariodb <ariodb@example.com>"`. |
| `to` | `email` | list of strings | required | At least one recipient; each gets the same message. |

```toml
[[approvers]]
name = "ops-teams"
type = "teams"
url_secret = "teams-webhook-url"

[[approvers]]
name = "on-call"
type = "pagerduty"
routing_key_secret = "pagerduty-routing-key"
region = "eu"
timeout_seconds = 600

[[approvers]]
name = "ops-email"
type = "email"
smtp_host = "smtp.example.com"
smtp_user = "ariodb@example.com"
smtp_password_secret = "smtp-password"
from = "ariodb <ariodb@example.com>"
to = ["dba-oncall@example.com"]
```

The links are signed with a key ariodb keeps in the secret store as
`ariodb.approval-link-key`, made on first use. Deleting it
(`ariodb secret delete ariodb.approval-link-key`) invalidates every link
already sent.

### `llm` (a model)

A model judges the statement against a written policy. The statements, the
policy, the agent's name, the database and the rule are sent to the
provider with literal values intact.

| Key | Type | Default | What it does |
|---|---|---|---|
| `policy` | string | required | The written policy the model applies. |
| `provider` | string | `"anthropic"` | `anthropic`, `openai`, `gemini`, `azure_openai` or `openai_compatible`. |
| `model` | string | provider default | `claude-opus-5-5` (anthropic), `gpt-6-astra` (openai), `gemini-3.8-flash` (gemini). Required for `azure_openai` (the deployment name) and `openai_compatible`. |
| `base_url` | string | provider's public API | Required for `azure_openai` (the resource endpoint) and `openai_compatible` (up to and including `/v1`). Must be `https`, except for `localhost`, `*.localhost` and loopback addresses. |
| `api_key_env` / `api_key_secret` | string | provider variable | Where the API key comes from. Without either, ariodb reads `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` or `AZURE_OPENAI_API_KEY`; `openai_compatible` then sends no key. |
| `effort` | string | `low` on default models | The provider's reasoning control. anthropic: `low`, `medium`, `high`, `xhigh`, `max`. openai and azure_openai: `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`. gemini: `minimal`, `low`, `medium`, `high`. Ignored, with a warning, for `openai_compatible`. Sent by default only on each provider's default model and on every Anthropic model. |
| `api_version` | string | `"v1"` | `azure_openai` only: `v1` or `preview`. |

Each question is tried up to three times on network errors, 408, 429 and
5xx, with backoff that honours `Retry-After` (a request to wait more than 30
seconds counts as down). Each attempt may take up to 60 seconds, so a slow
provider can hold a statement for up to about four minutes before
`llm_fail_mode` decides. Any other HTTP status, or a redirect, is a
configuration error and always refuses.

```toml
[[approvers]]
name = "model"
type = "llm"
policy = "Allow reads of order data. Deny anything that exports personal data in bulk."
provider = "anthropic"
api_key_secret = "anthropic-key"

[[approvers]]
name = "local-model"
type = "llm"
provider = "openai_compatible"
policy = "Allow reads of order data. Deny anything that exports personal data in bulk."
base_url = "http://127.0.0.1:11434/v1"
model = "llama3.3"
```

### `plugin`

| Key | Type | Default | What it does |
|---|---|---|---|
| `plugin` | string | required | A [`[[plugins]]`](#plugins) entry that declares the `approver` capability. |

```toml
[[approvers]]
name = "office-hours"
type = "plugin"
plugin = "office_hours"
timeout_seconds = 10
```

## `[approvals]`

Settings shared by all approvers.

| Key | Type | Default | What it does |
|---|---|---|---|
| `timeout_seconds` | integer | `90` | How long a person or plugin has to decide. No decision in time means the statement is refused. Agents' own client timeouts should be longer than this. |
| `llm_fail_mode` | string | `"closed"` | When a model cannot be reached (network error, 408, 429, 5xx, or a reply that is not JSON): `closed` refuses, `open` allows and records that the model never answered. Configuration errors always refuse. |
| `llm_cache_seconds` | integer | `300` | Reuse a model's answer to the same question (same approver, model, address, policy, agent, database, rule and SQL) for this long. Only real answers are cached, never an outage. `0` asks every time. The cache is in memory and per process. |

```toml
[approvals]
timeout_seconds = 90
llm_fail_mode = "closed"
llm_cache_seconds = 300
```

An after-stage approval keeps the write's transaction open, and its row
locks held, while it waits.

## `[dashboard]`

The built-in dashboard, and the endpoints Slack and webhooks call back to.
See [the dashboard](dashboard.md).

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen` | string | `"127.0.0.1:8080"` | Where the dashboard listens. `""` switches it off, along with the Slack and webhook callbacks. It speaks plain HTTP; put TLS in front of it with a reverse proxy. |
| `public_url` | string | `"http://127.0.0.1:8080"` | The address people, Slack and webhook receivers use to reach the dashboard. Used for links in Slack messages, webhook payloads and channel messages, and for the single sign-on redirect address. When it starts with `https://`, session cookies are marked `Secure`. |
| `config_writes` | boolean | `false` | Let the dashboard save edits to the config file. Leave it off when the config is managed in Git; the config page then shows the edit to copy. When on, ariodb needs write access to the config file's directory (it writes `<file>.tmp` and keeps `<file>.bak`). |
| `approval_links` | string | `"sign_in"` with `[dashboard.oidc]`, otherwise `"signed"` | What a signed approval link (webhook and channel approvers) needs before it decides: `signed`, the link alone, recorded as `webhook`; or `sign_in`, also a signed-in dashboard user who may decide the request, recorded by name. See [approvals](approvals.md#links-that-need-sign-in). |

```toml
[dashboard]
listen = "127.0.0.1:8080"
public_url = "https://ariodb.internal.example"
config_writes = false
approval_links = "sign_in"
```

### `[dashboard.oidc]`

Single sign-on with any OpenID Connect provider. People sign in with the
provider and get a [role](dashboard.md#roles) from their groups. Provider
set-up, with worked examples for Okta, Microsoft Entra ID, Google
Workspace, Auth0 and Keycloak, is in
[the dashboard](dashboard.md#single-sign-on).

Unlike the rest of the file, **unknown keys in `[dashboard.oidc]` are
refused**, so a misspelt `password_login` cannot leave passwords on
unnoticed.

| Key | Type | Default | What it does |
|---|---|---|---|
| `issuer` | string | required | The provider's issuer URL. ariodb reads `<issuer>/.well-known/openid-configuration`, and the document's `issuer` must match it (a trailing `/` aside). Must be `https://`; `http://` only for `localhost`, a `127.` address or `[::1]`. |
| `provider_name` | string | `"single sign-on"` | Shown on the button: "Sign in with <provider_name>". |
| `client_id` | string | required | The client (application) ID registered with the provider. |
| `client_secret_env` / `client_secret_secret` | string | none | The client secret, for a confidential client. Set at most one. Leave both out for a public client, which relies on PKCE alone. |
| `redirect_path` | string | `"/auth/callback"` | Where the provider sends people back, under `public_url`. Register `<public_url><redirect_path>` with the provider. It must be a path of its own: not `/`, nothing under `/api/`, `/hooks/`, `/slack/` or `/assets/`, not `/auth/login` or one of the dashboard's pages, and no `?` or `#`. |
| `scopes` | list of strings | `["openid", "profile", "email"]`, plus `"groups"` when any role groups are set | The scopes asked for. Must include `openid`. Set it without `groups` for a provider that has no `groups` scope. |
| `groups_claim` | string | `"groups"` | The ID token claim that lists a person's groups: a list of strings, or one string. A dotted name reaches into objects, such as `realm_access.roles`, so the claim's own name cannot contain a dot. |
| `admin_groups` | list of strings | `[]` | Groups whose members are admins. |
| `approver_groups` | list of strings | `[]` | Groups whose members are approvers. |
| `viewer_groups` | list of strings | `[]` | Groups whose members are viewers. At least one of the three lists must name a group. |
| `allowed_email_domains` | list of strings | `[]` (any) | Only people whose **verified** email (`email_verified` true in the ID token) is in one of these domains, compared without regard to case. A provider that does not send `email_verified` cannot be limited this way. |
| `password_login` | string | `"break_glass"` | Local passwords: `break_glass` keeps them working, offered below the sign-in button; `off` refuses them and ends existing password sessions. |
| `logout_at_provider` | boolean | `false` | Signing out also sends the browser to the provider's `end_session_endpoint`, with `post_logout_redirect_uri` set to `<public_url>/`. |

```toml
[dashboard]
listen = "127.0.0.1:8080"
public_url = "https://ariodb.example.com"

[dashboard.oidc]
issuer = "https://login.example.com/realms/ops"
provider_name = "Keycloak"
client_id = "ariodb"
client_secret_secret = "oidc-client-secret"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers", "dba"]
viewer_groups = ["engineering"]
allowed_email_domains = ["example.com"]
```

Each person gets the highest role any of their groups maps to; someone in
none of them is refused. The role is worked out again on every request from
the groups the provider sent at sign-in and the config in force, so a
change to the group lists, `allowed_email_domains` or `password_login`
applies to people already signed in. A change to someone's groups at the
provider applies when they next sign in.

With single sign-on configured, the dashboard's first-run password page is
switched off; set a break-glass password with `ariodb dashboard-password`.
A `public_url` that is not `https://` (or this machine) loads with a
warning, because session cookies would then be sent without `Secure`.


## `[audit]`

The decisions log in `<state dir>/ariodb.db`: every statement, verdict,
rule, row count and latency, hash-chained.

| Key | Type | Default | What it does |
|---|---|---|---|
| `retention_days` | integer | `30` | Delete entries older than this many days, checked hourly by `ariodb serve`. `0` keeps everything. |
| `redact_literals` | boolean | `false` | Store statements with literal values replaced by `$1`, `$2`, ..., so customer data in `WHERE` clauses or `VALUES` stays out of the decisions log, notifier plugins and audit-sink plugins. It does not affect approvals: the stored approval request, Slack messages, webhook payloads, and what model and plugin approvers and fact plugins are sent all carry the statement with its literals. See [the security model](security-model.md). |

```toml
[audit]
retention_days = 90
redact_literals = true
```

## `[clickhouse]`

ariodb in front of ClickHouse's HTTP interface and its native protocol. See
[ClickHouse](clickhouse.md) for behaviour and limits.

| Key | Type | Default | What it does |
|---|---|---|---|
| `http_listen` | string | `""` (off) | Where agents send ClickHouse HTTP requests. |
| `http_url` | string | `"http://127.0.0.1:8123"` | The real ClickHouse HTTP interface. `https://` is supported. |
| `native_listen` | string | `""` (off) | Where agents connect with the native protocol (`clickhouse-client`). Reads, and inserts whose rows ariodb counts before they reach ClickHouse. |
| `native_addr` | string | `"127.0.0.1:9000"` | The real native port, as `host:port`. ariodb connects to it without TLS. |
| `user` | string | `"default"` | The ClickHouse login ariodb uses for every agent. Agents never see it. |
| `password_env` / `password_secret` | string | none (empty password) | Its password. If both are set, the secret wins. |
| `accept_invalid_certificate` | boolean | `false` | Skip certificate checks for an `https://` `http_url`, for a private CA. There is no CA-file option. |
| `tls_cert` / `tls_key` | string | none | Certificate and key (PEM) for agents' connections. When set, both listeners accept TLS only: agents use `https://` and `clickhouse-client --secure`. Set both or neither. |
| `tunnel` | string | none | Reach ClickHouse (both interfaces) through this `[[tunnels]]` entry. The tunnel must forward to whichever port is used. Through a tunnel, TLS on `http_url` is still checked against the real host name. |

```toml
[clickhouse]
http_listen = "0.0.0.0:8124"
http_url = "https://ch.internal.example:8443"
native_listen = "0.0.0.0:9441"
native_addr = "ch.internal.example:9000"
user = "ariodb"
password_secret = "clickhouse-password"
tls_cert = "/etc/ariodb/ch.crt"
tls_key = "/etc/ariodb/ch.key"
```

Inserts need `access = "read_write"` in `[agents.clickhouse]` and the
table on its list. Over the native protocol, ariodb counts an insert's rows
against the agent's `max_rows_per_write` (or `[limits]
max_rows_per_write`) and holds them back until the last one has arrived, so
an insert over the limit inserts nothing. It holds at most 64 MiB of an
insert's data (256 MiB once decompressed); send larger loads in parts.
HTTP inserts are not counted. See
[ClickHouse inserts](clickhouse.md#inserts).

## `[mysql]`

ariodb in front of MySQL or MariaDB: agents connect with any MySQL client,
and ariodb relays their statements to the server as its own login. See
[MySQL and MariaDB](mysql.md) for behaviour, grants, server settings and
limits.

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen` | string | `""` (off) | Where agents connect, as `host:port`. While empty, the rest of `[mysql]` is unused and the MySQL journal does not run. |
| `addr` | string | `"127.0.0.1:3306"` | The real server, as `host:port`. |
| `database` | string | none | The database agents work in. Required when `listen` is set. Agents may log in to it or to no database, and unqualified table names (in statements and in `[agents.mysql] tables`) mean tables in it. |
| `user` | string | `"ariodb"` | The gateway login every agent's queries run as. Agents never see it. Needs the table grants agents need, `INSERT` on `tag_table`, and `PROCESS`. |
| `password_env` / `password_secret` | string | none (empty password) | The gateway's password. If both are set, the secret wins. |
| `tls` | string | `disable` for `localhost`, `127.*` and `[::1]`; `verify` otherwise | TLS to the server: `disable`, `require` (encrypted, certificate not checked) or `verify` (chain and host name checked). See [TLS](mysql.md#tls). |
| `ca_file` | string | none | An extra CA (PEM) trusted under `verify`. Used by the proxy, `setup`, `doctor`, the journal and `undo`. |
| `tls_cert` / `tls_key` | string | none | Certificate and key (PEM) for agents' connections. Set both or neither. |
| `require_tls` | boolean | `false` | Refuse agents that do not use TLS. Needs `tls_cert` and `tls_key`. |
| `tunnel` | string | none | Dial this `[[tunnels]]` entry instead of `addr`. TLS is still checked against `addr`'s host name. |
| `journal` | boolean | `true` | Tag every write with its session and read the binlog, for undo. Independent of `[journal] enabled`, which is Postgres's; the files go in `[journal] dir` either way. |
| `journal_user` | string | `user`, with its password | The login `ariodb setup`, the journal and `ariodb undo` use. Needs `REPLICATION SLAVE`, `REPLICATION CLIENT`, `SELECT, INSERT, DELETE` on `tag_table`, write access to the protected tables for undo, and `PROCESS`; for `setup`, `CREATE` on the tag table's database. |
| `journal_password_env` / `journal_password_secret` | string | none (empty password) | Its password, when `journal_user` is set. If both are set, the secret wins. |
| `server_id` | integer | `4242` | The server id the journal registers with to read the binlog. Must not be 0 while the journal is on, and must differ from the server's and every real replica's. Run one `ariodb serve` per id. |
| `tag_table` | string | `"ariodb.session_tags"` | The table each write transaction records its session in, as `database.table`; an unqualified name is in `database`. `ariodb setup` creates it. No agent may use it, whatever its `tables` say. |

```toml
[mysql]
listen = "0.0.0.0:3307"
addr = "mysql.internal.example:3306"
database = "app"
user = "ariodb_gw"
password_secret = "mysql-gateway-password"
tls = "verify"
ca_file = "/etc/ariodb/mysql-ca.pem"
tls_cert = "/etc/ariodb/mysql-proxy.crt"
tls_key = "/etc/ariodb/mysql-proxy.key"
require_tls = true
journal_user = "ariodb_journal"
journal_password_secret = "mysql-journal-password"
server_id = 4242
```

Unlike the other sections' tunnels, a `[mysql] tunnel` that names no
`[[tunnels]]` entry is not caught when the config loads: connections fail
with `tunnel '<name>' is not defined in [[tunnels]]`. Check the name with
`ariodb check`, which prints `(through tunnel '<name>')` on the `mysql`
line.

## `[[tunnels]]`

Side processes that carry ariodb's connections to a database:
`cloud-sql-proxy`, an IAP tunnel or an SSH port-forward. `ariodb serve`
starts each one before accepting agents, waits until its port accepts
connections, restarts it with backoff (1 s doubling to 30 s, reset after a
minute of good running) when it exits, and stops it on shutdown. One-off
commands (`setup`, `doctor`, `undo`, `mcp`) reuse a tunnel that is already
listening, or start their own.

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | Unique; `[database]`, credentials, `[clickhouse]` and `[mysql]` refer to it with `tunnel = "<name>"`. |
| `command` | list of strings | required | The program and its arguments, run directly (not through a shell). |
| `listen` | string | required | The local address the process listens on, as an IP address and port (`127.0.0.1:5433`, not `localhost:5433`). Must be unique across tunnels. |
| `ready_probe` | string | `"tcp"` | How ariodb knows the tunnel is up. `tcp` (a connection succeeds) is the only probe. |
| `ready_timeout_seconds` | integer | `30` | How long to wait for the port at start. Must be at least 1. `ariodb serve` refuses to start if a tunnel misses it. |
| `restart` | boolean | `true` | Start it again when it exits. |

The tunnel's output appears in ariodb's log prefixed `tunnel <name>:`. Its
process gets its own process group, and on shutdown receives SIGTERM, then
SIGKILL five seconds later.

```toml
[database]
url = "postgres://ariodb_gw@10.20.0.5:5432/app"
secret = "database-url"
tunnel = "cloudsql"
tls = "disable"   # cloud-sql-proxy encrypts the hop to Cloud SQL itself

[[tunnels]]
name = "cloudsql"
command = ["cloud-sql-proxy", "--port", "5433", "my-project:europe-west2:app-db"]
listen = "127.0.0.1:5433"
ready_timeout_seconds = 30
restart = true
```

With an SSH port-forward the database still speaks TLS end to end, so keep
`tls = "verify"`: the certificate is checked against the URL's host name,
not the tunnel's address.

```toml
[[tunnels]]
name = "bastion"
command = ["ssh", "-N", "-L", "127.0.0.1:5434:db.internal.example:5432", "ariodb@bastion.example.com"]
listen = "127.0.0.1:5434"
```

## `[[plugins]]`

Programs ariodb starts and talks to over stdin and stdout with
newline-delimited JSON-RPC 2.0. The protocol and lifecycle are in
[plugins](plugins.md).

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | Letters, digits and underscores, starting with a letter. Rules read its facts as `plugin.<name>.<key>`. |
| `command` | list of strings | required | The program and its arguments, run directly in ariodb's working directory. |
| `env` | table | `{}` | Variables set for the plugin. Do not put credentials here. |
| `pass_env` | list of strings | `[]` | Names of ariodb's own environment variables to pass on. |
| `secret_env` | table | `{}` | Variables filled from the secret store: variable name to secret name. |
| `timeout_ms` | integer | `5000` | How long one call may take, unless the call has its own limit (approvals use the approver's timeout). Must be at least 1. |
| `facts_cache_ms` | integer | `0` | Reuse a facts answer for the same request this long. `0` asks every time. |

The plugin's environment is only `PATH`, `HOME`, then `pass_env`, then
`secret_env`, then `env`.

```toml
[[plugins]]
name = "office_hours"
command = ["python3", "-I", "/opt/ariodb/plugins/ariodb_plugin.py"]
timeout_ms = 2000
facts_cache_ms = 10000
pass_env = ["ARIODB_PAGER_TOKEN"]
secret_env = { PAGER_KEY = "pager-key" }
env = { ARIODB_EXAMPLE_CUTOFF_HOUR = "18" }
```

## Environment variables

| Variable | Read by | What it does |
|---|---|---|
| `ARIODB_DATABASE_URL` | every command that connects | The gateway login. Wins over `[database] url` and `[database] secret`. |
| `ARIODB_JOURNAL_URL` | `setup`, the journal, `doctor` | The login for setup and the journal; needs the `REPLICATION` attribute, and for `setup`, ownership of the protected tables and `CREATE` on the database (to create the publication). Falls back to the gateway URL. See [Postgres roles](postgres.md). |
| `ARIODB_ADMIN_URL` | `undo`, dashboard undo | The login undo runs as; needs `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the protected tables. Falls back to the gateway URL. |
| `ARIODB_AGENT_TOKEN` | `mcp` | The token `ariodb mcp --agent <name>` checks against that agent's. |
| `ARIODB_MASTER_KEY` | everything that opens the secret store | The secret store's key: 32 bytes, base64. Without it, `<state dir>/master.key` is used, and created on first use. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AZURE_OPENAI_API_KEY` | model approvers | The provider's key when an approver names neither `api_key_env` nor `api_key_secret`. |
| `ARIODB_ANTHROPIC_API`, `ARIODB_OPENAI_API`, `ARIODB_GEMINI_API` | model approvers | Replace the provider's public API address when the approver sets no `base_url`. Meant for tests; prefer `base_url`. |
| `ARIODB_SLACK_API` | Slack approvers | Replace `https://slack.com/api`. Meant for tests. |
| `ARIODB_TELEGRAM_API`, `ARIODB_PAGERDUTY_API`, `ARIODB_OPSGENIE_API` | Telegram, PagerDuty and Opsgenie approvers | Replace `https://api.telegram.org`, the PagerDuty Events API and the Opsgenie API (for either region). Meant for tests. |
| `USER` | `approve`, `deny`, `undo --apply` | Recorded as the decider, `cli:<user>`. |
| `PATH`, `HOME` | plugins | Passed to every plugin. |
| Any name in a `*_env` key | as configured | Agent tokens, credential URLs, approver secrets, ClickHouse and MySQL passwords, plugin `pass_env`. |

Environment variables are read from ariodb's own process, so a change
needs a restart of that process to take effect. Secrets in the store do
not (see below).

## The secret store

An encrypted file for database URLs, tokens and API keys, so they need not
live in environment variables or the config file.

- **Where:** `<state dir>/secrets.json`, next to the key in
  `<state dir>/master.key` (created `0600` on first use) unless
  `ARIODB_MASTER_KEY` is set.
- **How:** each value is sealed with XChaCha20-Poly1305 under the 32-byte
  master key, with the secret's name bound in as associated data, so a
  sealed value cannot be moved to another name.
- **Managing it:** `ariodb secret set <name>` (value from stdin, so it stays
  out of shell history), `ariodb secret list` (names only),
  `ariodb secret delete <name>`, or the dashboard's settings page.
- **Keys that take a secret name:** `[database] secret`, `[[credentials]]
  secret`, `[[agents]] token_secret`, `[clickhouse] password_secret`,
  `[mysql] password_secret` and `journal_password_secret`,
  `[dashboard.oidc] client_secret_secret`, `bot_token_secret`,
  `signing_secret_secret`, `hmac_secret_secret`, `url_secret`,
  `routing_key_secret`, `smtp_password_secret` and `api_key_secret` on
  approvers, and the values of a plugin's `secret_env`.
- **ariodb's own entry:** `ariodb.approval-link-key`, the key that signs
  the chat, paging and email approvers' links, made on first use. The
  dashboard cannot set it (its secret names are letters, digits, `-` and
  `_`); delete it with `ariodb secret delete` to invalidate every link
  already sent. See [approvals](approvals.md#the-link-key).
- **When values are read:** at the moment they are used (each new agent
  connection, each ClickHouse request, each approval), so `ariodb secret
  set` takes effect for the next use without a restart. Plugins read
  `secret_env` when they start.

```bash
printf '%s\n' 'postgres://ariodb_gw:not-a-real-password@db.internal.example:5432/app' | ariodb secret set database-url
ariodb secret list
```

To keep secrets safe in backups of the state directory, set
`ARIODB_MASTER_KEY` from your secrets manager instead of relying on
`master.key`, and do not back the key up with the directory:

```bash
export ARIODB_MASTER_KEY="$(openssl rand -base64 32)"   # generate once, store it in your secrets manager
```

If you switch an existing store to `ARIODB_MASTER_KEY`, use the same key
that is in `master.key` (`cat <state dir>/master.key`), or set every secret
again: values sealed under one key cannot be opened with another.

## What reloads while ariodb runs

`ariodb serve` checks the config file's modification time every two
seconds. When it changes, ariodb loads and validates the whole file. If it
is valid, the new config is swapped in and the log says
`ariodb: reloaded <path>`. If not, the previous config stays in force and
the log says `ariodb: kept the previous config: <error>`. Saving from the
dashboard (with `config_writes = true`) applies at once.

```mermaid
flowchart LR
  edit[File modified] --> load{Loads and validates?}
  load -- yes --> swap[New config used for the next statement or connection]
  load -- no --> keep["Previous config kept, error logged"]
```

| Takes effect without a restart | Needs a restart of `ariodb serve` |
|---|---|
| `[[agents]]`: access, tables, row limits, credential, tokens from the secret store (for the next login or statement) | `[proxy] listen`, `tls_cert`, `tls_key` |
| `[[rules]]`, `[[approvers]]`, `[approvals]` (next statement) | `[dashboard] listen` |
| `[limits]` (next transaction) | `[clickhouse] http_listen`, `native_listen`, `tls_cert`, `tls_key` |
| `[[credentials]]` and `[database]` URL, secret and TLS (new connections) | `[[tunnels]]` (any change) |
| `[database] write_check` (new agent connections) | `[[plugins]]` (any change) |
| `[proxy] require_tls` (new connections; the certificate must already be loaded) | `[journal]` (any key, including `dir`) |
| `[dashboard] public_url`, `config_writes`, `approval_links`, and `[dashboard.oidc]` (next request; groups, domains and `password_login` apply to people already signed in) | `[audit] redact_literals` for the decisions log |
| `[audit] retention_days` (next hourly prune) | Environment variables, including `*_env` tokens |
| `[clickhouse] http_url`, `native_addr`, `user`, password, `accept_invalid_certificate` (next request) | `[mysql] listen`, `tls_cert`, `tls_key`, `journal`, `server_id`, `tag_table`, and the journal login |
| `[mysql] addr`, `database`, `user`, password, `tls`, `ca_file`, `require_tls` (new agent connections) | |

A config that points at a tunnel or plugin added since start-up is valid,
but connections through that tunnel fail until ariodb restarts. Other
processes (`ariodb mcp`, one-off commands) read the config when they start.

## Validation errors

These are the messages ariodb prints, prefixed `error:`, when a config does
not load. `ariodb check`, `serve` and every other command except `classify`
stop with exit code 1 (`ariodb test` uses 2). During a reload, the same
text follows `ariodb: kept the previous config:`.

### Reading and parsing

| Message | Fix |
|---|---|
| `cannot read ariodb.toml: No such file or directory (os error 2)` | Run from the directory holding the file, or pass `--config /path/to/ariodb.toml`. |
| `config is not valid TOML: TOML parse error at line 1, column 1` ... `missing field `database`` | Add a `[database]` section with a `url`. |
| `config is not valid TOML: ...` `unknown variant `superuser`, expected `read_only` or `read_write`` | An enumerated value is misspelt; the message lists the accepted ones. The same applies to `tls`, `verdict`, `stage`, `type`, `write_check` and `llm_fail_mode`. |

### `[database]`, `[limits]` and top level

| Message | Fix |
|---|---|
| `database.url must start with postgres:// or postgresql://` | Even with `secret` or `ARIODB_DATABASE_URL`, `url` must hold a `postgres://` URL. |
| `on_failure = "open" is not supported: ariodb always refuses a statement it cannot check. Remove the line or set it to "closed"` | As it says. |
| `limits.max_rows_per_write must be at least 1` | Use a positive limit. |

### Agents and credentials

| Message | Fix |
|---|---|
| `agent 'coding-agent' is listed twice` | Agent names must be unique. |
| `agent 'coding-agent' uses credential 'ro', which is not defined` | Add a `[[credentials]]` entry with that name. |
| `agent 'coding-agent' needs exactly one of token_env or token_secret` | Set one, not both. |
| `agent 'coding-agent' must list at least one table` | Add tables, or `["*"]`. An agent that only uses ClickHouse or MySQL still needs one Postgres table. |

### `[mysql]`

| Message | Fix |
|---|---|
| `[mysql] database must name the database agents work in` | Set `database` whenever `listen` is set. |
| `[mysql] server_id must not be 0: the journal registers with it as a replica` | Pick a number no server or replica uses, or set `journal = false`. |

### Rules and approvers

| Message | Fix |
|---|---|
| `rule 'r' is defined twice` | Rule names must be unique. |
| `rule 'r' has verdict approve but no approvers` | Add `approve = ["<approver>"]`. |
| `rule 'r' uses approver 'ops', which is not defined` | Add the `[[approvers]]` entry. |
| ``rule 'r': condition does not compile: `sql.kind ==` `` | Fix the CEL; try it with `ariodb explain`. |
| `rule 'r': plugin facts are only available to before-stage rules` | Remove `stage = "after"`, or move the plugin check to its own rule. |
| `rule 'r' reads facts from plugin 'x', which is not defined in [[plugins]]` | Define the plugin, or fix the name. |
| `approver 'ops' is defined twice` | Approver names must be unique. |
| `approver 's' (Slack) needs channel` | Also: `needs bot_token_secret or bot_token_env`, `needs signing_secret_secret or signing_secret_env for interactive buttons`. |
| `approver 'w' (Webhook) needs url` | Also: `needs hmac_secret_secret or hmac_secret_env`. |
| `approver 'm' (Llm) needs policy` | Write the policy the model applies. |
| `approver 'p' (Plugin) needs plugin` | Name the `[[plugins]]` entry. |
| `approver 'p' uses plugin 'x', which is not defined in [[plugins]]` | Define the plugin. |
| `approver 'm': unknown provider 'claude' (expected one of anthropic, openai, gemini, azure_openai, openai_compatible)` | Use one of the listed names. |
| `approver 'm' (openai_compatible) needs base_url` | Required for `openai_compatible` and `azure_openai`. |
| `approver 'm': base_url 'http://models.internal:8000/v1' must use https: statements and API keys would cross the network unencrypted (plain http is allowed only for localhost)` | Use `https`, or a local address. |
| `approver 'az' (azure_openai) needs model (the deployment name)` | Name the deployment; `openai_compatible` likewise `needs model`. |
| `approver 'm': api_version only applies to azure_openai` | Remove it. Also: `api_version must be "v1" or "preview" (Azure's v1 API)`. |
| `approver 'm': effort 'huge' is not one of low, medium, high, xhigh, max for anthropic` | Use a value the provider accepts. |
| `approver 'd' (discord) needs url_secret or url_env (the incoming webhook's URL)` | Likewise for `teams`, `google_chat` and `mattermost`. |
| `approver 'd' (discord): put the webhook URL in url_secret or url_env, not url: the URL itself is the credential` | Move the URL to the secret store or an environment variable. |
| `approver 't' (telegram) needs bot_token_secret or bot_token_env` | Also: `needs chat_id`. |
| `approver 'p' (pagerduty) needs routing_key_secret or routing_key_env (an Events API v2 integration key)` | Add the routing key. |
| `approver 'o' (opsgenie) needs api_key_secret or api_key_env` | Add the API key. |
| `approver 'p': region must be "us" or "eu"` | For `pagerduty` and `opsgenie`. |
| `approver 'e' (email) needs smtp_host` | Also: `needs from`, `needs at least one address in to`, `needs both smtp_user and smtp_password_secret or smtp_password_env, or neither`. |
| `approver 'e': 'ops at example' is not an email address: ...` | Write `from` and every `to` as `name@example.com` or `Name <name@example.com>`. |
| `approver 'e': smtp_tls = "none" is only allowed for a mail server on this machine; use "starttls" or "tls"` | Also: `smtp_tls must be "starttls", "tls" or "none", not "..."`. |
| `approver 's' (Slack) cannot set groups: only dashboard and webhook approvers are decided by signed-in people` | Remove `groups` from a `slack`, `llm` or `plugin` approver. |
| `approver 'ops' sets groups, which need [dashboard.oidc]` | Configure single sign-on, or remove `groups`. |
| `approver 'pager' sets groups, which its approval links can only check with [dashboard] approval_links = "sign_in"` | Use `sign_in` (the default with single sign-on), or remove `groups`. |

### `[dashboard.oidc]`

| Message | Fix |
|---|---|
| ``config is not valid TOML: ... unknown field `pasword_login` ...`` | A misspelt key: unknown keys are refused in this section. |
| `dashboard.oidc.issuer must be an https:// URL (http:// only for localhost)` | Use the provider's `https://` issuer. |
| `dashboard.oidc.client_id is empty` | Set the client ID. |
| `dashboard.oidc: set client_secret_env or client_secret_secret, not both` | Keep one. |
| `dashboard.oidc.redirect_path '/approvals' must be a path of its own, such as /auth/callback` | Pick a path that is not a dashboard page or under `/api/`, `/hooks/`, `/slack/` or `/assets/`. |
| `dashboard.oidc maps no groups to a role, so nobody could sign in: set admin_groups, approver_groups or viewer_groups` | Map at least one group. |
| `dashboard.oidc.groups_claim is empty` | Leave it out for the default, `groups`. |
| `dashboard.oidc.scopes must include openid` | Add `openid`. |

One warning does not stop the load: `ariodb: warning: approver 'y': effort
is ignored, because openai_compatible servers have no standard reasoning
control`.

### Tunnels and plugins

| Message | Fix |
|---|---|
| `every tunnel needs a name` / `tunnel 'pg' is listed twice` | Give each tunnel a unique name. |
| `tunnel 'pg' needs a command, such as ["cloud-sql-proxy", "--port", "5433", "project:region:instance"]` | Set `command`. |
| `tunnel 'pg': listen = "localhost:5433" must be an IP address and port, such as 127.0.0.1:5433` | Use an IP address. |
| `tunnels 'a' and 'b' both listen on 127.0.0.1:5433` | Give each its own port. |
| `tunnel 'pg': ready_timeout_seconds must be at least 1` | Use a positive timeout. |
| `[database] uses tunnel 'pg', which is not defined in [[tunnels]]` | Also reported for `credential '<name>'` and `[clickhouse]`. |
| `plugin name 'office-hours' must be letters, digits and underscores, starting with a letter (rules read its facts as plugin.<name>)` | Rename it, for example `office_hours`. |
| `plugin 'x' is listed twice` / `plugin 'x' needs a command, such as ["python3", "plugin.py"]` | As it says. |
| `plugin 'x': timeout_ms must be at least 1` | Use a positive timeout. |
| `plugin 'x': 'A=B' is not an environment variable name` | Variable names in `env`, `pass_env` and `secret_env` cannot contain `=`. |

### Errors that appear only when `ariodb serve` starts

These are not checked by `ariodb check`:

| Message | Fix |
|---|---|
| `proxy.tls_cert and proxy.tls_key must be set together` | Set both or neither. Likewise `clickhouse.tls_cert and clickhouse.tls_key must be set together`. |
| `proxy.require_tls needs proxy.tls_cert and proxy.tls_key` | Add the certificate and key. |
| `ariodb: MySQL proxy stopped: mysql.tls_cert and mysql.tls_key must be set together` | Set both or neither. Also `mysql.require_tls needs mysql.tls_cert and mysql.tls_key`, and `cannot listen on ...`. These stop only the MySQL listener; `ariodb serve` logs them and keeps running. |
| `/etc/ariodb/proxy.key: no private key found` | The file holds no PEM private key. A missing file gives `/etc/ariodb/proxy.key: No such file or directory (os error 2)`. |
| `TLS certificate: ...` | The certificate and key do not match, or the certificate is unusable. |
| `cannot listen on 0.0.0.0:6543: Address already in use (os error 98)` | Something else holds the port; often a second ariodb. |
| `bad clickhouse.http_url: ...` | Fix the URL. |

## Next

- [CLI reference](cli.md): every command, and which need the database
- [Operations](operations.md): running ariodb in production
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes
- [Rules](rules.md) and [approvals](approvals.md): the policy keys in depth
- [Compatibility](compatibility.md): `write_check` and database support
