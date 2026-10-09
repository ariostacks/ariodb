# Postgres

This page covers everything specific to running ariodb in front of
PostgreSQL: which versions work, the database roles to create and what to
grant them, TLS on both sides, how the wire proxy behaves (and what it
refuses), how reads and writes are run, statement timeouts, the change
journal that undo depends on, notes for managed services, and how to read
`ariodb doctor`. It is written for the engineer putting ariodb in front of
a production Postgres database. The rules about *which* statements an
agent may run are in [policy](policy.md) and [rules](rules.md); this page
is about how ariodb and Postgres work together.

## Which Postgres versions work

PostgreSQL 14 to 18 are tested with the full end-to-end suite, as are
TimescaleDB and the Supabase Postgres image. PostgreSQL 13 works for reads
and checked writes but not undo. YugabyteDB and CockroachDB speak the
protocol but cannot measure writes, so they need
[`write_check = "reported"`](#when-the-database-cannot-measure-writes-write_check--reported)
and have no undo.

| Database | Reads forced read-only | Writes checked before commit | Undo |
|---|---|---|---|
| PostgreSQL 14, 15, 16, 17, 18 | yes | yes | yes |
| PostgreSQL 13 (end of life) | yes | yes | no |
| TimescaleDB, Supabase Postgres | yes | yes | yes |
| YugabyteDB, CockroachDB | yes | only with `write_check = "reported"` | no |

The full table, with the date and suites it was tested with and the
managed services expected to work, is in
[compatibility](compatibility.md). Whatever the table says, run
[`ariodb doctor`](#reading-ariodb-doctor) against your own database: it
tests each guarantee directly.

## How a statement travels through ariodb

An agent connects to ariodb exactly as it would to Postgres. ariodb checks
each statement, opens its own transaction on the real database, runs the
statement, and, for writes, measures what happened before deciding whether
to commit.

```mermaid
sequenceDiagram
    participant A as Agent (psql, driver)
    participant P as ariodb
    participant D as Postgres
    A->>P: query (agent name + token)
    P->>P: parse, built-in policy, before-stage rules, approvals
    alt read
        P->>D: BEGIN READ ONLY, SET LOCAL statement_timeout
        P->>D: the agent's statements
        D-->>P: rows
        P-->>A: rows, passed on as they arrive
        P->>D: COMMIT
    else write
        P->>D: BEGIN, SET LOCAL statement_timeout, session tag
        P->>D: the agent's statements
        D-->>P: results (held back)
        P->>D: measure pg_stat_xact_user_tables
        P->>P: tables, row limit, after-stage rules, approvals
        alt passes
            P->>D: COMMIT
            P-->>A: the held results
        else fails
            P->>D: ROLLBACK
            P-->>A: error "ariodb: rolled back: ..."
        end
    end
```

Each agent connection gets its own connection to the database, opened as
the agent's login (the `[database]` URL, or the agent's `credential`) with
`application_name` set to `ariodb:<agent name>`, so you can find agents'
work in `pg_stat_activity`. There is no pooling: plan `max_connections`
for one database connection per agent connection, plus the journal's and
any `doctor`, `setup` or `undo` runs.

## Database roles and grants

ariodb uses up to three database logins. Keeping them separate is what
makes the database itself the backstop for anything ariodb's parsing
cannot see.

| Role | Configured by | Used for | Needs |
|---|---|---|---|
| Gateway | `[database]` `url` or `ARIODB_DATABASE_URL` | Every agent query (unless the agent names a `credential`) | Exactly the table grants agents need. Nothing more. |
| Extra credentials | `[[credentials]]` | Agents that should run as a different role, such as read-only ones | Their own, narrower grants |
| Journal | `ARIODB_JOURNAL_URL` (falls back to the gateway URL) | Reading the change stream for undo, and `ariodb setup` | `REPLICATION`; for `setup`, ownership of the protected tables and `CREATE` on the database |
| Undo | `ARIODB_ADMIN_URL` (falls back to the gateway URL) | Reversing a session with `ariodb undo` or the dashboard | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the protected tables |

### The gateway role

This is what agents' queries run as. Grant only what the agents behind it
need, on the tables they need it on:

```sql
CREATE ROLE ariodb_gw LOGIN PASSWORD 'not-a-real-password';
GRANT USAGE ON SCHEMA public TO ariodb_gw;
GRANT SELECT, INSERT, UPDATE, DELETE ON orders, customers TO ariodb_gw;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ariodb_gw;  -- for serial columns
-- Unqualified names must mean public.<name>, which is what the allow-list assumes.
ALTER ROLE ariodb_gw SET search_path = public;
```

Never give it superuser, `REPLICATION`, `pg_read_server_files` (or the
other `pg_*_server_files` roles), `pg_signal_backend`, or `EXECUTE` on
functions agents should not call. The reason is in
[security model](security-model.md): ariodb checks the tables a statement
*names*, so a view or function the gateway role can use can reach tables
the allow-list never sees. The grants are the real boundary; ariodb's
checks are a second, independent one.

The `search_path` line matters. ariodb treats `orders` and `public.orders`
as the same table. If the gateway role's `search_path` put another schema
first (including a schema named after the role, which the default
`"$user", public` path searches first), an unqualified `orders` would
resolve somewhere else while ariodb judged it as `public.orders`. Agents
cannot change `search_path` themselves: `SET search_path` and `set_config`
are refused.

### A read-only credential

Give read-only agents a login that can only read. If ariodb's checks ever
missed something, Postgres would still refuse the write.

```sql
CREATE ROLE ariodb_ro LOGIN PASSWORD 'not-a-real-password';
GRANT USAGE ON SCHEMA public TO ariodb_ro;
GRANT SELECT ON orders TO ariodb_ro;
ALTER ROLE ariodb_ro SET search_path = public;
```

```toml
[[credentials]]
name = "reporting"
url_env = "ARIODB_REPORTING_URL"   # postgres://ariodb_ro:...@db.internal:5432/app

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["orders"]
token_env = "ARIODB_TOKEN_SUPPORT_BOT"
credential = "reporting"
```

A credential inherits `[database]`'s `tls` setting unless it sets its own,
but not its `ca_file`: give the credential its own `ca_file` if it needs
one. See [configuration](configuration.md) for every key.

### The journal role

The journal reads Postgres's change stream through a logical replication
slot, which needs the `REPLICATION` attribute. It does not need to own or
read the tables.

```sql
CREATE ROLE ariodb_journal LOGIN REPLICATION PASSWORD 'not-a-real-password';
```

`ariodb setup` also connects with `ARIODB_JOURNAL_URL`, but it changes the
tables (`ALTER TABLE ... REPLICA IDENTITY FULL`) and creates a publication
for them, which needs the tables' owner and `CREATE` on the database. Run
it once with an owner's URL and then run the journal with the narrower
role:

```bash
# Once, and again whenever an agent gains write access to another table:
ARIODB_JOURNAL_URL='postgres://app_owner:not-a-real-password@db.internal:5432/app' ariodb setup

# From then on:
export ARIODB_JOURNAL_URL='postgres://ariodb_journal:not-a-real-password@db.internal:5432/app'
ariodb serve
```

### The undo role

`ariodb undo` writes the before-images back. It needs `SELECT` as well as
`INSERT`, `UPDATE` and `DELETE` on the protected tables, because its updates
and deletes find rows by their recorded values. Without `ARIODB_ADMIN_URL`
it uses the gateway role, which already has those on the tables agents may
write. Set it when you want undo to run as someone
else. See [undo](undo.md).

## Connecting agents

Agents log in with their agent name as the user and their token as the
password:

```bash
psql "postgres://coding-agent:agent-token-local-test-only@ariodb.internal:6543/app?sslmode=require"
```

- **The database name in the agent's URL is ignored.** Every query runs in
  the database named in the `[database]` URL (or the agent's credential).
- **Other startup parameters are not passed on**, including `options` and
  `search_path`. ariodb opens its own connection with its own parameters
  and replays the server's parameter messages (server version, encoding,
  time zone) to the agent.
- **The token travels as a cleartext password**, as Postgres's own
  `password` method does. Use TLS whenever agents connect over a network.

### Drivers that open their own transactions

ariodb runs each query in a transaction of its own and refuses `BEGIN`,
`COMMIT`, `ROLLBACK` and savepoints from agents (see
[below](#no-agent-controlled-transactions)). Most drivers are fine with
that, but some open a transaction implicitly:

- **psycopg (2 and 3)** sends `BEGIN` before the first statement unless the
  connection is in autocommit mode. Set `conn.autocommit = True`.
- **SQLAlchemy** follows the driver: create the engine with
  `isolation_level="AUTOCOMMIT"`.
- **JDBC** is in autocommit mode by default; leave it there.
- **node-postgres** (`pg`) only sends `BEGIN` if you do.

## TLS

### Between agents and ariodb

```toml
[proxy]
listen = "0.0.0.0:6543"
tls_cert = "/etc/ariodb/proxy.crt"   # PEM certificate chain
tls_key = "/etc/ariodb/proxy.key"    # PEM private key
require_tls = true                   # refuse agents that do not ask for TLS
```

- With a certificate and key, an agent that asks for TLS gets it
  (`sslmode=prefer`, `require`, `verify-full`). With `require_tls = true`,
  an agent that connects without TLS is refused with
  `ariodb requires TLS; connect with sslmode=require` (SQLSTATE `28000`).
- Without a certificate, ariodb answers "no" to a TLS request, so
  `sslmode=prefer` falls back to plain text and `sslmode=require` fails.
- `require_tls = true` without a certificate and key is a startup error.
- GSS encryption requests are always declined.

### Between ariodb and the database

```toml
[database]
url = "postgres://ariodb_gw:not-a-real-password@db.internal:5432/app"
tls = "verify"                      # disable | require | verify
ca_file = "/etc/ariodb/db-ca.pem"   # extra trusted CA, PEM
```

| `tls` | Encrypts | Checks the certificate | Use for |
|---|---|---|---|
| `disable` | no | no | A database on the same host. The default for `localhost`, `127.*` and `::1`. |
| `require` | yes | no: any certificate is accepted | Encryption where you cannot get the CA. Open to an active man in the middle. |
| `verify` | yes | yes: chain and host name | Everything else. The default for any other host. |

Under `verify`, ariodb trusts a built-in copy of the Mozilla root
certificates (not the operating system's store) plus `ca_file`. A database
whose certificate comes from a private CA, as on Amazon RDS, needs that
CA's bundle in `ca_file`.

**Known limit:** today `ca_file` is used for agents' connections only.
`ariodb setup`, `ariodb doctor`, the journal and `ariodb undo` check the
certificate against the built-in roots alone, so with a private CA and
`tls = "verify"` those connections fail verification. Until that changes,
reach such a database through a [tunnel](configuration.md) that handles
TLS itself (cloud-sql-proxy, for example), or accept `tls = "require"` for
the admin connections' sake.

When the connection goes through a [tunnel](configuration.md), the
certificate is still checked against the host name in the URL, not the
tunnel's local address.

ariodb authenticates to the database with a cleartext password, MD5 or
SCRAM-SHA-256 (without channel binding). Client-certificate, Kerberos and
GSSAPI authentication are not supported.

## The wire proxy

### Simple and extended protocol

Both of Postgres's query protocols work, so psql and every common driver
work unchanged.

- **Simple protocol.** One query message is one transaction. A message
  with several statements (`SELECT 1; UPDATE orders ...`) is split, each
  statement is checked, and they run together in one transaction: read only
  if every statement is a read, otherwise a checked write.
- **Extended protocol.** Everything an agent sends up to `Sync` is one
  transaction. ariodb opens and closes that transaction with hidden
  prepared statements of its own (named `__ariodb_*`) slipped into the
  message stream, and filters their responses out, so the agent's own
  prepared statements and portals are untouched. Any message from an agent
  that names a `__ariodb*` statement or portal is refused.
- **Prepared statements** are checked when they are parsed, so a refused
  statement fails at `Parse`, as a driver expects, even if it is never
  executed. ariodb remembers what each named statement holds across
  transactions and judges every `Execute` by it. If a batch fails at the
  database, ariodb forgets the names that batch parsed or closed, so a
  later `Bind` to one of them is refused rather than judged as whatever the
  name used to mean.
- **Portals** last until the end of the transaction, as in Postgres.
- **`Flush`** runs the batch so far, for drivers that wait for results
  before sending `Sync`.
- **The function-call protocol** (the `F` message) is refused with
  SQLSTATE `0A000`.

### Cancel requests

ariodb gives each agent connection its own random cancel key and maps it to
the database's. A cancel request is passed to the database, so a running
query stops as usual. It also withdraws a statement that is still waiting
for [approval](approvals.md): the approval is abandoned and the agent gets
an error saying it cancelled the statement. The database's own cancel keys
never reach agents.

### Size limit

ariodb will not inspect a protocol message over 1 MiB. Such a message is
read, discarded and refused with SQLSTATE `54000` ("message of N bytes is
over the 1 MiB inspection limit"), and the refusal is recorded. Batch
large inserts into several statements.

### What agents see when something is refused

Refusals are ordinary Postgres errors, so agents and drivers handle them
like any other failed statement. Every message starts `ariodb:`.

| Situation | SQLSTATE | Example message |
|---|---|---|
| Refused by the policy or a rule | `42501` | `ariodb: agent 'support-bot' is read only` |
| Write rolled back after running | `42501` | `ariodb: rolled back: the statement would change 599 rows (599 orders); the limit is 500` |
| Message over 1 MiB | `54000` | `ariodb: message of 2097152 bytes is over the 1 MiB inspection limit` |
| Function-call protocol | `0A000` | `ariodb: the function-call protocol is not supported` |
| Wrong agent name or token | `28P01` | `password authentication failed for user "coding-agent"` |
| TLS required but not used | `28000` | `ariodb requires TLS; connect with sslmode=require` |
| ariodb cannot reach the database | `08006` | `ariodb: cannot reach db.internal:5432: ...` |

Errors from Postgres itself (a constraint violation, a statement timeout)
reach the agent unchanged.

### What the proxy refuses

Some things ariodb refuses because it cannot check them, not because the
policy forbids them.

- **`COPY ... FROM STDIN`.** The data arrives in a sub-protocol after the
  statement, so ariodb would have to judge rows it has not seen. Use
  `INSERT`. If one slips past the classifier, ariodb aborts the copy.
  `COPY ... TO STDOUT` is a read and works.
- **Cursors.** `DECLARE` is judged by the query inside it, but `FETCH` is
  refused, so a cursor cannot be read. Drivers' server-side cursors
  (psycopg's named cursors, for example) do not work; fetch results in one
  go, or page with `LIMIT` and a key.
- **`DO`, `CALL`, `EXECUTE`, `LISTEN`, `NOTIFY`, `DEALLOCATE`** and other
  statements whose effect ariodb cannot see. See [policy](policy.md).

#### No agent-controlled transactions

`BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` and the rest are refused:
"ariodb runs every statement in its own transaction; send statements
without BEGIN or COMMIT". ariodb has to own the transaction to run reads
read-only and to measure a write before it commits. To make several
changes atomically, send them in one query string (simple protocol) or one
batch up to `Sync` (extended protocol): they run, are measured and commit
or roll back together.

## How reads run

A statement the policy classes as a read runs as:

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = 5000;   -- [limits] statement_timeout_ms
-- the agent's statement(s)
COMMIT;
```

`READ ONLY` is enforced by Postgres, not by ariodb, so a write hidden where
parsing cannot see it (inside a function the gateway role can call, for
example) fails with Postgres's own error, `cannot execute ... in a
read-only transaction` (SQLSTATE `25006`). This is why `nextval()` in a
read fails: it writes to a sequence.

Rows are streamed to the agent as they arrive, so large result sets do not
wait for the whole query. `SELECT ... FOR UPDATE` (and `FOR SHARE`) takes
row locks, so ariodb classes it as a write and needs write access for it.

## How writes are checked before commit

A write runs in an ordinary transaction that ariodb holds open until it
has decided:

```sql
BEGIN;
SET LOCAL statement_timeout = 5000;
SELECT pg_logical_emit_message(true, 'ariodb', '{"session":"s-...","agent":"coding-agent"}');  -- journal on
-- the agent's statement(s)
SELECT schemaname || '.' || relname, (n_tup_ins + n_tup_upd + n_tup_del)::bigint
  FROM pg_stat_xact_user_tables WHERE n_tup_ins + n_tup_upd + n_tup_del > 0 ORDER BY 1;
COMMIT;   -- or ROLLBACK
```

`pg_stat_xact_user_tables` reports, for the current transaction only,
how many rows were inserted, updated and deleted in each table. Because
Postgres counts these itself, rows changed by triggers, cascading foreign
keys and functions are included. ariodb then checks, in order:

1. **The measurement is trustworthy.** The database reports a row count
   for each `INSERT`, `UPDATE`, `DELETE` and `MERGE` (the `UPDATE 3` you
   see in psql). The measurement must account for at least that many rows.
   If it comes up short, ariodb cannot see what the write did, and it is
   rolled back:
   `rolled back: the database reported 5 changed rows but ariodb measured 0, so this write cannot be checked (run ariodb doctor)`.
   This catches Postgres-compatible databases whose statistics view stays
   empty, and writes to foreign tables, which Postgres does not count there.
2. **Every table changed is one the agent may change.** A trigger that
   writes to an audit table needs that table in the agent's `tables` too:
   `rolled back: the statement also changed table 'order_log', which agent 'coding-agent' may not change (1 order_log, 1 orders)`.
3. **The total is within the row limit** (`max_rows_per_write`, from the
   agent or `[limits]`; default 500). The total is the sum across every
   table, so an update of 300 orders whose trigger logs 300 rows counts as
   600. Updating the same row twice in one transaction counts twice.
4. **After-stage rules** pass, judged on `effects.rows` and
   `effects.tables`. See [rules](rules.md).
5. **Any approval** an after-stage rule asks for is granted. While it
   waits, the transaction stays open and its row locks are held.

Until the decision, the write's results are held back, so an agent never
sees `UPDATE 600` for a write that was then rolled back.

### When the database cannot measure writes: `write_check = "reported"`

YugabyteDB and CockroachDB do not count changes in
`pg_stat_xact_user_tables`. With the default `write_check = "measured"`,
the cross-check above therefore rolls back every write there. If you
accept a weaker check, switch to the row counts the database reports:

```toml
[database]
write_check = "reported"   # default "measured"
```

| | `measured` (default) | `reported` |
|---|---|---|
| Agent's tables | Checked against every table actually changed | Checked against the tables the statements name, before they run |
| Row limit | Rows actually changed, including triggers and cascades | Rows the database reports per statement |
| Rows and tables changed by triggers, cascades, functions | Seen and judged | **Not seen** |
| `effects.rows`, `effects.tables` in after-stage rules | Measured | Reported rows; the tables the write statements name |
| Refusals, approvals, `READ ONLY` reads | Enforced | Enforced |

Use `reported` only where `measured` cannot work, and keep the database
role's grants tight, since they become the only check on what triggers and
functions do. `ariodb doctor` prints a warning while it is set.

## Statement timeouts

```toml
[limits]
statement_timeout_ms = 5000   # default 5000
```

ariodb sets `statement_timeout` locally in every transaction it opens, so
it applies to each statement an agent runs. A statement that runs too long
is cancelled by Postgres with its usual error, `canceling statement due to
statement timeout` (SQLSTATE `57014`), and a write is rolled back.

Things to know:

- **Time waiting for approval is not counted.** A before-stage approval
  happens before the transaction opens. An after-stage approval happens
  after the statements finished, while the transaction is idle; if the
  database has `idle_in_transaction_session_timeout` set below the
  [approval timeout](approvals.md), Postgres will end the session first.
- **Agents may change `statement_timeout` and `lock_timeout` themselves.**
  Both are on the list of settings drivers commonly send (see
  [policy](policy.md#session-settings)), so a `SET statement_timeout = 0`
  sent in the same query string as a slow statement lifts the limit for
  it. Treat `statement_timeout_ms` as a default, not a ceiling. To make it
  one, add a rule that refuses every session setting except the
  formatting ones drivers send:

  ```toml
  [[rules]]
  name = "keep-the-timeouts"
  condition = '''sql.kind == 'session' && !sql.statement.matches('(?i)^\\s*set\\s+(session\\s+)?(application_name|client_encoding|datestyle|intervalstyle|timezone|time\\s+zone|extra_float_digits|bytea_output|standard_conforming_strings|client_min_messages)\\b')'''
  verdict = "deny"
  reason = "agents may change formatting settings only"
  ```

  It names what is allowed rather than what is refused, so `RESET`,
  comments before `SET`, and quoted or escaped setting names are all
  refused too.

- The same value, rounded up to whole seconds, becomes ClickHouse's
  `max_execution_time` (see [ClickHouse](clickhouse.md)).

## The journal: setting up for undo

Undo works from a journal of every row agents changed, with its before-
and after-image, tagged with the agent session that changed it. The
journal reads Postgres's logical change stream, so the database needs:

- **`wal_level = logical`**, which needs a restart. On managed services,
  turn on logical replication (see [below](#managed-services)).
- **PostgreSQL 14 or later.** The session tags travel as logical decoding
  messages, which `pgoutput` only carries from 14.
- **`ariodb setup`**, run once as described in
  [the journal role](#the-journal-role).

### What `ariodb setup` does

```text
$ ariodb setup
ok   wal_level is logical
ok   customers: changes will carry full before-images
ok   orders: changes will carry full before-images
ok   publication 'ariodb' covers customers, orders
ok   replication slot 'ariodb' is ready
```

1. Checks `wal_level`, and stops if it is not `logical`.
2. Works out the **protected tables**: every table a `read_write` agent
   lists. If any `read_write` agent has `tables = ["*"]`, that is every
   base table outside `pg_catalog` and `information_schema`.
3. Sets **`REPLICA IDENTITY FULL`** on each, so that updates and deletes
   carry the whole old row. Undo needs the old row to restore it, and uses
   it to spot rows someone else has changed since. The cost is more WAL
   for updates and deletes on those tables.
4. Creates the publication (`[journal] publication`, default `ariodb`), or
   sets its table list to exactly the protected tables if it exists. Use a
   publication name nothing else uses.
5. On PostgreSQL 18, sets `publish_generated_columns = stored` on the
   publication (see [below](#postgres-18-and-generated-columns)).
6. Creates the logical replication slot (`[journal] slot`, default
   `ariodb`) with the `pgoutput` plugin, if it does not exist.

It is safe to run again, and you must run it again when an agent gains
write access to a new table: until then, changes to that table are not
journalled and `doctor` reports it.

### How the journal runs

`ariodb serve` reads the slot every half second, appends one JSON line per
committed transaction to `<state dir>/journal.jsonl`, and only then
advances the slot, so a crash never loses a change. Only tables in the
publication are recorded.

**A slot holds WAL until it is read.** While `ariodb serve` is stopped, the
database keeps every WAL segment since the slot's position, and disk use
grows with your write volume. `doctor` warns once the slot holds back more
than 1 GiB. If you retire ariodb, drop the slot and publication:

```sql
SELECT pg_drop_replication_slot('ariodb');
DROP PUBLICATION ariodb;
```

### Running without the journal

On PostgreSQL 13, YugabyteDB, CockroachDB, or anywhere you do not want
undo, switch it off. Reads and checked writes still work.

```toml
[journal]
enabled = false
```

With the journal on, each write is tagged with `pg_logical_emit_message`.
Where that function does not exist (CockroachDB), every write fails until
the journal is off; `doctor` says so.

### Postgres 18 and generated columns

On PostgreSQL 18, a table with `REPLICA IDENTITY FULL` and a stored
generated column refuses updates and deletes unless its publication
includes generated columns. `ariodb setup` sets
`publish_generated_columns = stored` on 18 and later. If you ran setup
before upgrading to 18, run it again; `doctor` fails the journal check
until you do.

## Managed services

Managed services that run PostgreSQL itself should behave like the
matching version above, provided logical replication is on for undo. These
are expected to work but untested; `ariodb doctor` tells you for certain.

| Service | For undo | Notes |
|---|---|---|
| Amazon RDS for PostgreSQL, Aurora PostgreSQL | `rds.logical_replication = 1` in the parameter group (needs a reboot); `GRANT rds_replication TO ariodb_journal` | RDS certificates come from Amazon's own CA: put its bundle in `ca_file` and read the [TLS limit](#between-ariodb-and-the-database) |
| Google Cloud SQL for PostgreSQL | `cloudsql.logical_decoding = on`; `ALTER ROLE ariodb_journal WITH REPLICATION` | cloud-sql-proxy as a [tunnel](configuration.md) handles TLS and IAM |
| AlloyDB | `alloydb.logical_decoding = on` | |
| Azure Database for PostgreSQL (flexible server) | `wal_level = logical` | |
| Neon | Turn on logical replication for the project | |
| Supabase (hosted) | Logical replication is on | Run `ariodb setup` as `supabase_admin` (or another role that owns the tables and can replicate); `postgres` is not a superuser |
| Crunchy Bridge, Aiven, DigitalOcean | `wal_level = logical` (usually the default or a setting) | |

Untested and likely to need work: Amazon Aurora DSQL, Google Spanner's
PostgreSQL interface, Materialize, Redshift, and other databases that
speak the Postgres protocol without being Postgres. Expect reads to work,
and run `doctor` before giving an agent write access.

## Reading `ariodb doctor`

`ariodb doctor` connects with each login ariodb will use and tests, rather
than assumes, each guarantee. Every check is read-only or runs in a
transaction that is rolled back; each login's checks are given 30 seconds.
It exits 1 if any check fails (warnings do not fail it), so it can gate a
deployment.

On a healthy PostgreSQL 17 with a read-only credential and the journal on,
the output looks like this:

```text
default login: ariodb_gw@db.internal:5432/app
  ok    connected over TLS
  ok    PostgreSQL 17.6 (Debian 17.6-1.pgdg120+1)
  ok    reads run in READ ONLY transactions, and the database enforces them
  ok    writes are measured before commit (a 3-row test write counted 3)
  ok    writes can be tagged with their session for the journal
  ok    every agent table exists and this login can use it

credential 'reporting': ariodb_ro@db.internal:5432/app
  ok    connected over TLS
  ok    reads run in READ ONLY transactions, and the database enforces them
  ok    writes are measured before commit (a 3-row test write counted 3)
  ok    writes can be tagged with their session for the journal
  ok    every agent table exists and this login can use it

journal: ariodb_journal@db.internal:5432/app
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

### What each check means

**Per login** (the default login, then each credential an agent uses):

| Line | What it tested | If it is not `ok` |
|---|---|---|
| `connected over TLS` | `pg_stat_ssl` for this connection | `warn connected without TLS`: set `[database] tls = "verify"` |
| The server version | `version()`, plus TimescaleDB, Aurora, Supabase, Neon or AlloyDB if detected | Shown once, for the first login |
| `reads run in READ ONLY transactions...` | Tries to create a temporary table inside `BEGIN READ ONLY` and expects Postgres to refuse | `FAIL the database let a READ ONLY transaction create a table`: reads are not protected; do not use this database with ariodb. `warn ... enforcement could not be tested`: refused for another reason (no `TEMP` privilege), so not proven |
| `writes are measured before commit...` | Inserts 3 rows into a temporary table and checks `pg_stat_xact_user_tables` counts 3, then rolls back | `FAIL ... did not count a test write`: every write will be rolled back; see [`write_check`](#when-the-database-cannot-measure-writes-write_check--reported). `warn ... could not confirm`: no `TEMP` privilege, so only the view was probed |
| `writes can be tagged...` | `pg_logical_emit_message` in a rolled-back transaction (only with the journal on) | `FAIL`: every write will fail while the journal is on; set `[journal] enabled = false` |
| `every agent table exists...` | Each table of each agent using this login exists, and the login can `SELECT` it (and `INSERT, UPDATE, DELETE` for `read_write` agents) | `warn agent 'x': table 'y' does not exist`, `... cannot read ...`, `... cannot change ...`: fix the grant or the allow-list |

On YugabyteDB and CockroachDB, the write check is replaced by a `FAIL`
naming the database and suggesting `write_check = "reported"`, or by a
`warn` while `reported` is set.

**Journal** (only with `[journal] enabled = true`), using
`ARIODB_JOURNAL_URL`:

| Line | If it is not `ok` |
|---|---|
| `wal_level is logical` | Set it and restart, or turn on logical replication on a managed service |
| (version) | `FAIL Postgres 14 or later is needed for undo`: turn the journal off |
| `replication slot 'ariodb' exists` | Run `ariodb setup`; or the slot belongs to another database or plugin, so pick another `[journal] slot` |
| `publication 'ariodb' covers every table agents may change` | Run `ariodb setup` again; it names the missing tables |
| `protected tables keep full before-images` | Run `ariodb setup` again; it names the tables |
| (Postgres 18 only) | `FAIL Postgres 18 refuses updates to tables with generated columns...`: run `ariodb setup` again |
| `the change stream can be read, with session tags` | Usually a missing `REPLICATION` attribute on the journal role |
| `the slot holds back N of WAL` | `warn` over 1 GiB: is `ariodb serve` running? |

**What works here** sums it up. Each `no` line gives the first reason, for
example `no   undo of agent sessions: not set up (run ariodb setup)` or
`no   undo of agent sessions: the journal is off ([journal] enabled = false)`.
`writes` is also `no` when no agent has write access.

`ariodb serve` runs the same checks when it starts, logs every finding
that is not `ok` as `ariodb: <section>: <finding>`, and prints a one-line
summary such as `ariodb: reads yes; checked writes yes; undo yes`.

## Limits

- ariodb checks tables by the names a statement uses. Views, functions and
  `SECURITY DEFINER` functions can reach other tables; database grants are
  the boundary. See [security model](security-model.md).
- Table names are compared in lower case, so a quoted mixed-case table
  (`"Orders"`) is treated as `orders`. Avoid tables whose names differ only
  by case.
- Unqualified names beginning `pg_` are treated as the system catalogue
  and are readable by every agent. Do not give user tables names that
  start with `pg_`.
- No `COPY FROM STDIN`, no cursors, no agent-controlled transactions, no
  function-call protocol; messages up to 1 MiB.
- `statement_timeout_ms` is a default agents can change unless a rule
  stops them.
- No connection pooling. Connections are bounded by `[limits]
  max_connections`, `max_connections_per_agent` and `handshake_timeout_ms`
  (see [configuration](configuration.md#limits)); put the listener behind
  network controls too.
- Undo needs PostgreSQL 14 or later with logical replication.

## Next

- [Policy](policy.md): which statements each agent may run.
- [Rules](rules.md): refusing or holding statements, including after-stage
  rules on a write's measured effect.
- [Undo](undo.md): reversing an agent session from the journal.
- [Configuration](configuration.md): every key in `ariodb.toml`.
- [Compatibility](compatibility.md): the tested databases in full.
- [Operations](operations.md) and [troubleshooting](troubleshooting.md).
