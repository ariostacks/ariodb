# Undo

This page explains how ariodb records every change agents make to
Postgres and how it reverses one agent session's changes without touching
anyone else's: the change journal and how it is fed, what a session is, how
an undo plan is worked out, what happens when someone else has changed the
same rows since, what can and cannot be undone, and what running the
journal costs your database. It is for engineers who will rely on undo
after an agent has done something it should not have, and for whoever runs
the database underneath.

## The idea in one paragraph

Every write an agent makes through ariodb runs in a transaction that
carries a small tag naming the agent's session. Postgres's logical
replication streams every committed change to the protected tables, tag
included, and ariodb appends them to a journal on disk. To undo a session,
ariodb takes that session's changes from the journal, works out the single
statement that puts each row back the way it was before the session first
touched it, checks that nobody has changed those rows since, and runs all
of it in one transaction.

```mermaid
flowchart LR
    A[Agent] -->|write| P[ariodb proxy]
    P -->|"BEGIN, tag (session, agent), write, COMMIT"| DB[(Postgres)]
    DB -->|logical replication slot| J[ariodb journal]
    J -->|one JSON line per transaction| F[journal.jsonl]
    F -->|ariodb undo / dashboard| U[undo plan]
    U -->|one transaction, tagged undo:session| DB
```

## Requirements

- **Postgres 14 or later with `wal_level = logical`.** On managed services
  (RDS, Cloud SQL, Azure, Supabase and others), turn on logical
  replication. Before 14 the change stream cannot carry the session tags.
- **A journal role with the `REPLICATION` attribute**, given in
  `ARIODB_JOURNAL_URL`. `ariodb setup` connects with the same variable, and
  the role it runs as must also own the protected tables (to change their
  replica identity and publish them) and have `CREATE` on the database (to
  create the publication). Without `CREATE`, `setup` stops with
  `error: permission denied for database app`. The usual arrangement is to
  run `setup` once with a table owner's URL and the journal with a
  `REPLICATION`-only role; see [the journal role](postgres.md#the-journal-role).
- **A primary key on every table agents write to.** Without one, undo
  cannot find a row again.
- **An undo role** (`ARIODB_ADMIN_URL`, otherwise the gateway login) that
  may `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the protected tables.
  `SELECT` is needed because undo finds rows by their recorded values.

YugabyteDB and CockroachDB have no Postgres logical replication, so undo is
not available on them; set `[journal] enabled = false`. See
[compatibility.md](compatibility.md). Run `ariodb doctor` to see whether
your database supports undo; it checks every item on this list.

## Setting up the journal

```toml
[journal]
enabled = true          # default true
dir = ".ariodb"         # state directory: journal.jsonl, ariodb.db, secrets, master.key
slot = "ariodb"         # logical replication slot
publication = "ariodb"  # publication of the protected tables
```

Then, once, as a role that owns the protected tables:

```bash
ARIODB_JOURNAL_URL='postgres://app_owner:not-a-real-password@db.internal:5432/app' ariodb setup
```

`ariodb setup` is safe to run again, and you must run it again whenever
you give an agent write access to another table. It:

1. checks that `wal_level` is `logical`;
2. works out the **protected tables**: every table some `read_write` agent
   may write. If an agent has `tables = ["*"]`, that is every user table
   that exists when you run `setup` (tables created later are not covered
   until you run it again);
3. sets `REPLICA IDENTITY FULL` on each, so updates and deletes carry the
   whole row as it was before, not just its key;
4. creates the publication (or sets its table list) to exactly those
   tables; on Postgres 18 it also publishes stored generated columns, which
   Postgres 18 needs before it allows updates to such tables;
5. creates the logical replication slot, using the built-in `pgoutput`
   plugin, if it does not exist.

```text
ok   wal_level is logical
ok   customers: changes will carry full before-images
ok   orders: changes will carry full before-images
ok   publication 'ariodb' covers customers, orders
ok   replication slot 'ariodb' is ready
```

`REPLICA IDENTITY FULL` makes every update and delete on those tables write
the full old row to the write-ahead log. On wide, heavily updated tables
that is a noticeable amount of extra WAL. It applies to every writer, not
only agents.

## The journal

`ariodb serve` runs the journal alongside the proxy. Every half second it
reads up to 1,000 changes from the slot, groups them into committed
transactions, appends one JSON line per transaction to
`<state dir>/journal.jsonl`, flushes the file to disk, and only then
advances the slot. If ariodb crashes between writing and advancing, the
same changes are read again on restart; no change is lost.

### What is recorded

Every committed change to a protected table, **by anyone**: agents through
ariodb, people with psql, your application, migrations. Changes made
outside ariodb are recorded without a session. ariodb needs them to notice
when someone else changed a row after an agent did.

One line per transaction:

```json
{
  "xid": 1042,
  "lsn": 24312840,
  "lsn_text": "0/172FE08",
  "at_ms": 1791546012345,
  "session": "s-d4c9dddfdb",
  "agent": "coding-agent",
  "changes": [
    {
      "schema": "public",
      "table": "orders",
      "op": "update",
      "columns": ["id", "customer_id", "status", "total"],
      "old": ["7", "3", "paid", "120.00"],
      "new": ["7", "3", "void", "120.00"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `xid`, `lsn`, `lsn_text` | Transaction ID and commit position; `lsn` orders transactions |
| `at_ms` | Commit time, Unix milliseconds |
| `session`, `agent` | The ariodb session and agent that made the change; `null` for changes made outside ariodb; `undo:<session>` and `ariodb-undo` for an undo |
| `op` | `insert`, `update`, `delete` or `truncate` |
| `columns`, `old`, `new` | Column names, and values before and after as text (a `null` value is SQL NULL). `old` is `null` for inserts, `new` for deletes |

A value Postgres did not resend because it was unchanged and stored out of
line (TOAST) appears as `{"unchanged": true}`.

The journal holds complete rows, including any personal data in them, as
plain text. `[audit] redact_literals` does not apply to it. It is never
pruned. Treat the state directory as sensitive (ariodb creates it `0700`),
and see [Operational cautions](#operational-cautions).

### Session tagging

Each connection an agent opens to the Postgres proxy, and each
`ariodb mcp` process, is an **ariodb session**, with an ID such as
`s-d4c9dddfdb`. Every write transaction ariodb runs for it starts with:

```sql
BEGIN;
SET LOCAL statement_timeout = 5000;   -- [limits] statement_timeout_ms
SELECT pg_logical_emit_message(true, 'ariodb', '{"session":"s-d4c9dddfdb","agent":"coding-agent"}');
-- the agent's statement, then the effect check, then COMMIT or ROLLBACK
```

`pg_logical_emit_message` with `true` writes a transactional message into
the WAL: it is part of the transaction, so a rolled-back write leaves no
tag and no changes, and a committed one carries the tag with its changes.
Reads are not tagged.

Agents cannot forge or tamper with this tag: `pg_logical_emit_message` and
the replication-slot functions are refused for every agent, whatever the
rules say, as are agent `BEGIN`, `COMMIT` and savepoints. See
[security-model.md](security-model.md).

If the database cannot run `pg_logical_emit_message`, every write fails
while the journal is on. `ariodb doctor` checks for this.

## Listing sessions

```console
$ ariodb sessions
session        agent              txns   rows  status     tables
s-d4c9dddfdb   coding-agent          3     12             orders, order_items
s-0a71c2e9b4   coding-agent          1    400  undone     orders
```

Sessions appear only once they have changed data, newest first. `rows`
counts row changes, so a row updated twice counts twice. `undone` means an
undo of that session has been recorded in the journal. The dashboard's
[Sessions and undo page](dashboard.md#sessions-and-undo) shows the same
list.

To find the session behind a statement you saw in the decisions log, the
log records each statement's session. `ariodb mcp` prints its session ID
to stderr when it starts.

## Planning an undo

```console
$ ariodb undo --session s-d4c9dddfdb
undo plan for s-d4c9dddfdb: 4 steps
  delete inserted public.order_items row (5, 2)
  restore public.orders row (5)
  re-insert deleted public.order_items row (5, 1)
  restore public.orders row (7)

nothing changed. Run again with --apply to undo.
```

Without `--apply`, `ariodb undo` only shows the plan. The plan is worked
out like this:

1. **Collect the session's changes** from the journal, in commit order.
2. **One step per row, from the net effect.** For each row the session
   touched, ariodb compares the row as it was before the session's first
   change with the row as the session's last change left it, and writes
   the single inverse:

   | The session... | The step |
   |---|---|
   | inserted the row (and maybe changed it again) | `DELETE` it |
   | changed an existing row (any number of times) | `UPDATE` it back to its first before-image |
   | deleted an existing row (maybe after changing it) | `INSERT` it again, as it was before the first change |
   | inserted the row and deleted it again | nothing |

   Replaying every change backwards would give one row several steps that
   must run in a particular order; the net inverse gives each row exactly
   one.
3. **Newest first.** Steps are ordered by when the session last touched
   each row, latest first, which is usually the order foreign keys need
   (children created after their parents are removed before them).
4. **Find conflicts** (next section).
5. **Find what cannot be undone** (see
   [what can and cannot be undone](#what-can-and-cannot-be-undone)).

Values are written as typed SQL literals using each column's current type
(`'120.00'::numeric(10,2)`), quoted so they are safe whatever the server's
`standard_conforming_strings` setting. Generated columns are left for
Postgres to recompute. Re-inserts use `OVERRIDING SYSTEM VALUE`, so identity
columns get their old values back.

## Conflicts and `--skip-conflicts`

A row is a **conflict** when anyone else changed it after this session
first did: another agent session, a person or application outside ariodb,
or an earlier undo. Restoring the session's before-image would silently
overwrite their change, so ariodb never does that.

```console
$ ariodb undo --session s-d4c9dddfdb
undo plan for s-d4c9dddfdb: 4 steps
  delete inserted public.order_items row (5, 2)
  restore public.orders row (5)
  re-insert deleted public.order_items row (5, 1)
  restore public.orders row (7)
  conflict: public.orders row (7) was changed later by someone outside ariodb

nothing changed. Run again with --apply to undo.
```

With conflicts, `--apply` on its own refuses and changes nothing:

```text
error: rows were changed by others since; nothing was undone. Use --skip-conflicts to undo the rest.
  public.orders row (7) was changed later by someone outside ariodb
```

`--apply --skip-conflicts` undoes every row that has no conflict and
leaves the conflicting rows exactly as they are now. Decide which you
want: sometimes the later change was a person already fixing the agent's
mistake, and leaving it is right; sometimes you need to look at the row
first.

Conflicts are found in the journal, so a change only counts once the
journal has recorded it. The journal is usually less than a second behind,
but if `ariodb serve` (and so the journal) has been stopped, recent changes
by others are not yet known. Make sure the journal is running and caught
up before applying an undo.

## Applying an undo

```console
$ ariodb undo --session s-d4c9dddfdb --apply
undo plan for s-d4c9dddfdb: 4 steps
  delete inserted public.order_items row (5, 2)
  restore public.orders row (5)
  re-insert deleted public.order_items row (5, 1)
  restore public.orders row (7)

undone: 4 rows restored in one transaction
```

The whole plan runs in **one transaction**, tagged `undo:<session>` with
agent `ariodb-undo`, so the undo is itself journalled. Either every step
succeeds and it commits, or nothing changes. Each step runs inside a
savepoint, and ariodb checks it changed exactly the one row it meant to:

- **Foreign-key ordering is retried.** A step that fails on a foreign key
  (a child that needs its parent back first) is put aside and retried after
  the others, until no more progress can be made.
- **Cascades and triggers are refused.** If a step would change rows other
  than its own (an `ON DELETE CASCADE` or `SET NULL`, or a trigger,
  reaching rows the session never touched), it is rolled back to its
  savepoint and retried later; if it still would, the whole undo is
  refused and nothing changes:

  ```text
  error: could not undo without touching other rows: delete inserted public.orders row (12) would also change 3 other rows (a foreign key cascade or a trigger), which undo leaves alone; nothing was undone
  ```

- A step that changes no row, or more than one, stops the undo, and
  nothing changes.

Undoing the same session twice is refused (`session 's-...' was already
undone`), and the session is shown as `undone`. Undo notifies any
[plugins](plugins.md) with the `notifier` capability (`undo_applied`).

`ariodb undo` connects with `ARIODB_ADMIN_URL`, or the gateway URL if that
is not set, and reads the journal from the state directory, so run it on
the ariodb host with the same config as `ariodb serve`.

## What can and cannot be undone

| Change | Handling |
|---|---|
| Insert, update, delete, including rows changed by cascades and triggers during the agent's write | Undone, in one transaction |
| `TRUNCATE`, `DROP`, schema changes | Refused for agents, so never need undoing |
| Rows someone else changed after the session did | Reported as conflicts; with `--skip-conflicts` they are left alone and the rest undone, otherwise nothing is undone |
| Undo steps that would cascade (or fire triggers) into rows the session never touched | Refused; nothing is undone |
| Rows in tables without a primary key | Reported as not undoable; nothing is undone |
| A large value Postgres did not include in the change record (`{"unchanged": true}`) needed to restore a row | Reported as not undoable; nothing is undone |
| A session already undone | Refused |
| Sequence values | Not rewound; gaps in IDs are harmless |
| ClickHouse writes | Not journalled; cannot be undone |
| Changes through a database without logical replication (YugabyteDB, CockroachDB) | Not journalled; cannot be undone |
| Anything outside the database (emails sent, payments taken, webhooks fired by triggers) | Out of scope |

Anything "not undoable" blocks the whole undo: ariodb will not apply part
of a plan because part of it is impossible. The plan lists each item as
`cannot undo: ...`.

## Undo from the dashboard

The dashboard's **Sessions and undo** page lists the same sessions. **Review
undo** on a session opens its plan: the steps (the first ones listed, with
a count of the rest), any conflicts, anything that cannot be undone, and
whether it was already undone. If there are conflicts, a checkbox chooses
"Undo the rest and leave the conflicting rows as they are now", which is
`--skip-conflicts`. The **Undo** button asks for confirmation, then applies
the plan exactly as `ariodb undo --apply` does and reports how many rows
were restored. Any signed-in dashboard user can undo a session. See
[dashboard.md](dashboard.md#sessions-and-undo).

The dashboard runs undo from the `ariodb serve` process, so
`ARIODB_ADMIN_URL` (if you use it) must be in that process's environment.

## How undo is tested

Besides unit tests for each inverse and for the quoting, undo is checked by
a seeded simulation against a real Postgres behind a real `ariodb serve`
([tests/sim_undo.rs](../tests/sim_undo.rs), run by
[scripts/sim-undo.sh](../scripts/sim-undo.sh), which needs Docker):

```bash
./scripts/sim-undo.sh                                 # seeds 1 to 5, 60 operations, 4 sessions each
SIM_SEEDS="42 1234" ./scripts/sim-undo.sh             # other seeds
SIM_OPS=120 SIM_SESSIONS=6 ./scripts/sim-undo.sh      # longer runs
```

For each seed it builds three tables linked by cascading foreign keys,
opens several agent sessions through the proxy, and runs a random mix of
agent writes and direct "human" writes: inserts, updates, and deletes that
cascade. Every write is bracketed by snapshots of the whole database, so
the test knows exactly which rows each write changed without asking
ariodb. It then undoes random sessions (some twice, some with
`--skip-conflicts`), predicts each result from the snapshots alone, and
checks that:

- rows only that session touched are restored exactly;
- rows anyone else changed later are reported as conflicts and left alone,
  and without `--skip-conflicts` nothing changes at all;
- no other row changes, so an undo that would need to cascade into rows
  the session did not touch is refused;
- undoing a session twice is refused.

The same seed always produces the same workload, and a failure prints the
seed, the plan and the history of the rows involved, so it can be run
again on its own.

## Operational cautions

**An idle slot holds WAL.** A logical replication slot keeps every WAL
segment the slot has not yet consumed. While `ariodb serve` runs, the
journal consumes changes within a second or so. While it is stopped, or
cannot connect as the journal role, **Postgres keeps all WAL written since,
and the disk fills**. This applies to all writes to the database, not only
agents'.

- Monitor the slot:

  ```sql
  SELECT slot_name, active,
         pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) AS behind
  FROM pg_replication_slots WHERE slot_name = 'ariodb';
  ```

  Alert when `behind` grows steadily or `active` stays false.
- Consider `max_slot_wal_keep_size` to cap how much WAL a slot can hold.
  The trade-off: if the cap is reached, Postgres invalidates the slot, the
  journal stops, and changes from then on are not recorded; you would need
  to drop the slot, run `ariodb setup` again, and accept a gap in what can
  be undone.
- **If you stop using ariodb, or turn the journal off, drop the slot:**

  ```sql
  SELECT pg_drop_replication_slot('ariodb');
  DROP PUBLICATION ariodb;
  ```

  `[journal] enabled = false` stops ariodb reading the slot but does not
  drop it.

**`ariodb mcp` does not run the journal.** Writes made through
`ariodb mcp` are tagged, but they are only recorded while `ariodb serve`
is running somewhere with the same config and state directory. Run
`ariodb serve` alongside MCP agents.

**The journal file grows without limit.** `journal.jsonl` is never pruned
or rotated, and it holds full row images for every change to protected
tables, by anyone. Size the disk for it, keep it on encrypted storage, and
back it up with the same care as the database. If you move old lines out of
it, sessions in those lines can no longer be undone, and changes in them
are no longer seen as conflicts.

**One state directory per slot.** Two `ariodb serve` processes reading the
same slot would split the changes between two journals. Run one journal per
database, and give each database its own `slot` and `publication` names if
several ariodb deployments share a server.

**Undo is not a backup.** It reverses what agents did through ariodb, with
the limits above. Keep your usual backups and point-in-time recovery.

## Next

- [Dashboard](dashboard.md): reviewing and applying undo plans in the browser.
- [Postgres](postgres.md): database roles, `setup` and the effect check.
- [Operations](operations.md): running ariodb day to day.
- [CLI](cli.md): every command, including `sessions` and `undo`.
- [Security model](security-model.md): what the journal and undo can and cannot guarantee.
