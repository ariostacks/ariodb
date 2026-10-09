# Database compatibility

What ariodb guarantees depends on what the database can do. This page
lists the Postgres versions and Postgres-compatible databases that have been
tested, the managed services expected to work, and what
`write_check = "reported"` gives up. It is for operators choosing where to
put ariodb. Run `ariodb doctor` against your own database: it checks each
login and the journal, and ends with what works there. Every check is
read-only or runs in a transaction that is rolled back.

Tested on 9 October 2026 with `scripts/e2e.sh` (130 checks) and
`scripts/e2e-compat.sh` (17 checks).

## Tested

| Database | Reads forced read-only | Writes checked before commit | Undo | How tested |
|---|---|---|---|---|
| PostgreSQL 18 | yes | yes | yes | full suite |
| PostgreSQL 17 | yes | yes | yes | full suite |
| PostgreSQL 16 | yes | yes | yes | full suite |
| PostgreSQL 15 | yes | yes | yes | full suite |
| PostgreSQL 14 | yes | yes | yes | full suite |
| PostgreSQL 13 (end of life) | yes | yes | no | full suite fails at undo |
| TimescaleDB (pg17 image) | yes | yes | yes | full suite |
| Supabase Postgres 17.6 image | yes | yes | yes | full suite |
| YugabyteDB 2026.1 | yes | only with `write_check = "reported"` | no | compat suite |
| CockroachDB 25.2 | yes | only with `write_check = "reported"` | no | compat suite |

Notes:

- **PostgreSQL 13**: its change stream cannot carry the tags that tie a
  change to an agent session (`pgoutput` gained `messages` in 14), so undo
  is unavailable. Set `[journal] enabled = false`; reads and checked writes
  work. Postgres 13 reached end of life in November 2025.
- **PostgreSQL 18**: tables with generated columns need the publication to
  include them, or Postgres refuses updates. `ariodb setup` does this; if
  you set up ariodb before upgrading to 18, run `ariodb setup` again.
- **Supabase**: run `ariodb setup` as `supabase_admin` (or another role that
  owns the tables and can replicate). The `postgres` role is not a
  superuser on current images.
- **YugabyteDB and CockroachDB** do not count changes to their tables in
  `pg_stat_xact_user_tables`, which is how ariodb measures a write before
  commit. By default ariodb therefore rolls back every write there (reads
  work). `write_check = "reported"` allows writes, judged by the row counts
  the database reports for each statement; see below. Neither offers the
  SQL-level logical decoding the journal reads, so undo is unavailable: set
  `[journal] enabled = false`. CockroachDB also has no
  `pg_logical_emit_message`, so with the journal on, every write fails.

## Expected to work, untested

Managed services that run PostgreSQL itself should behave like the
matching Postgres version above, provided logical replication is turned on
for undo. `ariodb doctor` tells you for certain.

| Service | For undo |
|---|---|
| Amazon RDS for PostgreSQL | `rds.logical_replication = 1`; the journal role needs `rds_replication` |
| Amazon Aurora PostgreSQL | as RDS |
| Google Cloud SQL for PostgreSQL | `cloudsql.logical_decoding = on`; the journal role needs `REPLICATION` |
| AlloyDB | `alloydb.logical_decoding = on` |
| Azure Database for PostgreSQL (flexible server) | `wal_level = logical` |
| Neon | turn on logical replication for the project |
| Supabase (hosted) | logical replication is on |
| Crunchy Bridge, Aiven, DigitalOcean | `wal_level = logical` (usually the default or a setting) |

Untested and likely to need work: Amazon Aurora DSQL, Google Spanner's
PostgreSQL interface, Materialize, Redshift, and other databases that speak
the Postgres protocol without being Postgres. Expect reads to work and run
`ariodb doctor` before giving an agent write access.

## `write_check = "reported"`

```toml
[database]
write_check = "reported"   # default "measured"
```

With `measured` (the default), ariodb asks the database, before commit,
which tables the transaction changed and by how many rows, including
changes made by triggers, cascades and functions. A write that touches a
table the agent may not change, or more rows than its limit, is rolled
back. ariodb also compares that measurement with the row counts the
database reports for each statement (`UPDATE 3`); if the measurement comes
up short, it cannot be trusted and the write is rolled back.

With `reported`, ariodb judges a write by the row counts the database
reports. Still enforced: the agent's tables (checked from the statement
before it runs), its row limit (before commit), refusals, approvals and
after-write rules over `effects.rows`. Not seen: rows changed by triggers,
cascades and functions, and the tables they touch. Use it only where
`measured` cannot work, and keep the database role's grants tight, since
they are the backstop for what parsing cannot see.

## Next

- [Postgres](postgres.md): roles, privileges and logical replication.
- [Installation](installation.md): building and running ariodb.
- [CLI](cli.md): `ariodb doctor` and `ariodb setup`.
- [Troubleshooting](troubleshooting.md): when `doctor` reports a failure.
