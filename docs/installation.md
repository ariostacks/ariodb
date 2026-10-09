# Installation

This page covers building ariodb from source, running it as a long-lived
service under systemd, running it in a container, and upgrading it. It is
for the engineer who will operate ariodb in front of a real database. If
you only want to try ariodb on your laptop, the
[quickstart](quickstart.md) is quicker.

## Requirements

**To build:**

- **Rust**, through [rustup](https://rustup.rs). The crate uses the 2024
  edition and let chains, so you need Rust 1.88 or later. `Cargo.toml` does
  not pin a `rust-version`; ariodb is built and tested on current stable
  Rust, and that is what we recommend.
- **A C compiler and libclang.** ariodb parses SQL with Postgres's own
  parser (`libpg_query`, through the `pg_query` crate), which is compiled
  from C and bound with bindgen. SQLite and the TLS library (aws-lc) are
  compiled in as well, and the latter may want CMake on some platforms. On
  Debian or Ubuntu: `apt install build-essential clang libclang-dev cmake`.
  On macOS, the Xcode command line tools (plus `brew install cmake` if the
  build asks for it) are enough.
- **Node.js only if you change the dashboard.** The dashboard's built files
  (`dashboard/dist`) are committed and embedded in the binary, so
  `cargo build` needs no Node. See [Rebuilding the dashboard](#rebuilding-the-dashboard).

**To run:**

- A Unix-like system (Linux or macOS). ariodb uses Unix file permissions
  for its state directory and handles `SIGTERM` for a clean shutdown.
- **Postgres 14 or later** with `wal_level = logical` for the full feature
  set, including undo. Reads and checked writes work on older and
  Postgres-compatible databases; see [compatibility](compatibility.md) and
  run [`ariodb doctor`](cli.md) against yours.
- Optionally **ClickHouse**, reached over its HTTP interface or native
  protocol. See [ClickHouse](clickhouse.md).
- Docker only for the demo and the end-to-end test scripts.

## Building from source

```bash
git clone <repository URL> ariodb
cd ariodb
cargo build --release
```

The binary lands at `target/release/ariodb`. It is self-contained: the
dashboard's web app, the Postgres parser and SQLite are all inside it, and
TLS uses rustls with a bundled set of root certificates, so it does not
depend on OpenSSL. Copy it wherever you like:

```bash
sudo install -m 0755 target/release/ariodb /usr/local/bin/ariodb
ariodb --version
```

`ariodb --help` lists every command; the [CLI reference](cli.md) explains
each one.

A debug build (`cargo build`, binary at `target/debug/ariodb`) is what the
demo and the test scripts use. It works the same but is slower; use the
release build in production.

### Rebuilding the dashboard

Only needed after changing the front end in `dashboard/` (React, Vite,
Tailwind CSS and shadcn/ui). It needs Node.js and npm:

```bash
./scripts/build-dashboard.sh   # npm ci, then build into dashboard/dist
cargo build --release          # embeds the new files
```

Commit `dashboard/dist` with your change, so that `cargo build` keeps
working for everyone without Node. For live reloading while you work on the
front end, see [dashboard](dashboard.md).

## Running as a service (systemd)

In production, run `ariodb serve` as a dedicated, unprivileged user, with
its state directory private to that user, its config file owned by root,
and its secrets in an environment file only that user can read.

### 1. Create the user and directories

```bash
sudo useradd --system --home-dir /var/lib/ariodb --shell /usr/sbin/nologin ariodb
sudo install -d -o root -g ariodb -m 0750 /etc/ariodb
```

systemd creates the state directory, `/var/lib/ariodb`, from the unit
below, owned by `ariodb` with mode `0700`.

### 2. Write the config

Put the config at `/etc/ariodb/ariodb.toml`, owned by root and readable by
the `ariodb` group. The config is your policy, so the service should be
able to read it but not change it (unless you deliberately turn on
dashboard editing; see below). Use an absolute state directory:

```toml
[journal]
dir = "/var/lib/ariodb"
```

A relative `dir` is resolved against the working directory of whoever runs
ariodb, which is a common source of "where did my sessions go" surprises
when the service and an operator's shell disagree. The
[configuration reference](configuration.md) covers every section.

```bash
sudo install -o root -g ariodb -m 0640 ariodb.toml /etc/ariodb/ariodb.toml
```

### 3. Put secrets in an environment file

```bash
sudo install -o root -g ariodb -m 0640 /dev/null /etc/ariodb/ariodb.env
sudoedit /etc/ariodb/ariodb.env
```

```bash
# /etc/ariodb/ariodb.env: read by systemd and by the admin wrapper below.
# Every value here is an example: use your own.
ARIODB_DATABASE_URL='postgres://ariodb_gw:not-a-real-password@db.internal:5432/app'
ARIODB_JOURNAL_URL='postgres://ariodb_journal:not-a-real-password@db.internal:5432/app'
ARIODB_TOKEN_CODING_AGENT='agent-token-local-test-only'
# Optional: keep the secret store's key out of the state directory (and
# so out of its backups). Generate with: openssl rand -base64 32
# ARIODB_MASTER_KEY='...'
```

Generate real agent tokens with `openssl rand -hex 32`. Secrets can also
live in ariodb's encrypted secret store (`ariodb secret set <name>`), which
is in the state directory; see [configuration](configuration.md).

### 4. Install the unit

```ini
# /etc/systemd/system/ariodb.service
[Unit]
Description=ariodb safety proxy for AI agents
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ariodb
Group=ariodb
EnvironmentFile=/etc/ariodb/ariodb.env
ExecStart=/usr/local/bin/ariodb --config /etc/ariodb/ariodb.toml serve
WorkingDirectory=/var/lib/ariodb

# /var/lib/ariodb, created 0700 and owned by ariodb. ariodb warns at
# startup if its state directory is readable by other users.
StateDirectory=ariodb
StateDirectoryMode=0700
UMask=0077

# ariodb stops tunnels and plugins on SIGTERM before it exits.
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

# Hardening. ProtectSystem=strict makes /etc read-only to ariodb; if you
# set [dashboard] config_writes = true, add: ReadWritePaths=/etc/ariodb
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ariodb
journalctl -u ariodb -f
```

A healthy start logs lines such as:

```text
ariodb: agents can connect to postgres://<agent>@127.0.0.1:6543
ariodb: dashboard at https://ariodb.example.com
ariodb: journal is recording changes to /var/lib/ariodb/journal.jsonl
ariodb: reads yes; checked writes yes; undo yes
```

The last line is a summary of [`ariodb doctor`](cli.md), run once at
startup. Anything other than `yes` deserves a look before agents connect.

Notes on the unit:

- **No `ExecReload`.** ariodb watches its config file and reloads it within
  a couple of seconds of a change: agents, rules, approvers and limits
  apply to the next statement. Listen addresses, tunnels and plugins need a
  restart (`systemctl restart ariodb`). A config that fails to load is
  ignored and the previous one kept, with a message in the log.
- **Plugins and tunnels run as `ariodb`, under the same hardening.** A
  tunnel such as `cloud-sql-proxy` may need its own credentials file and a
  writable home; relax `ProtectHome` or point it at a path under
  `/var/lib/ariodb` if so.
- **Restarting drops agent connections.** Statements in flight roll back,
  and statements waiting for approval are refused. Agents should reconnect.

### 5. Run one-off commands as the service user

Commands such as `ariodb sessions`, `ariodb undo`, `ariodb approvals` and
`ariodb dashboard-password` read the same state directory and need the same
environment, so run them as `ariodb`. A small wrapper keeps that tidy:

```sh
#!/bin/sh
# /usr/local/sbin/ariodb-admin: run an ariodb command as the service runs it.
set -a
. /etc/ariodb/ariodb.env
set +a
cd /var/lib/ariodb || exit 1
exec /usr/local/bin/ariodb --config /etc/ariodb/ariodb.toml "$@"
```

```bash
sudo install -o root -g root -m 0755 ariodb-admin /usr/local/sbin/ariodb-admin
sudo -u ariodb /usr/local/sbin/ariodb-admin check
sudo -u ariodb /usr/local/sbin/ariodb-admin doctor
sudo -u ariodb /usr/local/sbin/ariodb-admin setup          # once; see below
read -rs PW && printf '%s\n' "$PW" | sudo -u ariodb /usr/local/sbin/ariodb-admin dashboard-password
```

`ariodb setup` changes table settings and creates a publication, which
needs a login that owns the protected tables, has `REPLICATION` and has
`CREATE` on the database. If your
journal role does not own them, run setup once with a table owner's URL in
`ARIODB_JOURNAL_URL` for that one command. The [quickstart](quickstart.md)
shows both roles, and [Postgres](postgres.md) explains the privileges.

Set the first dashboard password with `ariodb dashboard-password` before
you put the dashboard behind a reverse proxy: the dashboard lets any
request from the same machine set the first password, and behind a proxy
on the same host every request comes from the same machine.

## Running in a container

The repository does not ship a Dockerfile. The one below is **an example to
adapt**, not a supported image: it builds a release binary and runs it as
an unprivileged user with the state directory on a volume.

```dockerfile
# Example only: adapt before use. Not part of the ariodb repository.
FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/ariodb --shell /usr/sbin/nologin ariodb \
 && install -d -o ariodb -g ariodb -m 0700 /var/lib/ariodb
COPY --from=build /src/target/release/ariodb /usr/local/bin/ariodb
USER ariodb
WORKDIR /var/lib/ariodb
VOLUME ["/var/lib/ariodb"]
# Postgres proxy and dashboard; add ClickHouse ports if you use them.
EXPOSE 6543 8080
ENTRYPOINT ["/usr/local/bin/ariodb", "--config", "/etc/ariodb/ariodb.toml"]
CMD ["serve"]
```

Things to get right in a container:

- **Listen addresses.** The defaults (`127.0.0.1:6543` for the proxy,
  `127.0.0.1:8080` for the dashboard) are unreachable from outside the
  container. Set `[proxy] listen = "0.0.0.0:6543"` and
  `[dashboard] listen = "0.0.0.0:8080"`, and then turn on TLS for the proxy
  (`tls_cert`, `tls_key`, `require_tls = true`), because agents send their
  tokens as passwords. Put the dashboard behind HTTPS and set
  `public_url` to its `https://` address.
- **State directory on a volume.** `[journal] dir = "/var/lib/ariodb"`.
  The journal, the decisions log, pending approvals, dashboard users and
  the secret store live there; losing it loses undo history.
- **Config mounted read-only** at `/etc/ariodb/ariodb.toml`, and secrets
  passed as environment variables from your orchestrator's secret store.
  Set `ARIODB_MASTER_KEY` too if you use `ariodb secret`, so the key is not
  on the same volume as the secrets it protects.
- **One-off commands** run in the same container, so they see the same
  state: `docker exec -it ariodb ariodb --config /etc/ariodb/ariodb.toml sessions`.
- **Plugins and tunnels** must exist inside the image. Add Python, Node or
  `cloud-sql-proxy` to the runtime stage if your config starts them.
- **One replica.** ariodb keeps its state on local disk and reads one
  replication slot; do not run two copies against the same slot or state
  directory.

## Upgrading

ariodb is at version 0.x, so read the release notes for each upgrade
before you install it. The general procedure:

1. **Build the new binary** and keep the old one to hand.
2. **Back up the state directory**, without `master.key` (keep that
   separately, or use `ARIODB_MASTER_KEY`).
3. **Check the config with the new binary** before switching:
   `ariodb --config /etc/ariodb/ariodb.toml check`. A config the new
   version rejects is reported here rather than at startup.
4. **Install and restart:** `systemctl restart ariodb`. The replication slot
   holds changes while ariodb is down, so the journal catches up when it
   starts again.
5. **Run `ariodb doctor`** and look for the startup summary line in the log.

Keep downtime short. While ariodb is stopped, Postgres keeps WAL for the
replication slot, and a slot left unread for a long time can fill the
database's disk. `ariodb doctor` warns when the slot holds back more than
1 GiB. If you retire ariodb, drop the slot
(`SELECT pg_drop_replication_slot('ariodb')`).

After upgrading **Postgres** to 18, run `ariodb setup` again: Postgres 18
needs the publication to include generated columns. See
[compatibility](compatibility.md).

## Next

- [Quickstart](quickstart.md): a complete setup against a local Postgres.
- [Configuration](configuration.md): every section of `ariodb.toml`.
- [Postgres](postgres.md): roles, privileges and TLS for the database side.
- [Operations](operations.md): monitoring, backups and day-to-day running.
- [Security model](security-model.md): the deployment checklist.
