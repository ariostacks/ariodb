#!/usr/bin/env bash
# Postgres-compatible databases that are not Postgres underneath:
# YugabyteDB and CockroachDB. Neither can measure a write the way ariodb
# does by default, so this checks that writes are refused there, that
# `write_check = "reported"` allows them with row limits still applied, and
# that `ariodb doctor` says so. Postgres itself and images built on it
# (TimescaleDB, Supabase) run the full suite instead:
#   PG_IMAGE=timescale/timescaledb:latest-pg17 ./scripts/e2e.sh
#
# Run: ./scripts/e2e-compat.sh yugabyte|cockroach
# Needs Docker and a built ariodb (cargo build). All values are throwaway.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
ENGINE=${1:?usage: e2e-compat.sh yugabyte|cockroach}
OFF=${E2E_OFFSET:-0}
NAME=ariodb-compat-$ENGINE${E2E_NAME:+-$E2E_NAME}
PORT=$((55601 + OFF))
PROXY=$((6651 + OFF))
CLIENT=${CLIENT_IMAGE:-postgres:16}
WORK=$(mktemp -d)
SERVE_PID=""
trap 'kill $SERVE_PID 2>/dev/null || true; docker rm -f $NAME >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

pass() { printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
expect() { if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi; }

case $ENGINE in
  yugabyte)
    IMAGE=${YB_IMAGE:-yugabytedb/yugabyte:latest}
    DB=yugabyte
    docker run -d --name $NAME -p 127.0.0.1:$PORT:5433 "$IMAGE" bin/yugabyted start --background=false >/dev/null
    sql() { docker exec $NAME bash -c "ysqlsh -h \$(hostname) -tA -c \"$1\""; }
    ;;
  cockroach)
    IMAGE=${CRDB_IMAGE:-cockroachdb/cockroach:latest-v25.2}
    DB=defaultdb
    docker run -d --name $NAME -p 127.0.0.1:$PORT:26257 "$IMAGE" start-single-node --insecure >/dev/null
    sql() { docker exec $NAME cockroach sql --insecure --format=csv -e "$1" | tail -n +2; }
    ;;
  *) fail "unknown engine '$ENGINE'" ;;
esac

echo "starting $ENGINE"
for _ in $(seq 1 120); do sql "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
sql "SELECT 1" >/dev/null 2>&1 || fail "$ENGINE did not start"
echo "testing $(sql "SELECT version()" | head -1)"
sql "CREATE TABLE orders (id int PRIMARY KEY, status text NOT NULL)" >/dev/null
sql "INSERT INTO orders SELECT g, 'paid' FROM generate_series(1, 100) g" >/dev/null
sql "CREATE TABLE secrets (id int PRIMARY KEY, note text)" >/dev/null
sql "CREATE USER ariodb_gw" >/dev/null
sql "GRANT SELECT, INSERT, UPDATE, DELETE ON orders, secrets TO ariodb_gw" >/dev/null

write_config() { # write_config <write_check>
  cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://ariodb_gw@127.0.0.1:$PORT/$DB"
write_check = "$1"

[proxy]
listen = "127.0.0.1:$PROXY"

[journal]
enabled = false
dir = "$WORK/state"

[dashboard]
listen = ""

[[agents]]
name = "coder"
access = "read_write"
tables = ["orders"]
token_env = "COMPAT_TOKEN"
max_rows_per_write = 50

[[agents]]
name = "reader"
access = "read_only"
tables = ["orders"]
token_env = "COMPAT_TOKEN"
EOF
}
export COMPAT_TOKEN=compat-token-test-only
CFG=(--config "$WORK/ariodb.toml")
start() {
  kill $SERVE_PID 2>/dev/null || true; wait $SERVE_PID 2>/dev/null || true
  $BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 1 100); do nc -z 127.0.0.1 $PROXY 2>/dev/null && return 0; sleep 0.2; done
  cat "$WORK/serve.log"; fail "ariodb did not start"
}
agent() {
  docker run --rm -e PGPASSWORD=$COMPAT_TOKEN $CLIENT \
    psql "host=host.docker.internal port=$PROXY user=$1 dbname=$DB sslmode=disable" -c "$2" 2>&1 || true
}

echo "default write check"
write_config measured
DOC=$($BIN "${CFG[@]}" doctor 2>&1 || true)
expect "doctor: reads are forced read-only" "yes  reads, forced read-only" "$DOC"
expect "doctor: writes cannot be measured here" "does not count changes to its tables" "$DOC"
expect "doctor: and points to the weaker check" 'write_check = "reported"' "$DOC"
start
expect "agents connect and read" "100" "$(agent reader "SELECT count(*) FROM orders")"
expect "other tables refused" "may not use table 'secrets'" "$(agent reader "SELECT * FROM secrets")"
expect "a write it cannot measure is rolled back" "ariodb measured 0" "$(agent coder "UPDATE orders SET status = 'x' WHERE id < 4")"
expect "so nothing changed" "0" "$(sql "SELECT count(*) FROM orders WHERE status = 'x'")"

echo "write_check = \"reported\""
write_config reported
DOC=$($BIN "${CFG[@]}" doctor 2>&1 || true)
expect "doctor: writes are allowed with the weaker check" "yes  writes, checked before commit" "$DOC"
expect "doctor: and says what it cannot see" "triggers, cascades and functions are not seen" "$DOC"
start
expect "a small write commits" "UPDATE 3" "$(agent coder "UPDATE orders SET status = 'x' WHERE id < 4")"
expect "and landed" "3" "$(sql "SELECT count(*) FROM orders WHERE status = 'x'")"
expect "a write over the row limit is rolled back" "would change 100 rows (as counted by the database); the limit is 50" "$(agent coder "UPDATE orders SET status = 'y' WHERE id > 0")"
expect "so nothing changed" "0" "$(sql "SELECT count(*) FROM orders WHERE status = 'y'")"
expect "read-only agents still cannot write" "is read only" "$(agent reader "UPDATE orders SET status = 'z' WHERE id = 1")"
expect "reads still work" "97" "$(agent reader "SELECT count(*) FROM orders WHERE status = 'paid'")"
expect "the startup log says what works" "checked writes yes" "$(cat "$WORK/serve.log")"

echo "all $ENGINE checks passed"
