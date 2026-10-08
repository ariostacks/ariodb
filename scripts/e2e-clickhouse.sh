#!/usr/bin/env bash
# End-to-end test for ClickHouse: a real ClickHouse server in Docker, ariodb
# in front of it over HTTP and the native protocol. All passwords here are
# throwaway test values.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
CH=ariodb-e2e-ch
IMAGE=${CH_IMAGE:-clickhouse/clickhouse-server:24.10-alpine}
CH_HTTP=18123
CH_NATIVE=19000
PROXY_HTTP=8125
PROXY_NATIVE=9011
WORK=$(mktemp -d)
SERVE_PID=""
trap 'kill $SERVE_PID 2>/dev/null || true; docker rm -f $CH >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

pass() { printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
expect() { if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi; }

echo "starting ClickHouse"
docker rm -f $CH >/dev/null 2>&1 || true
docker run -d --name $CH -e CLICKHOUSE_USER=ariodb -e CLICKHOUSE_PASSWORD=ch-local-test-only \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -p 127.0.0.1:$CH_HTTP:8123 -p 127.0.0.1:$CH_NATIVE:9000 "$IMAGE" >/dev/null
until curl -s "http://127.0.0.1:$CH_HTTP/ping" | grep -q Ok; do sleep 0.5; done
admin() { curl -s -u ariodb:ch-local-test-only "http://127.0.0.1:$CH_HTTP/" --data-binary "$1"; }
admin "CREATE TABLE events (id UInt32, user String, kind String) ENGINE = MergeTree ORDER BY id"
admin "CREATE TABLE secrets (note String) ENGINE = MergeTree ORDER BY note"
admin "INSERT INTO events SELECT number, concat('user', toString(number % 10)), 'view' FROM numbers(1000)"
admin "INSERT INTO secrets VALUES ('not-a-real-secret')"

cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://unused@127.0.0.1:1/unused"

[journal]
enabled = false
dir = "$WORK/state"

[dashboard]
listen = ""

[clickhouse]
http_listen = "127.0.0.1:$PROXY_HTTP"
http_url = "http://127.0.0.1:$CH_HTTP"
native_listen = "127.0.0.1:$PROXY_NATIVE"
native_addr = "127.0.0.1:$CH_NATIVE"
user = "ariodb"
password_env = "E2E_CH_PASSWORD"

[[agents]]
name = "analyst"
access = "read_only"
tables = ["unused"]
token_env = "E2E_ANALYST_TOKEN"

[agents.clickhouse]
access = "read_only"
tables = ["events"]

[[agents]]
name = "loader"
access = "read_only"
tables = ["unused"]
token_env = "E2E_LOADER_TOKEN"

[agents.clickhouse]
access = "read_write"
tables = ["events"]

[[agents]]
name = "pg-only"
access = "read_only"
tables = ["unused"]
token_env = "E2E_PGONLY_TOKEN"

[[rules]]
name = "no-big-scans-of-users"
condition = "sql.engine == 'clickhouse' && sql.statement.contains('user7')"
verdict = "deny"
reason = "user7 is under a data hold"
EOF
export E2E_CH_PASSWORD=ch-local-test-only E2E_ANALYST_TOKEN=analyst-token-test-only
export E2E_LOADER_TOKEN=loader-token-test-only E2E_PGONLY_TOKEN=pgonly-token-test-only
CFG=(--config "$WORK/ariodb.toml")
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do nc -z 127.0.0.1 $PROXY_HTTP 2>/dev/null && break; sleep 0.2; done

ch() { # ch <agent> <token> <sql> [data]
  if [ $# -ge 4 ]; then
    curl -s -u "$1:$2" "http://127.0.0.1:$PROXY_HTTP/?query=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$3")" --data-binary "$4"
  else
    curl -s -u "$1:$2" "http://127.0.0.1:$PROXY_HTTP/" --data-binary "$3"
  fi
}
A=$E2E_ANALYST_TOKEN; L=$E2E_LOADER_TOKEN

echo "HTTP interface"
expect "agent reads through ariodb" "1000" "$(ch analyst $A "SELECT count() FROM events")"
expect "wrong token refused" "wrong token" "$(ch analyst nope "SELECT 1")"
expect "agent without ClickHouse access refused" "no ClickHouse access" "$(ch pg-only $E2E_PGONLY_TOKEN "SELECT 1")"
expect "other tables refused" "may not use table 'secrets'" "$(ch analyst $A "SELECT * FROM secrets")"
expect "read-only agent cannot insert" "is read only" "$(ch analyst $A "INSERT INTO events VALUES (5000, 'x', 'y')")"
expect "drop refused" "destructive" "$(ch loader $L "DROP TABLE events")"
expect "mutations refused" "cannot be undone" "$(ch loader $L "ALTER TABLE events DELETE WHERE id = 1")"
expect "url() table function refused" "reaches outside the server" "$(ch analyst $A "SELECT * FROM url('http://169.254.169.254/latest', CSV, 'a String')")"
expect "file() table function refused" "reaches outside the server" "$(ch analyst $A "SELECT * FROM file('/etc/passwd', LineAsString)")"
expect "two statements refused" "one statement per request" "$(ch analyst $A "SELECT 1; DROP TABLE events")"
expect "readonly cannot be switched off" "readonly or allow_ddl" "$(ch analyst $A "SELECT count() FROM events SETTINGS readonly = 0")"
expect "client settings cannot switch off read-only" "1000" "$(curl -s -u analyst:$A "http://127.0.0.1:$PROXY_HTTP/?readonly=0&allow_ddl=1" --data-binary "SELECT count() FROM events")"
expect "rules apply to ClickHouse" "data hold" "$(ch analyst $A "SELECT count() FROM events WHERE user = 'user7'")"
expect "schema discovery allowed" "events" "$(ch analyst $A "SELECT name FROM system.tables WHERE database = 'default'")"
expect "system.query_log is not" "may not use table 'system.query_log'" "$(ch analyst $A "SELECT * FROM system.query_log")"
expect "loader inserts with data in the body" "" "$(ch loader $L "INSERT INTO events FORMAT CSV" "5001,loaded,import")"
expect "the insert landed" "1" "$(admin "SELECT count() FROM events WHERE id = 5001")"
expect "query parameters pass through" "user3" "$(curl -s -u analyst:$A "http://127.0.0.1:$PROXY_HTTP/?param_id=3" --data-binary "SELECT user FROM events WHERE id = {id:UInt32}")"
expect "decisions are logged" "decisions log intact" "$($BIN "${CFG[@]}" audit)"

echo "all ClickHouse checks passed"
