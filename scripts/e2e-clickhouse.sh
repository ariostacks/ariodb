#!/usr/bin/env bash
# End-to-end test for ClickHouse: a real ClickHouse server in Docker, ariodb
# in front of it over HTTP and the native protocol. All passwords here are
# throwaway test values.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
OFF=${E2E_OFFSET:-0}
CH=ariodb-e2e-ch${E2E_NAME:+-$E2E_NAME}
IMAGE=${CH_IMAGE:-clickhouse/clickhouse-server:24.10-alpine}
CH_HTTP=$((18123 + OFF))
CH_NATIVE=$((19000 + OFF))
PROXY_HTTP=$((8125 + OFF))
PROXY_NATIVE=$((9011 + OFF))
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
# The image may start a temporary server for first-run setup, then restart.
# Wait until the server answers queries several times in a row.
ok=0
for _ in $(seq 1 240); do
  if curl -s -u ariodb:ch-local-test-only "http://127.0.0.1:$CH_HTTP/" --data-binary "SELECT 1" 2>/dev/null | grep -q '^1$'; then
    ok=$((ok + 1)); [ $ok -ge 5 ] && break
  else
    ok=0
  fi
  sleep 0.5
done
[ $ok -ge 5 ] || fail "ClickHouse did not become ready"
admin() { curl -s -u ariodb:ch-local-test-only "http://127.0.0.1:$CH_HTTP/" --data-binary "$1"; }
admin "CREATE TABLE events (id UInt32, user String, kind String) ENGINE = MergeTree ORDER BY id"
admin "CREATE TABLE secrets (note String) ENGINE = MergeTree ORDER BY note"
admin "INSERT INTO events SELECT number, concat('user', toString(number % 10)), 'view' FROM numbers(1000)"
admin "INSERT INTO secrets VALUES ('not-a-real-secret')"
admin "CREATE DATABASE hidden"
admin "CREATE TABLE hidden.events (note String) ENGINE = MergeTree ORDER BY note"
admin "INSERT INTO hidden.events VALUES ('hidden-not-a-real-secret')"

cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://unused@127.0.0.1:1/unused"

[journal]
enabled = false
dir = "$WORK/state"

[dashboard]
listen = ""

[proxy]
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
expect "comma joins are checked" "may not use table 'secrets'" "$(ch analyst $A "SELECT * FROM events, secrets")"
expect "IN <table> is checked" "may not use table 'secrets'" "$(ch analyst $A "SELECT count() FROM events WHERE user IN secrets")"
expect "INSERT with a column list is checked" "may not use table 'secrets'" "$(ch loader $L "INSERT INTO secrets (note) VALUES ('planted')")"
expect "merge() refused" "allow-list does not see" "$(ch analyst $A "SELECT * FROM merge('default', '^secrets\$')")"
expect "another database's tables are not the allowed ones" "may not use table 'hidden.events'" "$(curl -s -u analyst:$A "http://127.0.0.1:$PROXY_HTTP/?database=hidden" --data-binary "SELECT * FROM events")"
expect "loader inserts with data in the body" "" "$(ch loader $L "INSERT INTO events FORMAT CSV" "5001,loaded,import")"
expect "the insert landed" "1" "$(admin "SELECT count() FROM events WHERE id = 5001")"
expect "query parameters pass through" "user3" "$(curl -s -u analyst:$A "http://127.0.0.1:$PROXY_HTTP/?param_id=3" --data-binary "SELECT user FROM events WHERE id = {id:UInt32}")"
expect "decisions are logged" "decisions log intact" "$($BIN "${CFG[@]}" audit)"

echo "native protocol (clickhouse-client)"
for _ in $(seq 1 50); do nc -z 127.0.0.1 $PROXY_NATIVE 2>/dev/null && break; sleep 0.2; done
cli() { # cli <agent> <token> <sql> [extra args]
  local agent=$1 token=$2 sql=$3; shift 3
  docker run --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE \
    --user "$agent" --password "$token" "$@" --query "$sql" 2>&1 || true
}
expect "clickhouse-client reads through ariodb" "1001" "$(cli analyst $A "SELECT count() FROM events")"
expect "several result rows stream back" "user9" "$(cli analyst $A "SELECT DISTINCT user FROM events ORDER BY user")"
expect "wrong token refused" "wrong token" "$(cli analyst nope "SELECT 1")"
expect "other tables refused" "may not use table 'secrets'" "$(cli analyst $A "SELECT * FROM secrets")"
expect "comma joins are checked over native" "may not use table 'secrets'" "$(cli analyst $A "SELECT * FROM events, secrets")"
expect "the login database scopes table names" "may not use table 'hidden.events'" "$(cli analyst $A "SELECT * FROM events" --database hidden)"
expect "url() refused over native too" "reaches outside the server" "$(cli analyst $A "SELECT * FROM url('http://169.254.169.254/x', CSV, 'a String')")"
expect "rules apply over native" "data hold" "$(cli analyst $A "SELECT count() FROM events WHERE user = 'user7'")"
expect "native inserts refused with a pointer to HTTP" "use ariodb's ClickHouse HTTP interface" "$(cli loader $L "INSERT INTO events VALUES (6000, 'x', 'y')")"
expect "client settings cannot lift read-only mode" "1001" "$(cli analyst $A "SELECT count() FROM events" --readonly 0)"
expect "the connection keeps working after a refusal" "1001" "$(docker run --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE --user analyst --password $A --multiquery --query "SELECT * FROM secrets; SELECT count() FROM events" 2>&1 || true; docker run --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE --user analyst --password $A --query "SELECT count() FROM events" 2>&1)"
expect "uncompressed clients work too" "1001" "$(cli analyst $A "SELECT count() FROM events" --compression 0)"

echo "all ClickHouse checks passed"
