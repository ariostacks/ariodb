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
# Client containers reach ariodb on this machine as host.docker.internal.
# Docker Desktop resolves that name itself. On Linux a client shares the
# host's network instead, with the name pointing at 127.0.0.1, where ariodb
# listens: the host-gateway address reaches the host only on its Docker
# bridge, which listeners on 127.0.0.1 do not accept.
if [ "$(uname -s)" = Linux ]; then
  HOST_NET=(--network host --add-host=host.docker.internal:127.0.0.1)
else
  HOST_NET=(--add-host=host.docker.internal:host-gateway)
fi
# Whether something listens on a local port (bash's /dev/tcp, so no nc).
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
expect() { if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi; }
quiet() { if [ -z "$2" ]; then pass "$1"; else echo "$2"; fail "$1"; fi; } # quiet <description> <output>

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
admin "CREATE TABLE loads (id UInt32, user String, kind String) ENGINE = MergeTree ORDER BY id"
admin "CREATE TABLE typed (id UInt32, n Nullable(Int64), tags Array(String), m Map(String, UInt16), t Tuple(a UInt8, b String), lc LowCardinality(String), lcn LowCardinality(Nullable(String)), d Decimal(18, 4), ts DateTime64(3, 'UTC'), u UUID, fs FixedString(3), e Enum8('a' = 1, 'b' = 2), ip IPv6, ok Bool, nested Array(Array(Nullable(String)))) ENGINE = MergeTree ORDER BY id"
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

max_rows_per_write = 50

[agents.clickhouse]
access = "read_write"
tables = ["events", "loads", "typed"]

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

[[approvers]]
name = "ops"
type = "dashboard"

[[rules]]
name = "ask-dashboard"
condition = "sql.engine == 'clickhouse' && sql.statement.contains('ask-dashboard')"
verdict = "approve"
approve = ["ops"]
reason = "marked for a human"
EOF
export E2E_CH_PASSWORD=ch-local-test-only E2E_ANALYST_TOKEN=analyst-token-test-only
export E2E_LOADER_TOKEN=loader-token-test-only E2E_PGONLY_TOKEN=pgonly-token-test-only
CFG=(--config "$WORK/ariodb.toml")
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do port_open $PROXY_HTTP && break; sleep 0.2; done

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
expect "system.query_log is not" "may not use 'system.query_log'" "$(ch analyst $A "SELECT * FROM system.query_log")"
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
for _ in $(seq 1 50); do port_open $PROXY_NATIVE && break; sleep 0.2; done
cli() { # cli <agent> <token> <sql> [extra args]
  local agent=$1 token=$2 sql=$3; shift 3
  docker run "${HOST_NET[@]}" --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE \
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
expect "client settings cannot lift read-only mode" "1001" "$(cli analyst $A "SELECT count() FROM events" --readonly 0)"
expect "the connection keeps working after a refusal" "1001" "$(docker run "${HOST_NET[@]}" --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE --user analyst --password $A --multiquery --query "SELECT * FROM secrets; SELECT count() FROM events" 2>&1 || true; docker run "${HOST_NET[@]}" --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE --user analyst --password $A --query "SELECT count() FROM events" 2>&1)"
expect "uncompressed clients work too" "1001" "$(cli analyst $A "SELECT count() FROM events" --compression 0)"

echo "native inserts (clickhouse-client)"
cli_in() { # cli_in <agent> <token> <sql> <stdin> [extra args]
  local agent=$1 token=$2 sql=$3 input=$4; shift 4
  printf '%s' "$input" | docker run "${HOST_NET[@]}" --rm -i "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE \
    --user "$agent" --password "$token" "$@" --query "$sql" 2>&1 || true
}
csv() { python3 -c 'import sys; n, kind = int(sys.argv[1]), sys.argv[2]; print("\n".join(f"{i},user{i % 10},{kind}" for i in range(n)))' "$@"; }
landed() { admin "SELECT count() FROM loads WHERE kind = '$1'"; }
# The newest decision for statements containing the text: outcome and rows.
decided() {
  python3 - "$WORK/state/ariodb.db" "$1" <<'PY2'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = db.execute("SELECT outcome, rows FROM decisions WHERE sql LIKE ? ORDER BY id DESC LIMIT 1", (f"%{sys.argv[2]}%",)).fetchone()
print(row)
PY2
}
TYPED_ROW="(1, NULL, ['a', 'b c'], {'k': 7, 'l': 8}, (3, 'x'), 'low', NULL, 12.5, '2026-10-09 12:00:00.123', '00000000-0000-0000-0000-00000000000a', 'abc', 'b', '::1', true, [['p', NULL], []]), (2, -5, [], {}, (4, ''), 'low', 'card', -1.25, '2026-10-09 12:00:01', '00000000-0000-0000-0000-00000000000b', 'xyz', 'a', '2001:db8::1', false, [[], [NULL]])"
for mode in lz4 none zstd; do
  case $mode in
    lz4) ARGS=() ;;
    none) ARGS=(--compression 0) ;;
    zstd) ARGS=(--network_compression_method zstd) ;;
  esac
  quiet "INSERT ... VALUES lands ($mode)" "$(cli loader $L "INSERT INTO loads VALUES (1, 'user1', 'values-$mode')" ${ARGS[@]+"${ARGS[@]}"})"
  expect "  one row landed" "1" "$(landed values-$mode)"
  quiet "INSERT ... FORMAT CSV from stdin lands ($mode)" "$(cli_in loader $L "INSERT INTO loads FORMAT CSV" "$(csv 40 csv-$mode)" ${ARGS[@]+"${ARGS[@]}"})"
  expect "  all 40 rows landed" "40" "$(landed csv-$mode)"
  expect "  the decision records 40 rows" "('allowed', 40)" "$(decided "FORMAT CSV")"
  expect "an insert over the limit is refused ($mode)" "the limit is 50" "$(cli_in loader $L "INSERT INTO loads FORMAT CSV" "$(csv 75 big-$mode)" ${ARGS[@]+"${ARGS[@]}"})"
  expect "  and no rows landed" "0" "$(landed big-$mode)"
  expect "  the decision records the rows it was sent" "('rolled_back', 75)" "$(decided "FORMAT CSV")"
  expect "an insert over the limit in small blocks is refused ($mode)" "the limit is 50" \
    "$(cli_in loader $L "INSERT INTO loads FORMAT CSV" "$(csv 75 blocks-$mode)" --max_insert_block_size 20 ${ARGS[@]+"${ARGS[@]}"})"
  expect "  and none of its blocks landed" "0" "$(landed blocks-$mode)"
  expect "  the decision records the block it stopped at" "('rolled_back', 60)" "$(decided "FORMAT CSV")"
  quiet "every column type in a test table is read exactly ($mode)" "$(cli loader $L "INSERT INTO typed VALUES $TYPED_ROW" ${ARGS[@]+"${ARGS[@]}"})"
  expect "  and both rows landed intact" "2	[['p',NULL],[]]	2001:db8::1	card" \
    "$(admin "SELECT count(), anyIf(nested, id = 1), toString(anyIf(ip, id = 2)), anyIf(lcn, id = 2) FROM typed FORMAT TSV")"
  admin "TRUNCATE TABLE typed"
done
expect "the session carries on after a native insert" "42" "$(docker run "${HOST_NET[@]}" --rm "$IMAGE" clickhouse-client --host host.docker.internal --port $PROXY_NATIVE --user loader --password $L --multiquery --query "INSERT INTO loads VALUES (2, 'user2', 'values-lz4'); SELECT count() FROM loads WHERE kind LIKE '%-lz4'" 2>&1 || true)"
expect "a read-only agent cannot insert over native" "is read only" "$(cli analyst $A "INSERT INTO events VALUES (6000, 'x', 'y')")"
expect "an insert into another table is refused over native" "may not use table 'secrets'" "$(cli loader $L "INSERT INTO secrets VALUES ('planted')")"
expect "INSERT ... SELECT is refused over native" "only INSERT ... VALUES and INSERT ... FORMAT" "$(cli loader $L "INSERT INTO loads SELECT number, 'x', 'select' FROM numbers(1000)")"
expect "  and nothing landed" "0" "$(landed select)"
expect "external tables are still refused" "external tables are not supported" "$(cli_in analyst $A "SELECT count() FROM events WHERE id IN ext" "1" --external --file=- --name=ext --structure='id UInt32')"
# clickhouse-client keeps rows out of the query text, but a client may send
# them there: ClickHouse inserts whatever follows the first newline after
# FORMAT, blank lines and Unicode spaces included, before any data block.
raw_native() { # raw_native <agent> <token> <sql>: send the query text as given
  python3 - "$PROXY_NATIVE" "$1" "$2" "$3" <<'PY3'
import socket, sys, time
port, user, password, sql = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
def varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7f, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)
def s(x):
    x = x.encode()
    return varint(len(x)) + x
REV = 54429  # settings as strings; no addendum
sock = socket.create_connection(("127.0.0.1", port), timeout=3)
sock.sendall(varint(0) + s("raw") + varint(24) + varint(10) + varint(REV) + s("default") + s(user) + s(password))
time.sleep(0.3)
sock.recv(65536)  # the server's Hello
client_info = bytes([1]) + s("") + s("") + s("0.0.0.0:0") + bytes([1]) + s("") + s("") + s("raw")
client_info += varint(24) + varint(10) + varint(REV) + s("") + varint(0)
query = varint(1) + s("") + client_info + s("") + varint(2) + varint(0) + s(sql)
empty = varint(2) + s("") + bytes([1, 0, 2, 0xff, 0xff, 0xff, 0xff, 0]) + varint(0) + varint(0)
sock.sendall(query + empty)
time.sleep(0.5)
try:
    sock.sendall(empty)
except OSError:
    pass
reply = b""
try:
    while chunk := sock.recv(65536):
        reply += chunk
except OSError:
    pass
print(reply.decode("utf-8", "replace"))
PY3
}
blank() { admin "SELECT count() FROM loads WHERE kind = ''"; }
expect "rows in the query text after FORMAT are refused (blank lines)" "only INSERT ... VALUES and INSERT ... FORMAT" \
  "$(raw_native loader $L "$(printf 'INSERT INTO loads (user) FORMAT TSV\n'; python3 -c 'print("\n" * 80 + " ", end="")')")" # $() drops trailing newlines
expect "  and nothing landed" "0" "$(blank)"
expect "rows in the query text after FORMAT are refused (Unicode spaces)" "only INSERT ... VALUES and INSERT ... FORMAT" \
  "$(raw_native loader $L "$(printf 'INSERT INTO loads (user) FORMAT TSV\n'; python3 -c 'print("\u00a0\n" * 80, end="")')")"
expect "  and nothing landed" "0" "$(blank)"
expect "native insert decisions are logged" "decisions log intact" "$($BIN "${CFG[@]}" audit)"

echo "approvals"
wait_for_pending() {
  for _ in $(seq 1 100); do
    id=$($BIN "${CFG[@]}" approvals | awk '/ pending /{print $1; exit}')
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.2
  done
  fail "no pending approval appeared"
}
# Who decided the approvals of the newest decision with this outcome whose
# statement has the text.
decided_by() { # decided_by <outcome> <text>
  python3 -I - "$WORK/state/ariodb.db" "$1" "$2" <<'PY'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = db.execute("SELECT decided_by FROM decisions WHERE outcome = ? AND instr(sql, ?) > 0 ORDER BY id DESC LIMIT 1", sys.argv[2:]).fetchone()
print(row[0] if row else "no such decision")
PY
}
OUT="$WORK/held.out"
(ch analyst $A "SELECT 'ask-dashboard-http', count() FROM events" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" approve "$ID" >/dev/null; wait $BG
expect "a held HTTP query runs once approved" "ask-dashboard-http" "$(cat "$OUT")"
expect "  and its decision names who approved it" '["cli:' "$(decided_by allowed "'ask-dashboard-http'")"
(cli analyst $A "SELECT 'ask-dashboard-native', count() FROM events" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" approve "$ID" >/dev/null; wait $BG
expect "a held native query runs once approved" "ask-dashboard-native" "$(cat "$OUT")"
expect "  and its decision names who approved it" '["cli:' "$(decided_by allowed "'ask-dashboard-native'")"

echo "connection limits"
# Room for two connections, for a moment: the config reloads while ariodb runs.
cp "$WORK/ariodb.toml" "$WORK/ariodb.toml.orig"
reload_with() { # reload_with <config file>
  local reloads; reloads=$(grep -c "reloaded" "$WORK/serve.log" || true)
  cp "$1" "$WORK/ariodb.toml"
  for _ in $(seq 1 50); do
    [ "$(grep -c "reloaded" "$WORK/serve.log" || true)" -gt "$reloads" ] && return 0
    sleep 0.2
  done
  fail "the config was not reloaded"
}
{ cat "$WORK/ariodb.toml.orig"; printf '\n[limits]\nmax_connections = 2\n'; } > "$WORK/limited.toml"
reload_with "$WORK/limited.toml"
OUT=$(python3 -I scripts/conn_limits.py http-full $PROXY_HTTP 2 2>&1 || true)
expect "an HTTP request over max_connections gets 503" "HTTP/1.1 503" "$OUT"
expect "  with a ClickHouse exception its clients understand" "Code: 202. DB::Exception: ariodb: too many connections" "$OUT"
reload_with "$WORK/ariodb.toml.orig"
expect "and requests are served again once the limit is lifted" "1001" "$(ch analyst $A "SELECT count() FROM events")"

echo "recorded decisions as tests"
$BIN "${CFG[@]}" export-fixtures --out "$WORK/recorded" >/dev/null
expect "ClickHouse decisions export with their engine" '"engine": "clickhouse"' "$(cat "$WORK/recorded/recorded.json")"
if $BIN "${CFG[@]}" test "$WORK/recorded" >"$WORK/replay.out"; then
  pass "ClickHouse decisions replay with no drift"
else
  grep DRIFT "$WORK/replay.out" | head
  python3 -c 'import json,sys; [print(f["name"], "|", f["action"]["sql"]["statement"]) for f in json.load(open(sys.argv[1]))]' "$WORK/recorded/recorded.json"
  fail "ClickHouse decisions drifted"
fi
expect "explain judges ClickHouse statements" "deny" "$($BIN "${CFG[@]}" explain --agent analyst --engine clickhouse "SELECT * FROM url('http://x', CSV, 'a String')")"

echo "TLS on the ClickHouse listeners"
kill $SERVE_PID 2>/dev/null || true; wait $SERVE_PID 2>/dev/null || true
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal" \
  -keyout "$WORK/ch.key" -out "$WORK/ch.crt" >/dev/null 2>&1
python3 - "$WORK/ariodb.toml" "$WORK/ch.crt" "$WORK/ch.key" <<'PY'
import sys
p, crt, key = sys.argv[1:]
s = open(p).read()
s = s.replace('password_env = "E2E_CH_PASSWORD"\n', f'password_env = "E2E_CH_PASSWORD"\ntls_cert = "{crt}"\ntls_key = "{key}"\n', 1)
open(p, "w").write(s)
PY
$BIN "${CFG[@]}" serve >"$WORK/serve-tls.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do port_open $PROXY_NATIVE && break; sleep 0.2; done
expect "HTTPS reads through ariodb" "1001" "$(curl -sk -u analyst:$A "https://127.0.0.1:$PROXY_HTTP/" --data-binary "SELECT count() FROM events")"
expect "policy still applies over HTTPS" "may not use table 'secrets'" "$(curl -sk -u analyst:$A "https://127.0.0.1:$PROXY_HTTP/" --data-binary "SELECT * FROM secrets")"
expect "plain HTTP is not served once TLS is on" "000" "$(curl -s -o /dev/null -w '%{http_code}' -m 5 -u analyst:$A "http://127.0.0.1:$PROXY_HTTP/" --data-binary "SELECT 1" || true)"
expect "clickhouse-client --secure reads through ariodb" "1001" "$(cli analyst $A "SELECT count() FROM events" --secure --accept-invalid-certificate)"
expect "policy still applies over native TLS" "may not use table 'secrets'" "$(cli analyst $A "SELECT * FROM secrets" --secure --accept-invalid-certificate)"
expect "a plain native client is not served once TLS is on" "Exception" "$(cli analyst $A "SELECT 1" --connect_timeout 5 --receive_timeout 5)"
expect "a silent client does not block others" "1001" "$( ( (exec 3<>"/dev/tcp/127.0.0.1/$PROXY_HTTP"; sleep 8) >/dev/null 2>&1 &) ; curl -sk -m 5 -u analyst:$A "https://127.0.0.1:$PROXY_HTTP/" --data-binary "SELECT count() FROM events")"

echo "all ClickHouse checks passed"
