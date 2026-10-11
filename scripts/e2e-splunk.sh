#!/usr/bin/env bash
# End-to-end test of the Splunk exporter: a real Postgres in Docker, ariodb
# in front of it, and a local stand-in for Splunk's HTTP Event Collector
# (scripts/hec_standin.py), which follows Splunk's documented API and
# status codes and records what it receives. The official Splunk image is
# not used: starting it means accepting Splunk's licence.
#
# Checks that allowed, refused, approved and rolled-back statements arrive
# once and in order; that an outage (503s, then the collector down) loses
# and duplicates nothing; that a restart of ariodb resumes from its cursor;
# that a bad token is reported clearly and drops nothing; indexer
# acknowledgement; approval and undo events; TLS verification; and that no
# token ever appears in ariodb's output.
#
# Needs Docker, python3, openssl and a built ariodb (cargo build). All
# passwords and tokens here are throwaway test values.
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
# Parallel runs set E2E_OFFSET and E2E_NAME so ports and container names
# do not collide.
OFF=${E2E_OFFSET:-0}
PG=ariodb-e2e-spl-pg${E2E_NAME:+-$E2E_NAME}
CLIENT=${CLIENT_IMAGE:-postgres:16}
PORT=$((38000 + OFF))
PROXY=$((38001 + OFF))
DASH=$((38002 + OFF))
HEC=$((39700 + OFF))
HEC_TLS=$((39701 + OFF))
WORK=$(mktemp -d)
SERVE_PID=""
HEC_PID=""
TLS_PID=""
cleanup() {
  for pid in "$SERVE_PID" "$HEC_PID" "$TLS_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  pkill -f "$WORK/" 2>/dev/null || true
  docker rm -f "$PG" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() {
  printf '  \033[31mFAIL\033[0m %s\n' "$1"
  for f in "$WORK"/serve*.log "$WORK"/hec*.log; do
    [ -f "$f" ] && { echo "--- $f"; tail -20 "$f"; }
  done
  exit 1
}
# Client containers reach ariodb on this machine as host.docker.internal
# (see e2e-plugins.sh for why Linux shares the host's network).
if [ "$(uname -s)" = Linux ]; then
  HOST_NET=(--network host --add-host=host.docker.internal:127.0.0.1)
else
  HOST_NET=(--add-host=host.docker.internal:host-gateway)
fi
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
expect() { # expect <description> <needle> <output>
  if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi
}
# wait_for <seconds> <description> <command...>
wait_for() {
  local limit=$1 what=$2; shift 2
  for _ in $(seq 1 $((limit * 5))); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  fail "$what"
}
admin() { docker exec -i -e PGPASSWORD=local-test-only-pw $PG psql -q -v ON_ERROR_STOP=1 -U postgres -d app "$@"; }
# Run SQL through the proxy as the agent. Prints psql output, never fails.
agent() {
  docker run "${HOST_NET[@]}" --rm -e PGPASSWORD="$T" $CLIENT \
    psql "host=host.docker.internal port=$PROXY user=coding-agent dbname=app sslmode=disable" -c "$1" 2>&1 || true
}
start_serve() { # start_serve <log name>
  $BIN "${CFG[@]}" serve >"$WORK/$1" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 1 100); do
    port_open $PROXY && return 0
    kill -0 "$SERVE_PID" 2>/dev/null || { cat "$WORK/$1"; fail "ariodb exited"; }
    sleep 0.2
  done
  fail "ariodb did not start"
}
stop_serve() {
  kill "$SERVE_PID"
  wait "$SERVE_PID" 2>/dev/null || true
  SERVE_PID=""
}
start_hec() {
  python3 -I scripts/hec_standin.py $HEC "$WORK/hec" >>"$WORK/hec.log" 2>&1 &
  HEC_PID=$!
  wait_for 10 "the HEC stand-in starts" port_open $HEC
}
stop_hec() {
  kill "$HEC_PID"
  wait "$HEC_PID" 2>/dev/null || true
  HEC_PID=""
}
hec_mode() { printf '%s\n' "$1" > "$WORK/hec/mode"; }
# Swap in a config (a fresh file, so its modification time changes) and
# wait until ariodb says it reloaded it.
reload() { # reload <log name> <python expression on the config text t>
  local before
  before=$(grep -c "ariodb: reloaded" "$WORK/$1" || true)
  python3 -I -c "import sys; t=open(sys.argv[1]).read(); open(sys.argv[1]+'.new','w').write($2)" "$WORK/ariodb.toml"
  mv "$WORK/ariodb.toml.new" "$WORK/ariodb.toml"
  reloaded() { [ "$(grep -c "ariodb: reloaded" "$WORK/$1" || true)" -gt "$before" ]; }
  wait_for 20 "ariodb reloads its config" reloaded "$1"
}
decisions() { $BIN "${CFG[@]}" audit | sed -n 's/.*: \([0-9]*\) entries checked/\1/p'; }
# Decision ids the collector received, in arrival order.
received() {
  python3 -I - "$WORK/hec/events.jsonl" <<'PY'
import json, sys
try:
    lines = open(sys.argv[1]).read().splitlines()
except FileNotFoundError:
    lines = []
print(" ".join(str(json.loads(l)["event"]["event"]["id"]) for l in lines
               if json.loads(l)["event"]["sourcetype"] == "ariodb:decision"))
PY
}
# Every decision so far, once each, in order.
all_once() { [ "$(received)" = "$(seq 1 "$(decisions)" | paste -sd ' ' -)" ]; }
# Every decision so far, in order of first arrival (repeats allowed).
all_at_least_once() {
  python3 -I - "$(received)" "$(decisions)" <<'PY'
import sys
seen = []
for i in sys.argv[1].split():
    if int(i) not in seen:
        seen.append(int(i))
sys.exit(0 if seen == list(range(1, int(sys.argv[2]) + 1)) else 1)
PY
}
# add_line <from> <to> <line>: copy a config, adding a line to [audit.splunk].
add_line() {
  python3 -I -c 'import sys; t=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(t.replace("[audit.splunk]\n", "[audit.splunk]\n"+sys.argv[3]+"\n"))' "$1" "$2" "$3"
}
splunk_status() { curl -s -b "$WORK/cj" "http://127.0.0.1:$DASH/api/plugins"; }

echo "starting Postgres and the HEC stand-in"
docker rm -f $PG >/dev/null 2>&1 || true
docker run -d --name $PG -e POSTGRES_PASSWORD=local-test-only-pw -e POSTGRES_DB=app \
  -p 127.0.0.1:$PORT:5432 postgres:16 -c wal_level=logical >/dev/null
ok=0
for _ in $(seq 1 120); do
  if docker exec -e PGPASSWORD=local-test-only-pw $PG psql -U postgres -d app -tAc 'SELECT 1' >/dev/null 2>&1; then
    ok=$((ok + 1)); [ $ok -ge 3 ] && break
  else
    ok=0
  fi
  sleep 1
done
[ $ok -ge 3 ] || { docker logs $PG 2>&1 | tail -20; fail "Postgres did not become ready"; }

admin <<'SQL'
CREATE TABLE customers (id int PRIMARY KEY, name text NOT NULL);
CREATE TABLE orders (id int PRIMARY KEY, status text NOT NULL);
INSERT INTO customers SELECT g, 'Customer ' || g FROM generate_series(1, 20) g;
INSERT INTO orders SELECT g, 'paid' FROM generate_series(1, 100) g;
CREATE ROLE ariodb_gw LOGIN PASSWORD 'gw-local-test-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ariodb_gw;
SQL

export E2E_AGENT_TOKEN=agent-token-local-test-only
export E2E_HEC_TOKEN=hec-token-local-test-only
export E2E_HEC_WRONG=hec-wrong-token-local-test-only
export E2E_HEC_ACK=hec-ack-token-local-test-only
T=$E2E_AGENT_TOKEN
# The stand-in reads its tokens from the environment, never its command line.
export HEC_STANDIN_TOKENS="{\"$E2E_HEC_TOKEN\": {\"indexes\": [\"ariodb\"]}, \"$E2E_HEC_ACK\": {\"ack\": true, \"indexes\": [\"ariodb\"]}}"
mkdir -p "$WORK/hec"
start_hec

cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://ariodb_gw:gw-local-test-only@127.0.0.1:$PORT/app"

[limits]
max_rows_per_write = 5

[proxy]
listen = "127.0.0.1:$PROXY"

[journal]
enabled = true
dir = "$WORK/state"

[dashboard]
listen = "127.0.0.1:$DASH"
public_url = "http://127.0.0.1:$DASH"

[audit.splunk]
enabled = true
url = "http://127.0.0.1:$HEC"
token_env = "E2E_HEC_TOKEN"
index = "ariodb"
host = "e2e-gateway"
batch_size = 3
flush_interval_ms = 200
timeout_ms = 2000
ack_timeout_ms = 4000

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders"]
token_env = "E2E_AGENT_TOKEN"

[[approvers]]
name = "ops"
type = "dashboard"

[[rules]]
name = "ask"
condition = "sql.statement.contains('/*ask*/')"
verdict = "approve"
approve = ["ops"]
reason = "held for ops"
EOF
export ARIODB_JOURNAL_URL=postgres://postgres:local-test-only-pw@127.0.0.1:$PORT/app
unset ARIODB_DATABASE_URL ARIODB_ADMIN_URL
CFG=(--config "$WORK/ariodb.toml")
# Everything ariodb prints is kept here, to look for tokens at the end.
OUTPUTS="$WORK/outputs.txt"
: > "$OUTPUTS"
note() { printf '%s\n' "$1" >> "$OUTPUTS"; printf '%s' "$1"; }

echo "config"
sed 's/token_env = "E2E_HEC_TOKEN"/token = "hec-token-local-test-only"/' "$WORK/ariodb.toml" > "$WORK/in-file.toml"
expect "a token written in the file is refused" "must not be written in the config file" \
  "$($BIN --config "$WORK/in-file.toml" check 2>&1 || true)"
sed 's|url = "http://127.0.0.1:'$HEC'"|url = "http://127.0.0.1:'$HEC'/services/collector/event"|' "$WORK/ariodb.toml" > "$WORK/path.toml"
expect "a url with the endpoint path is refused" "the collector's base address" \
  "$($BIN --config "$WORK/path.toml" check 2>&1 || true)"

$BIN "${CFG[@]}" setup >/dev/null

echo "doctor"
DOCTOR=$(note "$($BIN "${CFG[@]}" doctor 2>&1 || true)")
expect "doctor reaches the collector" "ok    the collector answers: HEC is healthy" "$DOCTOR"
expect "doctor finds the token accepted" "ok    the collector accepts the token" "$DOCTOR"
expect "doctor shows the section with its index" "splunk: http://127.0.0.1:$HEC, index ariodb" "$DOCTOR"

start_serve serve.log
D=http://127.0.0.1:$DASH
curl -s -c "$WORK/cj" -X POST -H 'content-type: application/json' -d '{"password":"dashboard-test-only-pw"}' $D/api/setup >/dev/null

echo "decisions arrive once, in order"
wait_for_pending() {
  for _ in $(seq 1 100); do
    id=$($BIN "${CFG[@]}" approvals | awk '/ pending /{print $1; exit}')
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.2
  done
  fail "no pending approval appeared"
}
expect "an allowed read" "(1 row)" "$(agent "SELECT count(*) FROM orders")"
expect "a refused read" "may not use table" "$(agent "SELECT * FROM customers")"
(agent "SELECT /*ask*/ count(*) FROM orders" > "$WORK/held.out") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" approve "$ID" >/dev/null; wait $BG
expect "an approved read" "(1 row)" "$(cat "$WORK/held.out")"
expect "a write over the limit is rolled back" "rolled back" "$(agent "UPDATE orders SET status = 'bulk' WHERE id <= 50")"
expect "a write within it runs" "UPDATE 1" "$(agent "UPDATE orders SET status = 'shipped' WHERE id = 1")"
wait_for 20 "every decision reaches the collector" all_once
pass "the collector received decisions $(received), once each, in order"
python3 -I - "$WORK/hec/events.jsonl" <<'PY' || fail "decisions map to the documented fields"
import json, sys
events = [json.loads(l)["event"] for l in open(sys.argv[1])]
decisions = [e for e in events if e["sourcetype"] == "ariodb:decision"]
outcomes = [d["event"]["outcome"] for d in decisions]
assert outcomes == ["allowed", "refused", "allowed", "rolled_back", "allowed"], outcomes
for d in decisions:
    assert d["index"] == "ariodb" and d["host"] == "e2e-gateway" and d["source"] == "ariodb", d
    assert isinstance(d["time"], float) or isinstance(d["time"], int), d
    e = d["event"]
    assert e["agent"] == "coding-agent" and e["engine"] == "postgres" and e["database"] == "app", e
    for key in ("session", "kind", "tables", "rows", "latency_ms", "reason", "sql", "rule", "deciders", "hash", "prev"):
        assert key in e, (key, e)
approved = decisions[2]["event"]
assert approved["rule"] == "ask" and approved["deciders"] and approved["deciders"][0].startswith("cli:"), approved
assert "count(*)" in approved["sql"], approved
assert "customers" in decisions[1]["event"]["reason"], decisions[1]
assert decisions[3]["event"]["rows"] == 50, decisions[3]
assert decisions[1]["event"]["prev"] == decisions[0]["event"]["hash"]
PY
pass "decisions carry agent, engine, database, session, outcome, rule, deciders, rows and the SQL"
has_event() { grep -q "\"sourcetype\": \"ariodb:event\".*\"event\": \"$1\"\|\"event\": \"$1\".*\"sourcetype\": \"ariodb:event\"" "$WORK/hec/events.jsonl"; }
for e in approval_requested approval_decided; do
  wait_for 10 "the collector receives $e" has_event $e
  pass "the collector receives $e (sourcetype ariodb:event)"
done
STATUS=$(note "$(splunk_status)")
expect "the dashboard API shows the exporter" '"splunk":{' "$STATUS"
expect "with nothing waiting" '"backlog":0' "$STATUS"

echo "outage: the collector busy, then down"
hec_mode busy
COUNT=$(decisions)
agent "SELECT 'during the outage 1' FROM orders LIMIT 1" >/dev/null
agent "SELECT 'during the outage 2' FROM orders LIMIT 1" >/dev/null
busy_logged() { grep -q "HTTP 503, code 9 (Server is busy)" "$WORK/serve.log"; }
wait_for 20 "the 503 is logged" busy_logged
pass "a busy collector (503, code 9) is retried"
[ "$(received | wc -w | tr -d ' ')" = "$COUNT" ] && pass "nothing is counted as sent while it is busy" || fail "events stored while busy"
stop_hec
agent "SELECT 'during the outage 3' FROM orders LIMIT 1" >/dev/null
down_logged() { grep -q "cannot reach the collector" "$WORK/serve.log"; }
wait_for 30 "the collector being down is logged" down_logged
pass "a collector that is down is retried"
status_has() { splunk_status | grep -qF -- "$1"; }
wait_for 20 "the dashboard API shows the backlog" status_has '"backlog":3'
STATUS=$(note "$(splunk_status)")
expect "the dashboard API shows it retrying" '"state":"retrying"' "$STATUS"
expect "with the backlog" '"backlog":3' "$STATUS"
rm -f "$WORK/hec/mode"
start_hec
wait_for 90 "after the outage, every decision arrives" all_once
pass "after the outage: decisions $(received), none lost or repeated"
expect "and the log says delivery resumed" "delivering again" "$(cat "$WORK/serve.log")"

echo "restart"
hec_mode busy
agent "SELECT 'before the restart' FROM orders LIMIT 1" >/dev/null
sleep 2
stop_serve
[ "$(received | wc -w | tr -d ' ')" = "$(($(decisions) - 1))" ] && pass "an entry is held back when ariodb stops" || fail "the entry was sent while the collector was busy"
rm -f "$WORK/hec/mode"
start_serve serve2.log
agent "SELECT 'after the restart' FROM orders LIMIT 1" >/dev/null
wait_for 30 "after a restart, the exporter resumes from its cursor" all_once
pass "after a restart: decisions $(received), none lost or repeated"

echo "bad token"
reload serve2.log "t.replace('token_env = \"E2E_HEC_TOKEN\"', 'token_env = \"E2E_HEC_WRONG\"')"
agent "SELECT 'with a bad token 1' FROM orders LIMIT 1" >/dev/null
agent "SELECT 'with a bad token 2' FROM orders LIMIT 1" >/dev/null
refused_logged() { grep -q "Splunk refused decision.*HTTP 403, code 4 (Invalid token)" "$WORK/serve2.log"; }
wait_for 20 "the refused token is logged" refused_logged
expect "the log says what to fix" "check token_env or token_secret" "$(grep "Invalid token" "$WORK/serve2.log")"
expect "and that nothing is dropped" "Nothing is dropped" "$(grep "Invalid token" "$WORK/serve2.log")"
sleep 3
[ "$(grep -c "code 4 (Invalid token)" "$WORK/serve2.log")" = 1 ] && pass "it is logged once" || { grep "Invalid token" "$WORK/serve2.log"; fail "logged more than once"; }
STATUS=$(note "$(splunk_status)")
expect "the dashboard API shows it refused" '"state":"refused"' "$STATUS"
expect "with the reason" "Invalid token" "$STATUS"
DOCTOR=$(note "$($BIN "${CFG[@]}" doctor 2>&1 || true)")
expect "doctor reports the token" "FAIL  the token is not accepted: HTTP 403, code 4 (Invalid token)" "$DOCTOR"
expect "doctor reports the backlog" "decisions wait to be delivered" "$DOCTOR"
expect "doctor reports the last failure" "the last attempt failed" "$DOCTOR"
reload serve2.log "t.replace('token_env = \"E2E_HEC_WRONG\"', 'token_env = \"E2E_HEC_TOKEN\"')"
wait_for 20 "with the token fixed, the held decisions arrive" all_once
pass "with the token fixed (no restart): decisions $(received), none lost or repeated"

echo "indexer acknowledgement"
reload serve2.log "t.replace('token_env = \"E2E_HEC_TOKEN\"', 'token_env = \"E2E_HEC_ACK\"\nack = true')"
hec_mode ack-slow
agent "SELECT 'acknowledged 1' FROM orders LIMIT 1" >/dev/null
agent "SELECT 'acknowledged 2' FROM orders LIMIT 1" >/dev/null
wait_for 30 "acknowledged batches arrive" all_once
grep -q '"path": "/services/collector/ack", "status": 200' "$WORK/hec/requests.jsonl" && pass "ariodb asked /services/collector/ack until indexed" || fail "no ack queries"
grep -q '"ack_id": [0-9]' "$WORK/hec/events.jsonl" && pass "on its own channel" || fail "no channel used"
hec_mode ack-lost
agent "SELECT 'never acknowledged' FROM orders LIMIT 1" >/dev/null
lost_logged() { grep -q "did not confirm ackID" "$WORK/serve2.log"; }
wait_for 30 "an unconfirmed batch is sent again" lost_logged
pass "a batch Splunk never confirms is sent again"
rm -f "$WORK/hec/mode"
wait_for 30 "the resent batch is confirmed" all_at_least_once
pass "every decision arrived at least once (an unconfirmed batch may repeat)"
reload serve2.log "t.replace('token_env = \"E2E_HEC_ACK\"\nack = true', 'token_env = \"E2E_HEC_TOKEN\"')"

echo "undo"
sleep 1.5
SESSION=$($BIN "${CFG[@]}" sessions | awk 'NR==2{print $1}')
[ -n "$SESSION" ] && pass "journal recorded session $SESSION" || fail "no session recorded"
expect "undo applies" "rows restored" "$(note "$($BIN "${CFG[@]}" undo --session "$SESSION" --apply 2>&1)")"
wait_for 10 "the collector receives undo_applied" has_event undo_applied
pass "the collector receives undo_applied (from the CLI)"

echo "TLS"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 1 \
  -subj "/CN=ariodb e2e test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/hec.key" -out "$WORK/hec.csr" -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$WORK/hec.ext"
openssl x509 -req -in "$WORK/hec.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -out "$WORK/hec.pem" -days 1 -extfile "$WORK/hec.ext" >/dev/null 2>&1
mkdir -p "$WORK/hec-tls"
HEC_STANDIN_CERT="$WORK/hec.pem" HEC_STANDIN_KEY="$WORK/hec.key" \
  python3 -I scripts/hec_standin.py $HEC_TLS "$WORK/hec-tls" >"$WORK/hec-tls.log" 2>&1 &
TLS_PID=$!
wait_for 10 "the HTTPS stand-in starts" port_open $HEC_TLS
sed "s|url = \"http://127.0.0.1:$HEC\"|url = \"https://127.0.0.1:$HEC_TLS\"|" "$WORK/ariodb.toml" > "$WORK/tls.toml"
DOCTOR=$(note "$($BIN --config "$WORK/tls.toml" doctor 2>&1 || true)")
expect "an unknown CA is refused: certificates are checked by default" "FAIL  cannot reach the collector" "$DOCTOR"
add_line "$WORK/tls.toml" "$WORK/tls-ca.toml" "ca_file = \"$WORK/ca.pem\""
DOCTOR=$(note "$($BIN --config "$WORK/tls-ca.toml" doctor 2>&1 || true)")
expect "with ca_file, the collector is reached over TLS" "ok    the collector accepts the token" "$DOCTOR"
add_line "$WORK/tls.toml" "$WORK/tls-insecure.toml" "accept_invalid_certificate = true"
DOCTOR=$(note "$($BIN --config "$WORK/tls-insecure.toml" doctor 2>&1 || true)")
expect "accept_invalid_certificate reaches it" "ok    the collector accepts the token" "$DOCTOR"
expect "and doctor warns about it" "warn  accept_invalid_certificate is on" "$DOCTOR"

echo "shutdown"
stop_serve
cat "$WORK"/serve*.log >> "$OUTPUTS"
for token in "$E2E_HEC_TOKEN" "$E2E_HEC_WRONG" "$E2E_HEC_ACK"; do
  if grep -qF -- "$token" "$OUTPUTS"; then
    grep -nF -- "$token" "$OUTPUTS"
    fail "a token appears in ariodb's output"
  fi
done
pass "no token appears in ariodb's logs, doctor, CLI or dashboard output"

echo "all Splunk end-to-end checks passed"
