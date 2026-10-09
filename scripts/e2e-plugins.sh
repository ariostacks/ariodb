#!/usr/bin/env bash
# End-to-end test of plugins: a real Postgres in Docker, ariodb in front of
# it, the example Python plugin (examples/plugins/python) as approver, facts
# source, notifier and audit sink, and a deliberately broken plugin that
# crashes, stalls and answers nonsense on request.
#
# Needs Docker, python3 and a built ariodb (cargo build). All passwords and
# tokens here are throwaway test values.
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
# Parallel runs set E2E_OFFSET and E2E_NAME so ports and container names
# do not collide.
OFF=${E2E_OFFSET:-0}
PG=ariodb-e2e-plg-pg${E2E_NAME:+-$E2E_NAME}
CLIENT=${CLIENT_IMAGE:-postgres:16}
PORT=$((35300 + OFF))
PROXY=$((35301 + OFF))
DASH=$((35302 + OFF))
WORK=$(mktemp -d)
SERVE_PID=""
# Everything is set before the trap, so cleanup works however early a step
# fails. Plugin processes are stopped by ariodb; the pkill catches any left
# behind if ariodb itself was killed (their command lines name $WORK).
cleanup() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  pkill -f "$WORK/" 2>/dev/null || true
  docker rm -f "$PG" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

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
expect() { # expect <description> <needle> <output>
  if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi
}
wait_for_proxy() {
  for _ in $(seq 1 100); do
    port_open $PROXY && return 0
    kill -0 "$SERVE_PID" 2>/dev/null || { cat "$WORK"/serve*.log; fail "ariodb exited"; }
    sleep 0.2
  done
  fail "ariodb did not start"
}
# wait_for <description> <command...>: retry for up to 20 seconds.
wait_for() {
  local what=$1; shift
  for _ in $(seq 1 100); do
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
  wait_for_proxy
}
stop_serve() {
  kill "$SERVE_PID"
  wait "$SERVE_PID" 2>/dev/null || true
  SERVE_PID=""
}
# The pid ariodb logged for a plugin's newest process.
plugin_pid() { # plugin_pid <name> <log>
  sed -n "s/^ariodb: plugin '$1' is running (pid \([0-9]*\);.*/\1/p" "$WORK/$2" | tail -1
}
running_count() { grep -c "plugin '$1' is running" "$WORK/$2" || true; }

echo "starting Postgres"
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
CREATE TABLE orders (id int PRIMARY KEY, customer_id int NOT NULL REFERENCES customers(id), status text NOT NULL);
INSERT INTO customers SELECT g, 'Customer ' || g FROM generate_series(1, 20) g;
INSERT INTO orders SELECT g, 1 + g % 20, 'paid' FROM generate_series(1, 100) g;
CREATE ROLE ariodb_gw LOGIN PASSWORD 'gw-local-test-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ariodb_gw;
SQL

# The example plugin runs from the repository through a link in $WORK, so
# its command line names $WORK (for the cleanup above).
ln -s "$PWD/examples/plugins/python/ariodb_plugin.py" "$WORK/example_plugin.py"

# A plugin that misbehaves on request, by a word in the SQL:
#   garbage   writes a non-JSON line, then a malformed verdict
#   wrong-id  answers with an id ariodb never used
#   slow      answers after 4 seconds
#   crash     exits at once; while $WORK/hold exists, the next start waits
#             before answering initialize, so the plugin stays down
#   endless   starts a line on stdout that never ends
cat > "$WORK/broken.py" <<'PY'
import json, os, sys, time
hold = os.environ["BROKEN_HOLD_FILE"]
def send(v):
    sys.stdout.write(json.dumps(v) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    mid, method, params = msg["id"], msg["method"], msg.get("params", {})
    if method == "initialize":
        while os.path.exists(hold):
            time.sleep(0.1)
        send({"jsonrpc": "2.0", "id": mid, "result": {"name": "broken", "version": "0",
              "capabilities": {"approver": True}}})
        continue
    sql = " ".join(s["sql"] for s in params.get("statements", []))
    if "crash" in sql:
        os._exit(3)
    if "endless" in sql:
        while True:
            sys.stdout.write("x" * 65536); sys.stdout.flush()
    if "slow" in sql:
        time.sleep(4)
    if "garbage" in sql:
        print("this is not JSON", flush=True)
        send({"jsonrpc": "2.0", "id": mid, "result": {"verdict": "perhaps"}})
    elif "wrong-id" in sql:
        send({"jsonrpc": "2.0", "id": mid + 1000, "result": {"verdict": "allow"}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "result": {"verdict": "allow"}})
PY

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

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders", "customers"]
token_env = "E2E_AGENT_TOKEN"

[[plugins]]
name = "example"
command = ["python3", "-I", "$WORK/example_plugin.py"]
timeout_ms = 3000

[plugins.env]
ARIODB_EXAMPLE_START_HOUR = "0"
ARIODB_EXAMPLE_CUTOFF_HOUR = "24"
ARIODB_EXAMPLE_DENY_TABLES = "customers"
ARIODB_EXAMPLE_FREEZE_FILE = "$WORK/freeze"
ARIODB_EXAMPLE_EVENTS_FILE = "$WORK/events.jsonl"
ARIODB_EXAMPLE_AUDIT_FILE = "$WORK/audit.jsonl"
ARIODB_EXAMPLE_AUDIT_PAUSE_FILE = "$WORK/audit-paused"

[[plugins]]
name = "broken"
command = ["python3", "-I", "$WORK/broken.py"]
env = { BROKEN_HOLD_FILE = "$WORK/hold" }

[[approvers]]
name = "example-approver"
type = "plugin"
plugin = "example"

[[approvers]]
name = "broken-approver"
type = "plugin"
plugin = "broken"
timeout_seconds = 2

[[rules]]
name = "ask-example"
condition = "sql.statement.contains('/*ask-example*/')"
verdict = "approve"
approve = ["example-approver"]
reason = "held for the example plugin"

[[rules]]
name = "ask-broken"
condition = "sql.statement.contains('/*ask-broken*/')"
verdict = "approve"
approve = ["broken-approver"]
reason = "held for the broken plugin"

[[rules]]
name = "change-freeze"
condition = "plugin.example.freeze && sql.kind == 'write'"
verdict = "deny"
reason = "change freeze (from the example plugin)"
EOF
export E2E_AGENT_TOKEN=agent-token-local-test-only
T=$E2E_AGENT_TOKEN
export ARIODB_JOURNAL_URL=postgres://postgres:local-test-only-pw@127.0.0.1:$PORT/app
unset ARIODB_DATABASE_URL ARIODB_ADMIN_URL
CFG=(--config "$WORK/ariodb.toml")

echo "plugin commands"
LIST=$($BIN "${CFG[@]}" plugin list 2>&1) || { echo "$LIST"; fail "plugin list"; }
expect "plugin list shows the example's capabilities" "ariodb-example 1.0.0: approver, facts, notifier, audit_sink" "$LIST"
expect "plugin list shows the broken one's" "broken 0: approver" "$LIST"
TEST=$($BIN "${CFG[@]}" plugin test example 2>&1) || { echo "$TEST"; fail "plugin test example exits 0"; }
pass "plugin test example exits 0"
expect "plugin test: approve" "ok    approve: allow" "$TEST"
expect "plugin test: facts" '"freeze":false' "$TEST"
expect "plugin test: audit" "ok    audit: acknowledged" "$TEST"
[ ! -e "$WORK/audit.jsonl" ] && pass "the test sample was not stored" || fail "plugin test stored a sample entry"
sed "s|\"$WORK/broken.py\"|\"-c\", \"print(1)\"|" "$WORK/ariodb.toml" > "$WORK/dud.toml"
set +e; OUT=$($BIN --config "$WORK/dud.toml" plugin test broken 2>&1); code=$?; set -e
[ $code -eq 1 ] && pass "plugin test of a plugin that fails its handshake exits 1" || { echo "$OUT"; fail "expected exit 1, got $code"; }
expect "and says why" "before it answered initialize" "$OUT"
expect "an unknown plugin is refused" "not defined in [[plugins]]" "$($BIN "${CFG[@]}" plugin test nope 2>&1 || true)"
sed 's/plugin = "broken"/plugin = "nope"/' "$WORK/ariodb.toml" > "$WORK/bad.toml"
expect "an approver naming an unknown plugin is refused" "uses plugin 'nope'" "$($BIN --config "$WORK/bad.toml" check 2>&1 || true)"

# Undo needs the journal: prepare it (as the table owner).
$BIN "${CFG[@]}" setup >/dev/null
start_serve serve.log
expect "serve starts the plugins" "plugin 'example' is running" "$(cat "$WORK/serve.log")"
expect "plugin stderr is logged with its name" "plugin example: ariodb-example: started by ariodb" "$(cat "$WORK/serve.log")"

echo "approver"
expect "the plugin approver allows" "(1 row)" "$(agent "SELECT /*ask-example*/ count(*) FROM orders")"
expect "the plugin approver denies, with its note" "denied by plugin approver 'example-approver': customers may not be touched" \
  "$(agent "SELECT /*ask-example*/ count(*) FROM customers")"
expect "plugin decisions are recorded" "plugin:example" "$($BIN "${CFG[@]}" approvals --all)"

echo "facts"
expect "a write with no freeze runs" "UPDATE 1" "$(agent "UPDATE orders SET status = 'shipped' WHERE id = 1")"
touch "$WORK/freeze"
expect "facts drive a rule: the freeze refuses writes" "change freeze (from the example plugin)" \
  "$(agent "UPDATE orders SET status = 'frozen' WHERE id = 2")"
expect "reads still run during the freeze" "(1 row)" "$(agent "SELECT status FROM orders WHERE id = 2")"
rm "$WORK/freeze"
expect "the freeze lifts with the fact" "UPDATE 1" "$(agent "UPDATE orders SET status = 'thawed' WHERE id = 2")"

echo "notifier"
expect "a write over the limit is rolled back" "rolled back" "$(agent "UPDATE orders SET status = 'bulk' WHERE id <= 50")"
has_event() { grep -q "\"event\":\"$1\"" "$WORK/events.jsonl" 2>/dev/null; }
for e in approval_requested approval_decided statement_refused write_rolled_back; do
  wait_for "notifier receives $e" has_event $e
  pass "notifier receives $e"
done
expect "events carry details" '"rule":"change-freeze"' "$(grep statement_refused "$WORK/events.jsonl")"

echo "broken plugin"
expect "it allows when it behaves" "(1 row)" "$(agent "SELECT /*ask-broken*/ 1")"
OUT=$(agent "SELECT /*ask-broken*/ 'garbage'")
expect "a malformed verdict refuses" "answered approve wrongly" "$OUT"
expect "and is failing closed" "failing closed" "$OUT"
expect "non-JSON output is logged, not obeyed" "plugin 'broken' wrote a line that is not JSON-RPC" "$(cat "$WORK/serve.log")"
expect "an answer to another request id refuses" "no answer from plugin 'broken' within 2 seconds" "$(agent "SELECT /*ask-broken*/ 'wrong-id'")"
expect "and the stray answer is ignored" "which is not waiting" "$(cat "$WORK/serve.log")"
expect "a slow plugin times out and refuses" "no answer from plugin 'broken' within 2 seconds" "$(agent "SELECT /*ask-broken*/ 'slow'")"
sleep 3
OLD_PID=$(plugin_pid broken serve.log)
touch "$WORK/hold"
expect "a crash refuses the request in flight" "stopped before answering" "$(agent "SELECT /*ask-broken*/ 'crash'")"
expect "the crash is logged and the plugin restarted with backoff" "plugin 'broken' exited with status 3; restarting it in 1 s" "$(cat "$WORK/serve.log")"
expect "while it is down, it refuses" "plugin 'broken' is restarting" "$(agent "SELECT /*ask-broken*/ 2")"
rm "$WORK/hold"
broken_is_back() { [ "$(running_count broken serve.log)" -ge 2 ]; }
wait_for "the plugin comes back" broken_is_back
NEW_PID=$(plugin_pid broken serve.log)
[ "$NEW_PID" != "$OLD_PID" ] && pass "a new plugin process is running" || fail "no new process"
expect "and it allows again" "(1 row)" "$(agent "SELECT /*ask-broken*/ 3")"

echo "dashboard"
D=http://127.0.0.1:$DASH
curl -s -c "$WORK/cj" -X POST -H 'content-type: application/json' -d '{"password":"dashboard-test-only-pw"}' $D/api/setup >/dev/null
PLUGINS=$(curl -s -b "$WORK/cj" $D/api/plugins)
expect "the dashboard API lists plugins" '"name":"example"' "$PLUGINS"
expect "with their state" '"state":"running"' "$PLUGINS"
# One restart for the crash; a slow machine can add another while the new
# process starts.
RESTARTS=$(python3 -c 'import json,sys; print(next(p["restarts"] for p in json.loads(sys.argv[1])["plugins"] if p["name"] == "broken"))' "$PLUGINS")
[ "$RESTARTS" -ge 1 ] && pass "and restarts" || { echo "$PLUGINS"; fail "and restarts"; }

echo "endless line"
expect "a line that never ends refuses at the cap, not at the timeout" "stopped before answering" \
  "$(agent "SELECT /*ask-broken*/ 'endless'")"
expect "and restarts the plugin" "plugin 'broken' sent a line longer than 1048576 bytes; restarting it" "$(cat "$WORK/serve.log")"
broken_is_back_again() { [ "$(running_count broken serve.log)" -ge 3 ]; }
wait_for "the plugin comes back after the endless line" broken_is_back_again
expect "and it allows again" "(1 row)" "$(agent "SELECT /*ask-broken*/ 4")"

echo "audit sink"
decisions() { $BIN "${CFG[@]}" audit | sed -n 's/.*: \([0-9]*\) entries checked/\1/p'; }
# Every decision delivered exactly once, in order, ids 1..N.
audit_complete() {
  python3 -I - "$WORK/audit.jsonl" "$(decisions)" <<'PY'
import json, sys
ids = [json.loads(l)["id"] for l in open(sys.argv[1])]
n = int(sys.argv[2])
sys.exit(0 if ids == list(range(1, n + 1)) else 1)
PY
}
wait_for "the audit sink receives every decision" audit_complete
pass "the audit sink received every decision once, in order ($(decisions))"
expect "entries carry the hash chain" '"hash":"' "$(head -1 "$WORK/audit.jsonl")"
touch "$WORK/audit-paused"
sleep 1
BEFORE=$(wc -l < "$WORK/audit.jsonl")
agent "SELECT 'while paused 1'" >/dev/null
agent "SELECT 'while paused 2'" >/dev/null
wait_for "refused batches are logged" grep -q "audit delivery failed" "$WORK/serve.log"
[ "$(wc -l < "$WORK/audit.jsonl")" = "$BEFORE" ] && pass "unacknowledged entries are not counted as delivered" || fail "entries stored while paused"
stop_serve
rm "$WORK/audit-paused"
start_serve serve2.log
agent "SELECT 'after the restart'" >/dev/null
wait_for "after a restart the sink catches up" audit_complete
pass "after a restart, every decision delivered once, in order ($(decisions))"
expect "including those made while it refused" "while paused 2" "$(cat "$WORK/audit.jsonl")"

echo "undo"
sleep 1.5
SESSION=$($BIN "${CFG[@]}" sessions | awk 'NR==2{print $1}')
[ -n "$SESSION" ] && pass "journal recorded session $SESSION" || fail "no session recorded"
expect "undo applies" "rows restored" "$($BIN "${CFG[@]}" undo --session "$SESSION" --apply 2>&1)"
wait_for "notifier receives undo_applied" has_event undo_applied
pass "notifier receives undo_applied (from the CLI)"

echo "shutdown"
PIDS="$(plugin_pid example serve2.log) $(plugin_pid broken serve2.log)"
stop_serve
for pid in $PIDS; do
  kill -0 "$pid" 2>/dev/null && fail "plugin process $pid outlived ariodb"
done
pass "stopping ariodb stops its plugins"

echo "all plugin end-to-end checks passed"
