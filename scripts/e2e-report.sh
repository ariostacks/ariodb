#!/usr/bin/env bash
# End-to-end test of compliance report packs: a real Postgres in Docker,
# ariodb in front of it, and an agent whose statements are allowed, refused,
# held for a person and for a model, rolled back and undone, with a config
# change while ariodb runs. Then a pack for each framework and for all of
# them, made while ariodb is serving, is checked: sections, counts, the
# manifest, that no secret from the config reached it, and that an edited
# decisions-log entry is reported as a chain break.
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
PG=ariodb-e2e-rep-pg${E2E_NAME:+-$E2E_NAME}
CLIENT=${CLIENT_IMAGE:-postgres:16}
PORT=$((36300 + OFF))
PROXY=$((36301 + OFF))
DASH=$((36302 + OFF))
MOCK=$((36303 + OFF))
WORK=$(mktemp -d)
SERVE_PID=""
MOCK_PID=""
cleanup() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
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
    kill -0 "$SERVE_PID" 2>/dev/null || { cat "$WORK"/serve.log; fail "ariodb exited"; }
    sleep 0.2
  done
  fail "ariodb did not start"
}
admin() { docker exec -i -e PGPASSWORD=local-test-only-pw $PG psql -q -v ON_ERROR_STOP=1 -U postgres -d app "$@"; }
# Run SQL through the proxy as an agent. Prints psql output, never fails.
agent() {
  docker run "${HOST_NET[@]}" --rm -e PGPASSWORD="$2" $CLIENT \
    psql "host=host.docker.internal port=$PROXY user=$1 dbname=app sslmode=disable" -c "$3" 2>&1 || true
}
# A JSON value from a file, by a Python expression over `d`.
jq_py() { python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"; }

python3 -I scripts/mock_services.py $MOCK "$WORK/mock.log" &
MOCK_PID=$!

echo "starting Postgres"
docker rm -f $PG >/dev/null 2>&1 || true
docker run -d --name $PG -e POSTGRES_PASSWORD=local-test-only-pw -e POSTGRES_DB=app \
  -p 127.0.0.1:$PORT:5432 $CLIENT -c wal_level=logical >/dev/null
ok=0
for _ in $(seq 1 120); do
  if docker exec -e PGPASSWORD=local-test-only-pw $PG psql -U postgres -d app -tAc 'SELECT 1' >/dev/null 2>&1; then
    ok=$((ok + 1)); [ $ok -ge 3 ] && break
  else
    ok=0
  fi
  sleep 1
done
[ $ok -ge 3 ] || fail "Postgres did not become ready"

admin <<'SQL'
CREATE TABLE customers (id int PRIMARY KEY, name text NOT NULL);
CREATE TABLE orders (id int PRIMARY KEY, customer_id int NOT NULL REFERENCES customers(id), status text NOT NULL);
CREATE TABLE secrets (id int PRIMARY KEY, note text);
INSERT INTO customers SELECT g, 'Customer ' || g FROM generate_series(1, 20) g;
INSERT INTO orders SELECT g, 1 + g % 20, 'paid' FROM generate_series(1, 200) g;
CREATE ROLE ariodb_gw LOGIN PASSWORD 'gw-local-test-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ariodb_gw;
CREATE ROLE ariodb_journal LOGIN REPLICATION PASSWORD 'journal-local-test-only';
SQL

# The gateway password and the webhook's token are written into the config
# itself, so the pack can be checked for them.
cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://ariodb_gw:gw-local-test-only@127.0.0.1:$PORT/app"

[limits]
max_rows_per_write = 50

[proxy]
listen = "127.0.0.1:$PROXY"

[journal]
enabled = true
dir = "$WORK/state"

[audit]
retention_days = 30

[dashboard]
listen = "127.0.0.1:$DASH"
public_url = "http://127.0.0.1:$DASH"

[approvals]
timeout_seconds = 30

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders", "customers"]
token_env = "E2E_AGENT_TOKEN"

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["orders"]
token_env = "E2E_BOT_TOKEN"

[[approvers]]
name = "ops"
type = "dashboard"

[[approvers]]
name = "ops-quick"
type = "dashboard"
timeout_seconds = 2

[[approvers]]
name = "judge"
type = "llm"
api_key_env = "E2E_ANTHROPIC_KEY"
policy = "Allow reads of orders. Deny anything else."

[[approvers]]
name = "pager"
type = "webhook"
url = "http://127.0.0.1:$MOCK/hook?team=ops&token=hook-token-local-test-only"
hmac_secret_env = "E2E_HOOK_KEY"

[[rules]]
name = "ask-person"
condition = "sql.statement.contains('/*ask-person*/')"
verdict = "approve"
approve = ["ops"]

[[rules]]
name = "ask-quick"
condition = "sql.statement.contains('/*ask-quick*/')"
verdict = "approve"
approve = ["ops-quick"]

[[rules]]
name = "ask-model"
condition = "sql.statement.contains('/*ask-model*/')"
verdict = "approve"
approve = ["judge"]

[[rules]]
name = "no-customer-reads"
condition = "sql.verb == 'select' && 'customers' in sql.tables"
verdict = "deny"
reason = "customers are read through the CRM"
EOF
export E2E_AGENT_TOKEN=agent-token-local-test-only E2E_BOT_TOKEN=bot-token-local-test-only
export E2E_ANTHROPIC_KEY=sk-ant-not-a-real-key E2E_HOOK_KEY=hook-key-test-only
export ARIODB_ANTHROPIC_API=http://127.0.0.1:$MOCK/anthropic
export ARIODB_JOURNAL_URL=postgres://ariodb_journal:journal-local-test-only@127.0.0.1:$PORT/app
unset ARIODB_DATABASE_URL ARIODB_ADMIN_URL
CFG=(--config "$WORK/ariodb.toml")
T=$E2E_AGENT_TOKEN

ARIODB_JOURNAL_URL=postgres://postgres:local-test-only-pw@127.0.0.1:$PORT/app $BIN "${CFG[@]}" setup >/dev/null
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
wait_for_proxy

echo "agent activity"
for i in 1 2 3; do
  expect "read $i allowed" "(1 row)" "$(agent coding-agent $T "SELECT count(*) + $i FROM orders")"
done
expect "the support bot reads" "(1 row)" "$(agent support-bot $E2E_BOT_TOKEN "SELECT count(*) FROM orders")"
expect "refused by policy: another table" "may not use table" "$(agent coding-agent $T "SELECT * FROM secrets")"
expect "refused by policy: a drop" "destructive" "$(agent coding-agent $T "DROP TABLE orders")"
expect "refused by policy: a read-only agent's write" "is read only" "$(agent support-bot $E2E_BOT_TOKEN "UPDATE orders SET status = 'x' WHERE id = 1")"
expect "refused by a rule" "customers are read through the CRM" "$(agent coding-agent $T "SELECT count(*) FROM customers")"
expect "a bulk write is rolled back" "the limit is 50" "$(agent coding-agent $T "UPDATE orders SET status = 'void' WHERE id <= 120")"

wait_for_pending() {
  for _ in $(seq 1 100); do
    id=$($BIN "${CFG[@]}" approvals | awk '/ pending /{print $1; exit}')
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.2
  done
  fail "no pending approval appeared"
}
OUT="$WORK/held.out"
(agent coding-agent $T "SELECT /*ask-person*/ count(*) FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" approve "$ID" >/dev/null; wait $BG
expect "a person approves from the command line" "(1 row)" "$(cat "$OUT")"
(agent coding-agent $T "SELECT /*ask-person*/ 1 FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" deny "$ID" --note "not today" >/dev/null; wait $BG
expect "a person denies" "not today" "$(cat "$OUT")"
D=http://127.0.0.1:$DASH
JSONH='content-type: application/json'
curl -s -c "$WORK/cj" -X POST -H "$JSONH" -d '{"password":"dashboard-test-only-pw"}' $D/api/setup > "$WORK/setup.json"
CSRF=$(jq_py "$WORK/setup.json" "d['csrf']")
(agent coding-agent $T "SELECT /*ask-person*/ count(*) + 2 FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending)
expect "a person approves in the dashboard" '"ok":true' \
  "$(curl -s -b "$WORK/cj" -X POST -H "x-ariodb-csrf: $CSRF" -H "$JSONH" -d '{"verdict":"allow"}' $D/api/approvals/$ID)"
wait $BG
expect "  and the statement runs" "(1 row)" "$(cat "$OUT")"
expect "an approval times out" "within 2 seconds" "$(agent coding-agent $T "SELECT /*ask-quick*/ 1 FROM orders")"
expect "a model approves" "(1 row)" "$(agent coding-agent $T "SELECT /*ask-model*/ count(*) FROM orders")"
expect "a model denies" "mock judge said deny" "$(agent coding-agent $T "SELECT /*ask-model*/ 'deny-me' FROM orders")"

echo "a session's writes, and undo"
WRITES=$(docker run "${HOST_NET[@]}" --rm -e PGPASSWORD="$T" $CLIENT psql "host=host.docker.internal port=$PROXY user=coding-agent dbname=app sslmode=disable" \
  -c "UPDATE orders SET status = 'shipped' WHERE id IN (1, 2, 3)" -c "UPDATE customers SET name = 'Renamed' WHERE id = 4" 2>&1 || true)
expect "two writes in one session" "UPDATE 3
UPDATE 1" "$WRITES"
SESSION=""
for _ in $(seq 1 50); do
  SESSION=$($BIN "${CFG[@]}" sessions | awk 'NR==2{print $1}')
  [ -n "$SESSION" ] && [ "$($BIN "${CFG[@]}" sessions | awk 'NR==2{print $4}')" = "4" ] && break
  sleep 0.2
done
[ -n "$SESSION" ] || fail "the journal did not record the session"
expect "the session is undone" "4 rows restored" "$($BIN "${CFG[@]}" undo --session "$SESSION" --apply 2>&1)"
for _ in $(seq 1 50); do
  $BIN "${CFG[@]}" sessions | grep -q "undone" && break
  sleep 0.2
done
expect "  and the journal saw the undo" "undone" "$($BIN "${CFG[@]}" sessions)"

echo "a config change while running"
cat >> "$WORK/ariodb.toml" <<'TOML'

[[rules]]
name = "added-while-running"
condition = "sql.statement.contains('/*blocked-later*/')"
verdict = "deny"
reason = "added while running"
TOML
for _ in $(seq 1 50); do
  grep -q "reloaded" "$WORK/serve.log" && break
  sleep 0.2
done
expect "the new rule is in force" "added while running" "$(agent coding-agent $T "SELECT 1 /*blocked-later*/ FROM orders")"

# Expected counts, from the statements above.
ALLOWED=9   # 3 reads, the bot's read, 2 approved by people, 1 by the model, the session's 2 writes
REFUSED=8   # 4 by policy or rule, the denial, the timeout, the model's denial, the rule added while running

echo "report packs, made while ariodb serves"
DAYS=$(python3 -I -c "import datetime as d; t=d.datetime.now(d.timezone.utc).date(); print(t - d.timedelta(days=1), t + d.timedelta(days=1))")
FROM=${DAYS% *}; TO=${DAYS#* }
for fw in dora soc2 iso27001 eu-ai-act all; do
  $BIN "${CFG[@]}" report --from "$FROM" --to "$TO" --framework $fw --out "$WORK/pack-$fw" > "$WORK/report-$fw.out" 2>&1 \
    || { cat "$WORK/report-$fw.out"; fail "report for $fw"; }
done
pass "a pack for each framework, and for all"
expect "the command prints the manifest's hash" "manifest.sha256: " "$(cat "$WORK/report-all.out")"
expect "and says the chain is intact" "chain intact" "$(cat "$WORK/report-all.out")"
expect "ariodb kept serving" "(1 row)" "$(agent coding-agent $T "SELECT count(*) FROM orders")"

P="$WORK/pack-all"
for f in report.html summary.json manifest.sha256 decisions.csv decisions.json approvals.csv approvals.json \
  changes.csv undos.csv config_versions.json exceptions.csv refusals.csv rollbacks.csv controls.csv; do
  [ -s "$P/$f" ] || fail "the pack has no $f"
done
pass "the pack holds the report, the records and the manifest"
HTML=$(cat "$P/report.html")
for s in scope integrity access oversight change policy exceptions controls verify; do
  expect "section: $s" "<section id=\"$s\">" "$HTML"
done
grep -qi '<script' "$P/report.html" && fail "the report has a script" || pass "the report needs no scripts"
grep -Eq '(src|href)="(https?:)?//' "$P/report.html" && fail "the report loads something from outside" || pass "the report is self-contained"
expect "it says it is evidence, not a certification" "not a certification, an assessment" "$HTML"

S="$P/summary.json"
[ "$(jq_py "$S" "d['decisions']['by_outcome'].get('refused')")" = "$REFUSED" ] && pass "refusals counted ($REFUSED)" \
  || { cat "$S"; fail "refusals counted"; }
[ "$(jq_py "$S" "d['decisions']['by_outcome'].get('rolled_back')")" = "1" ] && pass "the rollback counted" || fail "the rollback counted"
[ "$(jq_py "$S" "d['decisions']['by_outcome'].get('allowed')")" = "$ALLOWED" ] && pass "allowed statements counted ($ALLOWED)" \
  || { cat "$S"; fail "allowed statements counted"; }
[ "$(jq_py "$S" "d['approvals']['decided_by_kind'].get('person')")" = "3" ] && pass "three decisions by people" || { cat "$S"; fail "decisions by people"; }
[ "$(jq_py "$S" "d['approvals']['decided_by_kind'].get('model')")" = "2" ] && pass "two decisions by the model" || fail "decisions by the model"
[ "$(jq_py "$S" "d['approvals']['by_result'].get('timed out')")" = "1" ] && pass "one timeout" || fail "the timeout"
[ "$(jq_py "$S" "d['changes']['undos']")" = "1" ] && pass "one undo" || fail "the undo"
[ "$(jq_py "$S" "d['policy']['versions_in_period']")" = "2" ] && pass "two config versions: at startup and on reload" || { cat "$S"; fail "config versions"; }
[ "$(jq_py "$S" "d['integrity']['intact']")" = "True" ] && pass "the chain is intact" || fail "the chain is intact"
expect "deciders are named" "dashboard:root" "$(cat "$P/approvals.csv")"
expect "  including the model" "model:anthropic/" "$(cat "$P/approvals.csv")"
expect "who undid the session is recorded" "cli:${USER:-}" "$(cat "$P/undos.csv")"
expect "the policy change is shown as a diff" "+ name = &quot;added-while-running&quot;" "$HTML"
expect "refusals are grouped by rule" "no-customer-reads" "$(cat "$P/refusals.csv")"

echo "the manifest"
python3 -I - "$P" "$(sed -n 's/^manifest.sha256: //p' "$WORK/report-all.out")" <<'PY' || fail "the manifest checks out"
import hashlib, os, sys
pack, printed = sys.argv[1], sys.argv[2]
digest = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
manifest = os.path.join(pack, "manifest.sha256")
assert digest(manifest) == printed, "the printed hash is the manifest's"
listed = {}
for line in open(manifest):
    h, name = line.rstrip("\n").split("  ", 1)
    assert digest(os.path.join(pack, name)) == h, name
    listed[name] = h
assert sorted(listed) == sorted(n for n in os.listdir(pack) if n != "manifest.sha256"), "every file is listed"
PY
pass "every file matches the manifest, and the printed hash is the manifest's"
if command -v sha256sum >/dev/null; then SUM=(sha256sum); else SUM=(shasum -a 256); fi
(cd "$P" && "${SUM[@]}" -c manifest.sha256 >/dev/null) && pass "${SUM[*]} -c accepts the manifest" || fail "${SUM[*]} -c"
cp -R "$P" "$WORK/altered"
printf '<!-- altered -->' >> "$WORK/altered/report.html"
(cd "$WORK/altered" && "${SUM[@]}" -c manifest.sha256 >/dev/null 2>&1) && fail "an altered file passes" || pass "an altered file fails the check"

echo "secrets and frameworks"
for secret in gw-local-test-only hook-token-local-test-only journal-local-test-only "$E2E_AGENT_TOKEN" "$E2E_ANTHROPIC_KEY"; do
  if grep -rqF -- "$secret" "$WORK"/pack-*; then fail "a secret reached a pack ($secret)"; fi
done
pass "no password, token or key from the config or environment is in any pack"
expect "the masked config is kept" "postgres://ariodb_gw:***@127.0.0.1:$PORT/app" "$(cat "$P/config_versions.json")"
expect "  with the webhook's token masked" "team=ops&token=***" "$(cat "$P/config_versions.json")"
DORA=$(cat "$WORK/pack-dora/report.html")
expect "a DORA pack names DORA articles" "<b>DORA</b> Art. 9(4)(e)" "$DORA"
expect "  and the RTS on ICT risk management" "RTS 2024/1774 Art. 12(2)(d)" "$DORA"
grep -qF "CC8.1" <<<"$DORA" && fail "a DORA pack names SOC 2 controls" || pass "  and no other framework's"
expect "a SOC 2 pack names its criteria" "CC6.1" "$(cat "$WORK/pack-soc2/report.html")"
expect "an ISO/IEC 27001 pack names Annex A controls" "A.8.15" "$(cat "$WORK/pack-iso27001/report.html")"
expect "an EU AI Act pack names human oversight" "Art. 14(4)(d)" "$(cat "$WORK/pack-eu-ai-act/report.html")"
expect "  and flags retention under six months" "at least six months" "$(cat "$WORK/pack-eu-ai-act/exceptions.csv")"
ALL=$(cat "$P/controls.csv")
for c in "DORA,Art. 10(1)" CC7.2 A.8.32 "Art. 26(6)"; do expect "the full pack maps $c" "$c" "$ALL"; done

echo "a pack from the dashboard"
curl -s -b "$WORK/cj" -D "$WORK/dl.headers" -o "$WORK/dl.tar" "$D/api/report?from=$FROM&to=$TO&framework=soc2"
expect "admins download a pack as a tar archive" "application/x-tar" "$(cat "$WORK/dl.headers")"
DL_HASH=$(tr -d '\r' < "$WORK/dl.headers" | sed -n 's/^x-ariodb-manifest-sha256: //p')
mkdir "$WORK/dl" && tar -xf "$WORK/dl.tar" -C "$WORK/dl"
DL=$(ls -d "$WORK"/dl/ariodb-report-*)
(cd "$DL" && "${SUM[@]}" -c manifest.sha256 >/dev/null) && pass "  which checks against its manifest" || fail "the downloaded pack's manifest"
[ "$("${SUM[@]}" "$DL/manifest.sha256" | cut -d' ' -f1)" = "$DL_HASH" ] && pass "  whose hash the response names" || fail "the manifest hash header"
expect "  with the chosen framework" "CC6.1" "$(cat "$DL/controls.csv")"
expect "a pack needs a signed-in admin" "log in first" "$(curl -s "$D/api/report?from=$FROM&to=$TO")"
expect "a reversed period is refused" "must start before it ends" "$(curl -s -b "$WORK/cj" "$D/api/report?from=$TO&to=$FROM")"

echo "a tampered decisions log"
EDITED=$(python3 -I - "$WORK/state/ariodb.db" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=10)
(id_,) = db.execute("SELECT id FROM decisions WHERE outcome = 'refused' ORDER BY id LIMIT 1").fetchone()
db.execute("UPDATE decisions SET outcome = 'allowed' WHERE id = ?", (id_,))
db.commit()
print(id_)
PY
)
$BIN "${CFG[@]}" report --from "$FROM" --to "$TO" --out "$WORK/pack-tampered" > "$WORK/report-tampered.out" 2>&1 \
  || { cat "$WORK/report-tampered.out"; fail "report after tampering"; }
expect "the command warns of the break" "entry $EDITED was changed after it was written" "$(cat "$WORK/report-tampered.out")"
[ "$(jq_py "$WORK/pack-tampered/summary.json" "d['integrity']['intact']")" = "False" ] && pass "the summary says the chain is broken" || fail "summary intact flag"
expect "the report names the entry" "entry $EDITED was changed after it was written" "$(cat "$WORK/pack-tampered/report.html")"
expect "  and lists it to follow up" "Decisions log chain broken" "$(cat "$WORK/pack-tampered/exceptions.csv")"
expect "ariodb audit agrees" "chain broken at entry $EDITED" "$($BIN "${CFG[@]}" audit 2>&1 || true)"

echo "all report checks passed"
