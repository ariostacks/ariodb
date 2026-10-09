#!/usr/bin/env bash
# End-to-end test of the MySQL change journal, `ariodb setup`, `ariodb doctor`
# and undo, against a real MySQL or MariaDB in Docker. Agent sessions are
# simulated by running their transactions directly as the gateway login,
# each starting with the tag row the gateway writes; a "human" changes rows
# without one. All passwords and tokens here are throwaway test values.
#
#   MYSQL_IMAGE=mariadb:11.4 E2E_OFFSET=50 ./scripts/e2e-mysql-journal.sh
#   MYSQL_ARGS=--binlog-transaction-compression=ON ./scripts/e2e-mysql-journal.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
IMAGE=${MYSQL_IMAGE:-mysql:8.4}
OFF=${E2E_OFFSET:-0}
NAME=ariodb-e2e-myj-$OFF
PORT=$((34300 + OFF))
DASH=$((34301 + OFF))
LISTEN=$((34302 + OFF))
WORK=$(mktemp -d)
SERVE_PID=""
cleanup() {
  if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" 2>/dev/null || true; wait "$SERVE_PID" 2>/dev/null || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
# A signal (such as timeout's TERM) exits through the EXIT trap too.
trap 'exit 130' INT TERM

pass() { printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() {
  printf '  \033[31mFAIL\033[0m %s\n' "$1"
  [ -f "$WORK/serve.log" ] && tail -20 "$WORK/serve.log"
  [ -f "$WORK/state/mysql-journal.jsonl" ] && python3 -c 'import json,sys
for l in open(sys.argv[1]): r=json.loads(l); print("journal:", r["lsn_text"], r["session"], [(c["op"], c["table"]) for c in r["changes"]])' "$WORK/state/mysql-journal.jsonl"
  exit 1
}
expect() { if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi; }
refute() { if grep -qF -- "$2" <<<"$3"; then echo "$3"; fail "$1"; else pass "$1"; fi; }

case "$IMAGE" in
  mariadb*) CLI=mariadb; ARGS=(--log-bin --binlog-format=ROW --binlog-row-metadata=FULL --server-id=1) ;;
  # MySQL 8.4 defaults suffice. binlog_row_metadata stays MINIMAL, so the
  # journal takes column names from information_schema.
  *) CLI=mysql; ARGS=() ;;
esac
# Extra server options, such as --binlog-transaction-compression=ON.
read -r -a EXTRA <<<"${MYSQL_ARGS:-}"
ARGS+=(${EXTRA[@]+"${EXTRA[@]}"})

timeout 600 cargo build -q 2>"$WORK/build.log" || { cat "$WORK/build.log"; fail "build"; }

echo "starting $IMAGE"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -e MYSQL_ROOT_PASSWORD=local-test-only-pw -e MYSQL_DATABASE=shop \
  -p "127.0.0.1:$PORT:3306" "$IMAGE" ${ARGS[@]+"${ARGS[@]}"} >/dev/null
# As root, over TCP: the image's first-run server listens on a socket only.
root() { timeout 30 docker exec -i -e MYSQL_PWD=local-test-only-pw "$NAME" $CLI -h127.0.0.1 -uroot --default-character-set=utf8mb4 -N "$@"; }
ok=0
for _ in $(seq 1 240); do
  if timeout 10 docker exec "$NAME" $CLI -h127.0.0.1 -uroot -plocal-test-only-pw -e 'SELECT 1' >/dev/null 2>&1; then
    ok=$((ok + 1)); [ $ok -ge 3 ] && break
  else
    ok=0
  fi
  sleep 0.5
done
[ $ok -ge 3 ] || fail "$IMAGE did not become ready"

root shop <<'SQL'
SET SESSION sql_mode = '';
CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL);
CREATE TABLE orders (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  status VARCHAR(20) NOT NULL,
  total DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (customer_id) REFERENCES customers (id)
);
CREATE TABLE items (
  id INT PRIMARY KEY,
  qty INT NOT NULL,
  price DECIMAL(8,2) NOT NULL,
  line_total DECIMAL(12,2) AS (qty * price) STORED,
  label VARCHAR(40) AS (CONCAT('qty ', qty)) VIRTUAL
);
CREATE TABLE kinds (
  id INT PRIMARY KEY,
  doc JSON,
  amount DECIMAL(30,10),
  happened DATETIME(6),
  stamp TIMESTAMP(3) NULL,
  data BLOB,
  bin BINARY(4),
  code CHAR(5),
  size ENUM('small','medium','it''s large'),
  flags SET('a','b','c'),
  ratio FLOAT,
  score DOUBLE,
  big BIGINT UNSIGNED,
  tiny TINYINT UNSIGNED,
  span TIME(2),
  day DATE,
  yr YEAR,
  bits BIT(10),
  note VARCHAR(40),
  latin VARCHAR(20) CHARACTER SET latin1,
  maybe INT NULL,
  lsize ENUM('small','große') CHARACTER SET latin1,
  lflags SET('a','ü') CHARACTER SET latin1,
  span6 TIME(6)
);
-- mysql_common misreads negative TIME(2) values with a fraction.
CREATE TABLE clock (id INT PRIMARY KEY, span TIME(2));
INSERT INTO clock VALUES (1, '-01:00:00.50');
CREATE TABLE shifty (id INT PRIMARY KEY, a VARCHAR(20), b VARCHAR(20));
INSERT INTO shifty VALUES (1, 'a1', 'b1');
CREATE TABLE notes (
  id INT PRIMARY KEY,
  customer_id INT NOT NULL,
  body VARCHAR(40) NOT NULL,
  FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE CASCADE
);
INSERT INTO customers VALUES (1, 'Acme'), (2, 'Globex'), (3, 'Initech'), (4, 'Umbrella'), (5, 'Hooli');
INSERT INTO notes VALUES (1, 5, 'call back');
INSERT INTO orders (customer_id, status, total) VALUES (1, 'paid', 10.50), (2, 'paid', 20.00), (3, 'paid', 30.25), (4, 'paid', 1.00);
INSERT INTO items (id, qty, price) VALUES (1, 2, 3.50), (2, 5, 1.10);
INSERT INTO kinds VALUES
  (1, '{"a": [1, 2.5, "x"], "b": {"c": null}}', 12345678901234567890.0123456789, '2026-10-09 08:07:06.123456',
   '2026-10-09 08:07:06.500', X'00FF10', X'01020304', 'ab', 'it''s large', 'a,c', 0.1, 1e-300, 18446744073709551615, 255,
   '-838:59:59.00', '2026-02-28', 2026, b'1010101010', 'Grüße, 世界 😀 \\ \'q\' \t', 'café', NULL, 'große', 'a,ü', '-00:00:01.000001'),
  (2, '[]', -0.0000000001, '1000-01-01 00:00:00', '1970-01-01 00:00:01.000', '', X'00000000', '', 'small', '', -3.4e38, -0.0,
   0, 0, '00:00:00.01', '0000-00-00', 0, b'0', '', '', 7, 'small', '', '-12:34:56.5');
SQL
root -e "CREATE USER 'ariodb'@'%' IDENTIFIED BY 'gateway-test-only-pw';
  CREATE USER 'ariodb_journal'@'%' IDENTIFIED BY 'journal-test-only-pw';
  GRANT SELECT, INSERT, UPDATE, DELETE ON shop.* TO 'ariodb'@'%';
  GRANT CREATE ON ariodb.* TO 'ariodb_journal'@'%';
  GRANT REPLICATION CLIENT ON *.* TO 'ariodb_journal'@'%';"
root -e "CREATE USER 'human'@'%' IDENTIFIED BY 'human-test-only-pw'; GRANT ALL ON shop.* TO 'human'@'%';"

cat > "$WORK/ariodb.toml" <<EOF
[database]
url = "postgres://unused@127.0.0.1:1/unused"

[proxy]
listen = ""

[journal]
enabled = false
dir = "$WORK/state"

[dashboard]
listen = "127.0.0.1:$DASH"
public_url = "http://127.0.0.1:$DASH"

[mysql]
listen = "127.0.0.1:$LISTEN"
addr = "127.0.0.1:$PORT"
database = "shop"
user = "ariodb"
password_env = "E2E_MYSQL_PASSWORD"
journal_user = "ariodb_journal"
journal_password_env = "E2E_MYSQL_JOURNAL_PASSWORD"
server_id = 4242

[[agents]]
name = "shop-agent"
access = "read_only"
tables = ["unused"]
token_env = "E2E_AGENT_TOKEN"

[agents.mysql]
access = "read_write"
tables = ["customers", "orders", "items", "kinds", "notes", "clock", "shifty"]
EOF
export E2E_MYSQL_PASSWORD=gateway-test-only-pw E2E_MYSQL_JOURNAL_PASSWORD=journal-test-only-pw
export E2E_AGENT_TOKEN=agent-token-test-only
CFG=(--config "$WORK/ariodb.toml")
ario() { timeout 60 $BIN "${CFG[@]}" "$@" 2>&1; }

echo "setup and doctor"
DOC=$(ario doctor || true)
expect "doctor: undo needs setup first" "no   MySQL undo of agent sessions: not set up (run ariodb setup)" "$DOC"
expect "doctor: the Postgres side is skipped when it is off" "what works here" "$DOC"
refute "doctor: no Postgres lines without Postgres" "default login" "$DOC"
OUT=$(ario setup) || { echo "$OUT"; fail "setup runs"; }
expect "setup checks the binlog" "ok   binlog_format is ROW" "$OUT"
expect "setup creates the tag table" "ok   tag table ariodb.session_tags is ready" "$OUT"
expect "setup records where the journal starts" "ok   the journal will record changes from" "$OUT"
expect "setup prints the gateway's grants" "GRANT PROCESS ON *.* TO 'ariodb'@'%';" "$OUT"
grep '^  GRANT' <<<"$OUT" | sed 's/--.*$//' > "$WORK/grants.sql"
root < "$WORK/grants.sql" || fail "the printed grants run"
pass "the printed grants run"
expect "setup runs again" "ok   the journal continues from" "$(ario setup)"
DOC=$(ario doctor) || { echo "$DOC"; fail "doctor passes after setup"; }
expect "doctor: reads are forced read-only" "yes  MySQL reads, forced read-only" "$DOC"
expect "doctor: READ ONLY is enforced by the server" "the server enforces them" "$DOC"
expect "doctor: writes are counted" "a 1-row test write counted 1" "$DOC"
expect "doctor: writes can be checked" "yes  MySQL writes, checked before commit" "$DOC"
expect "doctor: the binlog can be read" "the binlog can be read (REPLICATION SLAVE)" "$DOC"
expect "doctor: undo works after setup" "yes  MySQL undo of agent sessions" "$DOC"
case "$IMAGE" in
  mariadb*) expect "doctor: names the flavour" "MariaDB 11" "$DOC" ;;
  *) expect "doctor: names the flavour" "MySQL 8.4" "$DOC"
     expect "doctor: advises full row metadata" "binlog_row_metadata is MINIMAL" "$DOC" ;;
esac

$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do grep -q "MySQL journal is recording" "$WORK/serve.log" 2>/dev/null && break; sleep 0.2; done
expect "serve starts the MySQL journal" "MySQL journal is recording changes" "$(cat "$WORK/serve.log")"

# agent <session> <sql>: one transaction as the gateway writes it.
agent() {
  timeout 30 docker exec -i -e MYSQL_PWD=gateway-test-only-pw "$NAME" $CLI -h127.0.0.1 -uariodb --default-character-set=utf8mb4 shop -e \
    "START TRANSACTION; INSERT INTO ariodb.session_tags (session, agent) VALUES ('$1', 'shop-agent'); $2; COMMIT;"
}
human() {
  timeout 30 docker exec -i -e MYSQL_PWD=human-test-only-pw "$NAME" $CLI -h127.0.0.1 -uhuman --default-character-set=utf8mb4 shop -e "$1"
}
# Every row of every table, as the server prints it.
fingerprint() {
  {
    root shop -e "SELECT * FROM customers ORDER BY id; SELECT * FROM orders ORDER BY id; SELECT * FROM items ORDER BY id"
    root shop -e "SELECT *, HEX(data), HEX(bin), HEX(code), HEX(bits), HEX(latin), HEX(ratio), HEX(score), HEX(lsize), HEX(lflags) FROM kinds ORDER BY id"
  } | shasum | cut -d' ' -f1
}
# Wait until the journal has recorded what is asked.
wait_for() { # wait_for <needle> [--all]
  for _ in $(seq 1 75); do
    ario sessions | grep -qF -- "$1" && return 0
    sleep 0.2
  done
  ario sessions; fail "the journal recorded $1"
}
wait_journal() { # until the journal has read the whole binlog
  for _ in $(seq 1 75); do
    ario doctor | grep -qF "the journal has read the whole binlog" && return 0
    sleep 0.2
  done
  fail "the journal caught up"
}

echo "an agent session, undone"
human "UPDATE orders SET status = 'shipped' WHERE id = 4"
BEFORE=$(fingerprint)
S1=s-0000000a01
agent $S1 "INSERT INTO customers VALUES (100, 'New Co');
  INSERT INTO orders (customer_id, status, total) VALUES (100, 'paid', 9.99);
  UPDATE kinds SET doc = JSON_OBJECT('z', 1), amount = 1, happened = NOW(6), stamp = NULL, data = X'DEAD', bin = X'FF000000', code = 'xy',
    size = 'small', flags = 'b', ratio = 2.5, score = 3, big = 1, tiny = 1, span = '01:00:00', day = '2000-01-01', yr = 1999,
    bits = b'1', note = 'changed', latin = 'plain', maybe = 1, lsize = 'small', lflags = 'a', span6 = '00:00:00' WHERE id = 1;
  DELETE FROM kinds WHERE id = 2;
  UPDATE items SET qty = qty + 10 WHERE id IN (1, 2)"
agent $S1 "UPDATE orders SET status = 'refunded', total = 0 WHERE id IN (1, 2);
  UPDATE kinds SET note = 'changed twice' WHERE id = 1;
  INSERT INTO kinds (id, note) VALUES (3, 'brand new')"
human "UPDATE customers SET name = 'Initech Ltd' WHERE id = 3"
wait_for $S1
SESSIONS=$(ario sessions)
expect "sessions lists the agent session" "shop-agent" "$SESSIONS"
refute "the tag table itself is not a session's change" "session_tags" "$SESSIONS"
grep -F $S1 <<<"$SESSIONS" | grep -q " 2 *10 " || { echo "$SESSIONS"; fail "2 transactions, 10 rows"; }
pass "2 transactions, 10 rows"
[ "$(grep -c '^s-' <<<"$SESSIONS")" = 1 ] && pass "untagged changes are not a session" || { echo "$SESSIONS"; fail "untagged changes are not a session"; }
PLAN=$(ario undo --session $S1)
expect "the plan restores updated rows" "restore shop.kinds row (1)" "$PLAN"
expect "the plan re-inserts deleted rows" "re-insert deleted shop.kinds row (2)" "$PLAN"
expect "the plan deletes inserted rows" "delete inserted shop.customers row (100)" "$PLAN"
expect "one step per row" "undo plan for $S1: 9 steps" "$PLAN"
expect "the plan changes nothing" "nothing changed" "$PLAN"
[ "$(fingerprint)" != "$BEFORE" ] || fail "the session changed data"
human "UPDATE customers SET name = 'Initech' WHERE id = 3"
OUT=$(ario undo --session $S1 --apply) || { echo "$OUT"; fail "undo applies"; }
expect "undo restores every row in one transaction" "undone: 9 rows restored in one transaction" "$OUT"
[ "$(fingerprint)" = "$BEFORE" ] && pass "data identical to before, every type exactly" || fail "data differs after undo"
expect "a second undo is refused" "already undone" "$(ario undo --session $S1 --apply || true)"
wait_journal
expect "the undo is recorded and the session marked undone" "undone" "$(ario sessions | grep -F $S1)"

echo "conflicts"
S2=s-0000000b02
agent $S2 "UPDATE orders SET status = 'agent' WHERE id IN (1, 2)"
human "UPDATE orders SET status = 'human fix' WHERE id = 1"
wait_for $S2
wait_journal
OUT=$(ario undo --session $S2 --apply || true)
expect "a later change by someone else blocks undo" "changed by others" "$OUT"
expect "and names who" "was changed later by someone outside ariodb" "$OUT"
expect "nothing was undone" "agent" "$(root shop -e "SELECT status FROM orders WHERE id = 2")"
ario undo --session $S2 --apply --skip-conflicts >/dev/null || fail "undo with --skip-conflicts"
expect "the human's change is kept" "human fix" "$(root shop -e "SELECT status FROM orders WHERE id = 1")"
expect "the other row is restored" "paid" "$(root shop -e "SELECT status FROM orders WHERE id = 2")"

# A change the binlog never saw is still caught: the live row differs.
S3=s-0000000c03
agent $S3 "UPDATE customers SET name = 'Agent Co' WHERE id = 2"
wait_for $S3
root shop -e "SET SESSION sql_log_bin = 0; UPDATE customers SET name = 'Off the record' WHERE id = 2"
OUT=$(ario undo --session $S3 --apply || true)
expect "a row that differs from what the session left is a conflict" "has changed since the session left it" "$OUT"
expect "and is left alone" "Off the record" "$(root shop -e "SELECT name FROM customers WHERE id = 2")"

echo "foreign keys"
S4=s-0000000d04
agent $S4 "INSERT INTO customers VALUES (200, 'Parent'); INSERT INTO orders (id, customer_id, status, total) VALUES (900, 200, 'paid', 1)"
agent $S4 "UPDATE customers SET name = 'Parent renamed' WHERE id = 200"
wait_for $S4
OUT=$(ario undo --session $S4 --apply) || { echo "$OUT"; fail "undo retries in foreign-key order"; }
expect "undo retries steps a foreign key refused" "undone: 2 rows restored" "$OUT"
expect "parent and child are gone" "0" "$(root shop -e "SELECT COUNT(*) FROM customers WHERE id = 200")"

echo "dashboard API"
D=http://127.0.0.1:$DASH
JSONH='content-type: application/json'
curl -s -m 10 -c "$WORK/cj" -X POST -H "$JSONH" -d '{"password":"dashboard-test-only-pw"}' $D/api/setup > "$WORK/setup.json"
CSRF=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['csrf'])" "$WORK/setup.json")
api() { curl -s -m 30 -b "$WORK/cj" -H "$JSONH" -H "x-ariodb-csrf: $CSRF" "$@"; }
LIST=$(api $D/api/sessions)
expect "the sessions list includes MySQL sessions" "\"session\":\"$S2\"" "$LIST"
expect "and shows which were undone" "\"undone\":true" "$LIST"
S5=s-0000000e05
agent $S5 "UPDATE customers SET name = 'Via API' WHERE id = 4"
wait_for $S5
expect "an undo plan through the API" "restore shop.customers row (4)" "$(api $D/api/sessions/$S5/plan)"
expect "undo through the API" '"restored":1' "$(api -X POST -d '{}' $D/api/sessions/$S5/undo)"
expect "API undo restored the row" "Umbrella" "$(root shop -e "SELECT name FROM customers WHERE id = 4")"
expect "the overview counts MySQL sessions" '"sessions_with_changes":5' "$(api $D/api/overview)"

echo "cascades"
S7=s-0000001007
agent $S7 "DELETE FROM customers WHERE id = 5"
wait_for $S7
OUT=$(ario undo --session $S7 --apply) || { echo "$OUT"; fail "undo of a delete that cascaded"; }
expect "undo warns that cascaded changes are not in the binlog" "may have changed rows in shop.notes (ON DELETE CASCADE)" "$OUT"
expect "the deleted row is back" "Hooli" "$(root shop -e "SELECT name FROM customers WHERE id = 5")"
expect "the cascaded row is not (the binlog never had it)" "0" "$(root shop -e "SELECT COUNT(*) FROM notes WHERE id = 1")"
S8=s-0000001108
agent $S8 "INSERT INTO customers VALUES (300, 'Temp')"
human "INSERT INTO notes VALUES (2, 300, 'human note')"
wait_for $S8
OUT=$(ario undo --session $S8 --apply || true)
expect "undo refuses a step that would cascade into rows the session never touched" "would also change 1 other rows" "$OUT"
expect "and changes nothing" "human note" "$(root shop -e "SELECT body FROM notes WHERE id = 2")"

echo "tags"
S9=s-0000001209
agent $S9 "UPDATE orders SET status = 'tagged' WHERE id = 3;
  INSERT INTO ariodb.session_tags (session, agent) VALUES ('s-00000000ff', 'someone-else')"
wait_for $S9
SESSIONS=$(ario sessions)
refute "a tag row after the first does not take the transaction over" "s-00000000ff" "$SESSIONS"
expect "the change stays with the session that made it" "orders" "$(grep -F $S9 <<<"$SESSIONS")"

echo "values the driver misreads"
S10=s-000000130a
agent $S10 "UPDATE clock SET span = '00:00:01' WHERE id = 1"
wait_for $S10
expect "undo refuses a row whose old value was not recorded" "cannot undo: shop.clock" "$(ario undo --session $S10 || true)"
S12=s-000000140c
agent $S12 "UPDATE orders SET status = 'after clock' WHERE id = 3"
wait_for $S12
pass "the journal goes on after a value it cannot read"

echo "doctor beside a running journal"
sed 's/^server_id = 4242$/server_id = 4241/' "$WORK/ariodb.toml" > "$WORK/other-id.toml"
timeout 60 $BIN --config "$WORK/other-id.toml" doctor >/dev/null 2>&1 || true
sleep 1
refute "doctor's binlog read does not disconnect a replica using the next server id" "server_id" "$(cat "$WORK/serve.log")"

echo "restart"
wait_journal
kill "$SERVE_PID"; wait "$SERVE_PID" 2>/dev/null || true; SERVE_PID=""
S6=s-0000000f06
agent $S6 "UPDATE items SET price = 9.99 WHERE id = 1"
LINES=$(wc -l < "$WORK/state/mysql-journal.jsonl")
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
wait_for $S6
pass "changes made while the journal was down are recorded on restart"
[ "$(wc -l < "$WORK/state/mysql-journal.jsonl")" -eq $((LINES + 1)) ] && pass "and nothing is recorded twice" || fail "journal lines repeated"
refute "the journal reports no errors" "MySQL journal:" "$(cat "$WORK/serve.log")"

echo "a table that changes shape while the journal is down"
kill "$SERVE_PID"; wait "$SERVE_PID" 2>/dev/null || true; SERVE_PID=""
S13=s-000000160d
agent $S13 "UPDATE shifty SET a = 'a2' WHERE id = 1"
root shop -e "ALTER TABLE shifty ADD COLUMN z VARCHAR(20) NOT NULL DEFAULT 'zz' AFTER id"
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
wait_for $S13
OUT=$(ario undo --session $S13 || true)
case "$IMAGE" in
  # binlog_row_metadata = FULL: the binlog names the columns.
  mariadb*) expect "named columns are matched by name" "restore shop.shifty row (1)" "$OUT"
     refute "and are not a conflict" "conflict" "$OUT" ;;
  *) expect "unnamed columns of a changed table are not guessed at" "cannot undo: shop.shifty" "$OUT"
     expect "and the journal says why" "has changed shape" "$(cat "$WORK/serve.log")" ;;
esac

echo "a binlog that starts again"
kill "$SERVE_PID"; wait "$SERVE_PID" 2>/dev/null || true; SERVE_PID=""
case "$IMAGE" in
  mariadb*) root -e "RESET MASTER" ;;
  *) root -e "RESET BINARY LOGS AND GTIDS" ;;
esac
# What the journal's error says to do when its binlog is gone.
mv "$WORK/state/mysql-binlog-position.json" "$WORK/position.aside"
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
S11=s-000000150b
agent $S11 "UPDATE items SET price = 1.23 WHERE id = 2"
wait_for $S11
pass "changes after the binlog starts again from file 1 are recorded"
expect "and undone" "restore shop.items row (2)" "$(ario undo --session $S11)"

echo "all MySQL journal checks passed on $IMAGE"
