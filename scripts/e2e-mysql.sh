#!/usr/bin/env bash
# End-to-end test for MySQL and MariaDB: a real server in Docker, ariodb in
# front of it, and agents using the server image's own client.
#
#   ./scripts/e2e-mysql.sh                          # mysql:8.4
#   MYSQL_IMAGE=mariadb:11.4 ./scripts/e2e-mysql.sh
#
# Needs Docker and a built ariodb (cargo build). All passwords here are
# throwaway test values.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
# Parallel runs set E2E_OFFSET and E2E_NAME so ports and names do not collide.
OFF=${E2E_OFFSET:-0}
MY=ariodb-e2e-my${E2E_NAME:+-$E2E_NAME}
LEAVER=ariodb-e2e-my-leaver${E2E_NAME:+-$E2E_NAME}
IMAGE=${MYSQL_IMAGE:-mysql:8.4}
MY_PORT=$((33306 + OFF))
PROXY=$((33307 + OFF))
WORK=$(mktemp -d)
SERVE_PID=""
cleanup() {
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
  docker rm -f "$MY" "$LEAVER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo "stopped at line $LINENO: $BASH_COMMAND" >&2' ERR

pass() { printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
expect() { if grep -qF -- "$2" <<<"$3"; then pass "$1"; else echo "$3"; fail "$1"; fi; }
expect_not() { if grep -qF -- "$2" <<<"$3"; then echo "$3"; fail "$1"; else pass "$1"; fi; }

# MariaDB images ship `mariadb` and its own TLS options.
case "$IMAGE" in
  *mariadb*) CLIENT=mariadb; PLAIN=(--skip-ssl); TLS=(--ssl --disable-ssl-verify-server-cert) ;;
  *) CLIENT=mysql; PLAIN=(--ssl-mode=DISABLED); TLS=(--ssl-mode=REQUIRED) ;;
esac

echo "starting $IMAGE"
docker rm -f "$MY" >/dev/null 2>&1 || true
docker run -d --name "$MY" -e MYSQL_ROOT_PASSWORD=local-test-only-pw -e MYSQL_DATABASE=app \
  -p 127.0.0.1:$MY_PORT:3306 "$IMAGE" >/dev/null
# Over TCP, so the temporary server the image runs during first-run setup
# (which listens on a socket only) does not count as ready.
admin() {
  local out code=0
  out=$(docker exec -i "$MY" $CLIENT -h127.0.0.1 -uroot -plocal-test-only-pw "$@" 2>&1) || code=$?
  grep -v 'Using a password' <<<"$out" || true
  return $code
}
ok=0
for _ in $(seq 1 180); do
  if docker exec "$MY" $CLIENT -h127.0.0.1 -uroot -plocal-test-only-pw -e 'SELECT 1' >/dev/null 2>&1; then
    ok=$((ok + 1)); [ $ok -ge 3 ] && break
  else
    ok=0
  fi
  sleep 1
done
[ $ok -ge 3 ] || { docker logs "$MY" 2>&1 | tail -20; fail "$IMAGE did not become ready"; }
echo "testing $IMAGE: $(admin -N -e 'SELECT VERSION()')"

admin app <<'SQL'
CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(200));
CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, customer_id INT NOT NULL,
  status VARCHAR(20) NOT NULL, total DECIMAL(10,2) NOT NULL);
CREATE TABLE secrets (id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(100));
CREATE TABLE order_log (id INT AUTO_INCREMENT PRIMARY KEY, order_id INT);
-- Each order marked 'audited' writes three log rows the agent never named.
CREATE TRIGGER orders_log AFTER UPDATE ON orders FOR EACH ROW
  INSERT INTO order_log (order_id)
  SELECT NEW.id FROM (SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3) t WHERE NEW.status = 'audited';
INSERT INTO customers
  SELECT n, CONCAT('Customer ', n), CONCAT('c', n, '@example.test')
  FROM (WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 50) SELECT n FROM s) g;
INSERT INTO orders (customer_id, status, total)
  SELECT 1 + n % 50, 'paid', n % 97 + 0.99
  FROM (WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 1000) SELECT n FROM s) g;
INSERT INTO secrets (note) VALUES ('not-a-real-secret');
CREATE DATABASE other;
CREATE TABLE other.notes (note VARCHAR(100));
INSERT INTO other.notes VALUES ('other-not-a-real-secret');
CREATE DATABASE ariodb;
CREATE TABLE ariodb.session_tags (id BIGINT AUTO_INCREMENT PRIMARY KEY, session VARCHAR(64) NOT NULL,
  agent VARCHAR(255) NOT NULL, at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3));
CREATE USER 'ariodb_gw'@'%' IDENTIFIED BY 'gw-local-test-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON app.* TO 'ariodb_gw'@'%';
GRANT SELECT ON other.* TO 'ariodb_gw'@'%';
GRANT INSERT ON ariodb.session_tags TO 'ariodb_gw'@'%';
GRANT PROCESS ON *.* TO 'ariodb_gw'@'%';
SQL

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

[limits]
max_rows_per_write = 100
statement_timeout_ms = 5000

[approvals]
timeout_seconds = 30

[mysql]
listen = "127.0.0.1:$PROXY"
addr = "127.0.0.1:$MY_PORT"
database = "app"
user = "ariodb_gw"
password_env = "E2E_MY_PASSWORD"
journal = true

[[agents]]
name = "coding-agent"
access = "read_only"
tables = ["unused"]
token_env = "E2E_AGENT_TOKEN"

[agents.mysql]
access = "read_write"
tables = ["orders", "customers"]

[[agents]]
name = "support-bot"
access = "read_only"
tables = ["unused"]
token_env = "E2E_BOT_TOKEN"

[agents.mysql]
access = "read_only"
tables = ["orders"]

[[agents]]
name = "pg-only"
access = "read_only"
tables = ["unused"]
token_env = "E2E_PGONLY_TOKEN"

[[approvers]]
name = "ops"
type = "dashboard"

[[rules]]
name = "marked-statements"
condition = "sql.engine == 'mysql' && sql.statement.contains('blocked-marker')"
verdict = "deny"
reason = "marked statements are refused on MySQL"

[[rules]]
name = "ask-dashboard"
condition = "sql.statement.contains('ask-dashboard')"
verdict = "approve"
approve = ["ops"]
reason = "marked for a human"
EOF
export E2E_MY_PASSWORD=gw-local-test-only E2E_AGENT_TOKEN=agent-token-test-only
export E2E_BOT_TOKEN=bot-token-test-only E2E_PGONLY_TOKEN=pgonly-token-test-only
T=$E2E_AGENT_TOKEN; B=$E2E_BOT_TOKEN
CFG=(--config "$WORK/ariodb.toml")

start_ariodb() {
  $BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 1 100); do
    nc -z 127.0.0.1 $PROXY 2>/dev/null && return 0
    kill -0 $SERVE_PID 2>/dev/null || { cat "$WORK/serve.log"; fail "ariodb exited"; }
    sleep 0.2
  done
  cat "$WORK/serve.log"; fail "ariodb did not start"
}
start_ariodb

# Run SQL through ariodb as an agent with the image's own client. Never fails.
agent() { # agent <user> <token> <sql> [client options]
  local user=$1 token=$2 sql=$3; shift 3
  [ $# -eq 0 ] && set -- "${PLAIN[@]}"
  docker run --rm "$IMAGE" $CLIENT -h host.docker.internal -P $PROXY -u "$user" -p"$token" \
    "$@" app -e "$sql" 2>&1 | grep -v 'Using a password' || true
}
raw() { python3 -I scripts/mysql_raw.py $PROXY "$@" 2>&1 || true; }
q() { admin app -N -e "$1"; }
tags() { q "SELECT COUNT(*) FROM ariodb.session_tags"; }

echo "logging in"
expect "agent reads with its token (caching_sha2_password)" "1000" "$(agent coding-agent $T "SELECT COUNT(*) FROM orders")"
expect "wrong token refused" "wrong token" "$(agent coding-agent not-the-token "SELECT 1")"
expect "unknown agent refused" "unknown agent" "$(agent nobody $T "SELECT 1")"
expect "agent without MySQL access refused" "no MySQL access" "$(agent pg-only $E2E_PGONLY_TOKEN "SELECT 1")"
expect "another login database refused" "may only use database 'app'" "$(docker run --rm "$IMAGE" $CLIENT -h host.docker.internal -P $PROXY -u coding-agent -p$T "${PLAIN[@]}" other -e "SELECT 1" 2>&1 || true)"
expect "mysql_native_password login works too" "ROW 1000" "$(raw coding-agent $T "Q:SELECT COUNT(*) FROM orders")"

echo "reads"
expect "several rows stream back" "Customer 50" "$(agent coding-agent $T "SELECT name FROM customers ORDER BY id")"
expect "read-only agent reads" "paid" "$(agent support-bot $B "SELECT status FROM orders WHERE id = 1")"
expect "other tables refused" "may not use table 'secrets'" "$(agent coding-agent $T "SELECT * FROM secrets")"
expect "joins are checked" "may not use table 'secrets'" "$(agent coding-agent $T "SELECT o.id FROM orders o JOIN secrets s ON s.id = o.id")"
expect "other databases refused" "may not use table 'other.notes'" "$(agent coding-agent $T "SELECT * FROM other.notes")"
expect "USE of another database refused" "ariodb: " "$(agent coding-agent $T "USE other")"

echo "writes"
expect "read-only agent cannot write" "is read only" "$(agent support-bot $B "UPDATE orders SET status = 'x' WHERE id = 1")"
expect "DROP refused" "destructive" "$(agent coding-agent $T "DROP TABLE orders")"
expect "TRUNCATE refused" "destructive" "$(agent coding-agent $T "TRUNCATE TABLE orders")"
expect "DELETE without WHERE refused" "destructive" "$(agent coding-agent $T "DELETE FROM orders")"
expect "BEGIN refused" "ariodb runs every statement in its own transaction" "$(agent coding-agent $T "BEGIN")"
expect "COMMIT refused" "ariodb runs every statement in its own transaction" "$(agent coding-agent $T "COMMIT")"
expect "autocommit cannot be switched off" "ariodb: " "$(agent coding-agent $T "SET autocommit = 0")"
expect "LOCK TABLES refused" "ariodb: " "$(agent coding-agent $T "LOCK TABLES orders WRITE")"
BEFORE=$(tags)
expect_not "a write within the limit commits" "ERROR" "$(agent coding-agent $T "UPDATE orders SET status = 'shipped' WHERE id = 5")"
expect "and changed the row" "shipped" "$(q "SELECT status FROM orders WHERE id = 5")"
expect "and its session was tagged for the journal" "$((BEFORE + 1))" "$(tags)"
expect "the tag names the agent and session" "coding-agent s-" "$(q "SELECT CONCAT(agent, ' ', session) FROM ariodb.session_tags ORDER BY id DESC LIMIT 1")"
expect_not "inserts commit" "ERROR" "$(agent coding-agent $T "INSERT INTO customers (id, name) VALUES (51, 'Customer 51')")"
expect "the insert landed" "Customer 51" "$(q "SELECT name FROM customers WHERE id = 51")"
BEFORE=$(tags)
expect "a write over the row limit is rolled back" "rolled back" "$(agent coding-agent $T "UPDATE orders SET status = 'bulk' WHERE id <= 300")"
expect "and changed nothing" "0" "$(q "SELECT COUNT(*) FROM orders WHERE status = 'bulk'")"
expect "its tag row went with it (same transaction)" "$BEFORE" "$(tags)"
# 30 orders, and three log rows each from the trigger: 120 rows, over the limit of 100.
expect "a trigger that multiplies rows is caught" "would change 120 rows" "$(agent coding-agent $T "UPDATE orders SET status = 'audited' WHERE id <= 30")"
expect "and changed nothing" "0" "$(q "SELECT COUNT(*) FROM orders WHERE status = 'audited'")"
expect "nor did the trigger" "0" "$(q "SELECT COUNT(*) FROM order_log")"
expect_not "a small triggered write commits" "ERROR" "$(agent coding-agent $T "UPDATE orders SET status = 'audited' WHERE id <= 5")"
expect "with its trigger's rows" "15" "$(q "SELECT COUNT(*) FROM order_log")"
expect "two statements in one query refused" "one statement at a time" "$(raw coding-agent $T "Q:SELECT 1; DELETE FROM orders WHERE id = 1")"
expect "LOAD DATA LOCAL refused" "ariodb: " "$(agent coding-agent $T "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE orders" "${PLAIN[@]}" --local-infile=1)"
expect "rules apply to MySQL" "marked statements are refused on MySQL" "$(agent coding-agent $T "SELECT 'blocked-marker' FROM orders LIMIT 1")"
expect "KILL of another agent's connection refused" "unknown thread id" "$(agent support-bot $B "KILL QUERY 1")"
expect "the connection keeps working after a refusal" "ROW 1000" "$(raw coding-agent $T "Q:SELECT * FROM secrets" "Q:SELECT COUNT(*) FROM orders")"

echo "prepared statements"
expect "a prepared read with a parameter" "ROW Customer 7" "$(raw coding-agent $T "P:SELECT name FROM customers WHERE id = ?" "X:7")"
expect "a refused statement is refused at prepare" "may not use table 'secrets'" "$(raw coding-agent $T "P:SELECT note FROM secrets WHERE id = ?")"
expect "a prepared write commits" "OK 1" "$(raw coding-agent $T "P:UPDATE orders SET status = ? WHERE id = 6" "X:packed")"
expect "and changed the row" "packed" "$(q "SELECT status FROM orders WHERE id = 6")"
expect "a prepared write over the limit is rolled back" "rolled back" "$(raw coding-agent $T "P:UPDATE orders SET status = ? WHERE id <= 300" "X:bulk")"
expect "and changed nothing" "0" "$(q "SELECT COUNT(*) FROM orders WHERE status = 'bulk'")"
expect "statements run again after close are unknown" "unknown prepared statement" "$(raw coding-agent $T "P:SELECT 1 FROM orders" "C" "X")"

echo "approvals"
wait_for_pending() {
  for _ in $(seq 1 100); do
    id=$($BIN "${CFG[@]}" approvals | awk '/ pending /{print $1; exit}')
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.2
  done
  fail "no pending approval appeared"
}
OUT="$WORK/held.out"
(agent coding-agent $T "SELECT 'ask-dashboard', COUNT(*) FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" approve "$ID" >/dev/null; wait $BG
expect "held statement runs once approved" "1000" "$(cat "$OUT")"
(agent coding-agent $T "UPDATE orders SET status = 'held' WHERE id = 8 AND 'ask-dashboard' <> ''" > "$OUT") & BG=$!
ID=$(wait_for_pending); $BIN "${CFG[@]}" deny "$ID" --note "not during the freeze" >/dev/null; wait $BG
expect "denied statement is refused with the note" "not during the freeze" "$(cat "$OUT")"
# An agent that leaves while its statement waits must not have it run later.
docker run -d --name "$LEAVER" "$IMAGE" $CLIENT -h host.docker.internal -P $PROXY -u coding-agent -p$T "${PLAIN[@]}" app \
  -e "UPDATE orders SET status = 'left-behind' WHERE id = 77 AND 'ask-dashboard' <> ''" >/dev/null
ID=$(wait_for_pending)
docker rm -f "$LEAVER" >/dev/null
sleep 1.5
expect "a waiting request is withdrawn when the agent disconnects" "the agent disconnected" "$($BIN "${CFG[@]}" approvals --all | grep -A1 "$ID")"
expect "and can no longer be approved" "is not pending" "$($BIN "${CFG[@]}" approve "$ID" 2>&1 || true)"
expect "so the statement never ran" "paid" "$(q "SELECT status FROM orders WHERE id = 77")"
expect "KILL QUERY from a second connection withdraws a waiting statement" "the agent cancelled the statement" "$(raw coding-agent $T "CANCEL:1.5:SELECT 'ask-dashboard', COUNT(*) FROM orders")"
expect "nothing is left waiting" "nothing waiting for approval" "$($BIN "${CFG[@]}" approvals)"

echo "decisions log"
expect "decisions are logged with their engine" "decisions log intact" "$($BIN "${CFG[@]}" audit)"

echo "TLS"
kill $SERVE_PID 2>/dev/null || true; wait $SERVE_PID 2>/dev/null || true
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal" \
  -keyout "$WORK/my.key" -out "$WORK/my.crt" >/dev/null 2>&1
# TLS to the server too, after forgetting cached logins, so ariodb's
# caching_sha2_password full authentication over TLS runs.
admin -e "FLUSH PRIVILEGES"
python3 - "$WORK/ariodb.toml" "$WORK/my.crt" "$WORK/my.key" <<'PY'
import sys
p, crt, key = sys.argv[1:]
s = open(p).read()
s = s.replace('journal = true\n', f'journal = true\ntls = "require"\ntls_cert = "{crt}"\ntls_key = "{key}"\n', 1)
open(p, "w").write(s)
PY
start_ariodb
expect "agents connect over TLS" "1000" "$(agent coding-agent $T "SELECT COUNT(*) FROM orders" "${TLS[@]}")"
expect "policy still applies over TLS" "may not use table 'secrets'" "$(agent coding-agent $T "SELECT * FROM secrets" "${TLS[@]}")"
expect_not "writes work over TLS both ways" "ERROR" "$(agent coding-agent $T "UPDATE orders SET status = 'tls' WHERE id = 9" "${TLS[@]}")"
expect "and landed" "tls" "$(q "SELECT status FROM orders WHERE id = 9")"
kill $SERVE_PID 2>/dev/null || true; wait $SERVE_PID 2>/dev/null || true
python3 - "$WORK/ariodb.toml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('journal = true\n', 'journal = true\nrequire_tls = true\n', 1)
open(p, "w").write(s)
PY
start_ariodb
expect "require_tls refuses plaintext" "must use TLS" "$(agent coding-agent $T "SELECT 1")"
expect "and accepts TLS" "1000" "$(agent coding-agent $T "SELECT COUNT(*) FROM orders" "${TLS[@]}")"
expect "the decisions log is still intact" "decisions log intact" "$($BIN "${CFG[@]}" audit)"

echo "all MySQL checks passed against $IMAGE"
