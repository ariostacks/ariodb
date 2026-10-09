#!/usr/bin/env bash
# End-to-end test of dashboard single sign-on: Keycloak in Docker with a
# realm of admins, approvers, viewers and an outsider, ariodb's dashboard
# signing them in with OpenID Connect, and a real Postgres behind the proxy
# so approvals have something to hold. The browser is played by curl: it
# follows the redirects, posts Keycloak's login form and keeps the cookies.
#
# Needs Docker, python3 and a built ariodb (cargo build). Every password,
# token and secret here is a throwaway test value. Keycloak takes minutes
# to start the first time; E2E_KEEP_KEYCLOAK=1 leaves its container running
# for the next run to reuse (remove it with docker rm -f when done).
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BIN=./target/debug/ariodb
# Parallel runs set E2E_OFFSET and E2E_NAME so ports and container names
# do not collide.
OFF=${E2E_OFFSET:-0}
PG=ariodb-e2e-sso-pg${E2E_NAME:+-$E2E_NAME}
KCC=ariodb-e2e-sso-kc${E2E_NAME:+-$E2E_NAME}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.4.0}
CLIENT=${CLIENT_IMAGE:-postgres:16}
PORT=$((37000 + OFF))
PROXY=$((37001 + OFF))
DASH=$((37002 + OFF))
KC=$((37003 + OFF))
MOCK=$((37004 + OFF))
D=http://127.0.0.1:$DASH
ISSUER=http://127.0.0.1:$KC/realms/ariodb
KC_PW=local-test-only-pw
JSONH='content-type: application/json'
WORK=$(mktemp -d)
SERVE_PID=""
MOCK_PID=""
cleanup() {
  for pid in $SERVE_PID $MOCK_PID; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  docker rm -f "$PG" >/dev/null 2>&1 || true
  [ -n "${E2E_KEEP_KEYCLOAK:-}" ] || docker rm -f "$KCC" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

export E2E_AGENT_TOKEN=local-test-only-agent-token
export E2E_HOOK_KEY=local-test-only-hook-key
export E2E_OIDC_SECRET=not-a-real-secret-local-test-only
CFG=(--config "$WORK/ariodb.toml")

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
refute() { # refute <description> <needle> <output>
  if grep -qF -- "$2" <<<"$3"; then echo "$3"; fail "$1"; else pass "$1"; fi
}
admin() { docker exec -i -e PGPASSWORD=local-test-only-pw $PG psql -q -v ON_ERROR_STOP=1 -U postgres -d app "$@"; }
# Run SQL through the proxy as the agent. Prints psql output, never fails.
agent() {
  docker run "${HOST_NET[@]}" --rm -e PGPASSWORD="$E2E_AGENT_TOKEN" $CLIENT \
    psql "host=host.docker.internal port=$PROXY user=coding-agent dbname=app sslmode=disable" -c "$1" 2>&1 || true
}
# Print the id of the newest pending approval, waiting for it to appear.
wait_for_pending() {
  for _ in $(seq 1 100); do
    id=$($BIN "${CFG[@]}" approvals | awk '/ pending /{print $1; exit}')
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.2
  done
  fail "no pending approval appeared"
}
json() { # json <python expression on d> : read JSON on stdin
  python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"
}
urlencode() { python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# The browser, played by curl. Each person has a cookie jar.
cat > "$WORK/form.py" <<'PY'
import html.parser, sys
class Form(html.parser.HTMLParser):
    action = ""
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("id") == "kc-form-login":
            Form.action = a.get("action") or ""
Form().feed(sys.stdin.read())
print(Form.action)
PY
# Open ariodb's sign-in link and Keycloak's login page; print the form's address.
kc_form() { # kc_form <jar> <next>
  rm -f "$1"
  curl -s -L -c "$1" -b "$1" -o "$WORK/kc.html" "$D/auth/login?next=$(urlencode "$2")"
  local action
  action=$(python3 -I "$WORK/form.py" < "$WORK/kc.html")
  [ -n "$action" ] || { head -c 3000 "$WORK/kc.html"; fail "no Keycloak login form"; }
  echo "$action"
}
# Sign in through Keycloak, following every redirect back to ariodb. Prints
# the final status and address; the final page is left in $WORK/page.html.
sso_login() { # sso_login <jar> <user> [next]
  local action
  action=$(kc_form "$1" "${3:-/}")
  curl -s -L -c "$1" -b "$1" -o "$WORK/page.html" -w '%{http_code} %{url_effective}' \
    --data-urlencode "username=$2" --data-urlencode "password=$KC_PW" "$action"
}
# Sign in at Keycloak but stop before ariodb: print the callback address.
kc_callback() { # kc_callback <jar> <user>
  local action
  action=$(kc_form "$1" /)
  curl -s -c "$1" -b "$1" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=$2" --data-urlencode "password=$KC_PW" "$action"
}
csrf_of() { curl -s -b "$1" $D/api/me | json 'd.get("csrf") or ""'; }
api_as() { # api_as <jar> <curl args...>
  local jar=$1; shift
  curl -s -b "$jar" -H "$JSONH" -H "x-ariodb-csrf: $(csrf_of "$jar")" "$@"
}
reloads() { grep -c "reloaded" "$WORK/serve.log" || true; }
# Rewrite the config with extra [dashboard.oidc] (and [dashboard]) lines
# and wait for ariodb to reload it.
reconfigure() { # reconfigure <extra oidc lines> [extra dashboard lines]
  local before
  before=$(reloads)
  write_config "$1" "${2:-}"
  for _ in $(seq 1 50); do
    [ "$(reloads)" -gt "$before" ] && return 0
    sleep 0.2
  done
  cat "$WORK/serve.log"; fail "ariodb did not reload its config"
}

echo "starting Keycloak and Postgres"
docker rm -f $PG >/dev/null 2>&1 || true
REUSE=""
if [ -n "${E2E_KEEP_KEYCLOAK:-}" ] && curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; then
  REUSE=1
else
  docker rm -f $KCC >/dev/null 2>&1 || true
fi
# A realm with a client for ariodb, a groups scope whose mapper puts group
# names in the ID token, and one user per role (plus one in no group).
user_json() { # user_json <name> <groups as JSON>
  cat <<EOF
    {"username": "$1", "enabled": true, "email": "$1@example.test", "emailVerified": true,
     "firstName": "$1", "lastName": "Test", "groups": $2,
     "credentials": [{"type": "password", "value": "$KC_PW", "temporary": false}]}
EOF
}
mapper() { # mapper <name> <type> <config JSON>
  echo "{\"name\": \"$1\", \"protocol\": \"openid-connect\", \"protocolMapper\": \"$2\", \"config\": $3}"
}
ALL='"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"'
mkdir "$WORK/import"
cat > "$WORK/import/ariodb-realm.json" <<EOF
{
  "realm": "ariodb",
  "enabled": true,
  "sslRequired": "none",
  "groups": [{"name": "ariodb-admins"}, {"name": "ariodb-approvers"}, {"name": "ariodb-viewers"}, {"name": "dba"}],
  "clientScopes": [
    {"name": "basic", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "false"},
     "protocolMappers": [$(mapper sub oidc-sub-mapper '{"access.token.claim": "true", "introspection.token.claim": "true"}')]},
    {"name": "profile", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"},
     "protocolMappers": [$(mapper username oidc-usermodel-attribute-mapper "{\"user.attribute\": \"username\", \"claim.name\": \"preferred_username\", \"jsonType.label\": \"String\", $ALL}")]},
    {"name": "email", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"},
     "protocolMappers": [
       $(mapper email oidc-usermodel-attribute-mapper "{\"user.attribute\": \"email\", \"claim.name\": \"email\", \"jsonType.label\": \"String\", $ALL}"),
       $(mapper "email verified" oidc-usermodel-property-mapper "{\"user.attribute\": \"emailVerified\", \"claim.name\": \"email_verified\", \"jsonType.label\": \"boolean\", $ALL}")]},
    {"name": "groups", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"},
     "protocolMappers": [$(mapper groups oidc-group-membership-mapper "{\"full.path\": \"false\", \"claim.name\": \"groups\", $ALL}")]}
  ],
  "clients": [{
    "clientId": "ariodb", "enabled": true, "protocol": "openid-connect",
    "publicClient": false, "clientAuthenticatorType": "client-secret", "secret": "$E2E_OIDC_SECRET",
    "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false,
    "redirectUris": ["$D/auth/callback"],
    "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "$D/*"},
    "defaultClientScopes": ["basic", "profile", "email"],
    "optionalClientScopes": ["groups"]
  }],
  "users": [
$(user_json admin-user '["/ariodb-admins"]'),
$(user_json approver-user '["/ariodb-approvers"]'),
$(user_json dba-user '["/ariodb-approvers", "/dba"]'),
$(user_json viewer-user '["/ariodb-viewers"]'),
$(user_json outsider '[]')
  ]
}
EOF
python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$WORK/import/ariodb-realm.json" ||
  fail "the realm file is not valid JSON"
if [ -z "$REUSE" ]; then
  docker create --name $KCC -p 127.0.0.1:$KC:8080 $KC_IMAGE \
    start-dev --import-realm --hostname="http://127.0.0.1:$KC" >/dev/null
  chmod 755 "$WORK/import" && chmod 644 "$WORK/import/ariodb-realm.json"
  docker cp "$WORK/import" $KCC:/opt/keycloak/data/import
  docker start $KCC >/dev/null
fi
docker run -d --name $PG -e POSTGRES_PASSWORD=local-test-only-pw -e POSTGRES_DB=app \
  -p 127.0.0.1:$PORT:5432 postgres:16 >/dev/null
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
CREATE TABLE orders (id int PRIMARY KEY, status text NOT NULL);
INSERT INTO orders SELECT g, 'paid' FROM generate_series(1, 20) g;
CREATE ROLE ariodb_gw LOGIN PASSWORD 'gw-local-test-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ariodb_gw;
SQL
# Keycloak's first start in development mode builds itself, which takes a
# few minutes on a busy machine.
for _ in $(seq 1 600); do
  curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' $KCC 2>/dev/null | grep -q true || break
  sleep 1
done
curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null || { docker logs $KCC 2>&1 | tail -30; fail "Keycloak did not start"; }
pass "Keycloak serves the realm's discovery document"

write_config() { # write_config <extra [dashboard.oidc] lines> [extra [dashboard] lines]
  cat > "$WORK/ariodb.tmp" <<EOF
[database]
url = "postgres://ariodb_gw:gw-local-test-only@127.0.0.1:$PORT/app"

[proxy]
listen = "127.0.0.1:$PROXY"

[journal]
enabled = false
dir = "$WORK/state"

[approvals]
timeout_seconds = 60

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders"]
token_env = "E2E_AGENT_TOKEN"

[[approvers]]
name = "ops"
type = "dashboard"

[[approvers]]
name = "dba-ops"
type = "dashboard"
groups = ["dba"]

[[approvers]]
name = "pager"
type = "webhook"
url = "http://127.0.0.1:$MOCK/hook"
hmac_secret_env = "E2E_HOOK_KEY"

[[rules]]
name = "ask-ops"
condition = "sql.statement.contains('/*ask-ops*/')"
verdict = "approve"
approve = ["ops"]

[[rules]]
name = "ask-dba"
condition = "sql.statement.contains('/*ask-dba*/')"
verdict = "approve"
approve = ["dba-ops"]

[[rules]]
name = "ask-hook"
condition = "sql.statement.contains('/*ask-hook*/')"
verdict = "approve"
approve = ["pager"]

[dashboard]
listen = "127.0.0.1:$DASH"
public_url = "$D"
${2:-}

[dashboard.oidc]
issuer = "$ISSUER"
provider_name = "Keycloak"
client_id = "ariodb"
client_secret_env = "E2E_OIDC_SECRET"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers"]
logout_at_provider = true
$1
EOF
  mv "$WORK/ariodb.tmp" "$WORK/ariodb.toml"
}
VIEWERS='viewer_groups = ["ariodb-viewers"]'
write_config "$VIEWERS"
$BIN "${CFG[@]}" check >/dev/null || fail "the config does not check"
python3 -I scripts/mock_services.py $MOCK "$WORK/mock.log" &
MOCK_PID=$!
$BIN "${CFG[@]}" serve >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  port_open $DASH && port_open $PROXY && break
  kill -0 $SERVE_PID 2>/dev/null || { cat "$WORK/serve.log"; fail "ariodb exited"; }
  sleep 0.2
done

echo "signing in"
ME=$(curl -s $D/api/me)
expect "the sign-in page offers Keycloak" '"provider":"Keycloak"' "$ME"
expect "and a break-glass password by default" '"password_login":"break_glass"' "$ME"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$D/auth/login")
expect "sign-in goes to Keycloak's authorisation endpoint" "$ISSUER/protocol/openid-connect/auth?" "$LOC"
expect "with PKCE" "code_challenge_method=S256" "$LOC"
expect "and a nonce" "&nonce=" "$LOC"
expect "asking for the groups scope" "scope=openid+profile+email+groups" "$LOC"
for who in admin approver viewer dba; do
  RESULT=$(sso_login "$WORK/$who.jar" "$who-user")
  expect "$who-user signs in and lands on the dashboard" "200 $D/" "$RESULT"
done
expect "an admin gets the admin role" '"role":"admin"' "$(curl -s -b "$WORK/admin.jar" $D/api/me)"
ME=$(curl -s -b "$WORK/approver.jar" $D/api/me)
expect "an approver gets the approver role" '"role":"approver"' "$ME"
expect "signed in with single sign-on" '"method":"sso"' "$ME"
expect "with the email Keycloak sent" '"email":"approver-user@example.test"' "$ME"
expect "a viewer gets the viewer role" '"role":"viewer"' "$(curl -s -b "$WORK/viewer.jar" $D/api/me)"
expect "the highest of several groups wins" '"groups":["ariodb-approvers","dba"]' "$(curl -s -b "$WORK/dba.jar" $D/api/me)"
RESULT=$(sso_login "$WORK/outsider.jar" outsider)
expect "someone in no mapped group is refused" "403" "$RESULT"
expect "and told why" "not in any group that may use this dashboard" "$(cat "$WORK/page.html")"
expect "and has no session" '"user":null' "$(curl -s -b "$WORK/outsider.jar" $D/api/me)"
RESULT=$(sso_login "$WORK/deep.jar" viewer-user /decisions)
expect "sign-in returns to the page asked for" "200 $D/decisions" "$RESULT"

echo "the callback"
expect "a callback with a forged state is refused" "expired or was already used" \
  "$(curl -s -b "$WORK/approver.jar" "$D/auth/callback?state=forged-state&code=forged-code")"
CB=$(kc_callback "$WORK/cb.jar" approver-user)
expect "Keycloak sends the browser back with a code" "$D/auth/callback?" "$CB"
expect "a callback in another browser is refused" "started in another browser" "$(curl -s "$CB")"
expect "and it cannot be used again where it began" "expired or was already used" "$(curl -s -b "$WORK/cb.jar" "$CB")"
CB=$(kc_callback "$WORK/cb.jar" approver-user)
expect "a callback with the state changed is refused" "expired or was already used" \
  "$(curl -s -b "$WORK/cb.jar" "${CB/state=/state=x}")"
CB=$(kc_callback "$WORK/cb.jar" approver-user)
expect "a callback in the right browser signs in" "303" "$(curl -s -o /dev/null -w '%{http_code}' -c "$WORK/cb.jar" -b "$WORK/cb.jar" "$CB")"
expect "once" "already used" "$(curl -s -b "$WORK/cb.jar" "$CB")"

echo "roles on the API"
expect "a viewer reads the overview" '"version"' "$(curl -s -b "$WORK/viewer.jar" $D/api/overview)"
expect "a viewer reads decisions" '"decisions"' "$(curl -s -b "$WORK/viewer.jar" $D/api/decisions)"
expect "a viewer cannot read the config" "needs the admin role" "$(curl -s -b "$WORK/viewer.jar" $D/api/config)"
expect "a viewer cannot list users" "needs the admin role" "$(curl -s -b "$WORK/viewer.jar" $D/api/users)"
expect "an approver cannot read the config" "needs the admin role" "$(curl -s -b "$WORK/approver.jar" $D/api/config)"
expect "an approver cannot edit the config" "needs the admin role" \
  "$(api_as "$WORK/approver.jar" -X PUT -d '{"text":"[database]\nurl = \"postgres://x@y/z\""}' $D/api/config)"
expect "an approver cannot add users" "needs the admin role" \
  "$(api_as "$WORK/approver.jar" -X POST -d '{"name":"mallory","password":"local-test-only-pw-2"}' $D/api/users)"
expect "an approver cannot set secrets" "needs the admin role" \
  "$(api_as "$WORK/approver.jar" -X POST -d '{"value":"not-a-real-value"}' $D/api/secrets/x)"
expect "an approver cannot block like this" "needs the admin role" \
  "$(api_as "$WORK/approver.jar" -X POST -d '{"decision":1,"apply":false}' $D/api/block-like)"
expect "an admin reads the config" '"text"' "$(curl -s -b "$WORK/admin.jar" $D/api/config)"
expect "an admin lists users" '"users"' "$(curl -s -b "$WORK/admin.jar" $D/api/users)"
expect "changes still need the CSRF token" "CSRF" \
  "$(curl -s -b "$WORK/admin.jar" -H "$JSONH" -X POST -d '{"name":"x","password":"local-test-only-pw-3"}' $D/api/users)"

echo "approvals"
OUT="$WORK/held.out"
(agent "SELECT /*ask-ops*/ count(*) FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending)
expect "a viewer sees the request" "$ID" "$(curl -s -b "$WORK/viewer.jar" $D/api/approvals)"
expect "and is told it may not decide it" '"you_may_decide":false' "$(curl -s -b "$WORK/viewer.jar" $D/api/approvals)"
expect "a viewer cannot decide" "needs the approver role" \
  "$(api_as "$WORK/viewer.jar" -X POST -d '{"verdict":"allow"}' $D/api/approvals/$ID)"
expect "an approver decides" '"ok":true' "$(api_as "$WORK/approver.jar" -X POST -d '{"verdict":"allow"}' $D/api/approvals/$ID)"
wait $BG
expect "the approved statement runs" "(1 row)" "$(cat "$OUT")"
expect "the approver is recorded by their single sign-on name" "sso:approver-user@example.test" \
  "$($BIN "${CFG[@]}" approvals --all | grep "$ID")"

(agent "SELECT /*ask-dba*/ count(*) FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending)
LIST=$(curl -s -b "$WORK/approver.jar" $D/api/approvals)
expect "the approvals list says which groups decide" '"decider_groups":["dba"]' "$LIST"
expect "and that this approver may not" '"you_may_decide":false' "$LIST"
expect "an approver outside the approver's groups cannot decide" "only members of dba" \
  "$(api_as "$WORK/approver.jar" -X POST -d '{"verdict":"allow"}' $D/api/approvals/$ID)"
expect "even an admin outside them cannot" "only members of dba" \
  "$(api_as "$WORK/admin.jar" -X POST -d '{"verdict":"allow"}' $D/api/approvals/$ID)"
expect "a member of the group decides" '"ok":true' "$(api_as "$WORK/dba.jar" -X POST -d '{"verdict":"deny","note":"not today"}' $D/api/approvals/$ID)"
wait $BG
expect "the denied statement is refused" "not today" "$(cat "$OUT")"

echo "approval links"
(agent "SELECT /*ask-hook*/ count(*), 'no-answer' FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending)
for _ in $(seq 1 50); do grep -q no-answer "$WORK/mock.log" && break; sleep 0.2; done
LINK=$(grep no-answer "$WORK/mock.log" | tail -1 | json 'd["body"]["approve_url"]')
PAGE=$(curl -s "$LINK")
expect "opening a link without signing in asks for sign-in" "Sign in to decide this request" "$PAGE"
expect "with Keycloak" "Sign in with Keycloak" "$PAGE"
refute "and shows no button" "Approve this request" "$PAGE"
expect "a POST to the link without signing in decides nothing" "Sign in to decide" "$(curl -s -X POST "$LINK")"
expect "so the request still waits" "pending" "$($BIN "${CFG[@]}" approvals | grep "$ID")"
expect "a viewer may not use the link" "may not decide this request" "$(curl -s -b "$WORK/viewer.jar" "$LINK")"
RESULT=$(sso_login "$WORK/link.jar" approver-user "${LINK#"$D"}")
expect "signing in from the link comes back to it" "200 $LINK" "$RESULT"
PAGE=$(cat "$WORK/page.html")
expect "which now offers the button" "Approve this request" "$PAGE"
expect "and says who will be recorded" "Signed in as <b>approver-user@example.test</b>" "$PAGE"
FORM_CSRF=$(python3 -I -c 'import re,sys; print(re.search(r"name=\"csrf\" value=\"([0-9a-f]+)\"", sys.stdin.read()).group(1))' <<<"$PAGE")
expect "the button needs the page's CSRF token" "out of date" "$(curl -s -b "$WORK/link.jar" -X POST "$LINK")"
expect "a cross-site post is refused" "out of date" \
  "$(curl -s -b "$WORK/link.jar" -H 'Origin: http://evil.example' --data-urlencode "csrf=$FORM_CSRF" -X POST "$LINK")"
expect "the button records the decision" "Recorded: approved" \
  "$(curl -s -b "$WORK/link.jar" --data-urlencode "csrf=$FORM_CSRF" -X POST "$LINK")"
wait $BG
expect "the link-approved statement runs" "(1 row)" "$(cat "$OUT")"
expect "the signed-in approver is the decider, not the link" "sso:approver-user@example.test" \
  "$($BIN "${CFG[@]}" approvals --all | grep "$ID")"

echo "decisions by approver"
BY=$(curl -s -b "$WORK/viewer.jar" "$D/api/decisions?decided_by=$(urlencode sso:dba-user@example.test)")
expect "decisions filter by who decided" "ask-dba" "$BY"
refute "and leave out the rest" "no-answer" "$BY"
expect "each decision says who decided it" '"decided_by":["sso:dba-user@example.test"]' "$BY"
PEOPLE=$(curl -s -b "$WORK/viewer.jar" "$D/api/decisions?decided_by_kind=person")
expect "decisions decided by a person" "no-answer" "$PEOPLE"
refute "models decided none of these" "ask-" "$(curl -s -b "$WORK/viewer.jar" "$D/api/decisions?decided_by_kind=model" | json '[x["sql"] for x in d["decisions"]]')"
expect "the deciders are offered for the filter" '"deciders":[' "$PEOPLE"
expect "a bad kind is refused" "must be person, model or plugin" "$(curl -s -b "$WORK/viewer.jar" "$D/api/decisions?decided_by_kind=robot")"

echo "signing out"
OUTJSON=$(api_as "$WORK/approver.jar" -X POST $D/api/logout)
expect "sign-out answers" '"ok":true' "$OUTJSON"
expect "and offers Keycloak's logout" "$ISSUER/protocol/openid-connect/logout?client_id=ariodb" "$OUTJSON"
expect "the session has ended" '"user":null' "$(curl -s -b "$WORK/approver.jar" $D/api/me)"
expect "and the API refuses it" "log in first" "$(curl -s -b "$WORK/approver.jar" $D/api/overview)"

echo "local passwords"
expect "first-run setup is off under single sign-on" "single sign-on is configured" \
  "$(curl -s -X POST -H "$JSONH" -d '{"password":"local-test-only-root-pw"}' $D/api/setup)"
printf 'local-test-only-root-pw\n' | $BIN "${CFG[@]}" dashboard-password >/dev/null
printf 'local-test-only-view-pw\n' | $BIN "${CFG[@]}" dashboard-password --user watcher --role viewer >/dev/null
LOGIN=$(curl -s -c "$WORK/root.jar" -X POST -H "$JSONH" -d '{"user":"root","password":"local-test-only-root-pw"}' $D/api/login)
expect "break-glass root signs in with a password" '"role":"admin"' "$LOGIN"
expect "as a password session" '"method":"password"' "$LOGIN"
LOGIN=$(curl -s -c "$WORK/watcher.jar" -X POST -H "$JSONH" -d '{"user":"watcher","password":"local-test-only-view-pw"}' $D/api/login)
expect "a local user has their own role" '"role":"viewer"' "$LOGIN"
expect "which the API enforces" "needs the admin role" "$(curl -s -b "$WORK/watcher.jar" $D/api/users)"
expect "an admin changes a local user's role" '"ok":true' \
  "$(api_as "$WORK/root.jar" -X POST -d '{"role":"approver"}' $D/api/users/watcher/role)"
expect "which applies at once" '"role":"approver"' "$(curl -s -b "$WORK/watcher.jar" $D/api/me)"
expect "root stays an admin" "root is always an admin" \
  "$(api_as "$WORK/root.jar" -X POST -d '{"role":"viewer"}' $D/api/users/root/role)"
reconfigure "$VIEWERS
password_login = \"off\""
expect "the sign-in page says passwords are off" '"password_login":"off"' "$(curl -s $D/api/me)"
expect "password sign-in is refused when switched off" "local passwords are switched off" \
  "$(curl -s -X POST -H "$JSONH" -d '{"user":"root","password":"local-test-only-root-pw"}' $D/api/login)"
expect "and existing password sessions end" "log in first" "$(curl -s -b "$WORK/root.jar" $D/api/overview)"
expect "while single sign-on sessions carry on" '"version"' "$(curl -s -b "$WORK/admin.jar" $D/api/overview)"

echo "config changes apply to signed-in people"
reconfigure 'allowed_email_domains = ["example.org"]'
expect "a viewer whose group no longer maps to a role is signed out" "log in first" \
  "$(curl -s -b "$WORK/viewer.jar" $D/api/overview)"
RESULT=$(sso_login "$WORK/elsewhere.jar" approver-user)
expect "an email outside the allowed domains is refused" "403" "$RESULT"
expect "and told why" "not in a domain allowed" "$(cat "$WORK/page.html")"

echo "signed links without single sign-on's check"
reconfigure "$VIEWERS" 'approval_links = "signed"'
(agent "SELECT /*ask-hook*/ count(*), 'no-answer-2' FROM orders" > "$OUT") & BG=$!
ID=$(wait_for_pending)
for _ in $(seq 1 50); do grep -q no-answer-2 "$WORK/mock.log" && break; sleep 0.2; done
LINK=$(grep no-answer-2 "$WORK/mock.log" | tail -1 | json 'd["body"]["approve_url"]')
expect "with approval_links = signed, the link alone decides" "Recorded: approved" "$(curl -s -X POST "$LINK")"
wait $BG
expect "recorded as the link" " webhook" "$($BIN "${CFG[@]}" approvals --all | grep "$ID")"

grep -q "panicked" "$WORK/serve.log" && { cat "$WORK/serve.log"; fail "ariodb panicked"; }
echo "all single sign-on checks passed"
