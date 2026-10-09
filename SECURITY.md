# Security

ariodb sits between AI agents and production databases. This page sets out
what it defends against, what it does not, what the October 2026 review
found and fixed, and how to report a vulnerability.

## Threat model

### Who we defend against

1. **An agent that sends hostile SQL.** Assume the agent, or whoever can
   steer it (a prompt injection in a ticket, a web page or a database row),
   writes every byte of every statement and every protocol message it sends
   to the Postgres proxy, the ClickHouse HTTP and native proxies, and the
   MCP server. It holds a valid agent token.
2. **Someone on the network who can reach the dashboard** and its callback
   endpoints (`/hooks/approvals/...`, `/slack/actions`), with no account, or
   with a stolen or phished link.
3. **Content that reaches a person or a model approver.** Agent SQL is shown
   in Slack, in webhook payloads, on the dashboard and to the model approver,
   and must not be able to change what they see or decide.

### What ariodb is meant to guarantee

- An agent only runs statements the built-in policy and the rules allow,
  against the tables its allow-list names.
- Reads run in `READ ONLY` transactions; writes are measured before commit
  (rows changed, tables changed, including by triggers and cascades) and
  rolled back when over the limit or outside the agent's tables.
- An agent cannot interfere with ariodb's own transaction control, the
  change journal, the decisions log, or approvals meant for someone else.
- Dashboard changes need a logged-in user with a role that allows them, a
  CSRF token and a same-origin request; passwords cannot be guessed at
  speed. Roles are checked by the server on every endpoint, not only
  hidden in the app (see [Dashboard sign-in and roles](#dashboard-sign-in-and-roles)).
- Credentials for the databases never reach the agent.

### What ariodb does not protect against

- **The database role's privileges are the real boundary.** The table
  allow-list is checked against the tables a statement *names*. A view, a
  function or a `SECURITY DEFINER` function the gateway role may execute can
  read any table that role can read, and can do anything its owner can do
  (including calling `dblink` inside its body). Give the gateway role only
  the grants its agents need, do not install `dblink` or `postgres_fdw` in
  databases agents reach, and revoke `EXECUTE` on functions they should not
  call. ariodb refuses the built-in functions that would get round its own
  checks (see finding 3), but it cannot see inside your functions.
- **Server files.** `pg_read_file`, `pg_ls_dir`, `lo_import` and similar
  need superuser or the `pg_read_server_files` family of roles. Do not grant
  those to the gateway role. `lo_*` is refused by ariodb; for the others,
  add a rule (the example config has one).
- **Anyone who can write to the state directory.** The decisions log is a
  hash chain without a key (see accepted risk A1), the master key sits next
  to the encrypted secrets unless `ARIODB_MASTER_KEY` is set, and the config
  file is the policy. Protect the host and the state directory (ariodb
  creates it `0700` and warns when it is looser).
- **Agents that reach the database another way.** ariodb only sees what goes
  through it. Firewall the database so agents can reach it only via ariodb.
- **Effects outside the database** (emails, payments, webhooks fired by
  triggers) cannot be measured or undone.
- **ClickHouse writes** cannot be rolled back or undone; rules and approvals
  are the only control. ClickHouse reads run with `readonly = 2`, which
  still lets a query change most other settings (resource limits, for
  example); ariodb always sets `max_execution_time` itself.
- **Denial of service.** There are no connection limits or handshake
  timeouts on the listeners. Put them behind network controls.
- **Plugins are trusted code.** A plugin runs as ariodb's user, with that
  user's files and network. It sees the statements it is asked to approve
  or supply facts about, every event it is sent, and (as an audit sink) the
  whole decisions log, including literal values unless `redact_literals` is
  on. Its environment holds only `PATH`, `HOME` and what the config names,
  not ariodb's database URLs or tokens, but nothing stops it reading files
  ariodb's user can read, such as the state directory. Install plugins you
  would trust as much as ariodb, and keep them where only ariodb's owner
  can change them. What ariodb does guard against: an approver or facts
  plugin that is down, slow, crashing or answering nonsense refuses the
  statement; lines from a plugin are capped at 1 MiB; answers only reach
  the request whose id they carry; every message ariodb writes is one
  serialised JSON value, so agent SQL cannot forge a message; each plugin
  has its own pipes; text from plugins has control characters removed. See
  [docs/plugins.md](docs/plugins.md).
- **A model approver is not a security boundary on its own.** Agent SQL is
  passed to the model as JSON data, with an instruction never to follow
  text inside it, and structured output limits the answer to allow or deny.
  A determined injection may still persuade a model. Use model approvers to
  save people time, not as the only check on high-risk rules, and keep
  `llm_fail_mode = "closed"`.

### Dashboard sign-in and roles

With `[dashboard.oidc]`, people sign in with an OpenID Connect provider:

- The authorisation code flow with PKCE (S256), a random `state` and a
  random `nonce` per sign-in. The pending sign-in is bound to the browser
  that started it by an HttpOnly cookie, used once, and forgotten after ten
  minutes, so a callback link sent to someone else, replayed, or with a
  changed `state` is refused.
- The ID token must be signed with RSA, RSA-PSS, ECDSA or EdDSA by a key
  from the provider's published key set, for that key's algorithm: `none`,
  HMAC (including HMAC keyed with a public key) and a key of the wrong type
  are refused. The issuer must be the one the discovery document names
  (which must match the configured issuer), the audience must include the
  client id (and `azp` must be the client id when present or when there
  are several audiences), `exp`, `nbf` and `iat` are checked with a minute's
  leeway, and the nonce must be this sign-in's. Keys are cached for an
  hour and fetched again when a token names an unknown key id (at most
  every ten seconds), so the provider can rotate keys.
- The issuer, token and key URLs must be `https://` except on localhost;
  redirects are not followed when ariodb talks to the provider.
- The role (viewer, approver, admin) comes from the groups in the ID token
  and the current config on every request. No mapped group means no
  access; a config change that takes a group away ends that role at once.
  `allowed_email_domains` needs a verified email. A person is recorded as
  `sso:<email>` only when the email is verified; otherwise by user name or
  subject.
- Local passwords stay for break-glass use (`password_login =
  "break_glass"`) or are switched off (`"off"`), which also ends existing
  password sessions. Under single sign-on the first-run password page is
  off (accepted risk A4 does not apply).
- `[[approvers]]` of type `dashboard` or `webhook` may set `groups`; only
  members of those groups may then decide their requests, in the
  dashboard or through a link.
- Approval links (`approval_links = "sign_in"`, the default under single
  sign-on) need a signed-in approver as well as the signed link, and the
  form on the confirmation page carries the session's CSRF token. The
  person, not the link, is recorded as the decider. A link opened from a
  chat app or email arrives without the SameSite=Strict session cookie, so
  the page reloads itself once as a same-site navigation (a meta refresh;
  the page has no script) before asking anyone to sign in.

### Deployment checklist

- Least-privilege gateway role per credential; no superuser, no
  `REPLICATION`, no `pg_read_server_files`, no `pg_signal_backend`.
- Agents can reach the database only through ariodb.
- TLS on the proxy (`require_tls`) and to the database (`tls = "require"`).
- The dashboard behind HTTPS (`public_url` starting `https://` turns on
  `Secure` cookies), not exposed to the internet without a reason.
- Set the first dashboard password with `ariodb dashboard-password` before
  putting the dashboard behind a reverse proxy (see A4).
- With single sign-on: map only the groups that need each role, keep
  approvers' `groups` narrow for high-risk rules, keep the break-glass
  root password offline (or set `password_login = "off"`), and keep the
  client secret in `client_secret_env` or `client_secret_secret`.
- Long random agent tokens; keep `ARIODB_MASTER_KEY` out of the state
  directory's backups.
- `dashboard.config_writes = false` unless people are meant to edit policy
  from the dashboard.
- Plugins only from sources you trust, owned by ariodb's user and not
  writable by others; credentials for them through `pass_env` or
  `secret_env`, not `env` in the config file.

## Review of October 2026

A review of the proxy, wire protocol, executor, gate, classifiers and
policy, the ClickHouse proxies, MCP server, approvals, dashboard API,
secrets store, decisions log and undo, from the point of view of the
attackers above. Each fixed issue has a unit or end-to-end test that fails
without the fix.

### Fixed

| # | Severity | Area | Issue | Fix |
|---|---|---|---|---|
| 1 | Critical | Postgres proxy (`proxy.rs`) | With the extended protocol, an agent could Close one of ariodb's hidden statements (`__ariodb_begin_ro`, `__ariodb_effects`, `__ariodb_rollback` and the rest) and Parse its own statement under the same name. ariodb's transaction control would then silently stop working: reads outside a `READ ONLY` transaction, an effect check that measures nothing, a rollback that rolls nothing back. | Any Parse, Bind, Describe, Close or Execute naming a `__ariodb*` statement or portal is refused. |
| 2 | High | ClickHouse (`chsql.rs`, `clickhouse.rs`, `clickhouse_native.rs`) | The table allow-list could be bypassed: comma joins (`FROM events, secrets`) only saw the first table; `x IN secrets` was not seen; `INSERT INTO secrets (col) VALUES` took the column list for a function call; `merge()`, `dictionary()`, `cluster()`, `dictGet` and `joinGet` read tables named in strings; and the `database` parameter or native login database changed what unqualified names meant. | FROM lists, `IN` and column lists are tracked; only row-making table functions are allowed; dictionary and Join-table functions are refused; unqualified names are qualified with the session database, which ariodb now always names to ClickHouse. |
| 3 | High | Postgres policy (`policy.rs`) | Built-in functions could get round ariodb's checks: `query_to_xml` and the rest of the `*_to_xml` family, `ts_stat` and `dblink` run SQL ariodb never sees (reading tables outside the allow-list); `set_config` changes settings for the rest of the session (undoing the refusal of `SET search_path`); large-object functions write where the effect check cannot measure; `pg_logical_emit_message` can forge the session tag the journal and undo rely on; replication-slot functions can disturb the journal; `pg_terminate_backend` can end other agents' sessions on the shared login. | Refused for every agent, whatever the rules say. |
| 4 | Medium | Postgres classifier (`classify.rs`) | The parser's table and function lists stop at `PREPARE` and `DECLARE CURSOR`, so tables and functions named only inside them passed the allow-list and the rules unseen. | The wrapped query is printed back to SQL and read as well; failure to do so refuses the statement. |
| 5 | Medium | Postgres proxy (`proxy.rs`) | After a batch failed at the database, ariodb kept its old record of statement names the batch had parsed or closed, although the database may have changed them. A later Bind could be judged by the rules, approvals and the decisions log as the old statement. (`READ ONLY` and the effect check still applied.) | Those names are forgotten, so such a Bind is refused. |
| 6 | Medium | Dashboard login (`dashboard.rs`) | No limit on password guesses; unknown user names answered faster than known ones. | Failures are counted per client address (5 per 15 minutes) and per existing user (20 per 15 minutes); past either, logins get 429 without a password check. Unknown users are verified against a dummy hash. |
| 7 | Medium | Webhook approvals (`dashboard.rs`) | Decision links acted on GET. Chat apps and mail scanners fetch links to preview them, so a request could be approved or denied without anyone looking. | GET shows the request and a button; only POST decides. The page is never framed and sends no referrer. **Webhook receivers that followed links programmatically must now POST to them.** |
| 8 | Medium | Block-like-this (`dashboard_api.rs`) | The generated deny rule embedded table names from agent SQL with incomplete escaping (backslashes and new lines in the condition, and nothing at all in the rule name). A crafted quoted identifier could end the TOML string early, so the saved config differed from the rule the operator previewed. | CEL string escaping for every value, the TOML library writes the strings, and the rule name is a slug. |
| 9 | Low | Slack approvals (`approvals.rs`, `dashboard.rs`) | A valid Slack signature could decide any approval, including ones waiting on the dashboard or another approver. | Only requests waiting on the Slack approver whose secret signed the callback. |
| 10 | Low | Slack approvals (`approvals.rs`) | Agent SQL was put in a Slack code block unescaped, so it could close the block and add links ("approve here") or mentions. | `&`, `<`, `>` escaped as Slack asks; backtick runs broken up. |
| 11 | Low | Model approver (`approvals.rs`) | The decision cache was keyed on approver, agent and SQL only: a changed policy kept old answers, and an outage under fail-open was cached as an allow for the whole window. The cache never shrank. | Keyed on approver, model, policy, agent, database, rule and SQL; only the model's own answers are cached; expired entries are swept. |
| 12 | Low | Undo (`undo.rs`) | Recorded values were quoted as `'...'`, which is only safe while the server has `standard_conforming_strings` on. | Values containing a backslash are written as `E'...'` with backslashes doubled. |
| 13 | Low | ClickHouse native (`clickhouse_native.rs`) | Before authentication, each Hello field could make ariodb allocate up to 64 MiB. | Login fields capped at 64 KiB. |

### Accepted, with reasons

| # | Severity | Area | Issue | Why accepted, and mitigation |
|---|---|---|---|---|
| A1 | Medium | Decisions log (`audit.rs`) | The chain is unkeyed SHA-256. Anyone who can write `ariodb.db` can rewrite every hash, or delete the newest entries, and `ariodb audit` will still pass; deleting the oldest entries looks like retention pruning. | It is tamper-evident against casual edits, not against the host's owner. A keyed chain needs a key the attacker cannot read, which on the same host is the same problem. Ship decisions to an external log store, or record the head hash elsewhere, if you need more. |
| A2 | Medium | Postgres policy | Tables read through views and functions are not on the allow-list (see the threat model). | Parsing cannot see inside functions; database grants are the boundary. |
| A3 | Medium | Model approver | Prompt injection through SQL text remains possible. | Mitigated (data passed as JSON, instruction to ignore it, structured output, fail-closed by default); do not rely on a model alone. |
| A4 | Low | Dashboard first run (`dashboard.rs`) | The first password can be set by any request from a loopback address. Behind a reverse proxy on the same host, every request is from loopback. | Set the password with `ariodb dashboard-password` (or before exposing the dashboard). |
| A5 | Low | Listeners | No connection limits or handshake timeouts; slow clients can hold connections open. | Network controls; agents are authenticated before any database work. |
| A6 | Low | Postgres proxy auth | Unknown agent names fail slightly faster than known ones, and token guesses are not rate limited. | Tokens should be long random values, which makes guessing hopeless whatever the rate. |
| A7 | Low | ClickHouse HTTP | Agents may send their token as a `password` URL parameter, which intermediaries may log. | Supported for client compatibility; prefer Basic auth or `X-ClickHouse-Key`. |
| A8 | Low | Dashboard login limit | Twenty wrong passwords for a user, from anywhere, lock that user out for 15 minutes; the counts live in memory and reset on restart. | A deliberate trade-off against distributed guessing. |
| A9 | Medium | `write_check = "reported"` | Writes are judged by the row counts the database reports, so rows and tables changed by triggers, cascades and functions are not seen. | Off by default, for databases that cannot measure writes (YugabyteDB, CockroachDB); `ariodb doctor` and the docs say what it gives up. Database grants are the backstop. |
| A10 | Low | Dashboard single sign-on (`oidc.rs`) | Groups are read from the ID token at sign-in. Someone removed from a group at the provider keeps that group's role until their session ends (12 hours) or they sign out. Pending sign-ins live in memory, so a restart makes people start again. | A role mapping changed in the config applies at once, so take the group out of the mapping when someone must lose access before their session ends. |
| A11 | Low | Approval links with `approval_links = "signed"` | Without single sign-on (or with links set to `signed`), anyone holding a link can decide its request, and the decision is recorded as `webhook`. | Links are signed per request and verdict and only decide on POST (finding 7). Set `approval_links = "sign_in"` to tie each decision to a person. |

### Reviewed with no issue found

- Network-facing token and CSRF comparisons are constant-time; session tokens are
  stored only as SHA-256 hashes, with HttpOnly, SameSite=Strict cookies.
- Cancel requests: ariodb hands out its own random keys and maps them to
  the upstream key, so the database's own keys are never exposed.
- Frames over 1 MiB are drained and refused; the startup message is capped.
- The effect measurement is checked against the row counts the database
  reports for each statement; a measurement that comes up short (as on
  databases whose `pg_stat_xact_user_tables` stays empty, or for foreign
  tables) rolls the write back.
- Writes are held until the effect check passes; a refused write's results
  never reach the agent. COPY FROM STDIN is refused and aborted if it
  slips through.
- `DO`, `CALL`, `EXECUTE`, `FETCH`, `LISTEN`, `NOTIFY`, `DEALLOCATE` and
  `DISCARD` are refused.
- Secrets are sealed with XChaCha20-Poly1305 with the name as associated
  data; the key file is created `0600`.
- Webhook links are HMAC-signed per approval and verdict; Slack callbacks
  check the signature and a five-minute timestamp window.
- The decisions log is written with parameterised SQL; filters are bound
  parameters.

Not reviewed in depth this time: `tls.rs`, `upstream.rs`, `journal.rs`,
`pgoutput.rs`, `rules.rs` and the dashboard front end.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it
privately through the repository's **Security** tab ("Report a
vulnerability"), or contact the maintainers directly if you already know
them. Include:

- the ariodb version or commit,
- the relevant part of your config (with every credential removed),
- the SQL, protocol messages or requests that show the problem, and
- what you expected and what happened.

The maintainers will acknowledge the report and agree a disclosure date
with you once a fix is ready. Please test only against
systems you own or are allowed to test, and never with real customer data.
