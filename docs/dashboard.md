# Dashboard

This page describes ariodb's built-in web dashboard: how to set the first
password and add users, what each page shows and lets you do, how sign-in
and changes are protected, and how to run the dashboard behind a reverse
proxy with the right `public_url`. It is for the people who will review
approvals and undo agent sessions, and for whoever deploys and secures the
dashboard for them.

## What the dashboard is

`ariodb serve` serves the dashboard on `[dashboard] listen`
(`127.0.0.1:8080` by default). It is a single-page web app built into the
ariodb binary, with a JSON API behind it; nothing is loaded from anywhere
else. The same listener also takes the callbacks approvers use: Slack's
button presses at `/slack/actions` and signed webhook links at
`/hooks/approvals/...` (see [approvals.md](approvals.md)).

```toml
[dashboard]
listen = "127.0.0.1:8080"                    # default; "" switches the dashboard off
public_url = "https://ariodb.example.com"    # default http://127.0.0.1:8080
config_writes = false                        # default false
```

Switching `listen` off also switches off Slack buttons and webhook links,
and changing it needs a restart. `public_url` is explained
[below](#public_url-and-links), and `config_writes` under
[Config](#config). Every key is in
[configuration](configuration.md#dashboard).

The dashboard only exists while `ariodb serve` runs. `ariodb mcp` does not
serve it; approvals raised by MCP agents appear in the dashboard of an
`ariodb serve` that uses the same state directory.

## Signing in for the first time

There are no default passwords. Set the first one with the CLI, on the
ariodb host, before anyone else can reach the dashboard:

```console
$ printf '%s\n' 'not-a-real-password-123' | ariodb dashboard-password
password set for 'root'
```

`ariodb dashboard-password` reads the password from stdin (one line) and
stores it, hashed with Argon2, in `<state dir>/ariodb.db`. The user is
`root` unless you pass `--user <name>`. Passwords must be at least 12
characters:

```text
error: use a password of at least 12 characters
```

Run it again to reset a password; setting a new password signs that user
out everywhere. In practice, read the password from a password manager or
a file rather than typing it on the command line, so it does not land in
your shell history.

If no user exists yet, the dashboard's sign-in page instead offers to set
the `root` password, but **only to a browser on the ariodb host itself**
(a loopback address). Anyone else gets "set the first password from the
server itself, or run ariodb dashboard-password". Behind a reverse proxy on
the same host, every request comes from loopback, so anyone who can reach
the proxy could set the first password: always use
`ariodb dashboard-password` before putting the dashboard behind a proxy.

## Users

Add more users on the Settings page, or with
`ariodb dashboard-password --user <name>`. User names use letters, digits
and `-`, `_`, `.` and `@`.

Every user has a role, and each role may do everything the one before it
may:

| Role | May |
|---|---|
| viewer | Read every page except config: approvals, decisions, sessions and undo plans, rules, plugins |
| approver | Also decide approvals (within an approver's `groups`, if it sets them) |
| admin | Also read and edit the config, block requests like a decision, undo sessions, manage local users and secrets |

Pages and buttons a role may not use are hidden, and the server refuses
them anyway: roles are checked on every API request.

Local users: `root` is always an admin, and users from before roles
existed are admins. New users added from the Settings page are viewers
unless given another role; new users added with
`ariodb dashboard-password --user <name>` are admins unless `--role viewer`
or `--role approver` says otherwise, and `--role` on an existing user
changes their role. Admins can change roles and remove users on the
Settings page; `root` cannot be removed (set a new password instead).

## Single sign-on and roles

With `[dashboard.oidc]`, people sign in with any OpenID Connect provider
(Keycloak, Okta, Microsoft Entra ID and others) and get a role from their
groups. The keys are in [configuration](configuration.md#dashboardoidc).

```toml
[dashboard.oidc]
issuer = "https://login.example.com/realms/ops"   # https; http only for localhost
provider_name = "Keycloak"    # the sign-in button says "Sign in with Keycloak"
client_id = "ariodb"
client_secret_env = "ARIODB_OIDC_CLIENT_SECRET"   # or client_secret_secret; neither for a public client
redirect_path = "/auth/callback"   # default; register <public_url><redirect_path> with the provider
groups_claim = "groups"       # default; a dotted name reaches inside objects, e.g. "realm_access.roles"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers", "dba"]
viewer_groups = ["engineering"]
allowed_email_domains = ["example.com"]   # optional; needs email_verified = true in the ID token
password_login = "break_glass"   # default: local passwords still work, offered below the button; "off"
logout_at_provider = false    # true: signing out also ends the provider's session
```

- Each person gets the highest role any of their groups maps to; someone
  in none of the groups is refused. A signed-in person's role follows the
  current config, so removing a group from `admin_groups` takes effect at
  once. Groups themselves are read from the ID token at sign-in, so
  someone removed from a group at the provider keeps that role until their
  session ends (12 hours) or they sign out.
- The provider must put the groups in the ID token under `groups_claim`
  (Keycloak: a group membership mapper; Okta: a groups claim; Microsoft
  Entra ID: `groups` in the token configuration). If it has no `groups`
  scope, set `scopes` without it.
- A provider that does not send `email_verified` (Microsoft Entra ID, for
  one) cannot be limited by `allowed_email_domains`; limit it by groups
  instead.
- Local passwords stay for break-glass use unless `password_login =
  "off"`, and the first-run password page is switched off.
- Decisions by people who signed in this way are recorded as
  `sso:<email>` when the email is verified, otherwise by user name or
  subject.
- Approval links need a signed-in approver by default under single
  sign-on; see [approvals](approvals.md#single-sign-on-and-approver-groups).

How sign-in is checked (PKCE, `state`, `nonce`, token signatures and
claims) is in the [security model](security-model.md#dashboard-sign-in-and-roles).

## The pages

The sidebar has six main pages and Settings. The approvals queue is
checked every few seconds on every page, and the sidebar's Approvals entry
shows how many requests are waiting, so a dashboard left open shows new
requests as they arrive. The Overview and the plugin status also refresh
on their own; the other pages load when you open them.

### Overview

What agents did in the last 24 hours and how ariodb is set up.

- **Counts**: requests waiting for approval; statements allowed, refused
  and rolled back in the last 24 hours; sessions that changed data, and how
  many of those were undone. Each links to the page with the detail.
- **Agents**: each configured agent with its access (read only, or read
  and write), its tables, which database login it uses (`default` or a
  `[[credentials]]` name), and whether its token is set. A token shown as
  "not set" means the environment variable or secret it names is missing,
  and that agent cannot log in.
- **Setup**: the ariodb version, the address agents connect to, the number
  of rules, each approver with its type, and whether the change journal is
  on (and so whether undo is available).

### Approvals

Statements held by a rule with `verdict = "approve"`, waiting for a
decision. See [approvals.md](approvals.md) for how approvals work.

- **Waiting**: one card per pending request, with the agent, the rule, the
  approver it is waiting on, a countdown to its expiry, the rule's reason
  and the full statement. Type an optional note (up to 500 characters) and
  press **Approve** or **Deny**. On a deny, the agent sees the note in its
  error message, so use it to say what to do instead. Your decision is
  recorded as `dashboard:<your user name>`.
- **Recent decisions**: past requests, newest first, with their status
  (`allowed`, `denied`, `expired`), who decided (a person, `slack:...`,
  `webhook`, `model:...`, `plugin:...`, `ariodb`, or "nobody (expired)"),
  any note, and the statement. Model and plugin approvers' decisions appear
  here too.

Any signed-in user can decide any pending request, including ones that were
also announced in Slack or to a webhook. Links in Slack messages and webhook
payloads (`<public_url>/#approval-<id>`) open this page with that request
highlighted; if it has already been decided, the page says how and by whom.

### Decisions

Every statement agents sent, and what ariodb did with it, newest first.
This is the decisions log in `<state dir>/ariodb.db`.

Columns: when, agent, outcome, kind (ariodb's classification, such as
`read` or `write`), the rule that decided (empty for the built-in policy),
rows changed, latency in milliseconds, and the statement.

Filters, applied on the server:

| Filter | Matches |
|---|---|
| Agent | Exact agent name |
| Outcome | `allowed`, `refused`, `rolled_back` or `failed` |
| Rule | Exact rule name |
| Text in statement | Any statement containing the text |
| Latest | How many to show: 100, 200 (default), 500 or 1000 |

The filters are kept in the page's address, so a filtered view can be
bookmarked or shared with another dashboard user.

Each row's menu offers:

- **Block like this**: builds a deny rule matching this decision's agent,
  statement type and tables, for example:

  ```toml
  [[rules]]
  name = "block-coding-agent-delete-orders-1287"
  condition = "agent.name == 'coding-agent' && sql.verb == 'delete' && intersects(sql.tables, ['orders'])"
  verdict = "deny"
  reason = "blocked from the dashboard after decision 1287"
  ```

  The rule is checked against the whole config before anything is written.
  With `config_writes = true` you can **Apply** it, which saves the config
  and puts the rule in force at once. Otherwise copy it into your config
  repository. Table names come from the agent's SQL and are escaped for
  both CEL and TOML, so a crafted table name cannot add anything else to
  your config.
- **Copy as test**: copies the decision as a fixture for `ariodb test`
  (see [testing-policies.md](testing-policies.md)). Only `allowed` and
  `refused` decisions qualify; rollbacks and failures depend on the data,
  not just the policy.

`[audit] retention_days` (30 by default) controls how long decisions are
kept, and `[audit] redact_literals = true` stores statements with literal
values replaced by `$1`, `$2`, and so on. See
[configuration.md](configuration.md).

### Sessions and undo

Every agent session that changed data, newest first: when it last changed
something, the session ID, the agent, how many transactions and row changes
it made, which tables it touched, and whether it has been undone. See
[undo.md](undo.md) for how undo works.

**Review undo** opens the session's undo plan:

- the agent, how much it changed and when;
- the steps (the first ones listed, then a count of the rest), such as
  "restore public.orders row (7)";
- **Changed by someone else since**: conflicts, rows another session or
  someone outside ariodb changed after this session did;
- **Cannot be undone**: anything that blocks the undo, such as a table
  without a primary key;
- whether the session was already undone.

With conflicts, tick "Undo the rest and leave the conflicting rows as they
are now" (the CLI's `--skip-conflicts`) to undo everything else. **Undo**
asks for confirmation, then reverses the plan in one transaction and
reports how many rows were restored. If anything blocks it, nothing is
changed and the reason is shown.

Undo runs from the `ariodb serve` process, with `ARIODB_ADMIN_URL` if it
is set in that process's environment, otherwise the gateway login.

### Rules

The rules in force, on top of each agent's built-in policy: name, verdict
(and approvers for `approve`), stage (`before` or `after`), priority,
condition and the agents each applies to. See [rules.md](rules.md).

**Try a statement** shows what ariodb would decide for an agent and a
statement, without running anything: the verdict, the rule that decided
(or the built-in policy) and its reason. Like `ariodb explain`, it judges
the built-in policy and before-stage rules only; after-stage rules and the
row limit need the write to run.

### Config

The config file `ariodb serve` is using, in an editor, with its path.

- **Passwords in `postgres://` and `postgresql://` URLs are shown as
  `***`.** When you save, any `***` that is still there is replaced with
  the real password for the same user and host, so you can edit the rest of
  the file without ever seeing or retyping it. Typing a new password over
  `***` changes it. Nothing else in the file is masked, which is one more
  reason to keep credentials in environment variables or the secret store
  rather than in the file.
- **Check** validates the edited text as a complete config and reports the
  number of agents, rules and approvers, or the first error.
- **Save** needs `config_writes = true`. It validates the text again,
  keeps the previous file as `<name>.toml.bak` next to it, writes the new
  file atomically and applies it at once, with no restart. Settings that
  always need a restart (listen addresses, tunnels, plugins) still do.

With `config_writes = false` (the default), Save is switched off and the
page says so: edit and check here, then copy the result into wherever your
config is managed, such as a Git repository. Leave it off when the config
is reviewed through pull requests, so the dashboard cannot become a way
round that review.

### Settings

- **Secrets**: the names in the encrypted secret store (never the values).
  Add a secret or replace one's value; names use letters, digits, `-` and
  `_`. To delete a secret, use `ariodb secret delete <name>`.
- **Dashboard users**: list users, add one, or set a new password for an
  existing one (which signs them out everywhere).
- **Decisions log**: checks the decisions log's hash chain, as
  `ariodb audit` does, and reports how many entries it covers or where the
  chain breaks. See [security-model.md](security-model.md) for what the
  chain does and does not prove.
- **Plugins**: each plugin `ariodb serve` runs, refreshed every five
  seconds: its state (`starting`, `running`, `restarting` or `stopped`),
  the name and version it declared, its capabilities (`approver`, `facts`,
  `notifier`, `audit_sink`), its process ID, how many times it has been
  restarted, how many events were dropped because it could not keep up,
  and its last error. Changes to plugins need a restart. See
  [plugins.md](plugins.md).
- **This session**: who you are signed in as, and **Sign out**. Sessions
  last 12 hours.

## How sign-in and changes are protected

| Protection | Detail |
|---|---|
| Password storage | Argon2 hashes in `<state dir>/ariodb.db`; passwords of at least 12 characters |
| Guessing limits | After 5 failed sign-ins from one client address, or 20 against one existing user from anywhere, within 15 minutes, further attempts get HTTP 429 without the password being checked, until the window passes. A successful sign-in clears that address's and user's counts. Counts are kept in memory and reset when ariodb restarts |
| Timing | Every failed sign-in waits 400 ms; unknown user names are checked against a dummy hash, so a wrong answer takes as long whether or not the user exists |
| Session cookie | `ariodb_session`: a random 256-bit token, `HttpOnly`, `SameSite=Strict`, `Path=/`, valid 12 hours, and `Secure` when `public_url` starts with `https://`. The database stores only its SHA-256 hash |
| CSRF | Every change (deciding, undoing, saving, adding users or secrets, signing out) must carry the session's CSRF token in the `x-ariodb-csrf` header |
| Origin check | Changes, sign-in and first-run setup are refused ("cross-site request refused") when the browser's `Origin` host differs from the `Host` header |
| Page headers | A strict Content Security Policy (scripts only from the dashboard itself, no inline scripts, nothing from other sites), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` |
| Webhook link pages | No scripts, never framed, not cached, no referrer |

Two consequences to plan for:

- **A user can be locked out by others.** Twenty wrong passwords for
  `root` from anywhere lock `root` out for 15 minutes. That is deliberate,
  to bound guessing spread across many addresses, but it means someone who
  can reach the sign-in page can keep a user locked out. Do not expose the
  dashboard to networks you do not trust.
- **Behind a reverse proxy, every client has the proxy's address.** ariodb
  does not read `X-Forwarded-For`, so the five-failures-per-address limit
  then applies to everyone at once: five wrong passwords from anyone block
  sign-in for everyone for 15 minutes. The per-user limit still works as
  above.

## `public_url` and links

`public_url` is the address people and services use to reach the
dashboard, which is not always the address it listens on. ariodb uses it
for:

- the dashboard link in Slack messages and webhook payloads:
  `<public_url>/#approval-<id>`;
- webhook decision links: `<public_url>/hooks/approvals/<id>?verdict=...&token=...`;
- deciding whether the session cookie is `Secure`: it is when `public_url`
  starts with `https://`.

ariodb prints it at start-up (`ariodb: dashboard at <public_url>`). Set it
to the URL people type, without a trailing path. If you use Slack buttons,
also set the Slack app's interactivity URL to `<public_url>/slack/actions`.

## Running behind a reverse proxy

The dashboard speaks plain HTTP. To serve it over HTTPS, or on a name other
than the host's, put a reverse proxy in front and keep `listen` on
loopback:

```toml
[dashboard]
listen = "127.0.0.1:8080"
public_url = "https://ariodb.example.com"
```

The proxy must:

- **pass the `Host` header through unchanged.** The origin check compares
  the browser's `Origin` with `Host`; a proxy that rewrites `Host` to
  `127.0.0.1:8080` makes every change fail with "cross-site request
  refused";
- **pass the request body unchanged** to `/slack/actions`, since Slack's
  signature covers the exact bytes;
- not cache `/api/` responses.

An nginx example:

```nginx
server {
    listen 443 ssl;
    server_name ariodb.example.com;
    ssl_certificate     /etc/ssl/ariodb.example.com.crt;
    ssl_certificate_key /etc/ssl/ariodb.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
    }
}
```

Caddy passes `Host` through by default:

```text
ariodb.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Exposing only the callbacks

Slack has to reach `/slack/actions`, and people opening webhook links from
outside your network have to reach `/hooks/approvals/`. Neither needs the
rest of the dashboard. If the dashboard should stay on your internal
network, publish only those paths on the public side:

```nginx
server {
    listen 443 ssl;
    server_name ariodb-callbacks.example.com;
    # certificates as above

    location = /slack/actions      { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }
    location ^~ /hooks/approvals/  { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }
    location /                     { return 404; }
}
```

`public_url` is used for both dashboard links and webhook links, so with
split names, set it to the name the webhook links should use, and expect
the "open in the dashboard" links to point there too.

Before exposing the dashboard through a proxy:

1. set the first password with `ariodb dashboard-password` (the loopback
   first-run setup would otherwise be open to anyone reaching the proxy);
2. use `https://` in `public_url`, so cookies are `Secure`;
3. keep `config_writes = false` unless people are meant to change policy
   from the browser.

## Developing the dashboard

The front end is a React app (Vite, Tailwind CSS and shadcn/ui) in
[`dashboard/`](../dashboard). Its built files in `dashboard/dist` are
committed and embedded in the binary, so `cargo build` needs no Node. After
changing the front end, rebuild them with
[`scripts/build-dashboard.sh`](../scripts/build-dashboard.sh) and commit
the result. For live reloading, run ariodb with its dashboard on
`127.0.0.1:8080` (for example with `./scripts/demo.sh`), then
`cd dashboard && npm run dev`; Vite passes `/api` through to ariodb.

## Next

- [Approvals](approvals.md): approvers, Slack and webhook set-up.
- [Undo](undo.md): what the Sessions page's plans mean.
- [Rules](rules.md): writing the rules the Rules page lists.
- [Security model](security-model.md): the dashboard's place in the threat model.
- [Operations](operations.md): running ariodb in production.
