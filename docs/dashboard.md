# Dashboard

This page describes ariodb's built-in web dashboard: how to set the first
password and add users, the roles that decide what each person may do,
single sign-on with an OpenID Connect provider, what each page shows and
lets you do, how sign-in and changes are protected, and how to run the
dashboard behind a reverse proxy with the right `public_url`. It is for the people who will review
approvals and undo agent sessions, and for whoever deploys and secures the
dashboard for them.

## What the dashboard is

`ariodb serve` serves the dashboard on `[dashboard] listen`
(`127.0.0.1:8080` by default). It is a single-page web app built into the
ariodb binary, with a JSON API behind it; nothing is loaded from anywhere
else. The same listener also takes the callbacks approvers use: Slack's
button presses at `/slack/actions` and the signed links that webhook and
channel approvers send, at `/hooks/approvals/...` (see
[approvals.md](approvals.md)); and, with single sign-on, `/auth/login` and
the provider's redirect back.

```toml
[dashboard]
listen = "127.0.0.1:8080"                    # default; "" switches the dashboard off
public_url = "https://ariodb.example.com"    # default http://127.0.0.1:8080
config_writes = false                        # default false
# approval_links = "sign_in"                 # default with [dashboard.oidc]; "signed" without
```

Switching `listen` off also switches off Slack buttons and approval links,
and changing it needs a restart. `public_url` is explained
[below](#public_url-and-links), and `config_writes` under
[Config](#config), and `approval_links` in
[approvals](approvals.md#links-that-need-sign-in). Every key is in
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
`root` unless you pass `--user <name>`, and a new user is an admin unless
you pass `--role viewer` or `--role approver`. Passwords must be at least
12 characters:

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

With [single sign-on](#single-sign-on) configured there is no first-run
page; people sign in with the provider, and a local password, if you want
one for break-glass use, is set with `ariodb dashboard-password`.

## Users

People sign in with a local password, or, with `[dashboard.oidc]`, with an
identity provider ([single sign-on](#single-sign-on)). Either way, each
person has a role.

Add local users on the Settings page (admins only), or on the ariodb host:

```console
$ printf '%s\n' 'not-a-real-password-456' | ariodb dashboard-password --user sam --role approver
password set for 'sam'
```

User names use letters, digits and `-`, `_`, `.` and `@`. A new user added
from the Settings page is a viewer unless given another role; one added
with `ariodb dashboard-password` is an admin unless `--role` says otherwise.
Setting a new password for an existing user keeps their role (unless
`--role` is given) and signs them out everywhere. `root` is always an
admin and cannot be removed; users from before roles existed are admins.

On the Settings page an admin can also change a local user's role, which
applies at once, and remove a user, which ends their sessions.

### Roles

| Role | May |
|---|---|
| viewer | Read every page except Config: the overview, approvals, decisions, sessions and undo plans, rules (and try a statement), the decisions-log check, plugins and their own session |
| approver | Also decide approvals, within an approver's `groups` if it sets them |
| admin | Also read and edit the config, block requests like a decision, undo sessions, and manage local users and secrets |

Each role can do everything the one before it can. The server checks the
role on every request, so a role that is too low gets an error such as
"this needs the admin role; sam has the approver role" whatever the browser
sends; the app also hides what a role may not use (the Config page, the
Undo and Block like this buttons, and the Secrets and Dashboard users
cards).

A local user's role is read from `ariodb.db` on every request, so a change
of role applies at once. A single sign-on user's role is worked out on every
request from the groups the provider sent at sign-in and the config in
force.

## Single sign-on

With `[dashboard.oidc]`, people sign in with any OpenID Connect provider,
and their groups decide their role:

```toml
[dashboard]
public_url = "https://ariodb.example.com"

[dashboard.oidc]
issuer = "https://login.example.com/realms/ops"
provider_name = "Keycloak"                         # "Sign in with Keycloak"
client_id = "ariodb"
client_secret_env = "ARIODB_OIDC_CLIENT_SECRET"    # or client_secret_secret; neither for a public client
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers", "dba"]
viewer_groups = ["engineering"]
# redirect_path = "/auth/callback"                 # default
# groups_claim = "groups"                          # default
# allowed_email_domains = ["example.com"]
# password_login = "break_glass"                   # default; or "off"
# logout_at_provider = false                       # default
```

Every key is in [configuration](configuration.md#dashboardoidc).

### How sign-in works

The sign-in page shows **Sign in with <provider_name>**, which goes to
`/auth/login`. ariodb then runs OpenID Connect's authorisation code flow:

1. ariodb reads the provider's discovery document,
   `<issuer>/.well-known/openid-configuration`, and its signing keys, and
   keeps both for an hour. The document must name the configured issuer,
   and every endpoint in it must be `https` (`http` only on this machine).
2. The browser goes to the provider's authorisation endpoint with
   `response_type=code`, the scopes, a random `state`, a random `nonce`, and
   a PKCE challenge (`S256`). A short-lived cookie, `ariodb_sso`
   (`SameSite=Lax`, ten minutes), ties the sign-in to this browser.
3. The provider sends the browser back to `<public_url><redirect_path>`.
   ariodb checks the `state` and the cookie, then trades the code for
   tokens at the token endpoint with the PKCE verifier and, for a
   confidential client, the client secret (HTTP Basic if the provider
   lists `client_secret_basic` or lists nothing, otherwise
   `client_secret_post`).
4. ariodb accepts the ID token only with a good signature from one of the
   provider's keys (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384
   or EdDSA; never `none` or an HMAC), the right issuer and audience (and
   `azp`, when there are several audiences), an expiry in the future, and
   the nonce this browser was given. A minute's clock difference is
   tolerated. A token signed with a key ariodb has not seen fetches the
   keys again, so the provider can rotate them.
5. If `allowed_email_domains` is set, the token must carry an `email` with
   `email_verified` true, in one of those domains.
6. The groups claim decides the role: the highest role any of the person's
   groups maps to. Someone in none of the mapped groups is refused: "pat is
   not in any group that may use this dashboard".
7. ariodb starts a 12-hour dashboard session, the same kind of cookie as a
   password session, and returns to the page the person asked for.

People are named, on the dashboard and in the decisions they make, by
their verified email, otherwise their `preferred_username`, otherwise the
token's subject: a decision is recorded as `sso:pat@example.com`. An email
without `email_verified` true is not trusted, for the name or for
`allowed_email_domains`.

ariodb uses only the ID token: it does not call the provider's userinfo
endpoint, so the groups and email must be in the ID token itself.

### Registering ariodb with a provider

For any provider:

1. Register a web application (a confidential client with a secret; or a
   public client, with no secret, if the provider allows PKCE alone) using
   the authorisation code flow with PKCE.
2. Allow the redirect URI `<public_url><redirect_path>`, for example
   `https://ariodb.example.com/auth/callback`. With
   `logout_at_provider = true`, also allow the post-logout redirect URI
   `<public_url>/`.
3. Make the provider put the person's groups (or roles) in the **ID
   token**, under one claim, as a list of strings. Set `groups_claim` to
   its name if it is not `groups`.
4. Set `issuer` to the provider's issuer, exactly as its discovery document
   gives it, `client_id` to the application's ID, and the client secret in
   an environment variable or the secret store.
5. If the provider has no `groups` scope, set `scopes` without it; ariodb
   asks for `groups` by default whenever role groups are configured.

#### Keycloak

This is the set-up the end-to-end test, `scripts/e2e-sso.sh`, uses.

1. In the realm, create a client: client ID `ariodb`, client
   authentication on (confidential), the standard flow on, valid redirect
   URI `https://ariodb.example.com/auth/callback`, valid post-logout
   redirect URI `https://ariodb.example.com/*`, and the PKCE method `S256`.
   Copy the client secret from its Credentials tab.
2. Create a client scope named `groups` with a **Group Membership** mapper:
   token claim name `groups`, full group path off, added to the ID token.
   Add the scope to the client (as an optional scope is enough: ariodb asks
   for it).
3. Create groups such as `ariodb-admins` and `ariodb-approvers`, and put
   people in them.

```toml
[dashboard.oidc]
issuer = "https://keycloak.example.com/realms/ops"
provider_name = "Keycloak"
client_id = "ariodb"
client_secret_secret = "keycloak-client-secret"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers"]
logout_at_provider = true
```

With full group paths on, the claim holds `/ariodb-admins`, and the lists
must say so. To map realm roles instead of groups, set
`groups_claim = "realm_access.roles"` and make sure the realm roles mapper
adds them to the ID token, which it does not by default.

#### Okta

1. Create an app integration: OIDC, web application, with the
   authorisation code grant. Set the sign-in redirect URI to
   `https://ariodb.example.com/auth/callback` (and the sign-out redirect
   URI to `https://ariodb.example.com/` for `logout_at_provider`). Assign
   the groups who may use ariodb.
2. On the app's Sign On tab, set a **groups claim**: claim name `groups`,
   with a filter such as "Starts with `ariodb-`", so the ID token lists
   those groups.
3. Use the org authorisation server, whose issuer is your Okta domain and
   which knows the `groups` scope.

```toml
[dashboard.oidc]
issuer = "https://example.okta.com"
provider_name = "Okta"
client_id = "0oa1example2CLIENT3id"
client_secret_env = "ARIODB_OKTA_CLIENT_SECRET"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers"]
allowed_email_domains = ["example.com"]
```

With a custom authorisation server (an issuer such as
`https://example.okta.com/oauth2/default`), add a `groups` claim to its ID
tokens instead, and set `scopes = ["openid", "profile", "email"]` unless
you have defined a `groups` scope there.

#### Microsoft Entra ID

1. Register an application with a **Web** redirect URI of
   `https://ariodb.example.com/auth/callback`, and create a client secret.
2. Give the ID token the person's groups or roles. Either:
   - under **Token configuration**, add a groups claim (security groups,
     or "groups assigned to the application", which keeps the list short);
     the claim is `groups` and holds the groups' object IDs; or
   - define **app roles** such as `ariodb-admin`, assign people or groups
     to them under Enterprise applications, and set `groups_claim = "roles"`.
3. The issuer is `https://login.microsoftonline.com/<tenant ID>/v2.0`.

```toml
[dashboard.oidc]
issuer = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
provider_name = "Microsoft"
client_id = "11111111-1111-1111-1111-111111111111"
client_secret_secret = "entra-client-secret"
scopes = ["openid", "profile", "email"]       # Entra has no groups scope
admin_groups = ["22222222-2222-2222-2222-222222222222"]      # group object IDs
approver_groups = ["33333333-3333-3333-3333-333333333333"]
```

or, with app roles:

```toml
groups_claim = "roles"
admin_groups = ["ariodb-admin"]
approver_groups = ["ariodb-approver"]
```

Entra ID does not send `email_verified`, so `allowed_email_domains` refuses
everyone; limit sign-in by groups or app roles instead. People are named by
their `preferred_username` (usually their user principal name). Someone in
more groups than fit in a token gets no `groups` claim, and so no role;
"groups assigned to the application" or app roles avoid that.

#### Google Workspace

Google's ID tokens carry no groups, and Google has no `groups` scope. Two
claims Google does send can stand in, with `scopes` set without `groups`:

- `hd`, the Workspace domain, gives everyone in the domain one role;
- `email`, a single string, lets you list people by address.

1. In the Google Cloud console, create an OAuth client ID of type **Web
   application** with the authorised redirect URI
   `https://ariodb.example.com/auth/callback`. An "Internal" consent screen
   keeps sign-in to your Workspace.
2. Configure ariodb, always with `allowed_email_domains`, which also makes
   ariodb insist on a verified email:

```toml
[dashboard.oidc]
issuer = "https://accounts.google.com"
provider_name = "Google"
client_id = "123456789012-example.apps.googleusercontent.com"
client_secret_secret = "google-client-secret"
scopes = ["openid", "profile", "email"]
groups_claim = "email"
admin_groups = ["pat@example.com"]
approver_groups = ["sam@example.com", "lee@example.com"]
allowed_email_domains = ["example.com"]
```

To make everyone in the domain a viewer instead, use `groups_claim = "hd"`
and `viewer_groups = ["example.com"]`. To map Google groups to roles, put
a provider that puts groups in the token in front of Google (Keycloak, Okta
and Auth0 can all federate Google sign-in).

#### Auth0

1. Create a **Regular Web Application**. Add
   `https://ariodb.example.com/auth/callback` to its allowed callback URLs
   (and `https://ariodb.example.com/` to its allowed logout URLs for
   `logout_at_provider`).
2. Auth0 puts no groups in the ID token. Add a post-login Action that
   copies the person's roles into a claim, and use Auth0's roles (User
   Management, Roles) for `ariodb-admins` and the rest:

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.idToken.setCustomClaim("ariodb_roles", event.authorization?.roles ?? []);
   };
   ```

   ariodb reads a dotted `groups_claim` as a path into objects, so use a
   claim name without dots, not a namespaced URL such as
   `https://ariodb.example.com/roles`.
3. The issuer is your tenant's domain, with its trailing slash.

```toml
[dashboard.oidc]
issuer = "https://example.eu.auth0.com/"
provider_name = "Auth0"
client_id = "AbCdEfExampleClientId"
client_secret_env = "ARIODB_AUTH0_CLIENT_SECRET"
scopes = ["openid", "profile", "email"]
groups_claim = "ariodb_roles"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers"]
```

### Local passwords alongside single sign-on

`password_login` decides what local passwords are for once single sign-on
is configured:

- **`break_glass`** (the default): local passwords still work, offered
  below the sign-in button, for when the provider is down. Each such
  sign-in is logged: `ariodb: root signed in to the dashboard with a local
  password (break glass)`.
- **`off`**: password sign-in is refused ("local passwords are switched
  off; sign in with Okta"), and existing password sessions end at once.

The browser first-run page is switched off under single sign-on; set the
break-glass password on the host with `ariodb dashboard-password`. Local
users keep the roles given to them; they have no groups, so they cannot
decide requests for an approver that sets `groups`.

### Signing out

**Sign out** ends the dashboard session. With `logout_at_provider = true`,
it also sends the browser to the provider's `end_session_endpoint` (if the
discovery document has one), with the client ID and
`post_logout_redirect_uri` set to `<public_url>/`, so the provider's session
ends too. Otherwise the provider's session stays, and the next **Sign in**
may go straight through without a password.

### When sign-in fails

The page the provider returns to says why, and ariodb's log has a line
for each refusal (`ariodb: single sign-on refused pat@example.com: ...`).
The messages, their causes and fixes are in
[troubleshooting](troubleshooting.md#single-sign-on-and-roles).

### Approval links and approver groups

With single sign-on, approval links from webhook and channel approvers need
a signed-in approver by default (`[dashboard] approval_links = "sign_in"`),
who is recorded as the decider. An approver can also name `groups` whose
members alone may decide its requests. Both are described in
[approvals](approvals.md#who-may-decide).

## The pages

The sidebar has six main pages and Settings; people without the admin role
do not see Config. The approvals queue is
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
  recorded as `dashboard:<your user name>`, or `sso:<your name>` if you
  signed in with single sign-on. If you may not decide a request, its card
  has no buttons and says who may instead ("Only approvers and admins may
  decide this request.", or the members of the approver's `groups`).
- **Recent decisions**: past requests, newest first, with their status
  (`allowed`, `denied`, `expired`), who decided (a person, `slack:...`,
  `webhook`, `model:...`, `plugin:...`, `ariodb`, or "nobody (expired)"),
  any note, and the statement. Model and plugin approvers' decisions appear
  here too.

Anyone with the approver or admin role can decide any pending request,
including ones that were also announced in Slack, to a webhook or in a
channel, unless the approver sets `groups`: then only members of those
groups can (see [approvals](approvals.md#who-may-decide)). Viewers see the
queue but cannot decide. Links in Slack messages, webhook payloads and
channel messages (`<public_url>/#approval-<id>`) open this page with that
request highlighted; if it has already been decided, the page says how and
by whom.

### Decisions

Every statement agents sent, and what ariodb did with it, newest first.
This is the decisions log in `<state dir>/ariodb.db`.

Columns: when, agent, outcome, kind (ariodb's classification, such as
`read` or `write`), the rule that decided (empty for the built-in policy),
who decided its approvals, rows changed, latency in milliseconds, and the
statement.

Who decided is recorded with the entry itself, in the order they decided,
as the approvals list names them: `dashboard:<user>`, `sso:<user>`,
`slack:<user>`, `webhook` (a signed link followed without signing in),
`model:<provider>/<model>`, `plugin:<name>`, or `ariodb` (a request that
could not be delivered). A model that could not be reached under
`llm_fail_mode = "open"` is recorded as `ariodb:failed-open:model:...`,
since the model never allowed the statement. A refused statement names
who denied it. Entries written before ariodb recorded this show nobody.

Filters, applied on the server:

| Filter | Matches |
|---|---|
| Agent | Exact agent name |
| Outcome | `allowed`, `refused`, `rolled_back` or `failed` |
| Rule | Exact rule name |
| Decided by | Exactly this decider, such as `sso:pat@example.test` |
| Decider kind | Decided by a person, a model or a plugin |
| Text in statement | Any statement containing the text |
| Kind of decider | Statements held for approval and decided by a person, by a model or by a plugin |
| Decided by | Statements whose approval this decider decided, written as approvals record it (`sso:pat@example.com`, `dashboard:sam`, `slack:pat`, `webhook`, `model:anthropic/claude-opus-5-5`, `plugin:office_hours`); the field suggests everyone who has decided an approval |
| Latest | How many to show: 100, 200 (default), 500 or 1000 |

The filters are kept in the page's address, so a filtered view can be
bookmarked or shared with another dashboard user.

Each row's menu offers:

- **Block like this** (admins only): builds a deny rule matching this decision's agent,
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

Admins only. The config file `ariodb serve` is using, in an editor, with
its path.

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

- **Secrets** (admins only): the names in the encrypted secret store
  (never the values). Add a secret or replace one's value; names use
  letters, digits, `-` and `_`. To delete a secret, use
  `ariodb secret delete <name>`. `ariodb.approval-link-key`, which signs
  the channel approvers' links, is listed here but cannot be set from the
  dashboard (see [approvals](approvals.md#the-link-key)).
- **Dashboard users** (admins only): local users and their roles. Add a
  user with a role (viewer unless you choose another), set a new password
  for an existing one (which signs them out everywhere), change a role, or
  remove a user. `root` is always an admin and cannot be removed. With
  single sign-on, these are the break-glass users; people who sign in with
  the provider get their roles from their groups and are not listed.
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
- **This session**: who you are signed in as and how (a local password or
  the provider), your role and, with single sign-on, your groups, and
  **Sign out**. Sessions last 12 hours.

## How sign-in and changes are protected

| Protection | Detail |
|---|---|
| Roles | Checked by the server on every API request, from the users table (local users) or the person's groups and the current config (single sign-on). Hiding a button in the app is a convenience, not the check |
| Single sign-on | Authorisation code flow with PKCE, `state` and `nonce`; ID tokens checked for signature (public-key algorithms only), issuer, audience, expiry and nonce. See [how sign-in works](#how-sign-in-works) |
| Password storage | Argon2 hashes in `<state dir>/ariodb.db`; passwords of at least 12 characters |
| Guessing limits | After 5 failed sign-ins from one client address, or 20 against one existing user from anywhere, within 15 minutes, further attempts get HTTP 429 without the password being checked, until the window passes. A successful sign-in clears that address's and user's counts. Counts are kept in memory and reset when ariodb restarts |
| Timing | Every failed sign-in waits 400 ms; unknown user names are checked against a dummy hash, so a wrong answer takes as long whether or not the user exists |
| Session cookie | `ariodb_session`: a random 256-bit token, `HttpOnly`, `SameSite=Strict`, `Path=/`, valid 12 hours, and `Secure` when `public_url` starts with `https://`. The database stores only its SHA-256 hash |
| CSRF | Every change (deciding, undoing, saving, managing users or secrets, signing out) must carry the session's CSRF token in the `x-ariodb-csrf` header; the confirmation page behind a link that needs sign-in carries it in its form |
| Origin check | Changes, sign-in and first-run setup are refused ("cross-site request refused") when the browser's `Origin` host differs from the `Host` header |
| Page headers | A strict Content Security Policy (scripts only from the dashboard itself, no inline scripts, nothing from other sites), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` |
| Approval link and sign-in error pages | No scripts, never framed, not cached, no referrer |

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

- the dashboard link in Slack messages, webhook payloads and channel
  messages: `<public_url>/#approval-<id>`;
- decision links from webhook and channel approvers:
  `<public_url>/hooks/approvals/<id>?verdict=...&token=...`;
- with single sign-on, the redirect URI sent to the provider,
  `<public_url><redirect_path>`, and the post-logout redirect URI,
  `<public_url>/`, which must match what is registered there;
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

Slack has to reach `/slack/actions`, and people opening webhook and channel
links from outside your network have to reach `/hooks/approvals/`. Neither
needs the rest of the dashboard. If the dashboard should stay on your internal
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

`public_url` is used for both dashboard links and approval links, so with
split names, set it to the name the approval links should use, and expect
the "open in the dashboard" links to point there too.

This works only with `approval_links = "signed"`. With `"sign_in"` (the
default under single sign-on), the person opening a link needs a dashboard
session on that same name, so the sign-in paths (`/auth/login`, the
`redirect_path`, `/api/`) and the app itself must be reachable there too:
publish the whole dashboard, or keep the links for people on your
network.

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

- [Approvals](approvals.md): approvers, Slack, webhook and channel set-up, and who may decide.
- [Troubleshooting](troubleshooting.md#single-sign-on-and-roles): sign-in and role problems.
- [Undo](undo.md): what the Sessions page's plans mean.
- [Rules](rules.md): writing the rules the Rules page lists.
- [Security model](security-model.md): the dashboard's place in the threat model.
- [Operations](operations.md): running ariodb in production.
