# Plugins

A plugin is any program ariodb starts and talks to over its stdin and
stdout, one JSON-RPC 2.0 message per line, as MCP's stdio transport does. A
plugin can do any of four things:

| Capability | What ariodb asks of it |
|---|---|
| `approver` | Allow or deny a statement a rule held for approval |
| `facts` | Supply facts that rules read as `plugin.<name>.<key>` |
| `notifier` | Hear about approvals, refusals, rollbacks and undos |
| `audit_sink` | Receive every entry of the decisions log, in order, at least once |

This page covers configuring plugins, their lifecycle, the protocol, the
commands for trying them out, and their security. It is for operators
adding approvers or notifiers and for anyone writing a plugin.

Plugins can be written in anything that reads and writes lines. Two
examples come with ariodb:

- [`examples/plugins/python/ariodb_plugin.py`](../examples/plugins/python/ariodb_plugin.py):
  all four capabilities, standard library only (Python 3.9 or later). Its
  policy denies writes out of hours (18:00 to 07:00 GMT) and anything
  touching tables on a deny list, tells rules about a change freeze, writes
  events and decisions to files.
- [`examples/plugins/typescript/approver.ts`](../examples/plugins/typescript/approver.ts):
  an approver for Node 22.18 or later, no dependencies. It allows reads, and
  writes only to tables listed in `ARIODB_WRITABLE_TABLES`.

## Configuration

```toml
[[plugins]]
name = "office_hours"         # letters, digits and underscores; rules use plugin.office_hours.<key>
command = ["python3", "-I", "examples/plugins/python/ariodb_plugin.py"]
timeout_ms = 5000             # default 5000; per call (approvals use the approver's timeout instead)
facts_cache_ms = 0            # default 0; reuse a facts answer for the same request this long
pass_env = ["ARIODB_PAGER_TOKEN"]          # pass these variables from ariodb's environment
secret_env = { PAGER_KEY = "pager-key" }   # variables filled from the secret store
env = { ARIODB_EXAMPLE_AUDIT_FILE = "/var/log/ariodb/decisions.jsonl" }

[[plugins]]
name = "ts_approver"
command = ["node", "examples/plugins/typescript/approver.ts"]
env = { ARIODB_WRITABLE_TABLES = "orders" }

[[approvers]]
name = "office-hours"
type = "plugin"
plugin = "office_hours"       # the [[plugins]] entry that decides
timeout_seconds = 10          # optional, overrides [approvals] timeout_seconds

[[rules]]
name = "writes-need-office-hours"
condition = "sql.kind == 'write'"
verdict = "approve"
approve = ["office-hours"]

[[rules]]
name = "change-freeze"
condition = "plugin.office_hours.freeze && sql.kind != 'read'"
verdict = "deny"
reason = "change freeze"
```

- `command` is run directly, not through a shell, in ariodb's working
  directory. A program without a `/` is looked up on `PATH`.
- The plugin's environment is `PATH` and `HOME`, the variables named in
  `pass_env`, then `secret_env` (from `ariodb secret set`), then `env`.
  Nothing else of ariodb's environment reaches it, so database URLs and
  agent tokens in ariodb's environment stay out of it. Keep credentials out
  of `env` (the config file is often in Git); use `pass_env` or
  `secret_env`.
- `ariodb check` refuses a config whose approvers or rules name a plugin
  that is not defined, and a rule that reads plugin facts in any form other
  than `plugin.<name>`.

## Lifecycle

- `ariodb serve` starts every plugin after its tunnels and before it accepts
  agents, and waits up to ten seconds for each to finish its handshake. A
  plugin that fails to start does not stop ariodb; it is retried, and
  anything that needs it is refused meanwhile.
- A plugin that exits, closes its stdout, or breaks the protocol (a line
  over 1 MiB) is restarted after 1 s, doubling to 30 s; a minute of good
  running resets the delay. The log says why, for example
  `ariodb: plugin 'broken' exited with status 3; restarting it in 1 s`.
- On shutdown ariodb closes the plugin's stdin and gives it two seconds to
  exit, then sends SIGTERM to its process group, and SIGKILL five seconds
  later. A plugin should exit when its stdin ends.
- Each plugin runs in its own process group, so a Ctrl-C at ariodb's
  terminal reaches ariodb, which then stops the plugins in order.
- `ariodb mcp` starts the plugins too, so approvers and facts work for MCP
  agents; it does not deliver the decisions log, which `ariodb serve` does.
  `ariodb undo --apply` starts them briefly to tell notifiers. A plugin may
  therefore run in more than one process at once.
- Plugin changes in a reloaded config take effect at the next restart, as
  for tunnels and listen addresses. Rules and approvers reload as usual.
- Everything a plugin writes to stderr appears in ariodb's log, one line at
  a time, as `plugin <name>: <line>`.

## Protocol

### Framing

- Each message is one JSON object encoded in UTF-8 on one line, ending with
  `\n` (a `\r` before it is ignored). JSON never needs a raw newline inside
  a value, so a message can never be split or spliced by its contents.
- Batches (JSON arrays) are not supported.
- ariodb reads at most 1 MiB per line from a plugin. A longer line is a
  protocol error: it is discarded without being held in memory, and the
  plugin is restarted.
- Lines from ariodb carry agent SQL and can be several MiB long; read them
  without a small fixed limit.
- Lines that are not JSON-RPC 2.0 are logged and ignored. Write logs to
  stderr, never stdout.
- Each plugin has its own pipes. A plugin sees only its own messages and
  cannot write into another plugin's stream.

### Requests and answers

ariodb's requests carry `"jsonrpc": "2.0"`, an integer `id`, a `method` and
`params`. Answer each with the same `id`, unchanged, and exactly one of
`result` or `error`:

```json
{"jsonrpc":"2.0","id":7,"method":"approve","params":{...}}
{"jsonrpc":"2.0","id":7,"result":{"verdict":"allow"}}
{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"policy file unreadable"}}
```

- ariodb may send a request before an earlier one is answered. Answers may
  come in any order; ariodb matches them by `id`.
- An answer whose `id` names no waiting request (a late answer, or one ariodb
  never asked) is logged and ignored: an answer can only ever decide the
  request it names.
- An error answer, a malformed `result`, a timeout, or the plugin exiting
  before it answers all count as failures. On a deciding path (approvals and
  facts), a failure refuses the statement.
- ariodb accepts no requests from plugins; it answers any with error
  `-32601`. Notifications from plugins are logged and ignored.

### `initialize`

The first request, sent as soon as the plugin starts. Nothing else is sent
until it is answered (within ten seconds).

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
  "protocol_version":1, "ariodb_version":"0.1.0", "name":"office_hours"}}
```

`name` is the plugin's name in the config. Answer:

```json
{"jsonrpc":"2.0","id":1,"result":{
  "name":"ariodb-example", "version":"1.0.0", "protocol_version":1,
  "capabilities":{"approver":true, "facts":true, "notifier":true, "audit_sink":false}}}
```

`name` and `version` (strings) and `capabilities` are required; a missing
capability counts as `false`, and unknown ones are ignored.
`protocol_version` is optional; if given, it must be `1`. Calls for a
capability the plugin did not declare are never sent: whatever needed them
is refused (`plugin 'x' did not declare the approver capability`).

### `approve` (approver)

Sent when a rule holds statements for an approver with `type = "plugin"`.

```json
{"jsonrpc":"2.0","id":8,"method":"approve","params":{
  "approval_id":"a-3f9c0e1b2a4d",
  "approver":"office-hours",
  "agent":"coding-agent",
  "session":"s-d4c9dddfdb",
  "database":"app",
  "engine":"postgres",
  "rule":"writes-need-office-hours",
  "reason":"rule 'writes-need-office-hours'",
  "statements":[{"sql":"UPDATE orders SET status = 'void' WHERE id = 7",
                 "kind":"write", "tables":["orders"], "functions":[]}]}}
```

`kind` is ariodb's judgement (`read`, `write`, `destructive`,
`schema_change`, `session`, `transaction`, `unknown`); `tables` and
`functions` are lower case, tables without `public.`. Answer:

```json
{"jsonrpc":"2.0","id":8,"result":{"verdict":"deny","note":"writes stop at 18:00 GMT"}}
```

`verdict` must be exactly `"allow"` or `"deny"`; `note` is an optional
string (up to 1,000 characters are kept). The agent sees the note when the
statement is denied.

- The time limit is the approver's `timeout_seconds`, or
  `[approvals] timeout_seconds` (90 by default).
- If an agent on the Postgres proxy disconnects or cancels while it
  waits, the request is withdrawn and the plugin is told with a `cancel`
  notification (ClickHouse requests and `ariodb mcp` tool calls are not
  withdrawn this way):
  `{"jsonrpc":"2.0","method":"cancel","params":{"id":8,"approval_id":"a-3f9c0e1b2a4d","reason":"the agent disconnected"}}`.
  Any later answer is ignored.
- Every outcome is recorded with people's and models' decisions (`ariodb
  approvals --all`, the dashboard): a verdict as decided by `plugin:<name>`;
  a failure as denied by `ariodb`, with the reason in the note; a withdrawal
  as expired.

### `facts` (facts)

Sent before a statement runs, but only when a before-stage rule that
applies to the agent mentions `plugin.<name>`. Statements no such rule
applies to cost no call.

```json
{"jsonrpc":"2.0","id":9,"method":"facts","params":{
  "agent":"coding-agent", "session":"s-d4c9dddfdb", "database":"app", "engine":"postgres",
  "statements":[{"sql":"UPDATE orders SET status = 'void' WHERE id = 7",
                 "kind":"write", "tables":["orders"], "functions":[]}]}}
```

Answer with a JSON object; rules read its keys as `plugin.<name>.<key>`
(nested objects and lists work as in CEL):

```json
{"jsonrpc":"2.0","id":9,"result":{"hour_gmt":19, "out_of_hours":true, "freeze":false}}
```

- The time limit is the plugin's `timeout_ms`.
- If the call fails, times out, or the answer is not an object, every rule
  that reads this plugin's facts cannot be evaluated, which, as for any
  rule, refuses the statement. A missing key is an evaluation error too.
- With `facts_cache_ms`, an answer is reused for an identical request
  (same agent, session, database and statement) for that long. At most
  1,000 answers are kept per plugin; past that the oldest are dropped.
- Plugin facts are for before-stage rules only; `ariodb check` refuses a
  `stage = "after"` rule that reads them. `ariodb explain` and `ariodb test`
  do not start plugins, so they report such rules as unevaluable (a deny).

### `event` (notifier)

A notification (no `id`, no answer) for each event:

```json
{"jsonrpc":"2.0","method":"event","params":{"event":"statement_refused","at_ms":1791548400000,
  "details":{"agent":"coding-agent","session":"s-d4c9dddfdb","database":"app","engine":"postgres",
             "sql":"UPDATE orders SET status = 'frozen' WHERE id = 2","kind":"write",
             "tables":["orders"],"rows":null,"reason":"change freeze","rule":"change-freeze"}}}
```

| Event | Details |
|---|---|
| `approval_requested` | `rule`, `approver`, `approver_type`, `agent`, `session`, `database`, `sql`, `reason` |
| `approval_decided` | as above, plus `verdict` (`allow` or `deny`) and `why` (the refusal, or null) |
| `statement_refused` | `agent`, `session`, `database`, `engine`, `sql`, `kind`, `tables`, `rows`, `reason`, `rule` |
| `write_rolled_back` | as `statement_refused` |
| `undo_applied` | `session`, `rows` restored, `by` (`cli:<user>` or `dashboard:<user>`) |

- Events are queued per plugin (up to 1,000) and never hold up a statement.
  When the queue is full, new events are dropped and counted; the log says
  how many, and the dashboard shows the count. Events wait in the queue
  while the plugin restarts.
- Every event carries statements as the decisions log stores them, so
  `[audit] redact_literals` applies to approval events too. (The approver
  itself, like a person approving in Slack, sees the statement as written.)
- Delivery is at most once. Use `audit_sink` for a complete record.

### `audit` (audit_sink)

Sent by `ariodb serve` with the next entries of the decisions log, oldest
first, up to 100 entries or about 4 MiB of statements at a time:

```json
{"jsonrpc":"2.0","id":12,"method":"audit","params":{"entries":[
  {"id":41,"at_ms":1791548400000,"session":"s-d4c9dddfdb","agent":"coding-agent",
   "sql":"SELECT count(*) FROM orders","kind":"read","tables":["orders"],"outcome":"allowed",
   "rows":1,"reason":null,"rule":null,"latency_ms":3,"engine":"postgres","database":"app",
   "prev":"9b1f…","hash":"c04e…"}]}}
```

`outcome` is `allowed`, `refused`, `rolled_back` or `failed`. `prev` and
`hash` are the entry's links in the decisions log's hash chain, so a sink
can check the chain itself (see SECURITY.md, A1). Answer with the `id` of
the last entry stored durably:

```json
{"jsonrpc":"2.0","id":12,"result":{"ack":41}}
```

- ariodb keeps a cursor per plugin (in `ariodb.db` in the state directory)
  and moves it to `ack` only when the answer arrives. The next batch starts
  after it. Acknowledging part of a batch is allowed; the rest is sent
  again. An `ack` that is not an id in the batch, an error or a timeout
  moves nothing, and the batch is retried after 1 s, doubling to 30 s.
- So every entry is delivered in order, at least once, across restarts of
  ariodb and of the plugin. An entry can arrive twice if the plugin stored
  it but its acknowledgement was lost; use `id` to discard repeats.
- A new sink starts from the oldest entry the decisions log still holds.
  Entries pruned by `[audit] retention_days` before delivery are lost.

### Test calls

`ariodb plugin test <name>` sends one sample call for each declared
capability, with `"test": true` in `params` (the `audit` sample is one entry
with `id` 0). Answer them normally, but do not act on them: do not store
the sample entry, page anyone or count it.

## Commands

```bash
ariodb plugin list          # start each plugin once and show what it declares
ariodb plugin test <name>   # sample call per capability; exit 1 if any fails
```

```text
$ ariodb plugin test office_hours
started: ariodb-example 1.0.0
  ok    approve: allow (within the example policy)
  ok    facts: {"freeze":false,"hour_gmt":10,"out_of_hours":false,"weekday":"fri"}
  ok    notifier: sent a test event (notifications get no answer)
  ok    audit: acknowledged
```

The dashboard's settings page lists each plugin with its state, process id,
restarts, last error and dropped events (also at `GET /api/plugins`).

## Running the examples

```bash
# Python: all four capabilities
python3 -I examples/plugins/python/ariodb_plugin.py      # speaks the protocol on stdin/stdout
# TypeScript: an approver (Node 22.18 or later runs .ts directly)
node examples/plugins/typescript/approver.ts
```

Point `[[plugins]] command` at them as in the configuration above, then
`ariodb plugin test <name>`. The Python example's settings are environment
variables, described at the top of the file.

## Security

- **Plugins run as ariodb's user**, with that user's access to files and
  the network. They see every statement they are asked about (approvers and
  facts), every event (notifiers), and the whole decisions log (audit
  sinks), including literal values unless `redact_literals` is on. Install
  only plugins you trust as much as ariodb itself, and keep them where only
  ariodb's owner can change them.
- A plugin decides only what it is asked: an approver can allow only what a
  rule held for it, and facts feed only rules; neither can allow what the
  built-in policy refuses.
- Every failure on a deciding path refuses the statement: a plugin that is
  down, starting, slow, crashing, answering with the wrong id, or answering
  anything other than `allow` or `deny`.
- What ariodb guards against in the protocol: lines are capped at 1 MiB and
  read without holding more (a line that passes the cap restarts the
  plugin at once, even if it never ends); every message ariodb writes is a single
  serialised JSON value, so agent SQL cannot forge a message; each plugin
  has its own pipes; answers are matched to requests by id; plugin text
  (notes, errors, stderr) has control characters removed before it is
  logged or shown.
- The plugin's environment is limited to what the config names. It does not
  inherit ariodb's database URLs, agent tokens or API keys.

## Next

- [Approvals](approvals.md): plugin approvers alongside the other kinds.
- [Rules](rules.md): reading plugin facts as `plugin.<name>.<key>`.
- [Architecture](architecture.md#plugins): how ariodb supervises plugins.
- [Security model](security-model.md): why plugins are trusted code.
