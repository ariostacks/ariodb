# MCP server

This page explains `ariodb mcp`, which lets an AI agent use ariodb as a
Model Context Protocol (MCP) tool instead of connecting to the Postgres
proxy: what the server offers, how to configure it in an MCP client, how
ariodb's checks, approvals and undo apply to it, and where it falls short.
It is for engineers wiring a coding agent's MCP client to a
database through ariodb.

## When to use it

Agents that can open a Postgres connection should usually use the
[Postgres proxy](postgres.md): any driver works, and the agent never sees
anything but its own token. Use the MCP server when the agent's client
only speaks MCP, or when you would rather give the agent a single `query`
tool than a database connection string.

Either way the same checks apply: the built-in policy, the agent's table
allow-list, your [rules](rules.md), [approvals](approvals.md), the row
limit and effect check on writes, the decisions log, and the journal for
[undo](undo.md).

## How it runs

`ariodb mcp --agent <name>` is an MCP server on stdio. The MCP client
starts it as a child process and exchanges newline-delimited JSON-RPC 2.0
messages with it over stdin and stdout; log lines go to stderr.

```console
$ ariodb mcp --help
Run an MCP server on stdio for one agent

Usage: ariodb mcp [OPTIONS] --agent <AGENT>

Options:
      --agent <AGENT>    The agent name from the config file
  -c, --config <CONFIG>  Path to the config file [default: ariodb.toml]
  -h, --help             Print help
```

At start-up it:

1. loads the config and finds the `[[agents]]` entry named by `--agent`;
2. checks that `ARIODB_AGENT_TOKEN` in its environment equals that agent's
   token (from the agent's `token_env` variable or `token_secret`), and
   exits with an error otherwise;
3. starts any [plugins](plugins.md) that approve statements or supply
   facts (not audit sinks, which `ariodb serve` feeds from the same
   decisions log), and any [tunnels](configuration.md) it needs that are
   not already running;
4. opens one database connection for the agent, which is one ariodb
   session for the life of the process, and prints its ID to stderr:

   ```text
   ariodb mcp: session s-d4c9dddfdb for agent coding-agent
   ```

It then answers requests until stdin closes.

## The `query` tool

The server offers exactly one tool. `tools/list` returns:

```json
{
  "tools": [
    {
      "name": "query",
      "description": "Run SQL. Reads run read-only. Writes are limited in how many rows they may change, are recorded, and can be undone by a human. Send one statement at a time, without BEGIN or COMMIT.",
      "inputSchema": {
        "type": "object",
        "properties": { "sql": { "type": "string", "description": "The SQL to run" } },
        "required": ["sql"]
      }
    }
  ]
}
```

The `initialize` result also carries short instructions for the model:
"Run SQL against the database through ariodb. Writes are checked and can be
undone; destructive statements and schema changes are refused."

### Results

A read returns its rows as a JSON array of objects, one per row, keyed by
column name. Every value is a string as Postgres prints it, or `null`.
At most 500 rows are returned; past that, a note says how many there were:

```json
{"content":[{"type":"text","text":"[\n  {\n    \"id\": \"1\",\n    \"status\": \"paid\",\n    \"total\": \"1.00\"\n  },\n  {\n    \"id\": \"2\",\n    \"status\": \"paid\",\n    \"total\": \"2.00\"\n  }\n]"}],"isError":false}
```

A write returns Postgres's command tag:

```json
{"content":[{"type":"text","text":"UPDATE 2"}],"isError":false}
```

A refusal by ariodb, or an error from Postgres, comes back as a tool
result with `isError: true`, so the model sees why and can change course:

```json
{"content":[{"type":"text","text":"Refused by ariodb: destructive statements are never allowed for agents: DELETE without WHERE removes every row"}],"isError":true}
{"content":[{"type":"text","text":"Refused by ariodb: rolled back: the statement would change 12 rows (12 orders); the limit is 5"}],"isError":true}
{"content":[{"type":"text","text":"Refused by ariodb: agent 'coding-agent' may not use table 'nosuch'"}],"isError":true}
{"content":[{"type":"text","text":"Postgres error 42703: column \"nosuchcolumn\" does not exist"}],"isError":true}
```

(These are real answers from `ariodb mcp` with `max_rows_per_write = 5`.)

If the database connection itself fails, the tool result is
`connection to the database failed: ...`; restart the server to reconnect.

### Protocol support

| Method | Answer |
|---|---|
| `initialize` | Server info, `tools` capability, instructions. The protocol version the client asks for is echoed back (`2025-06-18` if it names none) |
| `ping` | `{}` |
| `tools/list` | The `query` tool |
| `tools/call` | Runs `query`; any other tool name, or a missing `sql`, is a tool error |
| Notifications (no `id`) | Ignored |
| Anything else (`resources/list`, `prompts/list`, ...) | JSON-RPC error `-32601`, "unknown method" |

Requests are handled one at a time, in order.

## Configuring an MCP client

The server needs, in its environment:

- `ARIODB_AGENT_TOKEN`: the agent's token, which must match the one in
  the config;
- the agent's own token variable (its `token_env`), unless the token is in
  the secret store, so the server can compare the two;
- the database login: `ARIODB_DATABASE_URL`, unless `[database]` names it
  another way, and any `url_env` of the agent's `[[credentials]]`;
- read and write access to the state directory (`[journal] dir`), where
  approvals and the decisions log live, and to `master.key` (or
  `ARIODB_MASTER_KEY`) if the config uses stored secrets.

Most MCP clients take a JSON configuration of this shape (the top-level
key and file location vary by client):

```json
{
  "mcpServers": {
    "ariodb": {
      "command": "/usr/local/bin/ariodb",
      "args": ["mcp", "--agent", "coding-agent", "--config", "/etc/ariodb/ariodb.toml"],
      "env": {
        "ARIODB_AGENT_TOKEN": "agent-token-local-test-only",
        "ARIODB_TOKEN_CODING_AGENT": "agent-token-local-test-only",
        "ARIODB_DATABASE_URL": "postgres://ariodb_gw:not-a-real-password@db.internal:5432/app"
      }
    }
  }
}
```

Use absolute paths for `command` and `--config`: clients start servers
from a working directory of their choosing, and a relative `[journal] dir`
in the config is resolved from that directory too, so make it absolute as
well.

To check the set-up by hand, send it a request on stdin:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ARIODB_AGENT_TOKEN=agent-token-local-test-only ariodb mcp --agent coding-agent -c /etc/ariodb/ariodb.toml
```

## How decisions apply

Each `tools/call` is handled exactly as a simple-protocol query string on
the Postgres proxy:

- **Classified with Postgres's parser**, then judged by the built-in policy
  and the agent's allow-list, then by before-stage rules.
- **Reads** run in a `READ ONLY` transaction.
- **Writes** run in a transaction that is tagged with the session, measured
  before commit (rows and tables changed, including by triggers and
  cascades), judged against the row limit, the agent's tables and
  after-stage rules, then committed or rolled back. A refused write's
  results never reach the agent.
- **Approvals**: a rule with `verdict = "approve"` holds the tool call
  until every approver decides, exactly as for the proxy. The tool call
  simply takes longer; the MCP client must not time it out before the
  approval timeout. Approvers see the session and agent as usual, and a
  person decides in the dashboard of `ariodb serve`, with `ariodb approve`,
  in Slack, or through the links a webhook or a chat, paging or email
  approver sends:

  ```json
  {"content":[{"type":"text","text":"Refused by ariodb: reading customer emails needs a person to agree: denied by cli:alice (use the reporting replica)"}],"isError":true}
  {"content":[{"type":"text","text":"Refused by ariodb: reading customer emails needs a person to agree: no decision from 'ops' within 90 seconds"}],"isError":true}
  ```

- **Decisions log**: every call is recorded, with the session, in the same
  decisions log the dashboard shows.
- **Undo**: writes are tagged with the session ID printed at start-up, and
  `ariodb sessions` lists the session once it has changed data. The
  journal that records those writes runs in `ariodb serve`, so keep
  `ariodb serve` running against the same database and state directory
  (see [undo.md](undo.md#operational-cautions)).
- Agent `BEGIN`, `COMMIT` and savepoints are refused; each call is its own
  transaction.

## Limits

- **Postgres only.** The MCP server talks to the Postgres database in
  `[database]` (or the agent's `[[credentials]]`). It does not reach
  ClickHouse; ClickHouse agents use the ClickHouse proxies.
- **One tool, one session.** There are no resources or prompts. A process
  is one ariodb session; undoing it undoes everything that process wrote.
  To make sessions smaller, have the client restart the server per task.
- **At most 500 rows** are returned per result; aggregate or page in SQL.
- **Values are text.** Numbers, booleans and JSON columns come back as
  strings.
- **No cancellation.** Unlike the Postgres proxy, a pending approval is not
  withdrawn when the client gives up; it waits until it is decided or
  times out.
- **A reconnect needs a restart.** If the database connection drops, the
  server reports it on each call until it is restarted.
- **The server runs with the client's privileges.** Because the MCP client
  starts `ariodb mcp` as a child process, the server's environment (with
  the database URL) and the state directory are available to whatever OS
  user runs the client. That is fine when the agent can only call tools.
  If the agent can also run shell commands or read files as that user, it
  can read the database credentials and go round ariodb entirely. For such
  agents, run ariodb as a different user or on a different host and point
  the agent at the Postgres proxy with only its token. See
  [security-model.md](security-model.md).

## Next

- [Postgres](postgres.md): the proxy, which most agents should use.
- [Approvals](approvals.md): what happens when a tool call needs a person.
- [Undo](undo.md): reversing what an MCP session wrote.
- [Configuration](configuration.md): agents, tokens and credentials.
- [Security model](security-model.md): the threats ariodb defends against.
