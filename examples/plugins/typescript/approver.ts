// An example ariodb approver plugin in TypeScript, for Node 22.18 or later
// (which runs .ts files directly). No dependencies.
//
// ariodb starts it and talks newline-delimited JSON-RPC 2.0 over stdin and
// stdout (see docs/plugins.md). Logs go to stderr, which ariodb copies into
// its own log.
//
// The policy: reads are allowed. Writes are allowed only to the tables in
// ARIODB_WRITABLE_TABLES (comma-separated); a write that names any other
// table, or none, is denied.
//
//   node approver.ts

import { createInterface } from "node:readline";

type Statement = { sql: string; kind: string; tables: string[]; functions: string[] };
type ApproveParams = {
  approval_id: string;
  agent: string;
  session: string;
  database: string;
  engine: string;
  rule: string;
  reason: string;
  statements: Statement[];
};
type Message = { jsonrpc: "2.0"; id?: number; method?: string; params?: any };

const writable = new Set(
  (process.env.ARIODB_WRITABLE_TABLES ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t !== ""),
);

function log(text: string): void {
  process.stderr.write(`ariodb-ts-approver: ${text}\n`);
}

function send(reply: object): void {
  // One JSON value per line: JSON.stringify never writes a raw newline.
  process.stdout.write(JSON.stringify(reply) + "\n");
}

function initialize(params: { protocol_version: number; ariodb_version: string }) {
  if (params.protocol_version !== 1) {
    throw new Error(`this plugin speaks protocol version 1, not ${params.protocol_version}`);
  }
  log(`started by ariodb ${params.ariodb_version}`);
  return {
    name: "ariodb-ts-approver",
    version: "1.0.0",
    protocol_version: 1,
    capabilities: { approver: true, facts: false, notifier: false, audit_sink: false },
  };
}

function approve(params: ApproveParams) {
  for (const s of params.statements) {
    if (s.kind === "read") continue;
    if (s.tables.length === 0) {
      return { verdict: "deny", note: "a write that names no table" };
    }
    const other = s.tables.filter((t) => !writable.has(t.toLowerCase()));
    if (other.length > 0) {
      return { verdict: "deny", note: `${other.join(", ")} may not be written by agents` };
    }
  }
  return { verdict: "allow", note: "reads, and writes to writable tables only" };
}

const methods: Record<string, (params: any) => object> = { initialize, approve };

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (line.trim() === "") return;
  let msg: Message;
  try {
    msg = JSON.parse(line);
  } catch {
    log("ignored a line that is not JSON");
    return;
  }
  if (msg.id === undefined || msg.id === null) {
    // Notifications (such as cancel) need no answer.
    if (msg.method === "cancel") log(`request ${msg.params?.approval_id} withdrawn`);
    return;
  }
  const handler = msg.method ? methods[msg.method] : undefined;
  if (!handler) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `unknown method ${msg.method}` } });
    return;
  }
  try {
    send({ jsonrpc: "2.0", id: msg.id, result: handler(msg.params ?? {}) });
  } catch (e) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: String(e) } });
  }
});
// ariodb closes stdin to stop the plugin.
lines.on("close", () => process.exit(0));
