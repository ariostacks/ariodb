// The dashboard's only way to talk to ariodb. Requests are same-origin with
// the session cookie; every request that changes something carries the
// session's CSRF token, which lives only in memory (never in storage).

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

let csrf: string | null = null
let onSignedOut: () => void = () => {}

export function setCsrf(token: string | null) {
  csrf = token
}

/** Called when the server says the session has gone (expired or signed out elsewhere). */
export function whenSignedOut(handler: () => void) {
  onSignedOut = handler
}

type Options = { method?: "GET" | "POST" | "PUT"; body?: unknown }

export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const method = opts.method ?? "GET"
  const headers: Record<string, string> = { accept: "application/json" }
  if (opts.body !== undefined) headers["content-type"] = "application/json"
  if (method !== "GET" && csrf) headers["x-ariodb-csrf"] = csrf
  const res = await fetch(path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    credentials: "same-origin",
    cache: "no-store",
  })
  const data = await res.json().catch(() => ({}))
  // A wrong password at sign-in is also a 401; that is not a lost session.
  if (res.status === 401 && path !== "/api/login") onSignedOut()
  if (!res.ok) {
    const message =
      typeof data?.error === "string" ? data.error : `Request failed (${res.status})`
    throw new ApiError(res.status, message)
  }
  return data as T
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

// ---------------------------------------------------------------------------
// Shapes of the JSON API (see src/dashboard.rs and src/dashboard_api.rs).

export type Me =
  | { user: string; csrf: string }
  | { user: null; needs_setup: boolean }

export type Session = { user: string; csrf: string }

export type Overview = {
  pending_approvals: number
  decisions_24h: { outcome: string; count: number }[]
  sessions_with_changes: number
  sessions_undone: number
  agents: {
    name: string
    access: string
    tables: string[]
    credential: string | null
    token_set: boolean
  }[]
  rules: number
  approvers: { name: string; type: string }[]
  journal: boolean
  proxy: string
  version: string
}

export type Approval = {
  id: string
  created_ms: number
  expires_ms: number
  agent: string
  session: string
  sql: string
  rule: string
  approver: string
  reason: string
  status: "pending" | "allowed" | "denied" | "expired" | string
  decided_by: string | null
  note: string | null
  decided_ms: number | null
}

export type Decision = {
  id: number
  at_ms: number
  session: string
  agent: string
  sql: string
  kind: string
  tables: string[]
  outcome: string
  rows: number | null
  reason: string | null
  rule: string | null
  latency_ms: number | null
}

export type BlockLike = { rule: string; snippet: string; applied: boolean }

export type AgentSession = {
  session: string
  agent: string
  transactions: number
  rows: number
  tables: string[]
  last_at_ms: number
  undone: boolean
}

export type UndoPlan = {
  session: string
  steps: string[]
  conflicts: string[]
  blocked: string[]
  already_undone: boolean
}

export type Rule = {
  name: string
  condition: string
  verdict: string
  approve: string[]
  reason: string
  agents: string[]
  priority: number
  stage: string
}

export type Explain = { verdict: string; rule: string | null; reason: string | null }

export type ConfigFile = { text: string; path: string; writable: boolean }

export type ConfigCheck =
  | { ok: true; agents: number; rules: number; approvers: number }
  | { ok: false; error: string }

export type AuditCheck = { ok: true; entries: number } | { ok: false; error: string }
