import { useState, type FormEvent } from "react"
import {
  CheckCircle2Icon,
  KeyRoundIcon,
  Loader2Icon,
  LogOutIcon,
  ShieldCheckIcon,
  Trash2Icon,
  UserPlusIcon,
} from "lucide-react"
import { toast } from "sonner"
import { ErrorNote, Loading, PageBody } from "@/components/page"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { StatusBadge } from "@/components/status-badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { api, errorText, ROLES, type AuditCheck, type DashboardUser, type PluginStatus, type Role } from "@/lib/api"
import { useApi } from "@/lib/hooks"
import { useCan, useMe } from "@/lib/me"

function RoleSelect({
  value,
  onChange,
  disabled,
  label,
  id,
}: {
  value: Role
  onChange: (r: Role) => void
  disabled?: boolean
  label: string
  id?: string
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Role)} disabled={disabled}>
      <SelectTrigger id={id} aria-label={label} className="w-36">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {ROLES.map((r) => (
          <SelectItem key={r.role} value={r.role}>
            {r.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

const NAME_PATTERN = "[A-Za-z0-9_-]+"
const USER_PATTERN = "[A-Za-z0-9_.@-]+"

function Secrets() {
  const { data, error, loading, reload } = useApi<{ secrets: string[] }>("/api/secrets")
  const [name, setName] = useState("")
  const [value, setValue] = useState("")
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setFormError(null)
    try {
      await api(`/api/secrets/${encodeURIComponent(name)}`, { method: "POST", body: { value } })
      toast.success(`Secret ${name} saved.`)
      setName("")
      setValue("")
      await reload()
    } catch (err) {
      setFormError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Secrets</CardTitle>
        <CardDescription>Encrypted at rest. Values can be replaced but are never shown.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <ErrorNote message={error} />}
        {loading && !data ? (
          <Loading rows={1} />
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data?.secrets.length ? (
              data.secrets.map((n) => (
                <Badge key={n} variant="secondary" className="font-mono">
                  <KeyRoundIcon />
                  {n}
                </Badge>
              ))
            ) : (
              <span className="text-sm text-muted-foreground">None yet.</span>
            )}
          </div>
        )}
        <form onSubmit={submit}>
          <FieldGroup className="gap-3">
            <Field>
              <FieldLabel htmlFor="secret-name">Name</FieldLabel>
              <Input
                id="secret-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                pattern={NAME_PATTERN}
                required
                autoComplete="off"
                className="font-mono"
              />
              <FieldDescription>Letters, digits, - and _. An existing name is replaced.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="secret-value">Value</FieldLabel>
              <Input
                id="secret-value"
                type="password"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                required
                autoComplete="off"
              />
            </Field>
            {formError && <ErrorNote title="Not saved" message={formError} />}
            <Button type="submit" disabled={busy} className="self-start">
              {busy && <Loader2Icon className="animate-spin" />}
              Save secret
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

function Users() {
  const me = useMe()
  const { data, error, loading, reload } = useApi<{ users: DashboardUser[] }>("/api/users")
  const [name, setName] = useState("")
  const [password, setPassword] = useState("")
  const [role, setRole] = useState<Role>("viewer")
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const existing = data?.users.find((u) => u.name === name)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setFormError(null)
    try {
      // Resetting a password leaves the role alone; roles change in the list.
      await api("/api/users", {
        method: "POST",
        body: existing ? { name, password } : { name, password, role },
      })
      toast.success(existing ? `Password for ${name} reset.` : `User ${name} added.`)
      setName("")
      setPassword("")
      await reload()
    } catch (err) {
      setFormError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  async function change(user: string, r: Role) {
    try {
      await api(`/api/users/${encodeURIComponent(user)}/role`, { method: "POST", body: { role: r } })
      toast.success(`${user} is now ${ROLES.find((x) => x.role === r)?.label.toLowerCase() ?? r}.`)
    } catch (err) {
      toast.error(errorText(err))
    }
    await reload()
  }

  async function remove(user: string) {
    try {
      await api(`/api/users/${encodeURIComponent(user)}`, { method: "DELETE" })
      toast.success(`${user} removed.`)
    } catch (err) {
      toast.error(errorText(err))
    }
    await reload()
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Local users</CardTitle>
        <CardDescription>
          {me.provider
            ? `People who sign in with ${me.provider} get their role from their groups. Local users are for break-glass use.`
            : "A new password signs that user out everywhere."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <ErrorNote message={error} />}
        {loading && !data ? (
          <Loading rows={1} />
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {data?.users.map((u) => (
              <li key={u.name} className="flex items-center gap-2 px-3 py-2 text-sm">
                <span className="min-w-0 flex-1 truncate font-medium">{u.name}</span>
                <RoleSelect
                  value={u.role}
                  label={`Role for ${u.name}`}
                  disabled={u.name === "root"}
                  onChange={(r) => void change(u.name, r)}
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-muted-foreground"
                  disabled={u.name === "root"}
                  title={u.name === "root" ? "root cannot be removed" : undefined}
                  onClick={() => void remove(u.name)}
                >
                  <Trash2Icon />
                  <span className="sr-only">Remove {u.name}</span>
                </Button>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={submit}>
          <FieldGroup className="gap-3">
            <Field>
              <FieldLabel htmlFor="user-name">User name</FieldLabel>
              <Input
                id="user-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                pattern={USER_PATTERN}
                required
                autoComplete="off"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="user-password">Password</FieldLabel>
              <Input
                id="user-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={12}
                required
                autoComplete="new-password"
              />
              <FieldDescription>At least 12 characters. A new password signs that user out everywhere.</FieldDescription>
            </Field>
            {!existing && (
              <Field>
                <FieldLabel htmlFor="user-role">Role</FieldLabel>
                <RoleSelect id="user-role" value={role} label="Role" onChange={setRole} />
                <FieldDescription>{ROLES.find((r) => r.role === role)?.can}.</FieldDescription>
              </Field>
            )}
            {formError && <ErrorNote title="Not saved" message={formError} />}
            <Button type="submit" disabled={busy} className="self-start">
              {busy ? <Loader2Icon className="animate-spin" /> : <UserPlusIcon />}
              {existing ? "Reset password" : "Add user"}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

const CAPABILITIES = ["approver", "facts", "notifier", "audit_sink"] as const

function Plugins() {
  const { data, error, loading } = useApi<{ plugins: PluginStatus[] }>("/api/plugins", 5000)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Plugins</CardTitle>
        <CardDescription>
          Programs ariodb runs as approvers, rule facts, notifiers and audit sinks. Changes to them need a restart.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <ErrorNote message={error} />}
        {loading && !data ? (
          <Loading rows={1} />
        ) : !data?.plugins.length ? (
          <span className="text-sm text-muted-foreground">None configured.</span>
        ) : (
          data.plugins.map((p) => (
            <div key={p.name} className="flex flex-col gap-1.5 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono font-medium">{p.name}</span>
                <StatusBadge status={p.state} />
                {p.declared && (
                  <span className="text-muted-foreground">
                    {p.declared.name} {p.declared.version}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {CAPABILITIES.filter((c) => p.declared?.capabilities[c]).map((c) => (
                  <Badge key={c} variant="secondary" className="font-mono">
                    {c}
                  </Badge>
                ))}
              </div>
              <div className="text-muted-foreground">
                {p.pid !== null && <>pid {p.pid} · </>}
                {p.restarts} {p.restarts === 1 ? "restart" : "restarts"}
                {p.dropped_events > 0 && <> · {p.dropped_events.toLocaleString()} events dropped</>}
              </div>
              {p.last_error && (
                <div className="font-mono text-xs break-all text-muted-foreground">Last error: {p.last_error}</div>
              )}
            </div>
          ))
        )}
      </CardContent>
    </Card>
  )
}

function AuditLog() {
  const [result, setResult] = useState<AuditCheck | null>(null)
  const [busy, setBusy] = useState(false)

  async function verify() {
    setBusy(true)
    try {
      setResult(await api<AuditCheck>("/api/audit/verify"))
    } catch (e) {
      setResult({ ok: false, error: errorText(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Decisions log</CardTitle>
        <CardDescription>
          Each entry is chained to the one before it by a hash, so edits and deletions show.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {result &&
          (result.ok ? (
            <Alert className="text-emerald-700 dark:text-emerald-400">
              <CheckCircle2Icon />
              <AlertDescription className="text-current">
                Intact: {result.entries.toLocaleString()} entries checked.
              </AlertDescription>
            </Alert>
          ) : (
            <ErrorNote title="The chain is broken" message={result.error} />
          ))}
      </CardContent>
      <CardFooter>
        <Button variant="outline" onClick={verify} disabled={busy}>
          {busy ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />}
          Check the chain
        </Button>
      </CardFooter>
    </Card>
  )
}

export function SettingsPage({ onSignOut }: { onSignOut: () => void }) {
  const me = useMe()
  const admin = useCan("admin")
  const role = ROLES.find((r) => r.role === me.role)
  return (
    <PageBody>
      <div className="grid gap-4 @4xl/main:grid-cols-2">
        {admin && <Secrets />}
        {admin && <Users />}
        <AuditLog />
        <Plugins />
        <Card>
          <CardHeader>
            <CardTitle>This session</CardTitle>
            <CardDescription>
              Signed in as <span className="font-medium text-foreground">{me.email ?? me.user}</span>
              {me.method === "sso" ? ` with ${me.provider ?? "single sign-on"}` : " with a local password"}.
              Sessions last 12 hours.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            <div>
              <Badge variant="secondary">{role?.label ?? me.role}</Badge>{" "}
              <span className="text-muted-foreground">{role?.can}.</span>
            </div>
            {me.groups.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-muted-foreground">Groups</span>
                {me.groups.map((g) => (
                  <Badge key={g} variant="outline">
                    {g}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
          <CardFooter className="mt-auto">
            <Button variant="outline" onClick={onSignOut}>
              <LogOutIcon />
              Sign out
            </Button>
          </CardFooter>
        </Card>
      </div>
    </PageBody>
  )
}
