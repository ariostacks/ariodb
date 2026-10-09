import { useMemo, useState, type FormEvent } from "react"
import { Loader2Icon, SparklesIcon } from "lucide-react"
import { columnHelper, DataTable } from "@/components/data-table"
import { ErrorNote, Loading, PageBody } from "@/components/page"
import { Sql } from "@/components/sql"
import { StatusBadge } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { api, errorText, type Explain, type Overview, type Rule } from "@/lib/api"
import { useApi } from "@/lib/hooks"

function TryStatement() {
  const agents = useApi<Overview>("/api/overview").data?.agents.map((a) => a.name) ?? []
  const [agent, setAgent] = useState("")
  const [sql, setSql] = useState("")
  const [result, setResult] = useState<Explain | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const chosen = agent || agents[0] || ""

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setResult(await api<Explain>("/api/explain", { method: "POST", body: { agent: chosen, sql } }))
    } catch (err) {
      setResult(null)
      setError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Try a statement</CardTitle>
        <CardDescription>See what ariodb would decide, without running anything.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="explain-agent">Agent</FieldLabel>
              {agents.length > 0 ? (
                <Select value={chosen} onValueChange={setAgent}>
                  <SelectTrigger id="explain-agent" className="w-full sm:w-64">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {agents.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  id="explain-agent"
                  value={agent}
                  onChange={(e) => setAgent(e.target.value)}
                  className="sm:w-64"
                  placeholder="Agent name"
                />
              )}
            </Field>
            <Field>
              <FieldLabel htmlFor="explain-sql">Statement</FieldLabel>
              <Textarea
                id="explain-sql"
                rows={4}
                value={sql}
                onChange={(e) => setSql(e.target.value)}
                placeholder="SELECT * FROM orders"
                className="font-mono text-xs"
                spellCheck={false}
              />
            </Field>
            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" disabled={busy || !sql.trim() || !chosen}>
                {busy ? <Loader2Icon className="animate-spin" /> : <SparklesIcon />}
                Explain
              </Button>
              {result && (
                <div className="flex flex-col gap-1 text-sm" role="status">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge status={result.verdict} />
                    <span className="text-muted-foreground">decided by</span>
                    <code className="font-mono text-xs">{result.rule || "no rule (the built-in policy)"}</code>
                  </div>
                  {result.reason && <p className="text-muted-foreground">{result.reason}</p>}
                </div>
              )}
            </div>
            {error && <ErrorNote message={error} />}
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

export function RulesPage() {
  const { data, error, loading } = useApi<{ rules: Rule[] }>("/api/rules")
  const columns = useMemo(() => {
    const col = columnHelper<Rule>()
    return col.columns([
      col.accessor("name", {
        header: "Rule",
        sortFn: "text",
        cell: ({ row }) => (
          <div className="flex max-w-[32ch] flex-col gap-0.5 whitespace-normal">
            <span className="font-medium">{row.original.name}</span>
            {row.original.reason && <span className="text-xs text-muted-foreground">{row.original.reason}</span>}
          </div>
        ),
      }),
      col.accessor("verdict", {
        header: "Verdict",
        sortFn: "text",
        cell: ({ row }) => (
          <div className="flex flex-col items-start gap-1">
            <StatusBadge status={row.original.verdict} />
            {row.original.approve.length > 0 && (
              <span className="text-xs text-muted-foreground">{row.original.approve.join(", ")}</span>
            )}
          </div>
        ),
      }),
      col.accessor("stage", { header: "Stage", sortFn: "text" }),
      col.accessor("priority", {
        header: "Priority",
        sortFn: "basic",
        cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
      }),
      col.accessor("condition", {
        header: "Condition",
        enableSorting: false,
        cell: ({ getValue }) => <Sql clamp>{getValue() || "(always)"}</Sql>,
      }),
      col.accessor((r) => r.agents.join(", "), {
        id: "agents",
        header: "Agents",
        enableSorting: false,
        cell: ({ getValue }) => <span className="whitespace-normal">{getValue() || "all"}</span>,
      }),
    ])
  }, [])

  return (
    <PageBody intro="Checked on top of each agent's built-in policy. Any matching deny wins; then priority decides between allow and approve.">
      <TryStatement />
      <section className="flex flex-col gap-3" aria-labelledby="rules-heading">
        <h2 id="rules-heading" className="text-sm font-medium">
          {data ? `${data.rules.length} rules` : "Rules"}
        </h2>
        {error && <ErrorNote message={error} />}
        {loading && !data ? (
          <Loading rows={5} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.rules ?? []}
            getRowId={(r) => r.name}
            empty="No rules; only the built-in policy applies."
            minWidth="52rem"
          />
        )}
      </section>
    </PageBody>
  )
}
