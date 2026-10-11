import { useEffect, useMemo, useState, type FormEvent } from "react"
import {
  BanIcon,
  ClipboardCopyIcon,
  CopyIcon,
  EllipsisVerticalIcon,
  FileDownIcon,
  FilterIcon,
  InfoIcon,
  Loader2Icon,
  RotateCcwIcon,
} from "lucide-react"
import { toast } from "sonner"
import { CopyDialog } from "@/components/copy-dialog"
import { columnHelper, DataTable } from "@/components/data-table"
import { ErrorNote, Loading, PageBody } from "@/components/page"
import { ReportDialog } from "@/components/report-dialog"
import { Sql } from "@/components/sql"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { api, errorText, type BlockLike, type ConfigFile, type Decision } from "@/lib/api"
import { ago, copyText, deciderLabel, when } from "@/lib/format"
import { useApi } from "@/lib/hooks"
import { useCan } from "@/lib/me"

type Filters = {
  agent: string
  outcome: string
  rule: string
  q: string
  decided_by: string
  decided_by_kind: string
  limit: string
}

const OUTCOMES = ["allowed", "refused", "rolled_back", "failed"]
const DECIDER_KINDS = [
  { value: "person", label: "Decided by a person" },
  { value: "model", label: "Decided by a model" },
  { value: "plugin", label: "Decided by a plugin" },
]
const EMPTY: Filters = { agent: "", outcome: "", rule: "", q: "", decided_by: "", decided_by_kind: "", limit: "200" }
const LIMITS = ["100", "200", "500", "1000"]
const ANY = "any"

function readFilters(): Filters {
  const p = new URLSearchParams(location.search)
  return {
    agent: p.get("agent") ?? "",
    outcome: p.get("outcome") ?? "",
    rule: p.get("rule") ?? "",
    q: p.get("q") ?? "",
    decided_by: p.get("decided_by") ?? "",
    decided_by_kind: DECIDER_KINDS.some((k) => k.value === p.get("decided_by_kind"))
      ? p.get("decided_by_kind")!
      : "",
    limit: LIMITS.includes(p.get("limit") ?? "") ? p.get("limit")! : "200",
  }
}

function query(f: Filters) {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(f)) if (v) p.set(k, v)
  return p.toString()
}

/** "Block like this": preview the generated deny rule, and add it when the config may be written. */
function BlockDialog({ decision, onClose }: { decision: Decision | null; onClose: () => void }) {
  const [preview, setPreview] = useState<BlockLike | null>(null)
  const [writable, setWritable] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [applying, setApplying] = useState(false)
  const [copy, setCopy] = useState<string | null>(null)

  // The page gives each decision its own instance (see `key` below), so the
  // state starts fresh every time.
  useEffect(() => {
    if (!decision) return
    let live = true
    Promise.all([
      api<BlockLike>("/api/block-like", { method: "POST", body: { decision: decision.id, apply: false } }),
      api<ConfigFile>("/api/config"),
    ])
      .then(([p, c]) => {
        if (!live) return
        setPreview(p)
        setWritable(c.writable)
      })
      .catch((e) => live && setError(errorText(e)))
    return () => {
      live = false
    }
  }, [decision])

  async function apply() {
    if (!decision || !preview) return
    setApplying(true)
    try {
      await api<BlockLike>("/api/block-like", { method: "POST", body: { decision: decision.id, apply: true } })
      toast.success(`Rule ${preview.rule} added and in force.`)
      onClose()
    } catch (e) {
      setError(errorText(e))
      setApplying(false)
    }
  }

  async function copySnippet() {
    if (!preview) return
    if (await copyText(preview.snippet.trim())) toast.success("Rule copied.")
    else setCopy(preview.snippet.trim())
  }

  return (
    <>
      <Dialog open={decision !== null} onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Block requests like this</DialogTitle>
            <DialogDescription>
              A deny rule matching this agent, statement type and tables. It is checked against the
              whole config before anything is written.
            </DialogDescription>
          </DialogHeader>
          {decision && (
            <div className="flex min-w-0 flex-col gap-3">
              <div className="text-sm">
                <span className="text-muted-foreground">From decision {decision.id} by </span>
                <span className="font-medium">{decision.agent}</span>
              </div>
              <Sql className="max-h-32 overflow-auto">{decision.sql}</Sql>
              {error && <ErrorNote title="No rule" message={error} />}
              {!preview && !error && <Loading rows={3} />}
              {preview && (
                <>
                  <div className="text-sm">
                    New rule <code className="font-mono text-xs">{preview.rule}</code>
                  </div>
                  <Sql className="max-h-64 overflow-auto">{preview.snippet.trim()}</Sql>
                  {!writable && (
                    <Alert>
                      <InfoIcon />
                      <AlertTitle>Config edits are off here</AlertTitle>
                      <AlertDescription>
                        dashboard.config_writes is false, so copy this rule into your config repository instead.
                      </AlertDescription>
                    </Alert>
                  )}
                </>
              )}
            </div>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Close</Button>
            </DialogClose>
            <Button variant="outline" onClick={copySnippet} disabled={!preview}>
              <CopyIcon />
              Copy rule
            </Button>
            {writable && (
              <Button onClick={apply} disabled={!preview || applying}>
                {applying ? <Loader2Icon className="animate-spin" /> : <BanIcon />}
                Apply
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <CopyDialog text={copy} title="The generated rule" onClose={() => setCopy(null)} />
    </>
  )
}

export function DecisionsPage() {
  const [form, setForm] = useState<Filters>(readFilters)
  const [applied, setApplied] = useState<Filters>(form)
  const { data, error, loading, reload } = useApi<{ decisions: Decision[]; deciders: string[] }>(
    `/api/decisions?${query(applied)}`
  )
  const admin = useCan("admin")
  const [blocking, setBlocking] = useState<Decision | null>(null)
  const [fixture, setFixture] = useState<string | null>(null)
  const [reporting, setReporting] = useState(false)

  function submit(e: FormEvent) {
    e.preventDefault()
    const q = query(form)
    history.replaceState(null, "", q ? `/decisions?${q}` : "/decisions")
    if (query(form) === query(applied)) void reload()
    setApplied(form)
  }

  function reset() {
    setForm(EMPTY)
    setApplied(EMPTY)
    history.replaceState(null, "", "/decisions")
  }

  async function copyAsTest(d: Decision) {
    try {
      const fx = await api<unknown>(`/api/decisions/${d.id}/fixture`)
      const text = JSON.stringify(fx, null, 2)
      if (await copyText(text)) toast.success("Copied as a test fixture.")
      else setFixture(text)
    } catch (e) {
      toast.error(errorText(e))
    }
  }

  // Built once: the row actions only call state setters, which never change.
  const columns = useMemo(() => {
    const col = columnHelper<Decision>()
    return col.columns([
    col.accessor("at_ms", {
      header: "When",
      sortFn: "basic",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs whitespace-nowrap text-muted-foreground" title={when(getValue())}>
          {ago(getValue())}
        </span>
      ),
    }),
    col.accessor("agent", { header: "Agent", sortFn: "text" }),
    col.accessor("outcome", {
      header: "Outcome",
      sortFn: "text",
      cell: ({ getValue }) => <StatusBadge status={getValue()} />,
    }),
    col.accessor("kind", { header: "Kind", sortFn: "text" }),
    col.accessor((d) => d.rule ?? "", {
      id: "rule",
      header: "Rule",
      sortFn: "text",
      cell: ({ getValue }) => <span className="font-mono text-xs">{getValue()}</span>,
    }),
    col.accessor((d) => d.decided_by.join(", "), {
      id: "decided_by",
      header: "Decided by",
      sortFn: "text",
      cell: ({ row }) => (
        <div className="flex max-w-[24ch] flex-col text-xs whitespace-normal">
          {row.original.decided_by.map((by) => (
            <span key={by}>{deciderLabel(by)}</span>
          ))}
        </div>
      ),
    }),
    col.accessor((d) => d.rows ?? -1, {
      id: "rows",
      header: "Rows",
      sortFn: "basic",
      cell: ({ row }) => <span className="font-mono text-xs tabular-nums">{row.original.rows ?? ""}</span>,
    }),
    col.accessor((d) => d.latency_ms ?? -1, {
      id: "ms",
      header: "ms",
      sortFn: "basic",
      cell: ({ row }) => <span className="font-mono text-xs tabular-nums">{row.original.latency_ms ?? ""}</span>,
    }),
    col.accessor("sql", {
      header: "Statement",
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-col gap-1">
          <Sql clamp>{row.original.sql}</Sql>
          {row.original.reason && (
            <span className="max-w-[48ch] text-xs whitespace-normal text-muted-foreground">{row.original.reason}</span>
          )}
        </div>
      ),
    }),
    col.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => {
        const d = row.original
        const fixtureable = d.outcome === "allowed" || d.outcome === "refused"
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="text-muted-foreground data-[state=open]:bg-muted">
                <EllipsisVerticalIcon />
                <span className="sr-only">Actions for decision {d.id}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              {admin && (
                <DropdownMenuItem onSelect={() => setBlocking(d)}>
                  <BanIcon />
                  Block like this
                </DropdownMenuItem>
              )}
              <DropdownMenuItem disabled={!fixtureable} onSelect={() => void copyAsTest(d)}>
                <ClipboardCopyIcon />
                Copy as test
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    }),
    ])
  }, [admin])

  return (
    <PageBody intro="Every statement agents sent, and what ariodb did with it. Filters run on the server; the newest come first.">
      <form onSubmit={submit} className="grid grid-cols-2 gap-2 @3xl/main:flex @3xl/main:flex-wrap @3xl/main:items-center">
        <Input
          placeholder="Agent"
          aria-label="Agent"
          value={form.agent}
          onChange={(e) => setForm({ ...form, agent: e.target.value })}
          className="@3xl/main:w-40"
        />
        <Select
          value={form.outcome || ANY}
          onValueChange={(v) => setForm({ ...form, outcome: v === ANY ? "" : v })}
        >
          <SelectTrigger aria-label="Outcome" className="w-full @3xl/main:w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any outcome</SelectItem>
            {OUTCOMES.map((o) => (
              <SelectItem key={o} value={o}>
                {o.replace("_", " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          placeholder="Rule"
          aria-label="Rule"
          value={form.rule}
          onChange={(e) => setForm({ ...form, rule: e.target.value })}
          className="@3xl/main:w-40"
        />
        <Input
          placeholder="Text in statement"
          aria-label="Text in statement"
          value={form.q}
          onChange={(e) => setForm({ ...form, q: e.target.value })}
          className="@3xl/main:w-56"
        />
        <Select
          value={form.decided_by_kind || ANY}
          onValueChange={(v) => setForm({ ...form, decided_by_kind: v === ANY ? "" : v })}
        >
          <SelectTrigger aria-label="Kind of decider" className="w-full @3xl/main:w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any decider</SelectItem>
            {DECIDER_KINDS.map((k) => (
              <SelectItem key={k.value} value={k.value}>
                {k.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          placeholder="Decided by"
          aria-label="Decided by"
          list="deciders"
          value={form.decided_by}
          onChange={(e) => setForm({ ...form, decided_by: e.target.value })}
          className="@3xl/main:w-56"
        />
        <datalist id="deciders">
          {(data?.deciders ?? []).map((d) => (
            <option key={d} value={d}>
              {deciderLabel(d)}
            </option>
          ))}
        </datalist>
        <Select value={form.limit} onValueChange={(v) => setForm({ ...form, limit: v })}>
          <SelectTrigger aria-label="How many" className="w-full @3xl/main:w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {LIMITS.map((l) => (
              <SelectItem key={l} value={l}>
                Latest {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="col-span-2 flex gap-2">
          <Button type="submit" className="flex-1 @3xl/main:flex-none">
            <FilterIcon />
            Filter
          </Button>
          <Button type="button" variant="outline" onClick={reset}>
            <RotateCcwIcon />
            Reset
          </Button>
          {admin && (
            <Button type="button" variant="outline" onClick={() => setReporting(true)}>
              <FileDownIcon />
              Report pack
            </Button>
          )}
        </div>
      </form>
      {error && <ErrorNote message={error} />}
      {loading && !data ? (
        <Loading rows={8} />
      ) : (
        <DataTable
          columns={columns}
          data={data?.decisions ?? []}
          getRowId={(d) => String(d.id)}
          empty="No decisions match."
          pageSize={25}
          minWidth="72rem"
        />
      )}
      <BlockDialog key={blocking?.id ?? "none"} decision={blocking} onClose={() => setBlocking(null)} />
      <CopyDialog text={fixture} title="Test fixture" onClose={() => setFixture(null)} />
      <ReportDialog open={reporting} onClose={() => setReporting(false)} />
    </PageBody>
  )
}
