import { useEffect, useMemo, useState } from "react"
import { CheckIcon, ClockIcon, InfoIcon, Loader2Icon, XIcon } from "lucide-react"
import { toast } from "sonner"
import { cn } from "cn"
import { columnHelper, DataTable } from "@/components/data-table"
import { Empty, ErrorNote, Loading, PageBody } from "@/components/page"
import { Sql } from "@/components/sql"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { api, errorText, type Approval } from "@/lib/api"
import { ago, when } from "@/lib/format"
import { useApi, useNow } from "@/lib/hooks"
import { usePending } from "@/lib/pending"

function PendingCard({
  a,
  now,
  highlighted,
  onDecided,
}: {
  a: Approval
  now: number
  highlighted: boolean
  onDecided: () => void
}) {
  const [note, setNote] = useState("")
  const [busy, setBusy] = useState<"allow" | "deny" | null>(null)
  const left = Math.max(0, Math.round((a.expires_ms - now) / 1000))

  async function decide(verdict: "allow" | "deny") {
    setBusy(verdict)
    try {
      await api(`/api/approvals/${encodeURIComponent(a.id)}`, {
        method: "POST",
        body: { verdict, note: note.trim() || null },
      })
      toast.success(verdict === "allow" ? `Approved ${a.agent}'s statement.` : `Denied ${a.agent}'s statement.`)
      onDecided()
    } catch (e) {
      toast.error(errorText(e))
      setBusy(null)
    }
  }

  return (
    <Card
      id={`approval-${a.id}`}
      className={cn(
        "scroll-mt-20 border-l-4 border-l-amber-500",
        highlighted && "ring-2 ring-amber-500/60"
      )}
    >
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <StatusBadge status="pending" />
          <span>{a.agent}</span>
        </CardTitle>
        <CardDescription className="flex flex-wrap gap-x-3 gap-y-1">
          <span>rule {a.rule}</span>
          <span>approver {a.approver}</span>
          <span className={cn("inline-flex items-center gap-1 tabular-nums", left <= 30 && "text-destructive")}>
            <ClockIcon className="size-3.5" />
            {left > 0 ? `${left}s left` : "expiring"}
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {a.reason && <p className="text-sm">{a.reason}</p>}
        <Sql className="max-h-64 overflow-auto">{a.sql}</Sql>
      </CardContent>
      <CardFooter className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-center">
        <Input
          placeholder="Note for the agent (optional)"
          aria-label="Note for the agent"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          className="sm:flex-1"
          maxLength={500}
        />
        <div className="flex gap-2">
          <Button className="flex-1 sm:flex-none" onClick={() => decide("allow")} disabled={busy !== null}>
            {busy === "allow" ? <Loader2Icon className="animate-spin" /> : <CheckIcon />}
            Approve
          </Button>
          <Button
            className="flex-1 sm:flex-none"
            variant="destructive"
            onClick={() => decide("deny")}
            disabled={busy !== null}
          >
            {busy === "deny" ? <Loader2Icon className="animate-spin" /> : <XIcon />}
            Deny
          </Button>
        </div>
      </CardFooter>
    </Card>
  )
}

const col = columnHelper<Approval>()
const historyColumns = col.columns([
  col.accessor("created_ms", {
    header: "When",
    sortFn: "basic",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs whitespace-nowrap text-muted-foreground" title={when(getValue())}>
        {ago(getValue())}
      </span>
    ),
  }),
  col.accessor("status", {
    header: "Status",
    sortFn: "text",
    cell: ({ getValue }) => <StatusBadge status={getValue()} />,
  }),
  col.accessor("agent", { header: "Agent", sortFn: "text" }),
  col.accessor("rule", { header: "Rule", sortFn: "text" }),
  col.accessor("decided_by", {
    header: "Decided by",
    enableSorting: false,
    cell: ({ row }) => (
      <div className="max-w-[28ch] whitespace-normal">
        <div>{row.original.decided_by ?? "nobody (expired)"}</div>
        {row.original.note && <div className="text-xs text-muted-foreground">{row.original.note}</div>}
      </div>
    ),
  }),
  col.accessor("sql", {
    header: "Statement",
    enableSorting: false,
    cell: ({ getValue }) => <Sql clamp>{getValue()}</Sql>,
  }),
])

export function ApprovalsPage() {
  const pending = usePending()
  const now = useNow(1000)
  const items = pending.data?.approvals ?? []
  const signature = items.map((a) => a.id).join(",")
  const all = useApi<{ approvals: Approval[] }>("/api/approvals?all=true", 15_000)
  const reloadAll = all.reload
  const [hash, setHash] = useState(() => location.hash.slice(1))

  // Recent decisions change whenever the queue does.
  useEffect(() => {
    void reloadAll()
  }, [signature, reloadAll])

  useEffect(() => {
    const onHash = () => setHash(location.hash.slice(1))
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  // A link from a notification names one request: bring it into view.
  const linkedId = hash.startsWith("approval-") ? hash.slice("approval-".length) : null
  const linkedPending = linkedId !== null && items.some((a) => a.id === linkedId)
  useEffect(() => {
    if (linkedPending) document.getElementById(`approval-${linkedId}`)?.scrollIntoView({ block: "center" })
  }, [linkedPending, linkedId])
  const linkedPast = useMemo(
    () => (linkedId && !linkedPending ? all.data?.approvals.find((a) => a.id === linkedId) : undefined),
    [linkedId, linkedPending, all.data]
  )

  const recent = (all.data?.approvals ?? []).filter((a) => a.status !== "pending")

  return (
    <PageBody intro="Statements held until someone decides. Nothing reaches the database while they wait, and a request that runs out of time is refused.">
      {linkedPast && (
        <Alert>
          <InfoIcon />
          <AlertDescription>
            The request you followed a link to is no longer waiting: it was {linkedPast.status}
            {linkedPast.decided_by ? ` by ${linkedPast.decided_by}` : ""}.
          </AlertDescription>
        </Alert>
      )}
      <section className="flex flex-col gap-3" aria-labelledby="waiting">
        <h2 id="waiting" className="text-sm font-medium">
          Waiting {items.length > 0 && <span className="text-muted-foreground">({items.length})</span>}
        </h2>
        {pending.error && <ErrorNote title="Could not refresh the queue" message={pending.error} />}
        {pending.loading && !pending.data ? (
          <Loading rows={2} />
        ) : items.length === 0 ? (
          <Empty>Nothing is waiting for approval. This page checks every few seconds.</Empty>
        ) : (
          <div className="grid gap-4 @5xl/main:grid-cols-2">
            {items.map((a) => (
              <PendingCard
                key={a.id}
                a={a}
                now={now}
                highlighted={a.id === linkedId}
                onDecided={() => void pending.reload()}
              />
            ))}
          </div>
        )}
      </section>
      <section className="flex flex-col gap-3" aria-labelledby="recent">
        <h2 id="recent" className="text-sm font-medium">
          Recent decisions
        </h2>
        {all.error && <ErrorNote message={all.error} />}
        {all.loading && !all.data ? (
          <Loading />
        ) : (
          <DataTable
            columns={historyColumns}
            data={recent}
            getRowId={(a) => a.id}
            empty="No decisions yet."
            pageSize={15}
            minWidth="52rem"
          />
        )}
      </section>
    </PageBody>
  )
}
