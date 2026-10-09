import { useEffect, useMemo, useState } from "react"
import { AlertTriangleIcon, BanIcon, CheckCircle2Icon, Loader2Icon, Undo2Icon } from "lucide-react"
import { toast } from "sonner"
import { columnHelper, DataTable } from "@/components/data-table"
import { ErrorNote, Loading, PageBody } from "@/components/page"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { api, errorText, type AgentSession, type UndoPlan } from "@/lib/api"
import { ago, plural, when } from "@/lib/format"
import { useApi } from "@/lib/hooks"

const SHOWN_STEPS = 200

function List({ items, className }: { items: string[]; className?: string }) {
  return (
    <ul className={className ?? "flex flex-col gap-1 font-mono text-xs"}>
      {items.map((t, i) => (
        <li key={i} className="break-words">
          {t}
        </li>
      ))}
    </ul>
  )
}

/** The undo plan for one session, with a confirmation before anything changes. */
function PlanSheet({
  session,
  onClose,
  onUndone,
}: {
  session: AgentSession | null
  onClose: () => void
  onUndone: () => void
}) {
  const [plan, setPlan] = useState<UndoPlan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [skip, setSkip] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState<number | null>(null)
  const id = session?.session

  // The page gives each session its own instance (see `key` below), so the
  // state starts fresh every time.
  useEffect(() => {
    if (!id) return
    let live = true
    api<UndoPlan>(`/api/sessions/${encodeURIComponent(id)}/plan`)
      .then((p) => live && setPlan(p))
      .catch((e) => live && setError(errorText(e)))
    return () => {
      live = false
    }
  }, [id])

  async function undo() {
    if (!id) return
    setRunning(true)
    try {
      const r = await api<{ restored: number }>(`/api/sessions/${encodeURIComponent(id)}/undo`, {
        method: "POST",
        body: { skip_conflicts: skip },
      })
      setDone(r.restored)
      toast.success(`Undone: ${plural(r.restored, "row")} restored in one transaction.`)
      onUndone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setRunning(false)
    }
  }

  const blocked = (plan?.blocked.length ?? 0) > 0
  const conflicts = plan?.conflicts.length ?? 0
  const canUndo =
    plan !== null && done === null && !plan.already_undone && !blocked && plan.steps.length > 0 && (conflicts === 0 || skip)

  return (
    <Sheet open={session !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="data-[side=right]:w-full data-[side=right]:sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Undo session</SheetTitle>
          <SheetDescription className="font-mono text-xs break-all">{id}</SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4">
          {session && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted-foreground">Agent</dt>
              <dd>{session.agent}</dd>
              <dt className="text-muted-foreground">Changed</dt>
              <dd>
                {plural(session.rows, "row")} in {plural(session.transactions, "transaction")}
              </dd>
              <dt className="text-muted-foreground">Last change</dt>
              <dd>{when(session.last_at_ms)}</dd>
            </dl>
          )}
          {error && <ErrorNote title="Undo is not possible" message={error} />}
          {!plan && !error && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2Icon className="size-4 animate-spin" />
              Working out the undo plan…
            </div>
          )}
          {done !== null && (
            <Alert>
              <CheckCircle2Icon />
              <AlertTitle>Undone</AlertTitle>
              <AlertDescription>{plural(done, "row")} restored in one transaction.</AlertDescription>
            </Alert>
          )}
          {plan?.already_undone && done === null && (
            <Alert>
              <CheckCircle2Icon />
              <AlertDescription>This session was already undone.</AlertDescription>
            </Alert>
          )}
          {plan && blocked && (
            <Alert variant="destructive">
              <BanIcon />
              <AlertTitle>Cannot be undone</AlertTitle>
              <AlertDescription>
                <List items={plan.blocked} className="flex list-disc flex-col gap-1 pl-4" />
              </AlertDescription>
            </Alert>
          )}
          {plan && conflicts > 0 && (
            <Alert className="border-amber-500/50 text-amber-800 dark:text-amber-300">
              <AlertTriangleIcon />
              <AlertTitle>Changed by someone else since ({conflicts})</AlertTitle>
              <AlertDescription className="text-amber-800/90 dark:text-amber-300/90">
                <List items={plan.conflicts} className="flex list-disc flex-col gap-1 pl-4" />
              </AlertDescription>
            </Alert>
          )}
          {plan && plan.steps.length > 0 && (
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Steps ({plan.steps.length})</h3>
              <div className="rounded-lg border bg-muted/40 p-3">
                <List items={plan.steps.slice(0, SHOWN_STEPS)} />
                {plan.steps.length > SHOWN_STEPS && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    …and {plan.steps.length - SHOWN_STEPS} more
                  </p>
                )}
              </div>
            </section>
          )}
          {plan && plan.steps.length === 0 && !plan.already_undone && (
            <p className="text-sm text-muted-foreground">There is nothing left to undo.</p>
          )}
        </div>
        <SheetFooter className="border-t">
          {conflicts > 0 && done === null && (
            <div className="flex items-start gap-2">
              <Checkbox id="skip-conflicts" checked={skip} onCheckedChange={(v) => setSkip(v === true)} />
              <Label htmlFor="skip-conflicts" className="leading-snug font-normal">
                Undo the rest and leave the conflicting rows as they are now
              </Label>
            </div>
          )}
          <Button variant="destructive" disabled={!canUndo || running} onClick={() => setConfirming(true)}>
            {running ? <Loader2Icon className="animate-spin" /> : <Undo2Icon />}
            {plan ? `Undo ${plural(plan.steps.length, "change")}` : "Undo"}
          </Button>
        </SheetFooter>
      </SheetContent>
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Undo this session for real?</AlertDialogTitle>
            <AlertDialogDescription>
              {plan ? plural(plan.steps.length, "change") : "The changes"} by {session?.agent} will be reversed in
              one transaction.{" "}
              {conflicts > 0
                ? `${plural(conflicts, "row")} changed since by someone else will be left alone.`
                : "Nobody else's changes are touched."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void undo()}>
              Undo
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}

export function SessionsPage() {
  const { data, error, loading, reload } = useApi<{ sessions: AgentSession[] }>("/api/sessions")
  const [open, setOpen] = useState<AgentSession | null>(null)

  const columns = useMemo(() => {
    const col = columnHelper<AgentSession>()
    return col.columns([
      col.accessor("last_at_ms", {
        header: "Last change",
        sortFn: "basic",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs whitespace-nowrap text-muted-foreground" title={when(getValue())}>
            {ago(getValue())}
          </span>
        ),
      }),
      col.accessor("session", {
        header: "Session",
        sortFn: "text",
        cell: ({ getValue }) => (
          <code className="font-mono text-xs" title={getValue()}>
            {getValue().length > 18 ? `${getValue().slice(0, 18)}…` : getValue()}
          </code>
        ),
      }),
      col.accessor("agent", { header: "Agent", sortFn: "text" }),
      col.accessor("transactions", {
        header: "Transactions",
        sortFn: "basic",
        cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
      }),
      col.accessor("rows", {
        header: "Rows",
        sortFn: "basic",
        cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
      }),
      col.accessor((s) => s.tables.join(", "), {
        id: "tables",
        header: "Tables",
        enableSorting: false,
        cell: ({ getValue }) => <span className="font-mono text-xs whitespace-normal">{getValue()}</span>,
      }),
      col.accessor("undone", {
        header: "Status",
        enableSorting: false,
        cell: ({ getValue }) => (getValue() ? <StatusBadge status="undone" /> : null),
      }),
      col.display({
        id: "actions",
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <Button variant="outline" size="sm" onClick={() => setOpen(row.original)}>
            <Undo2Icon />
            Review undo
          </Button>
        ),
      }),
    ])
  }, [])

  return (
    <PageBody intro="Every agent session that changed data. Undo reverses exactly one session and leaves everyone else's changes alone.">
      {error && <ErrorNote message={error} />}
      {loading && !data ? (
        <Loading rows={6} />
      ) : (
        <DataTable
          columns={columns}
          data={data?.sessions ?? []}
          getRowId={(s) => s.session}
          empty="No agent has changed data yet."
          minWidth="48rem"
        />
      )}
      <PlanSheet key={open?.session ?? "none"} session={open} onClose={() => setOpen(null)} onUndone={() => void reload()} />
    </PageBody>
  )
}
