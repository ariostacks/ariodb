import type { ReactNode } from "react"
import { CheckCircle2Icon, CircleSlashIcon, HistoryIcon, InboxIcon, Undo2Icon } from "lucide-react"
import { StatusBadge } from "@/components/status-badge"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Empty, ErrorNote, Loading, PageBody } from "@/components/page"
import type { Overview } from "@/lib/api"
import { useApi } from "@/lib/hooks"
import { linkClick } from "@/lib/router"

function Stat({
  label,
  value,
  note,
  icon,
  href,
}: {
  label: string
  value: number
  note: string
  icon: ReactNode
  href: string
}) {
  return (
    <Card className="@container/card bg-linear-to-t from-primary/5 to-card shadow-xs dark:bg-card">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
          {value.toLocaleString()}
        </CardTitle>
        <CardAction className="text-muted-foreground [&_svg]:size-4">{icon}</CardAction>
      </CardHeader>
      <CardFooter className="text-sm text-muted-foreground">
        <a
          href={href}
          onClick={(e) => linkClick(e, href)}
          className="underline-offset-4 hover:text-foreground hover:underline"
        >
          {note}
        </a>
      </CardFooter>
    </Card>
  )
}

export function OverviewPage() {
  const { data: d, error, loading } = useApi<Overview>("/api/overview", 10_000)
  if (loading && !d) {
    return (
      <PageBody>
        <Loading rows={6} />
      </PageBody>
    )
  }
  if (!d) {
    return (
      <PageBody>
        <ErrorNote message={error ?? "No data"} />
      </PageBody>
    )
  }
  const count = (o: string) => d.decisions_24h.find((x) => x.outcome === o)?.count ?? 0

  return (
    <PageBody intro="What agents did in the last 24 hours, and how ariodb is set up.">
      {error && <ErrorNote title="Could not refresh" message={error} />}
      <div className="grid grid-cols-1 gap-4 @xl/main:grid-cols-2 @5xl/main:grid-cols-5">
        <Stat label="Waiting for approval" value={d.pending_approvals} icon={<InboxIcon />} note="Open the queue" href="/approvals" />
        <Stat label="Statements allowed" value={count("allowed")} icon={<CheckCircle2Icon />} note="Last 24 hours" href="/decisions" />
        <Stat label="Statements refused" value={count("refused")} icon={<CircleSlashIcon />} note="Last 24 hours" href="/decisions" />
        <Stat label="Writes rolled back" value={count("rolled_back")} icon={<Undo2Icon />} note="Last 24 hours" href="/decisions" />
        <Stat
          label="Sessions that changed data"
          value={d.sessions_with_changes}
          icon={<HistoryIcon />}
          note={`${d.sessions_undone} undone`}
          href="/sessions"
        />
      </div>
      <div className="grid gap-4 @5xl/main:grid-cols-3">
        <Card className="@5xl/main:col-span-2">
          <CardHeader>
            <CardTitle>Agents</CardTitle>
            <CardDescription>Who may connect, and what each one may touch.</CardDescription>
          </CardHeader>
          <CardContent>
            {d.agents.length === 0 ? (
              <Empty>No agents are configured.</Empty>
            ) : (
              <div className="overflow-x-auto rounded-lg border">
                <Table>
                  <TableHeader className="bg-muted/60">
                    <TableRow>
                      <TableHead>Agent</TableHead>
                      <TableHead>Access</TableHead>
                      <TableHead>Tables</TableHead>
                      <TableHead>Database login</TableHead>
                      <TableHead>Token</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {d.agents.map((a) => (
                      <TableRow key={a.name}>
                        <TableCell className="font-medium">{a.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{a.access}</Badge>
                        </TableCell>
                        <TableCell className="max-w-[28ch] font-mono text-xs whitespace-normal">
                          {a.tables.join(", ")}
                        </TableCell>
                        <TableCell>{a.credential || "default"}</TableCell>
                        <TableCell>
                          <StatusBadge status={a.token_set ? "set" : "not set"} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Setup</CardTitle>
            <CardDescription>ariodb {d.version}</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-3 text-sm">
              <dt className="text-muted-foreground">Agents connect to</dt>
              <dd className="font-mono text-xs break-all">{d.proxy}</dd>
              <dt className="text-muted-foreground">Rules</dt>
              <dd>
                <a href="/rules" onClick={(e) => linkClick(e, "/rules")} className="underline-offset-4 hover:underline">
                  {d.rules}
                </a>
              </dd>
              <dt className="text-muted-foreground">Approvers</dt>
              <dd className="flex flex-wrap gap-1">
                {d.approvers.length === 0
                  ? "none"
                  : d.approvers.map((a) => (
                      <Badge key={a.name} variant="secondary">
                        {a.name} <span className="text-muted-foreground">({a.type})</span>
                      </Badge>
                    ))}
              </dd>
              <dt className="text-muted-foreground">Change journal</dt>
              <dd>
                {d.journal ? "on (undo is available)" : "off (undo is not available)"}
              </dd>
            </dl>
          </CardContent>
        </Card>
      </div>
    </PageBody>
  )
}
