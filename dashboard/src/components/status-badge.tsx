import { Badge } from "@/components/ui/badge"
import { cn } from "cn"

// Outcomes, approval states and rule verdicts share three tones: went
// through, stopped, and waiting or uncertain.
const tones: Record<string, string> = {
  allowed: "ok",
  allow: "ok",
  set: "ok",
  undone: "ok",
  refused: "bad",
  deny: "bad",
  denied: "bad",
  rolled_back: "bad",
  "not set": "bad",
  pending: "wait",
  approve: "wait",
  expired: "wait",
  failed: "wait",
}

const toneClass: Record<string, string> = {
  ok: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  bad: "bg-destructive/10 text-destructive dark:bg-destructive/20",
  wait: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
}

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const tone = tones[status]
  return (
    <Badge
      variant={tone ? "secondary" : "outline"}
      className={cn(tone && toneClass[tone], className)}
    >
      {status.replace(/_/g, " ")}
    </Badge>
  )
}
