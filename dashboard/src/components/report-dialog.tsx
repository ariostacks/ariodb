import { useState } from "react"
import { CopyIcon, FileDownIcon, Loader2Icon } from "lucide-react"
import { toast } from "sonner"
import { ErrorNote } from "@/components/page"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { copyText } from "@/lib/format"

const FRAMEWORKS = [
  { value: "all", label: "All frameworks" },
  { value: "dora", label: "DORA" },
  { value: "soc2", label: "SOC 2" },
  { value: "iso27001", label: "ISO/IEC 27001" },
  { value: "eu-ai-act", label: "EU AI Act" },
]

/** A UTC date `days` before today, as YYYY-MM-DD. */
function daysAgo(days: number) {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10)
}

/**
 * Download a compliance report pack (the same pack `ariodb report` writes)
 * as a tar archive, and show the manifest's hash so it can be recorded.
 */
export function ReportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [from, setFrom] = useState(() => daysAgo(29))
  const [to, setTo] = useState(() => daysAgo(0))
  const [framework, setFramework] = useState("all")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [manifest, setManifest] = useState<string | null>(null)

  async function download() {
    setBusy(true)
    setError(null)
    setManifest(null)
    try {
      const q = new URLSearchParams({ from, to, framework })
      const res = await fetch(`/api/report?${q}`, { credentials: "same-origin", cache: "no-store" })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(typeof data?.error === "string" ? data.error : `Request failed (${res.status})`)
      }
      const name =
        /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? "ariodb-report.tar"
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement("a")
      a.href = url
      a.download = name
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
      setManifest(res.headers.get("x-ariodb-manifest-sha256"))
      toast.success("Report pack downloaded.")
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function copyManifest() {
    if (manifest && (await copyText(manifest))) toast.success("Hash copied.")
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Compliance report pack</DialogTitle>
          <DialogDescription>
            An HTML report with the CSV and JSON records behind it and a manifest of their SHA-256
            hashes, for whole days in UTC. It is evidence for the controls it names, not a
            certification or legal advice.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-2">
            <Label htmlFor="report-from">From</Label>
            <Input id="report-from" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="report-to">To (included)</Label>
            <Input id="report-to" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
          </div>
          <div className="col-span-2 flex flex-col gap-2">
            <Label htmlFor="report-framework">Frameworks</Label>
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger id="report-framework" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FRAMEWORKS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        {error && <ErrorNote title="No report" message={error} />}
        {manifest && (
          <div className="flex min-w-0 flex-col gap-1 text-sm">
            <span className="text-muted-foreground">
              Record the manifest&apos;s SHA-256 to check the pack later:
            </span>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-xs" title={manifest}>
                {manifest}
              </code>
              <Button variant="outline" size="icon" onClick={copyManifest}>
                <CopyIcon />
                <span className="sr-only">Copy the hash</span>
              </Button>
            </div>
          </div>
        )}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Close</Button>
          </DialogClose>
          <Button onClick={download} disabled={busy || !from || !to}>
            {busy ? <Loader2Icon className="animate-spin" /> : <FileDownIcon />}
            Download
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
