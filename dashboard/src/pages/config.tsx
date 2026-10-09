import { useState } from "react"
import { CheckCircle2Icon, InfoIcon, Loader2Icon, RotateCcwIcon, SaveIcon, ShieldCheckIcon } from "lucide-react"
import { toast } from "sonner"
import { ErrorNote, Loading, PageBody } from "@/components/page"
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
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Textarea } from "@/components/ui/textarea"
import { api, errorText, type ConfigCheck, type ConfigFile } from "@/lib/api"
import { plural } from "@/lib/format"
import { useApi } from "@/lib/hooks"

export function ConfigPage() {
  const { data, error, loading, reload } = useApi<ConfigFile>("/api/config")
  // Unsaved edits; null means "as saved".
  const [edited, setEdited] = useState<string | null>(null)
  const [check, setCheck] = useState<ConfigCheck | null>(null)
  const [busy, setBusy] = useState<"check" | "save" | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const text = edited ?? data?.text ?? ""
  const dirty = data !== null && edited !== null && edited !== data.text

  async function runCheck() {
    setBusy("check")
    setSaveError(null)
    try {
      setCheck(await api<ConfigCheck>("/api/config/check", { method: "POST", body: { text } }))
    } catch (e) {
      setCheck({ ok: false, error: errorText(e) })
    } finally {
      setBusy(null)
    }
  }

  async function save() {
    setBusy("save")
    setSaveError(null)
    try {
      await api("/api/config", { method: "PUT", body: { text } })
      toast.success("Saved and in force. The previous file is kept as .bak.")
      setCheck(null)
      setEdited(null)
      await reload()
    } catch (e) {
      setSaveError(errorText(e))
    } finally {
      setBusy(null)
    }
  }

  if (loading && !data) {
    return (
      <PageBody>
        <Loading rows={10} />
      </PageBody>
    )
  }
  if (!data) {
    return (
      <PageBody>
        <ErrorNote message={error ?? "No config"} />
      </PageBody>
    )
  }

  return (
    <PageBody intro="Changes are checked before they are saved, and take effect at once. Database passwords are shown as *** and kept unless you type a new one.">
      {!data.writable && (
        <Alert>
          <InfoIcon />
          <AlertTitle>Saving is off</AlertTitle>
          <AlertDescription>
            dashboard.config_writes is false. Check your changes here, then commit them to your config repository.
          </AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-sm break-all">{data.path}</CardTitle>
          <CardDescription>{dirty ? "Edited, not saved" : "As saved"}</CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            aria-label="Config file"
            value={text}
            onChange={(e) => {
              setEdited(e.target.value)
              setCheck(null)
            }}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            className="min-h-[28rem] font-mono text-xs leading-relaxed"
          />
        </CardContent>
        <CardFooter className="flex flex-col items-stretch gap-3">
          {check &&
            (check.ok ? (
              <Alert className="text-emerald-700 dark:text-emerald-400">
                <CheckCircle2Icon />
                <AlertDescription className="text-current">
                  Valid: {plural(check.agents, "agent")}, {plural(check.rules, "rule")},{" "}
                  {plural(check.approvers, "approver")}.
                </AlertDescription>
              </Alert>
            ) : (
              <ErrorNote title="Not valid" message={check.error} />
            ))}
          {saveError && <ErrorNote title="Not saved" message={saveError} />}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={runCheck} disabled={busy !== null}>
              {busy === "check" ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />}
              Check
            </Button>
            <Button
              onClick={() => setConfirming(true)}
              disabled={!data.writable || !dirty || busy !== null}
              title={data.writable ? undefined : "Saving is off (dashboard.config_writes = false)"}
            >
              {busy === "save" ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
              Save
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                setEdited(null)
                setCheck(null)
              }}
              disabled={!dirty || busy !== null}
            >
              <RotateCcwIcon />
              Discard changes
            </Button>
          </div>
        </CardFooter>
      </Card>
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Save and apply the config?</AlertDialogTitle>
            <AlertDialogDescription>
              It is checked first, then takes effect at once for every agent. The previous file is kept as .bak.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => void save()}>Save</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageBody>
  )
}
