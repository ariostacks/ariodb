// Sign-in and first-run password setup, built from the shadcn login-03 block.
// With single sign-on, its button comes first; a local password is then
// for break-glass use only, or switched off.
import { useState, type FormEvent } from "react"
import { AlertCircleIcon, KeyRoundIcon, Loader2Icon, LogInIcon } from "lucide-react"
import { Logo } from "@/components/logo"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel, FieldSeparator } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { api, errorText, type Session, type SignedOut } from "@/lib/api"

const MIN_PASSWORD = 12

export function SignIn({ how, onSignedIn }: { how: SignedOut; onSignedIn: (s: Session) => void }) {
  const needsSetup = how.needs_setup
  const sso = how.sso
  // Under single sign-on the password form waits behind a button.
  const [showPassword, setShowPassword] = useState(how.password_login === "primary")
  const [user, setUser] = useState(sso ? "" : "root")
  const [password, setPassword] = useState("")
  const [repeat, setRepeat] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (needsSetup) {
      if (password.length < MIN_PASSWORD) {
        setError(`Use a password of at least ${MIN_PASSWORD} characters.`)
        return
      }
      if (password !== repeat) {
        setError("The two passwords are different.")
        return
      }
    }
    setBusy(true)
    try {
      const s = await api<Session>(needsSetup ? "/api/setup" : "/api/login", {
        method: "POST",
        body: needsSetup ? { password } : { user, password },
      })
      onSignedIn(s)
    } catch (err) {
      setError(errorText(err))
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <div className="flex items-center gap-2 self-center font-mono text-lg font-semibold tracking-tight">
          <Logo />
          ariodb
        </div>
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="text-xl">
              {needsSetup ? "Set the root password" : "Sign in"}
            </CardTitle>
            <CardDescription>
              {needsSetup
                ? "No dashboard password exists yet. Choose one for the root user."
                : "Review and approve what agents do in your databases."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              {sso && (
                <Field>
                  <Button asChild size="lg">
                    <a href={sso.login_url}>
                      <LogInIcon />
                      Sign in with {sso.provider}
                    </a>
                  </Button>
                </Field>
              )}
              {sso && how.password_login === "break_glass" && !showPassword && (
                <Field>
                  <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => setShowPassword(true)}>
                    <KeyRoundIcon />
                    Use a local password instead
                  </Button>
                </Field>
              )}
              {sso && showPassword && (
                <FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">
                  Break-glass password
                </FieldSeparator>
              )}
              {showPassword && (
                <form onSubmit={submit} noValidate={needsSetup}>
                  <FieldGroup>
                    {!needsSetup && (
                      <Field>
                        <FieldLabel htmlFor="user">User name</FieldLabel>
                        <Input
                          id="user"
                          autoComplete="username"
                          value={user}
                          onChange={(e) => setUser(e.target.value)}
                          required
                        />
                      </Field>
                    )}
                    {needsSetup && <input type="hidden" autoComplete="username" value="root" readOnly />}
                    <Field>
                      <FieldLabel htmlFor="password">Password</FieldLabel>
                      <Input
                        id="password"
                        type="password"
                        autoComplete={needsSetup ? "new-password" : "current-password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoFocus
                        required
                      />
                      {needsSetup && (
                        <FieldDescription>At least {MIN_PASSWORD} characters.</FieldDescription>
                      )}
                    </Field>
                    {needsSetup && (
                      <Field>
                        <FieldLabel htmlFor="repeat">Repeat the password</FieldLabel>
                        <Input
                          id="repeat"
                          type="password"
                          autoComplete="new-password"
                          value={repeat}
                          onChange={(e) => setRepeat(e.target.value)}
                          required
                        />
                      </Field>
                    )}
                    {error && (
                      <Alert variant="destructive" role="alert">
                        <AlertCircleIcon />
                        <AlertDescription>{error}</AlertDescription>
                      </Alert>
                    )}
                    <Field>
                      <Button type="submit" variant={sso ? "outline" : "default"} disabled={busy}>
                        {busy && <Loader2Icon className="animate-spin" />}
                        {needsSetup ? "Set password and sign in" : "Sign in"}
                      </Button>
                    </Field>
                  </FieldGroup>
                </form>
              )}
            </FieldGroup>
          </CardContent>
        </Card>
        <FieldDescription className="px-6 text-center">
          {needsSetup
            ? "This works only from the server itself. Elsewhere, run ariodb dashboard-password."
            : sso
              ? how.password_login === "off"
                ? `Local passwords are switched off. Ask an admin if ${sso.provider} lets you in but ariodb does not.`
                : "Local passwords are for when single sign-on is unavailable."
              : "Forgotten the password? Run ariodb dashboard-password on the server."}
        </FieldDescription>
      </div>
    </div>
  )
}
