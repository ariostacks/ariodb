import { useCallback, useEffect, useState, type CSSProperties } from "react"
import { Loader2Icon } from "lucide-react"
import { toast } from "sonner"
import { AppSidebar, titles } from "@/components/app-sidebar"
import { ErrorNote } from "@/components/page"
import { SignIn } from "@/components/sign-in"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { api, errorText, setCsrf, whenSignedOut, type Me, type Session, type SignedOut } from "@/lib/api"
import { MeProvider, useCan } from "@/lib/me"
import { PendingProvider, usePending } from "@/lib/pending"
import { upgradeLegacyHash, usePage, type Page } from "@/lib/router"
import { ApprovalsPage } from "@/pages/approvals"
import { ConfigPage } from "@/pages/config"
import { DecisionsPage } from "@/pages/decisions"
import { OverviewPage } from "@/pages/overview"
import { RulesPage } from "@/pages/rules"
import { SessionsPage } from "@/pages/sessions"
import { SettingsPage } from "@/pages/settings"

type Auth =
  | { state: "loading" }
  | { state: "failed"; error: string }
  | { state: "signed-out"; how: SignedOut }
  | { state: "signed-in"; me: Session }

export default function App() {
  const [auth, setAuth] = useState<Auth>({ state: "loading" })

  const signedIn = useCallback((s: Session) => {
    setCsrf(s.csrf)
    setAuth({ state: "signed-in", me: s })
  }, [])

  // Ask again how people may sign in: the session may have ended because
  // the config changed.
  const signedOut = useCallback(() => {
    setCsrf(null)
    api<Me>("/api/me")
      .then((me) => (me.user === null ? setAuth({ state: "signed-out", how: me }) : signedIn(me)))
      .catch((e) => setAuth({ state: "failed", error: errorText(e) }))
  }, [signedIn])

  useEffect(() => {
    upgradeLegacyHash()
    whenSignedOut(signedOut)
    signedOut()
  }, [signedOut])

  const signOut = useCallback(async () => {
    let logoutUrl: string | null = null
    try {
      logoutUrl = (await api<{ logout_url: string | null }>("/api/logout", { method: "POST" })).logout_url
    } catch (e) {
      toast.error(errorText(e))
      return
    }
    // Single sign-on may end the provider's session too.
    if (logoutUrl) {
      location.assign(logoutUrl)
      return
    }
    signedOut()
  }, [signedOut])

  return (
    <TooltipProvider>
      {auth.state === "loading" && (
        <div className="flex min-h-svh items-center justify-center text-muted-foreground">
          <Loader2Icon className="animate-spin" aria-label="Loading" />
        </div>
      )}
      {auth.state === "failed" && (
        <div className="mx-auto max-w-md p-6 pt-[20vh]">
          <ErrorNote title="The dashboard could not reach ariodb" message={auth.error} />
        </div>
      )}
      {auth.state === "signed-out" && <SignIn how={auth.how} onSignedIn={signedIn} />}
      {auth.state === "signed-in" && (
        <MeProvider me={auth.me}>
          <PendingProvider>
            <Shell onSignOut={signOut} />
          </PendingProvider>
        </MeProvider>
      )}
      <Toaster position="top-center" richColors closeButton />
    </TooltipProvider>
  )
}

function Shell({ onSignOut }: { onSignOut: () => void }) {
  const admin = useCan("admin")
  const asked = usePage()
  // Config is for admins; anyone else who follows a link there gets the overview.
  const page: Page = asked === "/config" && !admin ? "/" : asked
  const pending = usePending().data?.approvals.length ?? 0
  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 64)",
          "--header-height": "calc(var(--spacing) * 12)",
        } as CSSProperties
      }
    >
      <AppSidebar variant="inset" current={page} pending={pending} onSignOut={onSignOut} />
      <SidebarInset className="min-w-0">
        <SiteHeader title={titles[page]} pending={pending} onApprovals={page === "/approvals"} />
        <main className="flex flex-1 flex-col">
          <Content page={page} onSignOut={onSignOut} />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

function Content({ page, onSignOut }: { page: Page; onSignOut: () => void }) {
  switch (page) {
    case "/":
      return <OverviewPage />
    case "/approvals":
      return <ApprovalsPage />
    case "/decisions":
      return <DecisionsPage />
    case "/sessions":
      return <SessionsPage />
    case "/rules":
      return <RulesPage />
    case "/config":
      return <ConfigPage />
    case "/settings":
      return <SettingsPage onSignOut={onSignOut} />
  }
}
