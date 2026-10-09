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
import { api, errorText, setCsrf, whenSignedOut, type Me, type Session } from "@/lib/api"
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
  | { state: "signed-out"; needsSetup: boolean }
  | { state: "signed-in"; user: string }

export default function App() {
  const [auth, setAuth] = useState<Auth>({ state: "loading" })

  const signedIn = useCallback((s: Session) => {
    setCsrf(s.csrf)
    setAuth({ state: "signed-in", user: s.user })
  }, [])

  const signedOut = useCallback(() => {
    setCsrf(null)
    setAuth({ state: "signed-out", needsSetup: false })
  }, [])

  useEffect(() => {
    upgradeLegacyHash()
    whenSignedOut(signedOut)
    api<Me>("/api/me")
      .then((me) =>
        me.user === null
          ? setAuth({ state: "signed-out", needsSetup: me.needs_setup })
          : signedIn(me)
      )
      .catch((e) => setAuth({ state: "failed", error: errorText(e) }))
  }, [signedIn, signedOut])

  const signOut = useCallback(async () => {
    try {
      await api("/api/logout", { method: "POST" })
    } catch (e) {
      toast.error(errorText(e))
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
      {auth.state === "signed-out" && (
        <SignIn needsSetup={auth.needsSetup} onSignedIn={signedIn} />
      )}
      {auth.state === "signed-in" && (
        <PendingProvider>
          <Shell user={auth.user} onSignOut={signOut} />
        </PendingProvider>
      )}
      <Toaster position="top-center" richColors closeButton />
    </TooltipProvider>
  )
}

function Shell({ user, onSignOut }: { user: string; onSignOut: () => void }) {
  const page = usePage()
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
      <AppSidebar variant="inset" user={user} current={page} pending={pending} onSignOut={onSignOut} />
      <SidebarInset className="min-w-0">
        <SiteHeader title={titles[page]} pending={pending} onApprovals={page === "/approvals"} />
        <main className="flex flex-1 flex-col">
          <Content page={page} user={user} onSignOut={onSignOut} />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

function Content({ page, user, onSignOut }: { page: Page; user: string; onSignOut: () => void }) {
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
      return <SettingsPage user={user} onSignOut={onSignOut} />
  }
}
