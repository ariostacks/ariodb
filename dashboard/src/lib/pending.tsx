// The approvals queue, polled once for the whole app: the sidebar badge,
// the header, the tab title and the Approvals page all read the same list.
import { createContext, useContext, useEffect, type ReactNode } from "react"
import type { Approval } from "@/lib/api"
import { useApi, type Loaded } from "@/lib/hooks"

const POLL_MS = 2500

const Pending = createContext<Loaded<{ approvals: Approval[] }> | null>(null)

export function PendingProvider({ children }: { children: ReactNode }) {
  const pending = useApi<{ approvals: Approval[] }>("/api/approvals", POLL_MS)
  const count = pending.data?.approvals.length ?? 0
  useEffect(() => {
    document.title = count > 0 ? `(${count}) ariodb` : "ariodb"
  }, [count])
  return <Pending.Provider value={pending}>{children}</Pending.Provider>
}

export function usePending() {
  const ctx = useContext(Pending)
  if (!ctx) throw new Error("usePending outside PendingProvider")
  return ctx
}
