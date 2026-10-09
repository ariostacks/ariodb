// The signed-in user, for pages that show or hide things by role. The
// server checks every request's role itself; this only keeps people from
// being offered buttons that would be refused.
import { createContext, useContext, type ReactNode } from "react"
import { atLeast, type Role, type Session } from "@/lib/api"

const Me = createContext<Session | null>(null)

export function MeProvider({ me, children }: { me: Session; children: ReactNode }) {
  return <Me.Provider value={me}>{children}</Me.Provider>
}

export function useMe(): Session {
  const me = useContext(Me)
  if (!me) throw new Error("useMe outside MeProvider")
  return me
}

/** Does the signed-in user have at least this role? */
export function useCan(role: Role): boolean {
  return atLeast(useMe().role, role)
}
