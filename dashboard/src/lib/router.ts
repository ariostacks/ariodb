// A very small client-side router: the dashboard has seven fixed pages, so
// the History API is all it needs. The server sends index.html for any of
// these paths (see the SPA fallback in src/dashboard.rs).
import { useSyncExternalStore } from "react"

export const pages = [
  "/",
  "/approvals",
  "/decisions",
  "/sessions",
  "/rules",
  "/config",
  "/settings",
] as const
export type Page = (typeof pages)[number]

const listeners = new Set<() => void>()

function notify() {
  for (const l of listeners) l()
}

window.addEventListener("popstate", notify)

export function navigate(to: string, replace = false) {
  if (replace) history.replaceState(null, "", to)
  else history.pushState(null, "", to)
  window.scrollTo(0, 0)
  notify()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function usePage(): Page {
  const path = useSyncExternalStore(subscribe, () => location.pathname)
  const trimmed = path.length > 1 ? path.replace(/\/+$/, "") : path
  return (pages as readonly string[]).includes(trimmed) ? (trimmed as Page) : "/"
}

/**
 * Links in approval notifications point at `/#approval-<id>`, and the old
 * single-page dashboard used `#decisions` style addresses. Turn both into
 * real paths once, at start-up.
 */
export function upgradeLegacyHash() {
  const hash = location.hash.slice(1)
  if (!hash || location.pathname !== "/") return
  if (hash.startsWith("approval-")) navigate(`/approvals#${hash}`, true)
  else if ((pages as readonly string[]).includes(`/${hash}`)) navigate(`/${hash}`, true)
}

/** Follow a link inside the app without a page load, unless a modifier key asks for a new tab. */
export function linkClick(e: React.MouseEvent<HTMLAnchorElement>, to: string) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
  e.preventDefault()
  navigate(to)
}
