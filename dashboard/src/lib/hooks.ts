import { useCallback, useEffect, useRef, useState } from "react"
import { api, errorText } from "@/lib/api"

export type Loaded<T> = {
  data: T | null
  error: string | null
  /** True until the first answer for the current path arrives. */
  loading: boolean
  reload: () => Promise<void>
}

/**
 * GET a JSON endpoint, optionally polling it. A failed poll keeps the last
 * good data on screen and shows the error beside it; when the path changes
 * the old data stays until the new answer arrives.
 */
export function useApi<T>(path: string | null, intervalMs?: number): Loaded<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [answered, setAnswered] = useState<string | null>(null)
  const latest = useRef(path)
  useEffect(() => {
    latest.current = path
  }, [path])

  const reload = useCallback(async () => {
    if (path === null) return
    try {
      const d = await api<T>(path)
      if (latest.current !== path) return
      setData(d)
      setError(null)
    } catch (e) {
      if (latest.current !== path) return
      setError(errorText(e))
    }
    setAnswered(path)
  }, [path])

  useEffect(() => {
    void reload()
    if (!intervalMs) return
    const t = window.setInterval(() => void reload(), intervalMs)
    return () => window.clearInterval(t)
  }, [reload, intervalMs])

  return { data, error, loading: path !== null && answered !== path, reload }
}

/** The current time, updated every `everyMs`. */
export function useNow(everyMs = 1000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), everyMs)
    return () => window.clearInterval(t)
  }, [everyMs])
  return now
}
