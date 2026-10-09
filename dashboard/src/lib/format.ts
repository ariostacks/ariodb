const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
})

export function when(ms: number | null | undefined): string {
  return ms ? dateTime.format(new Date(ms)) : ""
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })

export function ago(ms: number, now = Date.now()): string {
  const s = Math.round((ms - now) / 1000)
  const abs = Math.abs(s)
  if (abs < 60) return relative.format(s, "second")
  if (abs < 3600) return relative.format(Math.round(s / 60), "minute")
  if (abs < 86400) return relative.format(Math.round(s / 3600), "hour")
  return relative.format(Math.round(s / 86400), "day")
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

/** Copy text, reporting whether the browser allowed it (it does not over plain HTTP from another host). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard) return false
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
