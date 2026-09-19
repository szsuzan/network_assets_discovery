export function fmtDateTime(
  iso: string | null | undefined,
  opts: { date?: boolean; time?: boolean } = {},
): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const datePart = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
  const timePart = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  if (opts.time === false) return datePart
  if (opts.date === false) return timePart
  return `${datePart} ${timePart}`
}

export function fmtDate(iso: string | null | undefined): string {
  return fmtDateTime(iso, { time: false })
}

/** Strip the "@domain" suffix so "admin@pentest.local" displays as "admin". */
export function usernameOf(value: string | null | undefined): string {
  if (!value) return ''
  const at = value.indexOf('@')
  return at > 0 ? value.slice(0, at) : value
}

/** Compact, human-friendly relative time: "just now", "5m ago", "3h ago". */
export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never'
  const diff = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000))
  if (diff < 5) return 'just now'
  if (diff < 90) return `${diff}s ago`
  const m = Math.round(diff / 60)
  if (m < 60) return `${m}min ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h ago`
  return fmtDate(iso)
}