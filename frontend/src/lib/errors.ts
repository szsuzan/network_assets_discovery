// Readable error text from an axios/AxiosError-style object.
//
// FastAPI returns validation failures (HTTP 422) as an ARRAY of
// { loc, msg, type } objects; stringifying them yields "[object Object]".
// Flatten those into human-readable text and fall back to the message or a
// sensible default when nothing usable is present.
export function errText(err: unknown, fallback = 'Something went wrong'): string {
  const e = err as { response?: { data?: { detail?: unknown } }; message?: string }
  const detail = e?.response?.data?.detail
  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => {
        if (d == null) return ''
        if (typeof d === 'string') return d
        if (typeof d === 'object' && typeof (d as any)?.msg === 'string') return (d as any).msg
        try {
          return JSON.stringify(d)
        } catch {
          return ''
        }
      })
      .filter(Boolean)
    return parts.length ? parts.join('; ') : fallback
  }
  if (typeof detail === 'string' && detail.trim()) return detail
  if (detail != null && typeof detail === 'object') {
    try {
      const s = JSON.stringify(detail)
      if (s && s !== '{}') return s
    } catch {
      /* ignore */
    }
  }
  if (typeof e?.message === 'string' && e.message.trim()) return e.message
  return fallback
}