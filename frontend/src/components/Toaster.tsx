import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

export type ToastKind = 'success' | 'error' | 'info'

export interface Toast {
  id: number
  kind: ToastKind
  title?: string
  message: string
  duration: number
}

interface ToastApi {
  push: (toast: Omit<Toast, 'id'>) => number
  success: (message: string, title?: string) => number
  error: (message: string, title?: string) => number
  info: (message: string, title?: string) => number
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastApi>({
  push: () => 0,
  success: () => 0,
  error: () => 0,
  info: () => 0,
  dismiss: () => {},
})

export function useToast() {
  return useContext(ToastContext)
}

let nextId = 1

const KIND_STYLE: Record<ToastKind, string> = {
  success: 'border-emerald-700/60 bg-emerald-950/60 text-emerald-300',
  error: 'border-red-700/60 bg-red-950/60 text-red-300',
  info: 'border-indigo-700/60 bg-indigo-950/60 text-indigo-300',
}

const KIND_DOT: Record<ToastKind, string> = {
  success: 'bg-emerald-400',
  error: 'bg-red-400',
  info: 'bg-indigo-400',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map())

  const dismiss = useCallback((id: number) => {
    const t = timers.current.get(id)
    if (t) {
      clearTimeout(t)
      timers.current.delete(id)
    }
    setToasts((prev) => prev.filter((x) => x.id !== id))
  }, [])

  const push = useCallback(
    (toast: Omit<Toast, 'id'>) => {
      const id = nextId++
      // Keep the stack bounded: drop the oldest once 5 are on screen.
      setToasts((prev) => [...prev.slice(-4), { ...toast, id }])
      if (toast.duration > 0) {
        const timer = setTimeout(() => dismiss(id), toast.duration)
        timers.current.set(id, timer)
      }
      return id
    },
    [dismiss],
  )

  useEffect(() => () => {
    timers.current.forEach((t) => clearTimeout(t))
    timers.current.clear()
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      push,
      success: (message, title) => push({ kind: 'success', message, title, duration: 4500 }),
      error: (message, title) => push({ kind: 'error', message, title, duration: 8000 }),
      info: (message, title) => push({ kind: 'info', message, title, duration: 4500 }),
      dismiss,
    }),
    [push, dismiss],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToasterViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

function ToasterViewport({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="pointer-events-none fixed right-3 top-3 z-[60] flex w-[min(24rem,calc(100vw-1.5rem))] flex-col gap-2"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role={t.kind === 'error' ? 'alert' : 'status'}
          className={`toast-enter pointer-events-auto flex items-start gap-3 rounded-lg border px-3 py-2.5 shadow-lg shadow-black/30 backdrop-blur ${KIND_STYLE[t.kind]}`}
        >
          <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${KIND_DOT[t.kind]}`} />
          <div className="min-w-0 flex-1">
            {t.title && <div className="mb-0.5 text-[13px] font-semibold leading-tight">{t.title}</div>}
            <div className="break-words text-[13px] leading-snug opacity-90">{t.message}</div>
          </div>
          <button
            onClick={() => onDismiss(t.id)}
            aria-label="Dismiss notification"
            className="shrink-0 rounded p-0.5 text-current opacity-50 transition-opacity hover:opacity-100"
          >
            <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
            </svg>
          </button>
        </div>
      ))}
    </div>
  )
}