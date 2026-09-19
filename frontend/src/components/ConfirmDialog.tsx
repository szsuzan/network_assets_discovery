import { useEffect, useRef, type ReactNode } from 'react'
import { ActionButton } from './ui'

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Delete',
  busy = false,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean
  title: string
  message: ReactNode
  confirmLabel?: string
  busy?: boolean
  onConfirm: () => void
  onCancel: () => void
  children?: ReactNode
}) {
  const confirmRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open) confirmRef.current?.focus()
  }, [open])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-5 shadow-xl">
        <h3 id="confirm-title" className="text-sm font-semibold text-gray-100">{title}</h3>
        <div className="mt-2 text-xs leading-relaxed text-gray-400">{message}</div>
        {children}
        <div className="mt-4 flex items-center justify-end gap-2">
          <ActionButton tone="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </ActionButton>
          <ActionButton tone="confirm" onClick={onConfirm} disabled={busy}>
            {busy ? 'Working…' : confirmLabel}
          </ActionButton>
        </div>
      </div>
    </div>
  )
}