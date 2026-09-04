import type { ReactNode } from 'react'

export function Badge({ children, color = 'gray' }: { children: ReactNode; color?: string }) {
  const colors: Record<string, string> = {
    gray: 'bg-gray-600/20 text-gray-400',
    blue: 'bg-blue-500/20 text-blue-400',
    green: 'bg-emerald-500/20 text-emerald-400',
    yellow: 'bg-yellow-500/20 text-yellow-400',
    red: 'bg-red-500/20 text-red-400',
    orange: 'bg-orange-500/20 text-orange-400',
    fuchsia: 'bg-fuchsia-500/20 text-fuchsia-400',
  }
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${colors[color]}`}>
      {children}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; color: string }> = {
    queued: { label: 'Queued', color: 'gray' },
    discovering: { label: 'Discovering', color: 'blue' },
    scanning: { label: 'Scanning', color: 'blue' },
    fingerprinting: { label: 'Fingerprinting', color: 'blue' },
    analyzing: { label: 'Analyzing', color: 'blue' },
    reverifying: { label: 'Re-verifying', color: 'fuchsia' },
    completed: { label: 'Completed', color: 'green' },
    stopped: { label: 'Stopped', color: 'yellow' },
    failed: { label: 'Failed', color: 'red' },
    active: { label: 'Active', color: 'green' },
    archived: { label: 'Archived', color: 'gray' },
  }
  const s = map[status] || { label: status, color: 'gray' }
  return <Badge color={s.color}>{s.label}</Badge>
}
