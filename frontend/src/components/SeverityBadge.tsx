import { DEVICE_ICONS, normalizeDeviceType } from '../lib/types'

const SEVERITY_DOTS: Record<string, string> = {
  info: '#8B95A1',
  notable: '#E0B341',
  concerning: '#E08341',
  critical: '#E04B4B',
}

export function DeviceIcon({ type, size = 'md' }: { type?: string | null; size?: 'sm' | 'md' | 'lg' }) {
  const sizes = { sm: 'text-sm', md: 'text-lg', lg: 'text-2xl' }
  return <span className={`${sizes[size]} inline-block text-center`}>{DEVICE_ICONS[normalizeDeviceType(type)] || DEVICE_ICONS.unidentified}</span>
}

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_DOTS[severity] || SEVERITY_DOTS.info
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wide"
      style={{ backgroundColor: `${color}20`, color }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {severity}
    </span>
  )
}

export function SeverityDot({ severity }: { severity: string }) {
  const color = SEVERITY_DOTS[severity] || SEVERITY_DOTS.info
  return <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
}
