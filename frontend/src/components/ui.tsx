import { useState, type ReactNode } from 'react'

export function StatCard({ label, value, tone = 'text-white' }: {
  label: string
  value: number
  tone?: string
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 px-4 py-3">
      <div className={`text-2xl font-bold ${tone}`}>{value}</div>
      <div className="text-[12px] font-medium uppercase tracking-wider text-gray-500">{label}</div>
    </div>
  )
}

type ChipTone = 'gray' | 'indigo' | 'emerald' | 'amber'
const CHIP_TONES: Record<ChipTone, string> = {
  gray: 'border-gray-700 bg-gray-800/70 text-gray-400',
  indigo: 'border-indigo-700/60 bg-indigo-500/10 text-indigo-300',
  emerald: 'border-emerald-700/60 bg-emerald-500/10 text-emerald-300',
  amber: 'border-amber-700/60 bg-amber-500/10 text-amber-300',
}

export function Chip({ children, tone = 'gray' }: { children: string; tone?: ChipTone }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[12px] font-medium ${CHIP_TONES[tone]}`}>
      {children}
    </span>
  )
}

export type DotTone = 'online' | 'offline' | 'disabled'
const DOT_TONES: Record<DotTone, { dot: string; txt: string; wrap: string; pulse: boolean }> = {
  online: { dot: 'bg-emerald-400', txt: 'text-emerald-300', wrap: 'bg-emerald-500/15', pulse: true },
  offline: { dot: 'bg-gray-500', txt: 'text-gray-400', wrap: 'bg-gray-500/15', pulse: false },
  disabled: { dot: 'bg-red-400', txt: 'text-red-300', wrap: 'bg-red-500/15', pulse: false },
}

export function DotPill({ tone, children }: { tone: DotTone; children: ReactNode }) {
  const c = DOT_TONES[tone]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${c.wrap} ${c.txt}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${c.dot} ${c.pulse ? 'animate-pulse' : ''}`} />
      {children}
    </span>
  )
}

export type ActionTone = 'ghost' | 'reset' | 'danger' | 'confirm' | 'primary'
const ACTION_TONES: Record<ActionTone, string> = {
  ghost: 'border border-gray-700 bg-gray-800/60 text-gray-300 hover:bg-gray-700',
  reset: 'border border-amber-800/60 bg-amber-950/40 text-amber-300 hover:bg-amber-900/40',
  danger: 'text-red-400 hover:bg-red-500/10',
  confirm: 'bg-red-600 text-white hover:bg-red-500',
  primary: 'bg-indigo-600 text-white hover:bg-indigo-500',
}

export function Spinner({ className = 'h-3.5 w-3.5' }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent align-middle opacity-80 ${className}`}
    />
  )
}

export function ActionButton({ children, onClick, tone = 'ghost', disabled, loading, title }: {
  children: ReactNode
  onClick: () => void
  tone?: ActionTone
  disabled?: boolean
  loading?: boolean
  title?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${ACTION_TONES[tone]}`}
    >
      {loading ? <Spinner className="h-3 w-3" /> : children}
    </button>
  )
}

export function PrimaryButton({ children, onClick, disabled, loading, className = '', title }: {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  loading?: boolean
  className?: string
  title?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      title={title}
      className={`inline-flex items-center justify-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    >
      {loading && <Spinner className="h-3.5 w-3.5" />}
      {children}
    </button>
  )
}

/** Pulsing placeholder block for loading states. */
export function Skeleton({ className = '', animate = true }: { className?: string; animate?: boolean }) {
  return (
    <div
      aria-hidden="true"
      className={`rounded-md bg-gray-700/50 ${animate ? 'animate-pulse' : ''} ${className}`}
    />
  )
}

/** A card-shaped skeleton (used where pages render loading placeholders). */
export function SkeletonCard({ lines = 3, className = '' }: { lines?: number; className?: string }) {
  return (
    <div className={`rounded-xl border border-gray-800 bg-gray-900 p-4 ${className}`}>
      <Skeleton className="h-5 w-1/3" />
      <div className="mt-3 space-y-2">
        {Array.from({ length: lines }).map((_, i) => (
          <Skeleton key={i} className={`h-3.5 ${i % 3 === 1 ? 'w-2/3' : 'w-full'}`} />
        ))}
      </div>
    </div>
  )
}

export function Toggle({ checked, onChange, disabled, label }: {
  checked: boolean
  onChange: (next: boolean) => void
  disabled?: boolean
  label?: string
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`flex w-full items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm transition-colors ${
        checked ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300' : 'border-gray-700 bg-gray-800 text-gray-400'
      } ${disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}
    >
      <span>{label ?? (checked ? 'Enabled' : 'Disabled')}</span>
      <span className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${checked ? 'bg-emerald-500' : 'bg-gray-600'}`}>
        <span
          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${checked ? 'translate-x-[18px]' : 'translate-x-1'}`}
        />
      </span>
    </button>
  )
}