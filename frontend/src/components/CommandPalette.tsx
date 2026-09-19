import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useEngagements, useAgents } from '../hooks/useApi'
import { isAdmin, currentRole, canMutate } from '../lib/auth'

interface Option {
  label: string
  hint: string
  to: string
  group: string
  icon: string
}

function PagesSection(): Option[] {
  const role = currentRole()
  const items: Option[] = [
    { label: 'Engagements', hint: 'Browse engagements', to: '/', group: 'Pages', icon: '🗂️' },
    { label: 'Agents', hint: 'Manage scan agents', to: '/agents', group: 'Pages', icon: '🐧' },
    { label: 'Integrations', hint: 'Webhooks & integrations', to: '/integrations', group: 'Pages', icon: '🔌' },
    { label: 'Settings', hint: 'Scanner & report settings', to: '/settings', group: 'Pages', icon: '⚙️' },
  ]
  if (isAdmin()) {
    items.push({ label: 'Administration', hint: 'Users, roles & deletion requests', to: '/admin', group: 'Pages', icon: '🛡️' })
  }
  return role === 'viewer' ? items.filter((i) => i.label === 'Engagements') : items
}

export default function CommandPalette() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [index, setIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const { data: engagements } = useEngagements(open)
  const { data: agents } = useAgents(open && canMutate())

  const toggle = () => {
    setOpen((o) => {
      if (o) return false
      setQuery('')
      setIndex(0)
      return true
    })
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 10)
    else setQuery('')
  }, [open])

  const options = useMemo<Option[]>(() => {
    const all: Option[] = [...PagesSection()]
    for (const e of engagements ?? []) {
      all.push({
        label: e.engagement_name,
        hint: `${e.client_name} · ${e.status}`,
        to: `/engagements/${e.id}`,
        group: 'Engagements',
        icon: '🎯',
      })
    }
    for (const a of agents ?? []) {
      all.push({
        label: a.name,
        hint: `${a.status}${a.hostname ? ` · ${a.hostname}` : ''}`,
        to: '/agents',
        group: 'Agents',
        icon: '🐧',
      })
    }
    const q = query.trim().toLowerCase()
    if (!q) return all
    return all.filter(
      (o) => o.label.toLowerCase().includes(q) || o.hint.toLowerCase().includes(q),
    )
  }, [query, engagements, agents])

  useEffect(() => {
    if (index >= options.length) setIndex(Math.max(0, options.length - 1))
  }, [options.length, index])

  const go = (o: Option | undefined) => {
    if (!o) return
    navigate(o.to)
    setOpen(false)
  }

  if (!open) return null

  const groups: { name: string; items: Option[] }[] = []
  for (const o of options) {
    const g = groups.find((g) => g.name === o.group)
    if (g) g.items.push(o)
    else groups.push({ name: o.group, items: [o] })
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[12vh]"
      onClick={() => setOpen(false)}
      role="dialog"
      aria-modal="true"
      aria-label="Quick search"
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-xl border border-gray-600 bg-gray-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault()
            setIndex((i) => Math.min(i + 1, options.length - 1))
          } else if (e.key === 'ArrowUp') {
            e.preventDefault()
            setIndex((i) => Math.max(i - 1, 0))
          } else if (e.key === 'Enter') {
            e.preventDefault()
            go(options[index])
          } else if (e.key === 'Escape') {
            e.preventDefault()
            setOpen(false)
          }
        }}
      >
        <div className="flex items-center gap-3 border-b border-gray-700 px-4 py-3">
          <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0 text-gray-500" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="7" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setIndex(0)
            }}
            placeholder="Search pages, engagements, agents…"
            className="w-full bg-transparent text-sm text-white placeholder-gray-500 outline-none"
          />
          <kbd className="text-[11px] text-gray-500">Esc</kbd>
        </div>
        <div className="max-h-[50vh] overflow-y-auto p-1.5">
          {groups.length ? (
            groups.map((g) => (
              <div key={g.name}>
                <div className="px-2.5 pb-1 pt-2.5 text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                  {g.name}
                </div>
                {g.items.map((o, i) => {
                  const flat = options.indexOf(o)
                  return (
                    <button
                      key={`${o.group}:${o.label}:${o.to}`}
                      type="button"
                      onMouseEnter={() => setIndex(flat)}
                      onClick={() => go(o)}
                      className={`flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left transition-colors ${
                        flat === index ? 'bg-indigo-600/40' : ''
                      }`}
                    >
                      <span className="text-sm">{o.icon}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-white">{o.label}</span>
                        <span className="block truncate text-xs text-gray-500">{o.hint}</span>
                      </span>
                    </button>
                  )
                })}
              </div>
            ))
          ) : (
            <div className="px-2.5 py-10 text-center text-sm text-gray-500">No matches for “{query}”</div>
          )}
        </div>
      </div>
    </div>
  )
}