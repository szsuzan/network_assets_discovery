import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../hooks/useApi'
import type { Setting } from '../lib/types'
import { StatCard, Toggle, PrimaryButton, ActionButton, Skeleton } from '../components/ui'
import { useToast } from '../components/Toaster'
import { errText } from '../lib/errors'

const MANAGER_ROLES = ['admin', 'scanner']

function groupName(s: Setting): string {
  return s.category_label
}

function SettingControl({ s, value, jsonDraft, canEdit, onValue, onJsonDraft }: {
  s: Setting
  value: any
  jsonDraft: string
  canEdit: boolean
  onValue: (v: any) => void
  onJsonDraft: (v: string) => void
}) {
  const base =
    'w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white outline-none transition-colors ' +
    'focus:border-indigo-500 ' +
    (canEdit ? '' : 'opacity-60')
  const jsonBroken = s.type === 'json' && (() => {
    try {
      JSON.parse(jsonDraft)
      return false
    } catch {
      return true
    }
  })()

  if (s.type === 'boolean') {
    return <Toggle checked={!!value} onChange={onValue} disabled={!canEdit} />
  }

  if (s.type === 'select') {
    return (
      <select value={value} disabled={!canEdit} onChange={(e) => onValue(e.target.value)} className={base}>
        {(s.options || []).map((o) => (
          <option key={o} value={o}>
            {o.replace(/_/g, ' ')}
          </option>
        ))}
      </select>
    )
  }

  if (s.type === 'number') {
    return (
      <input
        type="number"
        step={Number.isInteger(s.default) ? 1 : 'any'}
        value={value}
        disabled={!canEdit}
        onChange={(e) => {
          const v = e.target.value
          onValue(v === '' ? s.default : Number(v))
        }}
        className={base + ' mono'}
      />
    )
  }

  if (s.type === 'text') {
    return (
      <input
        type="text"
        value={value}
        disabled={!canEdit}
        onChange={(e) => onValue(e.target.value)}
        className={base + ' mono'}
      />
    )
  }

  return (
    <div>
      <textarea
        value={jsonDraft}
        disabled={!canEdit}
        onChange={(e) => onJsonDraft(e.target.value)}
        rows={3}
        className={base + ' font-mono'}
      />
      {jsonBroken && canEdit && <p className="mt-1 text-xs text-red-400">Invalid JSON (fix before saving)</p>}
    </div>
  )
}

function SettingRow({ s, value, jsonDraft, canEdit, onValue, onJsonDraft }: {
  s: Setting
  value: any
  jsonDraft: string
  canEdit: boolean
  onValue: (v: any) => void
  onJsonDraft: (v: string) => void
}) {
  return (
    <div className="flex flex-col gap-1 py-3 sm:flex-row sm:items-start sm:gap-4">
      <div className="flex-1">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
          {s.label}
          {value !== s.default && canEdit && (
            <span className="rounded border border-indigo-700/60 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-normal uppercase tracking-wide text-indigo-300">
              custom
            </span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-gray-500">{s.description}</p>
        <div className="mt-1 mono text-[10px] text-gray-600">key: {s.key}</div>
      </div>
      <div className="w-full sm:w-72">
        <SettingControl
          s={s}
          value={value}
          jsonDraft={jsonDraft}
          canEdit={canEdit}
          onValue={onValue}
          onJsonDraft={onJsonDraft}
        />
      </div>
    </div>
  )
}

export default function Settings() {
  const { data, isLoading } = useSettings()
  const save = useUpdateSettings()
  const toast = useToast()

  const [server, setServer] = useState<Setting[]>([])
  const [draft, setDraft] = useState<Record<string, any>>({})
  const [jsonDraft, setJsonDraft] = useState<Record<string, string>>({})

  const role = localStorage.getItem('role') || ''
  const canEdit = MANAGER_ROLES.includes(role)

  useEffect(() => {
    if (!data) return
    setServer(data)
    const d: Record<string, any> = {}
    const jd: Record<string, string> = {}
    for (const s of data) {
      d[s.key] = s.value
      if (s.type === 'json') jd[s.key] = JSON.stringify(s.value ?? {}, null, 2)
    }
    setDraft(d)
    setJsonDraft(jd)
  }, [data])

  const changed = Object.keys(draft).filter(
    (k) => JSON.stringify(draft[k]) !== JSON.stringify(server.find((s) => s.key === k)?.value),
  )
  const jsonBroken = changed.some((k) => {
    const s = server.find((x) => x.key === k)!
    if (s.type !== 'json') return false
    try {
      JSON.parse(jsonDraft[k])
      return false
    } catch {
      return true
    }
  })

  const groups: Array<[string, Setting[]]> = []
  for (const s of server) {
    const name = groupName(s)
    const last = groups[groups.length - 1]
    if (last && last[0] === name) last[1].push(s)
    else groups.push([name, [s]])
  }

  const customCount = server.filter((s) => draft[s.key] !== undefined && draft[s.key] !== s.default).length

  const reset = () => {
    setDraft(Object.fromEntries(server.map((s) => [s.key, s.value])))
    setJsonDraft(
      Object.fromEntries(
        server.filter((s) => s.type === 'json').map((s) => [s.key, JSON.stringify(s.value ?? {}, null, 2)]),
      ),
    )
  }

  const submit = async () => {
    if (!changed.length || jsonBroken) return
    const payload: Record<string, any> = {}
    for (const k of changed) {
      const s = server.find((x) => x.key === k)!
      payload[k] = s.type === 'json' ? JSON.parse(jsonDraft[k] || '{}') : draft[k]
    }
    save.mutate(payload, {
      onSuccess: () => toast.success('Settings saved'),
      onError: (err) => toast.error(errText(err, 'Failed to save settings')),
    })
  }

  if (isLoading || !server.length) {
    return (
      <div className="mx-auto max-w-6xl">
        <Skeleton className="h-7 w-40" />
        <Skeleton className="mt-2 h-4 w-full max-w-2xl" />
        <div className="mb-6 mt-6 grid grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-400">
            Global defaults and scan-method behaviour for the platform. Changes apply to future
            scans / re-scans (containers, worker and scanner agents).
          </p>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-3 gap-4">
        <StatCard label="Categories" value={groups.length} tone="text-white" />
        <StatCard label="Settings" value={server.length} tone="text-indigo-400" />
        <StatCard label="Custom values" value={customCount} tone="text-amber-400" />
      </div>

      {!canEdit && (
        <div className="mb-4 rounded-md border border-amber-700/50 bg-amber-950/30 px-3 py-2 text-sm text-amber-300">
          Read-only: only admins and scanners can change settings.
        </div>
      )}

      <div className="space-y-6">
        {groups.map(([name, items]) => (
          <section key={name} className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
            <div className="border-b border-gray-800/80 bg-gray-900/70 px-4 py-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-300">{name}</h2>
            </div>
            <div className="divide-y divide-gray-800 px-4">
              {items.map((s) => (
                <SettingRow
                  key={s.key}
                  s={s}
                  value={draft[s.key]}
                  jsonDraft={jsonDraft[s.key] ?? ''}
                  canEdit={canEdit}
                  onValue={(v) => setDraft((d) => ({ ...d, [s.key]: v }))}
                  onJsonDraft={(v) => setJsonDraft((d) => ({ ...d, [s.key]: v }))}
                />
              ))}
            </div>
          </section>
        ))}
      </div>

      <div className="sticky bottom-3 mt-6 flex items-center gap-3 rounded-xl border border-gray-800 bg-gray-900/95 p-3 shadow-lg backdrop-blur">
        <span className="text-sm text-gray-400">
          {changed.length > 0
            ? jsonBroken
              ? 'Fix invalid JSON to save'
              : `${changed.length} unsaved change${changed.length === 1 ? '' : 's'}`
            : 'No changes'}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <ActionButton onClick={reset} disabled={!canEdit || changed.length === 0 || save.isPending}>
            Discard
          </ActionButton>
          <PrimaryButton
            onClick={submit}
            disabled={!canEdit || changed.length === 0 || jsonBroken || save.isPending}
          >
            {save.isPending ? 'Saving…' : 'Save settings'}
          </PrimaryButton>
        </div>
      </div>
    </div>
  )
}