import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../hooks/useApi'
import type { Setting } from '../lib/types'

const MANAGER_ROLES = ['admin', 'pentester']

function groupName(s: Setting): string {
  return s.category_label
}

function SettingRow({
  s,
  value,
  jsonDraft,
  canEdit,
  onValue,
  onJsonDraft,
}: {
  s: Setting
  value: any
  jsonDraft: string
  canEdit: boolean
  onValue: (v: any) => void
  onJsonDraft: (v: string) => void
}) {
  const base =
    'w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white ' +
    (canEdit ? '' : 'opacity-60')
  const jsonBroken = s.type === 'json' && (() => {
    try {
      JSON.parse(jsonDraft)
      return false
    } catch {
      return true
    }
  })()

  return (
    <div className="flex flex-col gap-1 py-3 sm:flex-row sm:items-start sm:gap-4">
      <div className="flex-1">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
          {s.label}
          {value !== s.default && canEdit && (
            <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-normal uppercase tracking-wide text-blue-300">
              custom
            </span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-gray-500">{s.description}</p>
        <div className="mt-1 text-[10px] text-gray-600 mono">key: {s.key}</div>
      </div>

      <div className="w-full sm:w-64">
        {s.type === 'boolean' && (
          <button
            type="button"
            disabled={!canEdit}
            onClick={() => onValue(!value)}
            className={`flex w-full items-center justify-between rounded border px-3 py-2 text-sm ${
              canEdit ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'
            } ${
              value
                ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                : 'border-gray-700 bg-gray-800 text-gray-400'
            }`}
          >
            <span>{value ? 'Enabled' : 'Disabled'}</span>
            <span className="text-xs">{value ? '●' : '○'}</span>
          </button>
        )}

        {s.type === 'select' && (
          <select
            value={value}
            disabled={!canEdit}
            onChange={(e) => onValue(e.target.value)}
            className={base}
          >
            {(s.options || []).map((o) => (
              <option key={o} value={o}>
                {o.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        )}

        {s.type === 'number' && (
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
        )}

        {s.type === 'text' && (
          <input
            type="text"
            value={value}
            disabled={!canEdit}
            onChange={(e) => onValue(e.target.value)}
            className={base + ' mono'}
          />
        )}

        {s.type === 'json' && (
          <div>
            <textarea
              value={jsonDraft}
              disabled={!canEdit}
              onChange={(e) => onJsonDraft(e.target.value)}
              rows={3}
              className={base + ' mono font-mono'} 
            />
            {jsonBroken && canEdit && (
              <p className="mt-1 text-xs text-red-400">Invalid JSON (fix before saving)</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function Settings() {
  const { data, isLoading } = useSettings()
  const save = useUpdateSettings()

  const [server, setServer] = useState<Setting[]>([])
  const [draft, setDraft] = useState<Record<string, any>>({})
  const [jsonDraft, setJsonDraft] = useState<Record<string, string>>({})
  const [savedMsg, setSavedMsg] = useState<string | null>(null)

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
      onSuccess: () => {
        setSavedMsg('Settings saved')
        window.setTimeout(() => setSavedMsg(null), 3000)
      },
    })
  }

  if (isLoading || !server.length) {
    return <div className="py-10 text-center text-sm text-gray-500">Loading settings…</div>
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="mt-1 text-sm text-gray-400">
            Global defaults and scan-method behaviour for the platform. Changes apply to future
            scans / re-scans (containers, worker and scanner agents).
          </p>
        </div>
      </div>

      {!canEdit && (
        <div className="mb-4 rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-sm text-amber-300">
          Read-only: only admins and pentesters can change settings.
        </div>
      )}

      <div className="space-y-6">
        {groups.map(([name, items]) => (
          <section key={name} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
            <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-gray-300">
              {name}
            </h2>
            <div className="divide-y divide-gray-800">
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

      <div className="sticky bottom-3 mt-6 flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/95 p-3 shadow-lg backdrop-blur">
        <span className="text-sm text-gray-400">
          {changed.length > 0
            ? jsonBroken
              ? 'Fix invalid JSON to save'
              : `${changed.length} unsaved change${changed.length === 1 ? '' : 's'}`
            : 'No changes'}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {savedMsg && <span className="text-sm text-emerald-400">{savedMsg}</span>}
          <button
            onClick={reset}
            disabled={!canEdit || changed.length === 0 || save.isPending}
            className="rounded border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40"
          >
            Discard
          </button>
          <button
            onClick={submit}
            disabled={!canEdit || changed.length === 0 || jsonBroken || save.isPending}
            className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {save.isPending ? 'Saving…' : 'Save settings'}
          </button>
        </div>
      </div>
    </div>
  )
}