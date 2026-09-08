import { useState } from 'react'
import {
  useRiskRules,
  useUpdateRiskRules,
  useReanalyze,
  type RiskRule,
} from '../hooks/useApi'

const SEVERITIES = ['critical', 'concerning', 'notable', 'info']

export default function RiskRulesPanel({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data: rules } = useRiskRules(scanId)
  const update = useUpdateRiskRules(scanId)
  const reanalyze = useReanalyze(scanId)
  const [draft, setDraft] = useState<Record<string, { enabled: boolean; severity: string | null }>>({})

  const list = (rules || []).map((r) => {
    const d = draft[r.key]
    return d ? { ...r, enabled: d.enabled, severity: d.severity } : r
  })

  const setEnabled = (r: RiskRule, enabled: boolean) =>
    setDraft({ ...draft, [r.key]: { enabled, severity: r.severity } })

  const setSeverity = (r: RiskRule, severity: string) =>
    setDraft({ ...draft, [r.key]: { enabled: r.enabled, severity: severity || null } })

  const dirty = Object.keys(draft).length > 0

  const save = () => {
    update.mutate(
      list.map((r) => ({ key: r.key, enabled: r.enabled, severity: r.severity })),
      { onSuccess: () => setDraft({}) }
    )
  }

  const applyAndClose = () => {
    if (dirty) {
      update.mutate(
        list.map((r) => ({ key: r.key, enabled: r.enabled, severity: r.severity })),
        { onSuccess: () => reanalyze.mutate() }
      )
    } else {
      reanalyze.mutate()
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-lg border border-gray-700 bg-gray-900 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">Risk Rules</h2>
            <p className="text-sm text-gray-400">
              Enable/disable analysis rules and override severities. Changes are baked in on the next
              analysis run.
            </p>
          </div>
          <button onClick={onClose} className="rounded px-2 py-1 text-gray-400 hover:text-white">✕</button>
        </div>

        <div className="divide-y divide-gray-800">
          {list.map((r) => (
            <div key={r.key} className="flex items-center gap-4 py-3">
              <input
                type="checkbox"
                checked={r.enabled}
                onChange={(e) => setEnabled(r, e.target.checked)}
                className="h-4 w-4 rounded border-gray-600 bg-gray-800"
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white">{r.label}</span>
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase text-gray-500">{r.kind}</span>
                </div>
                <p className="text-xs text-gray-500">{r.description}</p>
              </div>
              <select
                value={r.severity || ''}
                disabled={!r.enabled}
                onChange={(e) => setSeverity(r, e.target.value)}
                className="w-36 rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-white outline-none focus:border-blue-500 disabled:opacity-40"
                title={r.severity ? `Override: ${r.severity} (default ${r.default_severity})` : `Default: ${r.default_severity}`}
              >
                <option value="">Default ({r.default_severity})</option>
                {SEVERITIES.filter((s) => s !== r.default_severity).map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
          ))}
        </div>

        <div className="mt-5 flex items-center justify-end gap-3 border-t border-gray-800 pt-4">
          <span className="text-xs text-gray-500">
            {reanalyze.isPending || update.isPending
              ? 'Applying…'
              : dirty
                ? 'Unsaved changes'
                : 'All rules at defaults'}
          </span>
          <button
            onClick={save}
            disabled={!dirty || update.isPending}
            className="rounded border border-gray-700 px-4 py-1.5 text-sm text-gray-300 hover:border-gray-500 disabled:opacity-40"
          >
            Save
          </button>
          <button
            onClick={applyAndClose}
            disabled={update.isPending || reanalyze.isPending}
            className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40"
          >
            Apply &amp; Re-analyze
          </button>
        </div>
      </div>
    </div>
  )
}