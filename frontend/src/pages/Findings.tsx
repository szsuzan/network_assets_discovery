import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useFindings, usePatchFinding } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { SEVERITY_ORDER, type Finding } from '../lib/types'
import ScanNav from '../components/ScanNav'

const TYPE_LABELS: Record<string, string> = {
  default_credentials: 'Default Credentials',
  eol_software: 'EOL Software',
  exposed_admin_panel: 'Exposed Admin Panel',
  unencrypted_protocol: 'Unencrypted Protocol',
  unexpected_exposure: 'Unexpected Exposure',
}

export default function Findings() {
  const { engagementId, scanId } = useParams()
  const { data: findings } = useFindings(scanId)
  const patchFinding = usePatchFinding()

  const [groupBy, setGroupBy] = useState<'severity' | 'type' | 'host'>('severity')

  const toggleIncluded = (f: Finding) => {
    patchFinding.mutate({ id: f.id, data: { included_in_report: !f.included_in_report } })
  }

  const grouped = useMemo(() => {
    if (!findings) return []
    const map = new Map<string, Finding[]>()
    findings.forEach((f) => {
      let key: string
      if (groupBy === 'severity') key = f.severity
      else if (groupBy === 'type') key = TYPE_LABELS[f.type] || f.type
      else key = f.host_ip || 'Unknown host'
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(f)
    })
    const entries = Array.from(map.entries())
    if (groupBy === 'severity') {
      const order: Record<string, number> = { critical: 0, concerning: 1, notable: 2, info: 3 }
      entries.sort((a, b) => (order[a[0]] ?? 99) - (order[b[0]] ?? 99))
    }
    return entries
  }, [findings, groupBy])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, concerning: 0, notable: 0, info: 0 }
    findings?.forEach((f) => {
      if (counts[f.severity] !== undefined) counts[f.severity]++
    })
    return counts
  }, [findings])

  return (
    <div>
      <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">
        ← Back to engagement
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Risk Findings</h1>
          <p className="mt-1 text-sm text-gray-400">{findings?.length || 0} total findings</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Group by:</span>
          <select
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as any)}
            className="rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-white"
          >
            <option value="severity">Severity</option>
            <option value="type">Type</option>
            <option value="host">Host</option>
          </select>
        </div>
      </div>

      {/* Severity summary */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        {SEVERITY_ORDER.map((sev) => (
          <button
            key={sev}
            onClick={() => setGroupBy('severity')}
            className="rounded-lg border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-600"
          >
            <div className="text-xs uppercase tracking-wide text-gray-500">{sev}</div>
            <div className="mt-1 text-3xl font-bold text-white">{severityCounts[sev] || 0}</div>
          </button>
        ))}
      </div>

      <div className="space-y-4">
        {grouped.map(([key, items]) => (
          <div key={key} className="rounded-lg border border-gray-800 bg-gray-900">
            <div className="border-b border-gray-800 bg-gray-900/70 px-4 py-3">
              <h2 className="font-medium capitalize text-white">{key} <span className="text-sm text-gray-500">({items.length})</span></h2>
            </div>
            <div className="divide-y divide-gray-800">
              {items.map((f) => (
                <div key={f.id} className="px-4 py-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={f.severity} />
                        <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">
                          {TYPE_LABELS[f.type] || f.type}
                        </span>
                      </div>
                      <h3 className="mt-2 font-medium text-white">{f.title}</h3>
                      {f.host_ip && (
                        <Link
                          to={`/engagements/${engagementId}/scans/${scanId}/host/${f.host_ip}`}
                          className="mono mt-1 inline-block text-xs text-blue-400 hover:underline"
                        >
                          {f.host_ip}
                        </Link>
                      )}
                      {f.description && <p className="mt-2 text-sm text-gray-400">{f.description}</p>}
                      {f.cve_refs && f.cve_refs.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {f.cve_refs.map((cve) => (
                            <span key={cve} className="mono rounded bg-gray-800 px-1.5 py-0.5 text-xs text-orange-400">{cve}</span>
                          ))}
                        </div>
                      )}
                      {f.recommendation && (
                        <div className="mt-2 rounded border border-emerald-800/50 bg-emerald-900/20 px-3 py-2 text-sm text-emerald-300">
                          <span className="font-medium">Recommendation: </span>
                          <span>{f.recommendation}</span>
                        </div>
                      )}
                    </div>
                    <label className="flex shrink-0 items-center gap-2 text-xs text-gray-400">
                      <input
                        type="checkbox"
                        checked={f.included_in_report}
                        onChange={() => toggleIncluded(f)}
                        className="h-4 w-4 rounded border-gray-600 bg-gray-800"
                      />
                      Include in report
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {!findings?.length && (
          <div className="rounded-lg border border-gray-800 bg-gray-900 py-12 text-center text-gray-400">
            No findings yet. Run a scan to generate findings.
          </div>
        )}
      </div>
    </div>
  )
}
