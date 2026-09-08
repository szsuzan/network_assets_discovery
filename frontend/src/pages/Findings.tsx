import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useFindings, usePatchFinding, useFindingAudit } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import {
  DEVICE_TYPE_LABELS,
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  normalizeDeviceType,
  SEVERITY_ORDER,
  type Finding,
  type FindingAuditEntry,
} from '../lib/types'
import ScanNav from '../components/ScanNav'
import RiskRulesPanel from '../components/RiskRulesPanel'

const TYPE_LABELS: Record<string, string> = {
  default_credentials: 'Default Credentials',
  eol_software: 'EOL Software',
  exposed_admin_panel: 'Exposed Admin Panel',
  unencrypted_protocol: 'Unencrypted Protocol',
  unencrypted_video: 'Unencrypted Video Stream',
  weak_crypto: 'Weak TLS/Crypto',
  expired_certificate: 'Expired Certificate',
  smb_signing_disabled: 'SMB Signing Not Required',
  anonymous_ftp: 'Anonymous FTP',
  unrestricted_share: 'World-Readable SMB Share',
  dangerous_http_methods: 'Dangerous HTTP Methods',
  missing_auth: 'Missing Authentication',
  empty_password: 'Empty Password',
  web_service_exposed: 'Web Service Exposed',
  information_disclosure: 'Information Disclosure',
  unexpected_exposure: 'Unexpected Exposure',
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-gray-800 text-gray-300',
  triaged: 'bg-blue-900/50 text-blue-300',
  confirmed: 'bg-orange-900/50 text-orange-300',
  remediation_in_progress: 'bg-yellow-900/50 text-yellow-300',
  retest: 'bg-purple-900/50 text-purple-300',
  resolved: 'bg-emerald-900/50 text-emerald-300',
  accepted_risk: 'bg-slate-700 text-slate-300',
  false_positive: 'bg-slate-800 text-slate-400 line-through',
}

function hostKey(f: Finding): string {
  if (f.host_hostname) return f.host_hostname
  if (f.host_device_type) {
    const label = DEVICE_TYPE_LABELS[normalizeDeviceType(f.host_device_type)]
    if (label) return label
  }
  return f.host_ip || 'Unknown host'
}

function hostContext(f: Finding): string {
  const parts: string[] = []
  if (f.host_hostname) parts.push(f.host_hostname)
  const label = DEVICE_TYPE_LABELS[normalizeDeviceType(f.host_device_type)]
  if (label) parts.push(label)
  return parts.join(' · ')
}

function AuditHistory({ scanId, findingId }: { scanId: string; findingId: string }) {
  const { data: entries } = useFindingAudit(scanId, findingId)
  const list = entries as FindingAuditEntry[] | undefined
  if (!list?.length) return <p className="text-xs text-gray-500">No audit history.</p>
  return (
    <ul className="space-y-1.5">
      {list.map((e) => (
        <li key={e.id} className="text-xs text-gray-400">
          <span className="mono text-gray-500">{new Date(e.created_at).toLocaleString()}</span>{' '}
          {e.field === 'included_in_report'
            ? (e.new_value === 'True' ? 'included in report' : 'excluded from report')
            : `${e.field || 'updated'} changed`}
          {e.old_value != null && e.new_value != null && e.old_value !== e.new_value && (
            <span className="mono text-gray-400">
              : {e.old_value || '—'} → {e.new_value || '—'}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

function statusBadge(f: Finding) {
  const cls = STATUS_COLORS[f.status] || STATUS_COLORS.open
  return (
    <span className={`rounded px-2 py-0.5 text-xs ${cls}`}>
      {FINDING_STATUS_LABELS[f.status] || f.status}
    </span>
  )
}

export default function Findings() {
  const { engagementId, scanId } = useParams()
  const { data: findings } = useFindings(scanId)
  const patchFinding = usePatchFinding()

  const [groupBy, setGroupBy] = useState<'severity' | 'type' | 'host'>('severity')
  const [notesDraft, setNotesDraft] = useState<Record<string, string>>({})
  const [historyOpen, setHistoryOpen] = useState<Record<string, boolean>>({})
  const [rulesOpen, setRulesOpen] = useState(false)

  const patch = (f: Finding, data: Partial<Finding>) => {
    patchFinding.mutate({ id: f.id, data })
  }

  const toggleIncluded = (f: Finding) => {
    patch(f, { included_in_report: !f.included_in_report })
  }

  const saveNotes = (f: Finding) => {
    const draft = notesDraft[f.id]
    if (draft === undefined) return
    patch(f, { notes: draft.length ? draft : null })
  }

  const grouped = useMemo(() => {
    if (!findings) return []
    const map = new Map<string, Finding[]>()
    findings.forEach((f) => {
      let key: string
      if (groupBy === 'severity') key = f.severity
      else if (groupBy === 'type') key = TYPE_LABELS[f.type] || f.type
      else key = hostKey(f)
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

  const excluded = findings?.filter((f) => !f.included_in_report).length || 0

  return (
    <div>
      <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">
        ← Back to engagement
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Risk Findings</h1>
          <p className="mt-1 text-sm text-gray-400">
            {findings?.length || 0} total findings{excluded > 0 ? ` · ${excluded} excluded from report` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setRulesOpen(true)}
            className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700"
          >
            Risk Rules
          </button>
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
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-3">
                        <SeverityBadge severity={f.severity} />
                        <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">
                          {TYPE_LABELS[f.type] || f.type}
                        </span>
                        {statusBadge(f)}
                        {f.cwe && (
                          <span className="mono rounded border border-gray-700 px-2 py-0.5 text-xs text-orange-400">{f.cwe}</span>
                        )}
                        {f.cvss_score != null && (
                          <span className="mono rounded border border-gray-700 px-2 py-0.5 text-xs text-gray-300">
                            CVSS {f.cvss_score.toFixed(1)}
                            {f.cvss_vector ? <span className="text-gray-500" title={f.cvss_vector}>*</span> : null}
                          </span>
                        )}
                      </div>
                      <h3 className="mt-2 font-medium text-white">{f.title}</h3>
                      {f.host_ip && (
                        <Link
                          to={`/engagements/${engagementId}/scans/${scanId}/host/${f.host_ip}`}
                          className="mono mt-1 inline-block text-xs text-blue-400 hover:underline"
                        >
                          {f.host_ip}{f.host_ip && hostContext(f) ? ` · ${hostContext(f)}` : ''}
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
                      {f.evidence?.output && (
                        <div className="mono mt-2 max-h-24 overflow-y-auto whitespace-pre-wrap rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-500">
                          <span className="text-gray-400">[evidence: {f.evidence.script}] </span>
                          {f.evidence.output}
                        </div>
                      )}
                      {f.recommendation && (
                        <div className="mt-2 rounded border border-emerald-800/50 bg-emerald-900/20 px-3 py-2 text-sm text-emerald-300">
                          <span className="font-medium">Recommendation: </span>
                          <span>{f.recommendation}</span>
                        </div>
                      )}
                      <div className="mt-2 flex flex-wrap items-center gap-3">
                        <label className="flex shrink-0 items-center gap-2 text-xs text-gray-400">
                          <input
                            type="checkbox"
                            checked={f.included_in_report}
                            onChange={() => toggleIncluded(f)}
                            className="h-4 w-4 rounded border-gray-600 bg-gray-800"
                          />
                          Include in report
                        </label>
                        <button
                          onClick={() => setHistoryOpen({ ...historyOpen, [f.id]: !historyOpen[f.id] })}
                          className="text-xs text-gray-500 hover:text-gray-300"
                        >
                          {historyOpen[f.id] ? 'Hide' : 'View'} audit history
                        </button>
                      </div>
                      {historyOpen[f.id] && (
                        <div className="mt-3 rounded border border-gray-800 bg-gray-950 p-3">
                          <AuditHistory scanId={scanId!} findingId={f.id} />
                        </div>
                      )}
                    </div>

                    {/* Workflow column */}
                    <div className="flex w-56 shrink-0 flex-col gap-3">
                      <div>
                        <label className="mb-1 block text-[11px] uppercase tracking-wide text-gray-500">Status</label>
                        <select
                          value={f.status}
                          onChange={(e) => patch(f, { status: e.target.value })}
                          className="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-white outline-none focus:border-blue-500"
                        >
                          {FINDING_STATUSES.map((s) => <option key={s} value={s}>{FINDING_STATUS_LABELS[s]}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-[11px] uppercase tracking-wide text-gray-500">Analyst Notes</label>
                        <textarea
                          rows={2}
                          defaultValue={f.notes || ''}
                          onChange={(e) => setNotesDraft({ ...notesDraft, [f.id]: e.target.value })}
                          onBlur={() => saveNotes(f)}
                          placeholder="Add analyst notes…"
                          className="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-300 outline-none focus:border-blue-500"
                        />
                      </div>
                    </div>
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

      {rulesOpen && scanId && (
        <RiskRulesPanel scanId={scanId} onClose={() => setRulesOpen(false)} />
      )}
    </div>
  )
}