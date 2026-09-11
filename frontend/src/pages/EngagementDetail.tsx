import { useEffect, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import {
  useEngagement,
  useEngagementScans,
  useStartScan,
  useScanDiff,
  useStopScan,
  usePauseScan,
  useResumeScan,
  useReverifyScan,
  useDeleteScan,
  useUpdateEngagement,
  useSettings,
} from '../hooks/useApi'
import { StatusBadge } from '../components/Badge'
import type { Scan } from '../lib/types'

const ACTIVE_STATUSES = ['queued', 'discovering', 'scanning', 'fingerprinting', 'analyzing', 'paused', 'agent_running', 'reverifying']

const PROFILE_NOTES: Record<string, string> = {
  quick: 'Fast top-1000 port scan, standard timing. For most engagements.',
  full: 'Comprehensive top-10000 port scan with deep fingerprinting. Default.',
  stealth: 'Heavily throttled. Safer for fragile OT/IoT devices that can crash under aggressive scanning.',
  passive_only: 'No active probes. Passive CDP/LLDP/mDNS capture only. Slowest, zero footprint.',
}

// Port range each profile implies, applied when the profile is selected.
const PROFILE_PORT_RANGES: Record<string, string> = {
  quick: '1-1000',
  full: '1-10000',
  stealth: '1-1000',
  passive_only: '1-10000',
}

export default function EngagementDetail() {
  const { engagementId } = useParams()
  const stopScan = useStopScan()
  const pauseScan = usePauseScan()
  const resumeScan = useResumeScan()
  const reverifyScan = useReverifyScan()
  const navigate = useNavigate()
  const { data: engagement } = useEngagement(engagementId)
  const { data: scans } = useEngagementScans(engagementId)
  const startScan = useStartScan(engagementId!)
  const deleteScan = useDeleteScan()

  const [confirmDeleteScan, setConfirmDeleteScan] = useState<string | null>(null)

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    targets: '',
    profile: 'full',
    port_range: '1-10000',
    protocol: 'tcp',
    scope_confirmed: false,
  })
  const [touched, setTouched] = useState(false)
  const { data: globalSettings } = useSettings()
  const updateEngagement = useUpdateEngagement()

  const [editing, setEditing] = useState(false)
  const [editForm, setEditForm] = useState({
    client_name: '',
    engagement_name: '',
    authorized_scope: '',
    start_date: '',
    end_date: '',
  })
  const [editError, setEditError] = useState<string | null>(null)

  const startEdit = () => {
    if (!engagement) return
    setEditForm({
      client_name: engagement.client_name,
      engagement_name: engagement.engagement_name,
      authorized_scope: engagement.authorized_scope.join(', '),
      start_date: engagement.start_date || '',
      end_date: engagement.end_date || '',
    })
    setEditError(null)
    setEditing(true)
  }

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault()
    setEditError(null)
    const scope = editForm.authorized_scope.split(/[\s,]+/).filter(Boolean)
    try {
      await updateEngagement.mutateAsync({
        id: engagementId!,
        client_name: editForm.client_name,
        engagement_name: editForm.engagement_name,
        authorized_scope: scope,
        start_date: editForm.start_date || null,
        end_date: editForm.end_date || null,
      })
      setEditing(false)
    } catch (err: any) {
      setEditError(err?.response?.data?.detail || 'Failed to update engagement')
    }
  }

  // Prefill the new-scan form with the defaults configured in Settings (only
  // until the user starts editing those fields themselves).
  useEffect(() => {
    if (!globalSettings || touched) return
    const val = (key: string, fallback: string) =>
      globalSettings.find((s) => s.key === key)?.value ?? fallback
    setForm((f) => ({
      ...f,
      profile: val('scan.default_profile', f.profile),
      port_range: val('scan.default_port_range', f.port_range),
      protocol: val('scan.default_protocol', f.protocol),
    }))
  }, [globalSettings, touched])

  const [diffScanA, setDiffScanA] = useState('')
  const [diffScanB, setDiffScanB] = useState('')
  const diff = useScanDiff(diffScanA || undefined, diffScanB || undefined)

  const [startError, setStartError] = useState<string | null>(null)

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.scope_confirmed) return
    const targets = form.targets.split(/[\s,]+/).filter(Boolean)
    if (targets.length === 0) return
    setStartError(null)
    try {
      const scan = await startScan.mutateAsync({
        targets,
        profile: form.profile,
        port_range: form.port_range,
        protocol: form.protocol,
      })
      navigate(`/engagements/${engagementId}/scans/${scan.id}/live`)
    } catch (err: any) {
      setStartError(err?.response?.data?.detail || 'Failed to start scan')
    }
  }

  return (
    <div>
      <Link to="/" className="text-sm text-gray-400 hover:text-white">← Back to engagements</Link>

      <div className="mt-4 mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{engagement?.engagement_name}</h1>
          <p className="mt-1 text-sm text-gray-400">
            Client: <span className="text-gray-300">{engagement?.client_name}</span> · Scope:{' '}
            <span className="mono text-gray-300">{engagement?.authorized_scope.join(', ')}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={engagement?.status || 'active'} />
          <button
            onClick={() => (editing ? setEditing(false) : startEdit())}
            className="rounded border border-blue-600 px-4 py-2 text-sm font-medium text-blue-400 hover:bg-blue-600/20"
          >
            {editing ? 'Cancel Edit' : 'Edit'}
          </button>
          <button
            onClick={() => setShowForm(!showForm)}
            className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            {showForm ? 'Cancel' : '+ New Scan'}
          </button>
        </div>
      </div>

      {editing && (
        <form onSubmit={handleUpdate} className="mb-6 rounded-lg border border-blue-800 bg-gray-900 p-4">
          <h2 className="mb-3 font-medium">Edit Engagement</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm text-gray-300">Client Name *</label>
              <input
                value={editForm.client_name}
                onChange={(e) => setEditForm({ ...editForm, client_name: e.target.value })}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Engagement Name *</label>
              <input
                value={editForm.engagement_name}
                onChange={(e) => setEditForm({ ...editForm, engagement_name: e.target.value })}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Authorized Scope (CIDR list)</label>
              <input
                value={editForm.authorized_scope}
                onChange={(e) => setEditForm({ ...editForm, authorized_scope: e.target.value })}
                placeholder="10.0.0.0/24, 192.168.1.0/24"
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white mono"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="mb-1 block text-sm text-gray-300">Start Date</label>
                <input
                  type="date"
                  value={editForm.start_date}
                  onChange={(e) => setEditForm({ ...editForm, start_date: e.target.value })}
                  className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm text-gray-300">End Date</label>
                <input
                  type="date"
                  value={editForm.end_date}
                  onChange={(e) => setEditForm({ ...editForm, end_date: e.target.value })}
                  className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                />
              </div>
            </div>
          </div>
          {editError && (
            <p className="mt-3 whitespace-pre-line text-sm text-red-400">{editError}</p>
          )}
          <button
            type="submit"
            disabled={updateEngagement.isPending}
            className="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {updateEngagement.isPending ? 'Saving...' : 'Save Changes'}
          </button>
        </form>
      )}

      {showForm && (
        <form onSubmit={handleStart} className="mb-6 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm text-gray-300">Targets (must be within authorized scope)</label>
              <input
                value={form.targets}
                onChange={(e) => setForm({ ...form, targets: e.target.value })}
                placeholder={engagement?.authorized_scope.join(' ')}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white mono"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Port Range</label>
              <input
                value={form.port_range}
                onChange={(e) => {
                  setTouched(true)
                  setForm({ ...form, port_range: e.target.value })
                }}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white mono"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Protocol</label>
              <div className="flex gap-2">
                {(['tcp', 'udp'] as const).map((p) => (
                  <button
                    type="button"
                    key={p}
                    onClick={() => {
                      setTouched(true)
                      setForm({ ...form, protocol: p })
                    }}
                    className={`flex-1 rounded border px-3 py-2 text-sm font-medium uppercase transition-colors ${
                      form.protocol === p
                        ? 'border-blue-500 bg-blue-500/10 text-white'
                        : 'border-gray-700 text-gray-300 hover:border-gray-500'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-xs text-gray-500">
                UDP is a separate scan pass and does not include TCP ports.
              </p>
            </div>
          </div>

          <div className="mt-4">
            <label className="mb-2 block text-sm text-gray-300">Scan Profile</label>
            <div className="grid grid-cols-4 gap-3">
              {Object.entries(PROFILE_NOTES).map(([key, note]) => (
                <button
                  type="button"
                  key={key}
                  onClick={() => {
                        setTouched(true)
                        setForm({ ...form, profile: key, port_range: PROFILE_PORT_RANGES[key] })
                      }}
                  className={`rounded border p-3 text-left transition-colors ${
                    form.profile === key
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-gray-700 hover:border-gray-500'
                  }`}
                >
                  <div className="font-medium capitalize text-white">{key.replace('_', ' ')}</div>
                  <div className="mt-1 text-xs text-gray-400">{note}</div>
                </button>
              ))}
            </div>
          </div>

          <label className="mt-4 flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.scope_confirmed}
              onChange={(e) => setForm({ ...form, scope_confirmed: e.target.checked })}
              className="h-4 w-4 rounded border-gray-600"
            />
            I confirm all targets are within the engagement's authorized scope
          </label>

          <button
            type="submit"
            disabled={!form.scope_confirmed || !form.targets.trim() || startScan.isPending}
            className="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {startScan.isPending ? 'Starting...' : 'Start Scan'}
          </button>
          {startError && (
            <div className="mt-3 whitespace-pre-line rounded border border-red-800 bg-red-950/50 px-3 py-2 text-sm text-red-400">
              {startError}
            </div>
          )}
          {!form.targets.trim() && (
            <p className="mt-2 text-xs text-amber-400">Enter at least one target (IP or CIDR) to start a scan.</p>
          )}
        </form>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Scans list */}
        <div className="lg:col-span-2 overflow-hidden rounded-lg border border-gray-800">
          <h2 className="border-b border-gray-800 bg-gray-900 px-4 py-3 font-medium">Scans</h2>
          <table className="w-full text-sm">
            <thead className="bg-gray-900/50 text-left text-gray-400">
              <tr>
                <th className="px-4 py-2 font-medium">Profile</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Targets</th>
                <th className="px-4 py-2 font-medium">Progress</th>
                <th className="px-4 py-2 font-medium">Started</th>
                <th className="px-4 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans?.map((s: Scan) => (
                <tr key={s.id} className="bg-gray-900/50 hover:bg-gray-800/50">
                  <td className="px-4 py-3">
                    <Link to={`/engagements/${engagementId}/scans/${s.id}/live`} className="text-blue-400 hover:underline capitalize">
                      {s.profile.replace('_', ' ')}
                    </Link>
                    <span className="ml-2 rounded border border-gray-700 px-1.5 py-0.5 text-[10px] uppercase text-gray-400">{s.protocol}</span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                  <td className="px-4 py-3 mono text-gray-300">{s.targets.join(', ')}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded bg-gray-800">
                        <div className="h-full bg-blue-600" style={{ width: `${s.progress_pct}%` }} />
                      </div>
                      <span className="text-xs text-gray-400">{s.progress_pct}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{s.started_at ? new Date(s.started_at).toLocaleString() : '—'}</td>
                  <td className="px-4 py-3">
                    {ACTIVE_STATUSES.includes(s.status) ? (
                      <div className="flex items-center gap-1.5">
                        {s.status === 'paused' ? (
                          <button
                            onClick={() => resumeScan.mutate(s.id)}
                            className="rounded border border-blue-600 px-2 py-1 text-xs text-blue-400 hover:bg-blue-600/20"
                          >
                            Resume
                          </button>
                        ) : (
                          <button
                            onClick={() => pauseScan.mutate(s.id)}
                            className="rounded border border-amber-600 px-2 py-1 text-xs text-amber-400 hover:bg-amber-600/20"
                          >
                            Pause
                          </button>
                        )}
                        <button
                          onClick={() => stopScan.mutate(s.id)}
                          className="rounded border border-red-600 px-2 py-1 text-xs text-red-400 hover:bg-red-600/20"
                        >
                          Stop
                        </button>
                        {confirmDeleteScan === s.id ? (
                          <span className="inline-flex items-center gap-1.5">
                            <button
                              onClick={async () => {
                                await deleteScan.mutateAsync(s.id)
                                setConfirmDeleteScan(null)
                              }}
                              disabled={deleteScan.isPending}
                              className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setConfirmDeleteScan(null)}
                              className="rounded bg-gray-700 px-2 py-1 text-xs font-medium text-white hover:bg-gray-600"
                            >
                              Cancel
                            </button>
                          </span>
                        ) : (
                          <button
                            onClick={() => setConfirmDeleteScan(s.id)}
                            className="rounded border border-red-800 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
                            title="Permanently delete this scan and all its hosts, findings, and audit trail"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => {
                            reverifyScan.mutate(s.id, {
                              onSuccess: (scan) =>
                                navigate(`/engagements/${engagementId}/scans/${scan.id}/live`),
                            })
                          }}
                          className="rounded border border-fuchsia-600 px-2 py-1 text-xs text-fuchsia-400 hover:bg-fuchsia-600/20"
                          title="Re-verify: re-check down hosts and sweep ports the initial scan didn't check. Merges into this report without duplication."
                        >
                          Re-verify
                        </button>
                        {confirmDeleteScan === s.id ? (
                          <span className="inline-flex items-center gap-1.5">
                            <button
                              onClick={async () => {
                                await deleteScan.mutateAsync(s.id)
                                setConfirmDeleteScan(null)
                              }}
                              disabled={deleteScan.isPending}
                              className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setConfirmDeleteScan(null)}
                              className="rounded bg-gray-700 px-2 py-1 text-xs font-medium text-white hover:bg-gray-600"
                            >
                              Cancel
                            </button>
                          </span>
                        ) : (
                          <button
                            onClick={() => setConfirmDeleteScan(s.id)}
                            className="rounded border border-red-800 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
                            title="Permanently delete this scan and all its hosts, findings, and audit trail"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Scan comparison */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 font-medium">Scan Comparison</h2>
          <p className="mb-3 text-xs text-gray-400">Compare two scans to see what's new, changed, or gone.</p>

          <div className="space-y-2">
            <select
              value={diffScanA}
              onChange={(e) => setDiffScanA(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
            >
              <option value="">Select first scan</option>
              {scans?.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.profile} — {s.started_at ? new Date(s.started_at).toLocaleDateString() : ''}
                </option>
              ))}
            </select>
            <select
              value={diffScanB}
              onChange={(e) => setDiffScanB(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
            >
              <option value="">Select second scan</option>
              {scans?.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.profile} — {s.started_at ? new Date(s.started_at).toLocaleDateString() : ''}
                </option>
              ))}
            </select>
          </div>

          {diff.data && (
            <div className="mt-4 space-y-3 text-sm">
              <div className="flex gap-2">
                <span className="rounded bg-emerald-500/20 px-2 py-1 text-emerald-400">+{diff.data.new_hosts.length} new</span>
                <span className="rounded bg-red-500/20 px-2 py-1 text-red-400">−{diff.data.missing_hosts.length} gone</span>
                <span className="rounded bg-yellow-500/20 px-2 py-1 text-yellow-400">~{diff.data.changed_ports.length} changed</span>
              </div>
              {diff.data.new_hosts.slice(0, 3).map((h: any) => (
                <div key={h.ip} className="mono text-emerald-400">+ {h.ip} {h.hostname || ''}</div>
              ))}
              {diff.data.missing_hosts.slice(0, 3).map((h: any) => (
                <div key={h.ip} className="mono text-red-400">− {h.ip} {h.hostname || ''}</div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
