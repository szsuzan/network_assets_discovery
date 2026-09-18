import { Fragment, useEffect, useState } from 'react'
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
  useUpdateScan,
  useDeleteScan,
  useUpdateEngagement,
  useCreateDeletionRequest,
  useSettings,
} from '../hooks/useApi'
import { StatusBadge } from '../components/Badge'
import type { Scan } from '../lib/types'
import { isAdmin, canMutate, currentUserId } from '../lib/auth'

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
  const createDeletionRequest = useCreateDeletionRequest()
  const admin = isAdmin()
  const canEdit = canMutate()
  const myId = currentUserId()
  const isArchived = engagement?.status === 'archived'
  const readOnly = isArchived && !admin

  const [confirmDeleteScan, setConfirmDeleteScan] = useState<string | null>(null)
  const [deleteReqScan, setDeleteReqScan] = useState<Scan | null>(null)
  const [deleteScanReason, setDeleteScanReason] = useState('')
  const [deleteScanReqError, setDeleteScanReqError] = useState<string | null>(null)
  const [revertTarget, setRevertTarget] = useState<Scan | null>(null)
  const updateScan = useUpdateScan()
  const [editScanId, setEditScanId] = useState<string | null>(null)
  const [editScanForm, setEditScanForm] = useState({
    name: '',
    targets: '',
    profile: 'full',
    port_range: '1-10000',
    protocol: 'tcp',
  })
  const [editScanError, setEditScanError] = useState<string | null>(null)

  const openScanEdit = (s: Scan) => {
    setEditScanId(s.id)
    setEditScanForm({
      name: s.name || '',
      targets: s.targets.join(', '),
      profile: s.profile,
      port_range: s.port_range,
      protocol: s.protocol,
    })
    setEditScanError(null)
  }

  const saveScanEdit = async (s: Scan) => {
    setEditScanError(null)
    const finished = !ACTIVE_STATUSES.includes(s.status)
    const data: Record<string, any> = { name: editScanForm.name.trim() }
    if (finished) {
      data.targets = editScanForm.targets.split(/[\s,]+/).filter(Boolean)
      data.profile = editScanForm.profile
      data.port_range = editScanForm.port_range.split(' ').join('')
      data.protocol = editScanForm.protocol
    }
    try {
      await updateScan.mutateAsync({ scanId: s.id, data })
      setEditScanId(null)
    } catch (err: any) {
      setEditScanError(err?.response?.data?.detail || 'Failed to update scan')
    }
  }

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: '',
    targets: '',
    profile: 'full',
    port_range: '1-10000',
    protocol: 'tcp',
    mode: 'standard',
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

  const handleToggleArchive = async () => {
    setEditError(null)
    try {
      await updateEngagement.mutateAsync({
        id: engagementId!,
        status: isArchived ? 'active' : 'archived',
      })
      setEditing(false)
    } catch (err: any) {
      setEditError(err?.response?.data?.detail || 'Could not change archive state')
    }
  }

  const submitScanDeleteRequest = async () => {
    if (!deleteReqScan) return
    setDeleteScanReqError(null)
    try {
      await createDeletionRequest.mutateAsync({
        target_type: 'scan',
        target_id: deleteReqScan.id,
        reason: deleteScanReason || undefined,
      })
      setDeleteReqScan(null)
      setDeleteScanReason('')
    } catch (err: any) {
      setDeleteScanReqError(err?.response?.data?.detail || 'Could not submit deletion request')
    }
  }

  const renderScanDelete = (s: Scan) => {
    if (readOnly) return null
    if (admin) {
      if (confirmDeleteScan !== s.id) {
        return (
          <button
            onClick={() => setConfirmDeleteScan(s.id)}
            className="rounded border border-red-800 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
            title="Permanently delete this scan and all its hosts, findings, and audit trail"
          >
            Delete
          </button>
        )
      }
      return (
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
      )
    }
    return (
      <button
        onClick={() => setDeleteReqScan(s)}
        className="rounded border border-red-800 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
        title="Submit a deletion request for admin approval"
      >
        Request delete
      </button>
    )
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
        name: form.name.trim() || undefined,
        targets,
        profile: form.profile,
        port_range: form.port_range,
        protocol: form.protocol,
        mode: form.mode,
      })
      navigate(`/engagements/${engagementId}/scans/${scan.id}/live`)
    } catch (err: any) {
      setStartError(err?.response?.data?.detail || 'Failed to start scan')
    }
  }

  return (
    <div>
      <Link to="/" className="text-sm text-gray-400 hover:text-white">← Back to engagements</Link>

      {isArchived && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800/60 px-4 py-2.5 text-sm text-gray-300">
          <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0 text-gray-400" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20.59 13.41 13.42 20.6a2 2 0 0 1-2.83 0L4 14.17V4h10.17l7.42 7.42a2 2 0 0 1 0 2.83Z" />
            <path d="M7.5 7.5h.01" />
          </svg>
          <span>
            This engagement is <span className="font-semibold text-gray-200">archived</span>
            {admin ? ' — read-only for other users, but you can still restore or delete it.'
              : ' and read-only. Restore it to run scans or make changes.'}
          </span>
          {!admin && canEdit && (engagement?.created_by === myId) && (
            <button
              onClick={handleToggleArchive}
              className="ml-auto rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-700"
            >
              Restore
            </button>
          )}
        </div>
      )}

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
          {canEdit && !isArchived && (
            <button
              onClick={() => (editing ? setEditing(false) : startEdit())}
              className="rounded border border-blue-600 px-4 py-2 text-sm font-medium text-blue-400 hover:bg-blue-600/20"
            >
              {editing ? 'Cancel Edit' : 'Edit'}
            </button>
          )}
          {canEdit && (
            <button
              onClick={handleToggleArchive}
              className={`rounded px-4 py-2 text-sm font-medium ${isArchived ? 'bg-blue-600 text-white hover:bg-blue-700' : 'border border-amber-600 text-amber-400 hover:bg-amber-600/20'}`}
            >
              {isArchived ? 'Restore' : 'Archive'}
            </button>
          )}
          {canEdit && !isArchived && (
            <button
              onClick={() => setShowForm(!showForm)}
              className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
            >
              {showForm ? 'Cancel' : '+ New Scan'}
            </button>
          )}
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

      {showForm && !readOnly && (
        <form onSubmit={handleStart} className="mb-6 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm text-gray-300">Scan Name (optional)</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Q3 internal audit"
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
              />
              <p className="mt-1 text-xs text-gray-500">
                Shown in the scans list and comparison; defaults to the profile when empty.
              </p>
            </div>
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

          <div className="mt-4">
            <label className="mb-2 block text-sm text-gray-300">Report &amp; Findings</label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => { setTouched(true); setForm({ ...form, mode: 'standard' }) }}
                className={`rounded border p-3 text-left transition-colors ${
                  form.mode === 'standard'
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 hover:border-gray-500'
                }`}
              >
                <div className="font-medium text-white">Full (report + findings)</div>
                <div className="mt-1 text-xs text-gray-400">
                  Port scan + banner grab + OS/device type + risk findings + topology.
                </div>
              </button>
              <button
                type="button"
                onClick={() => { setTouched(true); setForm({ ...form, mode: 'discovery' }) }}
                className={`rounded border p-3 text-left transition-colors ${
                  form.mode === 'discovery'
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 hover:border-gray-500'
                }`}
              >
                <div className="font-medium text-white">Discovery only (no findings)</div>
                <div className="mt-1 text-xs text-gray-400">
                  Report generated (findings section empty). Host + port + banner + OS/device type still discovered.
                </div>
              </button>
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
                <th className="px-4 py-2 font-medium">Scan</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Targets</th>
                <th className="px-4 py-2 font-medium">Progress</th>
                <th className="px-4 py-2 font-medium">Started</th>
                <th className="px-4 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans?.map((s: Scan) => (
                <Fragment key={s.id}>
                <tr
                  onClick={() => navigate(`/engagements/${engagementId}/scans/${s.id}/live`)}
                  className="bg-gray-900/50 hover:bg-gray-800/50 cursor-pointer"
                >
                  <td className="px-4 py-3">
                    <span className="text-blue-400 capitalize">
                      {s.name || s.profile.replace('_', ' ')}
                    </span>
                    {s.name ? (
                      <span className="ml-2 text-xs capitalize text-gray-400">{s.profile.replace('_', ' ')}</span>
                    ) : null}
                    <span className="ml-2 rounded border border-gray-700 px-1.5 py-0.5 text-[10px] uppercase text-gray-400">{s.protocol}</span>
                    {s.mode === 'discovery' && (
                      <span className="ml-1.5 rounded border border-emerald-700 px-1.5 py-0.5 text-[10px] uppercase text-emerald-400">
                        discovery
                      </span>
                    )}
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
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    {readOnly ? (
                      <span className="text-xs text-gray-500">read-only</span>
                    ) : ACTIVE_STATUSES.includes(s.status) ? (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => openScanEdit(s)}
                          className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                          title="Edit scan details (name)"
                        >
                          Edit
                        </button>
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
                        {renderScanDelete(s)}
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => openScanEdit(s)}
                          className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                          title="Edit scan details (name, targets, profile, port range, protocol)"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => setRevertTarget(s)}
                          className="rounded border border-fuchsia-600 px-2 py-1 text-xs text-fuchsia-400 hover:bg-fuchsia-600/20"
                          title="Re-verify: re-check down hosts and sweep ports the initial scan didn't check. Merges into this report without duplication."
                        >
                          Re-verify
                        </button>
                        {renderScanDelete(s)}
                      </div>
                    )}
                  </td>
                </tr>
                {editScanId === s.id && (
                  <tr className="bg-gray-950">
                    <td colSpan={6} className="px-4 py-3">
                      <div className="rounded border border-gray-800 bg-gray-900 p-3">
                        <div className="grid grid-cols-2 gap-3 lg:grid-cols-8">
                          <div className="lg:col-span-3">
                            <label className="mb-1 block text-xs text-gray-400">Name</label>
                            <input
                              value={editScanForm.name}
                              onChange={(e) => setEditScanForm({ ...editScanForm, name: e.target.value })}
                              placeholder="Scan name (e.g. Q3 internal audit)"
                              className="w-full rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-white"
                            />
                          </div>
                          {!ACTIVE_STATUSES.includes(s.status) ? (
                            <>
                              <div className="lg:col-span-3">
                                <label className="mb-1 block text-xs text-gray-400">Targets (within scope)</label>
                                <input
                                  value={editScanForm.targets}
                                  onChange={(e) => setEditScanForm({ ...editScanForm, targets: e.target.value })}
                                  className="w-full rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-white mono"
                                />
                              </div>
                              <div>
                                <label className="mb-1 block text-xs text-gray-400">Profile</label>
                                <select
                                  value={editScanForm.profile}
                                  onChange={(e) => {
                                    setEditScanForm({ ...editScanForm, profile: e.target.value, port_range: PROFILE_PORT_RANGES[e.target.value] })
                                  }}
                                  className="w-full rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-white"
                                >
                                  {Object.keys(PROFILE_NOTES).map((p) => (
                                    <option key={p} value={p}>{p.replace('_', ' ')}</option>
                                  ))}
                                </select>
                              </div>
                              <div>
                                <label className="mb-1 block text-xs text-gray-400">Port range</label>
                                <input
                                  value={editScanForm.port_range}
                                  onChange={(e) => setEditScanForm({ ...editScanForm, port_range: e.target.value })}
                                  className="w-full rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-white mono"
                                />
                              </div>
                              <div>
                                <label className="mb-1 block text-xs text-gray-400">Protocol</label>
                                <select
                                  value={editScanForm.protocol}
                                  onChange={(e) => setEditScanForm({ ...editScanForm, protocol: e.target.value })}
                                  className="w-full rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-white"
                                >
                                  <option value="tcp">tcp</option>
                                  <option value="udp">udp</option>
                                </select>
                              </div>
                            </>
                          ) : (
                            <div className="lg:col-span-5 flex items-end pb-1 text-xs text-amber-400">
                              Targets, profile, port range and protocol are locked while the scan runs; you can still rename it.
                            </div>
                          )}
                        </div>
                        {editScanError && (
                          <p className="mt-2 whitespace-pre-line text-xs text-red-400">{editScanError}</p>
                        )}
                        <div className="mt-3 flex items-center gap-2">
                          <button
                            onClick={() => saveScanEdit(s)}
                            disabled={updateScan.isPending}
                            className="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                          >
                            {updateScan.isPending ? 'Saving...' : 'Save'}
                          </button>
                          <button
                            onClick={() => setEditScanId(null)}
                            className="rounded bg-gray-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-600"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
                </Fragment>
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
                  {s.name || s.profile} — {s.started_at ? new Date(s.started_at).toLocaleDateString() : ''}
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
                  {s.name || s.profile} — {s.started_at ? new Date(s.started_at).toLocaleDateString() : ''}
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

      {revertTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setRevertTarget(null)}
        >
          <div
            className="w-full max-w-md rounded-lg border border-gray-700 bg-gray-900 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-lg font-bold text-white">Re-verify scan</h2>
            <p className="mt-2 text-sm text-gray-400">
              Re-verify{' '}
              <span className="text-white">{revertTarget.name || revertTarget.profile.replace('_', ' ')}</span>?
              New hosts, open ports and findings are merged into the same report without duplicates.
            </p>
            <p className="mt-3 text-sm text-gray-400">Want to check for new hosts?</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <button
                disabled={reverifyScan.isPending}
                onClick={() => {
                  reverifyScan.mutate(
                    { scanId: revertTarget.id, check_new_hosts: false },
                    {
                      onSuccess: (scan) =>
                        navigate(`/engagements/${engagementId}/scans/${scan.id}/live`),
                      onSettled: () => setRevertTarget(null),
                    }
                  )
                }}
                className="rounded border border-fuchsia-600 px-4 py-2 text-sm font-medium text-fuchsia-400 hover:bg-fuchsia-600/20 disabled:opacity-50"
              >
                No — re-check existing hosts &amp; ports
              </button>
              <button
                disabled={reverifyScan.isPending}
                onClick={() => {
                  reverifyScan.mutate(
                    { scanId: revertTarget.id, check_new_hosts: true },
                    {
                      onSuccess: (scan) =>
                        navigate(`/engagements/${engagementId}/scans/${scan.id}/live`),
                      onSettled: () => setRevertTarget(null),
                    }
                  )
                }}
                className="rounded bg-fuchsia-600 px-4 py-2 text-sm font-medium text-white hover:bg-fuchsia-700 disabled:opacity-50"
              >
                Yes — also check for new hosts
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteReqScan && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setDeleteReqScan(null)}
        >
          <div
            className="w-full max-w-md rounded-lg border border-gray-700 bg-gray-900 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-lg font-bold text-white">Request scan deletion</h2>
            <p className="mt-2 text-sm text-gray-400">
              "<span className="text-white">{deleteReqScan.name || deleteReqScan.profile.replace('_', ' ')}</span>"
              will be queued for an admin to review. Nothing is deleted until an admin approves.
            </p>
            <label className="mt-4 mb-1 block text-xs text-gray-400">Reason (recommended)</label>
            <textarea
              value={deleteScanReason}
              onChange={(e) => setDeleteScanReason(e.target.value)}
              rows={3}
              placeholder="Why should this scan be removed?"
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
            />
            {deleteScanReqError && (
              <p className="mt-2 text-sm text-red-400">{deleteScanReqError}</p>
            )}
            <div className="mt-4 flex items-center justify-end gap-2">
              <button
                onClick={() => { setDeleteReqScan(null); setDeleteScanReason(''); setDeleteScanReqError(null) }}
                className="rounded bg-gray-700 px-4 py-2 text-sm font-medium text-white hover:bg-gray-600"
              >
                Cancel
              </button>
              <button
                onClick={submitScanDeleteRequest}
                disabled={createDeletionRequest.isPending}
                className="rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
              >
                {createDeletionRequest.isPending ? 'Submitting…' : 'Submit request'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
