import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useEngagements,
  useCreateEngagement,
  useDeleteEngagement,
  useUpdateEngagement,
  useCreateDeletionRequest,
} from '../hooks/useApi'
import { StatCard, Chip, DotPill, ActionButton, PrimaryButton, SkeletonCard } from '../components/ui'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { Engagement } from '../lib/types'
import { isAdmin, canMutate, currentUserId } from '../lib/auth'
import { useToast } from '../components/Toaster'
import { errText } from '../lib/errors'

const inputCls =
  'w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500'

function EngagementAvatar({ name }: { name: string }) {
  return (
    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500/30 to-fuchsia-500/20 text-sm font-bold text-indigo-200 ring-1 ring-white/10">
      {(name[0] || '?').toUpperCase()}
    </div>
  )
}

function EngagementCard({ e, editing, editForm, onStartEdit, onCancelEdit, onEditChange, onSaveEdit, onDeleteRequest, canEdit, canArchive, canDelete, onToggleArchive }: {
  e: Engagement
  editing: boolean
  editForm: { client_name: string; engagement_name: string; authorized_scope: string; start_date: string; end_date: string }
  onStartEdit: () => void
  onCancelEdit: () => void
  onEditChange: (patch: Partial<typeof editForm>) => void
  onSaveEdit: () => void
  onDeleteRequest: () => void
  canEdit: boolean
  canArchive: boolean
  canDelete: boolean
  onToggleArchive: () => void
}) {
  const archived = e.status === 'archived'
  const navigate = useNavigate()
  return (
    <div
      onClick={() => navigate(`/engagements/${e.id}`)}
      className={`overflow-hidden rounded-xl border bg-gray-900 transition-colors hover:border-gray-700 cursor-pointer ${archived ? 'border-gray-800/60 opacity-90' : 'border-gray-800'}`}
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5">
        <EngagementAvatar name={e.engagement_name} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span
              className="truncate text-base font-semibold text-white transition-colors hover:text-indigo-300"
            >
              {e.engagement_name}
            </span>
            <DotPill tone={archived ? 'offline' : 'online'}>{e.status}</DotPill>
            {archived && canEdit && (
              <span className="text-[11px] text-gray-500">read-only — restore to make changes</span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-gray-500">
            Client <span className="text-gray-300">{e.client_name}</span>
            {e.start_date || e.end_date ? (
              <span className="ml-2">
                {[e.start_date, e.end_date].filter(Boolean).join(' → ') || ''}
              </span>
            ) : null}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[12px] font-semibold uppercase tracking-wider text-gray-600">Scope</span>
            {e.authorized_scope.map((s) => (
              <Chip key={s} tone="indigo">{s}</Chip>
            ))}
          </div>
        </div>
        {canEdit && (
          <div className="flex flex-wrap items-center gap-2" onClick={(e) => e.stopPropagation()}>
            {!archived && (
              <ActionButton onClick={editing ? onCancelEdit : onStartEdit} tone="ghost">
                {editing ? 'Cancel' : 'Edit'}
              </ActionButton>
            )}
            {canArchive && (
              <ActionButton onClick={onToggleArchive} tone={archived ? 'primary' : 'reset'}>
                {archived ? 'Restore' : 'Archive'}
              </ActionButton>
            )}
            {canDelete && (
              <ActionButton onClick={onDeleteRequest} tone="danger">
                Delete
              </ActionButton>
            )}
          </div>
        )}
      </div>

      {editing && !archived && (
        <div className="border-t border-gray-800 bg-gray-950/40 px-5 py-4" onClick={(e) => e.stopPropagation()}>
          <div className="mb-3">
            <span className="text-sm font-semibold text-gray-200">Edit Engagement</span>
            <span className="mt-0.5 block text-xs text-gray-500">
              Changes apply immediately to this engagement.
            </span>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-gray-500">Client Name *</label>
              <input
                value={editForm.client_name}
                onChange={(e) => onEditChange({ client_name: e.target.value })}
                className={inputCls}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">Engagement Name *</label>
              <input
                value={editForm.engagement_name}
                onChange={(e) => onEditChange({ engagement_name: e.target.value })}
                className={inputCls}
              />
            </div>
            <div className="md:col-span-2">
              <label className="mb-1 block text-xs text-gray-500">Authorized Scope (CIDR list, comma-separated) *</label>
              <input
                value={editForm.authorized_scope}
                onChange={(e) => onEditChange({ authorized_scope: e.target.value })}
                className={inputCls + ' mono'}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">Start Date</label>
              <input
                type="date"
                value={editForm.start_date}
                onChange={(e) => onEditChange({ start_date: e.target.value })}
                className={inputCls}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">End Date</label>
              <input
                type="date"
                value={editForm.end_date}
                onChange={(e) => onEditChange({ end_date: e.target.value })}
                className={inputCls}
              />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2">
            <PrimaryButton onClick={onSaveEdit} loading={false}>Save Changes</PrimaryButton>
            <ActionButton onClick={onCancelEdit} tone="ghost">Cancel</ActionButton>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Engagements() {
  const toast = useToast()
  const { data: engagements, isLoading } = useEngagements()
  const createEngagement = useCreateEngagement()
  const deleteEngagement = useDeleteEngagement()
  const updateEngagement = useUpdateEngagement()
  const createDeletionRequest = useCreateDeletionRequest()
  const [deleteTarget, setDeleteTarget] = useState<Engagement | null>(null)
  const admin = isAdmin()
  const canEdit = canMutate()
  const myId = currentUserId()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    client_name: '',
    engagement_name: '',
    authorized_scope: '',
    start_date: '',
    end_date: '',
  })

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState({
    client_name: '',
    engagement_name: '',
    authorized_scope: '',
    start_date: '',
    end_date: '',
  })

  const [deleteRequestFor, setDeleteRequestFor] = useState<Engagement | null>(null)
  const [deleteReason, setDeleteReason] = useState('')

  const startEdit = (e: Engagement) => {
    setEditForm({
      client_name: e.client_name,
      engagement_name: e.engagement_name,
      authorized_scope: e.authorized_scope.join(', '),
      start_date: e.start_date || '',
      end_date: e.end_date || '',
    })
    setEditingId(e.id)
  }

  const handleUpdate = async (id: string) => {
    const scope = editForm.authorized_scope.split(',').map((s) => s.trim()).filter(Boolean)
    try {
      await updateEngagement.mutateAsync({
        id,
        client_name: editForm.client_name,
        engagement_name: editForm.engagement_name,
        authorized_scope: scope,
        start_date: editForm.start_date || null,
        end_date: editForm.end_date || null,
      })
      setEditingId(null)
      toast.success('Engagement updated')
    } catch (err: any) {
      toast.error(errText(err, 'Failed to update engagement'))
    }
  }

  const handleToggleArchive = async (e: Engagement) => {
    const archive = e.status === 'archived' ? false : true
    try {
      await updateEngagement.mutateAsync({ id: e.id, status: e.status === 'archived' ? 'active' : 'archived' })
      setEditingId(null)
      toast.success(archive ? 'Engagement archived' : 'Engagement restored')
    } catch (err: any) {
      toast.error(errText(err, archive ? 'Could not archive engagement' : 'Could not restore engagement'))
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const scope = form.authorized_scope.split(',').map((s) => s.trim()).filter(Boolean)
    try {
      await createEngagement.mutateAsync({
        client_name: form.client_name,
        engagement_name: form.engagement_name,
        authorized_scope: scope,
        start_date: form.start_date || null,
        end_date: form.end_date || null,
      })
      setShowForm(false)
      setForm({ client_name: '', engagement_name: '', authorized_scope: '', start_date: '', end_date: '' })
      toast.success('Engagement created')
    } catch (err: any) {
      toast.error(errText(err, 'Failed to create engagement'))
    }
  }

  const handleDelete = async (id: string) => {
    setDeleteTarget(null)
    try {
      await deleteEngagement.mutateAsync(id)
      toast.success('Engagement deleted')
    } catch (err: any) {
      toast.error(errText(err, 'Could not delete engagement'))
    }
  }

  const submitDeleteRequest = async () => {
    if (!deleteRequestFor) return
    try {
      await createDeletionRequest.mutateAsync({
        target_type: 'engagement',
        target_id: deleteRequestFor.id,
        reason: deleteReason || undefined,
      })
      setDeleteRequestFor(null)
      setDeleteReason('')
      toast.success('Deletion request submitted for admin approval')
    } catch (err: any) {
      toast.error(errText(err, 'Could not submit deletion request'))
    }
  }

  const total = engagements?.length || 0
  const active = engagements?.filter((e) => e.status === 'active').length || 0
  const archived = total - active

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Engagements</h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-400">
            Client engagements and their scan history — define the authorized scope, then run
            scans against it.
          </p>
        </div>
        {canEdit && (
          <PrimaryButton onClick={() => setShowForm(!showForm)}>
            {showForm ? 'Close form' : '+ New Engagement'}
          </PrimaryButton>
        )}
      </div>

      <div className="mb-6 grid grid-cols-3 gap-4">
        <StatCard label="Total engagements" value={total} tone="text-white" />
        <StatCard label="Active" value={active} tone="text-emerald-400" />
        <StatCard label="Archived" value={archived} tone="text-gray-400" />
      </div>

      {showForm && canEdit && (
        <form onSubmit={handleCreate} className="mb-6 overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800/80 bg-gray-900/70 px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-200">New Engagement</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Create the client engagement that scans will report against.
            </p>
          </div>
          <div className="px-5 py-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-gray-500">Client Name *</label>
                <input
                  value={form.client_name}
                  onChange={(e) => setForm({ ...form, client_name: e.target.value })}
                  className={inputCls}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Engagement Name *</label>
                <input
                  value={form.engagement_name}
                  onChange={(e) => setForm({ ...form, engagement_name: e.target.value })}
                  className={inputCls}
                  required
                />
              </div>
              <div className="md:col-span-2">
                <label className="mb-1 block text-xs text-gray-500">Authorized Scope (CIDR list, comma-separated) *</label>
                <input
                  value={form.authorized_scope}
                  onChange={(e) => setForm({ ...form, authorized_scope: e.target.value })}
                  placeholder="10.0.0.0/24, 192.168.1.0/24"
                  className={inputCls + ' mono'}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Start Date</label>
                <input
                  type="date"
                  value={form.start_date}
                  onChange={(e) => setForm({ ...form, start_date: e.target.value })}
                  className={inputCls}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">End Date</label>
                <input
                  type="date"
                  value={form.end_date}
                  onChange={(e) => setForm({ ...form, end_date: e.target.value })}
                  className={inputCls}
                />
              </div>
            </div>
            <div className="mt-4 flex items-center gap-3">
              <button
                type="submit"
                disabled={createEngagement.isPending}
                className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {createEngagement.isPending ? 'Creating…' : 'Create Engagement'}
              </button>
              <span className="text-xs text-gray-500">the engagement can be edited later</span>
            </div>
          </div>
        </form>
      )}

      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Client engagements</span>
        {engagements?.length ? (
          <span className="text-[12px] text-gray-500">
            {admin ? 'admins delete directly (confirm dialog); archiving makes an engagement read-only'
              : canEdit ? 'deletion requests are queued for admin approval'
              : 'read-only access'}
          </span>
        ) : null}
      </div>

      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <SkeletonCard key={i} lines={3} />
          ))}
        </div>
      ) : engagements?.length ? (
        <div className="space-y-4">
          {engagements.map((e: Engagement) => (
            <EngagementCard
              key={e.id}
              e={e}
              editing={editingId === e.id}
              editForm={editForm}
              onStartEdit={() => startEdit(e)}
              onCancelEdit={() => setEditingId(null)}
              onEditChange={(patch) => setEditForm((f) => ({ ...f, ...patch }))}
              onSaveEdit={() => handleUpdate(e.id)}
              onDeleteRequest={() => setDeleteTarget(e)}
              canEdit={canEdit}
              canArchive={admin || e.created_by === myId}
              canDelete={admin}
              onToggleArchive={() => handleToggleArchive(e)}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-gray-700 px-6 py-16 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gray-800">
            <svg viewBox="0 0 24 24" className="h-7 w-7 text-indigo-400" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3v18M3 12h18" />
              <circle cx="12" cy="12" r="9" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-gray-200">No engagements yet</h3>
          <p className="mx-auto mt-1 max-w-md text-sm text-gray-500">
            Define the client and its authorized scope, then start a scan to build the asset inventory.
          </p>
          <ol className="mx-auto mt-5 flex max-w-2xl flex-col gap-2 text-left text-sm text-gray-400 sm:flex-row sm:gap-4">
            {[
              ['1', 'Create the engagement'],
              ['2', 'Open it and start a scan'],
              ['3', 'Review hosts, findings and the report'],
            ].map(([n, t]) => (
              <li key={n} className="flex items-center gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-indigo-600/40 text-xs font-bold text-indigo-200">{n}</span>
                {t}
              </li>
            ))}
          </ol>
          {canEdit && (
            <PrimaryButton onClick={() => setShowForm(true)} className="mt-6">New Engagement</PrimaryButton>
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!deleteTarget}
        title="Delete engagement permanently?"
        confirmLabel="Delete engagement"
        busy={deleteEngagement.isPending}
        onConfirm={() => deleteTarget && handleDelete(deleteTarget.id)}
        onCancel={() => setDeleteTarget(null)}
        message={
          <>
            <span className="font-semibold text-gray-200">"{deleteTarget?.engagement_name}"</span> and
            everything it contains will be permanently deleted — all scans, hosts, findings and
            the audit trail. This cannot be undone.
          </>
        }
      />

      {deleteRequestFor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-5">
            <h3 className="text-sm font-semibold text-gray-200">Request engagement deletion</h3>
            <p className="mt-1 text-xs text-gray-400">
              "{deleteRequestFor.engagement_name}" will be queued for an admin to review. Nothing is
              deleted until an admin approves.
            </p>
            <label className="mt-4 mb-1 block text-xs text-gray-500">Reason (recommended)</label>
            <textarea
              value={deleteReason}
              onChange={(e) => setDeleteReason(e.target.value)}
              rows={3}
              placeholder="Why should this engagement be removed?"
              className={inputCls}
            />
            <div className="mt-4 flex items-center justify-end gap-2">
              <ActionButton tone="ghost" onClick={() => { setDeleteRequestFor(null); setDeleteReason('') }}>
                Cancel
              </ActionButton>
              <PrimaryButton onClick={submitDeleteRequest} disabled={createDeletionRequest.isPending}>
                {createDeletionRequest.isPending ? 'Submitting…' : 'Submit request'}
              </PrimaryButton>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}