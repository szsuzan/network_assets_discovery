import { useState } from 'react'
import {
  useUsers,
  useCreateUser,
  useUpdateUser,
  useResetUserPassword,
  useDeletionRequests,
  useApproveDeletionRequest,
  useRejectDeletionRequest,
} from '../hooks/useApi'
import { Chip, DotPill, ActionButton, PrimaryButton } from '../components/ui'
import { USER_ROLES, DELETION_REQUEST_LABELS } from '../lib/types'
import { currentUserId } from '../lib/auth'

const inputCls =
  'w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500'

const ROLE_HELP: Record<string, string> = {
  admin: 'Full control: manage users, delete anything, approve deletion requests.',
  pentester: 'Create and run engagements/scans; deletions require admin approval.',
  viewer: 'Read-only access to engagements, scans, hosts and findings.',
}

export default function Administration() {
  const { data: users, isLoading: usersLoading } = useUsers()
  const { data: requests, isLoading: requestsLoading } = useDeletionRequests()
  const createUser = useCreateUser()
  const updateUser = useUpdateUser()
  const resetPassword = useResetUserPassword()
  const approveRequest = useApproveDeletionRequest()
  const rejectRequest = useRejectDeletionRequest()
  const selfId = currentUserId()

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ email: '', password: '', role: 'pentester' })
  const [formError, setFormError] = useState<string | null>(null)
  const [formOk, setFormOk] = useState<string | null>(null)

  const [resetUser, setResetUser] = useState<string | null>(null)
  const [resetPw, setResetPw] = useState('')
  const [resetError, setResetError] = useState<string | null>(null)
  const [resetOk, setResetOk] = useState<string | null>(null)

  const [rejectTarget, setRejectTarget] = useState<string | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormError(null)
    setFormOk(null)
    if (form.password.length < 10) {
      setFormError('Password must be at least 10 characters')
      return
    }
    try {
      const created = await createUser.mutateAsync({
        email: form.email.trim(),
        password: form.password,
        role: form.role,
      })
      setForm({ email: '', password: '', role: 'pentester' })
      setShowForm(false)
      setFormOk(`Created ${created.email} — they must set a password on first login.`)
    } catch (err: any) {
      setFormError(err?.response?.data?.detail?.toString?.() || 'Failed to create user')
    }
  }

  const handleRoleChange = async (id: string, role: string) => {
    setActionError(null)
    try {
      await updateUser.mutateAsync({ id, data: { role } })
    } catch (err: any) {
      setActionError(err?.response?.data?.detail?.toString?.() || 'Could not change role')
    }
  }

  const handleActiveToggle = async (id: string, active: boolean) => {
    setActionError(null)
    try {
      await updateUser.mutateAsync({ id, data: { active } })
    } catch (err: any) {
      setActionError(err?.response?.data?.detail?.toString?.() || 'Could not update account')
    }
  }

  const handleReset = async (id: string) => {
    setResetError(null)
    setResetOk(null)
    if (resetPw.length < 10) {
      setResetError('Password must be at least 10 characters')
      return
    }
    try {
      await resetPassword.mutateAsync({ id, password: resetPw })
      setResetPw('')
      setResetUser(null)
      setResetOk('Password reset — the user must change it on next login and all old sessions were signed out.')
    } catch (err: any) {
      setResetError(err?.response?.data?.detail?.toString?.() || 'Failed to reset password')
    }
  }

  const handleApprove = async (id: string) => {
    setActionError(null)
    try {
      await approveRequest.mutateAsync(id)
    } catch (err: any) {
      setActionError(err?.response?.data?.detail?.toString?.() || 'Could not approve request')
    }
  }

  const handleReject = async (id: string) => {
    try {
      await rejectRequest.mutateAsync({ id, reason: rejectReason || undefined })
      setRejectTarget(null)
      setRejectReason('')
    } catch (err: any) {
      setActionError(err?.response?.data?.detail?.toString?.() || 'Could not reject request')
    }
  }

  const pending = requests?.filter((r) => r.status === 'pending') ?? []
  const resolved = requests?.filter((r) => r.status !== 'pending') ?? []

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Administration</h1>
        <p className="mt-1 max-w-3xl text-sm text-gray-400">
          Role-based access control — manage users and permissions, and review deletion requests
          from pentesters for approval.
        </p>
      </div>

      {actionError && (
        <div className="mb-4 rounded-md border border-red-800/60 bg-red-950/30 px-3 py-2 text-sm text-red-400">
          {actionError}
        </div>
      )}
      {formOk && (
        <div className="mb-4 rounded-md border border-emerald-800/60 bg-emerald-950/30 px-3 py-2 text-sm text-emerald-400">
          {formOk}
        </div>
      )}
      {resetOk && (
        <div className="mb-4 rounded-md border border-emerald-800/60 bg-emerald-950/30 px-3 py-2 text-sm text-emerald-400">
          {resetOk}
        </div>
      )}

      <section className="mb-8 overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 px-5 py-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Users &amp; roles</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Passwords are stored as salted bcrypt hashes only. Role changes apply immediately.
            </p>
          </div>
          <PrimaryButton onClick={() => setShowForm(!showForm)}>
            {showForm ? 'Close form' : '+ New User'}
          </PrimaryButton>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="border-b border-gray-800 bg-gray-950/40 px-5 py-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <label className="mb-1 block text-xs text-gray-500">Email / username *</label>
                <input
                  type="text"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className={inputCls}
                  placeholder="analyst (or analyst@company.com)"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Temporary password *</label>
                <input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className={inputCls}
                  placeholder="min 10 characters"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Role *</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                  className={inputCls}
                >
                  {USER_ROLES.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
                <p className="mt-1 text-[11px] text-gray-500">{ROLE_HELP[form.role]}</p>
              </div>
            </div>
            {formError && (
              <p className="mt-3 whitespace-pre-line text-sm text-red-400">{formError}</p>
            )}
            <div className="mt-4 flex items-center gap-3">
              <button
                type="submit"
                disabled={createUser.isPending}
                className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:opacity-50"
              >
                {createUser.isPending ? 'Creating…' : 'Create user'}
              </button>
              <span className="text-xs text-gray-500">
                The user must change this password at first login.
              </span>
            </div>
          </form>
        )}

        {usersLoading ? (
          <div className="px-5 py-8 text-center text-sm text-gray-400">Loading users...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-[11px] uppercase tracking-wider text-gray-500">
                  <th className="px-5 py-2.5 font-medium">User</th>
                  <th className="px-3 py-2.5 font-medium">Role</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Action</th>
                  <th className="px-5 py-2.5 font-medium">Reset password</th>
                </tr>
              </thead>
              <tbody>
                {users?.map((u) => {
                  const isSelf = u.id === selfId
                  return (
                    <tr key={u.id} className="border-b border-gray-800/60 last:border-0">
                      <td className="px-5 py-2.5">
                        <span className="font-medium text-gray-200">{u.email}</span>
                        {isSelf && <Chip tone="indigo">you</Chip>}
                        {u.must_change_password && (
                          <span className="ml-1 text-[11px] text-amber-400">must change password</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <select
                          value={u.role}
                          disabled={isSelf}
                          onChange={(e) => handleRoleChange(u.id, e.target.value)}
                          className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white disabled:opacity-50"
                          title={ROLE_HELP[u.role]}
                        >
                          {USER_ROLES.map((r) => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      </td>
                      <td className="px-3 py-2.5">
                        {u.active ? (
                          <DotPill tone="online">enabled</DotPill>
                        ) : (
                          <DotPill tone="disabled">disabled</DotPill>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <ActionButton
                          tone={u.active ? 'reset' : 'primary'}
                          disabled={isSelf}
                          onClick={() => handleActiveToggle(u.id, !u.active)}
                        >
                          {u.active ? 'Disable' : 'Enable'}
                        </ActionButton>
                      </td>
                      <td className="px-5 py-2.5">
                        {resetUser === u.id ? (
                          <div className="flex items-center gap-2">
                            <input
                              type="password"
                              value={resetPw}
                              onChange={(e) => setResetPw(e.target.value)}
                              placeholder="new password (min 10 chars)"
                              className="w-48 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white"
                            />
                            <ActionButton tone="confirm" onClick={() => handleReset(u.id)}>Save</ActionButton>
                            <ActionButton tone="ghost" onClick={() => { setResetUser(null); setResetPw(''); setResetError(null) }}>Cancel</ActionButton>
                          </div>
                        ) : (
                          <ActionButton tone="ghost" onClick={() => { setResetUser(u.id); setResetError(null); setResetOk(null) }}>
                            Reset…
                          </ActionButton>
                        )}
                        {resetUser === u.id && resetError && (
                          <span className="ml-2 text-xs text-red-400">{resetError}</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-gray-200">Deletion approvals</h2>
          <p className="mt-0.5 text-xs text-gray-500">
            Pentesters request data deletion here; approving permanently deletes it.
          </p>
        </div>

        {requestsLoading ? (
          <div className="px-5 py-8 text-center text-sm text-gray-400">Loading requests...</div>
        ) : pending.length === 0 && resolved.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-gray-500">
            No deletion requests yet.
          </div>
        ) : (
          <div className="divide-y divide-gray-800/60">
            {pending.length > 0 && (
              <div className="px-5 py-2 text-[11px] font-semibold uppercase tracking-wider text-amber-400">
                Pending — {pending.length}
              </div>
            )}
            {pending.map((r) => (
              <div key={r.id} className="px-5 py-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Chip tone={r.target_type === 'engagement' ? 'indigo' : 'amber'}>{r.target_type}</Chip>
                      <span className="font-medium text-gray-200">{r.target_label}</span>
                      {r.parent_label && (
                        <span className="text-xs text-gray-500">in {r.parent_label}</span>
                      )}
                    </div>
                    {r.reason && <p className="mt-1 text-xs text-gray-400">Reason: {r.reason}</p>}
                    <p className="mt-1 text-[11px] text-gray-500">
                      Requested {new Date(r.created_at).toLocaleString()} by{' '}
                      <span className="text-gray-300">{r.requested_by_email || 'unknown'}</span>
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {rejectTarget === r.id ? (
                      <>
                        <input
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          placeholder="why rejected? (optional)"
                          className="w-48 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white"
                        />
                        <ActionButton tone="confirm" onClick={() => handleReject(r.id)}>Reject</ActionButton>
                        <ActionButton tone="ghost" onClick={() => { setRejectTarget(null); setRejectReason('') }}>Cancel</ActionButton>
                      </>
                    ) : (
                      <>
                        <ActionButton tone="confirm" onClick={() => handleApprove(r.id)}>
                          {approveRequest.isPending ? 'Deleting…' : 'Approve & delete'}
                        </ActionButton>
                        <ActionButton tone="reset" onClick={() => setRejectTarget(r.id)}>Reject</ActionButton>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {resolved.length > 0 && (
              <div className="px-5 py-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                History — {resolved.length}
              </div>
            )}
            {resolved.map((r) => (
              <div key={r.id} className="px-5 py-2.5">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <Chip tone={r.status === 'approved' ? 'emerald' : 'gray'}>{DELETION_REQUEST_LABELS[r.status]}</Chip>
                  <span className="text-gray-300">{r.target_label}</span>
                  <span className="text-xs text-gray-500">
                    {r.status === 'approved' ? 'deleted' : 'kept'} · requested by{' '}
                    {r.requested_by_email || 'unknown'} · {new Date(r.created_at).toLocaleString()}
                  </span>
                </div>
                {r.resolver_comment && (
                  <p className="mt-0.5 pl-16 text-xs text-gray-500">{r.resolver_comment}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}