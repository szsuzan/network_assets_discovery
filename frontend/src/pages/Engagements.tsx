import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useEngagements, useCreateEngagement, useDeleteEngagement } from '../hooks/useApi'
import { StatusBadge } from '../components/Badge'
import type { Engagement } from '../lib/types'

export default function Engagements() {
  const { data: engagements, isLoading } = useEngagements()
  const createEngagement = useCreateEngagement()
  const deleteEngagement = useDeleteEngagement()
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const isAdmin = localStorage.getItem('role') === 'admin'
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    client_name: '',
    engagement_name: '',
    authorized_scope: '',
    start_date: '',
    end_date: '',
  })

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const scope = form.authorized_scope.split(',').map((s) => s.trim()).filter(Boolean)
    await createEngagement.mutateAsync({
      client_name: form.client_name,
      engagement_name: form.engagement_name,
      authorized_scope: scope,
      start_date: form.start_date || null,
      end_date: form.end_date || null,
    })
    setShowForm(false)
    setForm({ client_name: '', engagement_name: '', authorized_scope: '', start_date: '', end_date: '' })
  }

  const handleDelete = async (id: string) => {
    setConfirmDelete(null)
    await deleteEngagement.mutateAsync(id)
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Engagements</h1>
          <p className="mt-1 text-sm text-gray-400">Client engagements and their scan history</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          {showForm ? 'Cancel' : '+ New Engagement'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="mb-6 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm text-gray-300">Client Name *</label>
              <input
                value={form.client_name}
                onChange={(e) => setForm({ ...form, client_name: e.target.value })}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Engagement Name *</label>
              <input
                value={form.engagement_name}
                onChange={(e) => setForm({ ...form, engagement_name: e.target.value })}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-gray-300">Authorized Scope (CIDR list, comma-separated)</label>
              <input
                value={form.authorized_scope}
                onChange={(e) => setForm({ ...form, authorized_scope: e.target.value })}
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
                  value={form.start_date}
                  onChange={(e) => setForm({ ...form, start_date: e.target.value })}
                  className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm text-gray-300">End Date</label>
                <input
                  type="date"
                  value={form.end_date}
                  onChange={(e) => setForm({ ...form, end_date: e.target.value })}
                  className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white"
                />
              </div>
            </div>
          </div>
          <button
            type="submit"
            disabled={createEngagement.isPending}
            className="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {createEngagement.isPending ? 'Creating...' : 'Create Engagement'}
          </button>
        </form>
      )}

      {isLoading ? (
        <div className="py-12 text-center text-gray-400">Loading engagements...</div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-gray-400">
              <tr>
                <th className="px-4 py-3 font-medium">Client</th>
                <th className="px-4 py-3 font-medium">Engagement</th>
                <th className="px-4 py-3 font-medium">Scope</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Date Range</th>
                <th className="px-4 py-3 font-medium">Created</th>
                {isAdmin && <th className="px-4 py-3 font-medium text-right">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {engagements?.map((e: Engagement) => (
                <tr key={e.id} className="bg-gray-900/50 hover:bg-gray-800/50">
                  <td className="px-4 py-3 font-medium text-white">{e.client_name}</td>
                  <td className="px-4 py-3">
                    <Link to={`/engagements/${e.id}`} className="text-blue-400 hover:underline">
                      {e.engagement_name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 mono text-gray-300">{e.authorized_scope.join(', ')}</td>
                  <td className="px-4 py-3"><StatusBadge status={e.status} /></td>
                  <td className="px-4 py-3 text-gray-300">
                    {e.start_date && e.end_date ? `${e.start_date} → ${e.end_date}` : e.start_date || '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{new Date(e.created_at).toLocaleDateString()}</td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-right">
                      {confirmDelete === e.id ? (
                        <span className="inline-flex gap-2">
                          <button
                            onClick={() => handleDelete(e.id)}
                            disabled={deleteEngagement.isPending}
                            className="rounded bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setConfirmDelete(null)}
                            className="rounded bg-gray-700 px-3 py-1 text-xs font-medium text-white hover:bg-gray-600"
                          >
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <button
                          onClick={() => setConfirmDelete(e.id)}
                          disabled={deleteEngagement.isPending}
                          className="rounded border border-red-800 px-3 py-1 text-xs font-medium text-red-400 hover:bg-red-950 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
              {!engagements?.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-gray-400">
                    No engagements yet. Create your first one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
