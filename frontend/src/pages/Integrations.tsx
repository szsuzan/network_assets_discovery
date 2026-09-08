import { useState } from 'react'
import {
  useWebhooks,
  useCreateWebhook,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
  type Webhook,
} from '../hooks/useApi'

const EVENTS = [
  { key: 'finding_created', label: 'Finding created' },
  { key: 'finding_updated', label: 'Finding updated (status/severity)' },
]

function StatusCell({ wh }: { wh: Webhook }) {
  if (!wh.last_triggered_at) return <span className="text-xs text-gray-500">Never triggered</span>
  if (wh.last_status && wh.last_status < 400) {
    return <span className="text-xs text-emerald-400">HTTP {wh.last_status}</span>
  }
  return (
    <span className="text-xs text-red-400" title={wh.last_error || ''}>
      {wh.last_status ? `HTTP ${wh.last_status}` : 'Failed'}: {(wh.last_error || '').slice(0, 60)}
    </span>
  )
}

export default function Integrations() {
  const { data: webhooks } = useWebhooks()
  const create = useCreateWebhook()
  const update = useUpdateWebhook()
  const remove = useDeleteWebhook()
  const test = useTestWebhook()

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', url: '', secret: '', events: EVENTS.map((e) => e.key) })

  const submit = () => {
    create.mutate(
      { name: form.name, url: form.url, secret: form.secret || undefined, events: form.events, enabled: true },
      { onSuccess: () => { setShowForm(false); setForm({ name: '', url: '', secret: '', events: EVENTS.map((e) => e.key) }) } }
    )
  }

  const toggleEvent = (key: string) => {
    setForm({
      ...form,
      events: form.events.includes(key)
        ? form.events.filter((e) => e !== key)
        : [...form.events, key],
    })
  }

  return (
    <div className="mx-auto max-w-3xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Integrations</h1>
          <p className="mt-1 text-sm text-gray-400">
            Forward finding lifecycle events to your ticketing/chat systems as signed HTTPS webhooks.
          </p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
        >
          {showForm ? 'Cancel' : '+ New webhook'}
        </button>
      </div>

      {showForm && (
        <div className="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-medium text-white">New webhook</h2>
          <div className="grid gap-3">
            <input
              placeholder="Name (e.g. Slack #sec-alerts)"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
            />
            <input
              placeholder="https://hooks.example.com/endpoint"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
            />
            <input
              placeholder="Shared secret (HMAC-SHA256 signing, optional)"
              value={form.secret}
              onChange={(e) => setForm({ ...form, secret: e.target.value })}
              className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
            />
          </div>
          <div className="mt-3 flex flex-wrap gap-4">
            {EVENTS.map((ev) => (
              <label key={ev.key} className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={form.events.includes(ev.key)}
                  onChange={() => toggleEvent(ev.key)}
                  className="h-4 w-4 rounded border-gray-600 bg-gray-800"
                />
                {ev.label}
              </label>
            ))}
          </div>
          <div className="mt-4 flex justify-end">
            <button
              onClick={submit}
              disabled={!form.name.trim() || !form.url.trim() || form.events.length === 0 || create.isPending}
              className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40"
            >
              Create webhook
            </button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {!webhooks?.length && (
          <div className="rounded-lg border border-gray-800 bg-gray-900 py-10 text-center text-sm text-gray-400">
            No webhooks configured. Create one to start receiving finding events.
          </div>
        )}
        {webhooks?.map((wh) => (
          <div key={wh.id} className="flex flex-wrap items-center gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={wh.enabled}
                onChange={() => update.mutate({ id: wh.id, data: { enabled: !wh.enabled } })}
                className="h-4 w-4 rounded border-gray-600 bg-gray-800"
              />
            </label>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-medium text-white">{wh.name}</span>
                <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase ${wh.enabled ? 'bg-emerald-900/40 text-emerald-300' : 'bg-gray-800 text-gray-500'}`}>
                  {wh.enabled ? 'enabled' : 'disabled'}
                </span>
              </div>
              <div className="mono truncate text-xs text-gray-500">{wh.url}</div>
              <div className="text-xs text-gray-500">
                {wh.events.map((e) => EVENTS.find((x) => x.key === e)?.label || e).join(' · ')}
              </div>
            </div>
            <StatusCell wh={wh} />
            <div className="flex items-center gap-2">
              <button
                onClick={() => test.mutate(wh.id)}
                disabled={test.isPending}
                className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-gray-500 disabled:opacity-40"
              >
                Test
              </button>
              <button
                onClick={() => remove.mutate(wh.id)}
                className="rounded border border-red-800 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/30"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}