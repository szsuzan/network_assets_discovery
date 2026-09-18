import { useState } from 'react'
import {
  useWebhooks,
  useCreateWebhook,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
  type Webhook,
} from '../hooks/useApi'
import { StatCard, Chip, DotPill, ActionButton, PrimaryButton } from '../components/ui'

const EVENTS = [
  { key: 'finding_created', label: 'Finding created' },
  { key: 'finding_updated', label: 'Finding updated (status/severity)' },
  { key: 'host_discovered', label: 'Host discovered (new live host)' },
  { key: 'scan_completed', label: 'Scan / re-verify completed' },
]

const EVENT_TONE: Record<string, 'gray' | 'indigo' | 'emerald' | 'amber'> = {
  finding_created: 'indigo',
  finding_updated: 'emerald',
  host_discovered: 'amber',
  scan_completed: 'gray',
}

function WebhookAvatar({ name }: { name: string }) {
  return (
    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500/30 to-fuchsia-500/20 text-sm font-bold text-indigo-200 ring-1 ring-white/10">
      {(name[0] || '?').toUpperCase()}
    </div>
  )
}

function EventChips({ events }: { events: string[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {events.map((e) => (
        <Chip key={e} tone={EVENT_TONE[e] || 'gray'}>
          {EVENTS.find((x) => x.key === e)?.label || e}
        </Chip>
      ))}
    </div>
  )
}

function LastDelivery({ wh }: { wh: Webhook }) {
  if (!wh.last_triggered_at) {
    return (
      <div className="text-xs text-gray-500">
        never triggered
        <div className="text-[12px] text-gray-600">no delivery recorded yet</div>
      </div>
    )
  }
  const ok = !!wh.last_status && wh.last_status < 400
  return (
    <div className="text-xs">
      <div className={ok ? 'font-medium text-emerald-300' : 'font-medium text-red-300'}>
        {ok ? `HTTP ${wh.last_status}` : wh.last_status ? `HTTP ${wh.last_status}` : 'Failed (no response)'}
      </div>
      <div className="text-[12px] text-gray-500">{new Date(wh.last_triggered_at).toLocaleString()}</div>
      {wh.last_error ? (
        <div className="mt-0.5 max-w-[220px] break-words text-[12px] text-red-400/80" title={wh.last_error}>
          {wh.last_error.slice(0, 80)}
        </div>
      ) : null}
    </div>
  )
}

function EventPicker({ selected, onToggle }: { selected: string[]; onToggle: (k: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2">
      {EVENTS.map((ev) => {
        const on = selected.includes(ev.key)
        return (
          <button
            key={ev.key}
            type="button"
            onClick={() => onToggle(ev.key)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
              on
                ? 'border-indigo-600 bg-indigo-500/15 text-indigo-200'
                : 'border-gray-700 bg-gray-800/60 text-gray-400 hover:border-gray-600'
            }`}
          >
            <span className={`flex h-3.5 w-3.5 items-center justify-center rounded border ${
              on ? 'border-indigo-400 bg-indigo-500 text-white' : 'border-gray-600'
            }`}>
              {on && (
                <svg viewBox="0 0 12 12" className="h-2.5 w-2.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M2 6l3 3 5-5" />
                </svg>
              )}
            </span>
            {ev.label}
          </button>
        )
      })}
    </div>
  )
}

function WebhookCard({ wh, onToggleEnabled, onDelete, onTest, testPending }: {
  wh: Webhook
  onToggleEnabled: () => void
  onDelete: () => void
  onTest: () => void
  testPending: boolean
}) {
  const [deleteArmed, setDeleteArmed] = useState(false)
  const doDelete = () => {
    if (deleteArmed) {
      onDelete()
      setDeleteArmed(false)
    } else {
      setDeleteArmed(true)
      setTimeout(() => setDeleteArmed(false), 3000)
    }
  }
  return (
    <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900 transition-colors hover:border-gray-700">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5">
        <WebhookAvatar name={wh.name} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="truncate text-base font-semibold text-white">{wh.name}</span>
            <DotPill tone={wh.enabled ? 'online' : 'disabled'}>{wh.enabled ? 'enabled' : 'disabled'}</DotPill>
            {wh.secret ? <Chip tone="indigo">HMAC signed</Chip> : <Chip tone="amber">unsigned</Chip>}
          </div>
          <div className="mt-0.5 truncate mono text-xs text-gray-500">{wh.url}</div>
          <div className="mt-1.5"><EventChips events={wh.events} /></div>
        </div>
        <div className="min-w-[150px]"><LastDelivery wh={wh} /></div>
        <div className="flex flex-wrap items-center gap-2">
          <ActionButton onClick={onTest} disabled={testPending}>
            {testPending ? 'Testing…' : 'Test delivery'}
          </ActionButton>
          <ActionButton onClick={onToggleEnabled} tone="ghost">
            {wh.enabled ? 'Disable' : 'Enable'}
          </ActionButton>
          <ActionButton onClick={doDelete} tone={deleteArmed ? 'confirm' : 'danger'}>
            {deleteArmed ? 'Confirm?' : 'Delete'}
          </ActionButton>
        </div>
      </div>
    </div>
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
      {
        onSuccess: () => {
          setShowForm(false)
          setForm({ name: '', url: '', secret: '', events: EVENTS.map((e) => e.key) })
        },
      },
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

  const total = webhooks?.length || 0
  const enabled = webhooks?.filter((w) => w.enabled).length || 0
  const signed = webhooks?.filter((w) => w.secret).length || 0

  const inputCls =
    'w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500'

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Integrations</h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-400">
            Forward finding and scan lifecycle events to your ticketing / chat systems as signed
            HTTPS webhooks.
          </p>
        </div>
        <PrimaryButton onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Close form' : '+ New webhook'}
        </PrimaryButton>
      </div>

      <div className="mb-6 grid grid-cols-3 gap-4">
        <StatCard label="Total webhooks" value={total} tone="text-white" />
        <StatCard label="Enabled" value={enabled} tone="text-emerald-400" />
        <StatCard label="HMAC signed" value={signed} tone="text-indigo-400" />
      </div>

      {showForm && (
        <div className="mb-6 rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-1">
            <h2 className="text-sm font-semibold text-gray-200">New webhook</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Point this at any HTTPS endpoint that can accept a POST JSON payload.
            </p>
          </div>
          <div className="mt-4 grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-gray-500">Name (unique, e.g. Slack #sec-alerts)</label>
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="team-alerts"
                  className={inputCls}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Shared secret (optional — enables HMAC-SHA256 signing)</label>
                <input
                  value={form.secret}
                  onChange={(e) => setForm({ ...form, secret: e.target.value })}
                  placeholder="leave empty to skip signing"
                  className={inputCls + ' mono'}
                />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">Endpoint URL</label>
              <input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="https://hooks.example.com/endpoint"
                className={inputCls + ' mono'}
              />
            </div>
          </div>

          <div className="mt-4">
            <label className="mb-2 block text-xs text-gray-500">Events to subscribe to</label>
            <EventPicker selected={form.events} onToggle={toggleEvent} />
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <span className="max-w-lg text-[12px] leading-relaxed text-gray-500">
              Every delivery is POSTed as JSON with a{' '}
              <code className="text-gray-400">X-Asset-Discovery-Event</code> header. With a secret,
              an <code className="text-gray-400">X-Asset-Discovery-Signature</code> header holds{' '}
              <code className="text-gray-400">sha256=HMAC-SHA256(body)</code> so receivers can
              verify authenticity.
            </span>
            <div className="flex items-center gap-2">
              <ActionButton onClick={() => setShowForm(false)} tone="ghost">Cancel</ActionButton>
              <PrimaryButton
                onClick={submit}
                disabled={!form.name.trim() || !form.url.trim() || form.events.length === 0 || create.isPending}
              >
                {create.isPending ? 'Creating…' : 'Create webhook'}
              </PrimaryButton>
            </div>
          </div>
        </div>
      )}

      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Configured webhooks</span>
        {webhooks?.length ? <span className="text-[12px] text-gray-500">delete requires a two-step confirm</span> : null}
      </div>

      {webhooks?.length ? (
        <div className="space-y-4">
          {webhooks.map((wh) => (
            <WebhookCard
              key={wh.id}
              wh={wh}
              testPending={test.isPending}
              onTest={() => test.mutate(wh.id)}
              onToggleEnabled={() => update.mutate({ id: wh.id, data: { enabled: !wh.enabled } })}
              onDelete={() => remove.mutate(wh.id)}
            />
          ))}
        </div>
      ) : (
        !showForm && (
          <div className="rounded-xl border border-dashed border-gray-700 px-6 py-14 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gray-800">
              <svg viewBox="0 0 24 24" className="h-7 w-7 text-indigo-400" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-gray-200">No webhooks configured</h3>
            <p className="mx-auto mt-1 max-w-md text-sm text-gray-500">
              Create one to start receiving finding, host-discovery and scan-completion events as
              signed HTTPS deliveries.
            </p>
            <PrimaryButton onClick={() => setShowForm(true)} className="mt-6">New webhook</PrimaryButton>
          </div>
        )
      )}

      <div className="mt-8 grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-4">
          <div className="text-xs font-semibold text-gray-200">Verifying a delivery</div>
          <p className="mt-1 text-[12px] leading-relaxed text-gray-500">
            If a secret was configured, recompute <code className="text-gray-400">sha256=HMAC-SHA256</code>{' '}
            over the raw request body using the secret and compare with the{' '}
            <code className="text-gray-400">X-Asset-Discovery-Signature</code> header.
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-4">
          <div className="text-xs font-semibold text-gray-200">When events fire</div>
          <p className="mt-1 text-[12px] leading-relaxed text-gray-500">
            <code className="text-gray-400">host_discovered</code> fires for each new live host,
            <code className="text-gray-400"> scan_completed</code> once per finished scan or
            re-verify, and finding events on creation or status/severity changes.
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-4">
          <div className="text-xs font-semibold text-gray-200">Payload shape</div>
          <p className="mt-1 text-[12px] leading-relaxed text-gray-500">
            Finding events carry <code className="text-gray-400">{'{ finding, host, scan, engagement }'}</code>
            (updated also adds <code className="text-gray-400">changes[]</code>), host discovery carries{' '}
            <code className="text-gray-400">{'{ host, scan, engagement }'}</code>, and scan completion adds a{' '}
            <code className="text-gray-400">summary</code> with up-host and open-port counts.
          </p>
        </div>
      </div>
    </div>
  )
}