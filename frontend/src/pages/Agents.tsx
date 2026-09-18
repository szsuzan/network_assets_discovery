import { useEffect, useState } from 'react'
import {
  useAgents,
  useCreateAgent,
  useDeleteAgent,
  useResetAgentKey,
  useAgentHealth,
  useRestartAgent,
  useUpdateAgent,
  type AgentHealth,
  type AgentInfo,
} from '../hooks/useApi'
import { StatCard, Chip, DotPill, ActionButton } from '../components/ui'

type Os = 'windows' | 'unix'

const OS_LABEL: Record<Os, string> = {
  windows: 'Windows',
  unix: 'Linux / macOS',
}

function origin(): string {
  return window.location.origin
}

function useNow(ms: number): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(t)
  }, [ms])
  return now
}

function relTime(iso: string | null, now: number): string {
  if (!iso) return 'never seen'
  const diff = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000))
  if (diff < 5) return 'just now'
  if (diff < 90) return `${diff}s ago`
  const m = Math.round(diff / 60)
  if (m < 60) return `${m}min ago`
  return `${Math.round(m / 60)}h ago`
}

function agentctlCmd(name: string, subnets: string, key: string | null, os: Os) {
  const py = os === 'windows' ? 'python' : 'python3'
  const sep = os === 'windows' ? '\\' : '/'
  const ctl = `agent${sep}agentctl.py`
  const keyArg = key ? ` --api-key ${key}` : ''
  const subArg = subnets ? ` --subnets ${subnets}` : ''
  const run = `${py} ${ctl} run --server ${origin()} --name ${name}${subArg}${keyArg}`
  const install = `${py} ${ctl} install`
  return {
    run,
    install,
    status: `${py} ${ctl} status`,
    repair: `${py} ${ctl} repair`,
    keySet: (k: string) => `${py} ${ctl} key --set ${k}`,
  }
}

type CopyButtonStyle = 'minimal' | 'solid'

function CopyButton({ value, tone = 'minimal' }: { value: string; tone?: CopyButtonStyle }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  if (tone === 'solid') {
    return (
      <button
        onClick={copy}
        className={
          'rounded-md px-3 py-1 text-xs font-medium transition-colors ' +
          (copied
            ? 'bg-emerald-600 text-white'
            : 'bg-white/10 text-gray-200 hover:bg-white/20')
        }
      >
        {copied ? 'Copied ✓' : 'Copy'}
      </button>
    )
  }
  return (
    <button
      onClick={copy}
      className="rounded px-1.5 py-0.5 text-[12px] text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200"
    >
      {copied ? <span className="text-emerald-400">copied ✓</span> : 'copy'}
    </button>
  )
}

function KeyBox({ value, label = 'Agent API key', hint }: {
  value: string
  label?: string
  hint?: string
}) {
  const [revealed, setRevealed] = useState(false)
  return (
    <div>
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <span className="text-[12px] font-semibold uppercase tracking-wider text-gray-500">{label}</span>
          {hint ? <span className="ml-2 text-[12px] text-gray-600">{hint}</span> : null}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setRevealed((v) => !v)}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-800 px-2 py-1 text-[12px] font-medium text-gray-300 transition-colors hover:bg-gray-700"
          >
            {revealed ? (
              <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
            {revealed ? 'Hide' : 'Show'}
          </button>
          <CopyButton value={value} />
        </div>
      </div>
      <code
        className={`block break-all rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-xs leading-relaxed text-gray-300 ${
          revealed ? '' : 'select-none blur-[5px]'
        }`}
      >
        {value}
      </code>
    </div>
  )
}

function CodeBlock({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-semibold uppercase tracking-wider text-gray-500">{label}</span>
        <CopyButton value={value} />
      </div>
      <pre className="mt-1 overflow-x-auto rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-xs leading-relaxed text-gray-300">
        {value}
      </pre>
    </div>
  )
}

function CommandColumn({ title, blocks, keyed }: {
  title: string
  blocks: { label: string; value: string }[]
  keyed?: (k: string) => string
}) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-xs font-semibold text-gray-200">{title}</span>
        <span className="text-[12px] text-gray-500">on the LAN machine</span>
      </div>
      <div className="space-y-3">
        {blocks.map((b) => (
          <CodeBlock key={b.label} label={b.label} value={b.value} />
        ))}
        {keyed && (
          <div className="rounded border border-orange-800/50 bg-orange-950/30 px-3 py-2 text-[12px] leading-relaxed text-orange-200/90">
            After rotating the key, sync it on the agent:{' '}
            <code className="break-all text-orange-100">{keyed('<NEW_KEY>')}</code>
          </div>
        )}
      </div>
    </div>
  )
}

function AgentAvatar({ name }: { name: string }) {
  return (
    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500/30 to-fuchsia-500/20 text-sm font-bold text-indigo-200 ring-1 ring-white/10">
      {(name[0] || '?').toUpperCase()}
    </div>
  )
}

function ActionRow({ onHealth, onToggleSetup, onRestart, onUpdate, onReset, onDelete, busy, setupOpen }: {
  onHealth: () => void
  onToggleSetup: () => void
  onRestart: () => void
  onUpdate: () => void
  onReset: () => void
  onDelete: () => void
  busy: boolean
  setupOpen: boolean
}) {
  const [deleteArmed, setDeleteArmed] = useState(false)
  const [resetArmed, setResetArmed] = useState(false)
  const [restartArmed, setRestartArmed] = useState(false)
  const [updateArmed, setUpdateArmed] = useState(false)

  const doDelete = () => {
    if (deleteArmed) {
      onDelete()
      setDeleteArmed(false)
    } else {
      setDeleteArmed(true)
      setTimeout(() => setDeleteArmed(false), 3000)
    }
  }
  const doReset = () => {
    if (resetArmed) {
      onReset()
      setResetArmed(false)
    } else {
      setResetArmed(true)
      setTimeout(() => setResetArmed(false), 3000)
    }
  }
  const doRestart = () => {
    if (restartArmed) {
      onRestart()
      setRestartArmed(false)
    } else {
      setRestartArmed(true)
      setTimeout(() => setRestartArmed(false), 3000)
    }
  }
  const doUpdate = () => {
    if (updateArmed) {
      onUpdate()
      setUpdateArmed(false)
    } else {
      setUpdateArmed(true)
      setTimeout(() => setUpdateArmed(false), 3000)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <ActionButton onClick={onHealth} disabled={busy}>
        {busy ? 'Checking…' : 'Health check'}
      </ActionButton>
      <ActionButton onClick={doUpdate} tone="primary">
        {updateArmed ? 'Confirm update?' : 'Update'}
      </ActionButton>
      <ActionButton onClick={doRestart} tone="primary">
        {restartArmed ? 'Confirm restart?' : 'Restart'}
      </ActionButton>
      <ActionButton onClick={onToggleSetup} tone="ghost">
        {setupOpen ? 'Hide setup' : 'Setup / repair'}
      </ActionButton>
      <ActionButton onClick={doReset} tone="reset">
        {resetArmed ? 'Confirm reset?' : 'Rotate key'}
      </ActionButton>
      <div className="mx-1 h-4 w-px bg-gray-800" />
      <ActionButton onClick={doDelete} tone={deleteArmed ? 'confirm' : 'danger'}>
        {deleteArmed ? 'Confirm remove?' : 'Remove'}
      </ActionButton>
    </div>
  )
}

function HealthPanel({ info, error }: { info: AgentHealth | null; error: string | null }) {
  if (error) {
    return (
      <div className="rounded-lg border border-red-800/60 bg-red-950/30 px-4 py-3 text-sm text-red-300">
        Health check failed: {error}
      </div>
    )
  }
  if (!info) return null
  const live = info.live === 'online'
  const age = info.age_seconds === null ? 'never' : info.age_seconds < 90 ? `${Math.round(info.age_seconds)}s` : `${Math.round(info.age_seconds / 60)}min`
  return (
    <div className="mx-4 mb-4 overflow-hidden rounded-lg border border-gray-800 bg-gray-950/40 px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className={`inline-flex items-center gap-1.5 text-sm font-semibold ${live ? 'text-emerald-300' : 'text-gray-400'}`}>
          <span className={`h-2 w-2 rounded-full ${live ? 'bg-emerald-400' : 'bg-gray-500'}`} />
          {live ? 'Agent is healthy' : 'Agent not responding'}
        </span>
        <span className="text-xs text-gray-500">
          heartbeat <span className="text-gray-300">{age} ago</span>
        </span>
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
        {[
          ['Host', info.hostname || '—'],
          ['OS', info.os || '—'],
          ['Agent version', info.version || '—'],
          ['L2 coverage', (info.subnets || []).join(', ') || '—'],
        ].map(([k, v]) => (
          <div key={k}>
            <dt className="text-gray-500">{k}</dt>
            <dd className="truncate text-gray-200">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

function updateAvailable(agent: AgentInfo): boolean {
  return !!(agent.version && agent.current_version && agent.version !== agent.current_version)
}

function DiagnosePanel({ agent, now }: { agent: AgentInfo; now: number }) {
  const [open, setOpen] = useState(false)
  const items: { tone: 'ok' | 'warn' | 'err'; title: string; body: string }[] = []

  if (agent.status === 'disabled') {
    items.push({
      tone: 'err',
      title: 'Agent is disabled',
      body: 'It is excluded from scans. Re-enable it or register a replacement if you want LAN coverage again.',
    })
  } else if (agent.status !== 'online') {
    const ago = relTime(agent.last_seen, now)
    items.push({
      tone: 'err',
      title: `Agent not responding (last heartbeat ${ago})`,
      body: 'The process is down or unreachable. Check the machine is powered and the agent process is running, then hit Restart (or run the repair command on the LAN machine).',
    })
  } else {
    items.push({ tone: 'ok', title: 'Heartbeating normally', body: 'The agent polls every few seconds and is eligible for scan delegation.' })
  }

  if (!agent.version) {
    items.push({ tone: 'warn', title: 'No version reported yet', body: 'First heartbeat has not arrived. If this sticks, the machine may be using a very old agent build.' })
  } else if (updateAvailable(agent)) {
    items.push({
      tone: 'warn',
      title: `Update available: v${agent.version} → v${agent.current_version}`,
      body: 'The server has a newer agent build. Click Update — the agent pulls it, swaps its own file and re-launches itself.',
    })
  } else {
    items.push({ tone: 'ok', title: `Agent is current (v${agent.version})`, body: 'Matching the build the server serves for self-updates.' })
  }

  if (agent.last_seen && agent.status === 'online' && Date.now() - new Date(agent.last_seen).getTime() > 90000) {
    items.push({ tone: 'warn', title: 'Reports online but heartbeat is stale', body: 'Status comes from the last update; if it stays stale in the UI, the page query may be cached — refresh or re-run the check.' })
  }

  if (!(agent.subnets || []).length) {
    items.push({
      tone: 'warn',
      title: 'No L2 coverage yet',
      body: 'Without advertised ranges the server may fall back to the container scanner for scans. The agent auto-detects local subnets on heartbeat.', 
    })
  }

  if (!(agent.capabilities || []).length) {
    items.push({ tone: 'warn', title: 'No capabilities advertised', body: 'SYN/ARP/NSE features are reported with the heartbeat; an empty list usually means the agent just started.' })
  }

  if (!items.length) {
    items.push({ tone: 'ok', title: 'All checks passed', body: 'No issues detected.' })
  }

  return (
    <div className="mx-4 mb-4">
      <button
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 text-[12px] font-medium text-gray-400 transition-colors hover:text-gray-200"
      >
        <svg viewBox="0 0 24 24" className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="m9 18 6-6-6-6" />
        </svg>
        Diagnostics
      </button>
      {open && (
        <ul className="mt-2 space-y-2 rounded-lg border border-gray-800 bg-gray-950/40 px-4 py-3">
          {items.map((it, i) => (
            <li key={i} className="flex gap-2.5">
              <span
                className={`mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full ${
                  it.tone === 'ok' ? 'bg-emerald-400' : it.tone === 'warn' ? 'bg-amber-400' : 'bg-red-400'
                }`}
              />
              <p className="text-xs leading-relaxed text-gray-300">
                <span className="font-semibold text-gray-200">{it.title}.</span>{' '}
                <span className="text-gray-400">{it.body}</span>
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function AgentCard({ agent, os, now }: { agent: AgentInfo; os: Os; now: number }) {
  const del = useDeleteAgent()
  const resetKey = useResetAgentKey()
  const health = useAgentHealth()
  const restart = useRestartAgent()
  const updateAgent = useUpdateAgent()
  const [setupOpen, setSetupOpen] = useState(false)
  const [healthInfo, setHealthInfo] = useState<AgentHealth | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)
  const [rotatedKey, setRotatedKey] = useState<string | null>(null)
  const [restartRequested, setRestartRequested] = useState(false)
  const [updateRequested, setUpdateRequested] = useState(false)

  useEffect(() => {
    if (!restartRequested) return
    const t = setTimeout(() => setRestartRequested(false), 30000)
    return () => clearTimeout(t)
  }, [restartRequested])

  useEffect(() => {
    if (!updateRequested) return
    const t = setTimeout(() => setUpdateRequested(false), 30000)
    return () => clearTimeout(t)
  }, [updateRequested])

  const cmds = agentctlCmd(agent.name, (agent.subnets || []).join(','), null, os)

  const runHealth = async () => {
    setHealthInfo(null)
    setHealthError(null)
    try {
      setHealthInfo(await health.mutateAsync(agent.id))
    } catch (e: any) {
      setHealthError(e?.response?.data?.detail || 'unexpected error')
    }
  }

  const rotate = async () => {
    setRotatedKey(null)
    try {
      const r = await resetKey.mutateAsync(agent.id)
      setRotatedKey(r.api_key)
    } catch (e: any) {
      setHealthError(`key rotation failed: ${e?.response?.data?.detail || 'unexpected error'}`)
    }
  }

  const requestRestart = async () => {
    setHealthError(null)
    try {
      await restart.mutateAsync(agent.id)
      setRestartRequested(true)
    } catch (e: any) {
      setHealthError(`restart request failed: ${e?.response?.data?.detail || 'unexpected error'}`)
    }
  }

  const requestUpdate = async () => {
    setHealthError(null)
    try {
      await updateAgent.mutateAsync(agent.id)
      setUpdateRequested(true)
    } catch (e: any) {
      setHealthError(`update request failed: ${e?.response?.data?.detail || 'unexpected error'}`)
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900 transition-colors hover:border-gray-700">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5">
        <AgentAvatar name={agent.name} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="truncate text-base font-semibold text-white">{agent.name}</span>
            {agent.status === 'online' ? (
              <DotPill tone="online">online</DotPill>
            ) : agent.status === 'disabled' ? (
              <DotPill tone="disabled">disabled</DotPill>
            ) : (
              <DotPill tone="offline">offline</DotPill>
            )}
            {agent.os ? <Chip>{agent.os}</Chip> : null}
            {agent.version ? <Chip>{`v${agent.version}`}</Chip> : null}
            {updateAvailable(agent) ? (
              <Chip tone="amber">{`update available: v${agent.current_version}`}</Chip>
            ) : agent.current_version && agent.version === agent.current_version ? (
              <Chip>up to date</Chip>
            ) : null}
          </div>
          <div className="mt-0.5 text-xs text-gray-500">
            last seen{' '}
            <span className="text-gray-400" title={agent.last_seen ? new Date(agent.last_seen).toLocaleString() : undefined}>
              {relTime(agent.last_seen, now)}
            </span>
            {agent.hostname ? <span className="ml-2">host <span className="text-gray-400">{agent.hostname}</span></span> : null}
          </div>
        </div>
        <ActionRow
          onHealth={runHealth}
          onToggleSetup={() => setSetupOpen((v) => !v)}
          onRestart={requestRestart}
          onUpdate={requestUpdate}
          onReset={rotate}
          onDelete={() => del.mutate(agent.id)}
          busy={health.isPending}
          setupOpen={setupOpen}
        />
      </div>

      {restartRequested && (
        <div className="mx-4 mb-4 rounded-lg border border-indigo-800/60 bg-indigo-950/30 px-4 py-2 text-xs text-indigo-200">
          Restart requested — the agent will self-restart on its next heartbeat and reconnect within
          about 15 seconds.
        </div>
      )}

      {updateRequested && (
        <div className="mx-4 mb-4 rounded-lg border border-amber-700/60 bg-amber-950/30 px-4 py-2 text-xs text-amber-200">
          Update requested — the agent pulls the latest build and re-launches itself within its next
          poll cycle (~15 seconds). Version will change to the update-available badge.
        </div>
      )}

      <div className="border-t border-gray-800/80 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[12px] font-semibold uppercase tracking-wider text-gray-600">L2 coverage</span>
          {(agent.subnets || []).length
            ? (agent.subnets || []).map((s) => <Chip key={s} tone="indigo">{s}</Chip>)
            : <span className="text-xs text-gray-600">none reported yet — auto-detected on heartbeat</span>}
          <span className="mx-2 h-3 w-px bg-gray-800" />
          {(agent.capabilities || []).map((c) => <Chip key={c}>{c}</Chip>)}
        </div>
        <div className="mt-1.5 text-xs text-gray-500">
          Not tied to one subnet: this agent is chosen for any scan whose targets all fall
          inside these ranges. Change them with <code className="text-gray-400">--subnets</code> on
          the agent, or let it auto-detect its local interfaces.
        </div>
        {agent.notes ? (
          <div className="mt-1.5 text-xs text-gray-500">{agent.notes}</div>
        ) : null}
      </div>

      {healthInfo || healthError ? <HealthPanel info={healthInfo} error={healthError} /> : null}

      <DiagnosePanel agent={agent} now={now} />

      {rotatedKey && (
        <div className="mx-4 mb-4 rounded-lg border border-amber-700/60 bg-amber-950/30 p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-semibold text-amber-300">New API key (shown once)</span>
          </div>
          <div className="mt-2">
            <KeyBox value={rotatedKey} label="API key" />
          </div>
          <p className="mt-2 text-xs text-gray-400">
            The old key stops working immediately. The agent exchanges it automatically on its next
            heartbeat within the 5-minute grace window. Only if it stays offline afterwards, set it
            by hand on the agent machine:{' '}
            <code className="break-all text-amber-200">{cmds.keySet(rotatedKey)}</code>
          </p>
        </div>
      )}

      {setupOpen && (
        <div className="border-t border-gray-800 bg-gray-950/40 px-4 py-4">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-medium text-gray-300">
                Setup · repair · health on the agent machine ({OS_LABEL[os]})
              </span>
              <span className="text-[12px] text-gray-500">use the OS toggle in the header</span>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <CommandColumn
                title="Run the agent"
                blocks={[
                  { label: 'Start (supervised, auto-restart)', value: cmds.run },
                  { label: 'Persist across reboot', value: cmds.install },
                ]}
              />
              <CommandColumn
                title="Maintain it"
                blocks={[
                  { label: 'Health check', value: cmds.status },
                  { label: 'Repair (restart + autostart)', value: cmds.repair },
                ]}
                keyed={cmds.keySet}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function FirstRunBanner({ name, subnets, apiKey, onClose }: {
  name: string
  subnets: string
  apiKey: string
  onClose: () => void
}) {
  const win = agentctlCmd(name, subnets, apiKey, 'windows')
  const unix = agentctlCmd(name, subnets, apiKey, 'unix')
  return (
    <div className="overflow-hidden rounded-xl border border-emerald-700/60 bg-gradient-to-br from-emerald-950/50 to-gray-900">
      <div className="px-4 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-emerald-300">
              Agent '{name}' created successfully
            </div>
            <p className="mt-0.5 text-xs text-gray-400">
              Copy the API key now — it is shown once. Then start the agent on the LAN machine.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onClose} className="rounded-md px-2 py-1 text-xs text-gray-400 hover:text-gray-200">
              Done
            </button>
          </div>
        </div>
        <div className="mt-3">
          <KeyBox value={apiKey} label="Agent API key" hint="shown once — masked until you reveal it" />
        </div>
      </div>
      <div className="border-t border-gray-800 px-4 py-4">
        <div className="mb-3 text-xs font-medium text-gray-300">
          1. Start the agent &nbsp;·&nbsp; 2. Make it persistent
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <CommandColumn
            title="Windows"
            blocks={[
              { label: 'Start the agent', value: win.run },
              { label: 'Auto-start at logon', value: win.install },
            ]}
          />
          <CommandColumn
            title="Linux / macOS"
            blocks={[
              { label: 'Start the agent', value: unix.run },
              { label: 'Auto-start via systemd / launchd', value: unix.install },
            ]}
          />
        </div>
      </div>
    </div>
  )
}

export default function Agents() {
  const { data: agents, isLoading } = useAgents()
  const create = useCreateAgent()
  const now = useNow(15000)
  const [os, setOs] = useState<Os>('windows')
  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [subnets, setSubnets] = useState('')
  const [notes, setNotes] = useState('')
  const [newAgent, setNewAgent] = useState<{ name: string; subnets: string; apiKey: string } | null>(null)

  const total = agents?.length || 0
  const online = agents?.filter((a) => a.status === 'online').length || 0
  const offline = agents?.filter((a) => a.status !== 'online').length || 0

  const submit = async () => {
    if (!name.trim()) return
    const res = await create.mutateAsync({
      name: name.trim(),
      subnets: subnets.split(',').map((s) => s.trim()).filter(Boolean),
      notes,
    })
    setNewAgent({ name: res.name, subnets, apiKey: res.api_key })
    setName('')
    setSubnets('')
    setNotes('')
    setFormOpen(false)
  }

  if (isLoading) return <div className="py-16 text-center text-gray-400">Loading agents…</div>

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Scanner Agents</h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-400">
            Drop an agent on any machine on the target LAN for full Layer-2 coverage — ARP discovery
            with MAC vendors, SYN scanning and OS fingerprinting — supervised, auto-restarting and
            re-pairable in one command.
          </p>
        </div>
        <button
          onClick={() => setFormOpen((v) => !v)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500"
        >
          {formOpen ? 'Close form' : '+ Register agent'}
        </button>
      </div>

      <div className="mb-6 grid grid-cols-3 gap-4">
        <StatCard label="Total agents" value={total} tone="text-white" />
        <StatCard label="Online" value={online} tone="text-emerald-400" />
        <StatCard label="Offline / disabled" value={offline} tone="text-gray-400" />
      </div>

      {newAgent && (
        <div className="mb-6">
          <FirstRunBanner
            name={newAgent.name}
            subnets={newAgent.subnets}
            apiKey={newAgent.apiKey}
            onClose={() => setNewAgent(null)}
          />
        </div>
      )}

      {formOpen && (
        <div className="mb-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="mb-3">
            <h2 className="text-sm font-semibold text-gray-200">Register a new agent</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              The name identifies it in scan logs. Subnets are the LAN ranges (CIDR) it can reach at
              Layer 2 — leave empty and the agent auto-detects its local subnets on first heartbeat.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs text-gray-500">Name (unique)</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="home-lan-nuc"
                className="w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">Subnets (comma-separated)</label>
              <input
                value={subnets}
                onChange={(e) => setSubnets(e.target.value)}
                placeholder="192.168.1.0/24"
                className="w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500">Notes</label>
              <input
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="optional — e.g. physical location"
                className="w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-indigo-500"
              />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={submit}
              disabled={create.isPending || !name.trim()}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {create.isPending ? 'Creating…' : 'Create agent'}
            </button>
            <span className="text-xs text-gray-500">the API key is generated once and shown immediately</span>
          </div>
        </div>
      )}

      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Registered agents</span>
        <div className="flex items-center gap-1 text-[12px] text-gray-500">
          <span className="mr-1">Show commands for</span>
          {(['windows', 'unix'] as Os[]).map((o) => (
            <button
              key={o}
              onClick={() => setOs(o)}
              className={`rounded-md px-2 py-1 font-medium transition-colors ${os === o ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
              title={o === 'windows' ? 'PowerShell on Windows' : 'Bash on Linux/macOS'}
            >
              {OS_LABEL[o]}
            </button>
          ))}
        </div>
      </div>

      {agents?.length ? (
        <div className="space-y-4">
          {(agents || []).map((a) => (
            <AgentCard key={a.id} agent={a} os={os} now={now} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-gray-700 px-6 py-16 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gray-800">
            <svg viewBox="0 0 24 24" className="h-7 w-7 text-indigo-400" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="4" width="18" height="7" rx="1.5" />
              <rect x="3" y="13" width="18" height="7" rx="1.5" />
              <path d="M7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-gray-200">No scanner agents yet</h3>
          <p className="mx-auto mt-1 max-w-md text-sm text-gray-500">
            Agent runs mean scans see the network from the inside — MAC addresses, exact OS versions
            and every open port, even when targets block the container's blanket discovery.
          </p>
          <ol className="mx-auto mt-5 flex max-w-2xl flex-col gap-2 text-left text-sm text-gray-400 sm:flex-row sm:gap-4">
            {[
              ['1', 'Register the agent here'],
              ['2', 'Run the two commands on a LAN machine'],
              ['3', 'Scans automatically prefer it'],
            ].map(([n, t]) => (
              <li key={n} className="flex items-center gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-indigo-600/40 text-xs font-bold text-indigo-200">{n}</span>
                {t}
              </li>
            ))}
          </ol>
          <button
            onClick={() => setFormOpen(true)}
            className="mt-6 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500"
          >
            Register an agent
          </button>
        </div>
      )}
    </div>
  )
}