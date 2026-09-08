import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
  useScan,
  useHosts,
  useStopScan,
  usePauseScan,
  useResumeScan,
  useScanLogs,
  useScanActivity,
  type ActivityEntry,
} from '../hooks/useApi'
import { StatusBadge } from '../components/Badge'
import { DeviceIcon, SeverityDot } from '../components/SeverityBadge'
import ScanNav from '../components/ScanNav'

interface WSMessage {
  type: string
  ts?: number
  host_id?: string
  ip?: string
  ports?: any[]
  device_type?: string
  [key: string]: any
}

const ACTIVE_STATUSES = ['queued', 'discovering', 'scanning', 'fingerprinting', 'analyzing', 'paused', 'agent_running', 'reverifying']
const TERMINAL_STATUSES = ['completed', 'failed', 'stopped']

const MAX_FEED = 500

type FeedEntry = { id: string; msg: WSMessage; ts: number }

const FEED_META: Record<string, { label: string; cls: string; dot: string }> = {
  scan_completed: { label: 'COMPLETED', cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400', dot: 'bg-emerald-400' },
  scan_failed: { label: 'FAILED', cls: 'border-red-500/40 bg-red-500/10 text-red-400', dot: 'bg-red-400' },
  scan_stopped: { label: 'STOPPED', cls: 'border-red-500/40 bg-red-500/10 text-red-400', dot: 'bg-red-400' },
  scan_started: { label: 'STARTED', cls: 'border-blue-500/40 bg-blue-500/10 text-blue-400', dot: 'bg-blue-400' },
  scan_paused: { label: 'PAUSED', cls: 'border-amber-500/40 bg-amber-500/10 text-amber-400', dot: 'bg-amber-400' },
  scan_resumed: { label: 'RESUMED', cls: 'border-blue-500/40 bg-blue-500/10 text-blue-400', dot: 'bg-blue-400' },
  scan_reverifying: { label: 'RE-VERIFYING', cls: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-400', dot: 'bg-fuchsia-400' },
  scan_delegated: { label: 'DELEGATED', cls: 'border-purple-500/40 bg-purple-500/10 text-purple-400', dot: 'bg-purple-400' },
  host_discovered: { label: 'DISCOVERED', cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400', dot: 'bg-emerald-400' },
  host_updated: { label: 'UPDATED', cls: 'border-blue-500/40 bg-blue-500/10 text-blue-400', dot: 'bg-blue-400' },
  finding_added: { label: 'FINDINGS', cls: 'border-orange-500/40 bg-orange-500/10 text-orange-400', dot: 'bg-orange-400' },
  scan_progress: { label: 'PROGRESS', cls: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400', dot: 'bg-cyan-400' },
}

function feedKey(type: string, ts: number, anchor?: string): string {
  return `${type}|${ts}|${anchor || 'scan'}`
}

function feedDetail(m: WSMessage): string {
  switch (m.type) {
    case 'host_discovered':
      return m.ip || ''
    case 'host_updated': {
      const parts: string[] = []
      if (m.ip) parts.push(m.ip)
      if (Array.isArray(m.ports) && m.ports.length) parts.push(`${m.ports.length} open ${m.ports.length === 1 ? 'port' : 'ports'}`)
      else if (typeof m.ports_count === 'number') parts.push(`${m.ports_count} open ${m.ports_count === 1 ? 'port' : 'ports'}`)
      if (m.device_type) parts.push(String(m.device_type).replace(/_/g, ' '))
      if (m.phase) parts.push(String(m.phase))
      return parts.join(' · ')
    }
    case 'finding_added': {
      if (typeof m.count === 'number') {
        const sev = m.by_severity as Record<string, number> | undefined
        const bits: string[] = [`${m.count} finding${m.count === 1 ? '' : 's'}`]
        if (sev) {
          if (sev.critical) bits.push(`${sev.critical} critical`)
          if (sev.concerning) bits.push(`${sev.concerning} concerning`)
          if (sev.notable) bits.push(`${sev.notable} notable`)
          if (sev.info) bits.push(`${sev.info} info`)
        }
        return bits.join(' · ')
      }
      return 'Risk analysis complete'
    }
    case 'scan_completed':
      return `Scan completed — ${m.hosts_discovered ?? '—'} host(s) discovered`
    case 'scan_started':
      return Array.isArray(m.targets) ? `Scan started — ${m.targets.join(', ')}` : 'Scan started'
    case 'scan_delegated':
      return m.agent ? `Delegated to scanner agent "${m.agent}"` : 'Delegated to scanner agent'
    case 'scan_failed':
      return m.error ? `Scan failed — ${m.error}` : 'Scan failed'
    case 'scan_stopped':
      return 'Scan stopped by user'
    case 'scan_reverifying':
      return 'Re-verifying discovered assets'
    case 'scan_paused':
      return 'Scan paused'
    case 'scan_resumed':
      return 'Scan resumed'
    case 'scan_progress':
      return typeof m.progress_pct === 'number' ? `Progress ${m.progress_pct}%` : 'Progress update'
    default:
      return ''
  }
}

function matchesFilter(filter: 'all' | 'system' | 'hosts' | 'findings', type: string): boolean {
  if (filter === 'all') return true
  if (filter === 'system') return type.startsWith('scan_')
  if (filter === 'hosts') return type === 'host_discovered' || type === 'host_updated'
  if (filter === 'findings') return type === 'finding_added'
  return false
}

export default function LiveScan() {
  const { engagementId, scanId } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { data: scan } = useScan(scanId)
  const { data: hosts } = useHosts(scanId)
  const { data: scanLogs } = useScanLogs(scanId)
  const { data: activity } = useScanActivity(scanId)
  const stopScan = useStopScan()
  const pauseScan = usePauseScan()
  const resumeScan = useResumeScan()

  const wsUrl = useMemo(() => {
    const wsScheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    return `${wsScheme}://${window.location.host}/api/ws/scans/${scanId}`
  }, [scanId])
  const [connected, setConnected] = useState(false)
  const [feed, setFeed] = useState<FeedEntry[]>([])
  const [feedFilter, setFeedFilter] = useState<'all' | 'system' | 'hosts' | 'findings'>('all')
  const [consoleLogs, setConsoleLogs] = useState<WSMessage[]>([])
  const [showConsole, setShowConsole] = useState(false)
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set())
  const [elapsed, setElapsed] = useState(0)
  const [reverifyElapsed, setReverifyElapsed] = useState(0) // re-verify pass duration
  const [openPortCount, setOpenPortCount] = useState(0)
  const [liveProgress, setLiveProgress] = useState<number | null>(null)
  const [liveHosts, setLiveHosts] = useState<number | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const startRef = useRef<number>(Date.now())
  const portMapRef = useRef<Map<string, number>>(new Map())
  const consoleRef = useRef<HTMLDivElement | null>(null)
  const feedRef = useRef<HTMLDivElement | null>(null)
  const feedKeysRef = useRef<Set<string>>(new Set())
  const seededCountRef = useRef(0)
  const terminalSyncedRef = useRef(false)

  // Seed the activity timeline from the persisted feed (survives reloads and
  // re-verify passes), deduped against live WebSocket events by ts+type+anchor.
  useEffect(() => {
    if (!activity) return
    const updates: FeedEntry[] = []
    for (const ev of activity as ActivityEntry[]) {
      const ts = ev.ts ? new Date(ev.ts).getTime() : Date.now()
      const key = feedKey(ev.type, ts, ev.ip || ev.host_id || 'scan')
      if (feedKeysRef.current.has(key)) continue
      feedKeysRef.current.add(key)
      updates.push({ id: key, msg: ev as unknown as WSMessage, ts })
    }
    if (updates.length) {
      setFeed((prev) => [...prev, ...updates].slice(-MAX_FEED))
    }
  }, [activity])

  // Keep the console in sync with the persisted log file. The WebSocket streams
  // lines live; the polled REST log catches up any lines written while the
  // socket was down. Polled lines identical to already-rendered ones (the
  // socket may have beaten the poll to them) are dropped so nothing renders
  // twice, even when the file and the WS carry slightly different timestamps.
  useEffect(() => {
    if (!scanLogs) return
    if (scanLogs.length > seededCountRef.current) {
      const missed = scanLogs.slice(seededCountRef.current).map((e) => {
        const ts = e.ts ? new Date(e.ts).getTime() : Date.now()
        return { type: 'cmd_log' as const, ts, level: e.level || 'info', line: e.line }
      })
      setConsoleLogs((prev) => {
        const seen = new Set(prev.map((x) => `${x.level}\u0000${x.line}`))
        const fresh = missed.filter((m) => !seen.has(`${m.level}\u0000${m.line}`))
        if (!fresh.length) return prev
        seededCountRef.current = scanLogs.length
        return [...prev.slice(-499), ...fresh]
      })
      seededCountRef.current = scanLogs.length
    }
  }, [scanLogs])

  useEffect(() => {
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (e) => {
      try {
        const msg: WSMessage = JSON.parse(e.data)
        const ts = msg.ts ? new Date(msg.ts).getTime() : Date.now()
        if (msg.type === 'cmd_log') {
          setConsoleLogs((prev) => {
            const tail = prev.slice(-25)
            if (tail.some((x) => x.level === msg.level && x.line === msg.line)) return prev
            return [...prev.slice(-499), { ...msg, ts }]
          })
        } else {
          const key = feedKey(msg.type, ts, (msg.ip || msg.host_id || 'scan') as string)
          if (!feedKeysRef.current.has(key)) {
            feedKeysRef.current.add(key)
            setFeed((prev) => [...prev, { id: key, msg, ts }].slice(-MAX_FEED))
          }
          if (msg.type === 'host_updated' && msg.ip && Array.isArray(msg.ports)) {
            portMapRef.current.set(msg.ip, msg.ports.length)
            setOpenPortCount([...portMapRef.current.values()].reduce((a, b) => a + b, 0))
          }
        }
        if (msg.type === 'host_discovered' && msg.ip) {
          setHighlighted((prev) => new Set(prev).add(msg.ip!))
          setTimeout(() => {
            setHighlighted((prev) => {
              const next = new Set(prev)
              next.delete(msg.ip!)
              return next
            })
          }, 4000)
        }
        if (msg.type === 'scan_progress' && typeof msg.progress_pct === 'number') {
          setLiveProgress(msg.progress_pct)
        }
        if (['scan_completed', 'scan_failed', 'scan_stopped'].includes(msg.type)) {
          // The scan finished: fall back to the authoritative REST state (which
          // the worker commits at 100% for completed scans) instead of a stale
          // live progress value, and invalidate so the badge/progress refresh.
          setLiveProgress(msg.type === 'scan_completed' ? 100 : null)
          setLiveHosts(null)
          if (!terminalSyncedRef.current) {
            terminalSyncedRef.current = true
            qc.invalidateQueries({ queryKey: ['scan', scanId] })
            qc.invalidateQueries({ queryKey: ['engagement', engagementId, 'scans'] })
          }
        }
        if (msg.type === 'scan_resumed' || msg.type === 'scan_reverifying') {
          terminalSyncedRef.current = false
        }
        if (msg.type === 'scan_reverifying') {
          // A re-verify pass restarts progress from 0; the persisted REST field
          // (reverify_started_at) drives the separate timer within ~3s.
          setLiveProgress(0)
          setLiveHosts(null)
        }
        if (msg.type === 'host_discovered' && typeof msg.up !== 'undefined') {
          setLiveHosts((prev) => (prev === null ? (msg.up ? 1 : 0) : prev + (msg.up ? 1 : 0)))
        }
      } catch {}
    }
    return () => ws.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [consoleLogs])

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight
    }
  }, [feed])

  const visibleFeed = useMemo(() => feed.filter((e) => matchesFilter(feedFilter, e.msg.type)), [feed, feedFilter])

  useEffect(() => {
    if (!scan) return
    const passes = scan.pass_history || []
    const settled = passes.reduce((a, p) => a + (p.duration || 0), 0)

    // Pre-history scans (or first pass still running): fall back to wall clock
    // from started_at with idle (paused) gaps deducted.
    if (!passes.length) {
      if (!scan.started_at) return
      startRef.current = new Date(scan.started_at).getTime()
      const paused = scan.total_paused_seconds || 0
      if (scan.completed_at && TERMINAL_STATUSES.includes(scan.status)) {
        const end = new Date(scan.completed_at).getTime()
        setElapsed(Math.max(0, Math.floor((end - startRef.current) / 1000) - paused))
        return
      }
      const interval = setInterval(() => {
        if (scan.started_at) setElapsed(Math.max(0, Math.floor((Date.now() - startRef.current) / 1000) - paused))
      }, 1000)
      return () => clearInterval(interval)
    }

    // History-based: sum the completed passes, plus a live tick for whichever
    // pass is currently running.
    if (!scan.reverify_started_at || TERMINAL_STATUSES.includes(scan.status)) {
      setElapsed(settled)
      return
    }
    const interval = setInterval(() => {
      const start = new Date(scan.reverify_started_at!).getTime()
      setElapsed(settled + Math.max(0, Math.floor((Date.now() - start) / 1000)))
    }, 1000)
    return () => clearInterval(interval)
  }, [scan])

  // Separate elapsed counter for a re-verify pass: it starts at reverify_started_at
  // and is frozen at completed_at, so it never bleeds into (or overrides) the
  // original scan's total elapsed time.
  useEffect(() => {
    if (!scan) return
    const start = scan.reverify_started_at ? new Date(scan.reverify_started_at).getTime() : null
    if (start === null) {
      setReverifyElapsed(0)
      return
    }
    if (scan.completed_at && TERMINAL_STATUSES.includes(scan.status)) {
      const end = new Date(scan.completed_at).getTime()
      setReverifyElapsed(Math.max(0, Math.floor((end - start) / 1000)))
      return
    }
    const interval = setInterval(() => {
      setReverifyElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)))
    }, 1000)
    return () => clearInterval(interval)
  }, [scan?.reverify_started_at, scan?.completed_at, scan?.status])

  const isActive = scan ? ACTIVE_STATUSES.includes(scan.status) : true

  const handleStop = async () => {
    if (scanId) {
      await stopScan.mutateAsync(scanId)
      navigate(0)
    }
  }

  const handlePause = async () => {
    if (scanId) await pauseScan.mutateAsync(scanId)
  }

  const handleResume = async () => {
    if (scanId) await resumeScan.mutateAsync(scanId)
  }

  const formatElapsed = (s: number) => {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60
    return `${h}h ${m}m ${sec}s`
  }

  // Per-pass labels and deltas: "Initial", "Re-verify", "Re-verify 2", ...
  const passes = scan?.pass_history || []
  const passLabel = (p: { index: number; kind: string }) =>
    p.kind === 'discover' ? 'Initial' : `Re-verify${p.index > 1 ? ` ${p.index}` : ''}`
  const deltaOf = (i: number, key: 'hosts' | 'ports') => {
    if (i === 0) return ''
    const d = passes[i][key] - passes[i - 1][key]
    return ` (${d > 0 ? '+' : ''}${d})`
  }
  const hostPassLines = passes.map((p, i) => `${passLabel(p)} ${p.hosts} hosts${deltaOf(i, 'hosts')}`)
  const portPassLines = passes.map((p, i) => `${passLabel(p)} ${p.ports} ports${deltaOf(i, 'ports')}`)
  const timePassLines = passes.map((p) => `${passLabel(p)} ${formatElapsed(p.duration || 0)}`)

  return (
    <div>
      <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">
        ← Back to engagement
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Live Scan View</h1>
          <div className="mt-2 flex items-center gap-3">
            <StatusBadge status={scan?.status || 'queued'} />
            <span className="mono text-sm text-gray-400">{scan?.targets.join(', ')}</span>
            <span className={`text-xs ${connected ? 'text-emerald-400' : 'text-gray-500'}`}>
              {connected ? '● live' : '○ disconnected'}
            </span>
          </div>
        </div>
        {isActive && (
          <div className="flex items-center gap-2">
            {scan?.status === 'paused' ? (
              <button onClick={handleResume} className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
                Resume
              </button>
            ) : (
              <button onClick={handlePause} className="rounded bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-700">
                Pause
              </button>
            )}
            <button onClick={handleStop} className="rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">
              Stop Scan
            </button>
          </div>
        )}
      </div>

      {/* Console toggle + panel */}
      <button
        onClick={() => setShowConsole(!showConsole)}
        className="mb-4 flex items-center gap-2 rounded border border-gray-700 px-3 py-1.5 text-xs font-medium text-gray-300 hover:border-gray-500"
      >
        <span className={`h-2 w-2 rounded-full ${consoleLogs.length ? 'bg-emerald-400' : 'bg-gray-600'}`} />
        {showConsole ? 'Hide' : 'Show'} Console {consoleLogs.length > 0 && `(${consoleLogs.length})`}
      </button>
      {showConsole && (
        <div className="mb-4 flex h-[55vh] flex-col rounded-lg border border-gray-800 bg-black p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs uppercase tracking-wide text-gray-500">Core Command Console</span>
            <button
              onClick={() => setConsoleLogs([])}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Clear
            </button>
          </div>
          <div
            ref={consoleRef}
            className="flex-1 space-y-0.5 overflow-y-auto whitespace-pre-wrap break-words font-mono text-sm leading-relaxed"
          >
            {consoleLogs.length === 0 && <div className="text-gray-600">Awaiting nmap commands...</div>}
            {consoleLogs.map((m, i) => (
              <div key={i} className="flex gap-2">
                <span className="shrink-0 text-gray-600">
                  {m.ts ? new Date(m.ts).toLocaleTimeString() : ''}
                </span>
                <span
                  className={
                    m.level === 'cmd'
                      ? 'text-cyan-300'
                      : m.level === 'warn'
                      ? 'text-amber-400'
                      : m.level === 'err'
                      ? 'text-red-400'
                      : m.level === 'info'
                      ? 'text-emerald-400'
                      : m.level === 'out'
                      ? 'text-gray-300'
                      : 'text-gray-400'
                  }
                >
                  {m.level === 'cmd' ? '$ ' : ''}
                  {m.line}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live stats */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Stat
          label="Hosts Discovered"
          value={(liveHosts ?? scan?.hosts_discovered) || 0}
          sub={hostPassLines}
        />
        <Stat label="Hosts in Scope" value={scan?.hosts_total_in_scope || 0} />
        <Stat
          label="Open Ports"
          value={openPortCount || scan?.open_ports_count || 0}
          sub={portPassLines}
        />
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="text-xs uppercase tracking-wide text-gray-500">Elapsed</div>
          <div className="mt-1 text-2xl font-bold text-white mono">{formatElapsed(elapsed)}</div>
          {timePassLines.map((line, i) => (
            <div key={i} className="mt-1 text-xs text-amber-400 mono" title="Per-pass duration">
              {line}
            </div>
          ))}
          {isActive && scan?.reverify_started_at && (
            <div className="mt-1 text-xs text-amber-400 mono" title="Running re-verify pass">
              {passLabel({ index: passes.length, kind: 'reverify' })} {formatElapsed(reverifyElapsed)}
            </div>
          )}
        </div>
      </div>

      <div className="mb-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="mb-2 flex items-center justify-between text-sm">
          <span className="text-gray-400">{scan?.status || 'queued'}</span>
          <span className="font-medium text-white">{(liveProgress ?? scan?.progress_pct) || 0}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded bg-gray-800">
          <div
            className="h-full bg-blue-600 transition-all duration-500"
            style={{ width: `${(liveProgress ?? scan?.progress_pct) || 0}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Activity timeline */}
        <div className="lg:col-span-2 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-medium text-gray-400">Activity Timeline</h2>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
              <span className="text-xs text-gray-500">{feed.length} events</span>
            </div>
            <div className="flex gap-1 text-xs">
              {(['all', 'system', 'hosts', 'findings'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFeedFilter(f)}
                  className={`rounded px-2.5 py-1 font-medium capitalize transition-colors ${
                    feedFilter === f
                      ? 'bg-blue-600/20 text-blue-300 ring-1 ring-blue-500/40'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div ref={feedRef} className="max-h-96 space-y-px overflow-y-auto">
            {visibleFeed.length === 0 && (
              <div className="py-10 text-center text-sm text-gray-500">No activity recorded yet.</div>
            )}
            {visibleFeed.map((e) => {
              const meta = FEED_META[e.msg.type] || { label: e.msg.type.toUpperCase(), cls: 'border-gray-600 bg-gray-800 text-gray-300', dot: 'bg-gray-500' }
              return (
                <div key={e.id} className="flex items-center gap-2.5 rounded px-2 py-1.5 hover:bg-gray-800/60">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${meta.dot}`} />
                  <span className="w-[58px] shrink-0 tabular-nums text-xs text-gray-500">
                    {new Date(e.ts).toLocaleTimeString([], { hour12: false })}
                  </span>
                  <span className={`shrink-0 rounded border px-1.5 py-px text-[10px] font-semibold tracking-wide ${meta.cls}`}>
                    {meta.label}
                  </span>
                  <span className="truncate mono text-sm text-gray-300">{feedDetail(e.msg)}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Live hosts */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-medium text-gray-400">Live Hosts ({hosts?.length || 0})</h2>
          <div className="max-h-96 space-y-1 overflow-y-auto">
            {hosts?.map((h) => (
              <Link
                key={h.id}
                to={`/engagements/${engagementId}/scans/${scanId}/host/${h.ip}`}
                className={`flex items-center justify-between rounded px-2 py-1.5 text-sm hover:bg-gray-800 transition-colors ${
                  highlighted.has(h.ip) ? 'bg-blue-500/10' : ''
                }`}
              >
                <div className="flex items-center gap-2">
                  <DeviceIcon type={h.device_type || 'unknown'} size="sm" />
                  <span className="mono text-gray-200">{h.ip}</span>
                </div>
                <SeverityDot severity="info" />
              </Link>
            ))}
            {!hosts?.length && <div className="py-6 text-center text-sm text-gray-500">No hosts yet</div>}
          </div>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: string | number; sub?: string[] }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-white mono">{value}</div>
      {sub?.map((line, i) => (
        <div key={i} className="mt-1 text-xs text-amber-400 mono" title="Per-pass committed count">
          {line}
        </div>
      ))}
    </div>
  )
}
