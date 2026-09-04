import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { useScan, useHosts, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '../hooks/useApi'
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

export default function LiveScan() {
  const { engagementId, scanId } = useParams()
  const navigate = useNavigate()
  const { data: scan } = useScan(scanId)
  const { data: hosts } = useHosts(scanId)
  const { data: scanLogs } = useScanLogs(scanId)
  const stopScan = useStopScan()
  const pauseScan = usePauseScan()
  const resumeScan = useResumeScan()

  const wsUrl = useMemo(() => {
    const base = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')
    const wsScheme = base.startsWith('https') ? 'wss' : 'ws'
    const host = base.replace(/^https?:\/\//, '')
    return `${wsScheme}://${host}/api/ws/scans/${scanId}`
  }, [scanId])
  const [connected, setConnected] = useState(false)
  const [feed, setFeed] = useState<WSMessage[]>([])
  const [consoleLogs, setConsoleLogs] = useState<WSMessage[]>([])
  const [showConsole, setShowConsole] = useState(false)
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set())
  const [elapsed, setElapsed] = useState(0)
  const [openPortCount, setOpenPortCount] = useState(0)
  const [liveProgress, setLiveProgress] = useState<number | null>(null)
  const [liveHosts, setLiveHosts] = useState<number | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const startRef = useRef<number>(Date.now())
  const portMapRef = useRef<Map<string, number>>(new Map())
  const consoleRef = useRef<HTMLDivElement | null>(null)
  const seededRef = useRef(false)

  // Seed the console with the scan's full persisted log history (initial scan +
  // any re-verify passes), so opening the view replays everything even when the
  // page was not open while the scan ran.
  useEffect(() => {
    if (seededRef.current || !scanLogs) return
    seededRef.current = true
    const seeded = scanLogs.map((e) => {
      const ts = e.ts ? new Date(e.ts).getTime() : Date.now()
      return { type: 'cmd_log', ts, level: e.level || 'info', line: e.line }
    })
    if (seeded.length) {
      setConsoleLogs((prev) => (prev.length >= seeded.length - 10 ? prev : seeded))
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
          setConsoleLogs((prev) => [...prev.slice(-499), { ...msg, ts }])
        } else {
          setFeed((prev) => [...prev.slice(-49), { ...msg, ts }])
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
        if (msg.type === 'host_discovered' && typeof msg.up !== 'undefined') {
          setLiveHosts((prev) => (prev === null ? 1 : prev + (msg.up ? 1 : 0)))
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
    if (!scan?.started_at) return
    startRef.current = new Date(scan.started_at).getTime()

    // Terminal states: freeze the elapsed time at (completed_at - started_at)
    // instead of letting the live ticking clock keep running past the scan.
    if (scan.completed_at && TERMINAL_STATUSES.includes(scan.status)) {
      const end = new Date(scan.completed_at).getTime()
      setElapsed(Math.max(0, Math.floor((end - startRef.current) / 1000)))
      return
    }

    const interval = setInterval(() => {
      if (scan.started_at) setElapsed(Math.floor((Date.now() - startRef.current) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [scan?.started_at, scan?.completed_at, scan?.status])

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
        <Stat label="Hosts Discovered" value={(liveHosts ?? scan?.hosts_discovered) || 0} />
        <Stat label="Hosts in Scope" value={scan?.hosts_total_in_scope || 0} />
        <Stat label="Open Ports" value={openPortCount} />
        <Stat label="Elapsed" value={formatElapsed(elapsed)} />
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
        {/* Activity feed */}
        <div className="lg:col-span-2 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-medium text-gray-400">Activity Feed</h2>
          <div className="max-h-96 space-y-1 overflow-y-auto">
            {feed.length === 0 && <div className="py-8 text-center text-sm text-gray-500">Waiting for scan events...</div>}
            {feed.map((msg, i) => (
              <div key={i} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-gray-800">
                <span className="text-xs text-gray-500">{msg.ts ? new Date(msg.ts).toLocaleTimeString() : ''}</span>
                <span className="text-gray-300">
                  {msg.type === 'host_discovered' && <span className="text-emerald-400">● discovered</span>}
                  {msg.type === 'host_updated' && <span className="text-blue-400">● updated</span>}
                  {msg.type === 'finding_added' && <span className="text-orange-400">● finding</span>}
                  {msg.type === 'scan_completed' && <span className="text-emerald-400">● completed</span>}
                  {msg.type === 'scan_failed' && <span className="text-red-400">● failed</span>}
                  {msg.type === 'scan_stopped' && <span className="text-red-400">● stopped</span>}
                  {msg.type === 'scan_paused' && <span className="text-amber-400">● paused</span>}
                  {msg.type === 'scan_resumed' && <span className="text-blue-400">● resumed</span>}
                  {msg.type === 'scan_started' && <span className="text-blue-400">● started</span>}
                  {msg.type === 'scan_delegated' && <span className="text-purple-400">● delegated</span>}
                  {msg.type === 'scan_reverifying' && <span className="text-fuchsia-400">● re-verifying</span>}
                  {msg.type === 'scan_progress' && <span className="text-cyan-400">● progress</span>}
                </span>
                <span className="mono">{msg.host?.ip || msg.ip || msg.host_id?.slice(0, 8) || ''}</span>
                {msg.type === 'host_updated' && msg.device_type && (
                  <DeviceIcon type={msg.device_type} size="sm" />
                )}
              </div>
            ))}
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

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-white mono">{value}</div>
    </div>
  )
}
