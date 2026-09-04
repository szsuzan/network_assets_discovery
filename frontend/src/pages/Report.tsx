import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useHosts, useFindings, useScan } from '../hooks/useApi'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { SEVERITY_COLORS, DEVICE_TYPE_LABELS, normalizeDeviceType } from '../lib/types'
import ScanNav from '../components/ScanNav'

export default function Report() {
  const { engagementId, scanId } = useParams()
  const { data: scan } = useScan(scanId)
  const { data: hosts } = useHosts(scanId)
  const { data: findings } = useFindings(scanId)
  const [exporting, setExporting] = useState('')

  const deviceBreakdown = useMemo(() => {
    const map = new Map<string, number>()
    hosts?.forEach((h) => {
      const type = DEVICE_TYPE_LABELS[normalizeDeviceType(h.device_type)] || 'Unknown'
      map.set(type, (map.get(type) || 0) + 1)
    })
    return Array.from(map.entries()).map(([name, value]) => ({ name, value }))
  }, [hosts])

  const severityBreakdown = useMemo(() => {
    const counts = { critical: 0, concerning: 0, notable: 0, info: 0 }
    findings?.forEach((f) => {
      if (counts[f.severity as keyof typeof counts] !== undefined) counts[f.severity as keyof typeof counts]++
    })
    return (['critical', 'concerning', 'notable', 'info'] as const).map((sev) => ({
      name: sev,
      count: counts[sev],
      fill: SEVERITY_COLORS[sev],
    }))
  }, [findings])

  const coveragePct = scan
    ? Math.round(((scan.hosts_discovered || 0) / Math.max(scan.hosts_total_in_scope || 1, 1)) * 100)
    : 0

  const [nextSteps, setNextSteps] = useState<string[]>([
    'Validate findings on critical exposed services',
    'Confirm admin panels require authentication',
    'Review SNMP community string findings',
  ])

  const handleExport = async (format: string) => {
    setExporting(format)
    const token = localStorage.getItem('token')
    const base = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')
    const res = await fetch(`${base}/api/scans/${scanId}/export?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const blob = await res.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${scanId}.${format}`
    a.click()
    window.URL.revokeObjectURL(url)
    setExporting('')
  }

  const updateNextStep = (i: number, value: string) => {
    setNextSteps((prev) => prev.map((s, idx) => (idx === i ? value : s)))
  }

  return (
    <div>
      <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">
        ← Back to engagement
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Report & Export</h1>
          <p className="mt-1 text-sm text-gray-400">Client-ready discovery report</p>
        </div>
        <div className="flex gap-2">
          {[['json', 'JSON'], ['csv', 'CSV'], ['pdf', 'PDF']].map(([f, label]) => (
            <button
              key={f}
              onClick={() => handleExport(f)}
              className="rounded border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 hover:border-gray-500"
            >
              {exporting === f ? 'Exporting...' : `Export ${label}`}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-6">
        {/* Executive summary */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h2 className="mb-4 text-lg font-bold">Executive Summary</h2>
          <div className="grid grid-cols-3 gap-4">
            <SummaryStat label="Coverage" value={`${coveragePct}%`} sub={`${scan?.hosts_discovered || 0} live of ${scan?.hosts_total_in_scope || 0} in-scope`} />
            <SummaryStat label="Hosts" value={hosts?.length || 0} sub="discovered" />
            <SummaryStat label="Findings" value={findings?.length || 0} sub={`${severityBreakdown.filter((s) => s.count > 0).length} severities`} />
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <h3 className="mb-4 font-medium">Device Breakdown</h3>
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={deviceBreakdown} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                  {deviceBreakdown.map((entry, i) => (
                    <Cell key={i} fill={['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B', '#EF4444', '#06B6D4'][i % 6]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: 'none', borderRadius: '8px', color: '#fff' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <h3 className="mb-4 font-medium">Findings by Severity</h3>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={severityBreakdown}>
                <XAxis dataKey="name" stroke="#9CA3AF" />
                <YAxis allowDecimals={false} stroke="#9CA3AF" />
                <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: 'none', borderRadius: '8px', color: '#fff' }} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                <Bar dataKey="count">
                  {severityBreakdown.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Coverage & limitations */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h3 className="mb-3 font-medium">Coverage & Limitations</h3>
          <div className="grid grid-cols-2 gap-6 text-sm">
            <div>
              <h4 className="mb-2 text-gray-400">Scope Covered</h4>
              <ul className="space-y-1 text-gray-300">
                <li className="mono">{scan?.targets.join(', ') || '—'}</li>
                <li>Profile: <span className="capitalize">{scan?.profile?.replace('_', ' ')}</span></li>
                <li>Port range: <span className="mono">{scan?.port_range}</span></li>
              </ul>
            </div>
            <div>
              <h4 className="mb-2 text-gray-400">Limitations</h4>
              <ul className="list-inside list-disc space-y-1 text-gray-300">
                <li>Hosts that filter ICMP may not be detected</li>
                <li>Passive-only scans do not enumerate open ports</li>
                <li>OS/banner identification depends on scan timing and host response</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Next steps */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h3 className="mb-3 font-medium">Prioritized Next Steps</h3>
          <div className="space-y-2">
            {nextSteps.map((step, i) => (
              <input
                key={i}
                value={step}
                onChange={(e) => updateNextStep(i, e.target.value)}
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function SummaryStat({ label, value, sub }: { label: string; value: React.ReactNode; sub: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-white">{value}</div>
      <div className="mt-1 text-xs text-gray-500">{sub}</div>
    </div>
  )
}
