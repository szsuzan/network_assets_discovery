import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useHosts, useFindings } from '../hooks/useApi'
import { DeviceIcon, SeverityBadge } from '../components/SeverityBadge'
import { DEVICE_TYPE_LABELS, SEVERITY_ORDER, normalizeDeviceType, type Host, type Finding } from '../lib/types'
import ScanNav from '../components/ScanNav'

export default function AssetInventory() {
  const { engagementId, scanId } = useParams()
  const { data: hosts, isLoading } = useHosts(scanId)
  const { data: findings } = useFindings(scanId)

  const [search, setSearch] = useState('')
  const [deviceFilter, setDeviceFilter] = useState('all')

  const findingByHost = useMemo(() => {
    const map = new Map<string, Finding[]>()
    findings?.forEach((f) => {
      const key = f.host_id || ''
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(f)
    })
    return map
  }, [findings])

  const worstSeverity = (hostId: string) => {
    const hostFindings = findingByHost.get(hostId) || []
    if (!hostFindings.length) return null
    for (const sev of SEVERITY_ORDER) {
      if (hostFindings.some((f) => f.severity === sev)) return sev
    }
    return 'info'
  }

  const filtered = useMemo(() => {
    let list = hosts || []
    if (deviceFilter !== 'all') list = list.filter((h) => normalizeDeviceType(h.device_type) === deviceFilter)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(
        (h) =>
          h.ip.toLowerCase().includes(q) ||
          (h.mac || '').toLowerCase().includes(q) ||
          (h.hostname || '').toLowerCase().includes(q) ||
          (h.vendor || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [hosts, search, deviceFilter])

  return (
    <div>
      <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">
        ← Back to engagement
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Asset Inventory</h1>
          <p className="mt-1 text-sm text-gray-400">{filtered.length} of {hosts?.length || 0} hosts</p>
        </div>
        <div className="flex items-center gap-3">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, MAC, vendor..."
            className="rounded border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 mono focus:border-blue-500 outline-none"
          />
          <select
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            className="rounded border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white"
          >
            <option value="all">All device types</option>
            {Object.entries(DEVICE_TYPE_LABELS).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-gray-400">Loading hosts...</div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-gray-400">
              <tr>
                <th className="px-4 py-3 font-medium">IP</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">MAC</th>
                <th className="px-4 py-3 font-medium">Vendor</th>
                <th className="px-4 py-3 font-medium">Hostname</th>
                <th className="px-4 py-3 font-medium">OS</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filtered.map((h: Host) => {
                const sev = worstSeverity(h.id)
                return (
                  <tr key={h.id} className="bg-gray-900/50 hover:bg-gray-800/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/engagements/${engagementId}/scans/${scanId}/host/${h.ip}`}
                        className="mono font-medium text-blue-400 hover:underline"
                      >
                        {h.ip}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <DeviceIcon type={h.device_type || undefined} size="sm" />
                        <span className="text-gray-300">{DEVICE_TYPE_LABELS[normalizeDeviceType(h.device_type)] || normalizeDeviceType(h.device_type)}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 mono text-gray-300">{h.mac || '—'}</td>
                    <td className="px-4 py-3 text-gray-300">{h.vendor || '—'}</td>
                    <td className="px-4 py-3 text-gray-200">{h.hostname || '—'}</td>
                    <td className="px-4 py-3 text-gray-300">
                      {h.os_guess ? (
                        <span>
                          {h.os_guess}
                          {h.os_confidence ? <span className="text-xs text-gray-500"> ({h.os_confidence}%)</span> : null}
                        </span>
                      ) : (
                        <span className="text-black/40">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3"><span className={h.status === 'up' ? 'text-emerald-400' : 'text-gray-400'}>{h.status}</span></td>
                    <td className="px-4 py-3">
                      {sev ? <SeverityBadge severity={sev} /> : <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-400">{new Date(h.last_seen).toLocaleString()}</td>
                  </tr>
                )
              })}
              {!filtered.length && (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-gray-400">
                    No hosts match your filters.
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
