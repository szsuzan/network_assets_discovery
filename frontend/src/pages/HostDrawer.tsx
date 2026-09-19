import { Fragment, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useHostDetail, usePatchHost } from '../hooks/useApi'
import { DeviceIcon, SeverityBadge } from '../components/SeverityBadge'
import { DEVICE_TYPE_LABELS, normalizeDeviceType } from '../lib/types'
import ScanNav from '../components/ScanNav'
import { useToast } from '../components/Toaster'
import { errText } from '../lib/errors'

export default function HostDrawer() {
  const { engagementId, scanId, hostIp } = useParams()
  const { data: host, isLoading } = useHostDetail(scanId, hostIp)
  const patchHost = usePatchHost(scanId!, hostIp!)
  const toast = useToast()

  const [notes, setNotes] = useState('')
  const [tagInput, setTagInput] = useState('')
  const [expandedPorts, setExpandedPorts] = useState<Set<string>>(new Set())

  const togglePort = (portId: string) => {
    setExpandedPorts((prev) => {
      const next = new Set(prev)
      if (next.has(portId)) {
        next.delete(portId)
      } else {
        next.add(portId)
      }
      return next
    })
  }

  useEffect(() => {
    if (host) setNotes(host.notes || '')
  }, [host])

  const saveNotes = async () => {
    try {
      await patchHost.mutateAsync({ notes })
      toast.success('Host notes saved')
    } catch (err) {
      toast.error(errText(err, 'Could not save notes'))
    }
  }

  const addTag = async () => {
    if (!tagInput.trim()) return
    const current = host?.tags || []
    try {
      await patchHost.mutateAsync({ tags: [...current, tagInput.trim()] })
      setTagInput('')
      toast.success(`Tag "${tagInput.trim()}" added`)
    } catch (err) {
      toast.error(errText(err, 'Could not add tag'))
    }
  }

  const removeTag = async (tag: string) => {
    try {
      await patchHost.mutateAsync({ tags: (host?.tags || []).filter((t) => t !== tag) })
      toast.success(`Tag "${tag}" removed`)
    } catch (err) {
      toast.error(errText(err, 'Could not remove tag'))
    }
  }

  return (
    <div>
      <Link to={`/engagements/${engagementId}/scans/${scanId}/inventory`} className="text-sm text-gray-400 hover:text-white">
        ← Back to inventory
      </Link>
      <ScanNav engagementId={engagementId!} scanId={scanId!} />

      {isLoading || !host ? (
        <div className="py-12 text-center text-gray-400">Loading host...</div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Host info */}
          <div className="self-start rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="mb-4 flex items-center gap-3">
              <DeviceIcon type={host.device_type || undefined} size="lg" />
              <div>
                <h1 className="mono text-2xl font-bold text-white">{hostIp}</h1>
                {host.hostname && <p className="text-sm text-gray-400">{host.hostname}</p>}
              </div>
            </div>

            <dl className="space-y-3 text-sm">
              <Row label="Type"><>{DEVICE_TYPE_LABELS[normalizeDeviceType(host.device_type)] || host.device_type || '—'}</></Row>
              <Row label="MAC"><span className="mono">{host.mac || '—'}</span></Row>
              <Row label="Vendor">{host.vendor || '—'}</Row>
              <Row label="OS">
                <>{host.os_guess || '—'}{host.os_confidence ? <span className="text-xs text-gray-500"> ({host.os_confidence}%)</span> : null}</>
              </Row>
              <Row label="Status"><span className={host.status === 'up' ? 'text-emerald-400' : 'text-gray-400'}>{host.status}</span></Row>
              <Row label="First Seen">{new Date(host.first_seen).toLocaleString()}</Row>
              <Row label="Last Seen">{new Date(host.last_seen).toLocaleString()}</Row>
            </dl>

            {/* Tags */}
            <div className="mt-6">
              <h3 className="mb-2 text-sm font-medium text-gray-400">Tags</h3>
              <div className="flex flex-wrap gap-1.5">
                {(host.tags || []).map((tag) => (
                  <button
                    key={tag}
                    onClick={() => removeTag(tag)}
                    className="group flex items-center gap-1 rounded bg-blue-500/20 px-2 py-0.5 text-xs text-blue-300 hover:bg-blue-500/40"
                  >
                    {tag}
                    <span className="text-blue-400 group-hover:text-white">×</span>
                  </button>
                ))}
                {!(host.tags || []).length && <span className="text-xs text-gray-600">No tags</span>}
              </div>
              <div className="mt-2 flex gap-2">
                <input
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addTag()}
                  placeholder="Add tag..."
                  className="flex-1 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-sm text-white outline-none focus:border-blue-500"
                />
                <button onClick={addTag} className="rounded bg-gray-700 px-3 text-sm text-white hover:bg-gray-600">Add</button>
              </div>
            </div>

            {/* Notes */}
            <div className="mt-6">
              <h3 className="mb-2 text-sm font-medium text-gray-400">Notes</h3>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Add pentest notes for this host..."
                rows={4}
                className="w-full rounded border border-gray-700 bg-gray-800 p-2 text-sm text-white outline-none focus:border-blue-500"
              />
              <button
                onClick={saveNotes}
                disabled={patchHost.isPending}
                className="mt-2 rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
              >
                Save Notes
              </button>
            </div>
          </div>

          {/* Ports + SNMP */}
          <div className="lg:col-span-2 space-y-6">
            <div className="rounded-lg border border-gray-800 bg-gray-900">
              <h2 className="border-b border-gray-800 bg-gray-900/70 px-4 py-3 font-medium">Open Ports ({host.ports?.length || 0})</h2>
              <table className="w-full table-fixed text-sm">
                <colgroup>
                  <col className="w-[12%]" />
                  <col className="w-[10%]" />
                  <col className="w-[14%]" />
                  <col className="w-[16%]" />
                  <col />
                </colgroup>
                <thead className="bg-gray-900/50 text-left text-gray-400">
                  <tr>
                    <th className="px-4 py-2 font-medium">Port</th>
                    <th className="px-4 py-2 font-medium">State</th>
                    <th className="px-4 py-2 font-medium">Service</th>
                    <th className="px-4 py-2 font-medium">Version</th>
                    <th className="px-4 py-2 font-medium">Banner</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {(host.ports || []).map((p) => {
                    const portScripts = p.scripts || []
                    const expanded = expandedPorts.has(p.id)
                    return (
                      <Fragment key={p.id}>
                        <tr
                          className={'cursor-pointer border-t border-gray-800 bg-gray-900/50 hover:bg-gray-800' + (expanded ? ' bg-gray-800' : '')}
                          onClick={() => togglePort(p.id)}
                          title="Click to expand port details"
                        >
                          <td className="mono px-4 py-2 text-blue-400">{p.port}/{p.protocol}</td>
                          <td className="px-4 py-2 text-emerald-400">{p.state}</td>
                          <td className="px-4 py-2 text-gray-200">{p.service || '—'}</td>
                          <td className="px-4 py-2 text-gray-400">{p.version || '—'}</td>
                          <td className="max-w-64 truncate px-4 py-2 text-gray-400 mono text-xs">
                            {p.banner || '—'}
                            {portScripts.length > 0 && (
                              <span className="ml-2 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400">
                                {expanded ? '▾' : '▸'} {portScripts.length} script{portScripts.length === 1 ? '' : 's'}
                              </span>
                            )}
                          </td>
                        </tr>
                        {expanded && (
                          <tr>
                            <td colSpan={5} className="bg-gray-950 px-4 py-3">
                              <div className="space-y-3">
                                {portScripts.length === 0 && (
                                  <div className="rounded border border-gray-800 bg-gray-900/40 px-3 py-3">
                                    <p className="text-xs text-gray-400">
                                      No NSE scripts captured for this port.
                                      {p.version && <span> Version detected: <span className="text-gray-200">{p.version}</span></span>}
                                      {p.banner && <span> Banner: <span className="mono text-gray-200">{p.banner}</span></span>}
                                    </p>
                                  </div>
                                )}
                                {portScripts.map((s) => (
                                  <div key={s.id} className="overflow-hidden rounded border border-gray-800 bg-gray-900/70">
                                    <div className="mono border-b border-gray-800 bg-gray-900 px-3 py-1.5 text-xs font-medium text-amber-400">
                                      {s.id}
                                    </div>
                                    <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap px-3 py-2 text-xs leading-relaxed text-gray-300">
                                      {s.output || '(no output)'}
                                    </pre>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                  {!host.ports?.length && (
                    <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No open ports detected</td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {host.snmp && (
              <div className="rounded-lg border border-gray-800 bg-gray-900">
                <h2 className="border-b border-gray-800 bg-gray-900/70 px-4 py-3 font-medium">SNMP</h2>
                <dl className="space-y-2 p-4 text-sm">
                  <Row label="System Name">{host.snmp.sys_name || '—'}</Row>
                  <Row label="System Description">{host.snmp.sys_descr || '—'}</Row>
                  <Row label="Location">{host.snmp.sys_location || '—'}</Row>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-500">Default community:</span>
                    {host.snmp.default_community_found
                      ? <SeverityBadge severity="notable" />
                      : <span className="text-emerald-400">Not found</span>}
                  </div>
                </dl>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-gray-500">{label}</dt>
      <dd className="text-right text-gray-300">{children}</dd>
    </div>
  )
}
