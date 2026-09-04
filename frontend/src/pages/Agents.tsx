import { useState } from 'react'
import { useAgents, useCreateAgent, useDeleteAgent } from '../hooks/useApi'

export default function Agents() {
  const { data: agents, isLoading } = useAgents()
  const create = useCreateAgent()
  const del = useDeleteAgent()
  const [name, setName] = useState('')
  const [subnets, setSubnets] = useState('')
  const [notes, setNotes] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)

  const submit = async () => {
    if (!name.trim()) return
    const res = await create.mutateAsync({
      name: name.trim(),
      subnets: subnets.split(',').map((s) => s.trim()).filter(Boolean),
      notes,
    })
    setNewKey(res.api_key)
    setName('')
    setSubnets('')
    setNotes('')
  }

  const clearKey = () => setNewKey(null)

  const pill = (s: string) => {
    const map: Record<string, string> = {
      online: 'bg-emerald-500/15 text-emerald-300',
      offline: 'bg-gray-500/15 text-gray-400',
      disabled: 'bg-red-500/15 text-red-300',
    }
    const cls = map[s] || map.offline
    return (
      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>{s}</span>
    )
  }

  if (isLoading) return <div className="py-12 text-center text-gray-400">Loading agents...</div>

  return (
    <div className="max-w-5xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scanner Agents</h1>
          <p className="mt-1 text-sm text-gray-400">
            Run one of these on any machine that sits on the target LAN to enable full Layer-2
            discovery (ARP → MAC/vendor, SYN + OS fingerprinting) — no SSH bridge required.
          </p>
        </div>
      </div>

      {newKey && (
        <div className="mb-6 rounded-lg border border-emerald-700/50 bg-emerald-950/40 p-4">
          <div className="mb-2 text-sm font-semibold text-emerald-300">
            Agent created — copy this API key now (shown once)
          </div>
          <code className="block break-all rounded bg-gray-900 p-3 text-xs text-emerald-200">
            {newKey}
          </code>
          <button onClick={clearKey} className="mt-3 rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600">
            Done
          </button>
        </div>
      )}

      <div className="mb-8 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300">Register a new agent</h2>
        <div className="grid gap-3 md:grid-cols-3">
          <div>
            <label className="mb-1 block text-xs text-gray-500">Name (unique)</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="home-lan-nuc"
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-500">
              Subnets it can reach at L2 (comma-separated)
            </label>
            <input
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder="192.168.1.0/24"
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-500">Notes</label>
            <input
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="optional"
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>
        <button
          onClick={submit}
          disabled={create.isPending || !name.trim()}
          className="mt-3 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
        >
          {create.isPending ? 'Creating…' : 'Create agent'}
        </button>
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Last seen</th>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Subnets</th>
              <th className="px-4 py-3">Capabilities</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {(agents || []).map((a) => (
              <tr key={a.id} className="border-t border-gray-800">
                <td className="px-4 py-3 font-medium text-white">{a.name}</td>
                <td className="px-4 py-3">{pill(a.status)}</td>
                <td className="px-4 py-3 text-gray-400">
                  {a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : '—'}
                </td>
                <td className="px-4 py-3 text-gray-400">
                  {a.hostname || '—'}
                  {a.version ? <span className="ml-2 text-xs text-gray-600">v{a.version}</span> : null}
                </td>
                <td className="px-4 py-3 text-gray-400">{(a.subnets || []).join(', ') || '—'}</td>
                <td className="px-4 py-3 text-gray-400">{(a.capabilities || []).join(', ') || '—'}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => {
                      if (window.confirm(`Delete agent '${a.name}'?`)) del.mutate(a.id)
                    }}
                    className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-500/10"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {!agents?.length && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No agents registered yet. Create one, run{' '}
                  <code className="text-gray-400">agent/scanner_agent.py</code> on a LAN machine, and
                  scans will automatically prefer it over the L3-only container.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-6">
        <h3 className="mb-2 text-sm font-semibold text-gray-300">Run it</h3>
        <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-900 p-4 text-xs text-gray-300">
{`# Linux (root gives ARP + SYN):
python agent/scanner_agent.py --server http://<SERVER_IP>:8000 --name my-lan \
  --api-key <KEY> --subnets 192.168.1.0/24

# Or in Docker on the LAN host (host networking = real L2):
docker run -d --network=host --cap-add NET_RAW --cap-add NET_ADMIN \\
  -e SCANNER_AGENT_KEY=<KEY> scanner-agent --server http://<SERVER_IP>:8000 --name my-lan

# Windows: install Npcap, use --connect if your user lacks privileges`}
        </pre>
      </div>
    </div>
  )
}