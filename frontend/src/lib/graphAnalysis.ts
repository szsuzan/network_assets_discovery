import { DEVICE_ICONS, normalizeDeviceType } from './types'

export type TopoNode = {
  id: string
  kind: 'host' | 'zone' | 'internet'
  name: string
  ip: string
  device_type: string
  is_gateway: boolean
  severity: Severity
  host_count: number
  out_of_scope?: boolean
  tested?: boolean
  new_since_last_scan?: boolean
  removed?: boolean
  changed?: boolean
  finding_count?: number
  port_count?: number
  internet_facing?: boolean
}

export type Severity = 'info' | 'notable' | 'concerning' | 'critical'

export const SEV_ORDER: Record<Severity, number> = {
  critical: 4,
  concerning: 3,
  notable: 2,
  info: 1,
}

export const SEV_RING: Record<string, string> = {
  critical: '#E04B4B',
  concerning: '#E08341',
  notable: '#E0B341',
  info: '#8B95A1',
}

export type EdgeType = 'l2' | 'l2_adjacency' | 'cdp_lldp' | 'l3' | 'in_subnet' | 'gateway' | 'inferred'

export type TopoLink = {
  id: string
  source: string | TopoNode
  target: string | TopoNode
  type: string
  confidence: number
}

export const EDGE_STYLE: Record<string, { dash: number[]; color: string; width: number }> = {
  l2: { dash: [], color: 'rgba(51,195,240,0.7)', width: 2 },
  l2_adjacency: { dash: [], color: 'rgba(51,195,240,0.6)', width: 1.8 },
  cdp_lldp: { dash: [6, 4], color: 'rgba(99,220,160,0.7)', width: 2.2 },
  l3: { dash: [2, 4], color: 'rgba(148,163,184,0.45)', width: 1.4 },
  inferred: { dash: [2, 5], color: 'rgba(148,163,184,0.4)', width: 1.3 },
  in_subnet: { dash: [2, 5], color: 'rgba(148,163,184,0.3)', width: 1.2 },
  gateway: { dash: [6, 4], color: '#f59e0b', width: 2.6 },
}

// clusters: group hosts by zone id. Zone node owns the cluster; internet sits alone.
export function computeClusters(
  nodes: TopoNode[],
  links: Array<{ source: any; target: any; type: string }>,
  nodeById: Map<string, TopoNode>,
) {
  const zoneByHost = new Map<string, string>()
  for (const l of links) {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id ?? ''
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id ?? ''
    const sN = nodeById.get(s)
    const tN = nodeById.get(t)
    if (sN && sN.kind === 'host' && tN && tN.kind === 'zone') zoneByHost.set(sN.id, tN.id)
    else if (tN && tN.kind === 'host' && sN && sN.kind === 'zone') zoneByHost.set(tN.id, sN.id)
  }

  const clusters: Record<string, { zoneId: string; hostIds: string[]; label: string }> = {}
  const inCluster = new Set<string>()
  for (const n of nodes) {
    const zid = zoneByHost.get(n.id)
    if (zid) {
      inCluster.add(n.id)
      if (!clusters[zid]) {
        const zone = nodeById.get(zid)
        clusters[zid] = { zoneId: zid, hostIds: [], label: zone ? zone.name : zid }
      }
      clusters[zid].hostIds.push(n.id)
    }
  }

  const unclustered = nodes.filter((n) => n.kind === 'host' && !inCluster.has(n.id))

  return { clusters: Object.values(clusters), unclustered, zoneByHost }
}

// BFS shortest path between two node ids (node graph). Returns [] if disconnected.
export function shortestPath(
  nodeIds: string[],
  links: Array<{ source: any; target: any }>,
  start: string,
  end: string,
): string[] {
  if (start === end) return [start]
  const adj = new Map<string, string[]>()
  for (const id of nodeIds) adj.set(id, [])
  for (const l of links) {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id ?? ''
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id ?? ''
    if (!adj.has(s)) adj.set(s, [])
    if (!adj.has(t)) adj.set(t, [])
    adj.get(s)!.push(t)
    adj.get(t)!.push(s)
  }
  const prev = new Map<string, string>()
  const seen = new Set<string>([start])
  const queue = [start]
  while (queue.length) {
    const cur = queue.shift()!
    if (cur === end) {
      const path = [cur]
      let p = cur
      while (prev.has(p)) { p = prev.get(p)!; path.unshift(p) }
      return path
    }
    for (const nb of adj.get(cur) || []) {
      if (seen.has(nb)) continue
      seen.add(nb)
      prev.set(nb, cur)
      queue.push(nb)
    }
  }
  return []
}

// Pivot points: hosts that bridge two otherwise-separated connected components.
// A host is a pivot if removing it increases the number of connected components.
export function detectPivots(
  nodeIds: string[],
  links: Array<{ source: any; target: any }>,
  kindOf: (id: string) => string,
): string[] {
  const adj = new Map<string, string[]>()
  for (const id of nodeIds) adj.set(id, [])
  for (const l of links) {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id ?? ''
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id ?? ''
    if (!adj.has(s)) adj.set(s, [])
    if (!adj.has(t)) adj.set(t, [])
    adj.get(s)!.push(t)
    adj.get(t)!.push(s)
  }
  const hostIds = nodeIds.filter((id) => kindOf(id) === 'host')

  const countComponents = (exclude: string | null): number => {
    const seen = new Set<string>()
    let comps = 0
    for (const id of nodeIds) {
      if (id === exclude || seen.has(id)) continue
      comps++
      const stack = [id]
      seen.add(id)
      while (stack.length) {
        const cur = stack.pop()!
        for (const nb of adj.get(cur) || []) {
          if (nb === exclude || seen.has(nb)) continue
          seen.add(nb)
          stack.push(nb)
        }
      }
    }
    return comps
  }

  const base = countComponents(null)
  const pivots = hostIds.filter((h) => countComponents(h) > base)
  return pivots
}

// Mark internet-facing nodes: any host that connects (directly or transitively)
// to the "internet" node.
export function computeInternetFacing(
  nodes: TopoNode[],
  links: Array<{ source: any; target: any }>,
  nodeById: Map<string, TopoNode>,
): Set<string> {
  const internetIds = nodes.filter((n) => n.kind === 'internet').map((n) => n.id)
  if (!internetIds.length) return new Set()
  const adj = new Map<string, string[]>()
  for (const n of nodes) adj.set(n.id, [])
  for (const l of links) {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id ?? ''
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id ?? ''
    if (!adj.has(s)) adj.set(s, [])
    if (!adj.has(t)) adj.set(t, [])
    adj.get(s)!.push(t)
    adj.get(t)!.push(s)
  }
  const reachable = new Set<string>()
  const queue = [...internetIds]
  internetIds.forEach((i) => reachable.add(i))
  while (queue.length) {
    const cur = queue.shift()!
    for (const nb of adj.get(cur) || []) {
      if (reachable.has(nb)) continue
      reachable.add(nb)
      queue.push(nb)
    }
  }
  return reachable
}

export function deviceIcon(type: string): string {
  return DEVICE_ICONS[normalizeDeviceType(type)] || DEVICE_ICONS.unidentified
}
