import * as d3Force from 'd3-force'
import type { TopoNode, TopoLink } from './graphAnalysis'

export type LayoutMode = 'force' | 'hierarchical' | 'radial' | 'matrix'

export type Cluster = {
  id: string
  label: string
  hostIds: string[]
  x: number
  y: number
  r: number
  collapsed: boolean
}

export type GraphNode = TopoNode & {
  x: number
  y: number
  vx?: number
  vy?: number
  fx?: number | null
  fy?: number | null
  r: number
  size: number
  clusterId?: string
  isCluster?: boolean
  idx: number
  hidden?: boolean
}

export type ComputedGraph = {
  nodes: GraphNode[]
  links: Array<TopoLink & { source: any; target: any }>
  clusters: Record<string, Cluster>
  bounds: { x: number; y: number; w: number; h: number }
}

// Node significance: open port count + highest finding severity.
export function computeNodeSize(node: TopoNode): number {
  const base = 7
  const portScore = Math.min(node.port_count || 0, 40) * 0.25
  const sevScore = (SEV_VAL[node.severity] || 1) * 2.5
  const findingScale = node.finding_count ? Math.min(node.finding_count, 10) * 0.6 : 0
  return clamp(base + portScore + sevScore + findingScale, 8, 26)
}

const SEV_VAL: Record<string, number> = { info: 1, notable: 2, concerning: 3, critical: 4 }

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v))
}

function sevOf(node: any): string {
  return node.severity || 'info'
}

function nodePosOf(a: any): TopoNode | undefined {
  return typeof a === 'object' && a ? (a as TopoNode) : undefined
}

function edgeWeight(l: any): number {
  const t = (l as any).type || (l as any).edge_type || ''
  if (t === 'cdp_lldp') return 3
  if (t === 'gateway') return 3
  if (t === 'l2' || t === 'l2_adjacency') return 2
  if (t === 'l3') return 1.5
  return 1
}

export type LayoutInput = {
  nodes: TopoNode[]
  links: Array<{ source: any; target: any; type: string }>
  width: number
  height: number
  mode: LayoutMode
  clusters: Array<{ zoneId: string; hostIds: string[]; label: string }>
  collapsedClusters: Set<string>
  focus?: string | null
}

const PAD = 60

// Maps a computed layout's node coordinates back into the fixed canvas box
// ([0,width] x [0,height], padded). Because force / radial / hierarchical
// layouts can run far outside the viewport, without this ForceGraph2D grows
// its scrollable canvas unboundedly. Keeps node aspect ratio by uniform scale.
function fitToCanvas(g: ComputedGraph, width: number, height: number): ComputedGraph {
  const pts = g.nodes
  if (!pts.length) return g
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of pts) {
    if (n.x < minX) minX = n.x
    if (n.x > maxX) maxX = n.x
    if (n.y < minY) minY = n.y
    if (n.y > maxY) maxY = n.y
  }
  const w = maxX - minX
  const h = maxY - minY
  if (w <= 0 || h <= 0 || !isFinite(w) || !isFinite(h)) return g
  const cx = (minX + maxX) / 2
  const cy = (minY + maxY) / 2
  const scale = Math.min(
    (width - PAD * 2) / w,
    (height - PAD * 2) / h,
    2.5, // don't blow up small graphs beyond readability
  )
  for (const n of pts) {
    n.x = width / 2 + (n.x - cx) * scale
    n.y = height / 2 + (n.y - cy) * scale
    if (n.fx !== undefined && n.fx !== null) n.fx = n.x
    if (n.fy !== undefined && n.fy !== null) n.fy = n.y
  }
  g.bounds = boundsOf(pts)
  return g
}

const SPACING = 130

export function computeLayout(input: LayoutInput): ComputedGraph {
  const { nodes, links, width, height, mode, collapsedClusters } = input
  const nodeById = new Map<string, TopoNode>()
  nodes.forEach((n) => nodeById.set(n.id, n))

  // Build a set of cluster ids for collapsed clusters.
  const clusterHostSet = new Map<string, Set<string>>()
  input.clusters.forEach((c) => {
    if (collapsedClusters.has(c.zoneId)) clusterHostSet.set(c.zoneId, new Set(c.hostIds))
  })

  // Resolve links to node objects.
  const resolvedLinks: Array<TopoLink & { source: any; target: any }> = []
  for (let i = 0; i < links.length; i++) {
    const l = links[i]
    const s = typeof l.source === 'string' ? nodeById.get(l.source) : nodePosOf(l.source)
    const t = typeof l.target === 'string' ? nodeById.get(l.target) : nodePosOf(l.target)
    if (!s || !t) continue
    const type = (l as any).type || (l as any).edge_type || 'l2'
    resolvedLinks.push({
      id: `${s.id}->${t.id}-${i}`,
      source: s,
      target: t,
      type,
      confidence: (l as any).confidence ?? 1,
    })
  }

  // Recompute graph with collapse applied (cluster hosts → supernode)
  const cg = buildCollapsedGraph(input, nodeById, clusterHostSet)
  const graphNodes = cg.nodes
  const graphLinks = cg.links
  const clusterIndexOf = cg.clusterIndexOf

  // ── 1. FORCE layout ─────────────────────────────────────────────────
  if (mode === 'force') {
    const sim = d3Force.forceSimulation(graphNodes as any)
      .force('charge', d3Force.forceManyBody().strength(-220).distanceMax(width * 0.9))
      .force('link', d3Force.forceLink(graphLinks as any).id((d: any) => d.id).distance(70).strength(0.6))
      .force('center', d3Force.forceCenter(width / 2, height / 2))
      .force('x', d3Force.forceX(width / 2).strength(0.045))
      .force('y', d3Force.forceY(height / 2).strength(0.045))
      .force('collide', d3Force.forceCollide().radius((d: any) => (d.r || 12) + 18).iterations(2))
      .stop()

    // Cluster attracts its own member nodes toward a shared anchor point.
    if (input.clusters.length) {
      const cAngle = (2 * Math.PI) / input.clusters.length
      const anchors = new Map<string, { x: number; y: number }>()
      input.clusters.forEach((c, ci) => {
        const ang = ci * cAngle - Math.PI / 2
        anchors.set(c.zoneId, {
          x: width / 2 + Math.cos(ang) * Math.min(width, height) * 0.3,
          y: height / 2 + Math.sin(ang) * Math.min(width, height) * 0.3,
        })
      })
      sim.force('cluster', makeClusterForce(graphNodes, anchors, input.clusters, clusterIndexOf))
    }

    sim.tick(220)
    // Pin every node so the idle engine cannot perturb the laid-out positions;
    // dragging still works (d3 updates fx/fy directly) thanks to autoPauseRedraw:false.
    const placed = graphNodes.map((n) => ({ ...n, fx: n.x, fy: n.y }))
    return finalizeZoneContainers(fitToCanvas({ nodes: placed, links: graphLinks, clusters: {}, bounds: boundsOf(placed) }, width, height), input)
  }

  // ── 2. HIERARCHICAL layout ──────────────────────────────────────────
  if (mode === 'hierarchical') {
    return finalizeZoneContainers(fitToCanvas(hierarchicalLayout(graphNodes, graphLinks, input.clusters, width, height), width, height), input)
  }

  // ── 3. RADIAL / subnet-grouped layout ───────────────────────────────
  if (mode === 'radial') {
    return finalizeZoneContainers(fitToCanvas(radialLayout(graphNodes, graphLinks, input.clusters, width, height), width, height), input)
  }

  // ── 4. MATRIX layout ────────────────────────────────────────────────
  return finalizeZoneContainers(fitToCanvas(matrixLayout(graphNodes, graphLinks, nodeById, width, height), width, height), input)
}

// After a layout, reposition zone nodes so each dashed container wraps its
// member hosts (centroid + enclosing radius). Zone nodes are drawn as the
// subnet container circles.
function finalizeZoneContainers(g: ComputedGraph, input: LayoutInput): ComputedGraph {
  const { clusters } = input
  if (!clusters.length) return g
  const zoneById = new Map(g.nodes.filter((n) => n.kind === 'zone').map((n) => [n.id, n]))
  const posById = new Map(g.nodes.map((n) => [n.id, { x: n.x, y: n.y }]))

  for (const c of clusters) {
    const zone = zoneById.get(c.zoneId)
    if (!zone) continue
    const memberPts: { x: number; y: number }[] = []
    for (const hid of c.hostIds) {
      const p = posById.get(hid)
      if (p) memberPts.push(p)
    }
    if (!memberPts.length) continue
    let cx = 0, cy = 0
    for (const p of memberPts) { cx += p.x; cy += p.y }
    cx /= memberPts.length
    cy /= memberPts.length
    let maxR = 0
    for (const p of memberPts) {
      const d = Math.hypot(p.x - cx, p.y - cy) + (zone.r || 12)
      if (d > maxR) maxR = d
    }
    zone.x = cx
    zone.y = cy
    zone.fx = cx
    zone.fy = cy
    zone.r = Math.max(maxR + 46, 100)
  }
  return g
}

type CG = {
  nodes: GraphNode[]
  links: Array<TopoLink & { source: any; target: any }>
  clusterIndexOf: Map<string, number>
}

function buildCollapsedGraph(
  input: LayoutInput,
  nodeById: Map<string, TopoNode>,
  clusterHostSet: Map<string, Set<string>>,
): CG {
  const { nodes, links, clusters } = input

  // Collapse = replace a cluster's host nodes with a single "cluster" supernode.
  const clusterHostOf = new Map<string, string>() // hostId -> clusterSuperId
  const clusterSuper = new Map<string, ClusterNode>()
  for (const [zid, hostSet] of clusterHostSet) {
    const ci = clusters.find((c) => c.zoneId === zid)
    const label = ci ? ci.label : zid
    // Reuse the zone node id so existing links that reference it (host→zone,
    // gateway→zone, internet→zone) keep resolving to this supernode.
    const superId = zid
    clusterSuper.set(zid, {
      id: superId,
      kind: 'zone',
      name: label,
      ip: '',
      device_type: '',
      is_gateway: false,
      severity: 'info',
      host_count: hostSet.size,
      isCluster: true,
      clusterId: zid,
      x: 0, y: 0, r: 18, size: 18, idx: 0,
    } as any)
    for (const hostId of hostSet) clusterHostOf.set(hostId, superId)
  }

  const outNodes: GraphNode[] = []
  for (const n of nodes) {
    const superId = clusterHostOf.get(n.id)
    if (superId) continue // collapsed away
    // When a zone's hosts are collapsed into a supernode, drop the zone
    // container node too (the supernode replaces it).
    if (n.kind === 'zone' && clusterSuper.has(n.id)) continue
    outNodes.push({ ...n, x: 0, y: 0, r: computeNodeSize(n), size: computeNodeSize(n), idx: 0 } as any)
  }
  for (const c of clusterSuper.values()) outNodes.push(c as any)

  // Map every output node id → the cloned node object, so links reference the
  // SAME objects present in `outNodes` (force-graph matches by reference).
  const outNodeById = new Map<string, GraphNode>()
  outNodes.forEach((n) => outNodeById.set(n.id, n))

  const outLinks: Array<TopoLink & { source: any; target: any }> = []
  const seen = new Set<string>()
  for (const l of links) {
    const s = nodeById.get(typeof l.source === 'object' ? (l.source as any).id : l.source)
    const t = nodeById.get(typeof l.target === 'object' ? (l.target as any).id : l.target)
    if (!s || !t) continue

    // A cluster supernode may be the endpoint; otherwise use the cloned node.
    const sOrigin = clusterHostOf.get(s.id) || s.id
    const tOrigin = clusterHostOf.get(t.id) || t.id
    const src = outNodeById.get(sOrigin) || sOrigin
    const tgt = outNodeById.get(tOrigin) || tOrigin
    if (src === tgt) continue
    const key = `${sOrigin}|${tOrigin}`
    if (seen.has(key)) continue
    seen.add(key)
    outLinks.push({
      id: key,
      source: src as any,
      target: tgt as any,
      type: (l as any).type || 'l2',
      confidence: (l as any).confidence ?? 1,
    })
  }

  // index clusters among output nodes
  const clusterIndexOf = new Map<string, number>()
  outNodes.forEach((n, i) => { if ((n as any).isCluster) clusterIndexOf.set((n as any).clusterId, i) })

  return { nodes: outNodes, links: outLinks, clusterIndexOf }
}

type ClusterNode = GraphNode

function makeClusterForce(
  nodes: GraphNode[],
  anchors: Map<string, { x: number; y: number }>,
  clusters: Array<{ zoneId: string; hostIds: string[] }>,
  clusterIndexOf: Map<string, number>,
) {
  const idxOfHost = new Map<string, number>()
  nodes.forEach((n, i) => idxOfHost.set(n.id, i))
  return (alpha: number) => {
    const k = alpha * 0.18
    for (const c of clusters) {
      const anchor = anchors.get(c.zoneId)
      if (!anchor) continue
      const members: string[] = [...c.hostIds]
      const superIdx = clusterIndexOf.get(c.zoneId)
      if (superIdx !== undefined) members.push(nodes[superIdx]?.id)
      for (const m of members) {
        const idx = idxOfHost.get(m)
        if (idx === undefined) continue
        const node = nodes[idx]
        node.vx = (node.vx || 0) + (anchor.x - node.x) * k
        node.vy = (node.vy || 0) + (anchor.y - node.y) * k
      }
    }
  }
}

function boundsOf(nodes: GraphNode[]) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of nodes) {
    if (n.x < minX) minX = n.x
    if (n.x > maxX) maxX = n.x
    if (n.y < minY) minY = n.y
    if (n.y > maxY) maxY = n.y
  }
  return { x: minX === Infinity ? 0 : minX - 40, y: minY === Infinity ? 0 : minY - 40, w: (maxX - minX) + 80 || 100, h: (maxY - minY) + 80 || 100 }
}

// ── Hierarchical (top-down): internet → gateway → subnet clusters ────
function hierarchicalLayout(
  nodes: GraphNode[],
  links: Array<TopoLink & { source: any; target: any }>,
  clusterDefs: Array<{ zoneId: string; hostIds: string[]; label: string }>,
  width: number,
  height: number,
): ComputedGraph {
  const result = cloneNodes(nodes)
  const placed = new Map<string, { x: number; y: number }>()
  const byId = new Map(result.map((n) => [n.id, n]))

  // Assign each host to a zone group (only for non-collapsed, real hosts)
  const zoneOfHost = new Map<string, string>()
  clusterDefs.forEach((c) => c.hostIds.forEach((h) => zoneOfHost.set(h, c.zoneId)))
  // collapsed cluster supernodes
  result.forEach((n) => { if ((n as any).isCluster) zoneOfHost.set(n.id, (n as any).clusterId) })

  const internets = result.filter((n) => n.kind === 'internet')
  const gateways = result.filter((n) => n.is_gateway && !(n as any).isCluster)
  const clusterNodes = result.filter((n) => (n as any).isCluster)
  const ordinaryLeaves = result.filter((n) => n.kind === 'host' && !n.is_gateway && !(n as any).isCluster)

  const ROW_H = clamp(height * 0.22, 120, 200)
  const INTERNET_Y = ROW_H * 0.35
  const GW_Y = ROW_H * 1.0
  const CLUSTER_Y = ROW_H * 1.7
  const LEAF_Y = ROW_H * 2.4

  internets.forEach((n) => placed.set(n.id, { x: width / 2, y: INTERNET_Y }))

  // Gateways row
  const gwList = gateways.map((g) => g.id)
  spreadRow(gwList, placed, width / 2, GW_Y, 140)

  // Zone groups: each cluster/zone occupies a horizontal region in the middle
  const zoneIds = [...new Set(clusterDefs.map((c) => c.zoneId))]
  const presentZoneIds = zoneIds.filter((zid) => result.some((n) => n.id === zid && (n as any).isCluster) || clusterDefs.some((c) => c.zoneId === zid))

  if (presentZoneIds.length) {
    const n = presentZoneIds.length
    const regionW = width * 0.85
    const step = regionW / n
    presentZoneIds.forEach((zid, zi) => {
      const zoneX = width / 2 + (zi - (n - 1) / 2) * step
      const zoneMembers = clusterDefs.find((c) => c.zoneId === zid)?.hostIds || []
      const nodeZids = zoneMembers.filter((hid) => byId.has(hid))
      // place cluster supernode at left edge of its region
      const clusterNode = clusterNodes.find((cn) => (cn as any).clusterId === zid)
      if (clusterNode) {
        placed.set(clusterNode.id, { x: zoneX - step * 0.45, y: CLUSTER_Y })
      }
      // place hosts across the region width, one row below the gateway
      spreadRow(nodeZids, placed, zoneX + step * 0.05, CLUSTER_Y, 70)
    })
  }

  // Ordinary leaves (not in any zone)
  const orphanLeaves = ordinaryLeaves.filter((n) => !zoneOfHost.has(n.id)).map((n) => n.id)
  if (orphanLeaves.length) spreadRow(orphanLeaves, placed, width / 2, LEAF_Y, 80)

  const resultNodes = result.map((n) => {
    const p = placed.get(n.id)
    const x = p ? p.x : width / 2
    const y = p ? p.y : height / 2
    return { ...n, x, y, fx: x, fy: y }
  })

  return { nodes: resultNodes, links, clusters: {}, bounds: boundsOf(resultNodes) }
}

function spreadRow(ids: string[], placed: Map<string, { x: number; y: number }>, centerX: number, y: number, step: number) {
  const n = ids.length
  if (!n) return
  const s = Math.min(step, Math.max(40, step))
  const start = centerX - ((n - 1) * s) / 2
  ids.forEach((id, i) => placed.set(id, { x: start + i * s, y }))
}

// ── Radial: one ring per subnet/VLAN, hosts arranged radially ────────
function radialLayout(
  nodes: GraphNode[],
  links: Array<TopoLink & { source: any; target: any }>,
  clusterDefs: Array<{ zoneId: string; hostIds: string[]; label: string }>,
  width: number,
  height: number,
): ComputedGraph {
  const result = cloneNodes(nodes)
  const placed = new Map<string, { x: number; y: number }>()
  const byId = new Map(result.map((n) => [n.id, n]))

  const centerX = width / 2
  const centerY = height / 2

  // internet at very center, then a ring of gateways, then subnet rings.
  result.filter((n) => n.kind === 'internet').forEach((n) => placed.set(n.id, { x: centerX, y: centerY - height * 0.05 }))

  const zoneIdSet = new Set(clusterDefs.map((c) => c.zoneId))
  // collapsed supernodes form their own "zone" ring
  result.forEach((n) => { if ((n as any).isCluster && (n as any).clusterId) zoneIdSet.add((n as any).clusterId) })

  const zoneIds = [...zoneIdSet]
  const nZones = Math.max(1, zoneIds.length)
  const zAngle = (2 * Math.PI) / nZones
  let zIndex = 0

  const zoneRingR = clamp(Math.min(width, height) * 0.2, 110, 180)
  const hostRingR = clamp(Math.min(width, height) * 0.38, 180, 340)

  for (const zid of zoneIds) {
    const ang = zIndex * zAngle - Math.PI / 2
    const zx = centerX + Math.cos(ang) * zoneRingR
    const zy = centerY + Math.sin(ang) * zoneRingR
    zIndex++

    // gateway(s) of this subnet sit on the inner ring near the zone angle
    const members = clusterDefs.find((c) => c.zoneId === zid)?.hostIds || []
    // place any cluster supernode at the zone center
    const superNode = result.find((n) => (n as any).isCluster && (n as any).clusterId === zid)
    if (superNode) placed.set(superNode.id, { x: zx, y: zy })

    // hosts on an arc around their zone axis
    const hostIds = members.filter((hid) => byId.has(hid))
    if (hostIds.length) {
      const n = hostIds.length
      const baseAngle = ang
      const spread = clamp(Math.PI / Math.max(1, Math.ceil(n / 4)), Math.PI / 8, Math.PI / 1.2)
      hostIds.forEach((hid, hi) => {
        const ha = baseAngle + (hi / Math.max(1, n - 1)) * spread - spread / 2
        placed.set(hid, { x: zx + Math.cos(ha) * hostRingR * 0.6, y: zy + Math.sin(ha) * hostRingR * 0.6 })
      })
    }
  }

  // Orphan hosts (no zone) in a loose far ring
  const orphans = result.filter((n) => n.kind === 'host' && !(n as any).isCluster && !placed.has(n.id))
  orphans.forEach((n, i) => {
    const ang = (2 * Math.PI * i) / Math.max(1, orphans.length)
    placed.set(n.id, { x: centerX + Math.cos(ang) * hostRingR, y: centerY + Math.sin(ang) * hostRingR })
  })

  const resultNodes = result.map((n) => {
    const p = placed.get(n.id)
    const x = p ? p.x : centerX
    const y = p ? p.y : centerY
    return { ...n, x, y, fx: x, fy: y }
  })

  return { nodes: resultNodes, links, clusters: {}, bounds: boundsOf(resultNodes) }
}

// ── Matrix: grid layout with sensible positions ──────────────────────
function matrixLayout(
  nodes: GraphNode[],
  links: Array<TopoLink & { source: any; target: any }>,
  nodeById: Map<string, TopoNode>,
  width: number,
  height: number,
): ComputedGraph {
  const result = cloneNodes(nodes)
  const n = result.length
  const cols = Math.ceil(Math.sqrt(n * (width / height)))
  const stepX = Math.min(90, width / cols)
  const rows = Math.ceil(n / cols)
  const stepY = Math.min(70, height / rows)
  const startX = width / 2 - ((cols - 1) * stepX) / 2
  const startY = height / 2 - ((rows - 1) * stepY) / 2
  result.forEach((node, i) => {
    const col = i % cols
    const row = Math.floor(i / cols)
    node.x = startX + col * stepX
    node.y = startY + row * stepY
  })
  return { nodes: result, links, clusters: {}, bounds: boundsOf(result) }
}

function cloneNodes(nodes: GraphNode[]): GraphNode[] {
  return nodes.map((n) => ({ ...n }))
}
