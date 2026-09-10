import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import ForceGraph2D from 'react-force-graph-2d'
import { useTopology, useFindings, useHostDetail } from '../hooks/useApi'
import ScanNav from '../components/ScanNav'
import { SEV_RING, EDGE_STYLE, EDGE_STYLE_LIGHT, deviceIcon, detectPivots, computeInternetFacing, type TopoNode } from '../lib/graphAnalysis'
import { DEVICE_TYPE_LABELS, normalizeDeviceType } from '../lib/types'
import { useTheme } from '../lib/theme'
import TopologyMinimap from '../components/TopologyMinimap'

// Escape text for safe insertion into the hover tooltip's innerHTML. Values
// originate from scan data / device labels, so the five HTML-significant chars
// must always be escaped to keep stored XSS (e.g. a hostile hostname) inert.
const esc = (s: unknown): string =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    (({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }) as Record<string, string>)[c],
  )

type HostNode = {
  id: string
  kind: 'host' | 'zone' | 'internet'
  name: string
  ip: string
  device_type: string
  severity: string
  host_count: number
  finding_count: number
  is_gateway: boolean
  x?: number
  y?: number
  vx?: number
  vy?: number
  fx?: number
  fy?: number
  _filtered?: boolean
  _zoneR?: number
}

// Compute a fixed, deterministic top-down layout and set x/y/fx/fy on every
// node so the initial render IS the permanent layout (the force simulation
// cannot move pinned nodes). Mirrors: internet top -> gateways -> zones ->
// hosts in centered circles.
function ipKey(id: string) {
  return id
    .split('.')
    .map((p) => Number(p).toString().padStart(3, '0'))
    .join('.')
}

function computeStaticLayout(nodes: HostNode[], links: { source: any; target: any; type: string }[]) {
  // zone -> member host ids
  const zoneByHost = new Map<string, string>()
  for (const l of links) {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
    const sN = nodes.find((n) => n.id === s)
    const tN = nodes.find((n) => n.id === t)
    if (sN?.kind === 'host' && tN?.kind === 'zone') zoneByHost.set(s, t)
    else if (tN?.kind === 'host' && sN?.kind === 'zone') zoneByHost.set(t, s)
  }

  const internet = nodes.find((n) => n.kind === 'internet')
  const zones = nodes.filter((n) => n.kind === 'zone')

  const centerX = 0

  // Build band descriptors with ring radius + gateway per zone.
  // Ring radius grows linearly with host count so neighbours stay EXACTLY
  // `gap` apart around the circle (their 16u hit-areas never overlap); the
  // dotted subnet border scales too — a margin that grows with the ring.
  const gap = 48
  const bands = zones.map((zone) => {
    const hosts = nodes
      .filter((n) => n.kind === 'host' && zoneByHost.get(n.id) === zone.id)
      .sort((a, b) => ipKey(a.id).localeCompare(ipKey(b.id)))
    const ringR = hosts.length ? Math.max(45, (hosts.length * gap) / (2 * Math.PI)) : 45
    return { zone, hosts, ringR }
  })

  // Dotted-border margin: constant ring-to-border spacing, same as the
  // original. Hosts sit on the ring; the border stays `zonePad` outside it
  // regardless of how many hosts are in the subnet.
  const zonePad = 40
  const outerOf = (b: (typeof bands)[number]) => b.ringR + zonePad
  const zoneGap = 70 // horizontal gap between neighbouring zone circles
  const rowGap = 90 // vertical gap between stacked rows

  // Pack zones into centered rows. A handful of zones keep the classic single
  // row at y=175; many zones wrap into compact rows so a wide scan still fits.
  const cols = bands.length > 8 ? Math.max(2, Math.ceil(Math.sqrt(bands.length * 1.5))) : bands.length
  const rows: { y: number; x: number; maxOuter: number; band: (typeof bands)[number] }[] = []

  for (let i = 0; i < bands.length; i += cols) {
    const rowBands = bands.slice(i, i + cols)
    const outer = rowBands.map(outerOf)
    const maxOuter = Math.max(...outer)
    const totalW = outer.reduce((a, b) => a + b, 0) * 2 + (rowBands.length - 1) * zoneGap
    // First band row sits below the pinned internet node; later rows go deeper.
    const y = i === 0 ? 175 : rows[rows.length - 1].y + rows[rows.length - 1].maxOuter + maxOuter + rowGap
    let x = -totalW / 2
    for (const b of rowBands) {
      x += outerOf(b)
      rows.push({ y, x, maxOuter, band: b })
      x += outerOf(b) + zoneGap
    }
  }

  const floorY = rows.length ? Math.max(...rows.map((r) => r.y)) + Math.max(...rows.map((r) => r.maxOuter)) : 175

  // Internet: pinned to the LEFT of the subnet circles (outside the ring),
  // aligned with the top band row so the gateway links run out to it. With no
  // zones at all it falls back to top-center.
  if (internet) {
    if (bands.length) {
      const leftmost = Math.min(...rows.map((r) => r.x - outerOf(r.band)))
      const margin = 90 // clear of the dotted circle + breathing room
      internet.x = centerX + leftmost - margin
      internet.y = rows[0].y
    } else {
      internet.x = centerX
      internet.y = 0
    }
    internet.fx = internet.x
    internet.fy = internet.y
  }

  const placedIds = new Set<string>()

  // Place every zone at its packed spot, its hosts on an equal-distance circle
  // around it (clockwise, ascending IP — lowest IP at top).
  for (const { y, x, band: b } of rows) {
    const zx = x
    const zy = y
    b.zone.x = zx
    b.zone.y = zy
    b.zone.fx = zx
    b.zone.fy = zy
    b.zone._zoneR = b.ringR + zonePad
    placedIds.add(b.zone.id)

    const startAngle = -Math.PI / 2
    b.hosts.forEach((h, hi) => {
      const angle = startAngle + (hi / Math.max(1, b.hosts.length)) * Math.PI * 2
      const hx = zx + b.ringR * Math.cos(angle)
      const hy = zy + b.ringR * Math.sin(angle)
      h.x = hx
      h.y = hy
      h.fx = hx
      h.fy = hy
      placedIds.add(h.id)
    })
  }

  // Leftover hosts (defensive: only happen if a host's zone link is missing
  // or there are no zones at all) get their own ring(s) hanging below the
  // bands — any count keeps a tidy circle instead of a stray line.
  const leftover = nodes
    .filter((n) => n.kind === 'host' && !placedIds.has(n.id))
    .sort((a, b) => ipKey(a.id).localeCompare(ipKey(b.id)))
  if (leftover.length) {
    const ringR = leftover.length ? Math.max(45, (leftover.length * gap) / (2 * Math.PI)) : 45
    const cx = centerX
    const cy = floorY + 110 + ringR
    const startAngle = -Math.PI / 2
    leftover.forEach((h, hi) => {
      const angle = startAngle + (hi / Math.max(1, leftover.length)) * Math.PI * 2
      h.x = cx + ringR * Math.cos(angle)
      h.y = cy + ringR * Math.sin(angle)
      h.fx = h.x
      h.fy = h.y
    })
  }

  // Safety net: anything still unpinned (unknown kinds, etc.) gets a row well
  // below everything else so no node is ever left at the origin.
  const unr = nodes.filter((n) => n.fx == null)
  if (unr.length) {
    const extraY = leftover.length ? floorY + 110 + (leftover.length * gap) / (2 * Math.PI) + 140 : floorY + 160
    unr.forEach((n, i) => {
      const ux = centerX + (i - (unr.length - 1) / 2) * 90
      n.x = ux
      n.y = extraY
      n.fx = ux
      n.fy = extraY
    })
  }
}

// ────────────────────────────────────────────────────────────────────────
// Canvas painting helpers
// ────────────────────────────────────────────────────────────────────────

function drawInternetCloud(ctx: CanvasRenderingContext2D, node: any, scale: number, dark: boolean) {
  const x = node.x || 0
  const y = node.y || 0
  const u = 1 / scale // unit so size stays constant on screen

  ctx.save()
  ctx.translate(x, y)

  // Rounded node panel sized to the actual text so "Internet" always sits
  // fully inside the rectangle (icon on the left, label on the right), with a
  // clear gap between the cloud logo and the text.
  ctx.font = `${11 / scale}px monospace`
  ctx.textAlign = 'left'
  ctx.textBaseline = 'middle'
  const textW = ctx.measureText('Internet').width
  const w = textW + 52 * u
  const h = 22 * u
  const r = 6 * u
  ctx.beginPath()
  ctx.moveTo(-w / 2 + r, -h / 2)
  ctx.arcTo(w / 2, -h / 2, w / 2, h / 2, r)
  ctx.arcTo(w / 2, h / 2, -w / 2, h / 2, r)
  ctx.arcTo(-w / 2, h / 2, -w / 2, -h / 2, r)
  ctx.arcTo(-w / 2, -h / 2, w / 2, -h / 2, r)
  ctx.closePath()
  ctx.fillStyle = dark ? 'rgba(51,65,85,0.85)' : 'rgba(255,255,255,0.96)'
  ctx.fill()
  ctx.strokeStyle = dark ? 'rgba(148,163,184,0.6)' : 'rgba(100,116,139,0.8)'
  ctx.lineWidth = 1.2 / scale
  ctx.stroke()

  // Cloud icon (left)
  const cx = -w / 2 + 14 * u
  const cy = 0
  const cr = 5 * u
  ctx.beginPath()
  ctx.arc(cx - cr * 0.9, cy, cr * 0.8, Math.PI * 0.5, Math.PI * 1.6)
  ctx.arc(cx - cr * 0.2, cy - cr * 0.7, cr * 0.8, Math.PI * 0.95, Math.PI * 0.35)
  ctx.arc(cx + cr * 0.8, cy - cr * 0.35, cr * 0.85, Math.PI * 1.4, Math.PI * 0.45)
  ctx.arc(cx + cr * 1.1, cy, cr * 0.75, Math.PI * 1.6, Math.PI * 0.6)
  ctx.arc(cx, cy, cr * 1.2, 0, Math.PI * 2)
  ctx.closePath()
  ctx.fillStyle = dark ? '#94a3b8' : '#475569'
  ctx.fill()

  // "Internet" text (right of cloud, clear of the logo)
  ctx.fillStyle = dark ? '#e2e8f0' : '#111827'
  ctx.fillText('Internet', -w / 2 + 26 * u, 0)

  ctx.restore()
}

function drawZoneContainer(ctx: CanvasRenderingContext2D, node: any, scale: number, dark: boolean) {
  const x = node.x || 0
  const y = node.y || 0
  const r = Math.max(30, node._zoneR || 60)

  ctx.save()
  ctx.translate(x, y)

  // Dotted circle — line width counter-scaled to stay thin
  ctx.beginPath()
  ctx.arc(0, 0, r, 0, Math.PI * 2)
  ctx.strokeStyle = dark ? 'rgba(129,140,248,0.45)' : 'rgba(99,102,241,0.55)'
  ctx.lineWidth = 1.5 / scale
  ctx.setLineDash([4 / scale, 4 / scale])
  ctx.stroke()
  ctx.setLineDash([])

  // Subtle fill
  ctx.fillStyle = dark ? 'rgba(99,102,241,0.03)' : 'rgba(99,102,241,0.05)'
  ctx.fill()

  // Label (subnet name) — constant size, centered at top of circle
  const label = node.name || ''
  const hostCount = node.host_count || 0
  ctx.fillStyle = dark ? 'rgba(165,180,252,0.85)' : 'rgba(67,56,202,0.95)'
  ctx.font = `${12 / scale}px monospace`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'bottom'
  const cap = hostCount > 0 ? `${label} · ${hostCount} hosts` : label
  ctx.fillText(cap, 0, -r - 6 / scale)

  ctx.restore()
}

function drawHostNode(ctx: CanvasRenderingContext2D, node: any, scale: number, _color: string, dark: boolean) {
  const x = node.x || 0
  const y = node.y || 0
  const r = 6 / scale

  ctx.save()
  ctx.translate(x, y)

  // Filled circle — fixed 6px on screen, rigid on zoom
  ctx.beginPath()
  ctx.arc(0, 0, r, 0, Math.PI * 2)
  ctx.fillStyle = _color
  ctx.fill()

  // Border
  ctx.strokeStyle = dark ? 'rgba(0,0,0,0.3)' : 'rgba(107,114,128,0.7)'
  ctx.lineWidth = 1 / scale
  ctx.stroke()

  // IP caption below node — constant size regardless of zoom
  const label = node.ip || (node.kind === 'host' ? node.id : '') || node.name || ''
  ctx.font = `${dark ? '600 ' : ''}9 / scale}px monospace`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'top'
  ctx.fillStyle = dark ? 'rgba(226,232,240,0.9)' : '#111827'
  ctx.fillText(label, 0, r + 4 / scale)

  ctx.restore()
}

// ────────────────────────────────────────────────────────────────────────
// Main component
// ────────────────────────────────────────────────────────────────────────

export default function Topology() {
  const { engagementId, scanId } = useParams()
  const { theme } = useTheme()
  const dark = theme === 'dark'
  const { data, isLoading } = useTopology(scanId)
  const { data: findings } = useFindings(scanId)
  const graphRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 960, h: 520 })
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [focusId, setFocusId] = useState<string | null>(null)
  const [selectedHostIp, setSelectedHostIp] = useState<string | null>(null)
  const [filterText, setFilterText] = useState('')
  const [collapsedZones, setCollapsedZones] = useState<Set<string>>(new Set())
  const [showLegend, setShowLegend] = useState(true)
  const [viewport, setViewport] = useState<{ x: number; y: number; k: number } | null>(null)
  const dragStartRef = useRef<{ id: string; x: number; y: number; orig: Map<string, { dx: number; dy: number }> } | null>(null)

  const { data: hostDetail } = useHostDetail(
    scanId || undefined,
    selectedHostIp || undefined,
  )

  // Resize observer
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const measure = () => {
      const w = el.clientWidth || 960
      const top = el.getBoundingClientRect().top
      const h = Math.max(320, (window.innerHeight || 800) - top - 20)
      setSize({ w, h })
    }
    const obs = new ResizeObserver(measure)
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  // Fullscreen enter/exit: keep button state in sync, re-measure the graph
  // card (it now fills the viewport) and refit so the diagram fills the screen.
  const refitOnFsChange = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const top = el.getBoundingClientRect().top
    const w = el.clientWidth || 960
    const h = Math.max(320, (window.innerHeight || 800) - top - 20)
    setSize({ w, h })
    setTimeout(() => {
      try {
        graphRef.current?.zoomToFit?.(0, 40)
        graphRef.current?.flushShadowCanvas?.()
      } catch {}
    }, 80)
  }, [])

  useEffect(() => {
    const onFsChange = () => {
      const active = Boolean(document.fullscreenElement)
      setIsFullscreen(active)
      refitOnFsChange()
    }
    document.addEventListener('fullscreenchange', onFsChange)
    document.addEventListener('webkitfullscreenchange', onFsChange as any)
    return () => {
      document.removeEventListener('fullscreenchange', onFsChange)
      document.removeEventListener('webkitfullscreenchange', onFsChange as any)
    }
  }, [refitOnFsChange])

  const toggleFullscreen = useCallback(async () => {
    const el = pageRef.current as any
    try {
      if (!document.fullscreenElement) {
        if (el?.requestFullscreen) await el.requestFullscreen()
        else if (el?.webkitRequestFullscreen) await el.webkitRequestFullscreen()
      } else {
        if (document.exitFullscreen) await document.exitFullscreen()
        else if ((document as any).webkitExitFullscreen) await (document as any).webkitExitFullscreen()
      }
    } catch {}
  }, [])

  // Build enriched node/link arrays
  const { graphNodes, graphLinks } = useMemo(() => {
    if (!data) return { graphNodes: [] as HostNode[], graphLinks: [] as any[] }

    const fMap = new Map<string, { count: number; sev: string }>()
    for (const f of (findings || []) as any[]) {
      const ip = f.host_ip || f.hostId || f.host?.ip
      if (!ip) continue
      const cur = fMap.get(ip) || { count: 0, sev: 'info' }
      cur.count++
      const order: Record<string, number> = { critical: 4, concerning: 3, notable: 2, info: 1 }
      if ((order[f.severity] || 0) > (order[cur.sev] || 0)) cur.sev = f.severity
      fMap.set(ip, cur)
    }

    const nodeById = new Map<string, HostNode>()

    const ns: HostNode[] = (data.nodes || []).map((n: any) => {
      const ip = n.kind === 'host' ? (n.ip || '') : ''
      const f = fMap.get(ip)
      const node: HostNode = {
        id: n.kind === 'host' ? n.ip : String(n.id),
        name: n.label || n.ip || n.id,
        ip,
        kind: n.kind || 'host',
        device_type: n.device_type || '',
        severity: f?.sev || n.severity || 'info',
        host_count: n.host_count ?? 0,
        finding_count: f?.count || 0,
        is_gateway: n.is_gateway || false,
      }
      nodeById.set(node.id, node)
      return node
    })

    const ls = (data.edges || []).map((e: any) => ({
      source: e.source,
      target: e.target,
      type: e.type || 'l2',
      source_kind: nodeById.get(e.source)?.kind,
    }))

    // Orient every link so its particles flow TOWARD the internet node:
    // host -> zone -> gateway -> internet.
    // source = endpoint farther from internet, target = endpoint nearer to it.
    const internetId = ns.find((n) => n.kind === 'internet')?.id
    if (internetId) {
      const dist: Record<string, number> = {}
      for (const n of ns) dist[n.id] = n.id === internetId ? 0 : Infinity
      const adj = new Map<string, string[]>()
      for (const n of ns) adj.set(n.id, [])
      for (const l of ls) {
        const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
        const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
        if (adj.has(s)) adj.get(s)!.push(t)
        if (adj.has(t)) adj.get(t)!.push(s)
      }
      const queue = [internetId]
      while (queue.length) {
        const cur = queue.shift()!
        for (const nb of adj.get(cur) || []) {
          if (dist[nb] !== Infinity) continue
          dist[nb] = dist[cur] + 1
          queue.push(nb)
        }
      }
      for (const l of ls) {
        const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
        const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
        if (dist[s] == null || dist[t] == null || dist[s] === Infinity || dist[t] === Infinity) continue
        if (dist[s] < dist[t]) {
          // currently flowing away from internet; swap so it flows toward it
          const tmp = l.source
          l.source = l.target
          l.target = tmp
        }
      }
      for (const l of ls) {
        l.source_kind = nodeById.get(typeof l.source === 'string' ? l.source : (l.source as any)?.id)?.kind
      }
    }

    const allIds = ns.map((n) => n.id)
    const pivots = detectPivots(allIds, ls, (id) => nodeById.get(id)?.kind || 'host')
    const internetFacing = computeInternetFacing(ns as TopoNode[], ls, nodeById as any)

    for (const n of ns) {
      n.finding_count = fMap.get(n.ip)?.count || n.finding_count || 0
      n.severity = fMap.get(n.ip)?.sev || n.severity
      ;(n as any).is_pivot = pivots.includes(n.id)
      ;(n as any).internet_facing = internetFacing.has(n.id)
    }

    // Apply the permanent static layout synchronously so the very first
    // render is already the final arrangement (pinned, no drift).
    computeStaticLayout(ns, ls)

    return { graphNodes: ns, graphLinks: ls }
  }, [data, findings])

  // Build zone membership map
  const zoneByHost = useMemo(() => {
    const m = new Map<string, string>()
    for (const l of graphLinks) {
      const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
      const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
      const sN = graphNodes.find((n) => n.id === s)
      const tN = graphNodes.find((n) => n.id === t)
      if (sN?.kind === 'host' && tN?.kind === 'zone') m.set(s, t)
      else if (tN?.kind === 'host' && sN?.kind === 'zone') m.set(t, s)
    }
    return m
  }, [graphNodes, graphLinks])

  // Filter and collapse
  const visibleNodes = useMemo(() => {
    let nodes = graphNodes

    if (collapsedZones.size > 0) {
      nodes = nodes.filter((n) => {
        if (n.kind !== 'host') return true
        const zid = zoneByHost.get(n.id)
        return !zid || !collapsedZones.has(zid)
      })
    }

    if (filterText.trim()) {
      const q = filterText.toLowerCase().trim()
      nodes = nodes
        .map((n) => ({
          ...n,
          _filtered: !(
            n.name.toLowerCase().includes(q) ||
            n.ip.toLowerCase().includes(q) ||
            n.device_type.toLowerCase().includes(q) ||
            n.severity.toLowerCase().includes(q)
          ),
        }))
        .filter((n) => !(n as any)._filtered)
    }

    // Order: internet, zones, then HOSTS LAST. Because the hit-test paints
    // nodes in this order (later = on top), hosts painted after their zone's
    // filled disk win the click, keeping every host independently grabbable
    // while the zone itself is grabbable anywhere inside its circle.
    const rank = (n: any) => (n.kind === 'internet' ? 0 : n.kind === 'zone' ? 1 : 2)
    return [...nodes].sort((a, b) => rank(a) - rank(b) || ipKey(a.id).localeCompare(ipKey(b.id)))
  }, [graphNodes, zoneByHost, collapsedZones, filterText])

  const visibleLinks = useMemo(() => {
    const nodeIds = new Set(visibleNodes.map((n) => n.id))
    return graphLinks.filter((l) => {
      const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
      const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
      return nodeIds.has(s) && nodeIds.has(t)
    })
  }, [graphLinks, visibleNodes])

  // Node sizing — the built-in hit radius is r = sqrt(nodeVal)*nodeRelSize.
  // Hosts get a large hit radius (~16px) and internet keeps its disk; the zone
  // does NOT use a disk: its clickable area is a thin band around the border
  // circle, painted by the nodePointerAreaPaint hook below (nodeVal=1 leaves
  // only a ~1px hit at the exact center).
  const getNodeVal = useCallback((n: HostNode) => {
    if (n.kind === 'internet') return 55 * 55
    if (n.kind === 'zone') return 1
    return 16 * 16
  }, [])

  // Node color — transparent default circles: the built-in circle is only used
  // for hit-testing; all visuals are drawn by our custom canvas painter.
  const getNodeColor = useCallback((n: HostNode) => {
    return 'rgba(0,0,0,0)'
  }, [])

  // Hover tooltip
  const getNodeLabel = useCallback((n: HostNode) => {
    const icon = n.kind === 'host' ? deviceIcon(n.device_type) : n.kind === 'internet' ? '🌍' : '🔷'
    if (n.kind === 'internet') return `<b>${icon} Internet</b>`
    if (n.kind === 'zone') {
      const parts = [`<b>${icon} ${esc(n.name)}</b>`, `${esc(n.host_count)} hosts`]
      if (n.severity && n.severity !== 'info') parts.push(`Severity: ${esc(n.severity)}`)
      return parts.join('<br/>')
    }
    const parts = [
      `<b>${icon} ${esc(n.name)}</b>`,
      esc(n.ip),
      esc(DEVICE_TYPE_LABELS[normalizeDeviceType(n.device_type)] || n.device_type || 'Unknown device'),
      `Severity: ${esc(n.severity)}`,
    ]
    if (n.finding_count) parts.push(`${esc(n.finding_count)} finding${n.finding_count > 1 ? 's' : ''}`)
    if ((n as any).is_pivot) parts.push('⚠️ Pivot host')
    if ((n as any).internet_facing) parts.push('🌐 Internet-facing')
    if (n.is_gateway) parts.push('🔗 Gateway')
    return parts.join('<br/>')
  }, [])

  // Custom canvas rendering — ALL node types (mode 'after': drawn on top of
  // the invisible default circles used for built-in hit-testing)
  const nodeCanvasObject = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    if (node.kind === 'internet') {
      drawInternetCloud(ctx, node, globalScale, dark)
    } else if (node.kind === 'zone') {
      drawZoneContainer(ctx, node, globalScale, dark)
    } else if (node.kind === 'host') {
      drawHostNode(ctx, node, globalScale, SEV_RING[node.severity] || SEV_RING.info, dark)
    }
  }, [dark])

  // Node click
  const handleNodeClick = useCallback((node: HostNode) => {
    setFocusId(node.id)
    if (node.kind === 'host') {
      setSelectedHostIp(node.ip)
    } else if (node.kind === 'zone') {
      setCollapsedZones((prev) => {
        const next = new Set(prev)
        if (next.has(node.id)) next.delete(node.id)
        else next.add(node.id)
        return next
      })
    } else {
      setSelectedHostIp(null)
    }
  }, [])

  // Center on the focused node
  useEffect(() => {
    if (!focusId || !graphRef.current) return
    const node = visibleNodes.find((n) => n.id === focusId)
    if (!node || node.x == null || node.y == null) return
    setTimeout(() => {
      try {
        graphRef.current?.centerAt?.(node.x!, node.y!, 400)
        graphRef.current?.zoom?.(2.5, 400)
      } catch {}
    }, 100)
  }, [focusId, visibleNodes])

  const handleFitAll = useCallback(() => {
    try { graphRef.current?.zoomToFit(400, 60) } catch {}
  }, [])

  // Length-based flow sizing: particle speed is a *ratio* of the link length
  // per frame, so on long links it produces huge on-screen jumps per frame and
  // the flow reads as a blur (invisible), while short links crawl visibly.
  // Normalise to a constant world-unit distance per frame (4 units) and place
  // one particle per ~36 units so the marching dots are equally dense and
  // clearly visible at any diagram size.
  const getLinkLength = useCallback((l: any) => {
    const s = typeof l.source === 'string' ? l.source : (l.source as any)?.id
    const t = typeof l.target === 'string' ? l.target : (l.target as any)?.id
    const sn = graphNodes.find((n) => n.id === s)
    const tn = graphNodes.find((n) => n.id === t)
    if (!sn || !tn || sn.x == null || sn.y == null || tn.x == null || tn.y == null) return 400
    return Math.hypot((tn.x as number) - (sn.x as number), (tn.y as number) - (sn.y as number))
  }, [graphNodes])

  const getParticleCount = useCallback((l: any) => {
    return Math.max(7, Math.min(80, Math.round(getLinkLength(l) / 36)))
  }, [getLinkLength])

  const getParticleSpeed = useCallback((l: any) => {
    const len = Math.max(60, getLinkLength(l))
    // Clamp the ratio so short links don't loop instantly and long links never
    // leap ahead of the eye.
    return Math.max(0.0006, Math.min(0.012, 4 / len))
  }, [getLinkLength])

  // Fit to the architecture IMMEDIATELY (no transition) so the first painted
  // frame is already the final view. Then force a reheat/refresh so the shadow
  // (hit-test) canvas repaints with the SAME transform as the visible canvas —
  // otherwise hit areas are offset from the visuals and nodes become unclickable.
  useEffect(() => {
    if (!graphNodes.length) return
    const t = setTimeout(() => {
      const graph = graphRef.current
      if (!graph) return
      try {
        graph.zoomToFit(0, 40)
        graph.flushShadowCanvas?.()
        setTimeout(() => { graph.flushShadowCanvas?.() }, 900)
        graph.d3ReheatSimulation?.()
      } catch {}
    }, 50)
    return () => clearTimeout(t)
  }, [graphNodes.length])

  // Minimap
  const minimapNodes = useMemo(() => {
    return visibleNodes.map((n) => ({
      x: n.x || 0,
      y: n.y || 0,
      r: n.kind === 'host' ? 3 : 5,
      sev: n.severity || 'info',
      isCluster: n.kind === 'zone',
    }))
  }, [visibleNodes])

  const hostCount = graphNodes.filter((n) => n.kind === 'host').length
  const zoneCount = graphNodes.filter((n) => n.kind === 'zone').length

  return (
    <div
      ref={pageRef}
      className={`flex h-full ${isFullscreen ? (dark ? 'bg-[#0b1020]' : 'bg-gray-50') : ''}`}
    >
      <div className="flex flex-1 flex-col">
        <Link to={`/engagements/${engagementId}`} className="text-sm text-gray-400 hover:text-white">← Back to engagement</Link>
        <ScanNav engagementId={engagementId!} scanId={scanId!} />

        <div className="mt-3 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Network Topology</h1>
            <p className="mt-1 text-sm text-gray-400">{hostCount} hosts · {zoneCount} subnets</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder="Filter hosts…"
              className="w-48 rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <button onClick={handleFitAll} className="rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-700">Fit View</button>
            <button onClick={toggleFullscreen} className="rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-700">
              {isFullscreen ? 'Exit Fullscreen' : '⛶ Fullscreen'}
            </button>
            <button onClick={() => setShowLegend(!showLegend)} className="rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-700">
              {showLegend ? 'Hide Legend' : 'Show Legend'}
            </button>
          </div>
        </div>

        <div
          ref={containerRef}
          className={`relative mt-3 min-h-[320px] flex-1 overflow-hidden rounded-lg border touch-none select-none ${
            dark ? 'border-gray-800 bg-[#0b1020]' : 'border-gray-200 bg-white shadow-sm'
          }`}
        >
          {!graphNodes.length ? (
            <div className="py-24 text-center text-gray-400">
              {isLoading ? 'Loading topology…' : 'No assets discovered'}
            </div>
          ) : (
            <ForceGraph2D
              ref={graphRef}
              graphData={{ nodes: visibleNodes, links: visibleLinks }}
              width={size.w}
              height={size.h}
              backgroundColor={dark ? '#0b1020' : '#ffffff'}
              nodeRelSize={1}
              nodeVal={getNodeVal}
              nodeColor={getNodeColor}
              nodeLabel={getNodeLabel}
              nodeCanvasObject={nodeCanvasObject}
              nodeCanvasObjectMode={() => 'after' as any}
              linkColor={(l: any) => (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT)[l.type]?.color || (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT).l2.color}
              linkWidth={(l: any) => ((dark ? EDGE_STYLE : EDGE_STYLE_LIGHT)[l.type]?.width || (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT).l2.width) * 1.6}
              linkLineDash={(l: any) => (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT)[l.type]?.dash || (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT).l2.dash}
              linkDirectionalParticles={(l: any) => (l.type === 'gateway' ? getParticleCount(l) : 3)}
              linkDirectionalParticleWidth={(l: any) => (l.type === 'gateway' ? 4.5 : 2.8)}
              linkDirectionalParticleSpeed={(l: any) => (l.type === 'gateway' ? getParticleSpeed(l) : 0.008)}
              linkDirectionalParticleColor={(l: any) => (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT)[l.type]?.color || (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT).l2.color}
              linkDirectionalArrowLength={7}
              linkDirectionalArrowRelPos={1}
              linkDirectionalArrowColor={(l: any) => (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT)[l.type]?.color || (dark ? EDGE_STYLE : EDGE_STYLE_LIGHT).l2.color}
              linkCurvature={(l: any) => {
                if (l.type === 'gateway') return 0
                // in_subnet edges toward the zone are drawn host->zone, but a
                // gateway host sits closer to internet than its zone, so its
                // edge flow was reversed (zone->host) by orientation. Mirror
                // the bend to match every other host->zone arc.
                return l.source_kind === 'zone' ? -0.08 : 0.08
              }}
              onZoom={(transform: any) => setViewport(transform)}
              autoPauseRedraw={false}
              enableNodeDrag={true}
              enablePointerInteraction={true}
              nodePointerAreaPaint={((node: any, color: any, ctx: CanvasRenderingContext2D) => {
                ctx.save()
                ctx.beginPath()
                if (node.kind === 'zone') {
                  // Clickable band around the border circle only: an annulus
                  // just inside/outside the dashed border, not the whole disk.
                  const rr = Math.max(30, node._zoneR || 60)
                  ctx.arc(node.x, node.y, rr + 3, 0, Math.PI * 2, false)
                  ctx.arc(node.x, node.y, Math.max(16, rr - 16), 0, Math.PI * 2, true)
                  ctx.fillStyle = color
                  ctx.fill('evenodd')
                } else {
                  ctx.arc(node.x, node.y, node.kind === 'internet' ? 55 : 16, 0, Math.PI * 2, false)
                  ctx.fillStyle = color
                  ctx.fill()
                }
                ctx.restore()
              }) as any}
              onNodeClick={handleNodeClick as any}
              onNodeDrag={((node: any) => {
                  if (!node || node.id == null) return
                  if (node.kind === 'zone') {
                    // Move the zone's member hosts ALONG with the circle, rigidly
                    // attached: record each host's offset from the zone center at
                    // drag start, then keep fx/fy = zoneCenter + offset every tick.
                    // Uses node.fx/fy (the true drag position) so hosts never lag.
                    let start = dragStartRef.current
                    if (!start || start.id !== node.id) {
                      const zx = node.fx ?? node.x ?? 0
                      const zy = node.fy ?? node.y ?? 0
                      const offs = new Map<string, { dx: number; dy: number }>()
                      for (const h of graphNodes) {
                        if (h.kind === 'host' && zoneByHost.get(h.id) === node.id && h.fx != null && h.fy != null) {
                          offs.set(h.id, { dx: h.fx - zx, dy: h.fy - zy })
                        }
                      }
                      start = { id: node.id, x: zx, y: zy, orig: offs }
                      dragStartRef.current = start
                    }
                    const nx = node.fx ?? node.x ?? start.x
                    const ny = node.fy ?? node.y ?? start.y
                    for (const [hid, off] of start.orig) {
                      const h = graphNodes.find((n) => n.id === hid)
                      if (h) {
                        h.fx = nx + off.dx
                        h.fy = ny + off.dy
                      }
                    }
                  } else {
                    dragStartRef.current = null
                  }
                }) as any}
              onNodeHover={(n: any) => {
                document.body.style.cursor = n ? 'pointer' : 'default'
              }}
              d3VelocityDecay={0.9}
              d3AlphaDecay={1}
              cooldownTicks={0}
            />
          )}

          {graphNodes.length > 0 && (
            <TopologyMinimap
              nodes={minimapNodes}
              width={size.w}
              height={size.h}
              viewport={viewport}
              dark={dark}
              onNavigate={(x, y) => {
                try { graphRef.current?.centerAt(x, y, 400) } catch {}
              }}
            />
          )}

          </div>
        </div>

      <div className={`ml-3 flex w-72 flex-shrink-0 flex-col rounded-lg border p-4 overflow-y-auto ${
          dark ? 'border-gray-800 bg-[#0b1020]' : 'border-gray-200 bg-gray-50 shadow-sm'
        }`}>
        {selectedHostIp && hostDetail ? (
          <HostDetailPanel host={hostDetail as any} onClose={() => setSelectedHostIp(null)} />
        ) : showLegend ? (
          <LegendPanel dark={dark} />
        ) : (
          <div className="py-24 text-center text-sm text-gray-500">Click a host to view details</div>
        )}
      </div>
    </div>
  )
}

// ────────────────────────────────────────────────────────────────────────
// Sub-components
// ────────────────────────────────────────────────────────────────────────

function HostDetailPanel({ host, onClose }: { host: any; onClose: () => void }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-white">Host Details</h3>
        <button onClick={onClose} className="text-gray-400 hover:text-white text-xs">✕</button>
      </div>
      <div className="space-y-2 text-xs">
        <Row label="IP" value={host.ip || host.id} />
        <Row label="Hostname" value={host.hostname || '—'} />
        <Row label="OS" value={host.os || '—'} />
        <Row label="Device Type" value={DEVICE_TYPE_LABELS[normalizeDeviceType(host.device_type)] || host.device_type || '—'} />
        <Row label="Severity" value={host.severity || 'info'} badge badgeColor={SEV_RING[host.severity] || SEV_RING.info} />
        {host.mac_address && <Row label="MAC" value={host.mac_address} />}
        {host.vendor && <Row label="Vendor" value={host.vendor} />}
      </div>
      {host.ports && host.ports.length > 0 && (
        <div>
          <h4 className="mb-1 text-xs font-semibold text-gray-300">Open Ports</h4>
          <div className="max-h-40 space-y-1 overflow-y-auto">
            {host.ports.map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between rounded bg-gray-800/50 px-2 py-1 text-xs">
                <span className="text-white font-mono">{p.port}/{p.protocol || 'tcp'}</span>
                <span className="text-gray-400 truncate ml-2">{p.service || '—'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {host.snmp && (
        <div>
          <h4 className="mb-1 text-xs font-semibold text-gray-300">SNMP</h4>
          <div className="space-y-1 rounded bg-gray-800/50 p-2 text-xs">
            {host.snmp.sys_name && <Row label="Name" value={host.snmp.sys_name} />}
            {host.snmp.sys_descr && <Row label="Description" value={host.snmp.sys_descr.slice(0, 80)} />}
            {host.snmp.sys_location && <Row label="Location" value={host.snmp.sys_location} />}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, value, badge, badgeColor }: { label: string; value: string; badge?: boolean; badgeColor?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-500">{label}</span>
      {badge ? (
        <span className="rounded px-1.5 py-0.5 text-xs font-medium text-white" style={{ backgroundColor: badgeColor || '#6b7280' }}>{value}</span>
      ) : (
        <span className="text-gray-200 truncate text-right max-w-[160px]">{value}</span>
      )}
    </div>
  )
}

function LegendPanel({ dark }: { dark: boolean }) {
  const styles = dark ? EDGE_STYLE : EDGE_STYLE_LIGHT
  return (
    <div className="flex flex-col gap-4">
      <h3 className="text-sm font-bold text-white">Legend</h3>
      <div>
        <h4 className="mb-2 text-xs font-semibold text-gray-300">Host Severity</h4>
        <div className="space-y-1.5">
          {(['critical', 'concerning', 'notable', 'info'] as const).map((sev) => (
            <div key={sev} className="flex items-center gap-2 text-xs">
              <span className="h-3 w-3 rounded-full" style={{ backgroundColor: SEV_RING[sev] }} />
              <span className="text-gray-300 capitalize">{sev}</span>
            </div>
          ))}
        </div>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold text-gray-300">Node Types</h4>
        <div className="space-y-1.5 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-base">☁️</span>
            <span className="text-gray-300">Internet</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-block h-3 w-3 rounded-full border border-dashed border-indigo-400" />
            <span className="text-gray-300">Subnet (dotted circle)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEV_RING.info, boxShadow: '0 0 0 1px rgba(0,0,0,0.4)' }} />
            <span className="text-gray-300">Host (colored by severity)</span>
          </div>
        </div>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold text-gray-300">Connection Types</h4>
        <div className="space-y-1.5">
          {(['gateway', 'l2', 'cdp_lldp', 'in_subnet'] as const).map((key) => {
            const style = styles[key]
            return (
              <div key={key} className="flex items-center gap-2 text-xs">
                <span
                  className="inline-block h-0.5 w-6 rounded"
                  style={{
                    backgroundColor: style.dash.length ? 'transparent' : style.color,
                    backgroundImage: style.dash.length
                      ? `repeating-linear-gradient(90deg, ${style.color} 0 ${style.dash[0]}px, transparent ${style.dash[0]}px ${style.dash[0] + style.dash[1]}px)`
                      : undefined,
                  }}
                />
                <span className="text-gray-300 capitalize">{key.replace(/_/g, ' ')}</span>
              </div>
            )
          })}
        </div>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold text-gray-300">Interactions</h4>
        <div className="space-y-1 text-xs text-gray-400">
          <p><span className="text-gray-300">Click host</span> — view details in sidebar</p>
          <p><span className="text-gray-300">Click subnet</span> — collapse/expand hosts</p>
          <p><span className="text-gray-300">Drag nodes</span> — reposition</p>
          <p><span className="text-gray-300">Scroll</span> — zoom in/out</p>
        </div>
      </div>
    </div>
  )
}
