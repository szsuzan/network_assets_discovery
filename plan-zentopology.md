# ZenMap-Inspired Topology Redesign Plan

## Goal
Replace the current topology page with a ZenMap-style network topology view using `react-force-graph-2d`'s **native rendering** (no custom canvas painting — to avoid the hit-testing/drag issues we've fought repeatedly).

## ZenMap Features to Replicate

| ZenMap Feature | Our Implementation |
|---|---|
| Internet at center, radial rings by hop | `computeLayout` with `radial` mode + `focus` on gateway |
| Node sizing by open ports | `computeNodeSize()` from `graphAnalysis.ts` (8–26px radius) |
| Node coloring by severity | `SEV_RING` palette from `graphAnalysis.ts` |
| Connection lines by type | `EDGE_STYLE` from `graphAnalysis.ts` (gateway=solid blue, in_subnet=dashed gray) |
| Click to focus (center on host) | React state `focusId` → `cooldownTicks` re-run with `focus` param |
| Host details on click | Right sidebar panel using `useHostDetail(scanId, hostIp)` |
| Search / filter bar | `useState<string>` filter input, highlight matching nodes |
| Zone grouping / collapse | `computeClusters` + collapsed cluster set |
| Legend | Sidebar legend panel (node colors, edge types, device icons) |
| Pan / zoom | Native react-force-graph-2d `enableZoomPanInteraction` |

---

## Files to Modify/Create

| File | Action |
|---|---|
| `frontend/src/pages/Topology.tsx` | **Rewrite** — ZenMap-inspired, native rendering |
| `frontend/src/lib/graphAnalysis.ts` | **No change** — already has everything we need |
| `frontend/src/lib/layoutEngine.ts` | **No change** — already works (78 unit tests pass) |
| `frontend/src/components/TopologyMinimap.tsx` | **Integrate** into the new Topology.tsx |
| `frontend/src/hooks/useApi.ts` | **No change** — hooks already exist |

---

## Implementation Steps

### Step 1: Rewrite `Topology.tsx` — Core Graph (Native Rendering)

**Key constraints** (learned from our 6+ failed iterations):
- ✅ `cooldownTicks = 0` is **DEAD** — never do this again
- ✅ `autoPauseRedraw = false` — keeps shadow canvas fresh for drag
- ✅ `enablePointerInteraction = true` — explicit drag enable
- ✅ NO `nodeCanvasObject` — use library's default circle rendering
- ✅ NO `linkCanvasObject` — use library's default line rendering
- ✅ Let d3-force settle naturally (default cooldown ~300 ticks)

**Node visual encoding** (via `nodeVal`, `nodeColor`, `nodeLabel` props):
- `nodeVal` → `computeNodeSize(node)` — larger circles for hosts with more findings/ports
- `nodeColor` → `SEV_RING[node.severity]` — severity coloring (green/yellow/orange/red)
- `nodeLabel` → IP + hostname + device icon — tooltip on hover
- `nodeRelSize={1}` — ensure radius maps 1:1 to pixel size

**Edge visual encoding** (via `linkWidth`, `linkColor`, `linkLineDash`):
- `linkWidth` → `EDGE_STYLE[type].width` — thicker for gateway links
- `linkColor` → `EDGE_STYLE[type].color` — blue for gateway, gray for in_subnet
- `linkLineDash` → `EDGE_STYLE[type].dash` — dashed for in_subnet

### Step 2: Click-to-Focus (ZenMap's Signature Feature)

- `onNodeClick` handler sets `focusId` state
- Trigger `graphData` re-render with focus node repositioned to center
- Re-run layout with focus node pinned, then animate view to center
- `d3ReheatSimulation()` to restart physics after focusing

### Step 3: Host Details Sidebar

- Right sidebar (280px wide) slides in when a host is clicked
- Uses `useHostDetail(scanId, hostIp)` to fetch enriched data
- Shows: IP, hostname, OS, open ports, findings, severity badge
- Close button to dismiss

### Step 4: Search / Filter

- Text input at top: `filterText` state
- `nodeCanvasObjectMode` stays default; use `nodeLabel` to show/hide
- Matching nodes get `nodeColor` highlight; non-matching get dimmed opacity
- Filter by: IP, hostname, device type, severity, port number

### Step 5: Zone Collapse/Expand

- `computeClusters()` from `graphAnalysis.ts` groups hosts by subnet
- Clicking a zone node toggles `collapsedZones` Set
- Collapsed zones: all hosts hidden, zone node gets `host_count` badge
- Uncollapse: hosts reappear with physics animation

### Step 6: Legend Panel

- Bottom-left overlay showing:
  - Severity color key (info → critical)
  - Edge type key (gateway, in_subnet)
  - Device type icons
- Toggle visibility with a button

### Step 7: Minimap Integration

- Use existing `TopologyMinimap.tsx` in bottom-right
- Feed it positioned nodes from the graph ref
- Viewport rectangle tracks current zoom/pan

### Step 8: Fit View Button

- "Fit All" button resets zoom/pan to show entire graph
- Uses `graphRef.current.zoomToFit(400)` with padding

---

## Data Flow

```
useTopology(scanId)
    ↓
TopoNode[] + TopoLink[]
    ↓
computeClusters()  →  clusters[]
    ↓
computeLayout({ mode: 'radial', focus, collapsedClusters })
    ↓
GraphNode[] + TopoLink[]  →  react-force-graph-2d (native rendering)
    ↓
graphRef  →  TopologyMinimap (viewport tracking)
```

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| Canvas hit-testing breaks again | Zero custom canvas painting — library handles everything |
| Force simulation never settles | `cooldownTicks: Infinity` (default) — simulation runs to completion |
| Drag stops working | `autoPauseRedraw: false` + `enablePointerInteraction: true` |
| Performance on large graphs | `nGraphPhysics` engine (already in layoutEngine.ts) handles 500+ nodes |
| Zones not visible | Use `nodeLabel` tooltip + zone nodes get larger `nodeVal` |

---

## Verification

After implementation:
1. `cd frontend && npm run lint` — no TypeScript errors
2. `cd frontend && npm run build` — builds successfully
3. `docker compose up -d --build frontend` — deploys to port 3000
4. Manual test: nodes visible, lines connect, drag works, click focuses, search filters, sidebar shows host details
