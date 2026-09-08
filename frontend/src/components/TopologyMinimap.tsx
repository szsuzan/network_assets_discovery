import { useEffect, useRef } from 'react'

type MinimapNode = { x: number; y: number; r: number; sev: string; isCluster?: boolean }
type MinimapProps = {
  nodes: MinimapNode[]
  width: number
  height: number
  viewport: { x: number; y: number; k: number } | null
  onNavigate: (x: number, y: number) => void
  size?: number
  dark?: boolean
}

const SEV_COLOR: Record<string, string> = {
  critical: '#E04B4B',
  concerning: '#E08341',
  notable: '#E0B341',
  info: '#8B95A1',
}

export default function TopologyMinimap({ nodes, width, height, viewport, onNavigate, size = 170, dark = true }: MinimapProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const dpr = window.devicePixelRatio || 1
    canvas.width = size * dpr
    canvas.height = size * dpr
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, size, size)

    if (!nodes.length) return

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
    for (const n of nodes) {
      if (n.x < minX) minX = n.x
      if (n.x > maxX) maxX = n.x
      if (n.y < minY) minY = n.y
      if (n.y > maxY) maxY = n.y
    }
    const gW = (maxX - minX) || 1
    const gH = (maxY - minY) || 1
    const scale = Math.min(size / gW, size / gH) * 0.9
    const ox = (size - gW * scale) / 2 - minX * scale
    const oy = (size - gH * scale) / 2 - minY * scale

    // background
    ctx.fillStyle = dark ? 'rgba(11,16,32,0.6)' : 'rgba(249,250,251,0.92)'
    ctx.fillRect(0, 0, size, size)

    // nodes
    for (const n of nodes) {
      const x = n.x * scale + ox
      const y = n.y * scale + oy
      const r = Math.max(1.2, n.r * scale * 0.9)
      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fillStyle = SEV_COLOR[n.sev] || '#8B95A1'
      if (n.isCluster) {
        ctx.strokeStyle = '#818cf8'
        ctx.lineWidth = 1
        ctx.stroke()
      }
      ctx.globalAlpha = 0.85
      ctx.fill()
      ctx.globalAlpha = 1
    }

    // viewport rect
    if (viewport) {
      const vw = (width / viewport.k) * scale
      const vh = (height / viewport.k) * scale
      const vx = viewport.x * scale + ox - vw / 2
      const vy = viewport.y * scale + oy - vh / 2
      ctx.strokeStyle = dark ? '#e2e8f0' : '#64748b'
      ctx.lineWidth = 1
      ctx.strokeRect(vx, vy, vw, vh)
    }
  }, [nodes, width, height, viewport, size])

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = (e.target as HTMLCanvasElement).getBoundingClientRect()
    const px = e.clientX - rect.left
    const py = e.clientY - rect.top
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
    for (const n of nodes) {
      if (n.x < minX) minX = n.x
      if (n.x > maxX) maxX = n.x
      if (n.y < minY) minY = n.y
      if (n.y > maxY) maxY = n.y
    }
    const gW = (maxX - minX) || 1
    const gH = (maxY - minY) || 1
    const scale = Math.min(size / gW, size / gH) * 0.9
    const ox = (size - gW * scale) / 2 - minX * scale
    const oy = (size - gH * scale) / 2 - minY * scale
    const gx = (px - ox) / scale
    const gy = (py - oy) / scale
    onNavigate(gx, gy)
  }

  return (
    <div className={`pointer-events-auto absolute bottom-3 right-3 z-10 rounded-md border p-1 shadow-lg ${
      dark ? 'border-gray-700 bg-[#0b1020]/90' : 'border-gray-300 bg-white/90'
    }`}>
      <canvas
        ref={canvasRef}
        onClick={handleClick}
        style={{ width: size, height: size, cursor: 'crosshair' }}
      />
    </div>
  )
}
