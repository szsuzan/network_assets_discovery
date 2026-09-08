import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'

const Login = lazy(() => import('./pages/Login'))
const Engagements = lazy(() => import('./pages/Engagements'))
const EngagementDetail = lazy(() => import('./pages/EngagementDetail'))
const LiveScan = lazy(() => import('./pages/LiveScan'))
const AssetInventory = lazy(() => import('./pages/AssetInventory'))
const Topology = lazy(() => import('./pages/Topology'))
const HostDrawer = lazy(() => import('./pages/HostDrawer'))
const Findings = lazy(() => import('./pages/Findings'))
const Report = lazy(() => import('./pages/Report'))
const Agents = lazy(() => import('./pages/Agents'))
const Integrations = lazy(() => import('./pages/Integrations'))
const Settings = lazy(() => import('./pages/Settings'))

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

function PageFallback() {
  return (
    <div className="flex h-screen items-center justify-center text-sm text-gray-400">
      Loading…
    </div>
  )
}

export default function App() {
  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Engagements />} />
          <Route path="/engagements/:engagementId" element={<EngagementDetail />} />
          <Route path="/engagements/:engagementId/scans/:scanId/live" element={<LiveScan />} />
          <Route path="/engagements/:engagementId/scans/:scanId/inventory" element={<AssetInventory />} />
          <Route path="/engagements/:engagementId/scans/:scanId/host/:hostIp" element={<HostDrawer />} />
          <Route path="/engagements/:engagementId/scans/:scanId/topology" element={<Topology />} />
          <Route path="/engagements/:engagementId/scans/:scanId/findings" element={<Findings />} />
          <Route path="/engagements/:engagementId/scans/:scanId/report" element={<Report />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </Suspense>
  )
}