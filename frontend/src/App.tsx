import { lazy, ReactNode, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'

const Login = lazy(() => import('./pages/Login'))
const ChangePassword = lazy(() => import('./pages/ChangePassword'))
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

function RequireAuth({ children }: { children: ReactNode }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

function PageFallback() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-gray-300 border-t-indigo-500" />
    </div>
  )
}

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<PageFallback />}>{children}</Suspense>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LazyPage><Login /></LazyPage>} />
      <Route path="/change-password" element={<LazyPage><ChangePassword /></LazyPage>} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<LazyPage><Engagements /></LazyPage>} />
        <Route path="/engagements/:engagementId" element={<LazyPage><EngagementDetail /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/live" element={<LazyPage><LiveScan /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/inventory" element={<LazyPage><AssetInventory /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/host/:hostIp" element={<LazyPage><HostDrawer /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/topology" element={<LazyPage><Topology /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/findings" element={<LazyPage><Findings /></LazyPage>} />
        <Route path="/engagements/:engagementId/scans/:scanId/report" element={<LazyPage><Report /></LazyPage>} />
        <Route path="/agents" element={<LazyPage><Agents /></LazyPage>} />
        <Route path="/integrations" element={<LazyPage><Integrations /></LazyPage>} />
        <Route path="/settings" element={<LazyPage><Settings /></LazyPage>} />
      </Route>
    </Routes>
  )
}