import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Layout from './components/Layout'
import Engagements from './pages/Engagements'
import EngagementDetail from './pages/EngagementDetail'
import LiveScan from './pages/LiveScan'
import AssetInventory from './pages/AssetInventory'
import Topology from './pages/Topology'
import HostDrawer from './pages/HostDrawer'
import Findings from './pages/Findings'
import Report from './pages/Report'
import Agents from './pages/Agents'
import Integrations from './pages/Integrations'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
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
      </Route>
    </Routes>
  )
}
