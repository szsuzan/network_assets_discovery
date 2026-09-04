import { NavLink } from 'react-router-dom'

export default function ScanNav({ engagementId, scanId }: { engagementId: string; scanId: string }) {
  const tabClass = ({ isActive }: { isActive: boolean }) =>
    `rounded px-3 py-1.5 text-sm font-medium transition-colors ${
      isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white'
    }`

  const base = `/engagements/${engagementId}/scans/${scanId}`

  return (
    <nav className="mb-6 flex flex-wrap items-center gap-1">
      <NavLink to={`${base}/live`} className={tabClass}>Live View</NavLink>
      <NavLink to={`${base}/inventory`} className={tabClass}>Assets</NavLink>
      <NavLink to={`${base}/topology`} className={tabClass}>Topology</NavLink>
      <NavLink to={`${base}/findings`} className={tabClass}>Findings</NavLink>
      <NavLink to={`${base}/report`} className={tabClass}>Report</NavLink>
    </nav>
  )
}
