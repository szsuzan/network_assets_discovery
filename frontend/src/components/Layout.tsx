import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useTheme } from '../lib/theme'

export default function Layout() {
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('role')
    navigate('/login')
  }

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `rounded px-3 py-1.5 text-sm font-medium transition-colors ${
      isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white'
    }`

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="text-lg font-bold text-white">🛡️ Asset Discovery</span>
            <nav className="flex items-center gap-1">
              <NavLink to="/" end className={navClass}>
                Engagements
              </NavLink>
              <NavLink to="/agents" className={navClass}>
                Agents
              </NavLink>
              <NavLink to="/integrations" className={navClass}>
                Integrations
              </NavLink>
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={toggle} className="text-gray-400 hover:text-white">
              {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
            </button>
            <button onClick={logout} className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700">
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="p-4">
        <Outlet />
      </main>
    </div>
  )
}
