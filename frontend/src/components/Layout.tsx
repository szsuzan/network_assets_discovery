import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useTheme } from '../lib/theme'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

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
            <div className="flex flex-col items-center text-center leading-tight">
              <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="h-20 w-auto" />
              <span className="text-[11px] text-gray-500 italic">Where your assets hide, SubNex finds.</span>
            </div>
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
              <NavLink to="/settings" className={navClass}>
                Settings
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
