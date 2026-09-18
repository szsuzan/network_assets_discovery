import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useTheme } from '../lib/theme'
import { isAdmin, clearAuth } from '../lib/auth'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

export default function Layout() {
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const admin = isAdmin()

  const logout = () => {
    clearAuth()
    navigate('/login')
  }

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `rounded px-3 py-1.5 text-base font-medium transition-colors ${
      isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white'
    }`

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-6">
            <NavLink to="/" end className="flex flex-col items-center rounded text-center leading-tight hover:opacity-90">
              <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="h-20 w-auto" />
              <span className="text-[12px] text-gray-500 italic">Where your assets hide, SubNex finds.</span>
            </NavLink>
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
              {admin && (
                <NavLink to="/admin" className={navClass}>
                  Administration
                </NavLink>
              )}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={toggle}
              title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              aria-label="Toggle color theme"
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-gray-800 bg-gray-800/60 text-gray-400 transition-all duration-300 hover:scale-105 hover:border-gray-700 hover:text-white"
            >
              {theme === 'dark' ? (
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="4" />
                  <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
                </svg>
              )}
            </button>
            <button onClick={logout} className="rounded bg-gray-800 px-3 py-1.5 text-base text-gray-300 hover:bg-gray-700">
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
