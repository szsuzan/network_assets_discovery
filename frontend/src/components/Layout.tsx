import { useEffect } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTheme } from '../lib/theme'
import { isAdmin, clearAuth } from '../lib/auth'
import { usernameOf } from '../lib/format'
import { useMe } from '../hooks/useApi'
import CommandPalette from './CommandPalette'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

const ROLE_LABELS: Record<string, string> = {
  admin: 'Admin',
  scanner: 'Scanner',
  viewer: 'Viewer',
}

const TITLE_BY_ROUTE: Array<[RegExp, string]> = [
  [/^\/login$/, 'Sign in'],
  [/^\/change-password$/, 'Change password'],
  [/^\/$/, 'Engagements'],
  [/^\/agents/, 'Agents'],
  [/^\/integrations/, 'Integrations'],
  [/^\/settings/, 'Settings'],
  [/^\/admin/, 'Administration'],
  [/\/host\//, 'Host details'],
  [/\/live$/, 'Live scan'],
  [/\/inventory$/, 'Asset inventory'],
  [/\/topology$/, 'Topology'],
  [/\/findings$/, 'Findings'],
  [/\/report$/, 'Report'],
  [/^\/engagements\/[^/]+/, 'Engagement'],
]

function pageTitle(path: string): string {
  for (const [re, label] of TITLE_BY_ROUTE) {
    if (re.test(path)) return label
  }
  return 'SubNex'
}

export default function Layout() {
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const admin = isAdmin()
  const { data: me } = useMe()

  useEffect(() => {
    document.title = `${pageTitle(location.pathname)} · SubNex`
  }, [location.pathname])

  const logout = () => {
    clearAuth()
    navigate('/login')
  }

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `rounded px-3 py-1.5 text-sm font-medium transition-colors ${
      isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white'
    }`

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-3">
          <div className="flex flex-1 items-center">
            <NavLink to="/" end className="flex flex-col items-start hover:opacity-90">
              <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="h-20 w-auto" />
              <span className="mt-1 text-sm italic text-gray-500">Where your assets hide, SubNex finds.</span>
            </NavLink>
          </div>
          <nav className="flex flex-wrap items-center justify-center gap-1">
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
          <div className="flex flex-1 flex-wrap items-center justify-end gap-2">
            <button
              onClick={() => {
                window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))
              }}
              title="Quick search (Ctrl+K)"
              className="flex h-9 items-center gap-2 rounded-lg border border-gray-800 bg-gray-800/60 px-3 text-sm text-gray-400 transition-colors hover:border-gray-700 hover:text-white"
            >
              <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <circle cx="11" cy="11" r="7" />
                <path d="m21 21-4.3-4.3" />
              </svg>
              <span className="hidden sm:inline">Search</span>
              <kbd className="rounded border border-gray-700 bg-gray-900 px-1 text-[10px] text-gray-500">Ctrl K</kbd>
            </button>
            {me && (
              <div className="flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-800/40 py-1 pl-2 pr-1.5">
                <span className="hidden max-w-[140px] truncate text-xs text-gray-400 lg:block">{usernameOf(me.email)}</span>
                <span className="rounded-md bg-indigo-600/30 px-2 py-0.5 text-[11px] font-medium text-indigo-200">
                  {ROLE_LABELS[me.role] || me.role}
                </span>
              </div>
            )}
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
            <button onClick={logout} className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700">
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="p-4">
        <Outlet />
      </main>

      <CommandPalette />
    </div>
  )
}