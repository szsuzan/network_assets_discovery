import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useLogin } from '../hooks/useApi'
import { useTheme } from '../lib/theme'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const location = useLocation()
  const login = useLogin()
  const { theme } = useTheme()
  const justChanged = (location.state as { passwordChanged?: boolean })?.passwordChanged

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      const res = await login.mutateAsync({ email, password })
      localStorage.setItem('token', res.access_token)
      localStorage.setItem('role', res.role)
      if (res.must_change_password) {
        navigate('/change-password', { replace: true })
      } else {
        navigate('/')
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed')
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-xl rounded-lg border border-gray-800 bg-gray-900 p-6">
        <div className="mb-8 text-center">
          <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="mx-auto mb-3 h-40 w-auto" />
          <p className="text-sm italic text-gray-400">Where your assets hide, SubNex finds.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              placeholder="you@example.com"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              placeholder="••••••••"
              required
            />
          </div>

          {error && (
            <div className="rounded border border-red-800 bg-red-900/30 px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          {justChanged && (
            <div className="rounded border border-green-800 bg-green-900/30 px-3 py-2 text-sm text-green-400">
              Password updated — log in with your new password.
            </div>
          )}

          <button
            type="submit"
            disabled={login.isPending}
            className="w-full rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {login.isPending ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
