import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useChangePassword } from '../hooks/useApi'
import { useTheme } from '../lib/theme'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

export default function ChangePassword() {
  const [current, setCurrent] = useState('')
  const [newPass, setNewPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const change = useChangePassword()
  const { theme } = useTheme()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (newPass.length < 10) {
      setError('New password must be at least 10 characters.')
      return
    }
    if (newPass === current) {
      setError('New password must differ from your current password.')
      return
    }
    if (newPass !== confirm) {
      setError('New password and confirmation do not match.')
      return
    }
    try {
      await change.mutateAsync({ current_password: current, new_password: newPass })
      localStorage.removeItem('token')
      localStorage.removeItem('role')
      navigate('/login', { state: { passwordChanged: true } })
    } catch (err: any) {
      if (err.response?.status === 401) {
        localStorage.removeItem('token')
        localStorage.removeItem('role')
        navigate('/login')
        return
      }
      setError(err.response?.data?.detail || 'Could not change password')
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-xl rounded-lg border border-gray-800 bg-gray-900 p-6">
        <div className="mb-8 text-center">
          <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="mx-auto mb-3 h-32 w-auto" />
          <p className="text-sm italic text-gray-400">A password change is required before you can continue.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">Current password</label>
            <input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              placeholder="••••••••"
              required
              autoFocus
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">New password</label>
            <input
              type="password"
              value={newPass}
              onChange={(e) => setNewPass(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              placeholder="At least 10 characters"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">Confirm new password</label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
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

          <button
            type="submit"
            disabled={change.isPending}
            className="w-full rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {change.isPending ? 'Updating...' : 'Update password'}
          </button>
        </form>
      </div>
    </div>
  )
}