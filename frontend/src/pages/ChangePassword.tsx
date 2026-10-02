import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useChangePassword, useMe } from '../hooks/useApi'
import { useTheme } from '../lib/theme'
import { errText } from '../lib/errors'
import { Spinner } from '../components/ui'
import { usePageTitle } from '../hooks/usePageTitle'
import subnexLogo from '../assets/subnex-logo.svg'
import subnexLogoLight from '../assets/subnex-logo-light.svg'

export default function ChangePassword() {
  const [current, setCurrent] = useState('')
  const [username, setUsername] = useState('')
  const [newPass, setNewPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const change = useChangePassword()
  // /api/auth/me accepts the not-yet-unlocked token, so the current handle can
  // be offered as the starting point for the rename.
  const { data: me } = useMe()
  const { theme } = useTheme()
  usePageTitle('Set up your account')

  const currentUsername = me?.email || ''

  useEffect(() => {
    if (currentUsername && !username) setUsername(currentUsername)
  }, [currentUsername])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const trimmedUser = username.trim()
    if (trimmedUser !== currentUsername.toLowerCase()) {
      if (!trimmedUser) {
        setError('Username cannot be empty.')
        return
      }
      if (/\s/.test(trimmedUser)) {
        setError('Username cannot contain spaces.')
        return
      }
    }
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
      await change.mutateAsync({
        current_password: current,
        new_password: newPass,
        new_username: trimmedUser || undefined,
      })
      localStorage.removeItem('token')
      localStorage.removeItem('role')
      localStorage.removeItem('user_id')
      navigate('/login', {
        state: { passwordChanged: true, username: trimmedUser || currentUsername },
        replace: true,
      })
    } catch (err: any) {
      if (err.response?.status === 401) {
        localStorage.removeItem('token')
        localStorage.removeItem('role')
        localStorage.removeItem('user_id')
        navigate('/login', { replace: true })
        return
      }
      setError(errText(err, 'Could not update your account'))
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-xl rounded-lg border border-gray-800 bg-gray-900 p-6">
        <div className="mb-8 text-center">
          <img src={theme === 'dark' ? subnexLogoLight : subnexLogo} alt="SubNex" className="mx-auto mb-3 h-32 w-auto" />
          <p className="text-sm italic text-gray-400">
            Choose your username and password before you can continue.
          </p>
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
            <label className="mb-1 block text-sm font-medium text-gray-300">New username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
              placeholder="your-username"
              autoComplete="username"
              required
            />
            <p className="mt-1 text-xs text-gray-500">
              This is what you sign in with. A bare name is kept as-is; anything with an
              address is used verbatim.
            </p>
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
            className="inline-flex w-full items-center justify-center gap-2 rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {change.isPending && <Spinner className="h-4 w-4" />}
            {change.isPending ? 'Saving...' : 'Save and continue'}
          </button>
        </form>
      </div>
    </div>
  )
}