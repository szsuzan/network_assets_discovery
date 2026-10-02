import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      // A bad password on the login form is itself a 401. Redirecting here
      // reloaded the page and wiped the component's error state, so the
      // "Invalid email or password" message could never render. Let the
      // login page handle its own 401.
      const onLogin = window.location.pathname === '/login'
      if (!onLogin) {
        localStorage.removeItem('token')
        localStorage.removeItem('role')
        window.location.href = '/login'
      }
    } else if (
      error.response?.status === 403 &&
      (error.response?.headers?.['x-require-password-change'] === 'true' ||
        error.response?.data?.detail === 'Password change required')
    ) {
      if (window.location.pathname !== '/change-password') {
        window.location.href = '/change-password'
      }
    }
    return Promise.reject(error)
  }
)
