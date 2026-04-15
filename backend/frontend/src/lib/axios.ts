import axios from 'axios'
import { getApiBaseUrl } from './runtimeConfig'

const api = axios.create({
  baseURL: getApiBaseUrl(),
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

// Attach Bearer token from localStorage on every request
api.interceptors.request.use((config) => {
  const user = localStorage.getItem('ss_user')
  if (user) {
    try {
      const parsed = JSON.parse(user)
      if (parsed?.access_token) {
        config.headers.Authorization = `Bearer ${parsed.access_token}`
      }
    } catch { /* Ignore malformed stored auth and continue without a bearer token. */ }
  }
  return config
})

// On 401, clear auth and redirect to login
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('ss_user')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api
