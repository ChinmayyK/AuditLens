function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '')
}

function ensureApiVersion(value: string) {
  return value.endsWith('/api/v1') ? value : `${value}/api/v1`
}

export function getApiBaseUrl() {
  const configured = import.meta.env.VITE_API_URL?.trim()
  if (configured) {
    return ensureApiVersion(trimTrailingSlash(configured))
  }

  return '/api/v1'
}

export function getWsBaseUrl() {
  const configured = import.meta.env.VITE_WS_URL?.trim()
  if (configured) {
    return trimTrailingSlash(configured)
  }

  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${protocol}//${window.location.host}`
  }

  return 'ws://localhost:8000'
}
