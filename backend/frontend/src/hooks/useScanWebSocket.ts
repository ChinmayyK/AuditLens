import { useEffect, useRef, useState } from 'react'
import { getWsBaseUrl } from '../lib/runtimeConfig'

export interface WSEvent {
  type: string
  message?: string
  progress?: number
  data?: unknown
  timestamp?: string
}

export function useScanWebSocket(scanId: string | null) {
  const [events, setEvents] = useState<WSEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    const wsUrl = `${getWsBaseUrl()}/ws/scan/${scanId}`
    let ws: WebSocket

    try {
      ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => setIsConnected(true)
      ws.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data) as WSEvent
          setEvents(prev => [...prev.slice(-49), { ...event, timestamp: new Date().toISOString() }])
        } catch { /* Ignore malformed websocket payloads. */ }
      }
      ws.onclose = () => setIsConnected(false)
      ws.onerror = () => setIsConnected(false)
    } catch {
      window.setTimeout(() => setIsConnected(false), 0)
    }

    return () => {
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [scanId])

  return { events, isConnected }
}
