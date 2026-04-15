import { useEffect, useRef, useState } from 'react'

export interface WSEvent {
  type: string
  message?: string
  progress?: number
  data?: any
  timestamp?: string
}

export function useScanWebSocket(scanId: string | null) {
  const [events, setEvents] = useState<WSEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    const wsUrl = `${import.meta.env.VITE_WS_URL}/ws/scan/${scanId}`
    let ws: WebSocket

    try {
      ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => setIsConnected(true)
      ws.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data) as WSEvent
          setEvents(prev => [...prev.slice(-49), { ...event, timestamp: new Date().toISOString() }])
        } catch {}
      }
      ws.onclose = () => setIsConnected(false)
      ws.onerror = () => setIsConnected(false)
    } catch {
      setIsConnected(false)
    }

    return () => {
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [scanId])

  return { events, isConnected }
}
