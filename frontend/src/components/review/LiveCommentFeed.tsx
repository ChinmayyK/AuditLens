import { AnimatePresence, motion } from 'framer-motion'
import type { WSEvent } from '../../hooks/useScanWebSocket'
import Badge from '../ui/Badge'

function timeAgo(iso?: string) {
  if (!iso) return ''
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  return `${Math.floor(diff / 60)}m ago`
}

const eventVariant: Record<string, any> = {
  comment: 'blue', score_update: 'success', progress: 'default', error: 'critical'
}

interface Props { events: WSEvent[]; isConnected: boolean }

export default function LiveCommentFeed({ events, isConnected }: Props) {
  return (
    <div className="bg-surface-card border border-surface-border rounded-2xl p-4 max-h-64 overflow-y-auto">
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-accent-green animate-pulse' : 'bg-slate-500'}`} />
        <span className="text-xs font-medium text-slate-400">{isConnected ? 'Live' : 'Offline'}</span>
      </div>
      <div className="space-y-2">
        <AnimatePresence>
          {events.slice().reverse().map((ev, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex items-start gap-2 text-xs">
              <span className="text-slate-600 shrink-0 w-12">{timeAgo(ev.timestamp)}</span>
              <Badge variant={eventVariant[ev.type] || 'default'}>{ev.type}</Badge>
              <span className="text-slate-400">{ev.message || JSON.stringify(ev.data)}</span>
            </motion.div>
          ))}
        </AnimatePresence>
        {!events.length && (
          <p className="text-xs text-slate-600 text-center py-4">
            {isConnected ? 'Waiting for events...' : 'Connect to a review session to see live updates'}
          </p>
        )}
      </div>
    </div>
  )
}
