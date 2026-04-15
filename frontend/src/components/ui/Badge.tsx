import type { ReactNode } from 'react'
import clsx from 'clsx'

type Variant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'default' | 'blue'

const variantMap: Record<Variant, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-slate-500/15 text-slate-400 border-slate-500/30',
  success:  'bg-green-500/15 text-green-400 border-green-500/30',
  warning:  'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  blue:     'bg-blue-500/15 text-blue-400 border-blue-500/30',
  default:  'bg-slate-700/40 text-slate-300 border-slate-600/40',
}

interface BadgeProps { variant?: Variant; children: ReactNode; className?: string }

export default function Badge({ variant = 'default', children, className }: BadgeProps) {
  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border', variantMap[variant], className)}>
      {children}
    </span>
  )
}
