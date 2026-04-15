import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight } from 'lucide-react'
import { motion } from 'framer-motion'
import Badge from '../components/ui/Badge'
import LoadingSkeleton from '../components/ui/LoadingSkeleton'
import { getScan, getScanFindings } from '../services/scanService'
import type { Finding } from '../types/scan'
import { useGsapReveal } from '../hooks/useGsapReveal'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const [filter, setFilter] = useState('all')
  const revealRef = useGsapReveal()

  useEffect(() => { document.title = 'Scan Detail | ShieldSentinel' }, [])

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId!),
  })
  const { data: findings = [], isLoading: findLoading } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => getScanFindings(scanId!),
  })

  const filtered: Finding[] = filter === 'all' ? findings : (findings as Finding[]).filter(f => f.severity === filter)
  const sevMap: Record<string, any> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' }

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className="px-6 py-8 sm:px-8 sm:py-10"
    >
      <main className="mx-auto w-full max-w-7xl">
        <div data-reveal className="flex items-center gap-2 text-sm text-slate-500 mb-6">
          <Link to="/scans" className="hover:text-slate-300">Scans</Link>
          <ChevronRight className="w-4 h-4" />
          <span className="text-slate-300 truncate max-w-xs">{scan?.target || scanId}</span>
        </div>

        {scanLoading ? (
          <div className="space-y-3 mb-8">{Array(3).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-6" />)}</div>
        ) : (
          <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6 mb-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-white font-mono truncate">{scan?.target}</h1>
                <div className="flex items-center gap-3 mt-2">
                  <Badge variant={({ complete: 'success', failed: 'critical', running: 'blue' } as any)[scan?.status] || 'default'}>
                    {scan?.status}
                  </Badge>
                  <span className="text-xs text-slate-500 capitalize">{scan?.scan_type} scan</span>
                </div>
              </div>
              {scan?.risk_grade && (
                <div className="text-5xl font-bold text-white opacity-80">{scan.risk_grade}</div>
              )}
            </div>
          </div>
        )}

        <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700 flex items-center gap-2 flex-wrap">
            {['all', ...SEVERITY_ORDER].map(s => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`px-3 py-1 rounded-lg text-xs font-medium capitalize transition-colors ${filter === s ? 'bg-indigo-500/15 text-indigo-200 border border-indigo-300/30' : 'text-slate-400 hover:text-slate-200'}`}
              >
                {s} ({s === 'all' ? (findings as Finding[]).length : (findings as Finding[]).filter(f => f.severity === s).length})
              </button>
            ))}
          </div>
          {findLoading ? (
            <div className="p-4 space-y-2">{Array(6).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-8" />)}</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-5 py-3 text-left font-medium">Severity</th>
                  <th className="px-5 py-3 text-left font-medium">Type</th>
                  <th className="px-5 py-3 text-left font-medium">File</th>
                  <th className="px-5 py-3 text-left font-medium">Tool</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f: Finding) => (
                  <tr key={f.id} className="border-b border-slate-700/60">
                    <td className="px-5 py-3"><Badge variant={sevMap[f.severity]}>{f.severity}</Badge></td>
                    <td className="px-5 py-3 text-slate-300 text-xs">{f.vuln_type}</td>
                    <td className="px-5 py-3 text-slate-400 font-mono text-xs truncate max-w-[180px]">{f.file_path || '—'}</td>
                    <td className="px-5 py-3 text-slate-500 text-xs">{f.tool_source}</td>
                  </tr>
                ))}
                {!filtered.length && (
                  <tr><td colSpan={4} className="px-5 py-8 text-center text-slate-500">No findings for this filter</td></tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </motion.div>
  )
}
