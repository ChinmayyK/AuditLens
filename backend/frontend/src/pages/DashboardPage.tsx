import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Scan, Bug, ShieldAlert, AlertTriangle } from 'lucide-react'
import { useDashboard } from '../hooks/useDashboard'
import Badge, { type BadgeVariant } from '../components/ui/Badge'
import LoadingSkeleton, { SkeletonCard } from '../components/ui/LoadingSkeleton'
import { useGsapReveal } from '../hooks/useGsapReveal'

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, BadgeVariant> = {
    queued: 'default', running: 'blue', complete: 'success', failed: 'critical', cancelled: 'default'
  }
  return <Badge variant={map[status] || 'default'}>{status}</Badge>
}

function GradeBadge({ grade }: { grade?: string }) {
  const map: Record<string, BadgeVariant> = { A: 'success', B: 'success', C: 'warning', D: 'high', F: 'critical' }
  if (!grade) return <span className="text-slate-500">—</span>
  return <Badge variant={map[grade] || 'default'}>{grade}</Badge>
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { data, isLoading } = useDashboard()
  const revealRef = useGsapReveal()

  useEffect(() => { document.title = 'Dashboard | ShieldSentinel' }, [])

  const scoreColor = (s: number | null) => !s ? 'text-slate-400' : s > 60 ? 'text-accent-red' : s > 30 ? 'text-accent-yellow' : 'text-accent-green'

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className="px-6 py-8 sm:px-8 sm:py-10"
    >
      <main className="mx-auto w-full max-w-7xl">
        <div data-reveal className="mb-8">
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Security assessment overview</p>
        </div>

        {/* Stat Cards */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-8">
          {isLoading ? Array(4).fill(0).map((_, i) => <SkeletonCard key={i} />) : (
            <>
              {[
                { label: 'Total Scans', value: data?.total_scans ?? 0, icon: Scan, color: 'text-indigo-200' },
                { label: 'Total Findings', value: data?.total_findings ?? 0, icon: Bug, color: 'text-accent-orange' },
                { label: 'Avg Risk Score', value: data?.avg_risk_score?.toFixed(1) ?? '—', icon: ShieldAlert, color: scoreColor(data?.avg_risk_score ?? null) },
                { label: 'Critical Open', value: data?.critical_open ?? 0, icon: AlertTriangle, color: 'text-accent-red' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs text-slate-400 font-medium">{label}</span>
                    <Icon className={`w-4 h-4 ${color}`} />
                  </div>
                  <div className={`text-3xl font-bold ${color}`}>{value}</div>
                </div>
              ))}
            </>
          )}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          {/* Recent Scans Table */}
          <div data-reveal className="xl:col-span-3 bg-slate-900/70 border border-slate-700/70 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-700">
              <h2 className="font-semibold text-white">Recent Scans</h2>
            </div>
            <div className="overflow-x-auto">
              {isLoading ? (
                <div className="p-4 space-y-3">{Array(5).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-8" />)}</div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-700 text-xs text-slate-500">
                      <th className="px-4 py-3 text-left font-medium">Target</th>
                      <th className="px-4 py-3 text-left font-medium">Status</th>
                      <th className="px-4 py-3 text-left font-medium">Grade</th>
                      <th className="px-4 py-3 text-left font-medium">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.recent_scans || []).map(scan => (
                      <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} className="border-b border-slate-700/60 hover:bg-slate-800/60 cursor-pointer transition-colors">
                        <td className="px-4 py-3 text-slate-300 max-w-[160px] truncate font-mono text-xs">{scan.target}</td>
                        <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                        <td className="px-4 py-3"><GradeBadge grade={scan.risk_grade || undefined} /></td>
                        <td className="px-4 py-3 text-slate-400">{scan.summary?.total ?? '—'}</td>
                      </tr>
                    ))}
                    {(!data?.recent_scans?.length) && (
                      <tr><td colSpan={4} className="px-4 py-8 text-center text-slate-500">No scans yet</td></tr>
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Top Vulns Chart */}
          <div data-reveal className="xl:col-span-2 bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6">
            <h2 className="font-semibold text-white mb-4">Top Vulnerabilities</h2>
            {isLoading ? <LoadingSkeleton height="h-40" /> : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={data?.top_vulns?.slice(0, 6) || []} layout="vertical" margin={{ left: 0 }}>
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis dataKey="vuln_type" type="category" tick={{ fill: '#94a3b8', fontSize: 10 }} width={100} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} labelStyle={{ color: '#e2e8f0' }} />
                  <Bar dataKey="count" fill="#a5b4fc" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
            {!isLoading && (
              <div className="mt-4 space-y-2">
                {(data?.tool_stats || []).slice(0, 5).map(t => (
                  <div key={t.tool} className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">{t.tool}</span>
                    <span className="text-slate-300 font-medium">{t.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </motion.div>
  )
}
