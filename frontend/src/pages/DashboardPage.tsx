import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Scan, Bug, ShieldAlert, AlertTriangle } from 'lucide-react'
import { useDashboard } from '../hooks/useDashboard'
import Badge from '../components/ui/Badge'
import LoadingSkeleton, { SkeletonCard } from '../components/ui/LoadingSkeleton'
import { useGsapReveal } from '../hooks/useGsapReveal'

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, any> = {
    queued: 'default', running: 'blue', complete: 'success', failed: 'critical', cancelled: 'default'
  }
  return <Badge variant={map[status] || 'default'}>{status}</Badge>
}

function GradeBadge({ grade }: { grade?: string }) {
  const map: Record<string, any> = { A: 'success', B: 'success', C: 'warning', D: 'high', F: 'critical' }
  if (!grade) return <span className="text-slate-500">—</span>
  return <Badge variant={map[grade] || 'default'}>{grade}</Badge>
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { data, isLoading } = useDashboard()
  const revealRef = useGsapReveal()

  useEffect(() => { document.title = 'Dashboard | ShieldSentinel' }, [])

  const scoreColor = (s: number | null) => !s ? 'text-blue-700/70' : s > 60 ? 'text-accent-red' : s > 30 ? 'text-amber-600' : 'text-emerald-600'

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
          <h1 className="text-2xl font-bold text-blue-900">Dashboard</h1>
          <p className="mt-1 text-sm text-blue-800/70">Security assessment overview</p>
        </div>

        {/* Stat Cards */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-8">
          {isLoading ? Array(4).fill(0).map((_, i) => <SkeletonCard key={i} />) : (
            <>
              {[
                { label: 'Total Scans', value: data?.total_scans ?? 0, icon: Scan, color: 'text-indigo-700' },
                { label: 'Total Findings', value: data?.total_findings ?? 0, icon: Bug, color: 'text-accent-orange' },
                { label: 'Avg Risk Score', value: data?.avg_risk_score?.toFixed(1) ?? '—', icon: ShieldAlert, color: scoreColor(data?.avg_risk_score ?? null) },
                { label: 'Critical Open', value: data?.critical_open ?? 0, icon: AlertTriangle, color: 'text-accent-red' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} data-reveal className="rounded-2xl border border-indigo-200 bg-white p-5 shadow-sm shadow-blue-100/60">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-blue-800/70">{label}</span>
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
          <div data-reveal className="xl:col-span-3 overflow-hidden rounded-2xl border border-indigo-200 bg-white shadow-sm shadow-blue-100/60">
            <div className="border-b border-indigo-100 px-6 py-4">
              <h2 className="font-semibold text-blue-900">Recent Scans</h2>
            </div>
            <div className="overflow-x-auto">
              {isLoading ? (
                <div className="p-4 space-y-3">{Array(5).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-8" />)}</div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-indigo-100 text-xs text-blue-800/70">
                      <th className="px-4 py-3 text-left font-medium">Target</th>
                      <th className="px-4 py-3 text-left font-medium">Status</th>
                      <th className="px-4 py-3 text-left font-medium">Grade</th>
                      <th className="px-4 py-3 text-left font-medium">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.recent_scans || []).map(scan => (
                      <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} className="cursor-pointer border-b border-indigo-100 transition-colors hover:bg-blue-50">
                        <td className="max-w-[160px] truncate px-4 py-3 font-mono text-xs text-blue-900">{scan.target}</td>
                        <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                        <td className="px-4 py-3"><GradeBadge grade={scan.risk_grade || undefined} /></td>
                        <td className="px-4 py-3 text-blue-800/70">{scan.summary?.total ?? '—'}</td>
                      </tr>
                    ))}
                    {(!data?.recent_scans?.length) && (
                      <tr><td colSpan={4} className="px-4 py-8 text-center text-blue-800/70">No scans yet</td></tr>
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Top Vulns Chart */}
          <div data-reveal className="xl:col-span-2 rounded-2xl border border-indigo-200 bg-white p-6 shadow-sm shadow-blue-100/60">
            <h2 className="mb-4 font-semibold text-blue-900">Top Vulnerabilities</h2>
            {isLoading ? <LoadingSkeleton height="h-40" /> : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={data?.top_vulns?.slice(0, 6) || []} layout="vertical" margin={{ left: 0 }}>
                  <XAxis type="number" tick={{ fill: '#1e3a8a', fontSize: 11 }} />
                  <YAxis dataKey="vuln_type" type="category" tick={{ fill: '#1e3a8a', fontSize: 10 }} width={100} />
                  <Tooltip contentStyle={{ background: '#ffffff', border: '1px solid #dbeafe', borderRadius: 8 }} labelStyle={{ color: '#1e3a8a' }} />
                  <Bar dataKey="count" fill="#1d4ed8" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
            {!isLoading && (
              <div className="mt-4 space-y-2">
                {(data?.tool_stats || []).slice(0, 5).map(t => (
                  <div key={t.tool} className="flex items-center justify-between text-xs">
                    <span className="font-mono text-blue-800/70">{t.tool}</span>
                    <span className="font-medium text-blue-900">{t.count}</span>
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
