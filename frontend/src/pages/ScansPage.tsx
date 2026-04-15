import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Plus, X } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import Badge from '../components/ui/Badge'
import LoadingSkeleton from '../components/ui/LoadingSkeleton'
import { getScans, createUrlScan, createGithubScan } from '../services/scanService'
import type { RecentScan } from '../types/scan'
import { useGsapReveal } from '../hooks/useGsapReveal'

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, any> = {
    queued: 'default', running: 'blue', complete: 'success', failed: 'critical', cancelled: 'default'
  }
  return <Badge variant={map[status] || 'default'} className={status === 'running' ? 'animate-pulse' : ''}>{status}</Badge>
}

export default function ScansPage() {
  const navigate = useNavigate()
  const [modal, setModal] = useState(false)
  const [tab, setTab] = useState<'url' | 'github'>('url')
  const [urlForm, setUrlForm] = useState({ target: '', intensity: 'standard' })
  const [ghForm, setGhForm] = useState({ repo: '', branch: 'main' })
  const [submitting, setSubmitting] = useState(false)
  const revealRef = useGsapReveal()

  useEffect(() => { document.title = 'Scans | ShieldSentinel' }, [])

  const hasRunning = (scans: RecentScan[]) => scans.some(s => s.status === 'running' || s.status === 'queued')

  const { data: scans = [], isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: getScans,
    refetchInterval: (query) => (query.state.data && hasRunning(query.state.data)) ? 5000 : false,
  })

  async function handleCreate() {
    setSubmitting(true)
    try {
      if (tab === 'url') {
        await createUrlScan(urlForm.target, urlForm.intensity)
        toast.success('URL scan started')
      } else {
        await createGithubScan(ghForm.repo, ghForm.branch)
        toast.success('GitHub scan started')
      }
      setModal(false)
      refetch()
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Failed to start scan')
    } finally { setSubmitting(false) }
  }

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className="px-6 py-8 sm:px-8 sm:py-10"
    >
      <main className="mx-auto w-full max-w-7xl">
        <div data-reveal className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">Security Scans</h1>
            <p className="text-slate-400 text-sm mt-1">Manage and view all scans</p>
          </div>
          <button onClick={() => setModal(true)} className="flex items-center gap-2 px-4 py-2 bg-slate-100 hover:bg-white text-slate-900 rounded-xl text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" /> New Scan
          </button>
        </div>

        <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl overflow-hidden">
          {isLoading ? (
            <div className="p-4 space-y-3">{Array(6).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-10" />)}</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-5 py-3 text-left font-medium">Target</th>
                  <th className="px-5 py-3 text-left font-medium">Type</th>
                  <th className="px-5 py-3 text-left font-medium">Status</th>
                  <th className="px-5 py-3 text-left font-medium">Risk</th>
                  <th className="px-5 py-3 text-left font-medium">Findings</th>
                  <th className="px-5 py-3 text-left font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {(scans as RecentScan[]).map(scan => (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} className="border-b border-slate-700/60 hover:bg-slate-800/60 cursor-pointer transition-colors">
                    <td className="px-5 py-3 font-mono text-xs text-slate-300 max-w-[200px] truncate">{scan.target}</td>
                    <td className="px-5 py-3 text-slate-400 capitalize">{scan.scan_type}</td>
                    <td className="px-5 py-3"><StatusBadge status={scan.status} /></td>
                    <td className="px-5 py-3">{scan.risk_grade ? <Badge variant={(['A','B'].includes(scan.risk_grade) ? 'success' : scan.risk_grade === 'C' ? 'warning' : 'critical') as any}>{scan.risk_grade}</Badge> : '—'}</td>
                    <td className="px-5 py-3 text-slate-400">{scan.summary?.total ?? '—'}</td>
                    <td className="px-5 py-3 text-slate-500 text-xs">{new Date(scan.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
                {!(scans as RecentScan[]).length && <tr><td colSpan={6} className="px-5 py-12 text-center text-slate-500">No scans yet. Click "New Scan" to start.</td></tr>}
              </tbody>
            </table>
          )}
        </div>

        {/* Modal */}
        {modal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
            <div className="bg-slate-900/90 border border-slate-700/70 rounded-2xl w-full max-w-md p-6">
              <div className="flex items-center justify-between mb-5">
                <h2 className="font-semibold text-white">New Scan</h2>
                <button onClick={() => setModal(false)} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
              </div>
              <div className="flex border border-slate-700 rounded-xl overflow-hidden mb-5">
                {(['url', 'github'] as const).map(t => (
                  <button key={t} onClick={() => setTab(t)} className={`flex-1 py-2 text-sm font-medium transition-colors ${tab === t ? 'bg-indigo-300 text-slate-900' : 'text-slate-400 hover:text-white'}`}>
                    {t === 'url' ? 'URL Scan' : 'GitHub Repo'}
                  </button>
                ))}
              </div>
              {tab === 'url' ? (
                <div className="space-y-4">
                  <input value={urlForm.target} onChange={e => setUrlForm({ ...urlForm, target: e.target.value })} placeholder="https://example.com" className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300" />
                  <select value={urlForm.intensity} onChange={e => setUrlForm({ ...urlForm, intensity: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-300">
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="deep">Deep</option>
                  </select>
                </div>
              ) : (
                <div className="space-y-4">
                  <input value={ghForm.repo} onChange={e => setGhForm({ ...ghForm, repo: e.target.value })} placeholder="owner/repo" className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300" />
                  <input value={ghForm.branch} onChange={e => setGhForm({ ...ghForm, branch: e.target.value })} placeholder="main" className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300" />
                </div>
              )}
              <button onClick={handleCreate} disabled={submitting} className="w-full mt-5 bg-slate-100 hover:bg-white disabled:opacity-50 text-slate-900 font-medium py-2.5 rounded-xl text-sm transition-colors">
                {submitting ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          </div>
        )}
      </main>
    </motion.div>
  )
}
