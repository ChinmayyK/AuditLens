import { useEffect, useState, useRef } from 'react'
import { Shield, RotateCcw, Copy, CheckCircle, Activity, FileCode } from 'lucide-react'
import toast from 'react-hot-toast'
import Sidebar from '../components/layout/Sidebar'
import PRInputForm from '../components/review/PRInputForm'
import ReviewSummaryPanel from '../components/review/ReviewSummaryPanel'
import InlineCodeView from '../components/review/InlineCodeView'
import ReEvaluationPanel from '../components/review/ReEvaluationPanel'
import ConfigViewer from '../components/review/ConfigViewer'
import ErrorBoundary from '../components/ui/ErrorBoundary'
import { submitPRReview } from '../services/reviewService'
import type { ReviewResult, ReviewRequest } from '../types/review'
import api from '../lib/axios'

const LOADING_STEPS = [
  'Fetching diff context...',
  'Running pattern detection...',
  'Filtering by relevance...',
  'Scoring findings...',
  'Generating inline comments...',
  'Building merge decision...',
]

function HealthIndicator() {
  const [status, setStatus] = useState<'loading' | 'up' | 'down'>('loading')
  const [info, setInfo] = useState<any>(null)

  useEffect(() => {
    api.get('/health')
      .then(r => { setStatus('up'); setInfo(r.data) })
      .catch(() => setStatus('down'))
  }, [])

  return (
    <div className="flex items-center gap-2 text-xs text-slate-500 group relative cursor-default">
      <div className={`w-2 h-2 rounded-full ${
        status === 'up' ? 'bg-emerald-300' :
        status === 'down' ? 'bg-accent-red' :
        'bg-accent-yellow animate-pulse'
      }`} />
      <span>Backend {status === 'loading' ? '...' : status === 'up' ? 'Connected' : 'Unreachable'}</span>
      {info && (
        <div className="hidden group-hover:block absolute top-5 right-0 bg-slate-900 border border-slate-700 rounded-xl p-3 shadow-xl z-50 w-48">
          <p className="text-slate-300">v{info.version}</p>
          <p className="text-slate-500">{info.environment}</p>
          <p className="text-slate-600 text-xs">{info.timestamp?.slice(0, 19)}</p>
        </div>
      )}
    </div>
  )
}

function LoadingState() {
  const [stepIdx, setStepIdx] = useState(0)

  useEffect(() => {
    const t = setInterval(() => setStepIdx(i => (i + 1) % LOADING_STEPS.length), 1500)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="flex flex-col items-center justify-center py-24">
      <div className="relative mb-8">
        <Shield className="w-16 h-16 text-indigo-300 animate-pulse" />
        <div className="absolute -top-1 -right-1 w-4 h-4 bg-emerald-300 rounded-full animate-ping" />
      </div>
      <h2 className="text-xl font-bold text-white mb-2">Analyzing PR Security...</h2>
      <div className="h-6">
        <p key={stepIdx} className="text-slate-400 text-sm animate-fade-in">
          {LOADING_STEPS[stepIdx]}
        </p>
      </div>
      <div className="mt-8 flex gap-1">
        {LOADING_STEPS.map((_, i) => (
          <div
            key={i}
            className={`w-2 h-2 rounded-full transition-colors ${
              i === stepIdx ? 'bg-indigo-300' : 'bg-slate-700'
            }`}
          />
        ))}
      </div>
    </div>
  )
}

export default function PRReviewPage() {
  const [state, setState] = useState<'idle' | 'loading' | 'result'>('idle')
  const [result, setResult] = useState<ReviewResult | null>(null)
  const [request, setRequest] = useState<ReviewRequest | null>(null)
  const [meta, setMeta] = useState<{ repo?: string; prNumber?: number }>({})
  const resultRef = useRef<HTMLDivElement>(null)

  useEffect(() => { document.title = 'PR Review | ShieldSentinel' }, [])

  async function handleSubmit(
    req: ReviewRequest,
    m: { repo?: string; prNumber?: number }
  ) {
    setRequest(req)
    setMeta(m)
    setState('loading')
    try {
      const res = await submitPRReview(req)
      setResult(res)
      setState('result')
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Review failed. Check backend connection.')
      setState('idle')
    }
  }

  function handleReEvaluated(newResult: ReviewResult) {
    setResult(newResult)
    resultRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  function copyGitHubReview() {
    if (!result?.pr_review) return
    navigator.clipboard.writeText(JSON.stringify(result.pr_review, null, 2))
    toast.success('GitHub PR review JSON copied!')
  }

  return (
    <div className="flex min-h-screen bg-surface">
      <Sidebar />
      <main className="ml-60 flex-1 p-8">
        {/* Page Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="w-6 h-6 text-indigo-300" /> PR Review Engine
            </h1>
            {state === 'result' && meta.repo && (
              <p className="text-slate-400 text-sm mt-1 font-mono">
                {meta.repo}{meta.prNumber ? ` · PR #${meta.prNumber}` : ''}
              </p>
            )}
          </div>
          <div className="flex items-center gap-4">
            <HealthIndicator />
            {state === 'result' && (
              <button
                onClick={() => setState('idle')}
                className="flex items-center gap-2 px-4 py-2 border border-slate-700 text-slate-300 hover:text-white rounded-xl text-sm transition-colors"
              >
                <RotateCcw className="w-4 h-4" /> Re-run Review
              </button>
            )}
          </div>
        </div>

        {/* IDLE STATE */}
        {state === 'idle' && (
          <div className="max-w-2xl mx-auto">
            <div className="text-center mb-8">
              <h2 className="text-lg font-semibold text-white mb-2">Submit a PR for Security Review</h2>
              <p className="text-slate-400 text-sm">
                Paste findings JSON or connect a GitHub PR to get inline comments,
                a security score, and a merge decision.
              </p>
            </div>
            <PRInputForm onSubmit={handleSubmit} loading={false} />
            <div className="mt-6">
              <ConfigViewer />
            </div>
          </div>
        )}

        {/* LOADING STATE */}
        {state === 'loading' && <LoadingState />}

        {/* RESULT STATE */}
        {state === 'result' && result && (
          <ErrorBoundary>
            <div ref={resultRef} className="space-y-6">
              {/* Summary Panel */}
              <ReviewSummaryPanel result={result} />

              {/* Two-column layout */}
              <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
                {/* Inline Code View */}
                <div className="xl:col-span-3">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="font-semibold text-white flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-indigo-200" /> Inline Comments
                      <span className="text-xs text-slate-500 font-normal">
                        ({result.comments.length} total)
                      </span>
                    </h2>
                  </div>
                  <InlineCodeView comments={result.comments} diffs={request?.diffs} />
                </div>

                {/* Right sidebar */}
                <div className="xl:col-span-2 space-y-5">
                  {/* Files Changed */}
                  <div className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-5">
                    <h3 className="font-semibold text-white text-sm mb-4 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-indigo-200" /> Files Reviewed
                    </h3>
                    <div className="space-y-2">
                      {[...new Set(result.comments.map(c => c.file_path).filter(Boolean))].map(f => {
                        const fc = result.comments.filter(c => c.file_path === f)
                        const hasCrit = fc.some(c => c.severity === 'critical')
                        const hasHigh = fc.some(c => c.severity === 'high')
                        return (
                          <div key={f} className="flex items-center gap-2 text-sm">
                            <FileCode className={`w-3.5 h-3.5 shrink-0 ${
                              hasCrit ? 'text-accent-red' :
                              hasHigh ? 'text-accent-orange' :
                              'text-indigo-200'
                            }`} />
                            <span className="font-mono text-xs text-slate-300 flex-1 truncate">{f}</span>
                            <span className="text-xs text-slate-500">{fc.length}</span>
                          </div>
                        )
                      })}
                      {!result.comments.length && (
                        <p className="text-xs text-slate-500">No files with comments</p>
                      )}
                    </div>
                  </div>

                  {/* GitHub PR Export */}
                  {result.pr_review && (
                    <div className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-5">
                      <h3 className="font-semibold text-white text-sm mb-3 flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-emerald-300" /> GitHub PR Review Export
                      </h3>
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs border border-slate-700 px-2 py-1 rounded text-slate-400">
                          {result.pr_review.event}
                        </span>
                        <span className="text-xs text-slate-500">
                          {result.pr_review.comments.length} inline comments
                        </span>
                      </div>
                      <button
                        onClick={copyGitHubReview}
                        className="w-full flex items-center justify-center gap-2 py-2 border border-slate-700 hover:border-indigo-300/40 text-slate-300 hover:text-white rounded-xl text-xs transition-colors"
                      >
                        <Copy className="w-3.5 h-3.5" /> Copy Review JSON
                      </button>
                    </div>
                  )}

                  {/* Config Viewer */}
                  <ConfigViewer />

                  {/* Re-evaluation Panel */}
                  {request && (
                    <ReEvaluationPanel
                      originalResult={result}
                      originalRequest={request}
                      onReEvaluated={handleReEvaluated}
                    />
                  )}
                </div>
              </div>
            </div>
          </ErrorBoundary>
        )}
      </main>
    </div>
  )
}
