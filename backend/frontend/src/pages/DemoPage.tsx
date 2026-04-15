import { useEffect, useState, useRef } from 'react'
import { Shield, Play, RotateCcw, FileCode, Activity, Copy } from 'lucide-react'
import toast from 'react-hot-toast'
import { motion, AnimatePresence } from 'framer-motion'
import Navbar from '../components/layout/Navbar'
import ReviewSummaryPanel from '../components/review/ReviewSummaryPanel'
import InlineCodeView from '../components/review/InlineCodeView'
import ReEvaluationPanel from '../components/review/ReEvaluationPanel'
import ConfigViewer from '../components/review/ConfigViewer'
import ErrorBoundary from '../components/ui/ErrorBoundary'
import type { ReviewResult, ReviewRequest, FindingInput } from '../types/review'
import { getApiBaseUrl } from '../lib/runtimeConfig'
import { asApiError } from '../lib/errors'

// Demo findings — guaranteed to trigger BLOCKED decision
const DEMO_FINDINGS: FindingInput[] = [
  {
    file_path: 'src/db/queries.js',
    line_number: 42,
    vuln_type: 'sql_injection',
    severity: 'critical',
    tool: 'semgrep',
    message: "User input concatenated directly into SQL query",
    code_snippet: "db.query('SELECT * FROM users WHERE id=' + userId)",
    confidence: 0.95,
    rule_id: 'SQLI-001',
  },
  {
    file_path: 'src/config/aws.js',
    line_number: 8,
    vuln_type: 'hardcoded_secret',
    severity: 'critical',
    tool: 'gitleaks',
    message: 'AWS API key found in source code',
    code_snippet: "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
    confidence: 1.0,
  },
  {
    file_path: 'src/api/fetch.js',
    line_number: 15,
    vuln_type: 'insecure_http',
    severity: 'medium',
    tool: 'pattern_detector',
    message: 'HTTP used instead of HTTPS',
    code_snippet: "fetch('http://api.example.com/data')",
    confidence: 0.85,
  },
  {
    file_path: 'src/utils/auth.js',
    line_number: 23,
    vuln_type: 'hardcoded_secret',
    severity: 'high',
    tool: 'gitleaks',
    message: 'Hardcoded JWT secret detected',
    code_snippet: "const JWT_SECRET = 'mysupersecretpassword123'",
    confidence: 0.98,
  },
]

const DEMO_REQUEST: ReviewRequest = {
  findings: DEMO_FINDINGS,
  diffs: {
    'src/db/queries.js': `@@ -40,5 +40,5 @@
 function getUser(userId) {
-  const query = 'SELECT * FROM users WHERE id=' + userId;
+  const query = 'SELECT * FROM users WHERE id=' + userId; // TODO: fix this
   return db.query(query);
 }`,
    'src/config/aws.js': `@@ -6,5 +6,5 @@
 // AWS Configuration
-const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
+const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'; // FIXME: move to env
 const AWS_REGION = 'us-east-1';`,
  },
  changed_lines: {
    'src/db/queries.js': [42, 43],
    'src/config/aws.js': [8, 9],
    'src/api/fetch.js': [15],
    'src/utils/auth.js': [23],
  },
}

const LOADING_STEPS = [
  '🔍 Fetching diff context...',
  '🛡️ Running pattern detection...',
  '📊 Scoring findings...',
  '💬 Generating inline comments...',
  '⚖️ Building merge decision...',
]

// Direct API call without requiring stored auth token for demo
async function callReviewAPI(request: ReviewRequest): Promise<ReviewResult> {
  const storedUser = (() => {
    try { return JSON.parse(localStorage.getItem('ss_user') || '{}') } catch { return {} }
  })()

  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (storedUser?.access_token) {
    headers['Authorization'] = `Bearer ${storedUser.access_token}`
  }

  const res = await fetch(`${getApiBaseUrl()}/review/pr-public`, {
    method: 'POST',
    headers,
    credentials: 'include',
    body: JSON.stringify(request),
  })


  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    if (res.status === 401) {
      throw new Error('Authentication required. Please log in first or ask backend to add a public demo endpoint.')
    }
    throw new Error(err.detail || `API error ${res.status}`)
  }
  return res.json()
}

export default function DemoPage() {
  const [state, setState] = useState<'idle' | 'loading' | 'result'>('idle')
  const [result, setResult] = useState<ReviewResult | null>(null)
  const [stepIdx, setStepIdx] = useState(0)
  const [error, setError] = useState('')
  const resultRef = useRef<HTMLDivElement>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    document.title = 'Live Demo | ShieldSentinel'
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [])

  async function runDemo() {
    setError('')
    setState('loading')
    setStepIdx(0)
    timerRef.current = setInterval(() => setStepIdx(i => (i + 1) % LOADING_STEPS.length), 1400)

    try {
      const res = await callReviewAPI(DEMO_REQUEST)
      if (timerRef.current) clearInterval(timerRef.current)
      setResult(res)
      setState('result')
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200)
    } catch (err: unknown) {
      const apiError = asApiError(err)
      if (timerRef.current) clearInterval(timerRef.current)
      setError(apiError.message || 'Demo failed')
      setState('idle')
      toast.error(apiError.message || 'Demo failed')
    }
  }

  function handleReEvaluated(newResult: ReviewResult) {
    setResult(newResult)
    resultRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  return (
    <div className="min-h-screen bg-surface">
      <Navbar />

      {/* Judge Banner */}
      <div className="bg-indigo-500/10 border-b border-indigo-300/20 px-6 py-3 text-center">
        <p className="text-sm text-indigo-200 font-medium">
          🎯 <strong>Live Demo</strong> — Judges: click "Run Demo" to see the complete review pipeline in action
          <span className="text-slate-500 ml-2">· No login required</span>
        </p>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="w-6 h-6 text-indigo-300" /> PR Review — Live Demo
            </h1>
            <p className="text-slate-400 text-sm mt-1">Analyzing 4 findings across 4 files including critical SQL injection + hardcoded secrets</p>
          </div>
          {state === 'result' && (
            <button onClick={() => { setState('idle'); setResult(null) }} className="flex items-center gap-2 px-4 py-2 border border-slate-700 text-slate-300 hover:text-white rounded-xl text-sm transition-colors">
              <RotateCcw className="w-4 h-4" /> Reset
            </button>
          )}
        </div>

        {/* IDLE */}
        {state === 'idle' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Input Preview */}
            <div>
              <h2 className="font-semibold text-white mb-3 text-sm">Input Findings (4 findings, 4 files)</h2>
              <div className="bg-slate-900/70 border border-slate-700/70 rounded-2xl overflow-hidden">
                <div className="px-4 py-2 border-b border-slate-700 flex items-center gap-2">
                  <div className="flex gap-1.5">{['bg-red-500', 'bg-yellow-500', 'bg-green-500'].map(c => <div key={c} className={`w-2.5 h-2.5 rounded-full ${c}`} />)}</div>
                  <span className="text-xs text-slate-500 font-mono">findings.json</span>
                </div>
                <pre className="p-4 text-xs text-slate-300 font-mono overflow-x-auto max-h-96">
                  {JSON.stringify(DEMO_FINDINGS, null, 2)}
                </pre>
              </div>
              {error && (
                <div className="mt-4 p-4 bg-accent-red/10 border border-accent-red/30 rounded-xl text-sm text-accent-red">
                  <strong>Error:</strong> {error}
                  <br />
                  <span className="text-xs mt-1 block text-red-300">
                    If you see 401: log in first at <a href="/login" className="underline">/login</a> or ask backend to add an unauthenticated demo endpoint.
                  </span>
                </div>
              )}
            </div>

            {/* Run button */}
            <div className="flex flex-col items-center justify-center">
              <div className="text-center mb-8">
                <div className="w-24 h-24 rounded-full bg-indigo-500/10 border-2 border-indigo-300/30 flex items-center justify-center mx-auto mb-4">
                  <Shield className="w-12 h-12 text-indigo-300" />
                </div>
                <h2 className="text-xl font-bold text-white mb-2">Ready to Review</h2>
                <p className="text-slate-400 text-sm max-w-xs">Click Run Demo to see the full review pipeline: pattern detection → scoring → decision → inline comments</p>
              </div>
              <button
                onClick={runDemo}
                className="flex items-center gap-3 px-10 py-4 bg-slate-100 hover:bg-white text-slate-900 font-bold rounded-2xl text-lg transition-colors shadow-lg shadow-black/20"
              >
                <Play className="w-5 h-5" /> Run Demo
              </button>
              <ConfigViewer />
            </div>
          </div>
        )}

        {/* LOADING */}
        {state === 'loading' && (
          <div className="flex flex-col items-center justify-center py-32">
            <Shield className="w-16 h-16 text-indigo-300 animate-pulse mb-6" />
            <h2 className="text-xl font-bold text-white mb-2">Analyzing PR Security...</h2>
            <AnimatePresence mode="wait">
              <motion.p
                key={stepIdx}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="text-slate-400 text-sm mb-6"
              >
                {LOADING_STEPS[stepIdx]}
              </motion.p>
            </AnimatePresence>
            <div className="flex gap-1.5">
              {LOADING_STEPS.map((_, i) => (
                <div key={i} className={`w-2 h-2 rounded-full transition-all duration-300 ${i === stepIdx ? 'bg-indigo-300 w-4' : 'bg-slate-700'}`} />
              ))}
            </div>
          </div>
        )}

        {/* RESULT */}
        {state === 'result' && result && (
          <ErrorBoundary>
            <div ref={resultRef} className="space-y-6">
              <ReviewSummaryPanel result={result} />

              <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
                <div className="xl:col-span-3">
                  <h2 className="font-semibold text-white flex items-center gap-2 mb-4">
                    <FileCode className="w-4 h-4 text-indigo-200" /> Inline Comments
                    <span className="text-xs text-slate-500 font-normal">({result.comments.length})</span>
                  </h2>
                  <InlineCodeView comments={result.comments} diffs={DEMO_REQUEST.diffs} />
                </div>

                <div className="xl:col-span-2 space-y-5">
                  {/* Files */}
                  <div className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-5">
                    <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-indigo-200" /> Files Reviewed
                    </h3>
                    {[...new Set(result.comments.map(c => c.file_path).filter(Boolean))].map(f => {
                      const count = result.comments.filter(c => c.file_path === f).length
                      const hasCrit = result.comments.some(c => c.file_path === f && c.severity === 'critical')
                      return (
                        <div key={f} className="flex items-center gap-2 text-xs mb-2">
                          <FileCode className={`w-3.5 h-3.5 ${hasCrit ? 'text-accent-red' : 'text-indigo-200'}`} />
                          <span className="font-mono text-slate-300 flex-1 truncate">{f}</span>
                          <span className="text-slate-500">{count}</span>
                        </div>
                      )
                    })}
                  </div>

                  {/* GitHub Export */}
                  {result.pr_review && (
                    <div className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-5">
                      <h3 className="text-sm font-semibold text-white mb-3">GitHub PR Review Export</h3>
                      <p className="text-xs text-slate-400 mb-3">Ready to POST to GitHub Reviews API</p>
                      <button
                        onClick={() => { navigator.clipboard.writeText(JSON.stringify(result.pr_review, null, 2)); toast.success('Copied!') }}
                        className="w-full flex items-center justify-center gap-2 py-2 border border-slate-700 hover:border-indigo-300/40 text-slate-300 rounded-xl text-xs transition-colors"
                      >
                        <Copy className="w-3.5 h-3.5" /> Copy Review JSON
                      </button>
                    </div>
                  )}

                  <ConfigViewer />

                  <ReEvaluationPanel
                    originalResult={result}
                    originalRequest={DEMO_REQUEST}
                    onReEvaluated={handleReEvaluated}
                  />
                </div>
              </div>
            </div>
          </ErrorBoundary>
        )}
      </div>
    </div>
  )
}
