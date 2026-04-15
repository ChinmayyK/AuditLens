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

  const res = await fetch(`${import.meta.env.VITE_API_URL}/review/pr-public`, {
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
    } catch (err: any) {
      if (timerRef.current) clearInterval(timerRef.current)
      setError(err.message || 'Demo failed')
      setState('idle')
      toast.error(err.message || 'Demo failed')
    }
  }

  function handleReEvaluated(newResult: ReviewResult) {
    setResult(newResult)
    resultRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  return (
    <div className="min-h-screen bg-white">
      <Navbar />

      {/* Judge Banner */}
      <div className="border-b border-indigo-200 bg-blue-50 px-6 py-3 text-center">
        <p className="text-sm font-medium text-blue-900">
          🎯 <strong>Live Demo</strong> — Judges: click "Run Demo" to see the complete review pipeline in action
          <span className="ml-2 text-blue-800/70">· No login required</span>
        </p>
      </div>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-2xl font-bold text-blue-900">
              <Shield className="h-6 w-6 shrink-0 text-indigo-700" /> PR Review - Live Demo
            </h1>
            <p className="mt-1 text-sm text-blue-800/70">Analyzing 4 findings across 4 files including critical SQL injection + hardcoded secrets</p>
          </div>
          {state === 'result' && (
            <button onClick={() => { setState('idle'); setResult(null) }} className="flex items-center gap-2 rounded-xl border border-indigo-200 px-4 py-2 text-sm text-blue-800 transition-colors hover:text-blue-900">
              <RotateCcw className="w-4 h-4" /> Reset
            </button>
          )}
        </div>

        {/* IDLE */}
        {state === 'idle' && (
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
            {/* Input Preview */}
            <div>
              <h2 className="mb-3 text-sm font-semibold text-blue-900">Input Findings (4 findings, 4 files)</h2>
              <div className="overflow-hidden rounded-2xl border border-indigo-200 bg-white shadow-sm shadow-blue-100/60">
                <div className="flex items-center gap-2 border-b border-indigo-100 px-4 py-2">
                  <div className="flex gap-1.5">{['bg-red-500', 'bg-yellow-500', 'bg-green-500'].map(c => <div key={c} className={`w-2.5 h-2.5 rounded-full ${c}`} />)}</div>
                  <span className="text-xs font-mono text-blue-800/70">findings.json</span>
                </div>
                <pre className="max-h-96 overflow-x-auto bg-blue-50/40 p-4 font-mono text-xs text-blue-900">
                  {JSON.stringify(DEMO_FINDINGS, null, 2)}
                </pre>
              </div>
              {error && (
                <div className="mt-4 p-4 bg-accent-red/10 border border-accent-red/30 rounded-xl text-sm text-accent-red">
                  <strong>Error:</strong> {error}
                  <br />
                  <span className="mt-1 block text-xs text-red-700">
                    If you see 401: log in first at <a href="/login" className="underline">/login</a> or ask backend to add an unauthenticated demo endpoint.
                  </span>
                </div>
              )}
            </div>

            {/* Run button */}
            <div className="flex flex-col items-center justify-center">
              <div className="text-center mb-8">
                <div className="mx-auto mb-4 flex h-24 w-24 items-center justify-center rounded-full border-2 border-indigo-300/40 bg-indigo-100">
                  <Shield className="h-12 w-12 text-indigo-700" />
                </div>
                <h2 className="mb-2 text-xl font-bold text-blue-900">Ready to Review</h2>
                <p className="max-w-xs text-sm text-blue-800/70">Click Run Demo to see the full review pipeline: pattern detection {'->'} scoring {'->'} decision {'->'} inline comments</p>
              </div>
              <button
                onClick={runDemo}
                className="flex items-center gap-3 rounded-2xl bg-indigo-700 px-10 py-4 text-lg font-bold text-white transition-colors hover:bg-indigo-800 shadow-lg shadow-indigo-200/60"
              >
                <Play className="w-5 h-5" /> Run Demo
              </button>
              <div className="mt-6 w-full rounded-2xl border border-indigo-200 bg-white p-4 shadow-sm shadow-blue-100/60">
                <ConfigViewer />
              </div>
            </div>
          </div>
        )}

        {/* LOADING */}
        {state === 'loading' && (
          <div className="flex flex-col items-center justify-center py-32">
            <Shield className="mb-6 h-16 w-16 animate-pulse text-indigo-700" />
            <h2 className="mb-2 text-xl font-bold text-blue-900">Analyzing PR Security...</h2>
            <AnimatePresence mode="wait">
              <motion.p
                key={stepIdx}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="mb-6 text-sm text-blue-800/70"
              >
                {LOADING_STEPS[stepIdx]}
              </motion.p>
            </AnimatePresence>
            <div className="flex gap-1.5">
              {LOADING_STEPS.map((_, i) => (
                <div key={i} className={`h-2 w-2 rounded-full transition-all duration-300 ${i === stepIdx ? 'w-4 bg-indigo-700' : 'bg-indigo-200'}`} />
              ))}
            </div>
          </div>
        )}

        {/* RESULT */}
        {state === 'result' && result && (
          <ErrorBoundary>
            <div ref={resultRef} className="space-y-6">
              <ReviewSummaryPanel result={result} />

              <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
                <div className="xl:col-span-3">
                  <h2 className="mb-4 flex items-center gap-2 font-semibold text-blue-900">
                    <FileCode className="h-4 w-4 text-indigo-700" /> Inline Comments
                    <span className="text-xs font-normal text-blue-800/70">({result.comments.length})</span>
                  </h2>
                  <InlineCodeView comments={result.comments} diffs={DEMO_REQUEST.diffs} />
                </div>

                <div className="xl:col-span-2 space-y-5">
                  {/* Files */}
                  <div className="rounded-2xl border border-indigo-200 bg-white p-5 shadow-sm shadow-blue-100/60">
                    <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-blue-900">
                      <Activity className="h-4 w-4 text-indigo-700" /> Files Reviewed
                    </h3>
                    {[...new Set(result.comments.map(c => c.file_path).filter(Boolean))].map(f => {
                      const count = result.comments.filter(c => c.file_path === f).length
                      const hasCrit = result.comments.some(c => c.file_path === f && c.severity === 'critical')
                      return (
                        <div key={f} className="flex items-center gap-2 text-xs mb-2">
                          <FileCode className={`h-3.5 w-3.5 ${hasCrit ? 'text-accent-red' : 'text-indigo-700'}`} />
                          <span className="flex-1 truncate font-mono text-blue-900">{f}</span>
                          <span className="text-blue-800/70">{count}</span>
                        </div>
                      )
                    })}
                  </div>

                  {/* GitHub Export */}
                  {result.pr_review && (
                    <div className="rounded-2xl border border-indigo-200 bg-white p-5 shadow-sm shadow-blue-100/60">
                      <h3 className="mb-3 text-sm font-semibold text-blue-900">GitHub PR Review Export</h3>
                      <p className="mb-3 text-xs text-blue-800/70">Ready to POST to GitHub Reviews API</p>
                      <button
                        onClick={() => { navigator.clipboard.writeText(JSON.stringify(result.pr_review, null, 2)); toast.success('Copied!') }}
                        className="flex w-full items-center justify-center gap-2 rounded-xl border border-indigo-200 py-2 text-xs text-blue-800 transition-colors hover:border-indigo-400"
                      >
                        <Copy className="w-3.5 h-3.5" /> Copy Review JSON
                      </button>
                    </div>
                  )}

                  <div className="rounded-2xl border border-indigo-200 bg-white p-4 shadow-sm shadow-blue-100/60">
                    <ConfigViewer />
                  </div>

                  <div className="rounded-2xl border border-indigo-200 bg-white p-4 shadow-sm shadow-blue-100/60">
                    <ReEvaluationPanel
                      originalResult={result}
                      originalRequest={DEMO_REQUEST}
                      onReEvaluated={handleReEvaluated}
                    />
                  </div>
                </div>
              </div>
            </div>
          </ErrorBoundary>
        )}
      </div>
    </div>
  )
}
