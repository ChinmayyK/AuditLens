import { useState } from 'react'
import { Eye, EyeOff, ShieldCheck, Code2, GitPullRequest, AlertCircle } from 'lucide-react'
import type { ReviewRequest, FindingInput } from '../../types/review'

const EXAMPLE_FINDINGS: FindingInput[] = [
  {
    file_path: 'src/db/queries.js',
    line_number: 42,
    vuln_type: 'sql_injection',
    severity: 'critical',
    tool: 'semgrep',
    message: "User input concatenated directly into SQL query",
    code_snippet: "db.query('SELECT * FROM users WHERE id=' + userId)",
    confidence: 0.95,
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
    message: 'HTTP used instead of HTTPS for API call',
    code_snippet: "fetch('http://api.example.com/data')",
    confidence: 0.85,
  },
  {
    file_path: 'src/utils/auth.js',
    line_number: 23,
    vuln_type: 'hardcoded_secret',
    severity: 'high',
    tool: 'gitleaks',
    message: 'Hardcoded JWT secret in source',
    code_snippet: "const JWT_SECRET = 'mysupersecretpassword123'",
    confidence: 0.98,
  },
]

interface Props {
  onSubmit: (request: ReviewRequest, meta: { repo?: string; prNumber?: number }) => void
  loading: boolean
}

export default function PRInputForm({ onSubmit, loading }: Props) {
  const [tab, setTab] = useState<'github' | 'manual'>('manual')
  const [ghForm, setGhForm] = useState({ repo: '', prNumber: '', token: '' })
  const [showToken, setShowToken] = useState(false)
  const [jsonText, setJsonText] = useState(JSON.stringify(EXAMPLE_FINDINGS, null, 2))
  const [jsonError, setJsonError] = useState('')

  function handleGitHubSubmit() {
    if (!ghForm.repo || !ghForm.prNumber) return
    const request: ReviewRequest = {
      findings: EXAMPLE_FINDINGS,
      diffs: {},
      changed_lines: {},
    }
    onSubmit(request, { repo: ghForm.repo, prNumber: Number(ghForm.prNumber) })
  }

  function handleManualSubmit() {
    setJsonError('')
    try {
      const parsed = JSON.parse(jsonText)
      if (!Array.isArray(parsed) || parsed.length === 0) {
        setJsonError('Must be a non-empty JSON array of findings')
        return
      }
      const request: ReviewRequest = {
        findings: parsed as FindingInput[],
        diffs: {},
        changed_lines: {},
      }
      onSubmit(request, {})
    } catch {
      setJsonError('Invalid JSON — check syntax and try again')
    }
  }

  return (
    <div className="w-full max-w-2xl mx-auto">
      {/* Tab Switcher */}
      <div className="flex border border-surface-border rounded-2xl overflow-hidden mb-6">
        <button
          onClick={() => setTab('github')}
          className={`flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors ${tab === 'github' ? 'bg-primary text-white' : 'text-slate-400 hover:text-white hover:bg-surface-hover'}`}
        >
          <GitPullRequest className="w-4 h-4" /> GitHub PR
        </button>
        <button
          onClick={() => setTab('manual')}
          className={`flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors ${tab === 'manual' ? 'bg-primary text-white' : 'text-slate-400 hover:text-white hover:bg-surface-hover'}`}
        >
          <Code2 className="w-4 h-4" /> Manual Input
        </button>
      </div>

      {tab === 'github' ? (
        <div className="space-y-4">
          <div className="p-3 bg-accent-yellow/10 border border-accent-yellow/30 rounded-xl text-xs text-accent-yellow flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              GitHub PR ingestion endpoint is pending on backend. The form submits example findings for demo.
              Add <code className="font-mono bg-black/20 px-1 rounded">POST /review/github-pr</code> to enable real PR fetching.
            </span>
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Repository</label>
            <input
              value={ghForm.repo}
              onChange={e => setGhForm({ ...ghForm, repo: e.target.value })}
              placeholder="owner/repo  (e.g. facebook/react)"
              className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">PR Number</label>
            <input
              type="number"
              value={ghForm.prNumber}
              onChange={e => setGhForm({ ...ghForm, prNumber: e.target.value })}
              placeholder="42"
              className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">GitHub Token (PAT)</label>
            <div className="relative">
              <input
                type={showToken ? 'text' : 'password'}
                value={ghForm.token}
                onChange={e => setGhForm({ ...ghForm, token: e.target.value })}
                placeholder="ghp_..."
                className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500"
              >
                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <button
            onClick={handleGitHubSubmit}
            disabled={loading || !ghForm.repo || !ghForm.prNumber}
            className="w-full flex items-center justify-center gap-2 py-3 bg-primary hover:bg-primary-dark disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl text-sm transition-colors"
          >
            <ShieldCheck className="w-4 h-4" />
            {loading ? 'Analyzing PR...' : 'Run AI Review'}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-sm text-slate-400">Findings JSON Array</label>
            <button
              onClick={() => setJsonText(JSON.stringify(EXAMPLE_FINDINGS, null, 2))}
              className="text-xs text-primary-light hover:underline"
            >
              Load example
            </button>
          </div>
          <textarea
            value={jsonText}
            onChange={e => { setJsonText(e.target.value); setJsonError('') }}
            rows={16}
            spellCheck={false}
            className="w-full bg-surface border border-surface-border rounded-xl px-4 py-3 text-xs text-slate-300 font-mono placeholder-slate-600 focus:outline-none focus:border-primary transition-colors resize-none"
          />
          {jsonError && (
            <div className="flex items-center gap-2 text-sm text-accent-red">
              <AlertCircle className="w-4 h-4" /> {jsonError}
            </div>
          )}
          <button
            onClick={handleManualSubmit}
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 bg-primary hover:bg-primary-dark disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl text-sm transition-colors"
          >
            <ShieldCheck className="w-4 h-4" />
            {loading ? 'Analyzing...' : 'Run AI Review'}
          </button>
        </div>
      )}
    </div>
  )
}
