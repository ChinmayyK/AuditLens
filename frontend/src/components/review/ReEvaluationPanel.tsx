import { useState } from 'react'
import { RefreshCw, ChevronDown, ChevronUp, ArrowUp, ArrowDown, Minus } from 'lucide-react'
import toast from 'react-hot-toast'
import type { ReviewResult, ReviewRequest } from '../../types/review'
import { reEvaluateReview } from '../../services/reviewService'
import Badge from '../ui/Badge'

interface Props {
  originalResult: ReviewResult
  originalRequest: ReviewRequest
  onReEvaluated: (newResult: ReviewResult) => void
}

export default function ReEvaluationPanel({ originalResult, originalRequest, onReEvaluated }: Props) {
  const uniqueFiles = [...new Set(
    originalResult.comments.map(c => c.file_path).filter(Boolean)
  )] as string[]

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [diffText, setDiffText] = useState('')
  const [diffOpen, setDiffOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [prevScore, setPrevScore] = useState<number | null>(null)
  const [prevDecision, setPrevDecision] = useState<string | null>(null)

  const SEV_VARIANT: Record<string, any> = {
    critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info'
  }

  function toggleFile(f: string) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(f) ? next.delete(f) : next.add(f)
      return next
    })
  }

  function getFileSeverity(filePath: string): string {
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
    const comments = originalResult.comments.filter(c => c.file_path === filePath)
    const minIdx = Math.min(...comments.map(c => sevOrder.indexOf(c.severity)))
    return sevOrder[minIdx] || 'info'
  }

  async function handleReEvaluate() {
    if (selected.size === 0) {
      toast.error('Select at least one fixed file')
      return
    }
    setLoading(true)
    setPrevScore(originalResult.score.total_score)
    setPrevDecision(originalResult.decision.decision)

    try {
      const result = await reEvaluateReview({
        original_findings: originalRequest.findings,
        fixed_file_paths: Array.from(selected),
        diffs: diffText
          ? {
              ...originalRequest.diffs,
              ...(selected.size === 1 ? { [[...selected][0]]: diffText } : {}),
            }
          : originalRequest.diffs,
        changed_lines: originalRequest.changed_lines,
      })
      onReEvaluated(result)
      toast.success('Re-evaluation complete! Score updated.')
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Re-evaluation failed')
    } finally {
      setLoading(false)
    }
  }

  const scoreDiff = prevScore !== null
    ? originalResult.score.total_score - prevScore
    : null

  return (
    <div className="bg-surface-card border border-accent-yellow/30 rounded-2xl p-5">
      <div className="flex items-center gap-2 mb-1">
        <RefreshCw className="w-4 h-4 text-accent-yellow" />
        <h3 className="font-semibold text-white text-sm">🔧 Mark Files as Fixed</h3>
      </div>
      <p className="text-xs text-slate-500 mb-4">
        Select files you've fixed. We'll re-evaluate only those lines.
      </p>

      {/* Score diff after re-eval */}
      {scoreDiff !== null && (
        <div className="flex items-center gap-4 p-3 bg-surface rounded-lg border border-surface-border mb-4 text-sm">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Score:</span>
            <span className="text-slate-500">{prevScore?.toFixed(0)}</span>
            <span className="text-slate-600">→</span>
            <span className={scoreDiff > 0 ? 'text-accent-green font-bold' : 'text-accent-red font-bold'}>
              {originalResult.score.total_score.toFixed(0)}
              {scoreDiff > 0
                ? <ArrowUp className="w-3 h-3 inline ml-1" />
                : scoreDiff < 0
                ? <ArrowDown className="w-3 h-3 inline ml-1" />
                : <Minus className="w-3 h-3 inline ml-1" />}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Decision:</span>
            <span className="text-slate-500 capitalize">{prevDecision?.replace('_', ' ')}</span>
            <span className="text-slate-600">→</span>
            <span className={
              originalResult.decision.decision === 'approve'
                ? 'text-accent-green font-medium capitalize'
                : originalResult.decision.decision === 'block'
                ? 'text-accent-red font-medium capitalize'
                : 'text-accent-yellow font-medium capitalize'
            }>
              {originalResult.decision.decision.replace('_', ' ')}
            </span>
          </div>
        </div>
      )}

      {/* File checklist */}
      <div className="space-y-2 mb-4">
        {uniqueFiles.map(f => {
          const sev = getFileSeverity(f)
          const count = originalResult.comments.filter(c => c.file_path === f).length
          return (
            <label
              key={f}
              className="flex items-center gap-3 p-3 rounded-lg bg-surface border border-surface-border cursor-pointer hover:border-primary/40 transition-colors"
            >
              <input
                type="checkbox"
                checked={selected.has(f)}
                onChange={() => toggleFile(f)}
                className="accent-primary w-4 h-4"
              />
              <span className="text-sm font-mono text-slate-300 flex-1 truncate">{f}</span>
              <Badge variant={SEV_VARIANT[sev]}>{sev}</Badge>
              <span className="text-xs text-slate-500">{count} issue{count !== 1 ? 's' : ''}</span>
            </label>
          )
        })}
        {uniqueFiles.length === 0 && (
          <p className="text-xs text-slate-500 text-center py-4">No files with comments</p>
        )}
      </div>

      {/* Optional diff input */}
      <div className="mb-4">
        <button
          onClick={() => setDiffOpen(!diffOpen)}
          className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          {diffOpen
            ? <ChevronUp className="w-3 h-3" />
            : <ChevronDown className="w-3 h-3" />}
          Paste updated diff (optional — improves accuracy)
        </button>
        {diffOpen && (
          <textarea
            value={diffText}
            onChange={e => setDiffText(e.target.value)}
            rows={6}
            placeholder="Paste unified diff of your fix here..."
            className="w-full mt-2 bg-surface border border-surface-border rounded-xl px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-primary resize-none"
          />
        )}
      </div>

      <button
        onClick={handleReEvaluate}
        disabled={loading || selected.size === 0}
        className="w-full flex items-center justify-center gap-2 py-2.5 bg-accent-yellow/10 border border-accent-yellow/30 hover:bg-accent-yellow/20 disabled:opacity-50 disabled:cursor-not-allowed text-accent-yellow font-medium rounded-xl text-sm transition-colors"
      >
        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        {loading
          ? 'Re-evaluating...'
          : `Re-evaluate${selected.size > 0 ? ` (${selected.size} file${selected.size > 1 ? 's' : ''})` : ''}`}
      </button>
    </div>
  )
}
