import { useState } from 'react'
import { ChevronDown, ChevronRight, FileCode, MessageSquare, Lightbulb } from 'lucide-react'
import Editor from '@monaco-editor/react'
import type { ReviewComment } from '../../types/review'
import Badge, { type BadgeVariant } from '../ui/Badge'

const SEV_VARIANT: Record<string, BadgeVariant> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info'
}

const SEV_BORDER: Record<string, string> = {
  critical: 'border-l-red-500',
  high:     'border-l-orange-500',
  medium:   'border-l-yellow-500',
  low:      'border-l-blue-500',
  info:     'border-l-slate-500',
}

function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase()
  const map: Record<string, string> = {
    js: 'javascript', ts: 'typescript', tsx: 'typescript', jsx: 'javascript',
    py: 'python', rb: 'ruby', java: 'java', php: 'php', go: 'go',
    rs: 'rust', cs: 'csharp', cpp: 'cpp', c: 'c', sh: 'shell',
    yaml: 'yaml', yml: 'yaml', json: 'json', md: 'markdown',
  }
  return map[ext || ''] || 'plaintext'
}

function FileSection({
  filePath, comments, diff
}: {
  filePath: string
  comments: ReviewComment[]
  diff?: string
}) {
  const [open, setOpen] = useState(true)

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
  const maxSev = comments.reduce((acc, c) => {
    return sevOrder.indexOf(c.severity) < sevOrder.indexOf(acc) ? c.severity : acc
  }, 'info')

  const codeValue = diff ||
    comments.filter(c => c.diff_hunk).map(c => c.diff_hunk).join('\n---\n') ||
    '// No code context available for this file'

  const lineCount = codeValue.split('\n').length
  const editorHeight = Math.min(Math.max(lineCount * 19, 80), 400)

  return (
    <div className="border border-surface-border rounded-xl overflow-hidden mb-4">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-surface-hover hover:bg-surface-border/30 transition-colors text-left"
      >
        {open
          ? <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
          : <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />
        }
        <FileCode className="w-4 h-4 text-primary-light shrink-0" />
        <span className="text-sm font-mono text-slate-200 truncate flex-1">{filePath}</span>
        <div className="flex items-center gap-2">
          <Badge variant={SEV_VARIANT[maxSev]}>{maxSev}</Badge>
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <MessageSquare className="w-3 h-3" /> {comments.length}
          </span>
        </div>
      </button>

      {open && (
        <div>
          {/* Monaco code view */}
          {codeValue !== '// No code context available for this file' && (
            <div className="border-b border-surface-border">
              <Editor
                height={`${editorHeight}px`}
                language={detectLanguage(filePath)}
                value={codeValue}
                theme="vs-dark"
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  fontSize: 12,
                  wordWrap: 'on',
                  folding: false,
                  renderLineHighlight: 'none',
                  overviewRulerLanes: 0,
                }}
              />
            </div>
          )}

          {/* Inline comment cards */}
          <div className="divide-y divide-surface-border/50">
            {[...comments]
              .sort((a, b) => (a.line_number || 0) - (b.line_number || 0))
              .map((comment, i) => (
                <div
                  key={i}
                  className={`border-l-4 ${SEV_BORDER[comment.severity] || 'border-l-slate-600'} px-5 py-4`}
                >
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    {comment.line_number && (
                      <span className="text-xs font-mono bg-surface border border-surface-border px-2 py-0.5 rounded text-slate-400">
                        Line {comment.line_number}
                      </span>
                    )}
                    <Badge variant={SEV_VARIANT[comment.severity] || 'default'}>
                      {comment.severity}
                    </Badge>
                    <span className="text-xs bg-primary/10 border border-primary/20 text-primary-light px-2 py-0.5 rounded">
                      {comment.category}
                    </span>
                    <span className="text-xs text-slate-500 font-mono ml-auto">
                      via {comment.tool}
                      {comment.rule_id && ` · ${comment.rule_id}`}
                    </span>
                  </div>
                  <p className="text-sm font-semibold text-white mb-1.5">
                    {comment.vuln_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  </p>
                  <p className="text-sm text-slate-300 leading-relaxed mb-2">{comment.body}</p>
                  {comment.suggestion && (
                    <div className="mt-3 p-3 bg-accent-green/5 border border-accent-green/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-1.5">
                        <Lightbulb className="w-3.5 h-3.5 text-accent-green" />
                        <span className="text-xs font-semibold text-accent-green">Suggestion</span>
                      </div>
                      <p className="text-xs text-green-200 leading-relaxed">{comment.suggestion}</p>
                    </div>
                  )}
                  {comment.confidence !== undefined && comment.confidence < 1 && (
                    <p className="text-xs text-slate-600 mt-2">
                      Confidence: {(comment.confidence * 100).toFixed(0)}%
                    </p>
                  )}
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}

interface Props {
  comments: ReviewComment[]
  diffs?: Record<string, string>
}

export default function InlineCodeView({ comments, diffs = {} }: Props) {
  if (!comments.length) {
    return (
      <div className="text-center py-12 text-slate-500">
        <MessageSquare className="w-10 h-10 mx-auto mb-3 opacity-40" />
        <p>No inline comments generated.</p>
      </div>
    )
  }

  // Group by file, sort most-severe file first
  const byFile = new Map<string, ReviewComment[]>()
  for (const c of comments) {
    const key = c.file_path || '(no file)'
    if (!byFile.has(key)) byFile.set(key, [])
    byFile.get(key)!.push(c)
  }

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sorted = [...byFile.entries()].sort(([, a], [, b]) => {
    const aMin = Math.min(...a.map(c => sevOrder.indexOf(c.severity)))
    const bMin = Math.min(...b.map(c => sevOrder.indexOf(c.severity)))
    return aMin - bMin
  })

  return (
    <div>
      {sorted.map(([filePath, fileComments]) => (
        <FileSection
          key={filePath}
          filePath={filePath}
          comments={fileComments}
          diff={diffs[filePath]}
        />
      ))}
    </div>
  )
}
