import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react'
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from 'recharts'
import type { ReviewResult } from '../../types/review'
import Badge, { type BadgeVariant } from '../ui/Badge'

function ScoreGauge({ score, max }: { score: number; max: number }) {
  const pct = Math.max(0, Math.min(100, (score / max) * 100))
  const color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#eab308' : '#ef4444'
  return (
    <div className="relative w-32 h-32 mx-auto">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          cx="50%" cy="50%"
          innerRadius="65%" outerRadius="100%"
          data={[{ value: pct }]}
          startAngle={90} endAngle={-270}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar dataKey="value" fill={color} background={{ fill: '#1e293b' }} cornerRadius={4} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-white">{score.toFixed(0)}</span>
        <span className="text-xs text-slate-400">/{max}</span>
      </div>
    </div>
  )
}

const SEV_VARIANT: Record<string, BadgeVariant> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info'
}

interface Props { result: ReviewResult }

export default function ReviewSummaryPanel({ result }: Props) {
  const { decision, score, pr_review } = result
  const dec = decision.decision

  const decisionConfig = {
    approve: {
      bg: 'bg-accent-green/10 border-accent-green/30',
      icon: CheckCircle,
      iconColor: 'text-accent-green',
      label: '✅ APPROVED',
      textColor: 'text-accent-green',
    },
    request_changes: {
      bg: 'bg-accent-yellow/10 border-accent-yellow/30',
      icon: AlertTriangle,
      iconColor: 'text-accent-yellow',
      label: '⚠️ CHANGES REQUESTED',
      textColor: 'text-accent-yellow',
    },
    block: {
      bg: 'bg-accent-red/10 border-accent-red/30',
      icon: XCircle,
      iconColor: 'text-accent-red',
      label: '🚫 BLOCKED — DO NOT MERGE',
      textColor: 'text-accent-red',
    },
  }[dec]

  const DecIcon = decisionConfig.icon

  return (
    <div className="space-y-4">
      {/* Decision Banner */}
      <div className={`border rounded-2xl p-5 ${decisionConfig.bg}`}>
        <div className="flex items-center gap-3 mb-3">
          <DecIcon className={`w-6 h-6 ${decisionConfig.iconColor}`} />
          <h2 className={`text-xl font-bold ${decisionConfig.textColor}`}>{decisionConfig.label}</h2>
          {pr_review && (
            <span className="ml-auto text-xs border border-surface-border text-slate-400 px-2 py-1 rounded-lg">
              {pr_review.event}
            </span>
          )}
        </div>
        {decision.hard_blockers.length > 0 && (
          <div className="mb-3 p-3 bg-accent-red/10 border border-accent-red/20 rounded-xl">
            <p className="text-xs font-semibold text-accent-red mb-1.5">🔴 Hard Blockers</p>
            {decision.hard_blockers.map((b, i) => (
              <p key={i} className="text-xs text-red-300">• {b}</p>
            ))}
          </div>
        )}
        {decision.reasons.length > 0 && (
          <div className="space-y-1">
            {decision.reasons.map((r, i) => (
              <p key={i} className="text-sm text-slate-400">• {r}</p>
            ))}
          </div>
        )}
      </div>

      {/* Score + Breakdown Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Score Gauge */}
        <div className="bg-surface-card border border-surface-border rounded-2xl p-5 flex flex-col items-center">
          <h3 className="text-xs text-slate-400 font-medium mb-4 uppercase tracking-wide">Security Score</h3>
          <ScoreGauge score={score.total_score} max={score.max_score} />
          <p className="text-xs text-slate-500 mt-3 text-center">Higher = fewer / less severe findings</p>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-surface-card border border-surface-border rounded-2xl p-5">
          <h3 className="text-xs text-slate-400 font-medium mb-4 uppercase tracking-wide">Severity Breakdown</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 border-b border-surface-border">
                <th className="text-left pb-2 font-medium">Severity</th>
                <th className="text-right pb-2 font-medium">Count</th>
                <th className="text-right pb-2 font-medium">Impact</th>
              </tr>
            </thead>
            <tbody>
              {score.severity_breakdown.filter(s => s.count > 0).map(s => (
                <tr key={s.severity} className="border-b border-surface-border/40">
                  <td className="py-2">
                    <Badge variant={SEV_VARIANT[s.severity] || 'default'}>
                      {s.emoji} {s.severity}
                    </Badge>
                  </td>
                  <td className="text-right text-slate-300 py-2 font-mono">{s.count}</td>
                  <td className="text-right text-slate-400 py-2 font-mono text-xs">{s.impact.toFixed(1)}</td>
                </tr>
              ))}
              {!score.severity_breakdown.filter(s => s.count > 0).length && (
                <tr>
                  <td colSpan={3} className="py-4 text-center text-slate-500 text-xs">No findings</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Finding Counts */}
        <div className="bg-surface-card border border-surface-border rounded-2xl p-5">
          <h3 className="text-xs text-slate-400 font-medium mb-4 uppercase tracking-wide">Finding Summary</h3>
          <div className="space-y-3">
            {[
              { label: 'Total Findings',     value: result.total_findings,         color: 'text-white' },
              { label: 'Relevant',           value: result.relevant_count,         color: 'text-accent-red' },
              { label: 'Contextual',         value: result.contextual_count,       color: 'text-accent-yellow' },
              { label: 'Unrelated',          value: result.unrelated_count,        color: 'text-slate-400' },
              { label: 'Pattern Detections', value: result.pattern_findings_count, color: 'text-primary-light' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center justify-between text-sm">
                <span className="text-slate-400">{label}</span>
                <span className={`font-bold ${color}`}>{value}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-surface-border">
            <h4 className="text-xs text-slate-500 mb-2">Tool Breakdown</h4>
            {score.tool_breakdown.slice(0, 4).map(t => (
              <div key={t.tool} className="flex justify-between text-xs mb-1">
                <span className="text-slate-400 font-mono">{t.tool}</span>
                <span className="text-slate-300">{t.count} findings</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Summary Markdown */}
      {result.summary_markdown && (
        <div className="bg-surface-card border border-surface-border rounded-2xl p-5">
          <h3 className="text-xs text-slate-400 font-medium mb-3 uppercase tracking-wide">Review Summary</h3>
          <pre className="text-sm text-slate-300 whitespace-pre-wrap font-sans leading-relaxed overflow-x-auto">
            {result.summary_markdown}
          </pre>
        </div>
      )}
    </div>
  )
}
