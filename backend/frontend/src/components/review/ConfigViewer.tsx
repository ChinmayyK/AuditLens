import { Settings2, CheckCircle } from 'lucide-react'

const configFiles = [
  { name: 'pattern_rules.yaml',   desc: 'Regex rules scanned against diff hunks',   count: '20+ rules',       color: 'text-primary-light' },
  { name: 'scoring_rules.yaml',   desc: 'Severity weights + tool trust multipliers', count: 'critical=25pt',   color: 'text-accent-yellow' },
  { name: 'merge_policy.yaml',    desc: 'Approve/block thresholds + hard blockers',  count: '3 hard blockers', color: 'text-accent-red'    },
  { name: 'comment_templates.yaml', desc: 'Templates for inline comment bodies',     count: 'per category',    color: 'text-accent-green'  },
]

export default function ConfigViewer() {
  return (
    <div className="bg-surface-card border border-surface-border rounded-2xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Settings2 className="w-4 h-4 text-primary-light" />
        <h3 className="font-semibold text-white text-sm">Config-Driven Rules</h3>
        <span className="ml-auto text-xs bg-accent-green/10 border border-accent-green/20 text-accent-green px-2 py-0.5 rounded-full">
          Live
        </span>
      </div>
      <div className="space-y-3">
        {configFiles.map(f => (
          <div key={f.name} className="flex items-start gap-3 p-3 bg-surface rounded-lg border border-surface-border/50">
            <CheckCircle className={`w-4 h-4 ${f.color} mt-0.5 shrink-0`} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-300">{f.name}</span>
                <span className="text-xs text-slate-600">·</span>
                <span className="text-xs text-slate-500">{f.count}</span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">{f.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-600 mt-3 border-t border-surface-border pt-3">
        Add a rule to{' '}
        <code className="font-mono bg-surface px-1 rounded">pattern_rules.yaml</code> → restart-free hot reload.
        <br />
        <span className="text-slate-700">
          Connect <code className="font-mono">GET /review/config</code> to view live JSON config.
        </span>
      </p>
    </div>
  )
}
