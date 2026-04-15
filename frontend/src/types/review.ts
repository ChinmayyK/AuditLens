// ── Input ─────────────────────────────────────────────
export interface FindingInput {
  file_path?: string
  line_number?: number
  vuln_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tool: string
  message?: string
  cvss_score?: number
  cve_id?: string
  cwe_id?: string
  code_snippet?: string
  fix?: string
  confidence?: number
  rule_id?: string
  is_synthetic?: boolean
}

export interface ReviewRequest {
  findings: FindingInput[]
  changed_lines?: Record<string, number[]>
  diffs?: Record<string, string>
}

export interface ReEvaluateRequest {
  original_findings: FindingInput[]
  fixed_file_paths: string[]
  diffs?: Record<string, string>
  changed_lines?: Record<string, number[]>
}


// ── Output ────────────────────────────────────────────
export interface ReviewComment {
  file_path?: string
  line_number?: number
  severity: string
  vuln_type: string
  tool: string
  category: string
  body: string
  impact: number
  suggestion?: string
  diff_hunk?: string
  side?: string
  confidence?: number
  rule_id?: string
}

export interface SeverityBreakdown {
  severity: string
  emoji: string
  count: number
  impact: number
}

export interface ToolBreakdown {
  tool: string
  count: number
  trust: number
  contribution: number
}

export interface ScoreResult {
  total_score: number
  max_score: number
  severity_breakdown: SeverityBreakdown[]
  tool_breakdown: ToolBreakdown[]
}

export interface DecisionResult {
  decision: 'approve' | 'request_changes' | 'block'
  reasons: string[]
  hard_blockers: string[]
}

export interface GitHubInlineComment {
  path: string
  line: number
  side: string
  body: string
}

export interface GitHubPRReview {
  event: string
  body: string
  comments: GitHubInlineComment[]
}

export interface ReviewResult {
  comments: ReviewComment[]
  score: ScoreResult
  decision: DecisionResult
  summary_markdown: string
  total_findings: number
  relevant_count: number
  contextual_count: number
  unrelated_count: number
  pr_review?: GitHubPRReview
  pattern_findings_count: number
}
