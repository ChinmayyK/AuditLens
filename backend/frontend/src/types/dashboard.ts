import type { RecentScan } from './scan'

export interface DashboardData {
  total_scans: number
  total_findings: number
  avg_risk_score: number | null
  critical_open: number
  recent_scans: RecentScan[]
  score_history: { date: string; score: number }[]
  tool_stats: { tool: string; count: number }[]
  top_vulns: { vuln_type: string; count: number }[]
}
