export interface Finding {
  id: string
  scan_id: string
  vuln_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tool_source: string
  file_path?: string
  line_number?: number
  description?: string
  attack_worked?: boolean
  fix_verified?: boolean
  ai_fix?: string
  created_at: string
}

export interface ScanSummary {
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface RecentScan {
  id: string
  scan_type: string
  target: string
  status: 'queued' | 'running' | 'complete' | 'failed' | 'cancelled'
  risk_score?: number
  risk_grade?: string
  created_at: string
  duration_seconds?: number
  summary?: ScanSummary
}
