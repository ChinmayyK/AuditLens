import api from '../lib/axios'
import type { RecentScan, Finding } from '../types/scan'

export async function getScans(): Promise<RecentScan[]> {
  const res = await api.get<{ scans: RecentScan[] }>('/scans')
  return res.data.scans || []
}

export async function getScan(id: string): Promise<RecentScan> {
  const res = await api.get(`/scans/${id}`)
  return res.data
}

export async function getScanFindings(id: string): Promise<Finding[]> {
  const res = await api.get<{ findings: Finding[] }>(`/scans/${id}/findings`)
  return res.data.findings || []
}

export async function createUrlScan(target: string, intensity: string): Promise<RecentScan> {
  const res = await api.post<RecentScan>('/scans/url', {
    target_url: target,
    intensity,
    ownership_confirmed: true,
  })
  return res.data
}

export async function createGithubScan(repo: string, branch: string): Promise<RecentScan> {
  const normalizedRepo = repo.startsWith('http://') || repo.startsWith('https://')
    ? repo
    : `https://github.com/${repo.replace(/^\/+/, '')}`

  const res = await api.post<RecentScan>('/scans/github', {
    repo_url: normalizedRepo,
    branch,
    ownership_confirmed: true,
  })
  return res.data
}

export async function cancelScan(id: string): Promise<void> {
  await api.post(`/scans/${id}/cancel`)
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`/scans/${id}`)
}
