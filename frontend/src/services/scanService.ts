import api from '../lib/axios'
import type { RecentScan, Finding } from '../types/scan'

export async function getScans(): Promise<RecentScan[]> {
  const res = await api.get<RecentScan[]>('/scans')
  return res.data
}

export async function getScan(id: string): Promise<any> {
  const res = await api.get(`/scans/${id}`)
  return res.data
}

export async function getScanFindings(id: string): Promise<Finding[]> {
  const res = await api.get<Finding[]>(`/scans/${id}/findings`)
  return res.data
}

export async function createUrlScan(target: string, intensity: string): Promise<RecentScan> {
  const res = await api.post<RecentScan>('/scans/url', { target, intensity })
  return res.data
}

export async function createGithubScan(repo: string, branch: string): Promise<RecentScan> {
  const res = await api.post<RecentScan>('/scans/github', { repo, branch })
  return res.data
}

export async function cancelScan(id: string): Promise<void> {
  await api.post(`/scans/${id}/cancel`)
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`/scans/${id}`)
}
