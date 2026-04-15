import api from '../lib/axios'
import type { ReviewRequest, ReviewResult, ScoreResult, ReviewComment } from '../types/review'

export async function submitPRReview(request: ReviewRequest): Promise<ReviewResult> {
  const res = await api.post<ReviewResult>('/review/pr', request)
  return res.data
}

export async function submitFullReview(request: ReviewRequest): Promise<ReviewResult> {
  const res = await api.post<ReviewResult>('/review', request)
  return res.data
}

export async function getScoreOnly(request: ReviewRequest): Promise<ScoreResult> {
  const res = await api.post<ScoreResult>('/review/score', request)
  return res.data
}

export async function getCommentsOnly(request: ReviewRequest): Promise<ReviewComment[]> {
  const res = await api.post<ReviewComment[]>('/review/comments', request)
  return res.data
}

// Unauthenticated version for /demo page
export async function submitPRReviewPublic(request: ReviewRequest): Promise<ReviewResult> {
  const { default: axios } = await import('axios')
  const res = await axios.post<ReviewResult>(
    `${import.meta.env.VITE_API_URL}/review/pr-public`,
    request,
    {
      headers: { 'Content-Type': 'application/json' },
      withCredentials: true,
    }
  )
  return res.data
}

export async function reEvaluateReview(request: any): Promise<ReviewResult> {
  const res = await api.post<ReviewResult>('/review/re-evaluate', request)
  return res.data
}

