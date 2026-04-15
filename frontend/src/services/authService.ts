import api from '../lib/axios'
import type { LoginRequest, SignupRequest, TokenResponse, User, PasswordStrengthResponse } from '../types/auth'

function saveAuth(data: TokenResponse) {
  // Store both token and user in single key
  localStorage.setItem('ss_user', JSON.stringify({
    access_token: data.access_token,
    ...data.user,
  }))
}

export async function login(data: LoginRequest): Promise<TokenResponse> {
  const res = await api.post<TokenResponse>('/auth/login', {
    ...data,
    email: data.email.trim().toLowerCase(),
  })
  saveAuth(res.data)
  return res.data
}

export async function signup(data: SignupRequest): Promise<TokenResponse> {
  const res = await api.post<TokenResponse>('/auth/signup/complete', data)
  saveAuth(res.data)
  return res.data
}



export async function logout(): Promise<void> {
  try { await api.post('/auth/logout') } catch {}
  localStorage.removeItem('ss_user')
}

export async function getMe(): Promise<User> {
  const res = await api.get<User>('/auth/me')
  return res.data
}

export async function checkPassword(password: string): Promise<PasswordStrengthResponse> {
  const res = await api.post<PasswordStrengthResponse>('/auth/password/check', { password })
  return res.data
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem('ss_user')
    return raw ? JSON.parse(raw) : null
  } catch { return null }
}
