export interface User {
  id: string
  email: string
  full_name: string
  avatar_url?: string | null
  plan: string
  scan_count?: number
  is_active?: boolean
  is_verified?: boolean
  created_at: string
  last_login?: string
}

export interface StoredAuth {
  access_token: string
  user: User
}

export interface LoginRequest {
  email: string
  password: string
}

export interface SignupRequest {
  email: string
  password: string
  full_name: string
}

export interface TokenResponse {
  access_token: string
  expires_in: number
  user: User
}

export interface PasswordStrengthResponse {
  score: number       // 0-5
  feedback: string[]
  valid?: boolean
  strength?: string
}
