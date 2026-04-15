import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import * as authService from '../services/authService'
import type { LoginRequest, SignupRequest } from '../types/auth'
import toast from 'react-hot-toast'

export function useAuth() {
  const qc = useQueryClient()
  const navigate = useNavigate()

  const { data: user, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: authService.getMe,
    retry: false,
    enabled: !!localStorage.getItem('ss_user'),
  })

  async function login(data: LoginRequest) {
    const result = await authService.login(data)
    qc.invalidateQueries({ queryKey: ['me'] })
    return result
  }

  async function signup(data: SignupRequest) {
    const result = await authService.signup(data)
    qc.invalidateQueries({ queryKey: ['me'] })
    return result
  }

  async function logout() {
    await authService.logout()
    qc.clear()
    navigate('/')
    toast.success('Logged out')
  }

  return { user, isLoading, login, logout, signup }
}
