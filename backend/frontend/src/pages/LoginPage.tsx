import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, AlertCircle } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { login, getStoredUser } from '../services/authService'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'
import { asApiError } from '../lib/errors'

export default function LoginPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '' })
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const revealRef = useGsapReveal()

  useEffect(() => {
    document.title = 'Login | ShieldSentinel'
    if (getStoredUser()?.access_token) navigate('/dashboard', { replace: true })
  }, [navigate])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!form.email || !form.password) {
      setError('Email and password are required')
      return
    }
    setLoading(true)
    try {
      await login({ email: form.email, password: form.password })
      toast.success('Welcome back!')
      navigate('/dashboard')
    } catch (err: unknown) {
      const apiError = asApiError(err)
      let msg = 'Invalid email or password'
      if (!apiError.response) {
        msg = 'Cannot reach the backend API. Check that the backend server is running.'
      } else if (apiError.response?.status === 404) {
        msg = 'Auth endpoint not found. Check the frontend API configuration.'
      } else if (typeof apiError.response?.data?.detail === 'string') {
        msg = apiError.response.data.detail
      }
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="min-h-screen bg-surface"
    >
      <Navbar />
      <div className="flex items-center justify-center px-4 py-20">
        <div data-reveal className="w-full max-w-md">
          <div className="bg-slate-900/75 shadow-2xl shadow-black/30 border border-slate-700/70 rounded-2xl p-8 backdrop-blur">
            <div className="text-center mb-8">
              <Shield className="w-10 h-10 text-indigo-300 mx-auto mb-3" />
              <h1 className="text-2xl font-bold text-white">Sign in</h1>
              <p className="text-slate-400 text-sm mt-1">Welcome back to ShieldSentinel</p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 bg-accent-red/10 border border-accent-red/30 rounded-lg mb-4 text-sm text-accent-red">
                <AlertCircle className="w-4 h-4 shrink-0" /> {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Email</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  placeholder="you@example.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300 transition-colors"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={form.password}
                    onChange={e => setForm({ ...form, password: e.target.value })}
                    placeholder="••••••••"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300 transition-colors"
                  />
                  <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-slate-100 hover:bg-white disabled:opacity-50 disabled:cursor-not-allowed text-slate-900 font-semibold py-2.5 rounded-xl transition-colors text-sm"
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>

            <p className="text-center text-slate-500 text-sm mt-6">
              Don't have an account?{' '}
              <Link to="/signup" className="text-indigo-200 hover:underline">Sign up</Link>
            </p>

          </div>
        </div>
      </div>
    </motion.div>
  )
}
