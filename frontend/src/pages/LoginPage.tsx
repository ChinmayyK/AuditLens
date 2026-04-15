import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, AlertCircle, Sparkles, Lock } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { login, getStoredUser } from '../services/authService'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'

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
  }, [])

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
    } catch (err: any) {
      let msg = 'Invalid email or password'
      if (!err?.response) {
        msg = 'Cannot reach backend API. Check that backend is running on localhost:9997.'
      } else if (err.response?.status === 404) {
        msg = 'Auth endpoint not found. Check VITE_API_URL configuration.'
      } else if (typeof err?.response?.data?.detail === 'string') {
        msg = err.response.data.detail
      }
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  const container = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.08 } },
  }

  const item = {
    hidden: { opacity: 0, y: 18 },
    show: { opacity: 1, y: 0, transition: { duration: 0.45 } },
  }

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="min-h-screen bg-white"
    >
      <Navbar />
      <div className="relative overflow-hidden px-4 py-14 sm:py-20">
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-24 -left-12 h-72 w-72 rounded-full bg-indigo-500/10 blur-3xl" />
          <div className="absolute -bottom-16 right-0 h-72 w-72 rounded-full bg-sky-400/10 blur-3xl" />
        </div>

        <motion.div variants={container} initial="hidden" animate="show" className="mx-auto grid w-full max-w-6xl items-stretch gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <motion.div
            variants={item}
            data-reveal
            className="hidden rounded-3xl border border-indigo-200 bg-gradient-to-br from-white via-blue-50 to-indigo-100 p-10 text-blue-900 shadow-xl shadow-blue-100/60 lg:flex lg:flex-col lg:justify-between"
          >
            <div>
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-indigo-300/30 bg-indigo-500/10 px-3 py-1 text-xs text-indigo-200">
                <Sparkles className="h-3.5 w-3.5" />
                Secure PR intelligence
              </div>
              <h2 className="text-3xl font-bold leading-tight">Welcome back to your security command center.</h2>
              <p className="mt-4 max-w-md text-sm leading-relaxed text-blue-900/80">
                Track risky pull requests, automate policy enforcement, and keep your team shipping safely with every merge.
              </p>
            </div>
            <div className="mt-8 rounded-2xl border border-indigo-200 bg-white/80 p-4">
              <p className="text-xs uppercase tracking-wider text-blue-700">Trusted workflow</p>
              <p className="mt-2 text-sm text-blue-900/80">Inline findings, risk scores, and merge verdicts integrated directly into your review process.</p>
            </div>
          </motion.div>

          <motion.div variants={item} className="w-full">
            <motion.div
              whileHover={{ y: -2 }}
              transition={{ duration: 0.2 }}
              className="rounded-3xl border border-indigo-200 bg-white p-8 shadow-xl shadow-blue-100/60 backdrop-blur sm:p-10"
            >
              <div className="mb-8 text-center">
                <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ duration: 0.35 }}>
                  <Shield className="mx-auto mb-3 h-10 w-10 text-indigo-300" />
                </motion.div>
                <h1 className="text-2xl font-bold text-blue-900 sm:text-3xl">Sign in</h1>
                <p className="mt-1 text-sm text-blue-800/80">Access your ShieldSentinel workspace</p>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-4 flex items-center gap-2 rounded-lg border border-accent-red/30 bg-accent-red/10 p-3 text-sm text-accent-red"
                >
                  <AlertCircle className="h-4 w-4 shrink-0" /> {error}
                </motion.div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="mb-1.5 block text-sm text-blue-800/80">Email</label>
                  <input
                    type="email"
                    value={form.email}
                    onChange={e => setForm({ ...form, email: e.target.value })}
                    placeholder="you@example.com"
                    className="w-full rounded-xl border border-indigo-200 bg-white px-4 py-2.5 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-400/20"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-blue-800/80">Password</label>
                  <div className="relative">
                    <input
                      type={showPw ? 'text' : 'password'}
                      value={form.password}
                      onChange={e => setForm({ ...form, password: e.target.value })}
                      placeholder="••••••••"
                      className="w-full rounded-xl border border-indigo-200 bg-white px-4 py-2.5 pr-10 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-400/20"
                    />
                    <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-blue-300 transition-colors hover:text-blue-700">
                      {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
                <motion.button
                  whileHover={{ scale: loading ? 1 : 1.01 }}
                  whileTap={{ scale: loading ? 1 : 0.99 }}
                  type="submit"
                  disabled={loading}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-slate-100 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Lock className="h-4 w-4" />
                  {loading ? 'Signing in...' : 'Sign In'}
                </motion.button>
              </form>

              <p className="mt-6 text-center text-sm text-blue-800/70">
                Don't have an account?{' '}
                <Link to="/signup" className="font-medium text-indigo-200 transition hover:text-indigo-100 hover:underline">
                  Sign up
                </Link>
              </p>

            </motion.div>
          </motion.div>
        </motion.div>
      </div>
    </motion.div>
  )
}
