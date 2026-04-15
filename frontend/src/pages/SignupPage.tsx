import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, AlertCircle, Sparkles, UserPlus } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { signup, checkPassword, getStoredUser } from '../services/authService'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'

function StrengthBar({ score }: { score: number }) {
  const bars = [0, 1, 2, 3, 4]
  const colors = ['bg-accent-red', 'bg-accent-red', 'bg-accent-yellow', 'bg-accent-yellow', 'bg-accent-green']
  const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
  return (
    <div className="mt-2">
      <div className="flex gap-1 mb-1">
        {bars.map(i => (
          <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${i < score ? colors[score - 1] : 'bg-surface-border'}`} />
        ))}
      </div>
      {score > 0 && <p className={`text-xs ${score >= 4 ? 'text-accent-green' : score >= 3 ? 'text-accent-yellow' : 'text-accent-red'}`}>{labels[score]}</p>}
    </div>
  )
}

export default function SignupPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ full_name: '', email: '', password: '', confirm: '' })
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pwScore, setPwScore] = useState(0)
  const [pwFeedback, setPwFeedback] = useState<string[]>([])
  const [checkTimer, setCheckTimer] = useState<ReturnType<typeof setTimeout> | null>(null)
  const revealRef = useGsapReveal()

  useEffect(() => {
    document.title = 'Sign Up | ShieldSentinel'
    if (getStoredUser()?.access_token) navigate('/dashboard', { replace: true })
  }, [])

  function handlePasswordChange(val: string) {
    setForm(f => ({ ...f, password: val }))
    if (checkTimer) clearTimeout(checkTimer)
    if (val.length < 3) { setPwScore(0); setPwFeedback([]); return }
    const t = setTimeout(async () => {
      try {
        const res = await checkPassword(val)
        setPwScore(res.score)
        setPwFeedback(res.feedback || [])
      } catch {}
    }, 500)
    setCheckTimer(t)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!form.full_name || !form.email || !form.password) {
      setError('All fields are required')
      return
    }
    if (form.password !== form.confirm) {
      setError('Passwords do not match')
      return
    }
    if (form.password.length < 6) {
      setError('Password must be at least 6 characters')
      return
    }
    setLoading(true)
    try {
      await signup({ full_name: form.full_name, email: form.email, password: form.password })
      toast.success('Welcome to ShieldSentinel!')
      navigate('/dashboard')
    } catch (err: any) {
      const msg = err?.response?.data?.detail || 'Signup failed. Please try again.'
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
      <div className="relative overflow-hidden px-4 py-12 sm:py-16">
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-16 right-0 h-72 w-72 rounded-full bg-indigo-500/10 blur-3xl" />
          <div className="absolute bottom-0 -left-8 h-72 w-72 rounded-full bg-cyan-400/10 blur-3xl" />
        </div>
        <motion.div variants={container} initial="hidden" animate="show" className="mx-auto grid w-full max-w-6xl gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <motion.div
            variants={item}
            data-reveal
            className="hidden rounded-3xl border border-indigo-200 bg-gradient-to-br from-white via-blue-50 to-indigo-100 p-10 text-blue-900 shadow-xl shadow-blue-100/60 lg:flex lg:flex-col lg:justify-between"
          >
            <div>
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-indigo-300/30 bg-indigo-500/10 px-3 py-1 text-xs text-indigo-200">
                <Sparkles className="h-3.5 w-3.5" />
                Enterprise-ready onboarding
              </div>
              <h2 className="text-3xl font-bold leading-tight">Create your account and secure every pull request.</h2>
              <p className="mt-4 max-w-md text-sm leading-relaxed text-blue-900/80">
                Activate automated checks, policy controls, and actionable review comments in a few minutes.
              </p>
            </div>
            <ul className="mt-8 space-y-3 rounded-2xl border border-indigo-200 bg-white/80 p-4 text-sm text-blue-900/80">
              <li>• Instant setup with your existing repo workflow</li>
              <li>• Prioritized findings with confidence scoring</li>
              <li>• Merge decisions aligned to your security policy</li>
            </ul>
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
                <h1 className="text-2xl font-bold text-blue-900 sm:text-3xl">Create Account</h1>
                <p className="mt-1 text-sm text-blue-800/80">Start securing your PRs today</p>
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
                  <label className="mb-1.5 block text-sm text-blue-800/80">Full Name</label>
                  <input
                    type="text"
                    value={form.full_name}
                    onChange={e => setForm({ ...form, full_name: e.target.value })}
                    placeholder="Jane Doe"
                    className="w-full rounded-xl border border-indigo-200 bg-white px-4 py-2.5 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-400/20"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-blue-800/80">Email</label>
                  <input
                    type="email"
                    value={form.email}
                    onChange={e => setForm({ ...form, email: e.target.value })}
                    placeholder="you@example.com"
                    className="w-full rounded-xl border border-indigo-200 bg-white px-4 py-2.5 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-400/20"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-blue-800/80">Password</label>
                  <div className="relative">
                    <input
                      type={showPw ? 'text' : 'password'}
                      value={form.password}
                      onChange={e => handlePasswordChange(e.target.value)}
                      placeholder="••••••••"
                      className="w-full rounded-xl border border-indigo-200 bg-white px-4 py-2.5 pr-10 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-400/20"
                    />
                    <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-blue-300 transition-colors hover:text-blue-700">
                      {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <StrengthBar score={pwScore} />
                  {pwFeedback.length > 0 && (
                    <ul className="mt-1 space-y-0.5">
                      {pwFeedback.slice(0, 3).map((f, i) => (
                        <li key={i} className="text-xs text-blue-800/70">• {f}</li>
                      ))}
                    </ul>
                  )}
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-blue-800/80">Confirm Password</label>
                  <input
                    type="password"
                    value={form.confirm}
                    onChange={e => setForm({ ...form, confirm: e.target.value })}
                    placeholder="••••••••"
                    className={`w-full rounded-xl border bg-white px-4 py-2.5 text-sm text-blue-900 placeholder-blue-300 transition-all duration-200 focus:outline-none ${form.confirm && form.confirm !== form.password ? 'border-accent-red' : 'border-indigo-200 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-400/20'}`}
                  />
                </div>
                <motion.button
                  whileHover={{ scale: loading ? 1 : 1.01 }}
                  whileTap={{ scale: loading ? 1 : 0.99 }}
                  type="submit"
                  disabled={loading}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-slate-100 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <UserPlus className="h-4 w-4" />
                  {loading ? 'Creating account...' : 'Create Account'}
                </motion.button>
              </form>

              <p className="mt-6 text-center text-sm text-blue-800/70">
                Already have an account?{' '}
                <Link to="/login" className="font-medium text-indigo-200 transition hover:text-indigo-100 hover:underline">
                  Sign in
                </Link>
              </p>

            </motion.div>
          </motion.div>
        </motion.div>
      </div>
    </motion.div>
  )
}
