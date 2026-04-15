import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, AlertCircle } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { signup, checkPassword, getStoredUser } from '../services/authService'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'
import { getApiErrorMessage } from '../lib/errors'

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
  }, [navigate])

  function handlePasswordChange(val: string) {
    setForm(f => ({ ...f, password: val }))
    if (checkTimer) clearTimeout(checkTimer)
    if (val.length < 3) { setPwScore(0); setPwFeedback([]); return }
    const t = setTimeout(async () => {
      try {
        const res = await checkPassword(val)
        setPwScore(res.score)
        setPwFeedback(res.feedback || [])
      } catch { /* Password feedback is optional, so keep typing smooth if the check fails. */ }
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
    } catch (err: unknown) {
      const msg = getApiErrorMessage(err, 'Signup failed. Please try again.')
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
      <div className="flex items-center justify-center px-4 py-16">
        <div data-reveal className="w-full max-w-md">
          <div className="bg-slate-900/75 shadow-2xl shadow-black/30 border border-slate-700/70 rounded-2xl p-8 backdrop-blur">
            <div className="text-center mb-8">
              <Shield className="w-10 h-10 text-indigo-300 mx-auto mb-3" />
              <h1 className="text-2xl font-bold text-white">Create Account</h1>
              <p className="text-slate-400 text-sm mt-1">Start securing your PRs today</p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 bg-accent-red/10 border border-accent-red/30 rounded-lg mb-4 text-sm text-accent-red">
                <AlertCircle className="w-4 h-4 shrink-0" /> {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Full Name</label>
                <input
                  type="text"
                  value={form.full_name}
                  onChange={e => setForm({ ...form, full_name: e.target.value })}
                  placeholder="Jane Doe"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300 transition-colors"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Email</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  placeholder="you@example.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300 transition-colors"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={form.password}
                    onChange={e => handlePasswordChange(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-300 transition-colors"
                  />
                  <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <StrengthBar score={pwScore} />
                {pwFeedback.length > 0 && (
                  <ul className="mt-1 space-y-0.5">
                    {pwFeedback.slice(0, 3).map((f, i) => (
                      <li key={i} className="text-xs text-slate-500">• {f}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">Confirm Password</label>
                <input
                  type="password"
                  value={form.confirm}
                  onChange={e => setForm({ ...form, confirm: e.target.value })}
                  placeholder="••••••••"
                  className={`w-full bg-slate-900 border rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none transition-colors ${form.confirm && form.confirm !== form.password ? 'border-accent-red' : 'border-slate-700 focus:border-indigo-300'}`}
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-slate-100 hover:bg-white disabled:opacity-50 disabled:cursor-not-allowed text-slate-900 font-semibold py-2.5 rounded-xl transition-colors text-sm"
              >
                {loading ? 'Creating account...' : 'Create Account'}
              </button>
            </form>

            <p className="text-center text-slate-500 text-sm mt-6">
              Already have an account?{' '}
              <Link to="/login" className="text-indigo-200 hover:underline">Sign in</Link>
            </p>

          </div>
        </div>
      </div>
    </motion.div>
  )
}
