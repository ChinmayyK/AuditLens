import { useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, Code2, Users } from 'lucide-react'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'

const detections = [
  'Hardcoded Secrets', 'SQL Injection', 'Insecure HTTP', 'API Key Exposure',
  'Command Injection', 'Shell Injection', 'Weak Cryptography', 'Auth Bypass',
]
const stack = ['FastAPI', 'PostgreSQL', 'Redis', 'Celery', 'React 18', 'TypeScript', 'Tailwind CSS']

export default function AboutPage() {
  useEffect(() => { document.title = 'About | ShieldSentinel' }, [])
  const revealRef = useGsapReveal()

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className="min-h-screen bg-surface text-slate-100"
    >
      <Navbar />
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div data-reveal className="flex items-center gap-3 mb-8">
          <Shield className="w-8 h-8 text-indigo-300" />
          <h1 className="text-3xl font-bold text-white">About ShieldSentinel</h1>
        </div>

        <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-amber-300" />
            <h2 className="font-semibold text-white">The Problem</h2>
          </div>
          <p className="text-slate-300 leading-relaxed">
            Code reviews are slow, inconsistent, and depend on who's available. Junior reviewers miss security issues.
            Senior reviewers don't have time. ShieldSentinel is an AI-native PR review system that handles the full
            review pipeline automatically — fetching diffs, detecting vulnerabilities, scoring findings, and generating
            a merge decision in seconds.
          </p>
        </div>

        <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Code2 className="w-5 h-5 text-indigo-200" />
            <h2 className="font-semibold text-white">What We Detect</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {detections.map(d => (
              <span key={d} className="px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-300/20 text-indigo-200 text-xs font-medium">{d}</span>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-6">
          <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6">
            <h2 className="font-semibold text-white mb-4">Tech Stack</h2>
            <div className="flex flex-wrap gap-2">
              {stack.map(s => (
                <span key={s} className="px-2.5 py-1 rounded bg-slate-900 text-xs text-slate-300 border border-slate-700">{s}</span>
              ))}
            </div>
          </div>
          <div data-reveal className="bg-slate-900/70 border border-slate-700/70 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-5 h-5 text-emerald-300" />
              <h2 className="font-semibold text-white">Team</h2>
            </div>
            <p className="text-slate-400 text-sm">3rd Year · Corporate Tech Domain</p>
            <p className="text-slate-400 text-sm mt-1">Security Analysis · Full-Stack · Config-Driven Architecture</p>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
