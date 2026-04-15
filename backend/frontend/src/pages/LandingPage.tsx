import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield,
  GitPullRequest,
  ShieldCheck,
  CheckCircle,
  Code2,
  BarChart3,
  Settings,
  Search,
  ArrowRight,
  Sparkles,
} from 'lucide-react'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: (i = 0) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.5 } }),
}

const features = [
  { icon: Code2, title: 'Inline Security Comments', desc: 'Auto-generated review comments mapped to exact files and lines with remediation guidance.' },
  { icon: BarChart3, title: 'Risk Scoring Engine', desc: 'Weighted scoring across finding severity, confidence, and tool trust to reduce noisy decisions.' },
  { icon: ShieldCheck, title: 'Merge Gate Decision', desc: 'Clear Approved, Changes Requested, or Blocked verdict based on configurable policy thresholds.' },
  { icon: Settings, title: 'Config-Driven Policy', desc: 'Control severity weights, block levels, and rule behaviors from a central configuration layer.' },
  { icon: Search, title: 'Pattern Detection', desc: 'Detection for secrets, insecure transport, injection risks, and exposed credentials in PR changes.' },
  { icon: GitPullRequest, title: 'PR-First Workflow', desc: 'Built for pull requests from day one, with fast feedback loops for engineering teams.' },
]

const steps = [
  { icon: GitPullRequest, step: '01', title: 'Connect PR or Findings', desc: 'Import a pull request or scanner output from your existing workflow.' },
  { icon: ShieldCheck, step: '02', title: 'Analyze and Prioritize', desc: 'Security signals are filtered, scored, and ranked by impact.' },
  { icon: CheckCircle, step: '03', title: 'Ship with Confidence', desc: 'Get merge verdict, comment payload, and clear next actions.' },
]

export default function LandingPage() {
  useEffect(() => { document.title = 'ShieldSentinel — AI-Powered PR Security Reviews' }, [])
  const revealRef = useGsapReveal()

  return (
    <div ref={revealRef} className="min-h-screen bg-surface text-slate-100">
      <Navbar />

      <section className="max-w-6xl mx-auto px-6 pt-20 pb-14">
        <motion.div
          data-reveal
          initial="hidden"
          animate="visible"
          variants={fadeUp}
          custom={0}
          className="relative overflow-hidden rounded-3xl border border-slate-700/70 bg-slate-900/70 px-6 py-10 sm:px-10 sm:py-14 backdrop-blur"
        >
          <div className="pointer-events-none absolute -top-28 right-0 h-60 w-60 rounded-full bg-indigo-400/10 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-24 left-8 h-56 w-56 rounded-full bg-slate-400/10 blur-3xl" />

          <span className="mb-6 inline-flex items-center gap-2 rounded-full border border-indigo-300/30 bg-indigo-500/10 px-3 py-1 text-xs font-semibold text-indigo-200">
            <Sparkles className="h-3.5 w-3.5" />
            Enterprise-ready PR security review
          </span>
          <motion.h1 initial="hidden" animate="visible" variants={fadeUp} custom={1} className="max-w-4xl text-4xl font-bold leading-tight text-white sm:text-5xl lg:text-6xl">
            Professional PR security reviews, <span className="text-indigo-300">without slowing releases.</span>
          </motion.h1>
          <motion.p initial="hidden" animate="visible" variants={fadeUp} custom={2} className="mt-6 max-w-2xl text-base leading-relaxed text-slate-300 sm:text-lg">
            ShieldSentinel analyzes pull-request changes for critical security risks, scores exposure, and produces actionable inline review comments in minutes.
          </motion.p>
          <motion.div initial="hidden" animate="visible" variants={fadeUp} custom={3} className="mt-8 flex flex-wrap items-center gap-3">
            <Link to="/demo" className="inline-flex items-center gap-2 rounded-xl bg-slate-100 px-6 py-3 text-sm font-semibold text-slate-900 transition-colors hover:bg-white">
              Run Live Demo
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/signup" className="rounded-xl border border-slate-600 px-6 py-3 text-sm font-medium text-slate-200 transition-colors hover:border-slate-400 hover:text-white">
              Start Free
            </Link>
          </motion.div>
        </motion.div>
      </section>

      <section data-reveal className="max-w-6xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[
            { label: 'Avg review turnaround', value: '< 5 min' },
            { label: 'Security checks automated', value: '25+' },
            { label: 'Policy confidence', value: 'Configurable' },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, amount: 0.3 }}
              variants={fadeUp}
              custom={i}
              className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-5"
            >
              <p className="text-xs text-slate-400">{stat.label}</p>
              <p className="mt-2 text-2xl font-semibold text-white">{stat.value}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section id="how-it-works" data-reveal className="max-w-6xl mx-auto px-6 py-16">
        <div className="mb-12 flex items-center justify-between gap-4">
          <h2 className="text-2xl font-bold text-white sm:text-3xl">How It Works</h2>
          <p className="hidden max-w-md text-right text-sm text-slate-400 sm:block">Three focused steps from raw findings to merge-ready decisions.</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {steps.map((s, i) => (
            <motion.div
              key={s.step} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} custom={i}
              className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-6"
            >
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-indigo-300/25 bg-indigo-500/10">
                <s.icon className="w-6 h-6 text-indigo-200" />
              </div>
              <div className="mb-2 text-xs font-mono font-bold text-indigo-200">Step {s.step}</div>
              <h3 className="mb-2 text-base font-semibold text-white">{s.title}</h3>
              <p className="text-sm leading-relaxed text-slate-400">{s.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section data-reveal className="max-w-6xl mx-auto px-6 py-16">
        <h2 className="mb-12 text-2xl font-bold text-white sm:text-3xl">Platform Capabilities</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((f, i) => (
            <motion.div
              key={f.title} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} custom={i % 3}
              className="group rounded-xl border border-slate-700/70 bg-slate-900/60 p-5 transition-colors hover:border-indigo-300/40"
            >
              <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/10">
                <f.icon className="w-5 h-5 text-indigo-200" />
              </div>
              <h3 className="mb-1.5 text-sm font-semibold text-white">{f.title}</h3>
              <p className="text-xs leading-relaxed text-slate-400">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section data-reveal className="max-w-6xl mx-auto px-6 pb-20 pt-6">
        <div className="rounded-3xl border border-slate-700/70 bg-gradient-to-r from-slate-900 via-slate-800/90 to-indigo-950/40 px-6 py-10 text-center sm:px-10">
          <h3 className="text-2xl font-bold text-white sm:text-3xl">Ready to secure every PR before merge?</h3>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-300 sm:text-base">Join teams using ShieldSentinel to reduce review friction and ship with stronger security confidence.</p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Link to="/signup" className="rounded-xl bg-slate-100 px-6 py-3 text-sm font-semibold text-slate-900 transition-colors hover:bg-white">
              Create Account
            </Link>
            <Link to="/about" className="rounded-xl border border-slate-600 px-6 py-3 text-sm font-medium text-slate-200 transition-colors hover:border-slate-400 hover:text-white">
              Learn More
            </Link>
          </div>
        </div>
      </section>

      <footer className="mt-8 border-t border-surface-border py-8 text-center text-sm text-slate-500">
        <div className="mb-2 flex items-center justify-center gap-2">
          <Shield className="w-4 h-4 text-indigo-300" />
          <span className="text-white font-medium">ShieldSentinel</span>
        </div>
        <p>AI-native PR security review platform</p>
      </footer>
    </div>
  )
}
