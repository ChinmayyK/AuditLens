import { Link } from 'react-router-dom'
import { ArrowRight, Sparkles } from 'lucide-react'
import { motion } from 'framer-motion'
import { useGsapReveal } from '../../hooks/useGsapReveal'

type ComingSoonPageProps = {
  title: string
  subtitle: string
  description: string
  bullets: string[]
  primaryCta: {
    to: string
    label: string
  }
  secondaryCta?: {
    to: string
    label: string
  }
}

export default function ComingSoonPage({
  title,
  subtitle,
  description,
  bullets,
  primaryCta,
  secondaryCta,
}: ComingSoonPageProps) {
  const revealRef = useGsapReveal()

  return (
    <motion.section
      ref={revealRef}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
      className="px-6 py-8 sm:px-8 sm:py-10"
    >
      <div className="mx-auto max-w-5xl">
        <div data-reveal className="relative overflow-hidden rounded-3xl border border-slate-700/70 bg-slate-900/70 p-8 backdrop-blur sm:p-10">
          <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-indigo-400/10 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-32 -left-20 h-72 w-72 rounded-full bg-slate-400/10 blur-3xl" />

          <span className="mb-5 inline-flex items-center gap-2 rounded-full border border-indigo-300/30 bg-indigo-500/10 px-3 py-1 text-xs font-semibold text-indigo-200">
            <Sparkles className="h-3.5 w-3.5" />
            {subtitle}
          </span>

          <h1 className="mb-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">{title}</h1>
          <p className="max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">{description}</p>

          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            {bullets.map((item) => (
              <div
                key={item}
                data-reveal
                className="rounded-xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300"
              >
                {item}
              </div>
            ))}
          </div>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link
              to={primaryCta.to}
              className="inline-flex items-center gap-2 rounded-xl bg-slate-100 px-4 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-white"
            >
              {primaryCta.label}
              <ArrowRight className="h-4 w-4" />
            </Link>
            {secondaryCta && (
              <Link
                to={secondaryCta.to}
                className="inline-flex items-center rounded-xl border border-slate-600 px-4 py-2.5 text-sm font-medium text-slate-300 transition-colors hover:border-slate-400 hover:text-white"
              >
                {secondaryCta.label}
              </Link>
            )}
          </div>
        </div>
      </div>
    </motion.section>
  )
}
