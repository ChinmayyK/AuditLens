import { Link } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { motion } from 'framer-motion'

export default function NotFoundPage() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="min-h-screen bg-surface flex items-center justify-center px-4"
    >
      <div className="text-center rounded-3xl border border-slate-700/70 bg-slate-900/70 px-10 py-12 shadow-2xl shadow-black/30 backdrop-blur">
        <Shield className="w-16 h-16 text-indigo-300/40 mx-auto mb-4" />
        <h1 className="text-6xl font-bold text-slate-600 mb-2">404</h1>
        <p className="text-slate-400 mb-6">Page not found</p>
        <Link to="/dashboard" className="px-6 py-2.5 bg-slate-100 hover:bg-white text-slate-900 rounded-xl text-sm font-medium transition-colors">
          Back to Dashboard
        </Link>
      </div>
    </motion.div>
  )
}
