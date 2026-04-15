import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { Shield, Menu, X, LogOut, Settings, ChevronDown, Zap } from 'lucide-react'
import api from '../../lib/axios'
import toast from 'react-hot-toast'

function getUser() {
  try {
    const raw = localStorage.getItem('ss_user')
    return raw ? JSON.parse(raw) : null
  } catch { return null }
}

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [dropOpen, setDropOpen] = useState(false)
  const navigate = useNavigate()
  const user = getUser()
  const isAuth = !!user?.access_token

  const initials = user?.full_name
    ? user.full_name.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2)
    : 'U'

  async function handleLogout() {
    try { await api.post('/auth/logout') } catch { /* Local logout should succeed even if the API is down. */ }
    localStorage.removeItem('ss_user')
    navigate('/')
    toast.success('Logged out')
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `text-sm font-medium transition-colors ${isActive ? 'text-primary-light' : 'text-slate-400 hover:text-slate-200'}`

  return (
    <nav className="sticky top-0 z-50 bg-surface-card/90 backdrop-blur border-b border-surface-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 shrink-0">
            <Shield className="w-7 h-7 text-primary" />
            <span className="font-bold text-white text-lg tracking-tight">
              Shield<span className="text-primary">Sentinel</span>
            </span>
          </Link>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-6">
            {!isAuth ? (
              <>
                <NavLink to="/" className={navLinkClass}>Home</NavLink>
                <NavLink to="/about" className={navLinkClass}>About</NavLink>
              </>
            ) : (
              <>
                <NavLink to="/dashboard" className={navLinkClass}>Dashboard</NavLink>
                <NavLink to="/scans" className={navLinkClass}>Scans</NavLink>
                <NavLink to="/review" className={navLinkClass}>PR Review</NavLink>
                <NavLink to="/settings" className={navLinkClass}>Settings</NavLink>
              </>
            )}
            {/* Demo always visible */}
            <Link
              to="/demo"
              className="flex items-center gap-1 px-3 py-1.5 rounded-full bg-primary/20 border border-primary/40 text-primary-light text-xs font-semibold hover:bg-primary/30 transition-colors"
            >
              <Zap className="w-3 h-3" /> Demo
            </Link>
          </div>

          {/* Right side */}
          <div className="hidden md:flex items-center gap-3">
            {!isAuth ? (
              <>
                <Link to="/login" className="text-sm text-slate-300 hover:text-white transition-colors border border-surface-border px-4 py-1.5 rounded-lg">
                  Login
                </Link>
                <Link to="/signup" className="text-sm bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-lg font-medium transition-colors">
                  Get Started
                </Link>
              </>
            ) : (
              <div className="relative">
                <button
                  onClick={() => setDropOpen(!dropOpen)}
                  className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-surface-hover transition-colors"
                >
                  <span className="text-xs text-slate-400 border border-surface-border px-2 py-0.5 rounded">
                    {user?.plan || 'Free'}
                  </span>
                  <div className="w-8 h-8 rounded-full bg-primary/30 border border-primary/50 flex items-center justify-center text-xs font-bold text-primary-light">
                    {initials}
                  </div>
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                </button>
                {dropOpen && (
                  <div className="absolute right-0 top-12 w-48 bg-surface-card border border-surface-border rounded-xl shadow-xl z-50 overflow-hidden">
                    <div className="px-4 py-3 border-b border-surface-border">
                      <p className="text-sm font-medium text-white truncate">{user?.full_name}</p>
                      <p className="text-xs text-slate-400 truncate">{user?.email}</p>
                    </div>
                    <Link to="/settings" onClick={() => setDropOpen(false)} className="flex items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-surface-hover transition-colors">
                      <Settings className="w-4 h-4" /> Settings
                    </Link>
                    <button onClick={handleLogout} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-accent-red hover:bg-surface-hover transition-colors">
                      <LogOut className="w-4 h-4" /> Logout
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Mobile hamburger */}
          <button className="md:hidden text-slate-400" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div className="md:hidden bg-surface-card border-t border-surface-border px-4 py-4 flex flex-col gap-3">
          {!isAuth ? (
            <>
              <Link to="/" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>Home</Link>
              <Link to="/about" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>About</Link>
              <Link to="/login" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>Login</Link>
              <Link to="/signup" className="bg-primary text-white text-sm px-4 py-2 rounded-lg text-center" onClick={() => setMenuOpen(false)}>Get Started</Link>
            </>
          ) : (
            <>
              <Link to="/dashboard" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>Dashboard</Link>
              <Link to="/scans" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>Scans</Link>
              <Link to="/review" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>PR Review</Link>
              <Link to="/settings" className="text-slate-300 text-sm" onClick={() => setMenuOpen(false)}>Settings</Link>
              <button onClick={handleLogout} className="text-accent-red text-sm text-left">Logout</button>
            </>
          )}
          <Link to="/demo" className="text-primary-light text-sm font-semibold" onClick={() => setMenuOpen(false)}>⚡ Demo</Link>
        </div>
      )}
    </nav>
  )
}
