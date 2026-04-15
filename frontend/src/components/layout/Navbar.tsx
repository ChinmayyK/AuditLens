import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
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
  const [scrolled, setScrolled] = useState(false)
  const [mobileClosing, setMobileClosing] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const dropdownRef = useRef<HTMLDivElement | null>(null)
  const user = getUser()
  const isAuth = !!user?.access_token

  const initials = user?.full_name
    ? user.full_name.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2)
    : 'U'

  async function handleLogout() {
    try { await api.post('/auth/logout') } catch {}
    localStorage.removeItem('ss_user')
    setDropOpen(false)
    setMenuOpen(false)
    navigate('/')
    toast.success('Logged out')
  }

  // Close dropdown and mobile menu when route changes
  useEffect(() => {
    setDropOpen(false)
    setMenuOpen(false)
    setMobileClosing(false)
  }, [location.pathname])

  // Add depth when user scrolls
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  // Close profile dropdown on outside click or ESC
  useEffect(() => {
    if (!dropOpen) return
    const onPointerDown = (event: PointerEvent) => {
      if (!dropdownRef.current) return
      if (!dropdownRef.current.contains(event.target as Node)) {
        setDropOpen(false)
      }
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDropOpen(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [dropOpen])

  const closeMobileMenu = () => {
    if (!menuOpen) return
    setMobileClosing(true)
    window.setTimeout(() => {
      setMenuOpen(false)
      setMobileClosing(false)
    }, 160)
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `relative text-sm font-medium transition-all duration-200 hover:-translate-y-0.5 ${
      isActive
        ? 'text-blue-900 after:absolute after:-bottom-1.5 after:left-0 after:h-[2px] after:w-full after:rounded-full after:bg-blue-700'
        : 'text-blue-800/70 hover:text-blue-900'
    }`

  return (
    <nav
      className={`sticky top-0 z-50 border-b border-indigo-100/90 bg-white/90 backdrop-blur transition-all duration-300 ${
        scrolled ? 'shadow-md shadow-blue-100/60' : 'shadow-none'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <Link to="/" className="group flex shrink-0 items-center gap-2">
            <Shield className="h-7 w-7 text-primary transition-transform duration-300 group-hover:scale-110 group-hover:rotate-6" />
            <span className="text-lg font-bold tracking-tight text-blue-900">
              Audit <span className="text-primary">Lines</span>
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
              className="group flex items-center gap-1 rounded-full border border-indigo-300 bg-indigo-100 px-3 py-1.5 text-xs font-semibold text-blue-900 transition-all duration-200 hover:-translate-y-0.5 hover:bg-indigo-200"
            >
              <Zap className="h-3 w-3 transition-transform duration-200 group-hover:rotate-12" /> Demo
            </Link>
          </div>

          {/* Right side */}
          <div className="hidden md:flex items-center gap-3">
            {!isAuth ? (
              <>
                <Link to="/login" className="rounded-lg border border-indigo-200 px-4 py-1.5 text-sm text-blue-800 transition-all duration-200 hover:-translate-y-0.5 hover:text-blue-900">
                  Login
                </Link>
                <Link to="/signup" className="rounded-lg bg-blue-700 px-4 py-1.5 text-sm font-medium text-white shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-800 hover:shadow-blue-200">
                  Get Started
                </Link>
              </>
            ) : (
              <div className="relative" ref={dropdownRef}>
                <button
                  onClick={() => setDropOpen(!dropOpen)}
                  className="flex items-center gap-2 rounded-lg px-2 py-1.5 transition-all duration-200 hover:bg-blue-50"
                >
                  <span className="rounded border border-indigo-200 px-2 py-0.5 text-xs text-blue-800/70">
                    {user?.plan || 'Free'}
                  </span>
                  <div className="flex h-8 w-8 items-center justify-center rounded-full border border-indigo-300 bg-indigo-100 text-xs font-bold text-blue-900">
                    {initials}
                  </div>
                  <ChevronDown className={`h-4 w-4 text-blue-800/70 transition-transform duration-200 ${dropOpen ? 'rotate-180' : ''}`} />
                </button>
                {dropOpen && (
                  <div className="absolute right-0 top-12 z-50 w-48 overflow-hidden rounded-xl border border-indigo-100 bg-white shadow-xl animate-in fade-in zoom-in-95 duration-200">
                    <div className="border-b border-indigo-100 px-4 py-3">
                      <p className="truncate text-sm font-medium text-blue-900">{user?.full_name}</p>
                      <p className="truncate text-xs text-blue-800/70">{user?.email}</p>
                    </div>
                    <Link to="/settings" onClick={() => setDropOpen(false)} className="flex items-center gap-2 px-4 py-2.5 text-sm text-blue-800 transition-colors hover:bg-blue-50">
                      <Settings className="w-4 h-4" /> Settings
                    </Link>
                    <button onClick={handleLogout} className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-accent-red transition-colors hover:bg-blue-50">
                      <LogOut className="w-4 h-4" /> Logout
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Mobile hamburger */}
          <button
            className="text-blue-800/70 transition-transform duration-200 hover:scale-105 md:hidden"
            onClick={() => (menuOpen ? closeMobileMenu() : setMenuOpen(true))}
            aria-label="Toggle navigation menu"
            aria-expanded={menuOpen}
          >
            {menuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div
          className={`border-t border-indigo-100 bg-white px-4 py-4 md:hidden ${
            mobileClosing
              ? 'animate-out slide-out-to-top-2 fade-out duration-150'
              : 'animate-in slide-in-from-top-2 fade-in duration-200'
          }`}
        >
          <div className="flex flex-col gap-3">
          {!isAuth ? (
            <>
              <Link to="/" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>Home</Link>
              <Link to="/about" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>About</Link>
              <Link to="/login" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>Login</Link>
              <Link to="/signup" className="rounded-lg bg-blue-700 px-4 py-2 text-center text-sm text-white transition-colors hover:bg-blue-800" onClick={closeMobileMenu}>Get Started</Link>
            </>
          ) : (
            <>
              <Link to="/dashboard" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>Dashboard</Link>
              <Link to="/scans" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>Scans</Link>
              <Link to="/review" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>PR Review</Link>
              <Link to="/settings" className="rounded-md px-2 py-1.5 text-sm text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>Settings</Link>
              <button onClick={handleLogout} className="text-left text-sm text-accent-red transition-colors hover:brightness-125">Logout</button>
            </>
          )}
          <Link to="/demo" className="rounded-md px-2 py-1.5 text-sm font-semibold text-blue-800 transition-colors hover:bg-blue-50 hover:text-blue-900" onClick={closeMobileMenu}>⚡ Demo</Link>
          </div>
        </div>
      )}
    </nav>
  )
}
