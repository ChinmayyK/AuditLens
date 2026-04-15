import { useState } from 'react'
import { NavLink, Link, useNavigate } from 'react-router-dom'
import { Outlet } from 'react-router-dom'
import {
  Shield, LayoutDashboard, ScanLine, GitPullRequest,
  Settings, LogOut, Menu, ChevronRight, Zap, Bell
} from 'lucide-react'
import { getStoredUser } from '../../services/authService'
import { logout } from '../../services/authService'
import toast from 'react-hot-toast'

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',     icon: ScanLine,        label: 'Scans'     },
  { to: '/review',    icon: GitPullRequest,   label: 'PR Review' },
  { to: '/settings',  icon: Settings,         label: 'Settings'  },
]

export default function DashboardLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const navigate = useNavigate()
  const user = getStoredUser()

  const initials = user?.full_name
    ? user.full_name.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2)
    : 'U'

  async function handleLogout() {
    try { await logout() } catch {}
    navigate('/')
    toast.success('Logged out')
  }

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150 ${
      isActive
        ? 'bg-primary/20 text-primary-light border border-primary/30'
        : 'text-slate-400 hover:text-slate-200 hover:bg-surface-hover'
    }`

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center justify-between px-4 py-5 border-b border-surface-border shrink-0">
        <Link to="/" className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary shrink-0" />
          {!collapsed && (
            <span className="font-bold text-white text-base tracking-tight">
              Shield<span className="text-primary">Sentinel</span>
            </span>
          )}
        </Link>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden lg:flex text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
        >
          <ChevronRight className={`w-4 h-4 transition-transform duration-200 ${collapsed ? '' : 'rotate-180'}`} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={linkClass} onClick={() => setMobileOpen(false)}>
            <Icon className="w-4 h-4 shrink-0" />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}

        <div className="pt-3 border-t border-surface-border mt-3">
          <NavLink
            to="/demo"
            className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-primary-light hover:bg-primary/10 transition-colors"
            onClick={() => setMobileOpen(false)}
          >
            <Zap className="w-4 h-4 shrink-0" />
            {!collapsed && <span>Live Demo</span>}
          </NavLink>
        </div>
      </nav>

      {/* User footer */}
      <div className="px-3 py-4 border-t border-surface-border shrink-0">
        <div className={`flex items-center gap-3 px-2 py-2 rounded-xl ${collapsed ? 'justify-center' : ''}`}>
          <div className="w-8 h-8 rounded-full bg-primary/30 border border-primary/50 flex items-center justify-center text-xs font-bold text-primary-light shrink-0">
            {initials}
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.full_name || 'User'}</p>
              <p className="text-xs text-slate-500 truncate">{user?.plan || 'Free'} plan</p>
            </div>
          )}
          {!collapsed && (
            <button
              onClick={handleLogout}
              className="text-slate-500 hover:text-accent-red transition-colors p-1"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  )

  return (
    <div className="flex h-screen bg-surface overflow-hidden">
      {/* Desktop Sidebar */}
      <aside
        className={`hidden lg:flex flex-col bg-surface-card border-r border-surface-border transition-all duration-200 ${
          collapsed ? 'w-16' : 'w-56'
        }`}
      >
        <SidebarContent />
      </aside>

      {/* Mobile Sidebar Overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="relative w-56 h-full bg-surface-card border-r border-surface-border flex flex-col">
            <SidebarContent />
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="h-14 border-b border-surface-border bg-surface-card/80 backdrop-blur flex items-center justify-between px-4 shrink-0">
          <button
            className="lg:hidden text-slate-400 hover:text-slate-200"
            onClick={() => setMobileOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex-1" />
          <div className="flex items-center gap-3">
            <button className="text-slate-500 hover:text-slate-300 transition-colors relative">
              <Bell className="w-5 h-5" />
            </button>
            <span className="text-xs text-slate-500 border border-surface-border px-2 py-1 rounded-lg">
              {user?.plan || 'Free'}
            </span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
