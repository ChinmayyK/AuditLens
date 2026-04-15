import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Shield, GitPullRequest, Settings, LogOut, Zap } from 'lucide-react'
import { logout } from '../../services/authService'
import toast from 'react-hot-toast'

const links = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/review', icon: GitPullRequest, label: 'PR Review', highlight: true },
  { to: '/scans', icon: Shield, label: 'Scans' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/')
    toast.success('Logged out')
  }

  return (
    <aside className="fixed left-0 top-0 h-screen w-60 bg-surface-card border-r border-surface-border flex flex-col z-40">
      <div className="flex items-center gap-2 px-6 py-5 border-b border-surface-border">
        <Shield className="w-6 h-6 text-primary" />
        <span className="font-bold text-white">Shield<span className="text-primary">Sentinel</span></span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {links.map(({ to, icon: Icon, label, highlight }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-primary/20 text-primary-light border border-primary/30'
                  : highlight
                  ? 'text-primary-light hover:bg-primary/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-hover'
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
            {highlight && <span className="ml-auto text-xs bg-primary/20 text-primary-light px-1.5 py-0.5 rounded">Focus</span>}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 pb-4 space-y-1">
        <NavLink to="/demo" className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-primary-light hover:bg-primary/10 transition-colors">
          <Zap className="w-4 h-4" /> Demo
        </NavLink>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-400 hover:text-accent-red hover:bg-accent-red/10 transition-colors"
        >
          <LogOut className="w-4 h-4" /> Logout
        </button>
      </div>
    </aside>
  )
}
