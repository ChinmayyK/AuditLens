import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { User, Key, Calendar, Plus, Trash2, Eye, Copy, X } from 'lucide-react'
import toast from 'react-hot-toast'
import Sidebar from '../components/layout/Sidebar'
import LoadingSkeleton from '../components/ui/LoadingSkeleton'
import api from '../lib/axios'

type Tab = 'profile' | 'apikeys' | 'schedules'

function ProfileTab() {
  const { data: profile, isLoading } = useQuery({ queryKey: ['profile'], queryFn: () => api.get('/settings/profile').then(r => r.data) })
  const [form, setForm] = useState({ full_name: '', email: '' })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (profile) setForm({ full_name: profile.full_name || '', email: profile.email || '' })
  }, [profile])

  async function save() {
    setSaving(true)
    try {
      await api.put('/settings/profile', form)
      toast.success('Profile updated')
    } catch { toast.error('Failed to update profile') }
    finally { setSaving(false) }
  }

  if (isLoading) return <div className="space-y-3">{Array(3).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-10" />)}</div>

  return (
    <div className="max-w-md space-y-4">
      <div>
        <label className="block text-sm text-slate-400 mb-1.5">Full Name</label>
        <input value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary" />
      </div>
      <div>
        <label className="block text-sm text-slate-400 mb-1.5">Email</label>
        <input value={form.email} disabled className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-slate-500 cursor-not-allowed" />
      </div>
      <button onClick={save} disabled={saving} className="px-6 py-2.5 bg-primary hover:bg-primary-dark disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors">
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  )
}

function APIKeysTab() {
  const qc = useQueryClient()
  const { data: keys = [], isLoading } = useQuery({ queryKey: ['apikeys'], queryFn: () => api.get('/settings/api-keys').then(r => r.data) })
  const [modal, setModal] = useState(false)
  const [form, setForm] = useState({ name: '', expires_in: '90d' })
  const [newKey, setNewKey] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  async function create() {
    if (!form.name) return
    setCreating(true)
    try {
      const res = await api.post('/settings/api-keys', form)
      setNewKey(res.data.key || res.data.access_key || null)
      qc.invalidateQueries({ queryKey: ['apikeys'] })
    } catch { toast.error('Failed to create API key') }
    finally { setCreating(false) }
  }

  async function deleteKey(id: string) {
    if (!confirm('Delete this API key? This cannot be undone.')) return
    try {
      await api.delete(`/settings/api-keys/${id}`)
      qc.invalidateQueries({ queryKey: ['apikeys'] })
      toast.success('API key deleted')
    } catch { toast.error('Failed to delete key') }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm text-slate-400">Manage your API keys</h3>
        <button onClick={() => setModal(true)} className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-xl text-sm transition-colors">
          <Plus className="w-4 h-4" /> Create Key
        </button>
      </div>

      <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
        {isLoading ? <div className="p-4 space-y-2">{Array(3).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-8" />)}</div> : (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-surface-border text-xs text-slate-500"><th className="px-4 py-3 text-left">Name</th><th className="px-4 py-3 text-left">Key</th><th className="px-4 py-3 text-left">Created</th><th className="px-4 py-3"></th></tr></thead>
            <tbody>
              {keys.map((k: any) => (
                <tr key={k.id} className="border-b border-surface-border/50">
                  <td className="px-4 py-3 text-white">{k.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{k.key_preview || '••••••••'}</td>
                  <td className="px-4 py-3 text-slate-500 text-xs">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => deleteKey(k.id)} className="text-slate-500 hover:text-accent-red transition-colors"><Trash2 className="w-4 h-4" /></button>
                  </td>
                </tr>
              ))}
              {!keys.length && <tr><td colSpan={4} className="px-4 py-8 text-center text-slate-500">No API keys</td></tr>}
            </tbody>
          </table>
        )}
      </div>

      {/* Create Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="bg-surface-card border border-surface-border rounded-2xl w-full max-w-md p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="font-semibold text-white">Create API Key</h2>
              <button onClick={() => { setModal(false); setNewKey(null); setForm({ name: '', expires_in: '90d' }) }} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            {newKey ? (
              <div>
                <p className="text-sm text-accent-yellow mb-3 font-medium">⚠️ Copy this key now. It will never be shown again.</p>
                <div className="flex items-center gap-2 p-3 bg-surface border border-surface-border rounded-xl">
                  <span className="font-mono text-xs text-white flex-1 break-all">{newKey}</span>
                  <button onClick={() => { navigator.clipboard.writeText(newKey); toast.success('Copied!') }} className="text-primary-light hover:text-white"><Copy className="w-4 h-4" /></button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1.5">Name</label>
                  <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="My API Key" className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary" />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1.5">Expires In</label>
                  <select value={form.expires_in} onChange={e => setForm({ ...form, expires_in: e.target.value })} className="w-full bg-surface border border-surface-border rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none">
                    <option value="30d">30 days</option>
                    <option value="90d">90 days</option>
                    <option value="1yr">1 year</option>
                    <option value="never">Never</option>
                  </select>
                </div>
                <button onClick={create} disabled={creating || !form.name} className="w-full bg-primary hover:bg-primary-dark disabled:opacity-50 text-white font-medium py-2.5 rounded-xl text-sm transition-colors">
                  {creating ? 'Creating...' : 'Create Key'}
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SchedulesTab() {
  const qc = useQueryClient()
  const { data: schedules = [], isLoading } = useQuery({ queryKey: ['schedules'], queryFn: () => api.get('/settings/schedules').then(r => r.data) })

  async function toggle(id: string) {
    try {
      await api.patch(`/settings/schedules/${id}/toggle`)
      qc.invalidateQueries({ queryKey: ['schedules'] })
    } catch { toast.error('Failed to toggle schedule') }
  }

  async function del(id: string) {
    if (!confirm('Delete this schedule?')) return
    try {
      await api.delete(`/settings/schedules/${id}`)
      qc.invalidateQueries({ queryKey: ['schedules'] })
      toast.success('Schedule deleted')
    } catch { toast.error('Failed to delete schedule') }
  }

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      {isLoading ? <div className="p-4 space-y-2">{Array(3).fill(0).map((_, i) => <LoadingSkeleton key={i} height="h-8" />)}</div> : (
        <table className="w-full text-sm">
          <thead><tr className="border-b border-surface-border text-xs text-slate-500"><th className="px-4 py-3 text-left">Name</th><th className="px-4 py-3 text-left">Target</th><th className="px-4 py-3 text-left">Frequency</th><th className="px-4 py-3 text-left">Status</th><th className="px-4 py-3"></th></tr></thead>
          <tbody>
            {schedules.map((s: any) => (
              <tr key={s.id} className="border-b border-surface-border/50">
                <td className="px-4 py-3 text-white">{s.name}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400 truncate max-w-[140px]">{s.target}</td>
                <td className="px-4 py-3 text-slate-400 capitalize">{s.frequency}</td>
                <td className="px-4 py-3">
                  <button onClick={() => toggle(s.id)} className={`px-2 py-1 rounded text-xs font-medium ${s.is_active ? 'bg-accent-green/15 text-accent-green' : 'bg-slate-700/40 text-slate-400'}`}>
                    {s.is_active ? 'Active' : 'Paused'}
                  </button>
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => del(s.id)} className="text-slate-500 hover:text-accent-red transition-colors"><Trash2 className="w-4 h-4" /></button>
                </td>
              </tr>
            ))}
            {!schedules.length && <tr><td colSpan={5} className="px-4 py-8 text-center text-slate-500">No schedules configured</td></tr>}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>('profile')
  useEffect(() => { document.title = 'Settings | ShieldSentinel' }, [])

  const tabs = [
    { id: 'profile' as Tab, label: 'Profile', icon: User },
    { id: 'apikeys' as Tab, label: 'API Keys', icon: Key },
    { id: 'schedules' as Tab, label: 'Schedules', icon: Calendar },
  ]

  return (
    <div className="flex min-h-screen bg-surface">
      <Sidebar />
      <main className="ml-60 flex-1 p-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white">Settings</h1>
        </div>

        <div className="flex border-b border-surface-border mb-8 gap-1">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${tab === id ? 'border-primary text-white' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
            >
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </div>

        {tab === 'profile' && <ProfileTab />}
        {tab === 'apikeys' && <APIKeysTab />}
        {tab === 'schedules' && <SchedulesTab />}
      </main>
    </div>
  )
}
