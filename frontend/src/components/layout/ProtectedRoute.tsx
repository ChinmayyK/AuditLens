import { Navigate, Outlet } from 'react-router-dom'

export default function ProtectedRoute() {
  const raw = localStorage.getItem('ss_user')
  if (!raw) return <Navigate to="/login" replace />
  try {
    const user = JSON.parse(raw)
    if (!user?.access_token) return <Navigate to="/login" replace />
  } catch {
    return <Navigate to="/login" replace />
  }
  return <Outlet />
}
