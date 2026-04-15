import { Component, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface State { hasError: boolean; error?: Error }

export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { hasError: false }

  static getDerivedStateFromError(error: Error) { return { hasError: true, error } }

  render() {
    if (!this.state.hasError) return this.props.children
    return (
      <div className="flex flex-col items-center justify-center min-h-[300px] text-center px-4">
        <AlertTriangle className="w-12 h-12 text-accent-yellow mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Something went wrong</h2>
        <p className="text-slate-400 text-sm mb-6">{this.state.error?.message}</p>
        <button
          onClick={() => this.setState({ hasError: false })}
          className="px-5 py-2 bg-primary hover:bg-primary-dark text-white rounded-xl text-sm"
        >
          Try Again
        </button>
      </div>
    )
  }
}
