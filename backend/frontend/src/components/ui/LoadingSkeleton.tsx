import clsx from 'clsx'

interface Props { width?: string; height?: string; className?: string; rounded?: string }

export default function LoadingSkeleton({ width = 'w-full', height = 'h-4', className, rounded = 'rounded' }: Props) {
  return <div className={clsx('animate-pulse bg-surface-border', width, height, rounded, className)} />
}

export function SkeletonCard() {
  return (
    <div className="bg-surface-card border border-surface-border rounded-2xl p-5 space-y-3">
      <LoadingSkeleton height="h-5" width="w-1/2" />
      <LoadingSkeleton height="h-3" width="w-3/4" />
      <LoadingSkeleton height="h-3" width="w-2/3" />
    </div>
  )
}
