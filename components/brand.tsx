import { Radar } from "lucide-react"

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      <span className="brand-mark">
        <Radar className="size-[18px]" strokeWidth={1.9} aria-hidden="true" />
      </span>
      {!compact && (
        <span className="truncate text-[15px] font-semibold tracking-[-0.01em] text-[var(--text)]">
          PacketLens
        </span>
      )}
    </span>
  )
}
