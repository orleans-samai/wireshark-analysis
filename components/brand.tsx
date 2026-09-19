import { Radar } from "lucide-react"

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <span className="brand-mark"><Radar className="size-5" strokeWidth={1.8} /></span>
      {!compact && (
        <span className="leading-none">
          <span className="block text-[15px] font-semibold tracking-[-0.02em] text-white">PacketLens</span>
          <span className="mt-1 block text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">Network analysis</span>
        </span>
      )}
    </div>
  )
}
