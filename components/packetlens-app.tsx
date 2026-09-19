"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { Activity, AlertTriangle, ArrowRight, FileSearch, FolderOpen, LockKeyhole, Moon, Search, ShieldCheck, Sun, UploadCloud } from "lucide-react"
import { Brand } from "@/components/brand"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { demoAnalysis } from "@/lib/demo-data"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { Workspace } from "@/components/workspace"

type AnalysisState = { percent: number; processed: number; stage: string }

export function PacketLensApp() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [analysis, setAnalysis] = useState<CaptureAnalysis | null>(null)
  const [progress, setProgress] = useState<AnalysisState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [light, setLight] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle("dark", !light)
    document.documentElement.classList.toggle("light", light)
  }, [light])

  const analyzeFile = useCallback((file: File) => {
    setError(null)
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setError("Formato não suportado. Selecione um arquivo .pcap ou .pcapng.")
      return
    }
    setProgress({ percent: 2, processed: 0, stage: "Lendo captura" })
    const worker = new Worker("/pcap-worker.js")
    worker.onmessage = ({ data }) => {
      if (data.type === "progress") setProgress(data)
      if (data.type === "done") { setAnalysis(data.result); setProgress(null); worker.terminate() }
      if (data.type === "error") { setError(data.message); setProgress(null); worker.terminate() }
    }
    worker.onerror = () => { setError("Não foi possível iniciar o analisador local. Tente novamente."); setProgress(null); worker.terminate() }
    worker.postMessage({ type: "analyze", file })
  }, [])

  if (analysis) {
    return <Workspace analysis={analysis} onNewCapture={() => setAnalysis(null)} light={light} onTheme={() => setLight((value) => !value)} />
  }

  return (
    <main className="min-h-screen bg-[#070a0f] text-slate-100 selection:bg-cyan-400/25">
      <div className="fixed inset-0 overflow-hidden pointer-events-none" aria-hidden="true">
        <div className="scan-grid absolute inset-0 opacity-35" />
        <div className="absolute left-[18%] top-[-18rem] h-[38rem] w-[38rem] rounded-full bg-cyan-500/[0.055] blur-3xl" />
        <div className="absolute bottom-[-25rem] right-[-10rem] h-[44rem] w-[44rem] rounded-full bg-indigo-500/[0.06] blur-3xl" />
      </div>
      <header className="relative z-10 flex h-20 items-center justify-between border-b border-white/[0.06] px-5 sm:px-8 lg:px-12">
        <Brand />
        <div className="flex items-center gap-2">
          <span className="hidden items-center gap-2 text-xs text-slate-500 sm:flex"><LockKeyhole className="size-3.5 text-emerald-400" /> Processamento local</span>
          <button className="icon-button" onClick={() => setLight((value) => !value)} aria-label="Alternar tema">{light ? <Moon className="size-4" /> : <Sun className="size-4" />}</button>
        </div>
      </header>
      <section className="relative z-10 mx-auto grid min-h-[calc(100vh-80px)] max-w-[1480px] items-center gap-12 px-5 py-10 lg:grid-cols-[0.82fr_1.18fr] lg:px-12">
        <div className="max-w-xl">
          <div className="eyebrow"><span className="status-dot" /> Análise forense sem upload</div>
          <h1 className="mt-7 text-[clamp(2.7rem,5.5vw,5.5rem)] font-semibold leading-[0.96] tracking-[-0.055em] text-white">Enxergue o que a <span className="text-gradient">captura revela.</span></h1>
          <p className="mt-7 max-w-lg text-base leading-7 text-slate-400 sm:text-lg">Transforme tráfego bruto em conversações, hosts, DNS, protocolos e sinais que merecem investigação — direto no seu navegador.</p>
          <div className="mt-8 flex flex-wrap gap-x-8 gap-y-3 text-sm text-slate-400">
            <span className="flex items-center gap-2"><ShieldCheck className="size-4 text-cyan-400" /> Dados permanecem no dispositivo</span>
            <span className="flex items-center gap-2"><Activity className="size-4 text-violet-400" /> PCAP e PCAPNG</span>
          </div>
        </div>
        <div className="relative">
          <div className="absolute -inset-6 rounded-[2rem] bg-cyan-400/[0.03] blur-2xl" />
          <div className={`drop-surface relative ${dragging ? "is-dragging" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) analyzeFile(file) }}>
            <div className="corner corner-tl" /><div className="corner corner-tr" /><div className="corner corner-bl" /><div className="corner corner-br" />
            {progress ? (
              <div className="w-full max-w-md text-center" aria-live="polite">
                <div className="mx-auto mb-7 flex size-20 items-center justify-center rounded-3xl border border-cyan-300/20 bg-cyan-400/[0.08]"><FileSearch className="size-9 animate-pulse text-cyan-300" strokeWidth={1.4} /></div>
                <h2 className="text-2xl font-semibold tracking-tight text-white">Analisando captura</h2><p className="mt-2 text-sm text-slate-400">{progress.stage}</p>
                <Progress value={progress.percent} className="mt-7 h-1.5 bg-white/[0.08] [&_[data-slot=progress-indicator]]:bg-cyan-400" />
                <div className="mt-3 flex justify-between font-mono text-xs text-slate-500"><span>{progress.processed.toLocaleString("pt-BR")} pacotes</span><span>{progress.percent}%</span></div>
              </div>
            ) : (
              <div className="w-full max-w-md text-center">
                <div className="upload-orbit mx-auto mb-7"><UploadCloud className="size-8 text-cyan-300" strokeWidth={1.5} /></div>
                <h2 className="text-2xl font-semibold tracking-[-0.025em] text-white">Arraste sua captura aqui</h2><p className="mt-2 text-sm leading-6 text-slate-400">Arquivos .pcap ou .pcapng processados localmente</p>
                <input ref={fileInput} type="file" className="sr-only" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => { const file = event.target.files?.[0]; if (file) analyzeFile(file) }} />
                <Button size="lg" className="mt-7 h-11 rounded-lg bg-cyan-300 px-5 font-semibold text-slate-950 hover:bg-cyan-200" onClick={() => fileInput.current?.click()}><FolderOpen className="size-4" /> Selecionar captura</Button>
                <button className="group mx-auto mt-5 flex items-center gap-2 text-sm font-medium text-slate-400 transition hover:text-white" onClick={() => setAnalysis(demoAnalysis)}>Explorar análise de exemplo <ArrowRight className="size-4 transition-transform group-hover:translate-x-1" /></button>
                {error && <div className="mt-6 flex items-start gap-3 rounded-xl border border-rose-400/20 bg-rose-400/[0.06] p-3 text-left text-sm text-rose-200"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{error}</div>}
              </div>
            )}
          </div>
          <div className="mt-4 flex items-center justify-between px-1 font-mono text-[11px] uppercase tracking-[0.14em] text-slate-600"><span>Offline-first</span><span>A captura não sai do navegador</span></div>
        </div>
      </section>
    </main>
  )
}

function DashboardPreview({ analysis, onNew, light, onTheme }: { analysis: CaptureAnalysis; onNew: () => void; light: boolean; onTheme: () => void }) {
  const total = analysis.protocols.reduce((sum, item) => sum + item.packets, 0)
  return (
    <main className="min-h-screen bg-[#080b11] text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[244px] border-r border-white/[0.07] bg-[#0a0e15] px-4 py-5 lg:block">
        <div className="px-2"><Brand /></div><nav className="mt-9 space-y-1"><button className="nav-item active"><Activity /> Dashboard</button><button className="nav-item"><Search /> Packet Explorer</button></nav>
        <div className="absolute bottom-5 left-4 right-4 rounded-xl border border-white/[0.06] bg-white/[0.025] p-3 text-xs leading-5 text-slate-500"><LockKeyhole className="mb-2 size-4 text-emerald-400" />A análise ocorreu localmente. Nenhum pacote foi enviado.</div>
      </aside>
      <section className="lg:pl-[244px]">
        <header className="sticky top-0 z-20 flex h-[72px] items-center justify-between border-b border-white/[0.07] bg-[#080b11]/90 px-5 backdrop-blur-xl sm:px-8">
          <div><p className="text-xs font-medium uppercase tracking-[0.13em] text-slate-500">Captura ativa</p><p className="mt-1 max-w-[45vw] truncate text-sm font-medium text-slate-200">{analysis.fileName}</p></div>
          <div className="flex items-center gap-2"><button className="icon-button" onClick={onTheme} aria-label="Alternar tema">{light ? <Moon className="size-4" /> : <Sun className="size-4" />}</button><Button variant="outline" className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]" onClick={onNew}>Nova captura</Button></div>
        </header>
        <div className="mx-auto max-w-[1500px] p-5 sm:p-8">
          <div className="flex items-end justify-between"><div><p className="eyebrow"><span className="status-dot" /> Análise concluída</p><h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] text-white">Visão geral da captura</h1></div><span className="hidden text-xs text-slate-500 sm:block">{analysis.analyzedAt}</span></div>
          <div className="mt-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[["Total de pacotes", analysis.packetCount.toLocaleString("pt-BR"), "100% processado"], ["Volume de tráfego", formatBytes(analysis.totalBytes), `${formatBytes(analysis.totalBytes / Math.max(1, analysis.duration))}/s`], ["Hosts identificados", analysis.hosts.length.toLocaleString("pt-BR"), `${analysis.conversations.length} conversações`], ["Sinais", analysis.alerts.length.toLocaleString("pt-BR"), "eventos para revisar"]].map(([label, value, hint]) => <div className="metric-card" key={label}><p>{label}</p><strong>{value}</strong><span>{hint}</span></div>)}
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-[1.55fr_0.85fr]">
            <div className="panel min-h-[360px] overflow-hidden p-5"><div className="flex items-center justify-between"><div><h2>Tráfego ao longo do tempo</h2><p>Pacotes processados por intervalo</p></div><span className="pill">Pacotes/s</span></div><div className="mt-10 flex h-56 items-end gap-1.5 border-b border-white/[0.06]">{analysis.timeline.slice(-32).map((point, index) => { const max = Math.max(...analysis.timeline.map((p) => p.packets)); return <div key={`${point.time}-${index}`} className="group relative flex-1 rounded-t bg-cyan-400/20 transition hover:bg-cyan-300/50" style={{ height: `${Math.max(5, (point.packets / max) * 100)}%` }}><span className="pointer-events-none absolute bottom-full left-1/2 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded bg-slate-900 px-2 py-1 text-[10px] group-hover:block">{point.packets} pacotes</span></div> })}</div></div>
            <div className="panel p-5"><div><h2>Distribuição de protocolos</h2><p>Participação no total de pacotes</p></div><div className="mt-7 space-y-5">{analysis.protocols.slice(0, 6).map((item) => <div key={item.name}><div className="mb-2 flex items-center justify-between text-sm"><span className="flex items-center gap-2 font-medium"><i className="size-2 rounded-full" style={{ background: item.color }} />{item.name}</span><span className="font-mono text-xs text-slate-400">{Math.round((item.packets / Math.max(1, total)) * 100)}%</span></div><div className="h-1 overflow-hidden rounded bg-white/[0.06]"><div className="h-full rounded" style={{ width: `${(item.packets / Math.max(1, total)) * 100}%`, background: item.color }} /></div></div>)}</div></div>
          </div>
        </div>
      </section>
    </main>
  )
}

function formatBytes(value: number) { if (!Number.isFinite(value)) return "0 B"; const units = ["B", "KB", "MB", "GB", "TB"]; let n = value, unit = 0; while (n >= 1000 && unit < units.length - 1) { n /= 1000; unit++ } return `${n >= 100 || unit === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[unit]}` }
