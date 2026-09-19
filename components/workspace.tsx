"use client"

import { useState } from "react"
import { Activity, Binary, Clock3, Database, Download, FileText, Globe2, KeyRound, LayoutDashboard, LockKeyhole, Menu, Moon, Network, Radar, Search, Server, Settings2, ShieldAlert, Sun, Table2, Waypoints, X } from "lucide-react"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { Brand } from "@/components/brand"
import { AnalysisView } from "@/components/analysis-views"
import { CaptureDashboard } from "@/components/capture-dashboard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

const navigation = [
  { group: "Visão geral", items: [{ label: "Dashboard", icon: LayoutDashboard }, { label: "Traffic", icon: Activity }, { label: "Hosts", icon: Server }, { label: "Conversations", icon: Waypoints }, { label: "Network Flows", icon: Network }] },
  { group: "Análise", items: [{ label: "Protocols", icon: Binary }, { label: "DNS", icon: Globe2 }, { label: "HTTP", icon: FileText }, { label: "TLS", icon: KeyRound }, { label: "Ports", icon: Database }, { label: "Packet Explorer", icon: Table2 }] },
  { group: "Investigação", items: [{ label: "Network Map", icon: Radar }, { label: "Security Insights", icon: ShieldAlert }, { label: "Timeline", icon: Clock3 }, { label: "Reports", icon: Download }, { label: "Settings", icon: Settings2 }] },
]

const viewCopy: Record<string, [string, string]> = {
  Dashboard: ["Visão geral da captura", "Resumo operacional e indicadores de maior relevância"],
  Traffic: ["Traffic", "Comportamento e volume durante a janela capturada"],
  Hosts: ["Hosts", "Dispositivos e endpoints observados na rede"],
  Conversations: ["Conversations", "Comunicações bidirecionais entre endpoints"],
  "Network Flows": ["Network Flows", "Fluxos agrupados por origem, destino e transporte"],
  Protocols: ["Protocolos", "Distribuição e volume por protocolo identificado"],
  DNS: ["DNS Analysis", "Domínios, origens, respostas e frequência de consulta"],
  HTTP: ["HTTP Analysis", "Requisições não criptografadas observáveis"],
  TLS: ["TLS Analysis", "Conexões protegidas e metadados disponíveis"],
  Ports: ["Ports", "Portas observadas e serviços prováveis"],
  "Packet Explorer": ["Packet Explorer", "Navegação detalhada pelos pacotes retidos"],
  "Network Map": ["Network Map", "Relações de maior volume entre os hosts"],
  "Security Insights": ["Security Insights", "Padrões incomuns que merecem investigação"],
  Timeline: ["Incident Timeline", "Sequência cronológica dos eventos relevantes"],
  Reports: ["Reports", "Exporte os resultados para investigação complementar"],
  Settings: ["Settings", "Privacidade, processamento e limites da análise"],
}

export function Workspace({ analysis, onNewCapture, light, onTheme }: { analysis: CaptureAnalysis; onNewCapture: () => void; light: boolean; onTheme: () => void }) {
  const [view, setView] = useState("Dashboard")
  const [query, setQuery] = useState("")
  const [protocol, setProtocol] = useState("Todos")
  const [mobileOpen, setMobileOpen] = useState(false)
  const [title, description] = viewCopy[view] || [view, ""]

  const navigate = (next: string) => { setView(next); setMobileOpen(false) }
  const chooseProtocol = (value: string) => { setProtocol(value); setView("Packet Explorer") }
  const investigate = (term: string) => { setQuery(term); setProtocol("Todos"); setView("Packet Explorer") }

  return (
    <main className="min-h-screen bg-[#080b11] text-slate-100 selection:bg-cyan-400/25">
      <aside className={`app-sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <div className="flex items-center justify-between px-2"><Brand /><button className="icon-button desktop-hide" onClick={() => setMobileOpen(false)} aria-label="Fechar menu"><X className="size-4" /></button></div>
        <nav className="mt-7 flex-1 overflow-y-auto pr-1">
          {navigation.map((section) => <div className="mb-6" key={section.group}><p className="nav-group">{section.group}</p><div className="mt-2 space-y-1">{section.items.map((item) => <button key={item.label} onClick={() => navigate(item.label)} className={`nav-item ${view === item.label ? "active" : ""}`}><item.icon />{item.label}{item.label === "Security Insights" && analysis.alerts.length > 0 ? <span className="ml-auto rounded bg-amber-300/10 px-1.5 py-0.5 font-mono text-[9px] text-amber-300">{analysis.alerts.length}</span> : null}</button>)}</div></div>)}
        </nav>
        <div className="privacy-card"><LockKeyhole className="size-4 text-emerald-400" /><p>Processamento local</p><span>Nenhum pacote foi enviado.</span></div>
      </aside>
      {mobileOpen && <button className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Fechar navegação" />}

      <section className="min-h-screen lg:pl-[244px]">
        <header className="app-header">
          <button className="icon-button desktop-hide" onClick={() => setMobileOpen(true)} aria-label="Abrir menu"><Menu className="size-4" /></button>
          <div className="relative hidden flex-1 sm:block sm:max-w-lg"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-600" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Pesquisar IP, domínio, porta, protocolo..." className="h-10 border-white/[.07] bg-white/[.025] pl-10 pr-16 text-sm shadow-none placeholder:text-slate-600" /><kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-white/[.08] bg-white/[.03] px-1.5 py-1 font-mono text-[9px] text-slate-600">GLOBAL</kbd></div>
          <div className="ml-auto flex items-center gap-2"><button className="icon-button" onClick={onTheme} aria-label="Alternar tema">{light ? <Moon className="size-4" /> : <Sun className="size-4" />}</button><Button variant="outline" size="sm" className="h-9 border-white/[.09] bg-white/[.025] text-slate-300 hover:bg-white/[.07] hover:text-white" onClick={onNewCapture}>Nova captura</Button></div>
        </header>

        <div className="mx-auto max-w-[1560px] px-4 py-5 sm:px-7 sm:py-7 xl:px-9">
          <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
            <div><div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.16em] text-slate-600"><span className="status-dot" /> Captura analisada <span className="text-slate-800">/</span> {analysis.fileName}</div><h1 className="text-2xl font-semibold tracking-[-.035em] text-slate-100 sm:text-[1.8rem]">{title}</h1><p className="mt-1.5 text-sm text-slate-500">{description}</p></div>
            <div className="sm:hidden"><Select value={view} onValueChange={navigate}><SelectTrigger className="w-[210px] border-white/[.08] bg-white/[.025]"><SelectValue /></SelectTrigger><SelectContent>{navigation.flatMap((section) => section.items).map((item) => <SelectItem key={item.label} value={item.label}>{item.label}</SelectItem>)}</SelectContent></Select></div>
          </div>
          {query && view !== "Packet Explorer" && <div className="search-context mb-4"><Search className="size-3.5" /> Resultados filtrados por “{query}” <button onClick={() => setQuery("")}>Limpar</button></div>}
          {view === "Dashboard" ? <CaptureDashboard analysis={analysis} onNavigate={navigate} onProtocol={chooseProtocol} /> : <AnalysisView view={view} analysis={analysis} query={query} protocol={protocol} setProtocol={setProtocol} onInvestigate={investigate} />}
        </div>
      </section>
    </main>
  )
}
