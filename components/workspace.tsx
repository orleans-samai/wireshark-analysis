"use client"

import { useEffect, useState } from "react"
import { Activity, Binary, Clock3, Database, Download, FileText, Globe2, KeyRound, LayoutDashboard, LockKeyhole, Menu, Moon, Network, Radar, Search, Server, Settings2, ShieldAlert, Sun, Table2, Waypoints, X } from "lucide-react"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
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

  // The drawer covers the page behind a scrim, so it has to dismiss like one.
  useEffect(() => {
    if (!mobileOpen) return
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setMobileOpen(false) }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [mobileOpen])

  const navigate = (next: string) => { setView(next); setMobileOpen(false) }
  const chooseProtocol = (value: string) => { setProtocol(value); setView("Packet Explorer") }
  const investigate = (term: string) => { setQuery(term); setProtocol("Todos"); setView("Packet Explorer") }

  const captureFacts = [
    formatBytes(analysis.fileSize),
    `${formatNumber(analysis.packetCount)} pacotes`,
    formatDuration(analysis.duration),
    `analisada em ${analysis.analyzedAt}`,
  ]

  return (
    <div className="shell">
      <aside className={`sidebar ${mobileOpen ? "is-open" : ""}`} id="workspace-nav">
        <div className="sidebar-head">
          <Brand />
          <button className="icon-button lg-hidden" onClick={() => setMobileOpen(false)} aria-label="Fechar navegação">
            <X className="size-4" />
          </button>
        </div>
        <nav className="sidebar-scroll" aria-label="Seções da análise">
          {navigation.map((section) => (
            <div key={section.group}>
              <h2 className="nav-group">{section.group}</h2>
              <ul className="space-y-0.5">
                {section.items.map((item) => (
                  <li key={item.label}>
                    <button
                      onClick={() => navigate(item.label)}
                      className="nav-item"
                      aria-current={view === item.label ? "page" : undefined}
                    >
                      <item.icon aria-hidden="true" />
                      {item.label}
                      {item.label === "Security Insights" && analysis.alerts.length > 0 ? (
                        <span className="nav-count">
                          {analysis.alerts.length}
                          <span className="sr-only"> sinais</span>
                        </span>
                      ) : null}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="sidebar-foot flex items-start gap-2 text-xs leading-relaxed text-[var(--text-muted)]">
          <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-[var(--ok)]" aria-hidden="true" />
          Processamento local. Nenhum pacote foi enviado.
        </p>
      </aside>

      {mobileOpen && (
        <button
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-label="Fechar navegação"
        />
      )}

      <div className="min-h-screen lg:pl-[240px]">
        <div className="workspace-header">
          <header className="topbar">
            <button
              className="icon-button lg-hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Abrir navegação"
              aria-expanded={mobileOpen}
              aria-controls="workspace-nav"
            >
              <Menu className="size-4" />
            </button>
            <div className="relative min-w-0 flex-1 sm:max-w-md">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-[var(--text-faint)]" aria-hidden="true" />
              <Input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label="Filtrar por IP, domínio, porta ou protocolo"
                placeholder="Filtrar por IP, domínio, porta, protocolo"
                className="h-8 bg-[var(--surface-raised)] pl-8 text-sm"
              />
            </div>
            <div className="ml-auto flex items-center gap-2">
              <button className="icon-button" onClick={onTheme} aria-label={light ? "Usar tema escuro" : "Usar tema claro"}>
                {light ? <Moon className="size-4" /> : <Sun className="size-4" />}
              </button>
              <Button variant="outline" size="sm" onClick={onNewCapture}>Nova captura</Button>
            </div>
          </header>

          <p className="capture-bar">
            <span className="mono max-w-full truncate font-medium text-[var(--text)]" title={analysis.fileName}>{analysis.fileName}</span>
            {captureFacts.map((fact) => (
              <span key={fact} className="num">{fact}</span>
            ))}
          </p>
        </div>

        <main className="mx-auto max-w-[1600px] px-3 py-5 sm:px-5 sm:py-6">
          <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
            <div className="min-w-0">
              <h1 className="text-[1.375rem] font-semibold tracking-[-0.02em] text-[var(--text)]">{title}</h1>
              <p className="mt-1 text-sm text-[var(--text-muted)]">{description}</p>
            </div>
            <div className="lg:hidden">
              <Select value={view} onValueChange={navigate}>
                <SelectTrigger className="h-8 w-[200px] bg-[var(--surface)]" aria-label="Trocar de seção">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {navigation.flatMap((section) => section.items).map((item) => (
                    <SelectItem key={item.label} value={item.label}>{item.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {query && view !== "Packet Explorer" && (
            <p className="filter-banner mb-4">
              <Search aria-hidden="true" />
              Filtrando por <span className="mono filter-term font-medium" title={query}>{query}</span>
              <button className="link-button ml-auto" onClick={() => setQuery("")}>Limpar filtro</button>
            </p>
          )}

          {view === "Dashboard"
            ? <CaptureDashboard analysis={analysis} onNavigate={navigate} onProtocol={chooseProtocol} />
            : <AnalysisView view={view} analysis={analysis} query={query} protocol={protocol} setProtocol={setProtocol} onInvestigate={investigate} />}
        </main>
      </div>
    </div>
  )
}
