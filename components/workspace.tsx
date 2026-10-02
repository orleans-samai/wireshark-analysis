"use client"

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Activity, Binary, Bookmark, Clock3, Database, Download, FileDiff, FileText, Globe2, KeyRound, LayoutDashboard, LockKeyhole, Menu, Moon, Network, Radar, Server, Settings2, ShieldAlert, Sun, Table2, Waypoints, X } from "lucide-react"
import type { AlertDisposition, AnalyzerOptions, CaptureAnalysis } from "@/lib/capture-types"
import type { ViewId } from "@/lib/views"
import type { CaseEvidence, FilterKind, InvestigationFilter, InvestigationTarget, SearchSuggestion } from "@/lib/investigation"
import { alertStorageKey, applyTarget, EMPTY_FILTER, removeFilterValue } from "@/lib/investigation"
import { appendEvidence } from "@/lib/casebook"
import { withRuleSuppression } from "@/lib/analyzer-options"
import { readLocalRecord, writeLocalRecord } from "@/lib/local-db"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import type { AnalysisState } from "@/components/packetlens-app"
import { Brand } from "@/components/brand"
import { InvestigationDrawer, useSavedInvestigations } from "@/components/investigation-drawer"
import { FilterToolbar, InvestigationSearch } from "@/components/investigation-controls"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

const AnalysisView = lazy(() => import("@/components/analysis-views").then((module) => ({ default: module.AnalysisView })))
const CaptureDashboard = lazy(() => import("@/components/capture-dashboard").then((module) => ({ default: module.CaptureDashboard })))

const navigation: { group: string; items: { label: ViewId; icon: typeof LayoutDashboard }[] }[] = [
  { group: "Visão geral", items: [{ label: "Dashboard", icon: LayoutDashboard }, { label: "Traffic", icon: Activity }, { label: "Hosts", icon: Server }, { label: "Conversations", icon: Waypoints }, { label: "Network Flows", icon: Network }] },
  { group: "Análise", items: [{ label: "Protocols", icon: Binary }, { label: "DNS", icon: Globe2 }, { label: "HTTP", icon: FileText }, { label: "TLS", icon: KeyRound }, { label: "Ports", icon: Database }, { label: "Packet Explorer", icon: Table2 }] },
  { group: "Investigação", items: [{ label: "Network Map", icon: Radar }, { label: "Security Insights", icon: ShieldAlert }, { label: "Timeline", icon: Clock3 }, { label: "Compare", icon: FileDiff }, { label: "Reports", icon: Download }, { label: "Settings", icon: Settings2 }] },
]

const viewCopy: Record<ViewId, [string, string]> = {
  Dashboard: ["Visão geral da captura", "Resumo operacional e indicadores de maior relevância"],
  Traffic: ["Tráfego", "Volume, qualidade TCP e comportamento durante a janela capturada"],
  Hosts: ["Hosts", "Dispositivos e endpoints observados na rede"],
  Conversations: ["Conversações", "Comunicações bidirecionais entre endpoints"],
  "Network Flows": ["Fluxos de rede", "Fluxos agrupados por origem, destino e transporte"],
  Protocols: ["Protocolos", "Distribuição e volume por protocolo identificado"],
  DNS: ["Análise DNS", "Consultas, respostas, erros e latência observada"],
  HTTP: ["Análise HTTP", "Requisições e respostas não criptografadas observáveis"],
  TLS: ["Análise TLS", "SNI, versões, ALPN e metadados de handshake"],
  Ports: ["Portas", "Portas observadas e serviços prováveis"],
  "Packet Explorer": ["Explorador de pacotes", "Pacotes retidos, filtros conectados e detalhes de protocolo"],
  "Network Map": ["Mapa de rede", "Relações de maior volume entre os hosts"],
  "Security Insights": ["Sinais de segurança", "Regras explicáveis, confiança e evidências relacionadas"],
  Timeline: ["Linha do tempo", "Sequência cronológica dos eventos relevantes"],
  Compare: ["Comparar capturas", "Diferenças de volume, hosts, protocolos e sinais"],
  Reports: ["Relatórios", "Exporte dados, evidências e o recorte investigado"],
  Settings: ["Configurações", "Privacidade, retenção local e limites das regras"],
}

const navLabels: Record<ViewId, string> = {
  Dashboard: "Painel geral", Traffic: "Tráfego", Hosts: "Hosts", Conversations: "Conversas", "Network Flows": "Fluxos de rede",
  Protocols: "Protocolos", DNS: "DNS", HTTP: "HTTP", TLS: "TLS", Ports: "Portas", "Packet Explorer": "Explorador de pacotes",
  "Network Map": "Mapa de rede", "Security Insights": "Sinais de segurança", Timeline: "Linha do tempo", Compare: "Comparar", Reports: "Relatórios", Settings: "Configurações",
}

type WorkspaceProps = {
  analysis: CaptureAnalysis
  sourceFile: File | null
  comparison: CaptureAnalysis | null
  comparisonFile: File | null
  comparisonProgress: AnalysisState | null
  comparisonError?: string | null
  onCompareCapture: (file: File) => void
  onCancelComparison: () => void
  onNewCapture: () => void
  light: boolean
  onTheme: () => void
  options: AnalyzerOptions
  onOptionsChange: (options: AnalyzerOptions) => void
}

export function Workspace(props: WorkspaceProps) {
  const { analysis, sourceFile, comparison, comparisonProgress, comparisonError, onCompareCapture, onCancelComparison, onNewCapture, light, onTheme, options, onOptionsChange } = props
  const [view, setView] = useState<ViewId>("Dashboard")
  const [filter, setFilter] = useState<InvestigationFilter>(EMPTY_FILTER)
  const [history, setHistory] = useState<InvestigationFilter[]>([])
  const [mobileOpen, setMobileOpen] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null)
  const [alertStatus, setAlertStatus] = useState<Record<string, AlertDisposition>>({})
  const loadedAlertKey = useRef("")
  const [saved, setSaved] = useSavedInvestigations(analysis)
  const [title, description] = viewCopy[view]
  const alertKey = alertStorageKey(analysis)

  useEffect(() => {
    if (!mobileOpen) return
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setMobileOpen(false) }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [mobileOpen])

  useEffect(() => {
    let cancelled = false
    loadedAlertKey.current = ""
    const load = async () => {
      let next: Record<string, AlertDisposition> = {}
      try {
        const stored = await readLocalRecord<Record<string, AlertDisposition>>(alertKey)
        if (stored) next = stored
        else {
          next = JSON.parse(window.localStorage.getItem(alertKey) || "{}")
          if (Object.keys(next).length) void writeLocalRecord(alertKey, next).catch(() => undefined)
        }
      } catch {
        try { next = JSON.parse(window.localStorage.getItem(alertKey) || "{}") } catch { /* Mantém a triagem vazia se o conteúdo local estiver inválido. */ }
      }
      if (cancelled) return
      loadedAlertKey.current = alertKey
      setAlertStatus(next)
    }
    void load()
    return () => { cancelled = true }
  }, [alertKey])

  useEffect(() => {
    if (loadedAlertKey.current !== alertKey) return
    void writeLocalRecord(alertKey, alertStatus).catch(() => {
      try { window.localStorage.setItem(alertKey, JSON.stringify(alertStatus)) } catch { /* A classificação segue valendo na sessão. */ }
    })
  }, [alertKey, alertStatus])

  const navigate = useCallback((next: ViewId) => { setView(next); setMobileOpen(false) }, [])

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const editing = target?.matches("input, textarea, select, [contenteditable='true']")
      if (event.key === "/" && !editing) {
        event.preventDefault()
        document.getElementById("investigation-search")?.focus()
      }
      if (event.altKey && event.key === "1") { event.preventDefault(); navigate("Dashboard") }
      if (event.altKey && event.key === "2") { event.preventDefault(); navigate("Packet Explorer") }
    }
    window.addEventListener("keydown", onShortcut)
    return () => window.removeEventListener("keydown", onShortcut)
  }, [navigate])

  const commitFilter = useCallback((next: InvestigationFilter) => {
    setFilter((current) => {
      if (JSON.stringify(current) === JSON.stringify(next)) return current
      setHistory((items) => [...items.slice(-19), current])
      return next
    })
  }, [])

  const investigate = useCallback((target: InvestigationTarget | Partial<InvestigationFilter>, destination: ViewId = "Packet Explorer") => {
    const next = "kind" in target ? applyTarget(filter, target) : { ...filter, ...target }
    commitFilter(next)
    setView(destination)
  }, [commitFilter, filter])

  const remove = useCallback((kind: FilterKind, value?: string | number) => commitFilter(removeFilterValue(filter, kind, value)), [commitFilter, filter])
  const clear = useCallback(() => commitFilter({ ...EMPTY_FILTER }), [commitFilter])
  const undo = useCallback(() => {
    setHistory((items) => {
      const previous = items.at(-1)
      if (previous) setFilter(previous)
      return items.slice(0, -1)
    })
  }, [])

  const chooseSuggestion = useCallback((item: SearchSuggestion) => {
    commitFilter(applyTarget({ ...filter, query: "" }, { kind: item.kind, value: item.value, replace: true }))
    setView(item.view)
  }, [commitFilter, filter])

  const setDisposition = useCallback((id: string, disposition: AlertDisposition) => setAlertStatus((current) => ({ ...current, [id]: disposition })), [])

  const addEvidence = useCallback((evidence: Omit<CaseEvidence, "id" | "capturedAt">) => {
    const next = appendEvidence(saved, activeCaseId, evidence)
    setSaved(next.cases)
    setActiveCaseId(next.activeId)
    setDrawerOpen(true)
  }, [activeCaseId, saved, setSaved])

  const suppressRule = useCallback((ruleId: string) => {
    if (options.suppressedRuleIds.includes(ruleId)) return
    onOptionsChange(withRuleSuppression(options, ruleId, true))
  }, [onOptionsChange, options])

  const activeCase = saved.find((item) => item.id === activeCaseId)

  const captureFacts = useMemo(() => [
    formatBytes(analysis.fileSize),
    `${formatNumber(analysis.packetCount)} pacotes`,
    formatDuration(analysis.duration),
    `parser ${analysis.metadata?.parserVersion || "1.x"}`,
  ], [analysis])

  return (
    <div className="shell">
      <a href="#conteudo" className="skip-link">Pular para o conteúdo</a>
      <aside className={`sidebar ${mobileOpen ? "is-open" : ""}`} id="workspace-nav">
        <div className="sidebar-head">
          <Brand />
          <button className="icon-button lg-hidden" onClick={() => setMobileOpen(false)} aria-label="Fechar navegação"><X className="size-4" /></button>
        </div>
        <nav className="sidebar-scroll" aria-label="Seções da análise">
          {navigation.map((section) => (
            <div key={section.group}>
              <h2 className="nav-group">{section.group}</h2>
              <ul className="space-y-0.5">
                {section.items.map((item) => (
                  <li key={item.label}>
                    <button onClick={() => navigate(item.label)} className="nav-item" aria-current={view === item.label ? "page" : undefined}>
                      <item.icon aria-hidden="true" />{navLabels[item.label]}
                      {item.label === "Security Insights" && analysis.alerts.length > 0 ? <span className="nav-count">{analysis.alerts.length}<span className="sr-only"> sinais</span></span> : null}
                      {item.label === "Compare" && comparison ? <span className="nav-dot" title="Comparação carregada" /> : null}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="sidebar-foot flex items-start gap-2 text-xs leading-relaxed text-[var(--text-muted)]"><LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-[var(--ok)]" aria-hidden="true" />Processamento local. Nenhum pacote foi enviado.</p>
      </aside>

      {mobileOpen && <button className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Fechar navegação" />}

      <div className="min-h-screen lg:pl-[240px]">
        <div className="workspace-header">
          <header className="topbar">
            <button className="icon-button lg-hidden" onClick={() => setMobileOpen(true)} aria-label="Abrir navegação" aria-expanded={mobileOpen} aria-controls="workspace-nav"><Menu className="size-4" /></button>
            <InvestigationSearch analysis={analysis} filter={filter} onQuery={(query) => setFilter((current) => ({ ...current, query }))} onSelect={chooseSuggestion} />
            <div className="ml-auto flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setDrawerOpen(true)} title={activeCase ? `Caso ativo: ${activeCase.name}` : "Abrir casos de investigação"}><Bookmark className="size-4" /><span className="hidden sm:inline">Casos</span>{activeCase ? <span className="nav-dot" aria-label="Há um caso ativo" /> : saved.length ? <span className="nav-count">{saved.length}</span> : null}</Button>
              <button className="icon-button" onClick={onTheme} aria-label={light ? "Usar tema escuro" : "Usar tema claro"}>{light ? <Moon className="size-4" /> : <Sun className="size-4" />}</button>
              <Button variant="outline" size="sm" onClick={onNewCapture}>Nova captura</Button>
            </div>
          </header>
          <p className="capture-bar">
            <span className="mono max-w-full truncate font-medium text-[var(--text)]" title={analysis.fileName}>{analysis.fileName}</span>
            {captureFacts.map((fact) => <span key={fact} className="num">{fact}</span>)}
            {activeCase && <span className="truncate text-[var(--accent)]" title={activeCase.name}>Caso: {activeCase.name}</span>}
          </p>
        </div>

        <main id="conteudo" tabIndex={-1} className="mx-auto max-w-[1600px] px-3 py-5 sm:px-5 sm:py-6">
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div className="min-w-0"><h1 className="text-[1.375rem] font-semibold tracking-[-0.02em] text-[var(--text)]">{title}</h1><p className="mt-1 text-sm text-[var(--text-muted)]">{description}</p></div>
            <div className="lg:hidden"><Select value={view} onValueChange={(value) => navigate(value as ViewId)}><SelectTrigger className="h-8 w-[200px] bg-[var(--surface)]" aria-label="Trocar de seção"><SelectValue /></SelectTrigger><SelectContent>{navigation.flatMap((section) => section.items).map((item) => <SelectItem key={item.label} value={item.label}>{navLabels[item.label]}</SelectItem>)}</SelectContent></Select></div>
          </div>

          {view !== "Settings" && view !== "Compare" && (
            <FilterToolbar
              analysis={analysis}
              filter={filter}
              onTarget={(target) => investigate(target, view === "Dashboard" ? "Packet Explorer" : view)}
              onRemove={remove}
              onSetProtocols={(protocols) => commitFilter({ ...filter, protocols })}
              onSetTime={(from, to) => commitFilter({ ...filter, from, to })}
              onClear={clear}
              onUndo={undo}
              canUndo={history.length > 0}
            />
          )}

          <div className={view !== "Settings" && view !== "Compare" ? "mt-4" : ""}>
            <Suspense fallback={<section className="panel grid min-h-48 place-items-center text-sm text-[var(--text-muted)]">Carregando visualização…</section>}>
              {view === "Dashboard" ? (
                <CaptureDashboard analysis={analysis} filter={filter} onNavigate={navigate} onInvestigate={investigate} />
              ) : (
                <AnalysisView
                view={view}
                analysis={analysis}
                sourceFile={sourceFile}
                comparison={comparison}
                comparisonProgress={comparisonProgress}
                comparisonError={comparisonError}
                onCompareCapture={onCompareCapture}
                onCancelComparison={onCancelComparison}
                filter={filter}
                onInvestigate={investigate}
                alertStatus={alertStatus}
                onAlertStatus={setDisposition}
                saved={saved}
                onAddEvidence={addEvidence}
                onSuppressRule={suppressRule}
                options={options}
                onOptionsChange={onOptionsChange}
                />
              )}
            </Suspense>
          </div>
        </main>
      </div>

      <InvestigationDrawer open={drawerOpen} onOpenChange={setDrawerOpen} analysis={analysis} filter={filter} saved={saved} setSaved={setSaved} activeCaseId={activeCaseId} onActiveCase={setActiveCaseId} onLoad={(next) => { commitFilter(next); setView("Packet Explorer") }} />
    </div>
  )
}
