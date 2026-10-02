"use client"

import { useMemo, useRef, useState } from "react"
import { ArrowDown, ArrowRight, ArrowUp, BookmarkPlus, Columns3, Filter, Info, LockKeyhole, Search } from "lucide-react"
import type { AlertDisposition, AnalyzerOptions, CaptureAnalysis, PacketRecord } from "@/lib/capture-types"
import type { ViewId } from "@/lib/views"
import type { CaseEvidence, InvestigationFilter, InvestigationHandler, SavedInvestigation } from "@/lib/investigation"
import { conversationMatchesFilter, packetMatchesFilter } from "@/lib/investigation"
import type { AnalysisState } from "@/components/packetlens-app"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { Address, PAGE_SIZE, Pager, ProtocolChip, TablePanel, usePage } from "@/components/data-display"
import { FlowCards, IncidentTimeline, NetworkMap, Reports, SecuritySettings, SecurityInsights, TrafficSummary } from "@/components/investigation-views"
import { CompareView } from "@/components/compare-view"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

type AnalysisViewProps = {
  view: ViewId
  analysis: CaptureAnalysis
  sourceFile: File | null
  comparison: CaptureAnalysis | null
  comparisonProgress: AnalysisState | null
  comparisonError?: string | null
  onCompareCapture: (file: File) => void
  onCancelComparison: () => void
  filter: InvestigationFilter
  onInvestigate: InvestigationHandler
  alertStatus: Record<string, AlertDisposition>
  onAlertStatus: (id: string, status: AlertDisposition) => void
  saved: SavedInvestigation[]
  onAddEvidence: (evidence: Omit<CaseEvidence, "id" | "capturedAt">) => void
  onSuppressRule: (ruleId: string) => void
  options: AnalyzerOptions
  onOptionsChange: (options: AnalyzerOptions) => void
}

export function AnalysisView(props: AnalysisViewProps) {
  const { view, analysis, filter, onInvestigate } = props
  switch (view) {
    case "Packet Explorer": return <PacketExplorer analysis={analysis} filter={filter} onInvestigate={onInvestigate} onAddEvidence={props.onAddEvidence} />
    case "Security Insights": return <SecurityInsights alerts={analysis.alerts} dispositions={props.alertStatus} onDisposition={props.onAlertStatus} onInvestigate={onInvestigate} onAddEvidence={props.onAddEvidence} onSuppressRule={props.onSuppressRule} />
    case "Timeline": return <IncidentTimeline analysis={analysis} onInvestigate={onInvestigate} />
    case "Network Map": return <NetworkMap analysis={analysis} onInvestigate={onInvestigate} />
    case "Reports": return <Reports analysis={analysis} sourceFile={props.sourceFile} filter={filter} saved={props.saved} />
    case "Settings": return <SecuritySettings analysis={analysis} options={props.options} onOptionsChange={props.onOptionsChange} />
    case "Compare": return <CompareView primary={analysis} secondary={props.comparison} progress={props.comparisonProgress} error={props.comparisonError} onSelect={props.onCompareCapture} onCancel={props.onCancelComparison} />
    case "Traffic": return <TrafficSummary analysis={analysis} />
    case "Network Flows": return <FlowCards analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
    case "HTTP":
    case "TLS": return <ApplicationPackets analysis={analysis} type={view} filter={filter} onInvestigate={onInvestigate} />
    case "Hosts": return <HostsTable analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
    case "Conversations": return <ConversationsTable analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
    case "DNS": return <DnsTable analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
    case "Ports": return <PortsTable analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
    case "Dashboard":
    case "Protocols": return <ProtocolsTable analysis={analysis} filter={filter} onInvestigate={onInvestigate} />
  }
}

function HostsTable({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => {
    const needle = filter.query.toLowerCase()
    const constrained = new Set(analysis.conversations.filter((row) => conversationMatchesFilter(row, filter, analysis.firstEpoch)).flatMap((row) => [row.source, row.destination]))
    const relationalFilter = filter.protocols.length || filter.ports.length || filter.from !== undefined || filter.to !== undefined
    return analysis.hosts.filter((row) => {
      if (needle && !`${row.ip} ${row.hostname || ""} ${row.mac || ""} ${row.vendor || ""} ${row.scope || ""}`.toLowerCase().includes(needle)) return false
      if (filter.addresses.length && !filter.addresses.includes(row.ip)) return false
      if (relationalFilter && !constrained.has(row.ip)) return false
      return true
    })
  }, [analysis, filter])
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel title="Hosts identificados" paging={paging}>
      <Table><TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Contexto local</TableHead><TableHead className="col-num">Enviados</TableHead><TableHead className="col-num">Recebidos</TableHead><TableHead className="col-num">Tráfego</TableHead><TableHead className="col-num">Conexões</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={row.ip}>
          <TableCell><span className="block min-w-0"><span className="cell-primary truncate" title={row.ip}>{row.ip}</span><span className="cell-secondary truncate">{row.hostname || "Hostname não identificado"}</span></span></TableCell>
          <TableCell><span className="cell-primary">{row.scope || "—"}</span><span className="cell-secondary mono">{row.vendor || row.mac || "Sem fabricante identificado"}</span></TableCell>
          <TableCell className="col-num"><Directional direction="up" packets={row.sentPackets} bytes={row.sentBytes} /></TableCell>
          <TableCell className="col-num"><Directional direction="down" packets={row.receivedPackets} bytes={row.receivedBytes} /></TableCell>
          <TableCell className="col-num">{formatBytes(row.sentBytes + row.receivedBytes)}</TableCell><TableCell className="col-num">{formatNumber(row.connections)}</TableCell>
          <TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ kind: "address", value: row.ip, replace: true })}><Filter className="size-3.5" /> Ver</Button></TableCell>
        </TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

function ConversationsTable({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.conversations.filter((row) => conversationMatchesFilter(row, filter, analysis.firstEpoch)), [analysis, filter])
  const { visible, paging } = usePage(rows)
  return (
    <TablePanel title="Conversações" paging={paging}>
      <Table><TableHeader><TableRow><TableHead>Origem</TableHead><TableHead>Destino</TableHead><TableHead>Transporte / aplicação</TableHead><TableHead className="col-num">Pacotes</TableHead><TableHead className="col-num">Volume</TableHead><TableHead className="col-num">Início</TableHead><TableHead className="col-num">Duração</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={row.id}><TableCell><Address ip={row.source} port={row.sourcePort} /></TableCell><TableCell><Address ip={row.destination} port={row.destinationPort} /></TableCell><TableCell><ProtocolChip value={row.application || row.protocol} /><span className="cell-secondary">{row.application ? row.protocol : ""}</span></TableCell><TableCell className="col-num">{formatNumber(row.packets)}</TableCell><TableCell className="col-num">{formatBytes(row.bytes)}</TableCell><TableCell className="col-num text-[var(--text-muted)]">{row.start}</TableCell><TableCell className="col-num">{formatDuration(row.duration)}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ addresses: [row.source, row.destination], ports: [row.sourcePort, row.destinationPort].filter(Boolean), protocols: [row.application || row.protocol] })}><Filter className="size-3.5" /> Ver</Button></TableCell></TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

function DnsTable({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.dns.filter((row) => {
    const needle = filter.query.toLowerCase()
    if (needle && !`${row.domain} ${row.source} ${row.answer} ${row.status} ${row.queryType || ""}`.toLowerCase().includes(needle)) return false
    if (filter.addresses.length && !filter.addresses.includes(row.source)) return false
    if (filter.domains.length && !filter.domains.some((domain) => row.domain.includes(domain))) return false
    if (filter.protocols.length && !filter.protocols.some((protocol) => protocol === "DNS" || protocol === "mDNS")) return false
    return true
  }), [analysis.dns, filter])
  const { visible, paging } = usePage(rows)
  return (
    <TablePanel title="Análise DNS" paging={paging}>
      <Table><TableHeader><TableRow><TableHead>Domínio / tipo</TableHead><TableHead>Origem</TableHead><TableHead>Respostas</TableHead><TableHead className="col-num">Consultas</TableHead><TableHead>Status</TableHead><TableHead className="col-num">Latência média</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={`${row.domain}-${row.source}`}><TableCell><span className="cell-primary truncate" title={row.domain}>{row.domain}</span><span className="cell-secondary">{row.queryType || "Tipo não identificado"}</span></TableCell><TableCell className="mono text-[13px]">{row.source}</TableCell><TableCell><span className="cell-truncate mono" title={row.answer}>{row.answer}</span></TableCell><TableCell className="col-num">{formatNumber(row.queries)}</TableCell><TableCell><span className={row.status === "NOERROR" ? "state state-ok" : "state state-warn"}>{row.status}</span></TableCell><TableCell className="col-num">{row.responseTime ? `${row.responseTime} ms` : "—"}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ kind: "domain", value: row.domain, replace: true })}><Filter className="size-3.5" /> Ver</Button></TableCell></TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

function PortsTable({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.ports.filter((row) => {
    if (filter.query && !`${row.port} ${row.protocol} ${row.service}`.toLowerCase().includes(filter.query.toLowerCase())) return false
    if (filter.ports.length && !filter.ports.includes(row.port)) return false
    if (filter.protocols.length && !filter.protocols.includes(row.protocol)) return false
    return true
  }), [analysis.ports, filter])
  const { visible, paging } = usePage(rows)
  return (
    <TablePanel title="Portas" paging={paging} advisory={<p className="advisory advisory-note"><Info aria-hidden="true" />O serviço é uma indicação baseada na porta. Confirme pelo conteúdo e pelo comportamento do fluxo.</p>}>
      <Table><TableHeader><TableRow><TableHead className="col-num">Porta</TableHead><TableHead>Transporte</TableHead><TableHead>Serviço provável</TableHead><TableHead className="col-num">Ocorrências</TableHead><TableHead className="col-num">Hosts</TableHead><TableHead className="col-num">Volume</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={`${row.port}-${row.protocol}`}><TableCell className="col-num font-semibold">{row.port}</TableCell><TableCell><ProtocolChip value={row.protocol} /></TableCell><TableCell>{row.service}</TableCell><TableCell className="col-num">{formatNumber(row.connections)}</TableCell><TableCell className="col-num">{formatNumber(row.hosts)}</TableCell><TableCell className="col-num">{formatBytes(row.bytes)}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ kind: "port", value: row.port, replace: true })}><Filter className="size-3.5" /> Ver</Button></TableCell></TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

function ProtocolsTable({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.protocols.filter((row) => (!filter.query || row.name.toLowerCase().includes(filter.query.toLowerCase())) && (!filter.protocols.length || filter.protocols.includes(row.name))), [analysis.protocols, filter])
  const { visible, paging } = usePage(rows)
  const total = Math.max(1, analysis.protocols.reduce((sum, row) => sum + row.packets, 0))
  return (
    <TablePanel title="Protocolos" paging={paging}>
      <Table><TableHeader><TableRow><TableHead>Protocolo</TableHead><TableHead>Participação</TableHead><TableHead className="col-num">Pacotes</TableHead><TableHead className="col-num">Volume</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={row.name}><TableCell><span className="flex items-center gap-2 font-medium"><i className="dist-swatch" style={{ background: row.color }} aria-hidden="true" />{row.name}</span></TableCell><TableCell><span className="flex items-center gap-3"><span className="dist-track h-[3px] w-28 shrink-0"><i className="dist-fill" style={{ width: `${(row.packets / total) * 100}%`, background: row.color }} /></span><span className="num mono text-[13px] text-[var(--text-muted)]">{Math.round((row.packets / total) * 100)}%</span></span></TableCell><TableCell className="col-num">{formatNumber(row.packets)}</TableCell><TableCell className="col-num">{formatBytes(row.bytes)}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ kind: "protocol", value: row.name, replace: true })}><Filter className="size-3.5" /> Ver</Button></TableCell></TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

function ApplicationPackets({ analysis, type, filter, onInvestigate }: { analysis: CaptureAnalysis; type: "HTTP" | "TLS"; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.packets.filter((row) => row.protocol === type && packetMatchesFilter(row, filter)), [analysis.packets, filter, type])
  const { visible, paging } = usePage(rows)
  return (
    <TablePanel title={`Análise ${type}`} paging={paging} emptyTitle={`Nenhum pacote ${type} nos pacotes retidos`} emptyHint="A captura pode não conter esse protocolo, ou ele pode estar fora da amostra retida." advisory={type === "TLS" ? <p className="advisory advisory-ok"><LockKeyhole aria-hidden="true" />O PacketLens não descriptografa TLS. Somente metadados observáveis de handshake e volume são exibidos.</p> : undefined}>
      <Table><TableHeader><TableRow><TableHead>Origem</TableHead><TableHead>Destino</TableHead>{type === "TLS" ? <><TableHead>SNI</TableHead><TableHead>Versão / ALPN</TableHead></> : <><TableHead>Método / status</TableHead><TableHead>Host / caminho</TableHead></>}<TableHead className="col-num">Horário</TableHead><TableHead className="col-num">Tamanho</TableHead><TableHead className="w-20"><span className="sr-only">Ações</span></TableHead></TableRow></TableHeader>
        <TableBody>{visible.map((row) => <TableRow key={row.no}><TableCell><Address ip={row.source} port={row.sourcePort} /></TableCell><TableCell><Address ip={row.destination} port={row.destinationPort} /></TableCell>{type === "TLS" ? <><TableCell className="mono text-[13px]">{row.tls?.serverName || "—"}</TableCell><TableCell>{row.tls?.version || "—"}<span className="cell-secondary">{row.tls?.alpn?.join(", ") || row.tls?.handshake || ""}</span></TableCell></> : <><TableCell>{row.http?.method || (row.http?.status ? String(row.http.status) : "—")}</TableCell><TableCell><span className="cell-primary">{row.http?.host || "—"}</span><span className="cell-secondary mono">{row.http?.path || row.http?.contentType || ""}</span></TableCell></>}<TableCell className="col-num">{row.timestamp}</TableCell><TableCell className="col-num">{formatBytes(row.length)}</TableCell><TableCell><Button variant="ghost" size="sm" onClick={() => onInvestigate({ addresses: [row.source, row.destination], protocols: [type], domains: [row.tls?.serverName || row.http?.host || ""].filter(Boolean) })}><Filter className="size-3.5" /> Ver</Button></TableCell></TableRow>)}</TableBody>
      </Table>
    </TablePanel>
  )
}

type ColumnKey = "no" | "timestamp" | "source" | "destination" | "protocol" | "bytes" | "info"
const allColumns: Array<{ key: ColumnKey; label: string }> = [
  { key: "no", label: "No." }, { key: "timestamp", label: "Timestamp" }, { key: "source", label: "Origem" }, { key: "destination", label: "Destino" }, { key: "protocol", label: "Protocolo" }, { key: "bytes", label: "Bytes" }, { key: "info", label: "Info" },
]

function PacketExplorer({ analysis, filter, onInvestigate, onAddEvidence }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler; onAddEvidence: (evidence: Omit<CaseEvidence, "id" | "capturedAt">) => void }) {
  const [localQuery, setLocalQuery] = useState("")
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<PacketRecord | null>(null)
  const [columns, setColumns] = useState<ColumnKey[]>(allColumns.map((item) => item.key))
  const lastRow = useRef<HTMLTableRowElement | null>(null)
  const rows = useMemo(() => analysis.packets.filter((row) => packetMatchesFilter(row, filter, localQuery)), [analysis.packets, filter, localQuery])
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const current = Math.min(page, pages)
  const start = (current - 1) * PAGE_SIZE
  const visible = rows.slice(start, start + PAGE_SIZE)
  const shown = (key: ColumnKey) => columns.includes(key)
  const toggleColumn = (key: ColumnKey) => setColumns((items) => items.includes(key) ? items.filter((item) => item !== key) : [...items, key])
  const open = (row: PacketRecord, element: HTMLTableRowElement) => { lastRow.current = element; setSelected(row) }

  return (
    <>
      <section className="panel overflow-hidden" aria-labelledby="panel-packets">
        <div className="panel-head">
           <div><h2 id="panel-packets" className="sr-only">Pacotes retidos</h2><p className="text-sm font-medium text-[var(--text)]">{rows.length === analysis.packets.length ? `${formatNumber(analysis.packets.length)} pacotes retidos` : `${formatNumber(rows.length)} de ${formatNumber(analysis.packets.length)} pacotes retidos`}</p>{analysis.truncatedPackets && <p className="panel-sub">Amostra distribuída de até {formatNumber(analysis.metadata?.packetLimit || analysis.packets.length)} pacotes; agregações cobrem a captura inteira. Filtros e exportações de pacotes usam apenas esta amostra e podem não incluir todos os pacotes de um sinal.</p>}</div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative"><Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-faint)]" aria-hidden="true" /><Input type="search" value={localQuery} onChange={(event) => { setLocalQuery(event.target.value); setPage(1) }} aria-label="Refinar dentro dos pacotes" placeholder="Refinar neste recorte" className="h-8 w-52 bg-[var(--surface-raised)] pl-8 text-sm" /></div>
            <details className="column-picker"><summary><Columns3 aria-hidden="true" /> Colunas</summary><div>{allColumns.map((column) => <label key={column.key}><input type="checkbox" checked={shown(column.key)} onChange={() => toggleColumn(column.key)} />{column.label}</label>)}</div></details>
          </div>
        </div>

        {rows.length === 0 ? <div className="empty-state"><Search aria-hidden="true" /><strong>Nenhum pacote retido corresponde ao filtro</strong><span>{analysis.truncatedPackets ? "O sinal pode estar fora da amostra. Revise o resumo da captura ou aumente o limite de retenção e reanalise o arquivo." : "Remova filtros ou reduza os termos da pesquisa."}</span></div> : (
          <div className="table-scroll max-h-[max(55vh,calc(100vh-21rem))]"><Table><TableHeader className="sticky top-0 z-10"><TableRow>{shown("no") && <TableHead className="col-num">No.</TableHead>}{shown("timestamp") && <TableHead>Timestamp</TableHead>}{shown("source") && <TableHead>Origem</TableHead>}{shown("destination") && <TableHead>Destino</TableHead>}{shown("protocol") && <TableHead>Protocolo</TableHead>}{shown("bytes") && <TableHead className="col-num">Bytes</TableHead>}{shown("info") && <TableHead>Info</TableHead>}</TableRow></TableHeader><TableBody>
            {visible.map((row) => <TableRow key={row.no} className="row-link" tabIndex={0} role="button" aria-label={`Detalhes do pacote ${row.no}`} data-selected={selected?.no === row.no ? "true" : undefined} onClick={(event) => open(row, event.currentTarget)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(row, event.currentTarget) } }}>{shown("no") && <TableCell className="col-num text-[var(--text-muted)]">{row.no}</TableCell>}{shown("timestamp") && <TableCell className="mono num text-[13px]">{row.timestamp}</TableCell>}{shown("source") && <TableCell className="mono text-[13px]">{row.source}</TableCell>}{shown("destination") && <TableCell className="mono text-[13px]">{row.destination}</TableCell>}{shown("protocol") && <TableCell><ProtocolChip value={row.protocol} />{row.retransmission && <span className="cell-secondary">Retransmissão</span>}</TableCell>}{shown("bytes") && <TableCell className="col-num">{formatNumber(row.length)}</TableCell>}{shown("info") && <TableCell><span className="cell-truncate" title={row.info}>{row.info}</span></TableCell>}</TableRow>)}
          </TableBody></Table></div>
        )}
        {rows.length > 0 && <p className="table-foot"><Pager paging={{ page: current, pages, start, shown: visible.length, total: rows.length, setPage }} label="pacotes" /></p>}
      </section>

      <Sheet open={!!selected} onOpenChange={(isOpen) => { if (!isOpen) { setSelected(null); lastRow.current?.focus() } }}>
        <SheetContent className="w-full gap-0 p-0 data-[state=closed]:duration-150 data-[state=open]:duration-200 sm:max-w-xl">
          <SheetHeader className="border-b border-[var(--line)] p-4"><SheetTitle className="text-[15px] font-semibold">Pacote {selected?.no}</SheetTitle><SheetDescription className="num mono text-[13px]">{selected?.timestamp} · {selected ? formatNumber(selected.length) : 0} bytes · {selected?.protocol}</SheetDescription></SheetHeader>
          <div className="overflow-y-auto p-4">
            <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-raised)] p-3"><Address ip={selected?.source || ""} port={selected?.sourcePort} /><ArrowRight className="size-4 text-[var(--text-faint)]" aria-hidden="true" /><Address ip={selected?.destination || ""} port={selected?.destinationPort} /></div>
            {selected && <div className="mt-3 flex flex-wrap gap-2"><Button size="sm" onClick={() => onAddEvidence({ type: "packet", reference: `packet:${selected.no}`, title: `Pacote ${selected.no} · ${selected.protocol}`, detail: `${selected.source}:${selected.sourcePort || 0} → ${selected.destination}:${selected.destinationPort || 0} · ${selected.info}` })}><BookmarkPlus className="size-4" /> Adicionar ao caso</Button><Button variant="outline" size="sm" onClick={() => { onInvestigate({ kind: "address", value: selected.source, replace: true }); setSelected(null) }}>Filtrar origem</Button><Button variant="outline" size="sm" onClick={() => { onInvestigate({ kind: "address", value: selected.destination, replace: true }); setSelected(null) }}>Filtrar destino</Button><Button variant="outline" size="sm" onClick={() => { onInvestigate({ kind: "protocol", value: selected.protocol, replace: true }); setSelected(null) }}>Mesmo protocolo</Button></div>}
            <Accordion type="multiple" defaultValue={["layer-0", "layer-1"]} className="mt-2">{selected?.layers.map((layer, index) => <AccordionItem key={`${layer.name}-${index}`} value={`layer-${index}`} className="border-[var(--line)]"><AccordionTrigger className="py-3 text-sm font-medium hover:no-underline">{layer.name}</AccordionTrigger><AccordionContent><dl className="kv pb-2">{layer.fields.map(([name, value]) => <div key={`${name}-${value}`} className="contents"><dt>{name}</dt><dd>{value}</dd></div>)}</dl></AccordionContent></AccordionItem>)}</Accordion>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}

function Directional({ direction, packets, bytes }: { direction: "up" | "down"; packets: number; bytes: number }) {
  const Icon = direction === "up" ? ArrowUp : ArrowDown
  return <span className="inline-flex items-center justify-end gap-1.5"><Icon className="size-3 text-[var(--text-faint)]" aria-hidden="true" /><span className="text-right"><span className="block">{formatNumber(packets)}</span><span className="cell-secondary">{formatBytes(bytes)}</span></span></span>
}
