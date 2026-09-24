"use client"

import { useMemo, useRef, useState } from "react"
import { ArrowDown, ArrowRight, ArrowUp, Info, LockKeyhole, Search } from "lucide-react"
import type { CaptureAnalysis, PacketRecord } from "@/lib/capture-types"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { Address, PAGE_SIZE, Pager, ProtocolChip, TablePanel, usePage } from "@/components/data-display"
import { FlowCards, IncidentTimeline, NetworkMap, Reports, SecuritySettings, SecurityInsights, TrafficSummary } from "@/components/investigation-views"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export function AnalysisView({ view, analysis, query, protocol, setProtocol, onInvestigate }: { view: string; analysis: CaptureAnalysis; query: string; protocol: string; setProtocol: (value: string) => void; onInvestigate: (term: string) => void }) {
  if (view === "Packet Explorer") return <PacketExplorer analysis={analysis} globalQuery={query} initialProtocol={protocol} setProtocol={setProtocol} />
  if (view === "Security Insights") return <SecurityInsights alerts={analysis.alerts} onInvestigate={onInvestigate} />
  if (view === "Timeline") return <IncidentTimeline analysis={analysis} />
  if (view === "Network Map") return <NetworkMap analysis={analysis} onInvestigate={onInvestigate} />
  if (view === "Reports") return <Reports analysis={analysis} />
  if (view === "Settings") return <SecuritySettings />
  if (view === "Traffic") return <TrafficSummary analysis={analysis} />
  if (view === "Network Flows") return <FlowCards analysis={analysis} query={query} />
  if (view === "HTTP" || view === "TLS") return <ApplicationPackets analysis={analysis} type={view} query={query} />
  if (view === "Hosts") return <HostsTable analysis={analysis} query={query} />
  if (view === "Conversations") return <ConversationsTable analysis={analysis} query={query} protocol={protocol} />
  if (view === "DNS") return <DnsTable analysis={analysis} query={query} />
  if (view === "Ports") return <PortsTable analysis={analysis} query={query} />
  return <ProtocolsTable analysis={analysis} query={query} />
}

function HostsTable({ analysis, query }: { analysis: CaptureAnalysis; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(() => analysis.hosts.filter((row) => `${row.ip} ${row.hostname || ""}`.toLowerCase().includes(needle)), [analysis.hosts, needle])
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel title="Hosts identificados" paging={paging}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Host</TableHead>
            <TableHead scope="col" className="col-num">Enviados</TableHead>
            <TableHead scope="col" className="col-num">Recebidos</TableHead>
            <TableHead scope="col" className="col-num">Tráfego</TableHead>
            <TableHead scope="col" className="col-num">Conexões</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={row.ip}>
              <TableCell>
                <span className="block min-w-0">
                  <span className="cell-primary truncate" title={row.ip}>{row.ip}</span>
                  <span className="cell-secondary truncate">{row.hostname || "Hostname não identificado"}</span>
                </span>
              </TableCell>
              <TableCell className="col-num"><Directional direction="up" packets={row.sentPackets} bytes={row.sentBytes} /></TableCell>
              <TableCell className="col-num"><Directional direction="down" packets={row.receivedPackets} bytes={row.receivedBytes} /></TableCell>
              <TableCell className="col-num">{formatBytes(row.sentBytes + row.receivedBytes)}</TableCell>
              <TableCell className="col-num">{formatNumber(row.connections)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function ConversationsTable({ analysis, query, protocol }: { analysis: CaptureAnalysis; query: string; protocol: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(
    () => analysis.conversations.filter((row) => (!protocol || row.protocol === protocol || protocol === "Todos") && `${row.source} ${row.destination} ${row.protocol} ${row.sourcePort} ${row.destinationPort}`.toLowerCase().includes(needle)),
    [analysis.conversations, needle, protocol],
  )
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel title="Conversations" paging={paging}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Origem</TableHead>
            <TableHead scope="col">Destino</TableHead>
            <TableHead scope="col">Protocolo</TableHead>
            <TableHead scope="col" className="col-num">Pacotes</TableHead>
            <TableHead scope="col" className="col-num">Volume</TableHead>
            <TableHead scope="col" className="col-num">Início</TableHead>
            <TableHead scope="col" className="col-num">Duração</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={row.id}>
              <TableCell><Address ip={row.source} port={row.sourcePort} /></TableCell>
              <TableCell><Address ip={row.destination} port={row.destinationPort} /></TableCell>
              <TableCell><ProtocolChip value={row.protocol} /></TableCell>
              <TableCell className="col-num">{formatNumber(row.packets)}</TableCell>
              <TableCell className="col-num">{formatBytes(row.bytes)}</TableCell>
              <TableCell className="col-num text-[var(--text-muted)]">{row.start}</TableCell>
              <TableCell className="col-num">{formatDuration(row.duration)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function DnsTable({ analysis, query }: { analysis: CaptureAnalysis; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(() => analysis.dns.filter((row) => `${row.domain} ${row.source} ${row.answer} ${row.status}`.toLowerCase().includes(needle)), [analysis.dns, needle])
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel title="DNS Analysis" paging={paging}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Domínio consultado</TableHead>
            <TableHead scope="col">Origem</TableHead>
            <TableHead scope="col">Resposta</TableHead>
            <TableHead scope="col" className="col-num">Consultas</TableHead>
            <TableHead scope="col">Status</TableHead>
            <TableHead scope="col" className="col-num">Tempo médio</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={`${row.domain}-${row.source}`}>
              <TableCell><span className="cell-primary truncate" title={row.domain}>{row.domain}</span></TableCell>
              <TableCell className="mono text-[13px]">{row.source}</TableCell>
              <TableCell className="mono text-[13px]">{row.answer}</TableCell>
              <TableCell className="col-num">{formatNumber(row.queries)}</TableCell>
              <TableCell><span className={row.status === "NOERROR" ? "state state-ok" : "state state-warn"}>{row.status}</span></TableCell>
              <TableCell className="col-num">{row.responseTime ? `${row.responseTime} ms` : "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function PortsTable({ analysis, query }: { analysis: CaptureAnalysis; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(() => analysis.ports.filter((row) => `${row.port} ${row.protocol} ${row.service}`.toLowerCase().includes(needle)), [analysis.ports, needle])
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel
      title="Ports"
      paging={paging}
      advisory={
        <p className="advisory advisory-note">
          <Info aria-hidden="true" />
          O serviço é uma indicação baseada no número da porta. Confirme pelo conteúdo e pelo comportamento do fluxo.
        </p>
      }
    >
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col" className="col-num">Porta</TableHead>
            <TableHead scope="col">Transporte</TableHead>
            <TableHead scope="col">Serviço provável</TableHead>
            <TableHead scope="col" className="col-num">Conexões</TableHead>
            <TableHead scope="col" className="col-num">Hosts</TableHead>
            <TableHead scope="col" className="col-num">Volume</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={`${row.port}-${row.protocol}`}>
              <TableCell className="col-num font-semibold">{row.port}</TableCell>
              <TableCell><ProtocolChip value={row.protocol} /></TableCell>
              <TableCell>{row.service}</TableCell>
              <TableCell className="col-num">{formatNumber(row.connections)}</TableCell>
              <TableCell className="col-num">{formatNumber(row.hosts)}</TableCell>
              <TableCell className="col-num">{formatBytes(row.bytes)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function ProtocolsTable({ analysis, query }: { analysis: CaptureAnalysis; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(() => analysis.protocols.filter((row) => row.name.toLowerCase().includes(needle)), [analysis.protocols, needle])
  const { visible, paging } = usePage(rows)
  const total = Math.max(1, analysis.protocols.reduce((sum, row) => sum + row.packets, 0))

  return (
    <TablePanel title="Protocolos" paging={paging}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Protocolo</TableHead>
            <TableHead scope="col">Participação</TableHead>
            <TableHead scope="col" className="col-num">Pacotes</TableHead>
            <TableHead scope="col" className="col-num">Volume</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={row.name}>
              <TableCell>
                <span className="flex items-center gap-2 font-medium">
                  <i className="dist-swatch" style={{ background: row.color }} aria-hidden="true" />
                  {row.name}
                </span>
              </TableCell>
              <TableCell>
                <span className="flex items-center gap-3">
                  <span className="dist-track h-[3px] w-28 shrink-0">
                    <i className="dist-fill" style={{ width: `${(row.packets / total) * 100}%`, background: row.color }} />
                  </span>
                  <span className="num mono text-[13px] text-[var(--text-muted)]">{Math.round((row.packets / total) * 100)}%</span>
                </span>
              </TableCell>
              <TableCell className="col-num">{formatNumber(row.packets)}</TableCell>
              <TableCell className="col-num">{formatBytes(row.bytes)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function ApplicationPackets({ analysis, type, query }: { analysis: CaptureAnalysis; type: string; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(
    () => analysis.packets.filter((row) => row.protocol === type && `${row.source} ${row.destination} ${row.info}`.toLowerCase().includes(needle)),
    [analysis.packets, needle, type],
  )
  const { visible, paging } = usePage(rows)

  return (
    <TablePanel
      title={`${type} Analysis`}
      paging={paging}
      emptyTitle={`Nenhum pacote ${type} nos pacotes retidos`}
      emptyHint="A captura pode não conter esse protocolo, ou ele pode estar fora da amostra retida para inspeção."
      advisory={
        type === "TLS" ? (
          <p className="advisory advisory-ok">
            <LockKeyhole aria-hidden="true" />
            O PacketLens não tenta descriptografar TLS. Apenas metadados de handshake e volume são exibidos.
          </p>
        ) : undefined
      }
    >
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Origem</TableHead>
            <TableHead scope="col">Destino</TableHead>
            <TableHead scope="col">Resumo</TableHead>
            <TableHead scope="col" className="col-num">Horário</TableHead>
            <TableHead scope="col" className="col-num">Tamanho</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((row) => (
            <TableRow key={row.no}>
              <TableCell><Address ip={row.source} port={row.sourcePort} /></TableCell>
              <TableCell><Address ip={row.destination} port={row.destinationPort} /></TableCell>
              <TableCell><span className="cell-truncate" title={row.info}>{row.info}</span></TableCell>
              <TableCell className="col-num">{row.timestamp}</TableCell>
              <TableCell className="col-num">{formatBytes(row.length)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TablePanel>
  )
}

function PacketExplorer({ analysis, globalQuery, initialProtocol, setProtocol }: { analysis: CaptureAnalysis; globalQuery: string; initialProtocol: string; setProtocol: (value: string) => void }) {
  const [localQuery, setLocalQuery] = useState("")
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<PacketRecord | null>(null)
  // The sheet is opened from a row rather than a trigger, so focus has to be
  // handed back to that row explicitly when it closes.
  const lastRow = useRef<HTMLTableRowElement | null>(null)
  const needle = `${globalQuery} ${localQuery}`.trim().toLowerCase()

  const rows = useMemo(
    () => analysis.packets.filter((row) => (initialProtocol === "Todos" || !initialProtocol || row.protocol === initialProtocol) && `${row.no} ${row.source} ${row.destination} ${row.protocol} ${row.sourcePort || ""} ${row.destinationPort || ""} ${row.info}`.toLowerCase().includes(needle)),
    [analysis.packets, initialProtocol, needle],
  )

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const current = Math.min(page, pages)
  const start = (current - 1) * PAGE_SIZE
  const visible = rows.slice(start, start + PAGE_SIZE)

  const open = (row: PacketRecord, element: HTMLTableRowElement) => {
    lastRow.current = element
    setSelected(row)
  }

  return (
    <>
      <section className="panel overflow-hidden">
        <div className="panel-head">
          <div>
            <h2 className="sr-only">Pacotes retidos</h2>
            <p className="text-sm font-medium text-[var(--text)]">
              {rows.length === analysis.packets.length
                ? `${formatNumber(analysis.packets.length)} pacotes retidos`
                : `${formatNumber(rows.length)} de ${formatNumber(analysis.packets.length)} pacotes retidos`}
            </p>
            {analysis.truncatedPackets && (
              <p className="panel-sub">Amostra dos 10.000 primeiros pacotes; as estatísticas cobrem a captura inteira</p>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-faint)]" aria-hidden="true" />
              <Input
                type="search"
                value={localQuery}
                onChange={(event) => { setLocalQuery(event.target.value); setPage(1) }}
                aria-label="Refinar dentro dos pacotes"
                placeholder="IP, porta, domínio"
                className="h-8 w-52 bg-[var(--surface-raised)] pl-8 text-sm"
              />
            </div>
            <Select value={initialProtocol || "Todos"} onValueChange={(value) => { setProtocol(value); setPage(1) }}>
              <SelectTrigger className="h-8 w-36 bg-[var(--surface-raised)]" aria-label="Filtrar por protocolo">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["Todos", ...analysis.protocols.map((item) => item.name)].map((item) => (
                  <SelectItem key={item} value={item}>{item}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {rows.length === 0 ? (
          <div className="empty-state">
            <Search aria-hidden="true" />
            <strong>Nenhum pacote corresponde ao filtro</strong>
            <span>Remova o protocolo selecionado ou reduza os termos da pesquisa.</span>
          </div>
        ) : (
          <div className="table-scroll max-h-[calc(100vh-19rem)]">
            <Table>
              <TableHeader className="sticky top-0 z-10">
                <TableRow>
                  <TableHead scope="col" className="col-num">No.</TableHead>
                  <TableHead scope="col">Timestamp</TableHead>
                  <TableHead scope="col">Origem</TableHead>
                  <TableHead scope="col">Destino</TableHead>
                  <TableHead scope="col">Protocolo</TableHead>
                  <TableHead scope="col" className="col-num">Bytes</TableHead>
                  <TableHead scope="col">Info</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((row) => (
                  <TableRow
                    key={row.no}
                    className="row-link"
                    tabIndex={0}
                    role="button"
                    aria-label={`Detalhes do pacote ${row.no}`}
                    data-selected={selected?.no === row.no ? "true" : undefined}
                    onClick={(event) => open(row, event.currentTarget)}
                    onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(row, event.currentTarget) } }}
                  >
                    <TableCell className="col-num text-[var(--text-muted)]">{row.no}</TableCell>
                    <TableCell className="mono num text-[13px]">{row.timestamp}</TableCell>
                    <TableCell className="mono text-[13px]">{row.source}</TableCell>
                    <TableCell className="mono text-[13px]">{row.destination}</TableCell>
                    <TableCell><ProtocolChip value={row.protocol} /></TableCell>
                    <TableCell className="col-num">{formatNumber(row.length)}</TableCell>
                    <TableCell><span className="cell-truncate" title={row.info}>{row.info}</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {rows.length > 0 && (
          <p className="table-foot">
            <Pager paging={{ page: current, pages, start, shown: visible.length, total: rows.length, setPage }} label="pacotes" />
          </p>
        )}
      </section>

      <Sheet
        open={!!selected}
        onOpenChange={(isOpen) => {
          if (!isOpen) {
            setSelected(null)
            lastRow.current?.focus()
          }
        }}
      >
        <SheetContent className="w-full gap-0 p-0 data-[state=closed]:duration-150 data-[state=open]:duration-200 sm:max-w-xl">
          <SheetHeader className="border-b border-[var(--line)] p-4">
            <SheetTitle className="text-[15px] font-semibold">Pacote {selected?.no}</SheetTitle>
            <SheetDescription className="num mono text-[13px]">
              {selected?.timestamp} · {selected ? formatNumber(selected.length) : 0} bytes · {selected?.protocol}
            </SheetDescription>
          </SheetHeader>
          <div className="overflow-y-auto p-4">
            <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-raised)] p-3">
              <Address ip={selected?.source || ""} port={selected?.sourcePort} />
              <ArrowRight className="size-4 text-[var(--text-faint)]" aria-hidden="true" />
              <Address ip={selected?.destination || ""} port={selected?.destinationPort} />
            </div>
            <Accordion type="multiple" defaultValue={["layer-0", "layer-1"]} className="mt-2">
              {selected?.layers.map((layer, index) => (
                <AccordionItem key={`${layer.name}-${index}`} value={`layer-${index}`} className="border-[var(--line)]">
                  <AccordionTrigger className="py-3 text-sm font-medium hover:no-underline">{layer.name}</AccordionTrigger>
                  <AccordionContent>
                    <dl className="kv pb-2">
                      {layer.fields.map(([name, value]) => (
                        <div key={`${name}-${value}`} className="contents">
                          <dt>{name}</dt>
                          <dd>{value}</dd>
                        </div>
                      ))}
                    </dl>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}

function Directional({ direction, packets, bytes }: { direction: "up" | "down"; packets: number; bytes: number }) {
  const Icon = direction === "up" ? ArrowUp : ArrowDown
  return (
    <span className="inline-flex items-center justify-end gap-1.5">
      <Icon className="size-3 text-[var(--text-faint)]" aria-hidden="true" />
      <span className="text-right">
        <span className="block">{formatNumber(packets)}</span>
        <span className="cell-secondary">{formatBytes(bytes)}</span>
      </span>
    </span>
  )
}
