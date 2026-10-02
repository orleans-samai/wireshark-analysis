"use client"

import { useMemo, useState, type CSSProperties } from "react"
import { BellOff, BookmarkPlus, CheckCircle2, Download, FileArchive, FileJson, FileSpreadsheet, Filter, LockKeyhole, Network, Printer, Save, Server, ShieldCheck } from "lucide-react"
import type { AlertDisposition, AlertRecord, AnalyzerOptions, CaptureAnalysis } from "@/lib/capture-types"
import type { CaseEvidence, InvestigationFilter, InvestigationHandler, SavedInvestigation } from "@/lib/investigation"
import { conversationMatchesFilter, filterFromAlert, packetMatchesFilter } from "@/lib/investigation"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { Address, EmptyState, Pager, ProtocolChip, SeverityBadge, severityMeta, usePage } from "@/components/data-display"
import { analysisForJson, conversationsCsv, filteredPacketsCsv, printAnalysisReport } from "@/lib/report"
import { downloadBlob, downloadSourceCapture, exportPacketsAsPcap } from "@/lib/pcap-export"
import { normalizeAnalyzerOptions, withRuleSuppression } from "@/lib/analyzer-options"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"

export function SecurityInsights({ alerts, dispositions, onDisposition, onInvestigate, onAddEvidence, onSuppressRule }: { alerts: AlertRecord[]; dispositions: Record<string, AlertDisposition>; onDisposition: (id: string, status: AlertDisposition) => void; onInvestigate: InvestigationHandler; onAddEvidence: (evidence: Omit<CaseEvidence, "id" | "capturedAt">) => void; onSuppressRule: (ruleId: string) => void }) {
  const active = alerts.filter((alert) => (dispositions[alert.id] || "open") === "open")
  if (alerts.length === 0) return <section className="panel"><EmptyState title="Nenhum sinal foi levantado" hint="As regras não encontraram padrões incomuns nesta captura. Isso não descarta atividade fora do escopo das regras." /></section>

  return (
    <div className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr] xl:items-start">
      <div className="space-y-3">
        {alerts.map((alert) => {
          const status = dispositions[alert.id] || "open"
          return (
            <article className={`panel alert-panel${status !== "open" ? " is-dismissed" : ""}`} key={alert.id} style={{ "--rail": severityMeta[alert.severity].rail } as CSSProperties}>
              <div className="panel-head">
                <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={alert.severity} />{alert.riskScore !== undefined && <span className="risk-score">Risco {alert.riskScore}/100</span>}{alert.confidence && <span className="confidence">Confiança {alert.confidence.toLowerCase()}</span>}{alert.category && <span className="tag">{alert.category}</span>}</div><h2 className="mt-2 text-base font-semibold tracking-[-0.005em] text-[var(--text)]">{alert.title}</h2></div>
                <span className="num mono text-xs text-[var(--text-muted)]">{alert.time}</span>
              </div>
              <div className="panel-body">
                <p className="text-base leading-relaxed text-[var(--text)]">{alert.description}</p>
                <dl className="evidence mt-4">
                  <div><dt>Evidência</dt><dd>{alert.evidence}</dd></div>
                  <div><dt>Comunicação</dt><dd className="mono">{alert.source}{alert.destination ? ` → ${alert.destination}` : ""}</dd></div>
                  <div><dt>Observado</dt><dd>{alert.observed || "—"}</dd></div>
                  <div><dt>Limite da regra</dt><dd>{alert.threshold || "—"}</dd></div>
                </dl>
                <p className="mt-3 text-sm leading-relaxed text-[var(--text-muted)]"><span className="font-semibold text-[var(--text)]">Interpretação: </span>{alert.reason}</p>
                {alert.baseline && <p className="mt-2 text-xs leading-relaxed text-[var(--text-muted)]"><span className="font-semibold text-[var(--text)]">Linha de base local: </span>{alert.baseline}</p>}
                {alert.mitre && <p className="mt-2 text-xs text-[var(--text-muted)]"><span className="mitre">MITRE sugerido · {alert.mitre.id}</span> {alert.mitre.tactic} · {alert.mitre.technique}</p>}
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  {alert.filter && <Button size="sm" onClick={() => onInvestigate(filterFromAlert(alert.filter))}><Filter className="size-4" /> Investigar evidências</Button>}
                  <Button variant="outline" size="sm" onClick={() => onAddEvidence({ type: "alert", reference: `alert:${alert.id}`, title: alert.title, detail: `${alert.evidence} · ${alert.source}${alert.destination ? ` → ${alert.destination}` : ""}` })}><BookmarkPlus className="size-4" /> Adicionar ao caso</Button>
                  {alert.ruleId && alert.ruleId !== "baseline" && <Button variant="ghost" size="sm" onClick={() => onSuppressRule(alert.ruleId!)}><BellOff className="size-4" /> Silenciar regra</Button>}
                  <Select value={status} onValueChange={(value) => onDisposition(alert.id, value as AlertDisposition)}>
                    <SelectTrigger className="h-8 w-44" aria-label={`Classificar ${alert.title}`}><SelectValue /></SelectTrigger>
                    <SelectContent><SelectItem value="open">Em investigação</SelectItem><SelectItem value="expected">Comportamento esperado</SelectItem><SelectItem value="false-positive">Falso positivo</SelectItem></SelectContent>
                  </Select>
                  {alert.ruleId && <span className="mono ml-auto text-xs text-[var(--text-faint)]">regra {alert.ruleId}</span>}
                </div>
              </div>
            </article>
          )
        })}
      </div>

      <aside className="panel xl:sticky xl:top-[105px]" aria-labelledby="panel-how-to-read">
        <div className="panel-head"><h2 id="panel-how-to-read" className="panel-title">Triagem</h2></div>
        <div className="panel-body">
          <p className="panel-note"><b>{active.length}</b> de {alerts.length} sinais continuam em investigação. As regras indicam padrões e não afirmam comprometimento.</p>
          <h3 className="mt-5 text-sm font-semibold text-[var(--text)]">Próximos passos</h3>
          <ol className="mt-2 space-y-1.5 text-sm text-[var(--text-muted)]"><li>1. Abra os pacotes relacionados</li><li>2. Valide a janela e o ativo de origem</li><li>3. Compare com comportamento conhecido</li><li>4. Correlacione com logs do endpoint</li></ol>
        </div>
      </aside>
    </div>
  )
}

const markerColor: Record<string, string> = { info: "var(--info)", high: "var(--danger)", medium: "var(--warn)", low: "var(--caution)", done: "var(--ok)" }

export function IncidentTimeline({ analysis, onInvestigate }: { analysis: CaptureAnalysis; onInvestigate: InvestigationHandler }) {
  const events = [
    { time: analysis.timeline[0]?.time || "Início", epoch: analysis.firstEpoch, title: "Captura iniciada", detail: `${formatNumber(analysis.packetCount)} pacotes na janela analisada`, type: "info", filter: undefined },
    ...analysis.alerts.map((alert) => ({ time: alert.time, epoch: alert.startEpoch, title: alert.title, detail: alert.description, type: alert.severity === "Alta" ? "high" : alert.severity === "Média" ? "medium" : "low", filter: alert.filter })),
    { time: analysis.timeline.at(-1)?.time || "Fim", epoch: analysis.lastEpoch, title: "Análise concluída", detail: `${formatNumber(analysis.hosts.length)} hosts e ${formatNumber(analysis.conversations.length)} conversações identificados`, type: "done", filter: undefined },
  ].sort((a, b) => (a.epoch || 0) - (b.epoch || 0))

  return <section className="panel" aria-labelledby="panel-timeline"><h2 id="panel-timeline" className="sr-only">Eventos em ordem cronológica</h2><ol className="panel-body">{events.map((event, index) => <li className="timeline-entry" key={`${event.title}-${index}`}><span className="timeline-marker" style={{ "--marker": markerColor[event.type] } as CSSProperties} aria-hidden="true" />{/^\d{2}:\d{2}/.test(event.time) ? <time className="timeline-time">{event.time}</time> : <span className="timeline-time">{event.time}</span>}<div className="min-w-0"><h3 className="timeline-title">{event.title}</h3><p className="timeline-detail">{event.detail}</p>{event.filter && <button className="link-button mt-1" onClick={() => onInvestigate(filterFromAlert(event.filter))}>Abrir evidências</button>}</div></li>)}</ol></section>
}

export function NetworkMap({ analysis, onInvestigate }: { analysis: CaptureAnalysis; onInvestigate: InvestigationHandler }) {
  const [selected, setSelected] = useState(analysis.hosts[0]?.ip || "")
  const central = analysis.hosts.find((host) => host.ip === selected) || analysis.hosts[0]
  const peers = analysis.conversations.filter((item) => item.source === central?.ip || item.destination === central?.ip).slice(0, 12)
  return (
    <section className="panel" aria-labelledby="panel-network-map">
      <div className="panel-head"><div><h2 id="panel-network-map" className="panel-title">Relações do host</h2><p className="panel-sub">Escolha o centro para explorar seus principais pares</p></div>{central && <Select value={central.ip} onValueChange={setSelected}><SelectTrigger className="h-8 w-52"><SelectValue /></SelectTrigger><SelectContent>{analysis.hosts.slice(0, 100).map((host) => <SelectItem key={host.ip} value={host.ip}>{host.hostname || host.ip}</SelectItem>)}</SelectContent></Select>}</div>
      <div className="panel-body">{central ? <div className="topology py-6"><button className="node node-central" onClick={() => onInvestigate({ kind: "address", value: central.ip, replace: true })}><Network aria-hidden="true" /><b title={central.hostname || central.ip}>{central.hostname || central.ip}</b><span className="mono">{central.ip}</span></button><div className="node-grid">{peers.map((peer) => { const ip = peer.source === central.ip ? peer.destination : peer.source; return <button key={peer.id} className="node" onClick={() => onInvestigate({ addresses: [central.ip, ip], protocols: [peer.application || peer.protocol] })}><span className="node-stem" aria-hidden="true" /><Server aria-hidden="true" /><b title={ip}>{ip}</b><span className="num">{peer.application || peer.protocol} · {formatBytes(peer.bytes)}</span></button> })}</div></div> : <EmptyState title="Sem hosts para mapear" hint="A captura não produziu endpoints suficientes para montar uma topologia." />}<p className="mt-4 border-t border-[var(--line)] pt-3 text-[13px] text-[var(--text-muted)]">Mapa lógico baseado nas conversações de maior volume; não representa a topologia física da rede.</p></div>
    </section>
  )
}

export function FlowCards({ analysis, filter, onInvestigate }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onInvestigate: InvestigationHandler }) {
  const rows = useMemo(() => analysis.conversations.filter((row) => conversationMatchesFilter(row, filter, analysis.firstEpoch)), [analysis, filter])
  const { visible, paging } = usePage(rows)
  if (!rows.length) return <section className="panel"><EmptyState title="Nenhum fluxo corresponde ao filtro" hint="Ajuste o escopo da investigação para ver os fluxos." /></section>
  return <div className="space-y-3"><div className="grid gap-3 lg:grid-cols-2 2xl:grid-cols-3">{visible.map((row) => <article className="panel p-3" key={row.id}><div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2"><Address ip={row.source} port={row.sourcePort} /><span className="text-[var(--text-faint)]" aria-label="para">→</span><Address ip={row.destination} port={row.destinationPort} /></div><dl className="mt-3 grid grid-cols-3 gap-2 border-t border-[var(--line)] pt-2.5"><div><dt className="text-xs text-[var(--text-muted)]">Aplicação</dt><dd className="mt-1"><ProtocolChip value={row.application || row.protocol} /></dd></div><div><dt className="text-xs text-[var(--text-muted)]">Duração</dt><dd className="num mono mt-1 text-[13px] text-[var(--text)]">{formatDuration(row.duration)}</dd></div><div><dt className="text-xs text-[var(--text-muted)]">Dados</dt><dd className="num mono mt-1 text-[13px] text-[var(--text)]">{formatBytes(row.bytes)}</dd></div></dl><button className="link-button mt-3" onClick={() => onInvestigate({ addresses: [row.source, row.destination], ports: [row.sourcePort, row.destinationPort].filter(Boolean), protocols: [row.application || row.protocol] })}>Investigar fluxo</button></article>)}</div><p className="table-foot panel"><Pager paging={paging} label="fluxos" /></p></div>
}

export function TrafficSummary({ analysis }: { analysis: CaptureAnalysis }) {
  const fallback = { time: "—", packets: 0, bytes: 0, connections: 0 }
  const peak = analysis.timeline.reduce((max, item) => (item.bytes > max.bytes ? item : max), analysis.timeline[0] || fallback)
  const tcp = analysis.tcpHealth || { syn: 0, synAck: 0, resets: 0, retransmissions: 0, incompleteHandshakes: 0 }
  const stats = [
    { label: "Taxa média", value: `${formatBytes(analysis.totalBytes / Math.max(1, analysis.duration))}/s`, hint: "janela completa" },
    { label: "Pico de volume", value: formatBytes(peak.bytes), hint: `intervalo de ${peak.time}` },
    { label: "Retransmissões", value: formatNumber(tcp.retransmissions), hint: `${formatNumber(tcp.resets)} resets TCP` },
    { label: "Handshakes incompletos", value: formatNumber(tcp.incompleteHandshakes), hint: `${formatNumber(tcp.syn)} SYN observados` },
  ]
  return <div className="space-y-4"><section className="stat-strip" aria-label="Resumo do tráfego"><div className="stat-grid">{stats.map((stat) => <div className="stat" key={stat.label}><p className="stat-label">{stat.label}</p><strong className="stat-value">{stat.value}</strong><span className="stat-hint">{stat.hint}</span></div>)}</div></section><div className="grid gap-4 lg:grid-cols-2"><section className="panel"><div className="panel-head"><h2 className="panel-title">Qualidade TCP</h2></div><dl className="panel-body kv"><dt>SYN</dt><dd>{formatNumber(tcp.syn)}</dd><dt>SYN/ACK</dt><dd>{formatNumber(tcp.synAck)}</dd><dt>RST</dt><dd>{formatNumber(tcp.resets)}</dd><dt>Retransmissões prováveis</dt><dd>{formatNumber(tcp.retransmissions)}</dd><dt>Fluxos TCP reagrupados</dt><dd>{formatNumber(analysis.metadata?.reassembledStreams || 0)}</dd><dt>Datagramas IPv4 reagrupados</dt><dd>{formatNumber(analysis.metadata?.reassembledDatagrams || 0)}</dd></dl></section><section className="panel"><div className="panel-head"><h2 className="panel-title">Cobertura e desempenho</h2></div><dl className="panel-body kv"><dt>Retidos</dt><dd>{formatNumber(analysis.metadata?.retainedPackets || analysis.packets.length)}</dd><dt>Não decodificados</dt><dd>{formatNumber(analysis.metadata?.unsupportedPackets || 0)}</dd><dt>Malformados</dt><dd>{formatNumber(analysis.metadata?.malformedPackets || 0)}</dd><dt>Modo</dt><dd>{analysis.metadata?.analysisMode === "deep" ? "Profundo" : "Padrão"}</dd><dt>Tempo de análise</dt><dd>{analysis.metadata?.analysisMs ? `${(analysis.metadata.analysisMs / 1000).toFixed(2)} s` : "—"}</dd><dt>Vazão do parser</dt><dd>{analysis.metadata?.throughputMbps ? `${analysis.metadata.throughputMbps.toFixed(2)} Mb/s` : "—"}</dd><dt>Memória estimada</dt><dd>{formatBytes(analysis.metadata?.estimatedMemoryBytes || 0)}</dd><dt>Histórico local</dt><dd>{formatNumber(analysis.metadata?.historySamples || 0)} captura(s)</dd><dt>Cardinalidade</dt><dd>{analysis.metadata?.aggregationLimited ? "Limitada pelo orçamento" : "Completa"}</dd></dl>{analysis.baseline && <p className="panel-note m-4">Linha de base desta captura: mediana de {formatBytes(analysis.baseline.medianHostBytes)} e {formatNumber(analysis.baseline.medianConnections)} conexões por host; P95 de {formatBytes(analysis.baseline.p95HostBytes)}.</p>}{analysis.metadata?.warnings?.length ? <ul className="advisory advisory-note">{analysis.metadata.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul> : null}</section></div></div>
}

export function Reports({ analysis, sourceFile, filter, saved }: { analysis: CaptureAnalysis; sourceFile: File | null; filter: InvestigationFilter; saved: SavedInvestigation[] }) {
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const filtered = useMemo(() => analysis.packets.filter((packet) => packetMatchesFilter(packet, filter)), [analysis.packets, filter])
  const run = async (key: string, action: () => void | Promise<void>) => { setError(null); setBusy(key); try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : "Não foi possível concluir a exportação.") } finally { setBusy(null) } }
  const exports = [
    { key: "json", Icon: FileJson, title: "Relatório estruturado", file: "packetlens-report.json", detail: "Agregações, metadados, pacotes retidos, sinais e cobertura do parser.", action: () => downloadBlob(new Blob([analysisForJson(analysis)], { type: "application/json" }), "packetlens-report.json") },
    { key: "csv-conversations", Icon: FileSpreadsheet, title: "Conversações", file: "packetlens-conversations.csv", detail: `${formatNumber(analysis.conversations.length)} conversações com transporte e aplicação.`, action: () => downloadBlob(new Blob([conversationsCsv(analysis)], { type: "text/csv;charset=utf-8" }), "packetlens-conversations.csv") },
    { key: "csv-packets", Icon: FileSpreadsheet, title: "Pacotes do recorte", file: "packetlens-filtered-packets.csv", detail: `${formatNumber(filtered.length)} pacotes da amostra correspondem ao escopo atual${analysis.truncatedPackets ? "; não inclui todos os pacotes da captura" : ""}.`, action: () => downloadBlob(new Blob([filteredPacketsCsv(analysis, filter)], { type: "text/csv;charset=utf-8" }), "packetlens-filtered-packets.csv") },
    { key: "pcap", Icon: FileArchive, title: "Recorte PCAP", file: "packetlens-filtered.pcap", detail: sourceFile ? "Exporta somente os quadros retidos da amostra; pacotes sem horário não podem ser exportados como PCAP." : "Disponível para capturas importadas; a demonstração não possui arquivo de origem.", disabled: !sourceFile || !filtered.length, action: async () => { if (!sourceFile) throw new Error("Arquivo original indisponível."); await exportPacketsAsPcap(sourceFile, filtered) } },
    { key: "print", Icon: Printer, title: "Relatório para PDF", file: "Impressão do navegador", detail: "Resumo, sinais, principais conversações e notas salvas em um layout de auditoria.", action: () => printAnalysisReport(analysis, filter, saved) },
    { key: "original", Icon: Download, title: "Captura original", file: sourceFile?.name || "Indisponível", detail: "Baixa novamente o arquivo selecionado, sem cópia ou transformação no servidor.", disabled: !sourceFile, action: () => { if (sourceFile) downloadSourceCapture(sourceFile) } },
  ]
  return <section className="panel overflow-hidden" aria-labelledby="panel-exports"><div className="panel-head"><div><h2 id="panel-exports" className="panel-title">Exportar resultados</h2><p className="panel-sub">Tudo é gerado localmente a partir da análise em memória</p></div></div>{error && <p className="inline-error m-4" role="alert">{error}</p>}<ul>{exports.map((item) => <li key={item.key} className="flex flex-wrap items-start gap-3 border-b border-[var(--line)] p-4 last:border-b-0"><item.Icon className="mt-0.5 size-4 shrink-0 text-[var(--text-faint)]" aria-hidden="true" /><div className="min-w-0 flex-1"><h3 className="text-sm font-semibold text-[var(--text)]">{item.title}</h3><p className="mt-1 text-[13px] leading-relaxed text-[var(--text-muted)]">{item.detail}</p><p className="mono mt-1 text-xs text-[var(--text-faint)]">{item.file}</p></div><Button size="sm" variant={item.key === "json" ? "default" : "outline"} disabled={item.disabled || busy !== null} onClick={() => run(item.key, item.action)}><Download className="size-4" />{busy === item.key ? "Gerando…" : "Exportar"}</Button></li>)}</ul></section>
}

export function SecuritySettings({ analysis, options, onOptionsChange }: { analysis: CaptureAnalysis; options: AnalyzerOptions; onOptionsChange: (options: AnalyzerOptions) => void }) {
  const [ruleJson, setRuleJson] = useState(() => JSON.stringify(options.ruleOptions, null, 2))
  const [message, setMessage] = useState<string | null>(null)
  const setRule = (key: keyof AnalyzerOptions["ruleOptions"], value: number) => onOptionsChange(normalizeAnalyzerOptions({ ...options, ruleOptions: { ...options.ruleOptions, [key]: value } }))
  const importRules = () => {
    try { const parsed = JSON.parse(ruleJson); onOptionsChange(normalizeAnalyzerOptions({ ...options, ruleOptions: parsed })); setMessage("Regras importadas. Elas serão usadas na próxima análise.") } catch { setMessage("JSON inválido. Revise o conteúdo antes de importar.") }
  }
  const exportRules = () => downloadBlob(new Blob([JSON.stringify(options.ruleOptions, null, 2)], { type: "application/json" }), "packetlens-rules.json")
  const limits = [["Parser", `Versão ${analysis.metadata?.parserVersion || "1.x"}`], ["Motor", analysis.metadata?.engine === "tshark" ? "TShark" : "Navegador"], ["Leitura", analysis.metadata?.streamed ? "Incremental em blocos" : "Arquivo em memória"], ["Modo", analysis.metadata?.analysisMode === "deep" ? "Profundo" : "Padrão"], ["Enlace", (analysis.metadata?.linkTypes || [1]).join(", ")], ["Interfaces", String(analysis.metadata?.interfaces || 1)], ["Pacotes retidos", formatNumber(analysis.metadata?.retainedPackets || analysis.packets.length)], ["Histórico", `${formatNumber(analysis.metadata?.historySamples || 0)} captura(s) local(is)`], ["Fora do escopo", "Descriptografia TLS, reagrupamento TCP ilimitado e dissecação completa de extensões proprietárias"]]
  return <div className="space-y-4"><div className="grid gap-4 lg:grid-cols-[0.8fr_1.2fr]"><section className="panel"><div className="panel-head"><div><h2 className="panel-title">Privacidade</h2><p className="panel-sub">Onde os dados são processados</p></div></div><div className="panel-body"><p className="panel-note">Capturas são lidas em janelas por um Web Worker. O conteúdo não é enviado a APIs externas. Casos, triagens e resumos históricos ficam no IndexedDB local; o conteúdo bruto da captura não é persistido.</p><p className="mt-4 flex items-center gap-2 text-sm font-medium text-[var(--ok)]"><CheckCircle2 className="size-4" />Modo local ativo</p><p className="mt-3 flex items-start gap-2 text-[13px] leading-relaxed text-[var(--text-muted)]"><LockKeyhole className="mt-0.5 size-3.5 shrink-0" />O arquivo de captura permanece disponível apenas na sessão atual.</p></div></section><section className="panel overflow-hidden"><div className="panel-head"><div><h2 className="panel-title">Cobertura desta análise</h2><p className="panel-sub">O que foi efetivamente processado</p></div><span className="tag"><ShieldCheck className="size-3.5" />Local</span></div><dl>{limits.map(([term, value]) => <div key={term} className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 border-b border-[var(--line)] px-4 py-2.5 text-sm last:border-b-0"><dt className="text-[var(--text-muted)]">{term}</dt><dd className="m-0 text-right text-[var(--text)]">{value}</dd></div>)}</dl></section></div>
    <section className="panel"><div className="panel-head"><div><h2 className="panel-title">Retenção e regras</h2><p className="panel-sub">Aplicadas à próxima captura analisada</p></div></div><div className="panel-body grid gap-5 xl:grid-cols-2"><div className="space-y-3"><NumberSetting label="Pacotes retidos" value={options.packetLimit} min={1000} max={100000} step={1000} onChange={(value) => onOptionsChange({ ...options, packetLimit: value })} /><NumberSetting label="Portas para sinalizar varredura" value={options.ruleOptions.portScanPorts} min={5} max={1024} onChange={(value) => setRule("portScanPorts", value)} /><NumberSetting label="Consultas DNS por segundo" value={options.ruleOptions.dnsQueriesPerSecond} min={1} max={100000} onChange={(value) => setRule("dnsQueriesPerSecond", value)} /><NumberSetting label="Conversações por host" value={options.ruleOptions.highConnectionCount} min={10} max={1000000} onChange={(value) => setRule("highConnectionCount", value)} /><NumberSetting label="Taxa mínima de retransmissão" value={Math.round(options.ruleOptions.retransmissionRatio * 100)} min={1} max={100} suffix="%" onChange={(value) => setRule("retransmissionRatio", value / 100)} /></div><div><label className="text-sm font-medium text-[var(--text)]" htmlFor="rule-json">Importar ou editar regras em JSON</label><Textarea id="rule-json" className="mono mt-2 min-h-56 text-xs" value={ruleJson} onChange={(event) => setRuleJson(event.target.value)} /><div className="mt-2 flex flex-wrap gap-2"><Button size="sm" onClick={importRules}><Save className="size-4" /> Importar</Button><Button variant="outline" size="sm" onClick={exportRules}><FileJson className="size-4" /> Exportar regras</Button></div>{message && <p className="mt-2 text-xs text-[var(--text-muted)]">{message}</p>}</div></div></section>
    <AnalyzerAdvancedSettings options={options} onOptionsChange={onOptionsChange} />
  </div>
}

const configurableRules = [
  ["port-scan", "Varredura de portas"], ["dns-rate", "Frequência DNS"], ["dns-nxdomain", "Respostas NXDOMAIN"],
  ["many-connections", "Muitas conversações"], ["unusual-port", "Porta desconhecida"],
  ["tcp-retransmissions", "Retransmissões TCP"], ["tcp-resets", "Resets TCP"],
  ["outbound-ratio", "Assimetria de envio"], ["periodic-connections", "Conexões periódicas"],
] as const

function AnalyzerAdvancedSettings({ options, onOptionsChange }: { options: AnalyzerOptions; onOptionsChange: (options: AnalyzerOptions) => void }) {
  return <section className="panel">
    <div className="panel-head"><div><h2 className="panel-title">Ajustes avançados</h2><p className="panel-sub">Aplicados à próxima captura analisada</p></div></div>
    <div className="panel-body grid gap-5 lg:grid-cols-2">
      <div className="space-y-3">
        <NumberSetting label="Orçamento de memória da análise" value={options.memoryBudgetMb} min={64} max={2048} step={64} suffix="MB" onChange={(value) => onOptionsChange({ ...options, memoryBudgetMb: value })} />
        <p className="text-xs text-[var(--text-muted)]">Divide a memória entre detalhes, entidades, fluxos TCP e fragmentos IPv4. Se uma lista atingir o limite, a cobertura reduzida será informada no resultado.</p>
        <label className="flex items-center justify-between gap-3 text-sm">Profundidade da análise
          <Select value={options.analysisMode} onValueChange={(value) => onOptionsChange({ ...options, analysisMode: value === "deep" ? "deep" : "standard" })}>
            <SelectTrigger className="w-40" aria-label="Profundidade da análise"><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="standard">Padrão</SelectItem><SelectItem value="deep">Profunda</SelectItem></SelectContent>
          </Select>
        </label>
        <p className="text-xs text-[var(--text-muted)]">O modo profundo mantém reagrupamento TCP limitado a 64 KB por direção e reagrupamento IPv4 limitado pelo orçamento. O modo padrão prioriza velocidade.</p>
      </div>
      <fieldset className="space-y-2"><legend className="text-sm font-medium text-[var(--text)]">Regras desativadas</legend>
        {configurableRules.map(([id, title]) => <label key={id} className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
          <input type="checkbox" checked={options.suppressedRuleIds.includes(id)} onChange={(event) => onOptionsChange(withRuleSuppression(options, id, event.target.checked))} />{title}
        </label>)}
        <p className="text-xs text-[var(--text-muted)]">Sinais dessas regras não serão exibidos por 30 dias. Reative uma regra desmarcando-a.</p>
      </fieldset>
    </div>
  </section>
}

function NumberSetting({ label, value, min, max, step = 1, suffix, onChange }: { label: string; value: number; min: number; max: number; step?: number; suffix?: string; onChange: (value: number) => void }) {
  return <label className="setting-row"><span>{label}</span><span className="flex items-center gap-1"><Input type="number" value={value} min={min} max={max} step={step} onChange={(event) => onChange(Number(event.target.value))} />{suffix}</span></label>
}
