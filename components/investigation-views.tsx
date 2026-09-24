"use client"

import { useMemo, type CSSProperties } from "react"
import { CheckCircle2, Download, FileJson, LockKeyhole, Network, Server, ShieldCheck } from "lucide-react"
import type { AlertRecord, CaptureAnalysis } from "@/lib/capture-types"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { Address, EmptyState, Pager, ProtocolChip, SeverityBadge, severityMeta, usePage } from "@/components/data-display"
import { Button } from "@/components/ui/button"

/* -------------------------------------------------------------------------
   Security Insights
   ---------------------------------------------------------------------- */

export function SecurityInsights({ alerts, onInvestigate }: { alerts: AlertRecord[]; onInvestigate: (term: string) => void }) {
  if (alerts.length === 0) {
    return (
      <section className="panel">
        <EmptyState
          title="Nenhum sinal foi levantado"
          hint="As regras não encontraram padrões incomuns nesta captura. Isso não descarta atividade relevante fora do escopo das regras."
        />
      </section>
    )
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr] xl:items-start">
      <div className="space-y-3">
        {alerts.map((alert) => (
          <article
            className="panel alert-panel"
            key={alert.id}
            style={{ "--rail": severityMeta[alert.severity].rail } as CSSProperties}
          >
            <div className="panel-head">
              <div className="min-w-0">
                <SeverityBadge severity={alert.severity} />
                <h2 className="mt-2 text-base font-semibold tracking-[-0.005em] text-[var(--text)]">{alert.title}</h2>
              </div>
              <span className="num mono text-xs text-[var(--text-muted)]">{alert.time}</span>
            </div>
            <div className="panel-body">
              <p className="text-base leading-relaxed text-[var(--text)]">{alert.description}</p>
              <dl className="evidence mt-4">
                <div>
                  <dt>Evidência</dt>
                  <dd>{alert.evidence}</dd>
                </div>
                <div>
                  <dt>Comunicação</dt>
                  <dd className="mono">{alert.source}{alert.destination ? ` → ${alert.destination}` : ""}</dd>
                </div>
              </dl>
              <p className="mt-3 text-sm leading-relaxed text-[var(--text-muted)]">
                <span className="font-semibold text-[var(--text)]">Por que foi sinalizado: </span>
                {alert.reason}
              </p>
              <Button size="sm" className="mt-4" onClick={() => onInvestigate(alert.source)}>
                Investigar pacotes de {alert.source}
              </Button>
            </div>
          </article>
        ))}
      </div>

      <aside className="panel xl:sticky xl:top-[73px]">
        <div className="panel-head">
          <h2 className="panel-title">Como interpretar</h2>
        </div>
        <div className="panel-body">
          <p className="panel-note">
            Os sinais são baseados em regras e indicam padrões que merecem contexto. Eles não afirmam comprometimento.
          </p>
          <h3 className="mt-5 text-sm font-semibold text-[var(--text)]">Próximos passos</h3>
          <ol className="mt-2 space-y-1.5 text-sm text-[var(--text-muted)]">
            <li>1. Verifique os pacotes relacionados</li>
            <li>2. Compare com o comportamento normal</li>
            <li>3. Identifique a aplicação responsável</li>
            <li>4. Correlacione com logs do endpoint</li>
          </ol>
        </div>
      </aside>
    </div>
  )
}

/* -------------------------------------------------------------------------
   Incident timeline
   ---------------------------------------------------------------------- */

const markerColor: Record<string, string> = {
  info: "var(--info)",
  high: "var(--danger)",
  medium: "var(--warn)",
  low: "var(--caution)",
  done: "var(--ok)",
}

export function IncidentTimeline({ analysis }: { analysis: CaptureAnalysis }) {
  const events = [
    { time: analysis.timeline[0]?.time || "Início", title: "Captura iniciada", detail: `${formatNumber(analysis.packetCount)} pacotes na janela analisada`, type: "info" },
    ...analysis.alerts.map((alert) => ({
      time: alert.time,
      title: alert.title,
      detail: alert.description,
      type: alert.severity === "Alta" ? "high" : alert.severity === "Média" ? "medium" : "low",
    })),
    { time: analysis.timeline.at(-1)?.time || "Fim", title: "Análise concluída", detail: `${formatNumber(analysis.hosts.length)} hosts e ${formatNumber(analysis.conversations.length)} conversações identificados`, type: "done" },
  ]

  return (
    <section className="panel" aria-labelledby="panel-timeline">
      <h2 id="panel-timeline" className="sr-only">Eventos em ordem cronológica</h2>
      <ol className="panel-body">
        {events.map((event, index) => (
          <li className="timeline-entry" key={`${event.title}-${index}`}>
            <span className="timeline-marker" style={{ "--marker": markerColor[event.type] } as CSSProperties} aria-hidden="true" />
            {/* The worker emits "Durante a captura" for window-wide findings,
                which is not a machine-readable time. */}
            {/^\d{2}:\d{2}/.test(event.time)
              ? <time className="timeline-time">{event.time}</time>
              : <span className="timeline-time">{event.time}</span>}
            <div className="min-w-0">
              <h3 className="timeline-title">{event.title}</h3>
              <p className="timeline-detail">{event.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

/* -------------------------------------------------------------------------
   Network map
   ---------------------------------------------------------------------- */

export function NetworkMap({ analysis, onInvestigate }: { analysis: CaptureAnalysis; onInvestigate: (term: string) => void }) {
  const central = analysis.hosts[0]
  const peers = analysis.conversations.filter((item) => item.source === central?.ip || item.destination === central?.ip).slice(0, 7)

  return (
    <section className="panel" aria-labelledby="panel-network-map">
      <h2 id="panel-network-map" className="sr-only">Topologia simplificada</h2>
      <div className="panel-body">
        {central ? (
          <div className="topology py-6">
            <button className="node node-central" onClick={() => onInvestigate(central.ip)}>
              <Network aria-hidden="true" />
              <b title={central.hostname || central.ip}>{central.hostname || central.ip}</b>
              {central.hostname ? <span className="mono">{central.ip}</span> : null}
            </button>
            <div className="node-grid">
              {peers.map((peer) => {
                const ip = peer.source === central.ip ? peer.destination : peer.source
                return (
                  <button key={peer.id} className="node" onClick={() => onInvestigate(ip)}>
                    <span className="node-stem" aria-hidden="true" />
                    <Server aria-hidden="true" />
                    <b title={ip}>{ip}</b>
                    <span className="num">{peer.protocol} · {formatBytes(peer.bytes)}</span>
                  </button>
                )
              })}
            </div>
          </div>
        ) : (
          <EmptyState title="Sem hosts para mapear" hint="A captura não produziu endpoints suficientes para montar uma topologia." />
        )}
        <p className="mt-4 border-t border-[var(--line)] pt-3 text-[13px] text-[var(--text-muted)]">
          Topologia simplificada: o mapa prioriza as conexões de maior volume do host mais ativo e não representa a
          topologia física da rede.
        </p>
      </div>
    </section>
  )
}

/* -------------------------------------------------------------------------
   Network flows
   ---------------------------------------------------------------------- */

export function FlowCards({ analysis, query }: { analysis: CaptureAnalysis; query: string }) {
  const needle = query.toLowerCase()
  const rows = useMemo(
    () => analysis.conversations.filter((row) => `${row.source} ${row.destination} ${row.protocol}`.toLowerCase().includes(needle)),
    [analysis.conversations, needle],
  )
  const { visible, paging } = usePage(rows)

  if (rows.length === 0) {
    return (
      <section className="panel">
        <EmptyState title="Nenhum fluxo corresponde ao filtro" hint="Ajuste a pesquisa para ver os fluxos da captura." />
      </section>
    )
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 lg:grid-cols-2 2xl:grid-cols-3">
      {visible.map((row) => (
        <article className="panel p-3" key={row.id}>
          <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2">
            <Address ip={row.source} port={row.sourcePort} />
            <span className="text-[var(--text-faint)]" aria-label="para">→</span>
            <Address ip={row.destination} port={row.destinationPort} />
          </div>
          <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-[var(--line)] pt-2.5">
            <div>
              <dt className="text-xs text-[var(--text-muted)]">Protocolo</dt>
              <dd className="mt-1"><ProtocolChip value={row.protocol} /></dd>
            </div>
            <div>
              <dt className="text-xs text-[var(--text-muted)]">Duração</dt>
              <dd className="num mono mt-1 text-[13px] text-[var(--text)]">{formatDuration(row.duration)}</dd>
            </div>
            <div>
              <dt className="text-xs text-[var(--text-muted)]">Dados</dt>
              <dd className="num mono mt-1 text-[13px] text-[var(--text)]">{formatBytes(row.bytes)}</dd>
            </div>
          </dl>
        </article>
      ))}
      </div>
      <p className="table-foot panel">
        <Pager paging={paging} label="fluxos" />
      </p>
    </div>
  )
}

/* -------------------------------------------------------------------------
   Traffic summary
   ---------------------------------------------------------------------- */

export function TrafficSummary({ analysis }: { analysis: CaptureAnalysis }) {
  const fallback = { time: "—", packets: 0, bytes: 0, connections: 0 }
  const peak = analysis.timeline.reduce((max, item) => (item.bytes > max.bytes ? item : max), analysis.timeline[0] || fallback)

  const stats = [
    { label: "Taxa média", value: `${formatBytes(analysis.totalBytes / Math.max(1, analysis.duration))}/s`, hint: "sobre a janela completa" },
    { label: "Pico de volume", value: formatBytes(peak.bytes), hint: `intervalo de ${peak.time}` },
    { label: "Conversações", value: formatNumber(analysis.conversations.length), hint: `${formatNumber(analysis.hosts.length)} hosts envolvidos` },
    { label: "Janela", value: formatDuration(analysis.duration), hint: `${formatNumber(analysis.packetCount)} pacotes` },
  ]

  return (
    <div className="space-y-4">
      <section className="stat-strip" aria-label="Resumo do tráfego">
        <div className="stat-grid">
          {stats.map((stat) => (
            <div className="stat" key={stat.label}>
              <p className="stat-label">{stat.label}</p>
              <strong className="stat-value">{stat.value}</strong>
              <span className="stat-hint">{stat.hint}</span>
            </div>
          ))}
        </div>
      </section>
      <section className="panel" aria-labelledby="panel-traffic-window">
        <h2 id="panel-traffic-window" className="sr-only">Janela completa</h2>
        <p className="panel-body panel-note">
          A captura durou {formatDuration(analysis.duration)} e contém {formatNumber(analysis.packetCount)} pacotes.
          Use o Dashboard para alternar entre pacotes, bytes e conexões por intervalo.
        </p>
      </section>
    </div>
  )
}

/* -------------------------------------------------------------------------
   Reports
   ---------------------------------------------------------------------- */

export function Reports({ analysis }: { analysis: CaptureAnalysis }) {
  const download = (kind: "json" | "csv") => {
    let content: string, type: string, name: string
    if (kind === "json") {
      content = JSON.stringify(analysis, null, 2)
      type = "application/json"
      name = "packetlens-report.json"
    } else {
      content = ["source,destination,protocol,packets,bytes", ...analysis.conversations.map((row) => `${row.source},${row.destination},${row.protocol},${row.packets},${row.bytes}`)].join("\n")
      type = "text/csv"
      name = "packetlens-conversations.csv"
    }
    const url = URL.createObjectURL(new Blob([content], { type }))
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = name
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const exports = [
    {
      kind: "json" as const,
      Icon: FileJson,
      title: "Relatório estruturado (JSON)",
      file: "packetlens-report.json",
      detail: "Resumo, hosts, protocolos, DNS, portas, conversações, pacotes retidos, sinais e timeline.",
      primary: true,
    },
    {
      kind: "csv" as const,
      Icon: Download,
      title: "Conversações (CSV)",
      file: "packetlens-conversations.csv",
      detail: `${formatNumber(analysis.conversations.length)} linhas com origem, destino, protocolo, pacotes e bytes.`,
      primary: false,
    },
  ]

  return (
    <section className="panel overflow-hidden">
      <div className="panel-head">
        <div>
          <h2 className="panel-title">Exportar resultados</h2>
          <p className="panel-sub">Os arquivos são gerados no navegador a partir da análise já em memória</p>
        </div>
      </div>
      <ul>
        {exports.map((item) => (
          <li key={item.kind} className="flex flex-wrap items-start gap-3 border-b border-[var(--line)] p-4 last:border-b-0">
            <item.Icon className="mt-0.5 size-4 shrink-0 text-[var(--text-faint)]" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold text-[var(--text)]">{item.title}</h3>
              <p className="mt-1 text-[13px] leading-relaxed text-[var(--text-muted)]">{item.detail}</p>
              <p className="mono mt-1 text-xs text-[var(--text-faint)]">{item.file}</p>
            </div>
            <Button size="sm" variant={item.primary ? "default" : "outline"} onClick={() => download(item.kind)}>
              <Download className="size-4" aria-hidden="true" />
              Exportar
            </Button>
          </li>
        ))}
      </ul>
    </section>
  )
}

/* -------------------------------------------------------------------------
   Settings
   ---------------------------------------------------------------------- */

const analyzerLimits = [
  ["Enlace", "Ethernet (Linktype 1)"],
  ["Rede", "IPv4, IPv6"],
  ["Transporte", "TCP, UDP, ICMP"],
  ["Aplicação", "DNS decodificado; HTTP e TLS classificados por metadados"],
  ["Pacotes retidos", "10.000 (as estatísticas cobrem a captura inteira)"],
  ["Fora do escopo", "Descriptografia de TLS e protocolos que exigem TShark"],
] as const

export function SecuritySettings() {
  return (
    <div className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2 className="panel-title">Privacidade</h2>
            <p className="panel-sub">Onde a captura é processada</p>
          </div>
        </div>
        <div className="panel-body">
          <p className="panel-note">
            Capturas são lidas por um Web Worker dentro do navegador. O arquivo completo não é enviado a APIs externas
            e nenhuma telemetria de conteúdo é criada.
          </p>
          <p className="mt-4 flex items-center gap-2 text-sm font-medium text-[var(--ok)]">
            <CheckCircle2 className="size-4" aria-hidden="true" />
            Modo local ativo
          </p>
          <p className="mt-3 flex items-start gap-2 text-[13px] leading-relaxed text-[var(--text-muted)]">
            <LockKeyhole className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            Fechar ou recarregar a página descarta a análise: nada é persistido em disco pelo PacketLens.
          </p>
        </div>
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-head">
          <div>
            <h2 className="panel-title">Limites do analisador</h2>
            <p className="panel-sub">O que esta versão decodifica</p>
          </div>
          <span className="tag">
            <ShieldCheck className="size-3.5" aria-hidden="true" />
            MVP
          </span>
        </div>
        <dl>
          {analyzerLimits.map(([term, value]) => (
            <div key={term} className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 border-b border-[var(--line)] px-4 py-2.5 text-sm last:border-b-0">
              <dt className="text-[var(--text-muted)]">{term}</dt>
              <dd className="m-0 text-right text-[var(--text)]">{value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  )
}
