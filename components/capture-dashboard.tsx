"use client"

import { useMemo, useState } from "react"
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { SeverityBadge, severityMeta } from "@/components/data-display"

const metrics = [
  { key: "packets", label: "Pacotes" },
  { key: "bytes", label: "Bytes" },
  { key: "connections", label: "Conexões" },
] as const

type Metric = (typeof metrics)[number]["key"]

export function CaptureDashboard({ analysis, onNavigate, onProtocol }: { analysis: CaptureAnalysis; onNavigate: (view: string) => void; onProtocol: (protocol: string) => void }) {
  const [metric, setMetric] = useState<Metric>("packets")
  const totalProtocols = analysis.protocols.reduce((sum, item) => sum + item.packets, 0)
  const topHosts = useMemo(() => analysis.hosts.slice(0, 5), [analysis.hosts])
  const maxHostBytes = Math.max(1, ...topHosts.map((host) => host.sentBytes + host.receivedBytes))
  const shownProtocols = analysis.protocols.slice(0, 6)
  const needsAttention = analysis.alerts.filter((item) => item.severity === "Alta" || item.severity === "Média").length
  const leadAlert = analysis.alerts[0]

  const stats = [
    { label: "Pacotes", value: formatNumber(analysis.packetCount), hint: "na captura" },
    { label: "Volume", value: formatBytes(analysis.totalBytes), hint: `${formatBytes(analysis.totalBytes / Math.max(1, analysis.duration))}/s em média` },
    { label: "Hosts", value: formatNumber(analysis.hosts.length), hint: `${formatNumber(analysis.conversations.length)} conversações` },
    { label: "Sinais", value: formatNumber(analysis.alerts.length), hint: needsAttention ? `${needsAttention} com prioridade` : "nenhum prioritário", attention: needsAttention > 0 },
    { label: "Duração", value: formatDuration(analysis.duration), hint: "janela analisada" },
  ]

  return (
    <div className="space-y-4">
      <section className="stat-strip" aria-label="Indicadores da captura">
        <div className="stat-grid">
          {stats.map((stat) => (
            <div className="stat" key={stat.label}>
              <p className="stat-label">{stat.label}</p>
              <strong className="stat-value">{stat.value}</strong>
              <span className={`stat-hint${stat.attention ? " is-attention" : ""}`}>{stat.hint}</span>
            </div>
          ))}
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[1.6fr_0.9fr]">
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Tráfego ao longo do tempo</h2>
              <p className="panel-sub">Passe o cursor para inspecionar um intervalo</p>
            </div>
            <div className="segmented" role="group" aria-label="Métrica do gráfico">
              {metrics.map((item) => (
                <button key={item.key} aria-pressed={metric === item.key} onClick={() => setMetric(item.key)}>
                  {item.label}
                </button>
              ))}
            </div>
          </div>
          <div className="h-[276px] w-full p-3 pl-0">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0} initialDimension={{ width: 760, height: 276 }}>
              <AreaChart data={analysis.timeline} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.22} />
                    <stop offset="100%" stopColor="var(--accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--chart-grid)" tick={{ fontSize: 12, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} minTickGap={36} />
                <YAxis width={58} stroke="var(--chart-grid)" tick={{ fontSize: 12, fill: "var(--chart-axis)" }} tickLine={false} axisLine={false} tickFormatter={(value) => metric === "bytes" ? formatBytes(value) : formatNumber(value)} />
                <Tooltip content={<TrafficTooltip metric={metric} />} cursor={{ stroke: "var(--line-strong)" }} />
                <Area type="monotone" dataKey={metric} stroke="var(--accent)" strokeWidth={1.75} fill="url(#traffic-fill)" activeDot={{ r: 3.5, fill: "var(--surface)", stroke: "var(--accent)", strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Protocolos</h2>
              <p className="panel-sub">Selecione um para filtrar os pacotes</p>
            </div>
          </div>
          <div className="grid items-center gap-3 p-3 sm:grid-cols-[132px_minmax(0,1fr)] xl:grid-cols-[minmax(0,1fr)] 2xl:grid-cols-[132px_minmax(0,1fr)]">
            <div className="relative mx-auto h-[132px] w-[132px] min-w-0">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0} initialDimension={{ width: 132, height: 132 }}>
                <PieChart>
                  <Pie data={shownProtocols} dataKey="packets" nameKey="name" innerRadius={44} outerRadius={62} paddingAngle={1.5} stroke="none" isAnimationActive={false}>
                    {shownProtocols.map((item) => <Cell key={item.name} fill={item.color} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <p className="pointer-events-none absolute inset-0 grid place-content-center text-center leading-tight">
                <span className="num text-lg font-semibold text-[var(--text)]">{analysis.protocols.length}</span>
                <span className="text-xs text-[var(--text-muted)]">{analysis.protocols.length === 1 ? "protocolo" : "protocolos"}</span>
              </p>
            </div>
            <ul className="min-w-0">
              {shownProtocols.map((item) => {
                const share = Math.round((item.packets / Math.max(1, totalProtocols)) * 100)
                return (
                  <li key={item.name}>
                    <button className="dist-row" onClick={() => onProtocol(item.name)}>
                      <span className="dist-name">
                        <i className="dist-swatch" style={{ background: item.color }} aria-hidden="true" />
                        {item.name}
                      </span>
                      <span className="dist-value">{share}%</span>
                      <span className="dist-track">
                        <i className="dist-fill" style={{ width: `${(item.packets / Math.max(1, totalProtocols)) * 100}%`, background: item.color }} />
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        </section>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_0.85fr]">
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Hosts mais ativos</h2>
              <p className="panel-sub">Volume total enviado e recebido</p>
            </div>
            <button className="link-button" onClick={() => onNavigate("Hosts")}>Ver todos os hosts</button>
          </div>
          <ul>
            {topHosts.map((host, index) => {
              const total = host.sentBytes + host.receivedBytes
              return (
                <li key={host.ip}>
                  <button className="rank-row" onClick={() => onNavigate("Hosts")}>
                    <span className="rank-index">{String(index + 1).padStart(2, "0")}</span>
                    <span className="min-w-0">
                      <span className="cell-primary truncate" title={host.ip}>{host.ip}</span>
                      <span className="cell-secondary truncate">{host.hostname || "Hostname não identificado"}</span>
                      <span className="rank-bar"><i style={{ width: `${(total / maxHostBytes) * 100}%` }} /></span>
                    </span>
                    <span className="num mono text-[13px] text-[var(--text)]">{formatBytes(total)}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </section>

        <section className="panel alert-panel" style={leadAlert ? ({ "--rail": severityMeta[leadAlert.severity].rail } as React.CSSProperties) : undefined}>
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Sinal prioritário</h2>
              <p className="panel-sub">Evento que merece contexto primeiro</p>
            </div>
          </div>
          {leadAlert ? (
            <div className="panel-body">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SeverityBadge severity={leadAlert.severity} />
                <span className="num mono text-xs text-[var(--text-muted)]">{leadAlert.time}</span>
              </div>
              <h3 className="mt-3 text-[15px] font-semibold text-[var(--text)]">{leadAlert.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-[var(--text-muted)]">{leadAlert.description}</p>
              <p className="mono mt-3 text-[13px] text-[var(--text-muted)]">
                {leadAlert.source}{leadAlert.destination ? ` → ${leadAlert.destination}` : ""}
              </p>
              <button className="link-button mt-4 block" onClick={() => onNavigate("Security Insights")}>
                Abrir Security Insights
              </button>
            </div>
          ) : (
            <p className="panel-body text-sm text-[var(--text-muted)]">Nenhum sinal foi gerado para esta captura.</p>
          )}
        </section>
      </div>
    </div>
  )
}

function TrafficTooltip({ active, payload, label, metric }: { active?: boolean; payload?: Array<{ value: number }>; label?: string; metric: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      <span>{label}</span>
      <b>{metric === "bytes" ? formatBytes(payload[0].value) : `${formatNumber(payload[0].value)} ${metric === "connections" ? "conexões" : "pacotes"}`}</b>
    </div>
  )
}
