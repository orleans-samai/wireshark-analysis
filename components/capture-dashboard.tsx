"use client"

import { useMemo, useState } from "react"
import { AlertTriangle, ArrowDown, ArrowUp, Clock3, RadioTower, Server, ShieldAlert, Waypoints } from "lucide-react"
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"

export function CaptureDashboard({ analysis, onNavigate, onProtocol }: { analysis: CaptureAnalysis; onNavigate: (view: string) => void; onProtocol: (protocol: string) => void }) {
  const [metric, setMetric] = useState<"packets" | "bytes" | "connections">("packets")
  const totalProtocols = analysis.protocols.reduce((sum, item) => sum + item.packets, 0)
  const topHosts = useMemo(() => analysis.hosts.slice(0, 5), [analysis.hosts])
  const maxHostBytes = Math.max(1, ...topHosts.map((host) => host.sentBytes + host.receivedBytes))

  const cards = [
    { label: "Total de pacotes", value: formatNumber(analysis.packetCount), hint: "capturados", icon: RadioTower, color: "cyan" },
    { label: "Volume de tráfego", value: formatBytes(analysis.totalBytes), hint: `${formatBytes(analysis.totalBytes / Math.max(1, analysis.duration))}/s`, icon: ArrowDown, color: "violet" },
    { label: "Hosts identificados", value: formatNumber(analysis.hosts.length), hint: `${formatNumber(analysis.conversations.length)} conversações`, icon: Server, color: "blue" },
    { label: "Alertas", value: formatNumber(analysis.alerts.length), hint: `${analysis.alerts.filter((item) => item.severity === "Alta" || item.severity === "Média").length} requerem atenção`, icon: ShieldAlert, color: "amber" },
    { label: "Duração", value: formatDuration(analysis.duration), hint: "janela analisada", icon: Clock3, color: "slate" },
  ]

  return (
    <div className="space-y-4">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {cards.map((card) => <article className={`metric-card metric-${card.color}`} key={card.label}><div className="flex items-start justify-between"><p>{card.label}</p><card.icon className="size-4" /></div><strong>{card.value}</strong><span>{card.hint}</span></article>)}
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.6fr_.9fr]">
        <article className="panel p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div><h2>Tráfego ao longo do tempo</h2><p>Movimente o cursor para inspecionar um intervalo</p></div>
            <div className="segmented" aria-label="Métrica do gráfico">
              {(["packets", "bytes", "connections"] as const).map((item) => <button key={item} className={metric === item ? "active" : ""} onClick={() => setMetric(item)}>{item === "packets" ? "Pacotes" : item === "bytes" ? "Bytes" : "Conexões"}</button>)}
            </div>
          </div>
          <div className="mt-6 h-[280px] w-full">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
              <AreaChart data={analysis.timeline} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                <defs><linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid stroke="rgba(148,163,184,.07)" vertical={false} />
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={28} />
                <YAxis stroke="#475569" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} tickFormatter={(value) => metric === "bytes" ? formatBytes(value) : formatNumber(value)} />
                <Tooltip content={<TrafficTooltip metric={metric} />} />
                <Area type="monotone" dataKey={metric} stroke="#22d3ee" strokeWidth={2} fill="url(#traffic-fill)" activeDot={{ r: 4, fill: "#0b1018", stroke: "#67e8f9", strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="panel p-5 sm:p-6">
          <div><h2>Protocolos</h2><p>Clique para filtrar os pacotes relacionados</p></div>
          <div className="mt-4 grid grid-cols-[145px_1fr] items-center gap-4">
            <div className="relative h-[150px] min-w-0"><ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}><PieChart><Pie data={analysis.protocols.slice(0, 6)} dataKey="packets" nameKey="name" innerRadius={48} outerRadius={66} paddingAngle={2} stroke="none">{analysis.protocols.slice(0, 6).map((item) => <Cell key={item.name} fill={item.color} />)}</Pie></PieChart></ResponsiveContainer><div className="pointer-events-none absolute inset-0 grid place-items-center text-center"><span><b className="block text-lg font-semibold text-slate-100">{analysis.protocols.length}</b><small className="text-[10px] uppercase tracking-wider text-slate-500">protocolos</small></span></div></div>
            <div className="space-y-2">{analysis.protocols.slice(0, 6).map((item) => <button key={item.name} onClick={() => onProtocol(item.name)} className="protocol-row"><span><i style={{ background: item.color }} />{item.name}</span><b>{Math.round(item.packets / Math.max(1, totalProtocols) * 100)}%</b></button>)}</div>
          </div>
        </article>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.35fr_.85fr]">
        <article className="panel overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 sm:px-6"><div><h2>Hosts mais ativos</h2><p>Volume total enviado e recebido</p></div><button className="text-link" onClick={() => onNavigate("Hosts")}>Ver todos</button></div>
          <div className="border-t border-white/[.06]">
            {topHosts.map((host, index) => { const total = host.sentBytes + host.receivedBytes; return <button key={host.ip} className="host-row" onClick={() => onNavigate("Hosts")}><span className="rank">{String(index + 1).padStart(2, "0")}</span><span className="min-w-0 flex-1 text-left"><b>{host.ip}</b><small>{host.hostname || "Hostname não identificado"}</small></span><span className="hidden w-40 sm:block"><i style={{ width: `${(total / maxHostBytes) * 100}%` }} /></span><span className="w-20 text-right font-mono text-xs text-slate-300">{formatBytes(total)}</span></button> })}
          </div>
        </article>

        <article className="panel overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 sm:px-6"><div><h2>Insight prioritário</h2><p>Evento que merece investigação</p></div><AlertTriangle className="size-4 text-amber-400" /></div>
          {analysis.alerts[0] ? <div className="border-t border-white/[.06] p-5 sm:p-6"><span className={`severity severity-${analysis.alerts[0].severity.toLowerCase()}`}>{analysis.alerts[0].severity}</span><h3 className="mt-4 text-lg font-semibold tracking-tight text-slate-100">{analysis.alerts[0].title}</h3><p className="mt-2 !text-sm !leading-6 text-slate-400">{analysis.alerts[0].description}</p><div className="mt-5 flex items-center gap-2 font-mono text-xs text-slate-500"><Waypoints className="size-3.5" />{analysis.alerts[0].source}{analysis.alerts[0].destination ? ` → ${analysis.alerts[0].destination}` : ""}</div><button className="mt-6 flex items-center gap-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200" onClick={() => onNavigate("Security Insights")}>Investigar evento <ArrowUp className="size-3.5 rotate-45" /></button></div> : <div className="p-6 text-sm text-slate-500">Nenhum insight foi gerado.</div>}
        </article>
      </section>
    </div>
  )
}

function TrafficTooltip({ active, payload, label, metric }: { active?: boolean; payload?: Array<{ value: number }>; label?: string; metric: string }) {
  if (!active || !payload?.length) return null
  return <div className="chart-tooltip"><span>{label}</span><b>{metric === "bytes" ? formatBytes(payload[0].value) : `${formatNumber(payload[0].value)} ${metric === "connections" ? "conexões" : "pacotes"}`}</b></div>
}
