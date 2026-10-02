"use client"

import { useMemo, useRef } from "react"
import { ArrowDown, ArrowUp, FileDiff, FileUp, Minus, XCircle } from "lucide-react"
import type { CaptureAnalysis } from "@/lib/capture-types"
import type { AnalysisState } from "@/components/packetlens-app"
import { formatBytes, formatDuration, formatNumber } from "@/lib/format"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export function CompareView({ primary, secondary, progress, error, onSelect, onCancel }: {
  primary: CaptureAnalysis
  secondary: CaptureAnalysis | null
  progress: AnalysisState | null
  error?: string | null
  onSelect: (file: File) => void
  onCancel: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  const protocolRows = useMemo(() => {
    if (!secondary) return []
    const names = new Set([...primary.protocols.map((item) => item.name), ...secondary.protocols.map((item) => item.name)])
    return [...names].map((name) => {
      const before = primary.protocols.find((item) => item.name === name)
      const after = secondary.protocols.find((item) => item.name === name)
      return { name, beforePackets: before?.packets || 0, afterPackets: after?.packets || 0, beforeBytes: before?.bytes || 0, afterBytes: after?.bytes || 0 }
    }).sort((a, b) => b.afterBytes - a.afterBytes)
  }, [primary, secondary])

  if (!secondary) {
    return (
      <section className="panel" aria-labelledby="compare-upload">
        <div className="panel-head"><div><h2 id="compare-upload" className="panel-title">Carregar captura de comparação</h2><p className="panel-sub">A segunda captura também é processada localmente</p></div></div>
        <div className="panel-body">
          {progress ? (
            <div className="mx-auto max-w-lg py-8"><ComparisonProgress progress={progress} onCancel={onCancel} /></div>
          ) : (
            <div className="compare-dropzone">
              <FileDiff className="size-6" aria-hidden="true" />
              <strong>Compare comportamento, protocolos, hosts e sinais</strong>
              <span>A captura atual será usada como base. Selecione o arquivo posterior ou alternativo.</span>
              <input ref={input} type="file" className="sr-only" accept=".pcap,.pcapng" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) onSelect(file) }} />
              <Button size="sm" onClick={() => input.current?.click()}><FileUp className="size-4" /> Selecionar captura</Button>
            </div>
          )}
          {error && <p className="inline-error mt-3" role="alert">{error}</p>}
        </div>
      </section>
    )
  }

  const primaryHosts = new Set(primary.hosts.map((item) => item.ip))
  const secondaryHosts = new Set(secondary.hosts.map((item) => item.ip))
  const newHosts = secondary.hosts.filter((item) => !primaryHosts.has(item.ip))
  const missingHosts = primary.hosts.filter((item) => !secondaryHosts.has(item.ip))
  const stats = [
    { label: "Pacotes", before: primary.packetCount, after: secondary.packetCount, format: formatNumber },
    { label: "Volume", before: primary.totalBytes, after: secondary.totalBytes, format: formatBytes },
    { label: "Hosts", before: primary.hosts.length, after: secondary.hosts.length, format: formatNumber },
    { label: "Conversações", before: primary.conversations.length, after: secondary.conversations.length, format: formatNumber },
    { label: "Sinais", before: primary.alerts.filter((item) => item.severity !== "Informativo").length, after: secondary.alerts.filter((item) => item.severity !== "Informativo").length, format: formatNumber },
  ]

  return (
    <div className="space-y-4">
      {progress && <section className="panel panel-body" aria-label="Substituição da captura em andamento">
        <p className="mb-2 text-sm text-[var(--text-muted)]">Exibindo a comparação anterior até a nova captura terminar.</p>
        <ComparisonProgress progress={progress} onCancel={onCancel} />
      </section>}
      {error && <p className="inline-error" role="alert">Não foi possível substituir a captura: {error}. A comparação anterior permanece disponível.</p>}
      <section className="comparison-heading panel">
        <div><small>Base</small><strong>{primary.fileName}</strong><span>{formatDuration(primary.duration)}</span></div>
        <FileDiff aria-hidden="true" />
        <div><small>Comparação</small><strong>{secondary.fileName}</strong><span>{formatDuration(secondary.duration)}</span></div>
        <Button variant="outline" size="sm" disabled={!!progress} onClick={() => input.current?.click()}>Substituir</Button>
        <input ref={input} type="file" className="sr-only" accept=".pcap,.pcapng" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) onSelect(file) }} />
      </section>

      <section className="comparison-grid" aria-label="Variação dos indicadores">
        {stats.map((item) => <DeltaCard key={item.label} {...item} />)}
      </section>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr]">
        <section className="panel overflow-hidden" aria-labelledby="protocol-comparison">
          <div className="panel-head"><h2 id="protocol-comparison" className="panel-title">Protocolos</h2></div>
          <div className="table-scroll"><Table><TableHeader><TableRow><TableHead>Protocolo</TableHead><TableHead className="col-num">Base</TableHead><TableHead className="col-num">Comparação</TableHead><TableHead className="col-num">Variação</TableHead></TableRow></TableHeader><TableBody>
            {protocolRows.map((row) => <TableRow key={row.name}><TableCell className="font-medium">{row.name}</TableCell><TableCell className="col-num">{formatNumber(row.beforePackets)}<span className="cell-secondary">{formatBytes(row.beforeBytes)}</span></TableCell><TableCell className="col-num">{formatNumber(row.afterPackets)}<span className="cell-secondary">{formatBytes(row.afterBytes)}</span></TableCell><TableCell className="col-num"><Delta value={row.afterPackets - row.beforePackets} /></TableCell></TableRow>)}
          </TableBody></Table></div>
        </section>
        <section className="panel" aria-labelledby="host-changes">
          <div className="panel-head"><h2 id="host-changes" className="panel-title">Mudanças de hosts</h2></div>
          <div className="panel-body space-y-4">
            <HostList title="Novos na comparação" rows={newHosts.map((item) => item.ip)} tone="up" />
            <HostList title="Ausentes na comparação" rows={missingHosts.map((item) => item.ip)} tone="down" />
          </div>
        </section>
      </div>
    </div>
  )
}

function ComparisonProgress({ progress, onCancel }: { progress: AnalysisState; onCancel: () => void }) {
  return <div aria-live="polite" aria-busy="true">
    <p className="text-sm font-semibold text-[var(--text)]">{progress.stage}</p>
    <Progress value={progress.percent} aria-label="Progresso da comparação" className="mt-3 h-1" />
    <div className="num mt-2 flex justify-between text-xs text-[var(--text-muted)]"><span>{formatNumber(progress.processed)} pacotes</span><span>{progress.percent}%</span></div>
    <Button variant="outline" size="sm" className="mt-4" onClick={onCancel}><XCircle className="size-4" /> Cancelar</Button>
  </div>
}

function DeltaCard({ label, before, after, format }: { label: string; before: number; after: number; format: (value: number) => string }) {
  const delta = after - before
  return <article className="comparison-card"><span>{label}</span><strong>{format(after)}</strong><small>base {format(before)}</small><Delta value={delta} /></article>
}

function Delta({ value }: { value: number }) {
  const Icon = value > 0 ? ArrowUp : value < 0 ? ArrowDown : Minus
  return <span className={`delta ${value > 0 ? "is-up" : value < 0 ? "is-down" : ""}`}><Icon aria-hidden="true" />{value > 0 ? "+" : ""}{formatNumber(value)}</span>
}

function HostList({ title, rows, tone }: { title: string; rows: string[]; tone: "up" | "down" }) {
  return <div><h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">{title} · {rows.length}</h3>{rows.length ? <ul className="mt-2 space-y-1">{rows.slice(0, 12).map((ip) => <li className={`host-change is-${tone}`} key={ip}>{ip}</li>)}</ul> : <p className="mt-2 text-sm text-[var(--text-muted)]">Nenhuma mudança</p>}</div>
}
