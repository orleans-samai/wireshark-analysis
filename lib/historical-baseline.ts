import type { AlertConfidence, AlertRecord, CaptureAnalysis, HostRecord } from "./capture-types"
import { readLocalRecord, writeLocalRecord } from "./local-db"

const HISTORY_KEY = "capture-history:v1"
const MAX_SNAPSHOTS = 30
const MAX_HOSTS_PER_SNAPSHOT = 2_000

export type HistoricalHostSample = Pick<HostRecord, "ip" | "sentBytes" | "receivedBytes" | "connections">
export type CaptureHistorySnapshot = {
  id: string
  analyzedAt: string
  hosts: HistoricalHostSample[]
}

type HostHistory = {
  samples: number
  medianBytes: number
  p95Bytes: number
  medianConnections: number
  p95Connections: number
  medianSentBytes: number
  p95SentBytes: number
}

function percentile(values: number[], ratio: number) {
  if (!values.length) return 0
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * ratio) - 1))]
}

function formatCompact(value: number) {
  if (value >= 1e9) return `${(value / 1e9).toFixed(1)} GB`
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)} MB`
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)} KB`
  return `${Math.round(value)} B`
}

function buildHistory(snapshots: CaptureHistorySnapshot[]) {
  const values = new Map<string, { bytes: number[]; connections: number[]; sentBytes: number[] }>()
  for (const snapshot of snapshots) {
    for (const host of snapshot.hosts) {
      const current = values.get(host.ip) || { bytes: [], connections: [], sentBytes: [] }
      current.bytes.push(host.sentBytes + host.receivedBytes)
      current.connections.push(host.connections)
      current.sentBytes.push(host.sentBytes)
      values.set(host.ip, current)
    }
  }
  return new Map<string, HostHistory>([...values].map(([ip, current]) => [ip, {
    samples: current.bytes.length,
    medianBytes: percentile(current.bytes, 0.5),
    p95Bytes: percentile(current.bytes, 0.95),
    medianConnections: percentile(current.connections, 0.5),
    p95Connections: percentile(current.connections, 0.95),
    medianSentBytes: percentile(current.sentBytes, 0.5),
    p95SentBytes: percentile(current.sentBytes, 0.95),
  }]))
}

function lowerConfidence(confidence: AlertConfidence | undefined): AlertConfidence {
  return confidence === "Alta" ? "Média" : "Baixa"
}

function tuneAlert(alert: AlertRecord, analysis: CaptureAnalysis, history: Map<string, HostHistory>) {
  const profile = history.get(alert.source)
  const host = analysis.hosts.find((item) => item.ip === alert.source)
  if (!profile || !host || profile.samples < 3) return alert
  const historicalText = `Histórico local (${profile.samples} capturas): mediana ${formatCompact(profile.medianBytes)} e ${Math.round(profile.medianConnections)} conexões; P95 ${formatCompact(profile.p95Bytes)} e ${Math.round(profile.p95Connections)} conexões.`
  let observed: number | undefined
  let p95: number | undefined
  if (alert.ruleId === "many-connections") {
    observed = host.connections
    p95 = profile.p95Connections
  } else if (alert.ruleId === "outbound-ratio") {
    observed = host.sentBytes
    p95 = profile.p95SentBytes
  }
  if (observed === undefined || p95 === undefined || p95 <= 0) return { ...alert, baseline: `${alert.baseline || ""} ${historicalText}`.trim() }
  if (observed <= p95 * 1.2) {
    return {
      ...alert,
      confidence: lowerConfidence(alert.confidence),
      riskScore: Math.max(10, (alert.riskScore || 10) - 20),
      baseline: `${alert.baseline || ""} ${historicalText}`.trim(),
      reason: `${alert.reason} O valor atual está dentro da faixa histórica deste ativo; trate como menor prioridade até existir outra evidência.`
    }
  }
  if (observed > p95 * 2) {
    return {
      ...alert,
      confidence: "Alta" as const,
      riskScore: Math.min(100, (alert.riskScore || 10) + 5),
      baseline: `${alert.baseline || ""} ${historicalText}`.trim(),
      reason: `${alert.reason} O valor atual supera em mais de duas vezes o P95 histórico deste ativo.`
    }
  }
  return { ...alert, baseline: `${alert.baseline || ""} ${historicalText}`.trim() }
}

export function applyHistoricalContext(analysis: CaptureAnalysis, snapshots: CaptureHistorySnapshot[]): CaptureAnalysis {
  const history = buildHistory(snapshots.filter((snapshot) => snapshot.id !== analysis.id))
  return {
    ...analysis,
    alerts: analysis.alerts.map((alert) => tuneAlert(alert, analysis, history)).sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)),
    metadata: { ...analysis.metadata!, historySamples: snapshots.length },
  }
}

function snapshotFor(analysis: CaptureAnalysis): CaptureHistorySnapshot {
  const hosts = [...analysis.hosts]
    .sort((a, b) => (b.sentBytes + b.receivedBytes) - (a.sentBytes + a.receivedBytes))
    .slice(0, MAX_HOSTS_PER_SNAPSHOT)
    .map(({ ip, sentBytes, receivedBytes, connections }) => ({ ip, sentBytes, receivedBytes, connections }))
  return { id: analysis.id || `${analysis.fileName}:${analysis.fileSize}:${analysis.packetCount}`, analyzedAt: new Date().toISOString(), hosts }
}

export async function contextualizeAnalysis(analysis: CaptureAnalysis, remember = true): Promise<CaptureAnalysis> {
  let snapshots: CaptureHistorySnapshot[] = []
  try {
    snapshots = (await readLocalRecord<CaptureHistorySnapshot[]>(HISTORY_KEY)) || []
  } catch {
    return analysis
  }
  const contextualized = applyHistoricalContext(analysis, snapshots)
  if (remember) {
    const snapshot = snapshotFor(analysis)
    const next = [snapshot, ...snapshots.filter((item) => item.id !== snapshot.id)].slice(0, MAX_SNAPSHOTS)
    try { await writeLocalRecord(HISTORY_KEY, next) } catch { /* A análise continua válida sem histórico persistido. */ }
  }
  return contextualized
}
