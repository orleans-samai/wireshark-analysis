import type { CaptureAnalysis } from "./capture-types"
import type { InvestigationFilter, SavedInvestigation } from "./investigation"
import { describeFilter, packetMatchesFilter } from "./investigation"
import { formatBytes, formatDuration, formatNumber } from "./format"

export function csvEscape(value: unknown) {
  const text = String(value ?? "")
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function conversationsCsv(analysis: CaptureAnalysis) {
  // BOM para o Excel pt-BR reconhecer UTF-8 com acentos.
  return CSV_BOM + [
    ["source", "source_port", "destination", "destination_port", "transport", "application", "packets", "bytes", "start", "duration_seconds"],
    ...analysis.conversations.map((row) => [row.source, row.sourcePort, row.destination, row.destinationPort, row.protocol, row.application || "", row.packets, row.bytes, row.start, row.duration]),
  ].map((row) => row.map(csvEscape).join(",")).join("\n")
}

export function filteredPacketsCsv(analysis: CaptureAnalysis, filter: InvestigationFilter) {
  const packets = analysis.packets.filter((packet) => packetMatchesFilter(packet, filter))
  // BOM para o Excel pt-BR reconhecer UTF-8 com acentos.
  return CSV_BOM + [
    ["number", "timestamp", "source", "source_port", "destination", "destination_port", "protocol", "length", "info"],
    ...packets.map((row) => [row.no, row.timestamp, row.source, row.sourcePort || "", row.destination, row.destinationPort || "", row.protocol, row.length, row.info]),
  ].map((row) => row.map(csvEscape).join(",")).join("\n")
}

export function analysisForJson(analysis: CaptureAnalysis) {
  return JSON.stringify(analysis, (_key, value) => value instanceof Uint8Array ? undefined : value, 2)
}

export function printAnalysisReport(analysis: CaptureAnalysis, filter: InvestigationFilter, saved: SavedInvestigation[]) {
  const relevantPackets = analysis.packets.filter((packet) => packetMatchesFilter(packet, filter))
  const html = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Relatório PacketLens</title><style>
    :root{font-family:Inter,Arial,sans-serif;color:#17202a}body{max-width:1100px;margin:40px auto;padding:0 24px}h1{font-size:24px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #d7dde5;padding-bottom:6px}.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{border:1px solid #d7dde5;border-radius:6px;padding:12px}.label{font-size:11px;text-transform:uppercase;color:#667085}.value{display:block;margin-top:4px;font-size:18px;font-weight:650}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:7px;border-bottom:1px solid #e4e7ec;text-align:left}th{color:#475467}.mono{font-family:ui-monospace,monospace}.alert{border-left:3px solid #b3282e;padding:8px 12px;margin:8px 0;background:#f8fafc}.note{white-space:pre-wrap}.muted{color:#667085;font-size:12px}@media print{body{margin:0}.no-print{display:none}}
  </style></head><body>
    <h1>Relatório de análise de captura</h1>
    <p class="muted">Gerado localmente pelo PacketLens em ${escapeHtml(new Date().toLocaleString("pt-BR"))}</p>
    <div class="meta"><div class="card"><span class="label">Arquivo</span><span class="value mono">${escapeHtml(analysis.fileName)}</span></div><div class="card"><span class="label">Pacotes</span><span class="value">${formatNumber(analysis.packetCount)}</span></div><div class="card"><span class="label">Volume</span><span class="value">${formatBytes(analysis.totalBytes)}</span></div><div class="card"><span class="label">Duração</span><span class="value">${formatDuration(analysis.duration)}</span></div></div>
    <h2>Escopo da investigação</h2><p>${escapeHtml(describeFilter(filter))}</p><p class="muted">${formatNumber(relevantPackets.length)} pacotes retidos correspondem ao filtro.</p>
    <h2>Sinais de segurança</h2>${analysis.alerts.map((alert) => `<div class="alert"><strong>${escapeHtml(alert.severity)} · ${escapeHtml(alert.title)}</strong><p>${escapeHtml(alert.description)}</p><span class="muted">${escapeHtml(alert.evidence)} · confiança ${escapeHtml(alert.confidence || "não calculada")}${alert.riskScore !== undefined ? ` · risco ${alert.riskScore}/100` : ""}${alert.mitre ? ` · MITRE ${escapeHtml(alert.mitre.id)}` : ""}</span></div>`).join("")}
    <h2>Principais conversações</h2><table><thead><tr><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Pacotes</th><th>Volume</th></tr></thead><tbody>${analysis.conversations.slice(0, 30).map((row) => `<tr><td class="mono">${escapeHtml(row.source)}:${row.sourcePort}</td><td class="mono">${escapeHtml(row.destination)}:${row.destinationPort}</td><td>${escapeHtml(row.application || row.protocol)}</td><td>${formatNumber(row.packets)}</td><td>${formatBytes(row.bytes)}</td></tr>`).join("")}</tbody></table>
    ${saved.length ? `<h2>Casos de investigação</h2>${saved.map((item) => `<article><strong>${escapeHtml(item.name)}</strong><p class="note">${escapeHtml(item.notes || "Sem notas")}</p><p class="muted">${escapeHtml(item.status || "open")} · ${escapeHtml(item.owner || "sem responsável")} · ${item.evidence?.length || 0} evidência(s) · ${escapeHtml(describeFilter(item.filter))}</p></article>`).join("")}` : ""}
    <p class="muted">As detecções são heurísticas e precisam de validação contextual.</p></body></html>`
  // Blob em vez de document.write: respeita CSP e evita parse incremental.
  const url = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }))
  const popup = window.open(url, "_blank")
  if (!popup) {
    URL.revokeObjectURL(url)
    throw new Error("O navegador bloqueou a janela do relatório. Permita pop-ups e tente novamente.")
  }
  popup.opener = null
  popup.addEventListener("load", () => popup.print(), { once: true })
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

const CSV_BOM = String.fromCharCode(0xfeff);

function escapeHtml(value: unknown) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char)
}
