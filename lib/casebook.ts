import type { CaptureAnalysis } from "./capture-types"
import type { CaseEvidence, InvestigationFilter, SavedInvestigation } from "./investigation"
import { EMPTY_FILTER } from "./investigation"

export type InvestigationCaseBundle = {
  schema: "packetlens-casebook"
  version: 1
  exportedAt: string
  capture: { fileName: string; fileSize: number; packetCount: number }
  cases: SavedInvestigation[]
}

export function normalizeInvestigationCase(value: unknown, index = 0): SavedInvestigation {
  const input = value && typeof value === "object" ? value as Partial<SavedInvestigation> : {}
  const now = new Date().toISOString()
  return {
    id: stringValue(input.id) || `case-${Date.now()}-${index}`,
    name: stringValue(input.name) || `Caso ${index + 1}`,
    notes: stringValue(input.notes),
    createdAt: validDate(input.createdAt) || now,
    updatedAt: validDate(input.updatedAt) || validDate(input.createdAt) || now,
    filter: normalizeFilter(input.filter),
    status: input.status === "monitoring" || input.status === "closed" ? input.status : "open",
    owner: stringValue(input.owner),
    tags: uniqueStrings(input.tags),
    evidence: Array.isArray(input.evidence) ? input.evidence.map(normalizeEvidence).filter(Boolean) as CaseEvidence[] : [],
  }
}

export function normalizeCaseList(value: unknown) {
  return Array.isArray(value) ? value.slice(0, 500).map(normalizeInvestigationCase) : []
}

export function createCaseBundle(analysis: CaptureAnalysis, cases: SavedInvestigation[]): InvestigationCaseBundle {
  return {
    schema: "packetlens-casebook",
    version: 1,
    exportedAt: new Date().toISOString(),
    capture: { fileName: analysis.fileName, fileSize: analysis.fileSize, packetCount: analysis.packetCount },
    cases: normalizeCaseList(cases),
  }
}

export function parseCaseBundle(text: string) {
  const parsed = JSON.parse(text) as Partial<InvestigationCaseBundle>
  if (parsed.schema !== "packetlens-casebook" || parsed.version !== 1 || !Array.isArray(parsed.cases)) {
    throw new Error("Arquivo de casos incompatível com o PacketLens.")
  }
  return normalizeCaseList(parsed.cases)
}

export function appendEvidence(cases: SavedInvestigation[], activeId: string | null, evidence: Omit<CaseEvidence, "id" | "capturedAt">) {
  const now = new Date().toISOString()
  const nextEvidence: CaseEvidence = { ...evidence, id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, capturedAt: now }
  const selected = cases.find((item) => item.id === activeId) || cases[0]
  if (!selected) {
    const created = normalizeInvestigationCase({ name: "Caso em investigação", notes: "", createdAt: now, updatedAt: now, filter: EMPTY_FILTER, evidence: [nextEvidence] })
    return { cases: [created], activeId: created.id }
  }
  return {
    cases: cases.map((item) => item.id === selected.id ? { ...item, updatedAt: now, evidence: [...(item.evidence || []), nextEvidence] } : item),
    activeId: selected.id,
  }
}

function normalizeFilter(value: unknown): InvestigationFilter {
  const input = value && typeof value === "object" ? value as Partial<InvestigationFilter> : {}
  return {
    query: stringValue(input.query),
    addresses: uniqueStrings(input.addresses),
    protocols: uniqueStrings(input.protocols),
    ports: Array.isArray(input.ports) ? [...new Set(input.ports.map(Number).filter(Number.isFinite))].slice(0, 1000) : [],
    domains: uniqueStrings(input.domains),
    from: finiteOrUndefined(input.from),
    to: finiteOrUndefined(input.to),
  }
}

function normalizeEvidence(value: unknown): CaseEvidence | null {
  const input = value && typeof value === "object" ? value as Partial<CaseEvidence> : {}
  if (!input.title || !input.reference) return null
  return {
    id: stringValue(input.id) || `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    type: input.type === "packet" || input.type === "alert" ? input.type : "note",
    reference: stringValue(input.reference),
    title: stringValue(input.title),
    detail: stringValue(input.detail),
    capturedAt: validDate(input.capturedAt) || new Date().toISOString(),
  }
}

function uniqueStrings(value: unknown) {
  return Array.isArray(value) ? [...new Set(value.map(stringValue).filter(Boolean))].slice(0, 100) : []
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value.trim().slice(0, 10_000) : ""
}

function validDate(value: unknown) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? value : ""
}

function finiteOrUndefined(value: unknown) {
  const number = Number(value)
  return Number.isFinite(number) ? number : undefined
}
