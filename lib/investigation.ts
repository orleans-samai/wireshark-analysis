import type { AlertFilter, CaptureAnalysis, ConversationRecord, PacketRecord } from "./capture-types"
import type { ViewId } from "./views"

export type InvestigationFilter = {
  query: string
  addresses: string[]
  protocols: string[]
  ports: number[]
  domains: string[]
  from?: number
  to?: number
}

export type FilterKind = "query" | "address" | "protocol" | "port" | "domain" | "time"

export type InvestigationTarget = {
  kind: Exclude<FilterKind, "time">
  value: string | number
  replace?: boolean
}

export type InvestigationHandler = (target: InvestigationTarget | Partial<InvestigationFilter>, destination?: ViewId) => void

export type SavedInvestigation = {
  id: string
  name: string
  notes: string
  createdAt: string
  updatedAt: string
  filter: InvestigationFilter
  status?: "open" | "monitoring" | "closed"
  owner?: string
  tags?: string[]
  evidence?: CaseEvidence[]
}

export type CaseEvidence = {
  id: string
  type: "packet" | "alert" | "note"
  reference: string
  title: string
  detail?: string
  capturedAt: string
}

export const EMPTY_FILTER: InvestigationFilter = {
  query: "",
  addresses: [],
  protocols: [],
  ports: [],
  domains: [],
}

export function filterFromAlert(filter?: AlertFilter): Partial<InvestigationFilter> {
  if (!filter) return {}
  return {
    query: filter.query || "",
    addresses: filter.addresses || [],
    protocols: filter.protocols || [],
    ports: filter.ports || [],
    domains: filter.domains || [],
    from: filter.from,
    to: filter.to,
  }
}

export function applyTarget(filter: InvestigationFilter, target: InvestigationTarget): InvestigationFilter {
  if (target.kind === "query") return { ...filter, query: String(target.value) }
  const key = (target.kind === "address" ? "addresses" : target.kind === "protocol" ? "protocols" : target.kind === "port" ? "ports" : "domains") as "addresses" | "protocols" | "ports" | "domains"
  const value = target.kind === "port" ? Number(target.value) : String(target.value)
  const current = filter[key] as Array<string | number>
  const next = target.replace ? [value] : current.includes(value) ? current : [...current, value]
  return { ...filter, [key]: next }
}

export function removeFilterValue(filter: InvestigationFilter, kind: FilterKind, value?: string | number): InvestigationFilter {
  if (kind === "query") return { ...filter, query: "" }
  if (kind === "time") return { ...filter, from: undefined, to: undefined }
  const key = kind === "address" ? "addresses" : kind === "protocol" ? "protocols" : kind === "port" ? "ports" : "domains"
  return { ...filter, [key]: (filter[key] as Array<string | number>).filter((entry) => entry !== value) } as InvestigationFilter
}

export function hasActiveFilters(filter: InvestigationFilter) {
  return Boolean(filter.query || filter.addresses.length || filter.protocols.length || filter.ports.length || filter.domains.length || filter.from !== undefined || filter.to !== undefined)
}

export function describeFilter(filter: InvestigationFilter) {
  const parts = [
    filter.query && `texto: ${filter.query}`,
    ...filter.addresses.map((value) => `host: ${value}`),
    ...filter.protocols.map((value) => `protocolo: ${value}`),
    ...filter.ports.map((value) => `porta: ${value}`),
    ...filter.domains.map((value) => `domínio: ${value}`),
    (filter.from !== undefined || filter.to !== undefined) && `tempo: ${Math.round(filter.from || 0)}s–${Math.round(filter.to || 0)}s`,
  ].filter(Boolean)
  return parts.join(" · ") || "Sem filtros"
}

export function packetMatchesFilter(packet: PacketRecord, filter: InvestigationFilter, localQuery = "") {
  if (filter.query.trim() || localQuery.trim()) {
    const haystack = `${packet.no} ${packet.source} ${packet.destination} ${packet.protocol} ${packet.transport || ""} ${packet.sourcePort || ""} ${packet.destinationPort || ""} ${packet.info} ${packet.http?.host || ""} ${packet.http?.path || ""} ${packet.tls?.serverName || ""} ${packet.dns?.domain || ""}`.toLowerCase()
    if (filter.query.trim() && !haystack.includes(filter.query.trim().toLowerCase())) return false
    if (localQuery.trim() && !haystack.includes(localQuery.trim().toLowerCase())) return false
  }
  if (filter.addresses.length && !filter.addresses.some((value) => packet.source === value || packet.destination === value)) return false
  if (filter.protocols.length && !filter.protocols.some((value) => packet.protocol === value || packet.transport === value)) return false
  if (filter.ports.length && !filter.ports.some((value) => packet.sourcePort === value || packet.destinationPort === value)) return false
  if (filter.domains.length && !filter.domains.some((value) => domainForPacket(packet).includes(value.toLowerCase()))) return false
  const relative = packet.relativeTime
  if ((filter.from !== undefined || filter.to !== undefined) && relative === undefined) return false
  if (filter.from !== undefined && relative !== undefined && relative < filter.from) return false
  if (filter.to !== undefined && relative !== undefined && relative > filter.to) return false
  return true
}

export function conversationMatchesFilter(row: ConversationRecord, filter: InvestigationFilter, captureStart?: number) {
  const haystack = `${row.source} ${row.destination} ${row.protocol} ${row.application || ""} ${row.sourcePort} ${row.destinationPort}`.toLowerCase()
  if (filter.query && !haystack.includes(filter.query.toLowerCase())) return false
  if (filter.addresses.length && !filter.addresses.some((value) => row.source === value || row.destination === value)) return false
  if (filter.protocols.length && !filter.protocols.some((value) => row.protocol === value || row.application === value)) return false
  if (filter.ports.length && !filter.ports.some((value) => row.sourcePort === value || row.destinationPort === value)) return false
  if ((filter.from !== undefined || filter.to !== undefined) && (captureStart === undefined || row.startEpoch === undefined)) return false
  if (captureStart !== undefined && row.startEpoch !== undefined) {
    const start = row.startEpoch - captureStart
    const end = (row.endEpoch || row.startEpoch) - captureStart
    if (filter.from !== undefined && end < filter.from) return false
    if (filter.to !== undefined && start > filter.to) return false
  }
  return true
}

export type SearchSuggestion = {
  id: string
  kind: InvestigationTarget["kind"]
  value: string | number
  label: string
  detail: string
  view: ViewId
}

export type SuggestionIndex = Array<SearchSuggestion & { searchText: string }>

/** Pré-processado uma vez por captura; inclui toda a captura, não apenas o top 100. */
export function buildSuggestionIndex(analysis: CaptureAnalysis): SuggestionIndex {
  const topHosts = [...analysis.hosts].sort((a, b) => b.connections - a.connections)
  const topProtocols = [...analysis.protocols].sort((a, b) => b.packets - a.packets)
  const topPorts = [...analysis.ports].sort((a, b) => b.connections - a.connections)
  const topDomains = [...analysis.dns].sort((a, b) => b.queries - a.queries)
  const suggestions: SearchSuggestion[] = [
    ...topHosts.map((host) => ({ id: `host-${host.ip}`, kind: "address" as const, value: host.ip, label: host.hostname || host.ip, detail: host.hostname ? host.ip : `${host.connections} conexões`, view: "Hosts" } as const)),
    ...topProtocols.map((item) => ({ id: `protocol-${item.name}`, kind: "protocol" as const, value: item.name, label: item.name, detail: `${item.packets} pacotes`, view: "Protocols" } as const)),
    ...topPorts.map((item) => ({ id: `port-${item.port}-${item.protocol}`, kind: "port" as const, value: item.port, label: `${item.port}/${item.protocol}`, detail: item.service, view: "Ports" } as const)),
    ...topDomains.map((item) => ({ id: `domain-${item.domain}-${item.source}`, kind: "domain" as const, value: item.domain, label: item.domain, detail: item.source, view: "DNS" } as const)),
  ]
  return suggestions.map((item) => ({ ...item, searchText: `${item.label} ${item.detail}`.toLowerCase() }))
}

export function buildSuggestions(index: SuggestionIndex, input: string): SearchSuggestion[] {
  const needle = input.trim().toLowerCase().replace(/^(ip|host|protocol|port|domain):\s*/, "")
  if (!needle) return index.slice(0, 8)
  const matches: SearchSuggestion[] = []
  for (const item of index) {
    if (item.searchText.includes(needle)) matches.push(item)
    if (matches.length === 8) break
  }
  return matches
}

export function investigationStorageKey(analysis: CaptureAnalysis) {
  return `packetlens:investigations:v2:${simpleHash(`${analysis.fileName}:${analysis.fileSize}:${analysis.packetCount}`)}`
}

export function alertStorageKey(analysis: CaptureAnalysis) {
  return `packetlens:alert-status:v1:${simpleHash(`${analysis.fileName}:${analysis.fileSize}:${analysis.packetCount}`)}`
}

function domainForPacket(packet: PacketRecord) {
  return `${packet.http?.host || ""} ${packet.tls?.serverName || ""} ${packet.dns?.domain || ""}`.toLowerCase()
}

function simpleHash(value: string) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0).toString(36)
}
