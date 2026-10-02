export type ProtocolStat = { name: string; packets: number; bytes: number; color: string }

export type HostScope = "Privado" | "Público" | "Link-local" | "Multicast" | "Reservado"

export type HostRecord = {
  ip: string
  hostname?: string
  mac?: string
  vendor?: string
  scope?: HostScope
  sentPackets: number
  receivedPackets: number
  sentBytes: number
  receivedBytes: number
  connections: number
}

export type TcpConversationMetrics = {
  syn: number
  synAck: number
  resets: number
  retransmissions: number
  completeHandshake: boolean
}

export type ConversationRecord = {
  id: string
  source: string
  destination: string
  sourcePort: number
  destinationPort: number
  protocol: string
  application?: string
  packets: number
  bytes: number
  start: string
  startEpoch?: number
  endEpoch?: number
  duration: number
  tcp?: TcpConversationMetrics
}

export type DnsRecord = {
  domain: string
  source: string
  answer: string
  answers?: string[]
  queryType?: string
  queries: number
  responses?: number
  failures?: number
  nxDomainResponses?: number
  status: string
  responseTime: number
}

export type PortRecord = {
  port: number
  protocol: string
  service: string
  connections: number
  hosts: number
  bytes: number
}

export type HttpMetadata = {
  kind: "request" | "response"
  method?: string
  host?: string
  path?: string
  status?: number
  version?: string
  userAgent?: string
  contentType?: string
}

export type TlsMetadata = {
  recordType?: string
  version?: string
  serverName?: string
  alpn?: string[]
  cipherSuites?: number
  cipherSuiteIds?: number[]
  extensionIds?: number[]
  ja3Raw?: string
  ja3?: string
  handshake?: string
}

export type QuicMetadata = {
  version: string
  versionNumber?: number
  longHeader: boolean
  packetType: string
  packetNumberLength?: number
  destinationConnectionId?: string
  sourceConnectionId?: string
}

export type DnsMetadata = {
  transactionId: number
  response: boolean
  domain: string
  queryType: string
  status: string
  answers: string[]
  responseTime?: number
}

export type PacketRecord = {
  no: number
  timestamp: string
  epoch?: number
  relativeTime?: number
  source: string
  destination: string
  sourcePort?: number
  destinationPort?: number
  sourceMac?: string
  destinationMac?: string
  protocol: string
  transport?: string
  serviceHint?: string
  length: number
  capturedLength?: number
  captureOffset?: number
  linkType?: number
  interfaceId?: number
  vlanId?: number
  payloadLength?: number
  tcpFlags?: string[]
  tcpStream?: string
  retransmission?: boolean
  reassembled?: boolean
  info: string
  http?: HttpMetadata
  tls?: TlsMetadata
  quic?: QuicMetadata
  dns?: DnsMetadata
  layers: Array<{ name: string; fields: Array<[string, string]> }>
}

export type AlertDisposition = "open" | "expected" | "false-positive"
export type AlertConfidence = "Alta" | "Média" | "Baixa"

export type AlertFilter = {
  query?: string
  addresses?: string[]
  protocols?: string[]
  ports?: number[]
  domains?: string[]
  from?: number
  to?: number
}

export type AlertRecord = {
  id: string
  ruleId?: string
  category?: string
  severity: "Informativo" | "Baixa" | "Média" | "Alta"
  confidence?: AlertConfidence
  title: string
  description: string
  source: string
  destination?: string
  time: string
  startEpoch?: number
  evidence: string
  observed?: string
  threshold?: string
  reason: string
  filter?: AlertFilter
  riskScore?: number
  baseline?: string
  mitre?: { id: string; tactic: string; technique: string }
}

export type TimelinePoint = {
  time: string
  epoch?: number
  packets: number
  bytes: number
  connections: number
}

export type HttpTransactionRecord = HttpMetadata & {
  id: string
  packetNo: number
  timestamp: string
  epoch?: number
  source: string
  destination: string
  sourcePort?: number
  destinationPort?: number
}

export type TlsSessionRecord = TlsMetadata & {
  id: string
  packetNo: number
  timestamp: string
  epoch?: number
  source: string
  destination: string
  sourcePort?: number
  destinationPort?: number
  packets: number
  bytes: number
}

export type QuicSessionRecord = QuicMetadata & {
  id: string
  packetNo: number
  timestamp: string
  epoch?: number
  source: string
  destination: string
  sourcePort?: number
  destinationPort?: number
  packets: number
  bytes: number
}

export type TcpHealth = {
  syn: number
  synAck: number
  resets: number
  retransmissions: number
  incompleteHandshakes: number
}

export type CaptureMetadata = {
  parserVersion: string
  streamed: boolean
  linkTypes: number[]
  interfaces: number
  retainedPackets: number
  packetLimit: number
  sampleStrategy?: "distributed" | "first"
  unsupportedPackets: number
  malformedPackets: number
  warnings: string[]
  engine?: "browser" | "tshark"
  analysisMode?: AnalysisMode
  analysisMs?: number
  throughputMbps?: number
  estimatedMemoryBytes?: number
  memoryBudgetMb?: number
  reassembledStreams?: number
  reassembledDatagrams?: number
  aggregationLimited?: boolean
  droppedEntities?: Partial<Record<"hosts" | "conversations" | "dns" | "ports" | "http" | "tls" | "quic" | "timeline" | "fragments" | "streams", number>>
  historySamples?: number
}

export type CaptureBaseline = {
  medianHostBytes: number
  medianConnections: number
  p95HostBytes: number
  p95Connections: number
}

export type CaptureAnalysis = {
  id?: string
  fileName: string
  fileSize: number
  analyzedAt: string
  packetCount: number
  totalBytes: number
  duration: number
  firstEpoch?: number
  lastEpoch?: number
  hosts: HostRecord[]
  conversations: ConversationRecord[]
  dns: DnsRecord[]
  ports: PortRecord[]
  packets: PacketRecord[]
  protocols: ProtocolStat[]
  timeline: TimelinePoint[]
  alerts: AlertRecord[]
  http?: HttpTransactionRecord[]
  tls?: TlsSessionRecord[]
  quic?: QuicSessionRecord[]
  tcpHealth?: TcpHealth
  baseline?: CaptureBaseline
  metadata?: CaptureMetadata
  truncatedPackets?: boolean
}

export type RuleOptions = {
  portScanPorts: number
  dnsQueriesPerSecond: number
  highConnectionCount: number
  unknownPortConnections: number
  nxDomainRatio: number
  retransmissionRatio: number
  outboundRatio: number
  outboundMinimumBytes: number
}

export type AnalyzerOptions = {
  packetLimit: number
  memoryBudgetMb: number
  analysisMode: AnalysisMode
  suppressedRuleIds: string[]
  ruleSuppressions: RuleSuppression[]
  ruleOptions: RuleOptions
}

export type RuleSuppression = {
  ruleId: string
  scope: "global"
  createdAt: string
  expiresAt: string
}

export type AnalysisMode = "standard" | "deep"
