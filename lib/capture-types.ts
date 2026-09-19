export type ProtocolStat = { name: string; packets: number; bytes: number; color: string }

export type HostRecord = {
  ip: string
  hostname?: string
  sentPackets: number
  receivedPackets: number
  sentBytes: number
  receivedBytes: number
  connections: number
}

export type ConversationRecord = {
  id: string
  source: string
  destination: string
  sourcePort: number
  destinationPort: number
  protocol: string
  packets: number
  bytes: number
  start: string
  duration: number
}

export type DnsRecord = {
  domain: string
  source: string
  answer: string
  queries: number
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

export type PacketRecord = {
  no: number
  timestamp: string
  source: string
  destination: string
  sourcePort?: number
  destinationPort?: number
  protocol: string
  length: number
  info: string
  layers: Array<{ name: string; fields: Array<[string, string]> }>
}

export type AlertRecord = {
  id: string
  severity: "Informativo" | "Baixa" | "Média" | "Alta"
  title: string
  description: string
  source: string
  destination?: string
  time: string
  evidence: string
  reason: string
}

export type TimelinePoint = { time: string; packets: number; bytes: number; connections: number }

export type CaptureAnalysis = {
  fileName: string
  fileSize: number
  analyzedAt: string
  packetCount: number
  totalBytes: number
  duration: number
  hosts: HostRecord[]
  conversations: ConversationRecord[]
  dns: DnsRecord[]
  ports: PortRecord[]
  packets: PacketRecord[]
  protocols: ProtocolStat[]
  timeline: TimelinePoint[]
  alerts: AlertRecord[]
  truncatedPackets?: boolean
}

