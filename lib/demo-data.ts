import type { CaptureAnalysis, PacketRecord } from "./capture-types"

const protocolColors: Record<string, string> = {
  TCP: "#42d3ff",
  UDP: "#8b7cff",
  DNS: "#f5b849",
  TLS: "#4ade80",
  HTTP: "#fb7185",
  ICMP: "#94a3b8",
}

const packetSeeds = [
  ["192.168.1.20", "142.250.218.14", "TLS", 1514, "Application Data"],
  ["192.168.1.25", "1.1.1.1", "DNS", 86, "Standard query A cdn-assets.net"],
  ["1.1.1.1", "192.168.1.25", "DNS", 134, "Standard query response A 104.21.31.18"],
  ["192.168.1.20", "142.250.218.14", "TCP", 66, "51234 → 443 [ACK] Seq=1281"],
  ["10.0.0.44", "192.168.1.1", "ICMP", 98, "Echo (ping) request id=0x0012"],
  ["192.168.1.35", "13.107.42.14", "TLS", 1280, "Client Hello (SNI=login.microsoftonline.com)"],
  ["192.168.1.20", "93.184.216.34", "HTTP", 489, "GET /status HTTP/1.1"],
] as const

const packets: PacketRecord[] = Array.from({ length: 48 }, (_, index) => {
  const seed = packetSeeds[index % packetSeeds.length]
  const [source, destination, protocol, length, info] = seed
  const elapsedMs = index * 137
  const second = 12 + Math.floor(elapsedMs / 1000)
  return {
    no: index + 1,
    timestamp: `14:33:${String(second).padStart(2, "0")}.${String(elapsedMs % 1000).padStart(3, "0")}`,
    source,
    destination,
    sourcePort: protocol === "DNS" ? (source === "1.1.1.1" ? 53 : 53042) : 51234 + (index % 8),
    destinationPort: protocol === "DNS" ? (destination === "1.1.1.1" ? 53 : 53042) : protocol === "HTTP" ? 80 : 443,
    protocol,
    length,
    info,
    layers: [
      { name: "Ethernet II", fields: [["Origem", "3c:52:82:4f:a1:20"], ["Destino", "04:d4:c4:88:2e:01"], ["Tipo", "IPv4 (0x0800)"]] },
      { name: "Internet Protocol Version 4", fields: [["Source", source], ["Destination", destination], ["TTL", "64"], ["Header length", "20 bytes"]] },
      { name: protocol === "DNS" ? "User Datagram Protocol" : "Transmission Control Protocol", fields: [["Source port", String(protocol === "DNS" ? 53042 : 51234)], ["Destination port", String(protocol === "DNS" ? 53 : protocol === "HTTP" ? 80 : 443)], ["Length", `${length} bytes`]] },
      { name: protocol, fields: [["Resumo", info], ["Conteúdo", protocol === "TLS" ? "Protegido por criptografia" : "Metadados observáveis"]] },
    ],
  }
})

export const demoAnalysis: CaptureAnalysis = {
  fileName: "office-incident-2026-09-18.pcapng",
  fileSize: 2_576_980_377,
  analyzedAt: "18 set 2026, 14:51",
  packetCount: 126_430,
  totalBytes: 2_576_980_377,
  duration: 1112,
  protocols: [
    { name: "TCP", packets: 77_122, bytes: 1_640_000_000, color: protocolColors.TCP },
    { name: "UDP", packets: 26_550, bytes: 412_000_000, color: protocolColors.UDP },
    { name: "DNS", packets: 8_850, bytes: 41_000_000, color: protocolColors.DNS },
    { name: "TLS", packets: 7_586, bytes: 398_000_000, color: protocolColors.TLS },
    { name: "HTTP", packets: 3_793, bytes: 72_000_000, color: protocolColors.HTTP },
    { name: "ICMP", packets: 2_529, bytes: 13_980_377, color: protocolColors.ICMP },
  ],
  timeline: Array.from({ length: 24 }, (_, i) => ({
    time: `14:${String(32 + Math.floor(i / 3)).padStart(2, "0")}:${String((i % 3) * 20).padStart(2, "0")}`,
    packets: [382, 415, 506, 488, 620, 742, 1384, 1690, 1210, 810, 760, 980, 720, 660, 804, 910, 1120, 880, 690, 618, 720, 830, 590, 440][i],
    bytes: [4.1, 4.8, 5.3, 5.1, 6.9, 7.8, 16.2, 21.4, 14.8, 9.1, 8.5, 10.2, 8.8, 7.4, 9.2, 10.7, 13.6, 9.9, 7.5, 6.8, 8.2, 9.1, 6.2, 4.9][i] * 1_000_000,
    connections: [12, 15, 18, 16, 21, 29, 86, 112, 75, 34, 29, 44, 31, 26, 35, 42, 54, 38, 25, 22, 29, 31, 20, 14][i],
  })),
  hosts: [
    { ip: "192.168.1.20", hostname: "ops-workstation", sentPackets: 43_240, receivedPackets: 51_034, sentBytes: 682_000_000, receivedBytes: 920_000_000, connections: 418 },
    { ip: "192.168.1.25", hostname: "build-runner", sentPackets: 19_820, receivedPackets: 12_404, sentBytes: 338_000_000, receivedBytes: 210_000_000, connections: 356 },
    { ip: "142.250.218.14", hostname: "edge.google.com", sentPackets: 18_290, receivedPackets: 15_330, sentBytes: 430_000_000, receivedBytes: 190_000_000, connections: 126 },
    { ip: "192.168.1.35", hostname: "finance-laptop", sentPackets: 8_440, receivedPackets: 10_662, sentBytes: 126_000_000, receivedBytes: 254_000_000, connections: 92 },
    { ip: "1.1.1.1", hostname: "one.one.one.one", sentPackets: 5_294, receivedPackets: 7_840, sentBytes: 18_000_000, receivedBytes: 12_000_000, connections: 53 },
  ],
  conversations: [
    { id: "conv-1", source: "192.168.1.20", destination: "142.250.218.14", sourcePort: 51234, destinationPort: 443, protocol: "TCP", packets: 12_431, bytes: 34_000_000, start: "14:32:04", duration: 14.2 },
    { id: "conv-2", source: "192.168.1.25", destination: "1.1.1.1", sourcePort: 53042, destinationPort: 53, protocol: "UDP", packets: 8_450, bytes: 12_800_000, start: "14:33:39", duration: 60.8 },
    { id: "conv-3", source: "192.168.1.35", destination: "13.107.42.14", sourcePort: 54081, destinationPort: 443, protocol: "TCP", packets: 6_920, bytes: 92_600_000, start: "14:34:06", duration: 188.4 },
    { id: "conv-4", source: "10.0.0.44", destination: "192.168.1.1", sourcePort: 0, destinationPort: 0, protocol: "ICMP", packets: 2_529, bytes: 13_980_377, start: "14:32:18", duration: 1002.1 },
    { id: "conv-5", source: "192.168.1.20", destination: "93.184.216.34", sourcePort: 51912, destinationPort: 80, protocol: "TCP", packets: 1_240, bytes: 4_720_000, start: "14:35:28", duration: 9.7 },
  ],
  dns: [
    { domain: "cdn-assets.net", source: "192.168.1.25", answer: "104.21.31.18", queries: 845, status: "NOERROR", responseTime: 24 },
    { domain: "google.com", source: "192.168.1.20", answer: "142.250.218.14", queries: 312, status: "NOERROR", responseTime: 18 },
    { domain: "github.com", source: "192.168.1.20", answer: "140.82.114.4", queries: 188, status: "NOERROR", responseTime: 31 },
    { domain: "login.microsoftonline.com", source: "192.168.1.35", answer: "20.190.160.0", queries: 142, status: "NOERROR", responseTime: 29 },
    { domain: "telemetry.invalid", source: "192.168.1.25", answer: "—", queries: 91, status: "NXDOMAIN", responseTime: 84 },
  ],
  ports: [
    { port: 443, protocol: "TCP", service: "HTTPS", connections: 812, hosts: 31, bytes: 1_420_000_000 },
    { port: 53, protocol: "UDP", service: "DNS", connections: 204, hosts: 28, bytes: 41_000_000 },
    { port: 80, protocol: "TCP", service: "HTTP", connections: 96, hosts: 17, bytes: 72_000_000 },
    { port: 22, protocol: "TCP", service: "SSH", connections: 42, hosts: 8, bytes: 18_000_000 },
    { port: 3389, protocol: "TCP", service: "RDP", connections: 18, hosts: 4, bytes: 8_200_000 },
  ],
  packets,
  alerts: [
    { id: "a1", severity: "Alta", title: "Muitas portas em pouco tempo", description: "O host iniciou conexões para 86 portas distintas do mesmo destino em 42 segundos.", source: "192.168.1.25", destination: "10.0.0.18", time: "14:33:12", evidence: "116 tentativas · 86 portas", reason: "Possível atividade de varredura de portas. O padrão merece investigação; não confirma um ataque." },
    { id: "a2", severity: "Média", title: "Frequência DNS acima do habitual", description: "Foram observadas 845 consultas para o mesmo domínio em aproximadamente 60 segundos.", source: "192.168.1.25", destination: "1.1.1.1", time: "14:33:41", evidence: "14,1 consultas/s", reason: "Aplicações legítimas, atualizações e automações também podem produzir esse padrão." },
    { id: "a3", severity: "Baixa", title: "Comunicação periódica", description: "Conexões pequenas ocorreram em intervalos regulares de aproximadamente 30 segundos.", source: "192.168.1.35", destination: "13.107.42.14", time: "14:34:18", evidence: "20 intervalos · desvio 1,8s", reason: "Possível comportamento periódico / beaconing. Compare com o software instalado." },
  ],
}
