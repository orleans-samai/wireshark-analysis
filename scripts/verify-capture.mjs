import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { runWorkerAnalysis } from "./run-worker-analysis.mjs"

const FIELDS = [
  "frame.number", "_ws.col.Protocol", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
  "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
  "dns.qry.name", "tls.handshake.extensions_server_name",
]

function add(set, value) {
  if (value) set.add(value)
}

function normalizedProtocol(value) {
  const upper = value.toUpperCase()
  if (upper.startsWith("HTTP2") || upper === "HTTP/2") return "HTTP/2"
  if (upper.startsWith("TLS")) return "TLS"
  if (upper.startsWith("QUIC")) return "QUIC"
  if (upper.startsWith("DNS")) return "DNS"
  if (upper.startsWith("MDNS")) return "MDNS"
  if (upper.startsWith("ICMPV6")) return "ICMP"
  return upper
}

function difference(left, right) {
  return [...left].filter((value) => !right.has(value))
}

export async function verifyCapture(input, { strict = false } = {}) {
  const path = resolve(input)
  if (!existsSync(path)) throw new Error(`Arquivo não encontrado: ${path}`)
  const version = spawnSync("tshark", ["-v"], { encoding: "utf8" })
  if (version.error || version.status !== 0) {
    const error = new Error("TShark não está disponível no PATH. Instale o Wireshark/TShark para executar a verificação de paridade.")
    error.exitCode = 2
    throw error
  }

  const tsharkArgs = ["-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f", ...FIELDS.flatMap((field) => ["-e", field])]
  const [analysis, tshark] = await Promise.all([
    runWorkerAnalysis(path, { analysisMode: "deep", packetLimit: 20_000, memoryBudgetMb: 256 }),
    Promise.resolve(spawnSync("tshark", tsharkArgs, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 })),
  ])
  if (tshark.status !== 0) throw new Error(tshark.stderr || "TShark não conseguiu abrir a captura.")

  const rows = tshark.stdout.split(/\r?\n/).filter(Boolean).map((row) => row.split("\t"))
  const tsharkProtocols = new Map()
  const tsharkHosts = new Set()
  const tsharkDomains = new Set()
  const tsharkSni = new Set()
  for (const row of rows) {
    const protocol = normalizedProtocol(row[1] || "UNKNOWN")
    tsharkProtocols.set(protocol, (tsharkProtocols.get(protocol) || 0) + 1)
    add(tsharkHosts, row[2] || row[3])
    add(tsharkHosts, row[4] || row[5])
    add(tsharkDomains, row[10]?.toLowerCase())
    add(tsharkSni, row[11]?.toLowerCase())
  }

  const workerHosts = new Set(analysis.hosts.filter((host) => host.ip.includes(".") || host.ip.includes(":")) .map((host) => host.ip))
  const workerDomains = new Set(analysis.dns.map((item) => item.domain.toLowerCase()).filter(Boolean))
  const workerSni = new Set((analysis.tls || []).map((item) => item.serverName?.toLowerCase()).filter(Boolean))
  const missingWorkerHosts = difference(workerHosts, tsharkHosts)
  const unexpectedDomains = difference(workerDomains, tsharkDomains)
  const unexpectedSni = difference(workerSni, tsharkSni)
  const report = {
    path,
    packetCount: { packetlens: analysis.packetCount, tshark: rows.length, equal: analysis.packetCount === rows.length },
    coverage: {
      packetlens: { hosts: workerHosts.size, domains: workerDomains.size, sni: workerSni.size },
      tshark: { hosts: tsharkHosts.size, domains: tsharkDomains.size, sni: tsharkSni.size },
    },
    differences: { hostsOnlyInPacketLens: missingWorkerHosts.slice(0, 20), domainsOnlyInPacketLens: unexpectedDomains.slice(0, 20), sniOnlyInPacketLens: unexpectedSni.slice(0, 20) },
    protocols: {
      packetlens: analysis.protocols.slice(0, 20).map((item) => [item.name, item.packets]),
      tshark: [...tsharkProtocols].sort((a, b) => b[1] - a[1]).slice(0, 20),
    },
  }
  const valid = report.packetCount.equal && !unexpectedDomains.length && !unexpectedSni.length
  if (strict && !valid) {
    const error = new Error(`Paridade estrita falhou: ${JSON.stringify(report.differences)}`)
    error.report = report
    throw error
  }
  return { valid, report }
}

async function main() {
  const input = process.argv[2]
  if (!input) {
    console.error("Uso: npm run verify:capture -- caminho/arquivo.pcap [--strict] [--json]")
    process.exit(1)
  }
  try {
    const { valid, report } = await verifyCapture(input, { strict: process.argv.includes("--strict") })
    if (process.argv.includes("--json")) console.log(JSON.stringify(report, null, 2))
    else {
      console.log(`Pacotes · PacketLens ${report.packetCount.packetlens} · TShark ${report.packetCount.tshark}`)
      console.log(`Cobertura · hosts ${report.coverage.packetlens.hosts}/${report.coverage.tshark.hosts} · DNS ${report.coverage.packetlens.domains}/${report.coverage.tshark.domains} · SNI ${report.coverage.packetlens.sni}/${report.coverage.tshark.sni}`)
      console.log(`PacketLens · ${report.protocols.packetlens.map(([name, count]) => `${name}:${count}`).join(", ")}`)
      console.log(`TShark     · ${report.protocols.tshark.map(([name, count]) => `${name}:${count}`).join(", ")}`)
      console.log(valid ? "Paridade de contagem e campos reconhecidos aprovada." : "Paridade básica aprovada, com diferenças de cobertura para revisão.")
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(error.exitCode || 1)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main()
