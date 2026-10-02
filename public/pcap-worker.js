/* PacketLens streaming PCAP/PCAPNG analyzer. No packet content leaves the worker. */
if (!self.PacketLensCodecs && typeof importScripts === "function") importScripts("pcap-codecs.js")
if (!self.PacketLensCodecs) throw new Error("Os decodificadores do PacketLens não foram carregados.")
const { parseHttp2, parseQuic, parseHttp } = self.PacketLensCodecs
const PARSER_VERSION = "3.1.0"
const READ_WINDOW = 8 * 1024 * 1024
const MAX_BLOCK = 64 * 1024 * 1024
const COLORS = { TCP: "#42d3ff", UDP: "#8b7cff", DNS: "#f5b849", TLS: "#4ade80", HTTP: "#fb7185", "HTTP/2": "#f472b6", QUIC: "#22d3ee", ICMP: "#94a3b8", ARP: "#d89b58", DHCP: "#2ab7cf", NTP: "#a78bfa", mDNS: "#f0c36a", IPv4: "#64748b", IPv6: "#a78bfa", Other: "#475569" }
const SERVICES = { 20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS", 2375: "Docker", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5353: "mDNS", 5672: "AMQP", 6379: "Redis", 8080: "HTTP alternate", 8443: "HTTPS alternate", 9200: "Elasticsearch" }
const OUI = { "3C:52:82": "Hewlett Packard", "04:D4:C4": "Netgear", "00:1A:2B": "Cisco", "00:50:56": "VMware", "08:00:27": "VirtualBox", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi" }
const DEFAULT_OPTIONS = { packetLimit: 20000, memoryBudgetMb: 256, analysisMode: "standard", suppressedRuleIds: [], ruleOptions: { portScanPorts: 20, dnsQueriesPerSecond: 10, highConnectionCount: 250, unknownPortConnections: 40, nxDomainRatio: 0.35, retransmissionRatio: 0.08, outboundRatio: 5, outboundMinimumBytes: 5000000 } }
const DNS_TYPES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS" }
const TLS_VERSIONS = { 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3" }
const TLS_RECORDS = { 20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data" }
const n = (value) => Number(value || 0).toLocaleString("pt-BR")

let cancelled = false

self.onmessage = async ({ data }) => {
  if (data.type === "cancel") {
    cancelled = true
    return
  }
  if (data.type !== "analyze") return
  cancelled = false
  try {
    const result = await analyzeFile(data.file, normalizeOptions(data.options))
    checkCancelled()
    postMessage({ type: "done", result })
  } catch (error) {
    if (error && error.name === "CancelledError") postMessage({ type: "cancelled" })
    else postMessage({ type: "error", message: error instanceof Error ? error.message : "Falha desconhecida ao analisar a captura." })
  }
}

class CaptureReader {
  constructor(file) {
    this.file = file
    this.start = -1
    this.bytes = new Uint8Array(0)
  }

  async read(offset, length) {
    checkCancelled()
    if (offset < 0 || length < 0 || offset + length > this.file.size) throw new Error("A captura terminou antes do esperado.")
    if (length > MAX_BLOCK) throw new Error("A captura contém um bloco maior que o limite seguro de 64 MB.")
    if (offset >= this.start && offset + length <= this.start + this.bytes.length) {
      return this.bytes.subarray(offset - this.start, offset - this.start + length)
    }
    const end = Math.min(this.file.size, offset + Math.max(READ_WINDOW, length))
    this.start = offset
    this.bytes = new Uint8Array(await this.file.slice(offset, end).arrayBuffer())
    checkCancelled()
    if (this.bytes.length < length) throw new Error("A captura terminou antes do esperado.")
    return this.bytes.subarray(0, length)
  }
}

async function analyzeFile(file, options) {
  if (!file || typeof file.slice !== "function") throw new Error("Arquivo de captura inválido.")
  if (file.size < 12) throw new Error("O arquivo está vazio ou não possui um cabeçalho de captura válido.")
  const reader = new CaptureReader(file)
  const first = await reader.read(0, Math.min(24, file.size))
  const magic = [...first.subarray(0, 4)].map((value) => value.toString(16).padStart(2, "0")).join("")
  const acc = createAccumulator(file.name, file.size, options)
  postProgress(2, 0, "Lendo cabeçalho")
  if (["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"].includes(magic)) await parsePcap(reader, magic, acc)
  else if (magic === "0a0d0d0a") await parsePcapNg(reader, acc)
  else throw new Error("Formato não reconhecido. Selecione um arquivo PCAP ou PCAPNG válido.")
  if (!acc.packetCount) throw new Error("A captura é válida, mas não contém pacotes analisáveis.")
  return finalize(acc)
}

function createAccumulator(fileName, fileSize, options) {
  const totalBudgetBytes = options.memoryBudgetMb * 1024 * 1024
  const entityBudgetBytes = Math.floor(totalBudgetBytes * 0.35)
  const retainedMemoryLimit = Math.floor(totalBudgetBytes * 0.55)
  const streamMemoryLimit = Math.max(4 * 1024 * 1024, totalBudgetBytes - entityBudgetBytes - retainedMemoryLimit)
  return {
    fileName, fileSize, options, packetLimit: options.packetLimit,
    startedAt: Date.now(),
    packetCount: 0, decodedPackets: 0, totalBytes: 0, firstTime: Infinity, lastTime: -Infinity, untimedPackets: 0,
    hosts: new Map(), conversations: new Map(), dns: new Map(), dnsPending: new Map(),
    ports: new Map(), protocols: new Map(), timeline: new Map(), packets: [], latestPacket: null, sampleSeen: 0,
    http: [], tls: new Map(), quic: new Map(), tcpStreams: new Map(), ipv4Fragments: new Map(), reassembledStreams: 0, reassembledDatagrams: 0, linkTypes: new Set(), interfaces: 0,
    unsupportedPackets: 0, malformedPackets: 0, warnings: [], retainedBytes: 0, entityBytes: 0, streamBytes: 0, memoryLimited: false, randomState: 0x9e3779b9,
    entityBudgetBytes, retainedMemoryLimit, streamMemoryLimit,
    droppedEntities: { hosts: 0, conversations: 0, dns: 0, ports: 0, http: 0, tls: 0, quic: 0, timeline: 0, fragments: 0, streams: 0 },
    limits: {
      hosts: Math.max(4096, Math.min(250000, Math.floor(entityBudgetBytes / 700))),
      conversations: Math.max(8192, Math.min(500000, Math.floor(entityBudgetBytes / 1300))),
      dns: Math.max(4096, Math.min(250000, Math.floor(entityBudgetBytes / 900))),
      ports: 131072,
      http: Math.max(2000, Math.min(options.packetLimit, Math.floor(entityBudgetBytes / 850))),
      tls: Math.max(2000, Math.min(100000, Math.floor(entityBudgetBytes / 850))),
      quic: Math.max(2000, Math.min(100000, Math.floor(entityBudgetBytes / 750))),
      timeline: Math.max(4096, Math.min(250000, Math.floor(entityBudgetBytes / 220))),
      fragments: Math.max(128, Math.min(8192, Math.floor(streamMemoryLimit / 65536))),
    },
  }
}

function reserveEntity(acc, kind, collection, estimatedBytes) {
  if (collection.size >= acc.limits[kind] || acc.entityBytes + estimatedBytes > acc.entityBudgetBytes) {
    acc.droppedEntities[kind]++
    acc.memoryLimited = true
    return false
  }
  acc.entityBytes += estimatedBytes
  return true
}

function noteDropped(acc, kind) {
  acc.droppedEntities[kind]++
  acc.memoryLimited = true
}

async function parsePcap(reader, magic, acc) {
  const header = await reader.read(0, 24)
  const view = asView(header)
  const little = magic === "d4c3b2a1" || magic === "4d3cb2a1"
  const nano = magic === "4d3cb2a1" || magic === "a1b23c4d"
  const linkType = view.getUint32(20, little)
  acc.linkTypes.add(linkType)
  acc.interfaces = 1
  let offset = 24
  while (offset + 16 <= reader.file.size) {
    const record = asView(await reader.read(offset, 16))
    const sec = record.getUint32(0, little)
    const fraction = record.getUint32(4, little)
    const captured = record.getUint32(8, little)
    const original = record.getUint32(12, little)
    if (captured > MAX_BLOCK || captured > reader.file.size - offset - 16) throw new Error(`Pacote ${acc.packetCount + 1} está truncado ou corrompido.`)
    const frameOffset = offset + 16
    const packet = await reader.read(frameOffset, captured)
    consumePacket(packet, original || captured, sec + fraction / (nano ? 1e9 : 1e6), linkType, acc, { captureOffset: frameOffset, capturedLength: captured, interfaceId: 0 })
    offset = frameOffset + captured
    maybeProgress(offset, reader.file.size, acc.packetCount)
  }
  if (offset !== reader.file.size) acc.warnings.push("O arquivo terminou com bytes residuais após o último registro completo.")
}

async function parsePcapNg(reader, acc) {
  let offset = 0
  let little = true
  let interfaces = []
  while (offset + 12 <= reader.file.size) {
    const header = await reader.read(offset, 12)
    const rawType = asView(header).getUint32(0, true)
    if (rawType === 0x0a0d0d0a) {
      const bom = [...header.subarray(8, 12)].map((value) => value.toString(16).padStart(2, "0")).join("")
      if (bom === "4d3c2b1a") little = true
      else if (bom === "1a2b3c4d") little = false
      else throw new Error("Cabeçalho PCAPNG possui byte-order magic inválido.")
      interfaces = []
    }
    const headerView = asView(header)
    const blockType = headerView.getUint32(0, little)
    const blockLength = headerView.getUint32(4, little)
    if (blockLength < 12 || blockLength % 4 !== 0 || blockLength > MAX_BLOCK || offset + blockLength > reader.file.size) throw new Error("A captura PCAPNG possui um bloco inválido ou corrompido.")
    const block = await reader.read(offset, blockLength)
    const view = asView(block)
    if (view.getUint32(blockLength - 4, little) !== blockLength) throw new Error("A captura PCAPNG possui comprimentos de bloco inconsistentes.")

    if (blockType === 1 && blockLength >= 20) {
      const info = { linkType: view.getUint16(8, little), resolution: readTimestampResolution(view, blockLength, little) }
      interfaces.push(info)
      acc.linkTypes.add(info.linkType)
      acc.interfaces++
    } else if (blockType === 6 && blockLength >= 32) {
      const interfaceId = view.getUint32(8, little)
      const high = view.getUint32(12, little)
      const low = view.getUint32(16, little)
      const captured = view.getUint32(20, little)
      const original = view.getUint32(24, little)
      const iface = interfaces[interfaceId] || { linkType: 1, resolution: 1e6 }
      if (captured <= blockLength - 32) {
        const timestamp = (high * 4294967296 + low) / iface.resolution
        consumePacket(block.subarray(28, 28 + captured), original || captured, timestamp, iface.linkType, acc, { captureOffset: offset + 28, capturedLength: captured, interfaceId })
      } else acc.malformedPackets++
    } else if (blockType === 3 && blockLength >= 16) {
      const original = view.getUint32(8, little)
      const captured = Math.min(original, blockLength - 16)
      const iface = interfaces[0] || { linkType: 1 }
      consumePacket(block.subarray(12, 12 + captured), original || captured, undefined, iface.linkType, acc, { captureOffset: offset + 12, capturedLength: captured, interfaceId: 0 })
    }
    offset += blockLength
    maybeProgress(offset, reader.file.size, acc.packetCount)
  }
  if (!acc.interfaces) acc.warnings.push("Nenhum bloco de interface foi encontrado; Ethernet foi assumido quando necessário.")
}

function readTimestampResolution(view, blockLength, little) {
  let cursor = 16
  const end = blockLength - 4
  while (cursor + 4 <= end) {
    const code = view.getUint16(cursor, little)
    const length = view.getUint16(cursor + 2, little)
    if (code === 0) break
    if (code === 9 && length >= 1 && cursor + 5 <= end) {
      const raw = view.getUint8(cursor + 4)
      return raw & 0x80 ? Math.pow(2, raw & 0x7f) : Math.pow(10, raw)
    }
    cursor += 4 + Math.ceil(length / 4) * 4
  }
  return 1e6
}

function consumePacket(packet, originalLength, timestamp, linkType, acc, sourceMeta) {
  acc.packetCount++
  acc.totalBytes += originalLength
  if (Number.isFinite(timestamp)) {
    acc.firstTime = Math.min(acc.firstTime, timestamp)
    acc.lastTime = Math.max(acc.lastTime, timestamp)
  } else acc.untimedPackets++
  let parsed
  try {
    parsed = decodePacket(packet, linkType, acc.options.analysisMode, acc)
  } catch {
    acc.malformedPackets++
    return
  }
  if (!parsed) {
    acc.unsupportedPackets++
    return
  }
  const decodedPacket = parsed.reassembledPacket || packet
  if (acc.options.analysisMode === "deep" && parsed.transport === "TCP") enrichTcpApplication(decodedPacket, parsed, acc)
  const { source, destination, sourcePort = 0, destinationPort = 0, transport, protocol, info, layers } = parsed
  addHost(acc, source, true, originalLength, parsed.sourceMac)
  addHost(acc, destination, false, originalLength, parsed.destinationMac)
  const conversation = addConversation(acc, parsed, originalLength, timestamp)
  addProtocol(acc, protocol, originalLength)
  if (destinationPort) addPort(acc, destinationPort, transport, destination, originalLength)
  if (Number.isFinite(timestamp)) {
    const second = Math.floor(timestamp)
    let bin = acc.timeline.get(second)
    if (!bin && reserveEntity(acc, "timeline", acc.timeline, 220)) bin = { time: formatClock(second), epoch: second, packets: 0, bytes: 0, connections: 0 }
    if (bin) {
      bin.packets++
      bin.bytes += originalLength
      if (transport === "TCP" && parsed.tcpFlags?.includes("SYN") && !parsed.tcpFlags.includes("ACK")) bin.connections++
      acc.timeline.set(second, bin)
    }
  }
  if (parsed.dns) addDns(acc, parsed.dns, parsed, timestamp)

  if (parsed.http && acc.http.length < acc.limits.http && acc.entityBytes + 850 <= acc.entityBudgetBytes) {
    acc.entityBytes += 850
    acc.http.push({ id: `http-${acc.packetCount}`, packetNo: acc.packetCount, timestamp: formatTimestamp(timestamp), epoch: timestamp, source, destination, sourcePort, destinationPort, ...parsed.http })
  } else if (parsed.http) noteDropped(acc, "http")
  if (parsed.tls) addTls(acc, parsed, originalLength, timestamp)
  if (parsed.quic) addQuic(acc, parsed, originalLength, timestamp)

  acc.decodedPackets++
  const retained = {
      no: acc.packetCount, timestamp: formatTimestamp(timestamp), epoch: timestamp, relativeTime: undefined,
      source, destination, sourcePort, destinationPort, sourceMac: parsed.sourceMac, destinationMac: parsed.destinationMac,
      protocol, transport, length: originalLength, capturedLength: sourceMeta.capturedLength, captureOffset: sourceMeta.captureOffset,
      linkType, interfaceId: sourceMeta.interfaceId, vlanId: parsed.vlanId, payloadLength: parsed.payloadLength,
      tcpFlags: parsed.tcpFlags, tcpStream: conversation?.id, retransmission: parsed.retransmission, reassembled: Boolean(parsed.reassembledPacket),
      info, serviceHint: parsed.serviceHint, http: parsed.http, tls: parsed.tls, quic: parsed.quic, dns: parsed.dns, layers,
  }
  retainPacket(acc, retained)
}

function retainPacket(acc, record) {
  // Amostra uniforme dos pacotes anteriores e retém o mais recente à parte.
  // Nenhum registro é armazenado duas vezes, mesmo ao substituir a amostra.
  const memoryLimit = acc.retainedMemoryLimit
  if (acc.latestPacket) {
    acc.retainedBytes -= acc.latestPacket._estimatedBytes
    offerSample(acc, acc.latestPacket, memoryLimit)
  }
  acc.latestPacket = null
  const estimate = JSON.stringify(record).length * 2 + 256
  if (estimate > memoryLimit) { acc.memoryLimited = true; return }
  while (acc.retainedBytes + estimate > memoryLimit && acc.packets.length) {
    acc.retainedBytes -= acc.packets.pop()._estimatedBytes
    acc.memoryLimited = true
  }
  record._estimatedBytes = estimate
  acc.latestPacket = record
  acc.retainedBytes += estimate
}

function offerSample(acc, record, memoryLimit) {
  const sampleSize = acc.packetLimit - 1
  acc.sampleSeen++
  acc.randomState ^= acc.randomState << 13
  acc.randomState ^= acc.randomState >>> 17
  acc.randomState ^= acc.randomState << 5
  const candidate = acc.sampleSeen <= sampleSize ? acc.packets.length : Math.floor((acc.randomState >>> 0) / 4294967296 * acc.sampleSeen)
  if (candidate >= sampleSize) return
  const previous = acc.packets[candidate]
  const previousBytes = previous ? previous._estimatedBytes : 0
  if (acc.retainedBytes - previousBytes + record._estimatedBytes > memoryLimit) { acc.memoryLimited = true; return }
  acc.packets[candidate] = record
  acc.retainedBytes += record._estimatedBytes - previousBytes
}

function decodePacket(packet, linkType, analysisMode, acc) {
  const view = asView(packet)
  const layers = []
  let offset = 0
  let etherType
  let sourceMac
  let destinationMac
  let vlanId

  if (linkType === 1) {
    if (packet.length < 14) return null
    destinationMac = mac(packet, 0)
    sourceMac = mac(packet, 6)
    etherType = view.getUint16(12, false)
    offset = 14
    const ethernetFields = [["Origem", sourceMac], ["Destino", destinationMac]]
    while ((etherType === 0x8100 || etherType === 0x88a8) && packet.length >= offset + 4) {
      const tag = view.getUint16(offset, false)
      vlanId = tag & 0x0fff
      ethernetFields.push(["VLAN", String(vlanId)])
      etherType = view.getUint16(offset + 2, false)
      offset += 4
    }
    ethernetFields.push(["Tipo", `0x${etherType.toString(16).padStart(4, "0")}`])
    layers.push({ name: "Ethernet II", fields: ethernetFields })
  } else if (linkType === 101 || linkType === 228 || linkType === 229) {
    etherType = (packet[0] >> 4) === 6 ? 0x86dd : 0x0800
  } else return null

  if (etherType === 0x0806) return decodeArp(packet, view, offset, layers, sourceMac, destinationMac, vlanId)

  let source
  let destination
  let ipProtocol
  let transportOffset
  let fragmented = false
  if (etherType === 0x0800) {
    if (packet.length < offset + 20) return null
    const headerLength = (packet[offset] & 15) * 4
    if (headerLength < 20 || packet.length < offset + headerLength) return null
    ipProtocol = packet[offset + 9]
    source = ipv4(packet, offset + 12)
    destination = ipv4(packet, offset + 16)
    const fragment = view.getUint16(offset + 6, false)
    const fragmentOffset = (fragment & 0x1fff) * 8
    const moreFragments = Boolean(fragment & 0x2000)
    fragmented = fragmentOffset > 0 || moreFragments
    transportOffset = offset + headerLength
    layers.push({ name: "Internet Protocol Version 4", fields: [["Source", source], ["Destination", destination], ["TTL", String(packet[offset + 8])], ["Header length", `${headerLength} bytes`], ["Fragmento", fragmented ? "Sim" : "Não"]] })
    if (fragmented && analysisMode === "deep" && acc) {
      const reassembled = reassembleIpv4(packet, linkType, offset, headerLength, source, destination, ipProtocol, fragmentOffset, moreFragments, acc)
      if (reassembled) {
        const decoded = decodePacket(reassembled, linkType, analysisMode, acc)
        if (decoded) {
          decoded.reassembledPacket = reassembled
          decoded.layers.push({ name: "Reagrupamento IPv4", fields: [["Estado", "Datagrama completo"], ["Fragmentos", "Reagrupados com limite de memória"]] })
        }
        return decoded
      }
    }
  } else if (etherType === 0x86dd) {
    if (packet.length < offset + 40) return null
    source = ipv6(packet, offset + 8)
    destination = ipv6(packet, offset + 24)
    ipProtocol = packet[offset + 6]
    transportOffset = offset + 40
    const extensionNames = []
    let guard = 0
    while ([0, 43, 44, 51, 60].includes(ipProtocol) && guard++ < 8 && transportOffset + 2 <= packet.length) {
      const next = packet[transportOffset]
      let size
      if (ipProtocol === 44) {
        size = 8
        fragmented = true
        extensionNames.push("Fragment")
      } else if (ipProtocol === 51) {
        size = (packet[transportOffset + 1] + 2) * 4
        extensionNames.push("AH")
      } else {
        size = (packet[transportOffset + 1] + 1) * 8
        extensionNames.push(ipProtocol === 0 ? "Hop-by-Hop" : ipProtocol === 43 ? "Routing" : "Destination")
      }
      if (size < 2 || transportOffset + size > packet.length) break
      transportOffset += size
      ipProtocol = next
    }
    layers.push({ name: "Internet Protocol Version 6", fields: [["Source", source], ["Destination", destination], ["Hop limit", String(packet[offset + 7])], ["Extensões", extensionNames.join(", ") || "Nenhuma"], ["Fragmento", fragmented ? "Sim" : "Não"]] })
  } else return null

  const common = { source, destination, sourceMac, destinationMac, vlanId, layers }
  if (ipProtocol === 1 || ipProtocol === 58) return decodeIcmp(packet, transportOffset, ipProtocol, common)
  if (fragmented) return { ...common, sourcePort: 0, destinationPort: 0, transport: "IP", protocol: etherType === 0x86dd ? "IPv6" : "IPv4", info: analysisMode === "deep" && etherType === 0x0800 ? "Fragmento IPv4 aguardando reagrupamento" : "Fragmento IP não reagrupado", payloadLength: Math.max(0, packet.length - transportOffset) }
  if (ipProtocol === 6) return decodeTcp(packet, view, transportOffset, common, analysisMode)
  if (ipProtocol === 17) return decodeUdp(packet, view, transportOffset, common)
  return { ...common, sourcePort: 0, destinationPort: 0, transport: "IP", protocol: etherType === 0x86dd ? "IPv6" : "IPv4", info: `Protocolo IP ${ipProtocol}`, payloadLength: Math.max(0, packet.length - transportOffset) }
}

function reassembleIpv4(packet, linkType, ipOffset, headerLength, source, destination, protocol, fragmentOffset, moreFragments, acc) {
  const view = asView(packet)
  const declaredLength = view.getUint16(ipOffset + 2, false)
  const payloadStart = ipOffset + headerLength
  const payloadEnd = Math.min(packet.length, ipOffset + Math.max(headerLength, declaredLength))
  const payload = packet.slice(payloadStart, payloadEnd)
  const identification = view.getUint16(ipOffset + 4, false)
  const key = `${source}|${destination}|${protocol}|${identification}`
  let datagram = acc.ipv4Fragments.get(key)

  if (!datagram) {
    while (acc.ipv4Fragments.size >= acc.limits.fragments) evictOldestFragment(acc)
    datagram = { fragments: new Map(), totalLength: null, prefix: null, lastSeen: acc.packetCount, bytes: 0, linkType }
    acc.ipv4Fragments.set(key, datagram)
  }

  if (!datagram.fragments.has(fragmentOffset)) {
    while (acc.streamBytes + payload.length > acc.streamMemoryLimit && acc.ipv4Fragments.size > 1) evictOldestFragment(acc, key)
    if (acc.streamBytes + payload.length > acc.streamMemoryLimit) {
      noteDropped(acc, "fragments")
      acc.streamBytes -= datagram.bytes
      acc.ipv4Fragments.delete(key)
      return null
    }
    const copy = payload.slice()
    datagram.fragments.set(fragmentOffset, copy)
    datagram.bytes += copy.length
    acc.streamBytes += copy.length
  }
  datagram.lastSeen = acc.packetCount
  if (fragmentOffset === 0) datagram.prefix = packet.slice(0, payloadStart)
  if (!moreFragments) datagram.totalLength = fragmentOffset + payload.length
  if (!datagram.prefix || datagram.totalLength === null) return null

  const ordered = [...datagram.fragments.entries()].sort((a, b) => a[0] - b[0])
  let covered = 0
  for (const [start, bytes] of ordered) {
    if (start > covered) return null
    covered = Math.max(covered, start + bytes.length)
  }
  if (covered < datagram.totalLength) return null

  const result = new Uint8Array(datagram.prefix.length + datagram.totalLength)
  result.set(datagram.prefix)
  for (const [start, bytes] of ordered) {
    const available = Math.min(bytes.length, datagram.totalLength - start)
    if (available > 0) result.set(bytes.subarray(0, available), datagram.prefix.length + start)
  }
  const resultView = asView(result)
  resultView.setUint16(ipOffset + 2, headerLength + datagram.totalLength, false)
  resultView.setUint16(ipOffset + 6, 0, false)
  acc.streamBytes -= datagram.bytes
  acc.ipv4Fragments.delete(key)
  acc.reassembledDatagrams++
  return result
}

function evictOldestFragment(acc, exceptKey) {
  let selectedKey
  let selected
  for (const [key, value] of acc.ipv4Fragments) {
    if (key === exceptKey) continue
    if (!selected || value.lastSeen < selected.lastSeen) {
      selectedKey = key
      selected = value
    }
  }
  if (!selectedKey || !selected) return false
  acc.streamBytes -= selected.bytes
  acc.ipv4Fragments.delete(selectedKey)
  noteDropped(acc, "fragments")
  return true
}

function decodeArp(packet, view, offset, layers, sourceMac, destinationMac, vlanId) {
  if (packet.length < offset + 28) return null
  const operation = view.getUint16(offset + 6, false)
  const senderMac = mac(packet, offset + 8)
  const senderIp = ipv4(packet, offset + 14)
  const targetMac = mac(packet, offset + 18)
  const targetIp = ipv4(packet, offset + 24)
  const info = operation === 1 ? `Quem possui ${targetIp}? Informe ${senderIp}` : `${senderIp} está em ${senderMac}`
  layers.push({ name: "Address Resolution Protocol", fields: [["Operação", operation === 1 ? "Request" : operation === 2 ? "Reply" : String(operation)], ["Sender MAC", senderMac], ["Sender IP", senderIp], ["Target MAC", targetMac], ["Target IP", targetIp]] })
  return { source: senderIp, destination: targetIp, sourceMac: sourceMac || senderMac, destinationMac, vlanId, sourcePort: 0, destinationPort: 0, transport: "ARP", protocol: "ARP", info, payloadLength: 28, layers }
}

function decodeIcmp(packet, offset, version, common) {
  if (offset + 4 > packet.length) return { ...common, sourcePort: 0, destinationPort: 0, transport: "ICMP", protocol: "ICMP", info: "ICMP truncado", payloadLength: 0 }
  const type = packet[offset]
  const code = packet[offset + 1]
  const names4 = { 0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded" }
  const names6 = { 1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 128: "Echo request", 129: "Echo reply", 135: "Neighbor solicitation", 136: "Neighbor advertisement" }
  const label = (version === 58 ? names6 : names4)[type] || `Type ${type}`
  common.layers.push({ name: version === 58 ? "ICMPv6" : "Internet Control Message Protocol", fields: [["Type", `${type} (${label})`], ["Code", String(code)]] })
  return { ...common, sourcePort: 0, destinationPort: 0, transport: "ICMP", protocol: "ICMP", info: `${label}, code ${code}`, payloadLength: Math.max(0, packet.length - offset - 4) }
}

function decodeTcp(packet, view, offset, common, analysisMode) {
  if (packet.length < offset + 20) return { ...common, sourcePort: 0, destinationPort: 0, transport: "TCP", protocol: "TCP", info: "TCP truncado", payloadLength: 0 }
  const sourcePort = view.getUint16(offset, false)
  const destinationPort = view.getUint16(offset + 2, false)
  const sequence = view.getUint32(offset + 4, false)
  const acknowledgement = view.getUint32(offset + 8, false)
  const headerLength = ((packet[offset + 12] >> 4) & 15) * 4
  if (headerLength < 20 || offset + headerLength > packet.length) return { ...common, sourcePort, destinationPort, transport: "TCP", protocol: "TCP", info: "Cabeçalho TCP inválido", payloadLength: 0 }
  const flagByte = packet[offset + 13]
  const tcpFlags = [[2, "SYN"], [16, "ACK"], [1, "FIN"], [4, "RST"], [8, "PSH"], [32, "URG"], [64, "ECE"], [128, "CWR"]].filter(([bit]) => flagByte & bit).map(([, name]) => name)
  const payloadOffset = offset + headerLength
  const payloadLength = Math.max(0, packet.length - payloadOffset)
  let protocol = "TCP"
  let info = `${sourcePort} → ${destinationPort}${tcpFlags.length ? ` [${tcpFlags.join(", ")}]` : ""} Seq=${sequence} Ack=${acknowledgement}`
  const http = parseHttp2(packet, payloadOffset) || parseHttp(packet, payloadOffset, analysisMode === "deep" ? 32768 : 8192)
  const tls = parseTls(packet, payloadOffset)
  const serviceHint = [443, 8443].includes(sourcePort) || [443, 8443].includes(destinationPort) ? "HTTPS provável" : [80, 8080].includes(sourcePort) || [80, 8080].includes(destinationPort) ? "HTTP provável" : undefined
  if (http) {
    protocol = http.version === "HTTP/2" ? "HTTP/2" : "HTTP"
    info = http.kind === "request" ? `${http.method} ${http.host || ""}${http.path || ""} ${http.version || ""}`.trim() : `${http.version || "HTTP"} ${http.status || ""}`.trim()
  } else if (tls) {
    protocol = "TLS"
    info = tls?.serverName ? `${tls.handshake || "TLS"} · SNI ${tls.serverName}` : `${tls?.handshake || info} · conteúdo criptografado`
  } else if (serviceHint) info += ` · ${serviceHint}`
  common.layers.push({ name: "Transmission Control Protocol", fields: [["Source port", String(sourcePort)], ["Destination port", String(destinationPort)], ["Sequence", String(sequence)], ["Acknowledgement", String(acknowledgement)], ["Flags", tcpFlags.join(", ") || "Nenhuma"], ["Payload", `${payloadLength} bytes`]] })
  if (http) common.layers.push(httpLayer(http))
  if (tls) common.layers.push({ name: "Transport Layer Security", fields: [["Registro", tls.recordType || "—"], ["Handshake", tls.handshake || "—"], ["Versão", tls.version || "—"], ["SNI", tls.serverName || "—"], ["ALPN", tls.alpn?.join(", ") || "—"], ["Cipher suites", tls.cipherSuites ? String(tls.cipherSuites) : "—"], ["JA3", tls.ja3 || "—"]] })
  return { ...common, sourcePort, destinationPort, transport: "TCP", protocol, info, serviceHint, payloadLength, payloadOffset, tcpFlags, sequence, acknowledgement, http, tls }
}

function decodeUdp(packet, view, offset, common) {
  if (packet.length < offset + 8) return { ...common, sourcePort: 0, destinationPort: 0, transport: "UDP", protocol: "UDP", info: "UDP truncado", payloadLength: 0 }
  const sourcePort = view.getUint16(offset, false)
  const destinationPort = view.getUint16(offset + 2, false)
  const payloadOffset = offset + 8
  const payloadLength = Math.max(0, packet.length - payloadOffset)
  let protocol = "UDP"
  let info = `${sourcePort} → ${destinationPort} Len=${payloadLength}`
  let dns
  let quic
  if (sourcePort === 53 || destinationPort === 53 || sourcePort === 5353 || destinationPort === 5353) {
    protocol = sourcePort === 5353 || destinationPort === 5353 ? "mDNS" : "DNS"
    dns = parseDns(packet, payloadOffset)
    if (dns?.domain) info = `${dns.response ? "Resposta" : "Consulta"} ${dns.queryType} ${dns.domain}${dns.answers.length ? ` → ${dns.answers.join(", ")}` : ""}`
  } else if ([67, 68].includes(sourcePort) || [67, 68].includes(destinationPort)) protocol = "DHCP"
  else if (sourcePort === 123 || destinationPort === 123) protocol = "NTP"
  else if ([443, 8443, 784].includes(sourcePort) || [443, 8443, 784].includes(destinationPort)) {
    quic = parseQuic(packet, payloadOffset)
    if (quic) {
      protocol = "QUIC"
      info = `${quic.packetType} · ${quic.version}`
    }
  }
  common.layers.push({ name: "User Datagram Protocol", fields: [["Source port", String(sourcePort)], ["Destination port", String(destinationPort)], ["Payload", `${payloadLength} bytes`]] })
  if (dns) common.layers.push({ name: "Domain Name System", fields: [["ID", `0x${dns.transactionId.toString(16).padStart(4, "0")}`], ["Tipo", dns.response ? "Resposta" : "Consulta"], ["Domínio", dns.domain || "Não decodificado"], ["Query type", dns.queryType], ["Status", dns.status], ["Respostas", dns.answers.join(", ") || "—"]] })
  if (quic) common.layers.push({ name: "QUIC", fields: [["Tipo", quic.packetType], ["Versão", quic.version], ["Cabeçalho", quic.longHeader ? "Longo" : "Curto"], ["DCID", quic.destinationConnectionId || "—"], ["SCID", quic.sourceConnectionId || "—"]] })
  return { ...common, sourcePort, destinationPort, transport: "UDP", protocol, info, payloadLength, dns, quic }
}

function httpLayer(http) {
  return { name: http.version === "HTTP/2" ? "Hypertext Transfer Protocol 2" : "Hypertext Transfer Protocol", fields: [["Tipo", http.kind], ["Método", http.method || "—"], ["Host", http.host || "—"], ["Caminho", http.path || "—"], ["Status", http.status ? String(http.status) : "—"], ["Versão", http.version || "—"], ["User-Agent", http.userAgent || "—"]] }
}

function enrichTcpApplication(packet, parsed, acc) {
  if (!parsed.payloadLength || !Number.isFinite(parsed.payloadOffset) || !Number.isFinite(parsed.sequence)) return
  if (parsed.http || parsed.tls) return
  const key = `${parsed.source}:${parsed.sourcePort}>${parsed.destination}:${parsed.destinationPort}`
  const payload = packet.slice(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
  const maxBytes = 64 * 1024
  let stream = acc.tcpStreams.get(key)
  const streamLimit = Math.min(2048, Math.max(32, Math.floor(acc.streamMemoryLimit / maxBytes)))
  if (!stream) {
    while (acc.tcpStreams.size >= streamLimit) evictOldestTcpStream(acc)
    stream = { segments: new Map(), bytes: new Uint8Array(0), bufferedBytes: 0, emitted: false, lastSeen: acc.packetCount }
    acc.tcpStreams.set(key, stream)
  }
  stream.lastSeen = acc.packetCount
  if (stream.emitted) return
  if (!stream.segments.has(parsed.sequence) && stream.segments.size < 64) {
    const available = Math.min(payload.length, maxBytes)
    while (acc.streamBytes + available > acc.streamMemoryLimit && acc.tcpStreams.size > 1) evictOldestTcpStream(acc, key)
    if (acc.streamBytes + available > acc.streamMemoryLimit) {
      noteDropped(acc, "streams")
      return
    }
    const copy = payload.slice(0, available)
    stream.segments.set(parsed.sequence, copy)
    stream.bufferedBytes += copy.length
    acc.streamBytes += copy.length
  }
  stream.bytes = contiguousTcpBytes(stream.segments, maxBytes)
  const http = parseHttp2(stream.bytes, 0) || parseHttp(stream.bytes, 0, maxBytes)
  const tls = parseTls(stream.bytes, 0)
  if (!http && !tls) return
  stream.emitted = true
  acc.reassembledStreams++
  if (parsed.http || parsed.tls) return
  if (http) {
    parsed.http = http
    parsed.protocol = http.version === "HTTP/2" ? "HTTP/2" : "HTTP"
    parsed.info = http.kind === "request" ? `${http.method} ${http.host || ""}${http.path || ""} ${http.version || ""}`.trim() : `${http.version || "HTTP"} ${http.status || ""}`.trim()
    parsed.layers.push(httpLayer(http))
  } else {
    parsed.tls = tls
    parsed.protocol = "TLS"
    parsed.info = tls.serverName ? `${tls.handshake || "TLS"} · SNI ${tls.serverName}` : `${tls.handshake || "TLS"} · fluxo reagrupado`
    parsed.layers.push({ name: "Transport Layer Security (reagrupado)", fields: [["Registro", tls.recordType || "—"], ["Handshake", tls.handshake || "—"], ["Versão", tls.version || "—"], ["SNI", tls.serverName || "—"], ["JA3", tls.ja3 || "—"]] })
  }
}

function contiguousTcpBytes(segments, maxBytes) {
  const ordered = [...segments.entries()].sort((a, b) => a[0] - b[0])
  if (!ordered.length) return new Uint8Array(0)
  const chunks = []
  let nextSequence = ordered[0][0]
  let total = 0
  for (const [sequence, bytes] of ordered) {
    if (sequence > nextSequence) break
    const overlap = Math.max(0, nextSequence - sequence)
    if (overlap >= bytes.length) continue
    const take = bytes.subarray(overlap, overlap + Math.max(0, maxBytes - total))
    if (!take.length) break
    chunks.push(take)
    total += take.length
    nextSequence = sequence + bytes.length
    if (total >= maxBytes) break
  }
  const result = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

function evictOldestTcpStream(acc, exceptKey) {
  let selectedKey
  let selected
  for (const [key, value] of acc.tcpStreams) {
    if (key === exceptKey) continue
    if (!selected || value.lastSeen < selected.lastSeen) {
      selectedKey = key
      selected = value
    }
  }
  if (!selectedKey || !selected) return false
  acc.streamBytes -= selected.bufferedBytes
  acc.tcpStreams.delete(selectedKey)
  noteDropped(acc, "streams")
  return true
}

function parseTls(packet, offset) {
  if (offset + 5 > packet.length) return null
  const type = packet[offset]
  const versionCode = (packet[offset + 1] << 8) | packet[offset + 2]
  const recordLength = (packet[offset + 3] << 8) | packet[offset + 4]
  if (![20, 21, 22, 23].includes(type) || versionCode < 0x0300 || versionCode > 0x0304 || recordLength > packet.length - offset - 5) return null
  const result = { recordType: TLS_RECORDS[type] || `Record ${type}`, version: TLS_VERSIONS[versionCode] || `0x${versionCode.toString(16)}` }
  if (type !== 22 || offset + 9 > packet.length) return result
  const handshake = packet[offset + 5]
  result.handshake = handshake === 1 ? "Client Hello" : handshake === 2 ? "Server Hello" : handshake === 11 ? "Certificate" : `Handshake ${handshake}`
  if (handshake !== 1) return result
  let cursor = offset + 9
  if (cursor + 34 > packet.length) return result
  const legacy = (packet[cursor] << 8) | packet[cursor + 1]
  result.version = TLS_VERSIONS[legacy] || result.version
  cursor += 34
  if (cursor >= packet.length) return result
  const sessionLength = packet[cursor++]
  cursor += sessionLength
  if (cursor + 2 > packet.length) return result
  const cipherLength = (packet[cursor] << 8) | packet[cursor + 1]
  result.cipherSuites = Math.floor(cipherLength / 2)
  cursor += 2
  if (cursor + cipherLength > packet.length) return result
  result.cipherSuiteIds = []
  for (let end = cursor + cipherLength; cursor + 1 < end; cursor += 2) {
    const cipher = (packet[cursor] << 8) | packet[cursor + 1]
    if (!isGrease(cipher)) result.cipherSuiteIds.push(cipher)
  }
  if (cursor >= packet.length) return result
  const compressionLength = packet[cursor++]
  cursor += compressionLength
  if (cursor + 2 > packet.length) return result
  const extensionEnd = Math.min(packet.length, cursor + 2 + ((packet[cursor] << 8) | packet[cursor + 1]))
  cursor += 2
  const extensionIds = []
  const supportedGroups = []
  const pointFormats = []
  while (cursor + 4 <= extensionEnd) {
    const extensionType = (packet[cursor] << 8) | packet[cursor + 1]
    const extensionLength = (packet[cursor + 2] << 8) | packet[cursor + 3]
    const body = cursor + 4
    if (body + extensionLength > extensionEnd) break
    if (!isGrease(extensionType)) extensionIds.push(extensionType)
    if (extensionType === 0 && extensionLength >= 5) {
      const nameLength = (packet[body + 3] << 8) | packet[body + 4]
      if (body + 5 + nameLength <= extensionEnd) result.serverName = ascii(packet, body + 5, body + 5 + nameLength)
    } else if (extensionType === 16 && extensionLength >= 3) {
      const names = []
      let item = body + 2
      while (item < body + extensionLength) {
        const length = packet[item++]
        if (item + length > body + extensionLength) break
        names.push(ascii(packet, item, item + length))
        item += length
      }
      result.alpn = names
    } else if (extensionType === 43 && extensionLength >= 3) {
      const supported = (packet[body + 1] << 8) | packet[body + 2]
      result.version = TLS_VERSIONS[supported] || result.version
    } else if (extensionType === 10 && extensionLength >= 2) {
      const groupEnd = Math.min(body + extensionLength, body + 2 + ((packet[body] << 8) | packet[body + 1]))
      for (let item = body + 2; item + 1 < groupEnd; item += 2) {
        const group = (packet[item] << 8) | packet[item + 1]
        if (!isGrease(group)) supportedGroups.push(group)
      }
    } else if (extensionType === 11 && extensionLength >= 1) {
      const formatEnd = Math.min(body + extensionLength, body + 1 + packet[body])
      for (let item = body + 1; item < formatEnd; item++) pointFormats.push(packet[item])
    }
    cursor = body + extensionLength
  }
  result.extensionIds = extensionIds
  result.ja3Raw = `${legacy},${result.cipherSuiteIds.join("-")},${extensionIds.join("-")},${supportedGroups.join("-")},${pointFormats.join("-")}`
  result.ja3 = md5(result.ja3Raw)
  return result
}

function isGrease(value) { return (value & 0x0f0f) === 0x0a0a }

function parseDns(packet, offset) {
  if (offset + 12 > packet.length) return null
  const view = asView(packet)
  const transactionId = view.getUint16(offset, false)
  const flags = view.getUint16(offset + 2, false)
  const response = Boolean(flags & 0x8000)
  const rcode = flags & 15
  const questionCount = view.getUint16(offset + 4, false)
  const answerCount = view.getUint16(offset + 6, false)
  let cursor = offset + 12
  let domain = ""
  let queryType = "Unknown"
  if (questionCount) {
    const question = readDnsName(packet, offset, cursor)
    domain = question.name
    cursor = question.next
    if (cursor + 4 <= packet.length) {
      const type = view.getUint16(cursor, false)
      queryType = DNS_TYPES[type] || `TYPE${type}`
      cursor += 4
    }
    for (let index = 1; index < questionCount && cursor < packet.length; index++) {
      const extra = readDnsName(packet, offset, cursor)
      cursor = extra.next + 4
    }
  }
  const answers = []
  for (let index = 0; index < Math.min(answerCount, 16) && cursor < packet.length; index++) {
    const name = readDnsName(packet, offset, cursor)
    cursor = name.next
    if (cursor + 10 > packet.length) break
    const type = view.getUint16(cursor, false)
    const length = view.getUint16(cursor + 8, false)
    cursor += 10
    if (cursor + length > packet.length) break
    let value = ""
    if (type === 1 && length === 4) value = ipv4(packet, cursor)
    else if (type === 28 && length === 16) value = ipv6(packet, cursor)
    else if (type === 5 || type === 2 || type === 12) value = readDnsName(packet, offset, cursor).name
    if (value) answers.push(value)
    cursor += length
  }
  return { transactionId, response, domain, queryType, status: rcode === 0 ? "NOERROR" : rcode === 3 ? "NXDOMAIN" : `RCODE ${rcode}`, answers }
}

function readDnsName(packet, base, start, depth = 0, seen = new Set()) {
  if (depth > 12) return { name: "", next: Math.min(packet.length, start + 1) }
  const labels = []
  let cursor = start
  let next = start
  let jumped = false
  let guard = 0
  while (cursor < packet.length && guard++ < 128) {
    const length = packet[cursor]
    if (length === 0) {
      if (!jumped) next = cursor + 1
      break
    }
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= packet.length) break
      const pointer = base + (((length & 0x3f) << 8) | packet[cursor + 1])
      if (!jumped) next = cursor + 2
      if (seen.has(pointer)) break
      seen.add(pointer)
      const nested = readDnsName(packet, base, pointer, depth + 1, seen)
      if (nested.name) labels.push(nested.name)
      jumped = true
      break
    }
    cursor++
    if (length > 63 || cursor + length > packet.length) break
    labels.push(ascii(packet, cursor, cursor + length))
    cursor += length
    if (!jumped) next = cursor
  }
  return { name: labels.filter(Boolean).join("."), next }
}

function addProtocol(acc, name, bytes) {
  let item = acc.protocols.get(name)
  if (!item) {
    if (acc.protocols.size >= 512 || acc.entityBytes + 160 > acc.entityBudgetBytes) return
    acc.entityBytes += 160
    item = { name, packets: 0, bytes: 0, color: COLORS[name] || COLORS.Other }
  }
  item.packets++
  item.bytes += bytes
  acc.protocols.set(name, item)
}

function addHost(acc, ip, sent, bytes, macAddress) {
  if (!ip) return
  let item = acc.hosts.get(ip)
  if (!item) {
    if (!reserveEntity(acc, "hosts", acc.hosts, 700)) return
    item = { ip, mac: macAddress, vendor: vendorForMac(macAddress), scope: scopeForIp(ip), sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, connections: new Set() }
  }
  if (!item.mac && macAddress) {
    item.mac = macAddress
    item.vendor = vendorForMac(macAddress)
  }
  if (sent) {
    item.sentPackets++
    item.sentBytes += bytes
  } else {
    item.receivedPackets++
    item.receivedBytes += bytes
  }
  acc.hosts.set(ip, item)
}

function addConversation(acc, parsed, bytes, time) {
  const sourcePort = parsed.sourcePort || 0
  const destinationPort = parsed.destinationPort || 0
  const left = `${parsed.source}:${sourcePort}`
  const right = `${parsed.destination}:${destinationPort}`
  const key = left < right ? `${left}|${right}|${parsed.transport}` : `${right}|${left}|${parsed.transport}`
  let item = acc.conversations.get(key)
  if (!item) {
    if (!reserveEntity(acc, "conversations", acc.conversations, 1300)) return undefined
    item = { id: `conv-${acc.conversations.size + 1}`, source: parsed.source, destination: parsed.destination, sourcePort, destinationPort, protocol: parsed.transport, application: parsed.protocol !== parsed.transport ? parsed.protocol : undefined, packets: 0, bytes: 0, first: Infinity, last: -Infinity, tcp: { syn: 0, synAck: 0, resets: 0, retransmissions: 0 }, seenSeq: new Set(), connectionEvents: [] }
  }
  item.packets++
  item.bytes += bytes
  if (Number.isFinite(time)) {
    item.first = Math.min(item.first, time)
    item.last = Math.max(item.last, time)
  }
  if (parsed.protocol !== parsed.transport && !["IPv4", "IPv6"].includes(parsed.protocol)) item.application = parsed.protocol
  if (parsed.transport === "TCP") {
    const flags = parsed.tcpFlags || []
    if (flags.includes("SYN") && flags.includes("ACK")) item.tcp.synAck++
    else if (flags.includes("SYN")) {
      item.tcp.syn++
      if (Number.isFinite(time) && item.connectionEvents.length < 256) item.connectionEvents.push(time)
    }
    if (flags.includes("RST")) item.tcp.resets++
    const direction = `${parsed.source}:${sourcePort}`
    const sequenceKey = `${direction}|${parsed.sequence}`
    if ((parsed.payloadLength > 0 || flags.includes("SYN")) && item.seenSeq.has(sequenceKey)) {
      item.tcp.retransmissions++
      parsed.retransmission = true
    } else if (item.seenSeq.size < 128) item.seenSeq.add(sequenceKey)
  }
  acc.conversations.set(key, item)
  acc.hosts.get(parsed.source)?.connections.add(key)
  acc.hosts.get(parsed.destination)?.connections.add(key)
  return item
}

function addPort(acc, port, protocol, host, bytes) {
  const key = `${port}/${protocol}`
  let item = acc.ports.get(key)
  if (!item) {
    if (!reserveEntity(acc, "ports", acc.ports, 420)) return
    item = { port, protocol, service: SERVICES[port] || "Desconhecido", connections: 0, hosts: new Set(), bytes: 0 }
  }
  item.connections++
  item.hosts.add(host)
  item.bytes += bytes
  acc.ports.set(key, item)
}

function addDns(acc, dns, parsed, timestamp) {
  if (!dns.domain) return
  const clientIp = dns.response ? parsed.destination : parsed.source
  const clientPort = dns.response ? parsed.destinationPort : parsed.sourcePort
  const serverIp = dns.response ? parsed.source : parsed.destination
  const serverPort = dns.response ? parsed.sourcePort : parsed.destinationPort
  const pendingKey = `${dns.transactionId}|${clientIp}:${clientPort}|${serverIp}:${serverPort}|${parsed.transport}|${dns.domain.toLowerCase()}`
  const pending = acc.dnsPending.get(pendingKey)
  const client = dns.response ? parsed.destination : parsed.source
  const key = `${dns.domain}|${client}`
  let item = acc.dns.get(key)
  if (!item) {
    if (!reserveEntity(acc, "dns", acc.dns, 900)) return
    item = { domain: dns.domain, source: client, answer: "—", answers: [], queryType: dns.queryType, queries: 0, responses: 0, failures: 0, nxDomainResponses: 0, status: dns.status, responseTime: 0, latencyTotal: 0, latencyCount: 0 }
  }
  if (dns.response) {
    item.responses++
    item.status = dns.status
    if (dns.status !== "NOERROR") item.failures++
    if (dns.status === "NXDOMAIN") item.nxDomainResponses++
    if (dns.answers.length) {
      item.answers = [...new Set([...item.answers, ...dns.answers])].slice(0, 16)
      item.answer = item.answers.join(", ")
    }
    if (pending?.length && Number.isFinite(timestamp)) {
      dns.responseTime = Math.max(0, (timestamp - pending.shift()) * 1000)
      item.latencyTotal += dns.responseTime
      item.latencyCount++
      item.responseTime = Math.round(item.latencyTotal / item.latencyCount)
      if (!pending.length) acc.dnsPending.delete(pendingKey)
    }
  } else {
    item.queries++
    if (Number.isFinite(timestamp) && (pending || acc.dnsPending.size < Math.min(20000, acc.limits.dns))) {
      const queue = pending || []
      if (queue.length < 8) queue.push(timestamp)
      acc.dnsPending.set(pendingKey, queue)
    }
  }
  acc.dns.set(key, item)
}

function addTls(acc, parsed, bytes, timestamp) {
  const key = `${parsed.source}:${parsed.sourcePort}|${parsed.destination}:${parsed.destinationPort}|${parsed.tls.serverName || "unknown"}`
  let item = acc.tls.get(key)
  if (!item) {
    if (!reserveEntity(acc, "tls", acc.tls, 850)) return
    item = { id: `tls-${acc.tls.size + 1}`, packetNo: acc.packetCount, timestamp: formatTimestamp(timestamp), epoch: timestamp, source: parsed.source, destination: parsed.destination, sourcePort: parsed.sourcePort, destinationPort: parsed.destinationPort, packets: 0, bytes: 0, ...parsed.tls }
  }
  item.packets++
  item.bytes += bytes
  if (parsed.tls.serverName) item.serverName = parsed.tls.serverName
  if (parsed.tls.alpn?.length) item.alpn = parsed.tls.alpn
  if (parsed.tls.version) item.version = parsed.tls.version
  acc.tls.set(key, item)
}

function addQuic(acc, parsed, bytes, timestamp) {
  const connectionId = parsed.quic.destinationConnectionId || parsed.quic.sourceConnectionId || "short"
  const key = `${parsed.source}:${parsed.sourcePort}|${parsed.destination}:${parsed.destinationPort}|${connectionId}`
  let item = acc.quic.get(key)
  if (!item) {
    if (!reserveEntity(acc, "quic", acc.quic, 750)) return
    item = { id: `quic-${acc.quic.size + 1}`, packetNo: acc.packetCount, timestamp: formatTimestamp(timestamp), epoch: timestamp, source: parsed.source, destination: parsed.destination, sourcePort: parsed.sourcePort, destinationPort: parsed.destinationPort, packets: 0, bytes: 0, ...parsed.quic }
  }
  item.packets++
  item.bytes += bytes
  acc.quic.set(key, item)
}

function finalize(acc) {
  postProgress(98, acc.packetCount, "Consolidando evidências")
  const conversations = [...acc.conversations.values()].map((item) => ({
    id: item.id, source: item.source, destination: item.destination, sourcePort: item.sourcePort, destinationPort: item.destinationPort,
    protocol: item.protocol, application: item.application, packets: item.packets, bytes: item.bytes,
    start: formatTimestamp(item.first).slice(0, 8), startEpoch: Number.isFinite(item.first) ? item.first : undefined, endEpoch: Number.isFinite(item.last) ? item.last : undefined, duration: Number.isFinite(item.first) ? Math.max(0, item.last - item.first) : 0,
    tcp: item.protocol === "TCP" ? { ...item.tcp, completeHandshake: item.tcp.syn > 0 && item.tcp.synAck > 0 } : undefined,
    connectionEvents: item.connectionEvents,
  })).sort((a, b) => b.bytes - a.bytes)
  const hosts = [...acc.hosts.values()].map((item) => ({ ip: item.ip, hostname: item.hostname, mac: item.mac, vendor: item.vendor, scope: item.scope, sentPackets: item.sentPackets, receivedPackets: item.receivedPackets, sentBytes: item.sentBytes, receivedBytes: item.receivedBytes, connections: item.connections.size })).sort((a, b) => b.sentBytes + b.receivedBytes - a.sentBytes - a.receivedBytes)
  const dns = [...acc.dns.values()].map(({ latencyTotal, latencyCount, ...item }) => { void latencyTotal; void latencyCount; return item }).sort((a, b) => b.queries - a.queries)
  const ports = [...acc.ports.values()].map((item) => ({ ...item, hosts: item.hosts.size })).sort((a, b) => b.connections - a.connections)
  const protocols = [...acc.protocols.values()].sort((a, b) => b.packets - a.packets)
  const timeline = compressTimeline([...acc.timeline.values()].sort((a, b) => (a.epoch || 0) - (b.epoch || 0)), 240)
  const tcpHealth = summarizeTcp(conversations)
  const baseline = buildBaseline(hosts)
  const alerts = buildAlerts(acc, hosts, dns, ports, conversations, tcpHealth, baseline)
  const sampledPackets = [...acc.packets, acc.latestPacket].filter(Boolean).sort((a, b) => a.no - b.no)
  for (const packet of sampledPackets) {
    delete packet._estimatedBytes
    if (Number.isFinite(packet.epoch) && Number.isFinite(acc.firstTime)) packet.relativeTime = Math.max(0, packet.epoch - acc.firstTime)
  }
  if (acc.untimedPackets) acc.warnings.push(`${n(acc.untimedPackets)} pacotes sem timestamp foram excluídos das métricas temporais.`)
  const droppedEntities = Object.fromEntries(Object.entries(acc.droppedEntities).filter(([, count]) => count > 0))
  const aggregationLimited = Object.keys(droppedEntities).some((kind) => !["streams", "fragments", "http"].includes(kind))
  if (acc.memoryLimited) acc.warnings.push(aggregationLimited
    ? `O orçamento de ${acc.options.memoryBudgetMb} MB limitou detalhes e algumas cardinalidades; os totais gerais continuam cobrindo o arquivo, mas listas de entidades podem estar incompletas.`
    : `A retenção de detalhes foi limitada pelo orçamento estimado de ${acc.options.memoryBudgetMb} MB; as agregações principais continuam cobrindo todos os pacotes.`)
  const analysisMs = Math.max(1, Date.now() - acc.startedAt)
  const metadata = { parserVersion: PARSER_VERSION, streamed: true, engine: "browser", linkTypes: [...acc.linkTypes], interfaces: acc.interfaces, retainedPackets: sampledPackets.length, packetLimit: acc.packetLimit, unsupportedPackets: acc.unsupportedPackets, malformedPackets: acc.malformedPackets, warnings: acc.warnings, analysisMode: acc.options.analysisMode, analysisMs, throughputMbps: Number(((acc.fileSize * 8) / (analysisMs * 1000)).toFixed(2)), estimatedMemoryBytes: acc.retainedBytes + acc.entityBytes + acc.streamBytes * 2, memoryBudgetMb: acc.options.memoryBudgetMb, reassembledStreams: acc.reassembledStreams, reassembledDatagrams: acc.reassembledDatagrams, aggregationLimited, droppedEntities, sampleStrategy: "distributed" }
  const firstEpoch = Number.isFinite(acc.firstTime) ? acc.firstTime : undefined
  const lastEpoch = Number.isFinite(acc.lastTime) ? acc.lastTime : undefined
  return { id: `${acc.fileName}:${acc.fileSize}:${acc.packetCount}`, fileName: acc.fileName, fileSize: acc.fileSize, analyzedAt: new Date().toLocaleString("pt-BR"), packetCount: acc.packetCount, totalBytes: acc.totalBytes, duration: firstEpoch === undefined ? 0 : Math.max(0, acc.lastTime - acc.firstTime), firstEpoch, lastEpoch, hosts, conversations: conversations.map(({ connectionEvents, ...item }) => { void connectionEvents; return item }), dns, ports, protocols, timeline, packets: sampledPackets, alerts, http: acc.http, tls: [...acc.tls.values()].sort((a, b) => b.bytes - a.bytes), quic: [...acc.quic.values()].sort((a, b) => b.bytes - a.bytes), tcpHealth, baseline, metadata, truncatedPackets: acc.decodedPackets > sampledPackets.length }
}

function buildBaseline(hosts) {
  const bytes = hosts.map((item) => item.sentBytes + item.receivedBytes).sort((a, b) => a - b)
  const connections = hosts.map((item) => item.connections).sort((a, b) => a - b)
  return { medianHostBytes: percentile(bytes, 0.5), medianConnections: percentile(connections, 0.5), p95HostBytes: percentile(bytes, 0.95), p95Connections: percentile(connections, 0.95) }
}

function percentile(values, ratio) {
  if (!values.length) return 0
  return values[Math.min(values.length - 1, Math.max(0, Math.ceil(values.length * ratio) - 1))]
}

function summarizeTcp(conversations) {
  const tcp = conversations.filter((item) => item.protocol === "TCP")
  return tcp.reduce((total, item) => {
    total.syn += item.tcp?.syn || 0
    total.synAck += item.tcp?.synAck || 0
    total.resets += item.tcp?.resets || 0
    total.retransmissions += item.tcp?.retransmissions || 0
    if (item.tcp?.syn && !item.tcp.completeHandshake) total.incompleteHandshakes++
    return total
  }, { syn: 0, synAck: 0, resets: 0, retransmissions: 0, incompleteHandshakes: 0 })
}

function buildAlerts(acc, hosts, dns, ports, conversations, tcpHealth, baseline) {
  const rules = acc.options.ruleOptions
  const duration = Math.max(1, acc.lastTime - acc.firstTime)
  const alerts = []
  const scanGroups = new Map()
  for (const item of conversations) {
    const key = `${item.source}|${item.destination}`
    const group = scanGroups.get(key) || { source: item.source, destination: item.destination, ports: new Set(), packets: 0, first: item.startEpoch, last: item.endEpoch }
    if (item.destinationPort) group.ports.add(item.destinationPort)
    group.packets += item.packets
    if (Number.isFinite(item.startEpoch)) group.first = Number.isFinite(group.first) ? Math.min(group.first, item.startEpoch) : item.startEpoch
    if (Number.isFinite(item.endEpoch)) group.last = Number.isFinite(group.last) ? Math.max(group.last, item.endEpoch) : item.endEpoch
    scanGroups.set(key, group)
  }
  const scan = [...scanGroups.values()].sort((a, b) => b.ports.size - a.ports.size).find((item) => item.ports.size >= rules.portScanPorts)
  if (scan) alerts.push(alert("port-scan", scan.ports.size >= rules.portScanPorts * 4 ? "Alta" : "Média", "Reconhecimento", "Muitas portas em uma mesma comunicação", `${scan.source} acessou ${n(scan.ports.size)} portas distintas de ${scan.destination}.`, scan.source, scan.destination, `${n(scan.packets)} pacotes · ${n(scan.ports.size)} portas`, `${n(scan.ports.size)} portas`, `≥ ${n(rules.portScanPorts)} portas`, scan.ports.size >= rules.portScanPorts * 2 ? "Alta" : "Média", "Possível varredura de portas. Confirme a janela temporal, o ativo de origem e a finalidade da comunicação.", { addresses: [scan.source, scan.destination] }, scan.first))

  const noisyDns = dns.map((item) => ({ item, rate: item.queries / duration })).sort((a, b) => b.rate - a.rate)[0]
  if (!acc.untimedPackets && noisyDns && noisyDns.rate >= rules.dnsQueriesPerSecond) alerts.push(alert("dns-rate", noisyDns.rate >= rules.dnsQueriesPerSecond * 4 ? "Média" : "Baixa", "DNS", "Frequência DNS elevada", `${n(noisyDns.item.queries)} consultas para ${noisyDns.item.domain} durante a captura.`, noisyDns.item.source, "Servidor DNS", `${noisyDns.rate.toFixed(1)} consultas/s`, `${noisyDns.rate.toFixed(1)} consultas/s`, `≥ ${rules.dnsQueriesPerSecond} consultas/s`, noisyDns.rate >= rules.dnsQueriesPerSecond * 2 ? "Alta" : "Média", "Atualizações e automações também podem produzir esse padrão. Compare com a linha de base do ativo.", { addresses: [noisyDns.item.source], domains: [noisyDns.item.domain], protocols: ["DNS"] }))

  const nxdomainResponses = dns.reduce((sum, item) => sum + item.nxDomainResponses, 0)
  const allDnsResponses = dns.reduce((sum, item) => sum + item.responses, 0)
  const nxRatio = allDnsResponses ? nxdomainResponses / allDnsResponses : 0
  if (allDnsResponses >= 20 && nxRatio >= rules.nxDomainRatio) alerts.push(alert("dns-nxdomain", nxRatio >= 0.7 ? "Média" : "Baixa", "DNS", "Proporção elevada de respostas NXDOMAIN", `${Math.round(nxRatio * 100)}% das respostas DNS foram NXDOMAIN.`, "Múltiplos hosts", undefined, `${n(nxdomainResponses)} de ${n(allDnsResponses)} respostas`, `${Math.round(nxRatio * 100)}%`, `≥ ${Math.round(rules.nxDomainRatio * 100)}%`, allDnsResponses >= 100 ? "Alta" : "Média", "Erros de configuração, DGA e software desatualizado podem gerar NXDOMAIN. Investigue os domínios e suas origens.", { protocols: ["DNS"] }))

  const busy = hosts.find((host) => host.connections > rules.highConnectionCount)
  if (busy) alerts.push(alert("many-connections", "Média", "Comportamento", "Grande quantidade de conexões", `${busy.ip} participou de ${n(busy.connections)} conversações.`, busy.ip, undefined, `${n(busy.connections)} conversações`, `${n(busy.connections)}`, `> ${n(rules.highConnectionCount)}`, busy.connections > rules.highConnectionCount * 2 ? "Alta" : "Média", "Navegação, automação e atualizações podem ser legítimas. Correlacione com o processo no endpoint.", { addresses: [busy.ip] }))

  const unknown = ports.find((item) => item.service === "Desconhecido" && item.connections > rules.unknownPortConnections)
  if (unknown) alerts.push(alert("unusual-port", "Baixa", "Serviço", "Uso recorrente de porta não classificada", `A porta ${unknown.port}/${unknown.protocol} apareceu em ${n(unknown.connections)} pacotes direcionados.`, "Múltiplos hosts", undefined, `${n(unknown.connections)} ocorrências`, `${n(unknown.connections)}`, `> ${n(rules.unknownPortConnections)}`, "Baixa", "A classificação por porta é indicativa. Verifique endpoints e conteúdo antes de concluir que o serviço é incomum.", { ports: [unknown.port], protocols: [unknown.protocol] }))

  const tcpPackets = conversations.filter((item) => item.protocol === "TCP").reduce((sum, item) => sum + item.packets, 0)
  const retransmissionRatio = tcpPackets ? tcpHealth.retransmissions / tcpPackets : 0
  if (tcpPackets >= 100 && retransmissionRatio >= rules.retransmissionRatio) alerts.push(alert("tcp-retransmissions", retransmissionRatio >= 0.2 ? "Média" : "Baixa", "Confiabilidade", "Retransmissões TCP acima do limite", `${n(tcpHealth.retransmissions)} possíveis retransmissões foram observadas.`, "Múltiplos hosts", undefined, `${(retransmissionRatio * 100).toFixed(1)}% dos pacotes TCP`, `${(retransmissionRatio * 100).toFixed(1)}%`, `≥ ${(rules.retransmissionRatio * 100).toFixed(0)}%`, tcpPackets >= 1000 ? "Média" : "Baixa", "Perda, latência, captura duplicada ou reordenação podem causar o padrão. Valide com métricas do enlace.", { protocols: ["TCP"] }))

  if (tcpHealth.resets >= 20) alerts.push(alert("tcp-resets", tcpHealth.resets >= 100 ? "Média" : "Baixa", "Confiabilidade", "Volume elevado de resets TCP", `${n(tcpHealth.resets)} pacotes RST foram observados.`, "Múltiplos hosts", undefined, `${n(tcpHealth.resets)} resets`, `${n(tcpHealth.resets)}`, "≥ 20", tcpHealth.resets >= 100 ? "Alta" : "Média", "Serviços indisponíveis, rejeições e varreduras podem gerar RST. Investigue os fluxos e destinos envolvidos.", { protocols: ["TCP"] }))

  const outbound = hosts.find((host) => host.sentBytes >= rules.outboundMinimumBytes && host.sentBytes / Math.max(1, host.receivedBytes) >= rules.outboundRatio)
  if (outbound) {
    const ratio = outbound.sentBytes / Math.max(1, outbound.receivedBytes)
    alerts.push(alert("outbound-ratio", ratio >= rules.outboundRatio * 2 ? "Média" : "Baixa", "Transferência", "Assimetria elevada de dados enviados", `${outbound.ip} enviou muito mais dados do que recebeu.`, outbound.ip, undefined, `${formatCompact(outbound.sentBytes)} enviados · ${ratio.toFixed(1)}× a recepção`, `${ratio.toFixed(1)}×`, `≥ ${rules.outboundRatio}× e ${formatCompact(rules.outboundMinimumBytes)}`, outbound.sentBytes >= 50_000_000 ? "Alta" : "Média", "Backups e uploads legítimos também são assimétricos. Valide o destino, o processo e a janela de negócio.", { addresses: [outbound.ip] }))
  }

  const beacon = conversations.map((item) => ({ item, score: periodicity(item.connectionEvents || []) })).filter((entry) => entry.score && entry.score.count >= 8 && entry.score.cv < 0.15 && entry.score.mean >= 5).sort((a, b) => a.score.cv - b.score.cv)[0]
  if (beacon) alerts.push(alert("periodic-connections", "Baixa", "Comportamento", "Conexões periódicas", `${beacon.item.source} iniciou conexões em intervalos regulares para ${beacon.item.destination}.`, beacon.item.source, beacon.item.destination, `${beacon.score.count} intervalos · média ${beacon.score.mean.toFixed(1)}s`, `CV ${(beacon.score.cv * 100).toFixed(1)}%`, "CV < 15% e ≥ 8 intervalos", "Média", "Agentes de gestão e telemetria também se comunicam periodicamente. Compare com o software instalado.", { addresses: [beacon.item.source, beacon.item.destination] }, beacon.item.startEpoch))

  const activeAlerts = alerts.filter((item) => !acc.options.suppressedRuleIds.includes(item.ruleId))
  if (!activeAlerts.length) activeAlerts.push(alert("baseline", "Informativo", "Resumo", "Nenhum sinal ativo", alerts.length ? "Os sinais identificados foram suprimidos pelas regras configuradas." : "Os indicadores locais não encontraram um padrão acima dos limites configurados.", "Captura", undefined, `${n(conversations.length)} conversações avaliadas`, "Sem sinais ativos", "Limites configurados", "Baixa", "A ausência de sinal não substitui revisão contextual, cobertura completa de protocolos ou correlação com endpoints."))
  const rank = { Alta: 0, Média: 1, Baixa: 2, Informativo: 3 }
  return activeAlerts.map((item) => enrichAlert(item, baseline)).sort((a, b) => rank[a.severity] - rank[b.severity] || b.riskScore - a.riskScore)
}

function alert(ruleId, severity, category, title, description, source, destination, evidence, observed, threshold, confidence, reason, filter, startEpoch) {
  return { id: ruleId, ruleId, category, severity, confidence, title, description, source, destination, time: startEpoch ? formatTimestamp(startEpoch).slice(0, 8) : "Durante a captura", startEpoch, evidence, observed, threshold, reason, filter }
}

function enrichAlert(item, baseline) {
  const severityScore = { Alta: 80, Média: 60, Baixa: 35, Informativo: 10 }[item.severity] || 10
  const confidenceScore = { Alta: 15, Média: 8, Baixa: 2 }[item.confidence] || 0
  const mitre = {
    "port-scan": { id: "T1046", tactic: "Discovery", technique: "Network Service Discovery" },
    "dns-rate": { id: "T1071.004", tactic: "Command and Control", technique: "DNS" },
    "dns-nxdomain": { id: "T1071.004", tactic: "Command and Control", technique: "DNS" },
    "outbound-ratio": { id: "T1041", tactic: "Exfiltration", technique: "Exfiltration Over C2 Channel" },
  }[item.ruleId]
  return { ...item, riskScore: Math.min(100, severityScore + confidenceScore), baseline: `Mediana por host: ${formatCompact(baseline.medianHostBytes)} e ${n(baseline.medianConnections)} conexões; P95: ${formatCompact(baseline.p95HostBytes)} e ${n(baseline.p95Connections)} conexões.`, mitre }
}

function periodicity(events) {
  if (events.length < 9) return null
  const intervals = events.slice(1).map((time, index) => time - events[index]).filter((value) => value > 0)
  if (!intervals.length) return null
  const mean = intervals.reduce((sum, value) => sum + value, 0) / intervals.length
  const variance = intervals.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / intervals.length
  return { count: intervals.length, mean, cv: Math.sqrt(variance) / Math.max(mean, 0.001) }
}

function normalizeOptions(input) {
  const rules = input?.ruleOptions || {}
  return {
    packetLimit: clamp(optionNumber(input?.packetLimit, DEFAULT_OPTIONS.packetLimit), 1000, 100000),
    memoryBudgetMb: clamp(optionNumber(input?.memoryBudgetMb, DEFAULT_OPTIONS.memoryBudgetMb), 64, 2048),
    analysisMode: input?.analysisMode === "deep" ? "deep" : "standard",
    suppressedRuleIds: Array.isArray(input?.suppressedRuleIds) ? input.suppressedRuleIds.filter((id) => typeof id === "string") : [],
    ruleOptions: {
      portScanPorts: clamp(Number(rules.portScanPorts) || DEFAULT_OPTIONS.ruleOptions.portScanPorts, 5, 1024),
      dnsQueriesPerSecond: clamp(Number(rules.dnsQueriesPerSecond) || DEFAULT_OPTIONS.ruleOptions.dnsQueriesPerSecond, 1, 100000),
      highConnectionCount: clamp(Number(rules.highConnectionCount) || DEFAULT_OPTIONS.ruleOptions.highConnectionCount, 10, 1000000),
      unknownPortConnections: clamp(Number(rules.unknownPortConnections) || DEFAULT_OPTIONS.ruleOptions.unknownPortConnections, 5, 1000000),
      nxDomainRatio: clamp(Number(rules.nxDomainRatio) || DEFAULT_OPTIONS.ruleOptions.nxDomainRatio, 0.01, 1),
      retransmissionRatio: clamp(Number(rules.retransmissionRatio) || DEFAULT_OPTIONS.ruleOptions.retransmissionRatio, 0.01, 1),
      outboundRatio: clamp(Number(rules.outboundRatio) || DEFAULT_OPTIONS.ruleOptions.outboundRatio, 1.1, 100),
      outboundMinimumBytes: clamp(Number(rules.outboundMinimumBytes) || DEFAULT_OPTIONS.ruleOptions.outboundMinimumBytes, 100000, 10000000000),
    },
  }
}

function optionNumber(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function maybeProgress(offset, total, processed) {
  if (processed % 1000 !== 0) return
  const ratio = total ? offset / total : 0
  const stages = ["Lendo captura", "Decodificando protocolos", "Correlacionando DNS e fluxos", "Calculando métricas TCP", "Executando regras", "Preparando a investigação"]
  postProgress(Math.min(96, Math.max(4, Math.round(ratio * 96))), processed, stages[Math.min(stages.length - 1, Math.floor(ratio * stages.length))])
}

function postProgress(percent, processed, stage) {
  postMessage({ type: "progress", percent, processed, stage })
}

function checkCancelled() {
  if (!cancelled) return
  const error = new Error("Análise cancelada.")
  error.name = "CancelledError"
  throw error
}

function compressTimeline(points, limit) {
  if (points.length <= limit) return points
  const size = Math.ceil(points.length / limit)
  const output = []
  for (let index = 0; index < points.length; index += size) {
    const slice = points.slice(index, index + size)
    output.push({ time: slice[0].time, epoch: slice[0].epoch, packets: slice.reduce((sum, item) => sum + item.packets, 0), bytes: slice.reduce((sum, item) => sum + item.bytes, 0), connections: slice.reduce((sum, item) => sum + item.connections, 0) })
  }
  return output
}

function scopeForIp(ip) {
  if (ip.includes(":")) {
    const lower = ip.toLowerCase()
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return "Link-local"
    if (lower.startsWith("ff")) return "Multicast"
    if (lower === "::1" || lower === "::") return "Reservado"
    if (lower.startsWith("fc") || lower.startsWith("fd")) return "Privado"
    return "Público"
  }
  const parts = ip.split(".").map(Number)
  if (parts.length !== 4 || parts.some(Number.isNaN)) return "Reservado"
  if (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168)) return "Privado"
  if (parts[0] === 169 && parts[1] === 254) return "Link-local"
  if (parts[0] >= 224 && parts[0] <= 239) return "Multicast"
  if (parts[0] === 0 || parts[0] === 127 || parts[0] >= 240) return "Reservado"
  return "Público"
}

function vendorForMac(value) {
  return value ? OUI[value.toUpperCase().slice(0, 8)] : undefined
}

function asView(bytes) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength) }
function clamp(value, min, max) { return Math.min(max, Math.max(min, value)) }
function ascii(bytes, start, end) { let output = ""; for (let index = start; index < end && index < bytes.length; index++) output += bytes[index] >= 32 && bytes[index] < 127 ? String.fromCharCode(bytes[index]) : "."; return output }
function mac(bytes, start) { return [...bytes.subarray(start, start + 6)].map((value) => value.toString(16).padStart(2, "0")).join(":") }
function ipv4(bytes, start) { return `${bytes[start]}.${bytes[start + 1]}.${bytes[start + 2]}.${bytes[start + 3]}` }
function ipv6(bytes, start) { const view = asView(bytes); const parts = []; for (let index = 0; index < 16; index += 2) parts.push(view.getUint16(start + index, false).toString(16)); return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::") }
function formatClock(value) { return new Date(value * 1000).toLocaleTimeString("pt-BR", { hour12: false }) }
function formatTimestamp(value) { if (!Number.isFinite(value)) return "—"; const date = new Date(value * 1000); return `${date.toLocaleTimeString("pt-BR", { hour12: false })}.${String(date.getMilliseconds()).padStart(3, "0")}` }
function formatCompact(value) { if (value >= 1e9) return `${(value / 1e9).toFixed(1)} GB`; if (value >= 1e6) return `${(value / 1e6).toFixed(1)} MB`; if (value >= 1e3) return `${(value / 1e3).toFixed(1)} KB`; return `${value} B` }

function md5(input) {
  const source = Uint8Array.from(input, (character) => character.charCodeAt(0) & 255)
  const length = Math.ceil((source.length + 9) / 64) * 64
  const bytes = new Uint8Array(length)
  bytes.set(source)
  bytes[source.length] = 0x80
  const view = new DataView(bytes.buffer)
  const bitLength = source.length * 8
  view.setUint32(length - 8, bitLength >>> 0, true)
  view.setUint32(length - 4, Math.floor(bitLength / 4294967296), true)
  const shifts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
  const constants = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 4294967296) >>> 0)
  let a0 = 0x67452301
  let b0 = 0xefcdab89
  let c0 = 0x98badcfe
  let d0 = 0x10325476
  for (let offset = 0; offset < length; offset += 64) {
    let a = a0
    let b = b0
    let c = c0
    let d = d0
    for (let index = 0; index < 64; index++) {
      let f
      let word
      if (index < 16) { f = (b & c) | (~b & d); word = index }
      else if (index < 32) { f = (d & b) | (~d & c); word = (5 * index + 1) % 16 }
      else if (index < 48) { f = b ^ c ^ d; word = (3 * index + 5) % 16 }
      else { f = c ^ (b | ~d); word = (7 * index) % 16 }
      const sum = (a + f + constants[index] + view.getUint32(offset + word * 4, true)) >>> 0
      const rotated = ((sum << shifts[index]) | (sum >>> (32 - shifts[index]))) >>> 0
      a = d
      d = c
      c = b
      b = (b + rotated) >>> 0
    }
    a0 = (a0 + a) >>> 0
    b0 = (b0 + b) >>> 0
    c0 = (c0 + c) >>> 0
    d0 = (d0 + d) >>> 0
  }
  return [a0, b0, c0, d0].map((word) => [0, 8, 16, 24].map((shift) => ((word >>> shift) & 255).toString(16).padStart(2, "0")).join("")).join("")
}
