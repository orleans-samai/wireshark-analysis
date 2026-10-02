// Bateria de robustez do parser PCAP/PCAPNG.
// Roda o worker real no mesmo harness `vm` usado por tests/pcap-worker.test.mjs.
import assert from "node:assert/strict"
import { File } from "node:buffer"
import { readFile } from "node:fs/promises"
import vm from "node:vm"

const workerCode = await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8")
const codecsCode = await readFile(new URL("../public/pcap-codecs.js", import.meta.url), "utf8")

async function analyze(buffer, name, options) {
  const messages = []
  const context = {
    self: {}, postMessage: (m) => messages.push(m), console,
    DataView, Uint8Array, ArrayBuffer, Date, Map, Set, Math, Intl, Number, String, Error, RegExp, TextDecoder,
  }
  vm.createContext(context)
  vm.runInContext(codecsCode, context)
  vm.runInContext(workerCode, context)
  await context.self.onmessage({ data: { type: "analyze", file: new File([buffer], name), options } })
  const done = messages.find((m) => m.type === "done")
  const err = messages.find((m) => m.type === "error")
  return { done: done?.result, error: err?.message }
}

/* ---------- construtores de quadro ---------- */

const cat = (...a) => Buffer.concat(a.map((x) => Buffer.from(x)))

function eth(etherType, vlan = null) {
  const base = Buffer.alloc(vlan === null ? 14 : 18)
  Buffer.from([0x04, 0xd4, 0xc4, 0x88, 0x2e, 0x01]).copy(base, 0)
  Buffer.from([0x3c, 0x52, 0x82, 0x4f, 0xa1, 0x20]).copy(base, 6)
  if (vlan === null) {
    base.writeUInt16BE(etherType, 12)
  } else {
    base.writeUInt16BE(0x8100, 12)
    base.writeUInt16BE(vlan, 14)
    base.writeUInt16BE(etherType, 16)
  }
  return base
}

// ihl em palavras de 32 bits (5 = sem opções)
function ipv4(proto, src, dst, payloadLen, ihl = 5) {
  const ip = Buffer.alloc(ihl * 4)
  ip[0] = 0x40 | ihl
  ip.writeUInt16BE(ihl * 4 + payloadLen, 2)
  ip[8] = 64
  ip[9] = proto
  Buffer.from(src).copy(ip, 12)
  Buffer.from(dst).copy(ip, 16)
  if (ihl > 5) ip[20] = 0x01 // NOP como opção
  return ip
}

function ipv4Fragment(proto, src, dst, payload, identification, offsetBytes, moreFragments) {
  const ip = ipv4(proto, src, dst, payload.length)
  ip.writeUInt16BE(identification, 4)
  ip.writeUInt16BE((moreFragments ? 0x2000 : 0) | Math.floor(offsetBytes / 8), 6)
  return cat(ip, payload)
}

// dataOffset em palavras de 32 bits (5 = sem opções)
function tcp(sp, dp, flags, payload, dataOffset = 5, sequence = 1000) {
  const t = Buffer.alloc(dataOffset * 4 + payload.length)
  t.writeUInt16BE(sp, 0)
  t.writeUInt16BE(dp, 2)
  t.writeUInt32BE(sequence, 4)
  t[12] = dataOffset << 4
  t[13] = flags
  t.writeUInt16BE(65535, 14)
  Buffer.from(payload).copy(t, dataOffset * 4)
  return t
}

function udp(sp, dp, payload) {
  const u = Buffer.alloc(8 + payload.length)
  u.writeUInt16BE(sp, 0)
  u.writeUInt16BE(dp, 2)
  u.writeUInt16BE(8 + payload.length, 4)
  Buffer.from(payload).copy(u, 8)
  return u
}

function dnsQuery(host) {
  const parts = []
  for (const label of host.split(".")) { parts.push(label.length); for (const c of label) parts.push(c.charCodeAt(0)) }
  parts.push(0)
  const q = Buffer.from(parts)
  const d = Buffer.alloc(12 + q.length + 4)
  d.writeUInt16BE(0x1234, 0); d.writeUInt16BE(0x0100, 2); d.writeUInt16BE(1, 4)
  q.copy(d, 12); d.writeUInt16BE(1, 12 + q.length); d.writeUInt16BE(1, 14 + q.length)
  return d
}

function dnsResponse(host, address = [203, 0, 113, 10]) {
  const query = dnsQuery(host)
  const answer = Buffer.alloc(16)
  answer.writeUInt16BE(0xc00c, 0)
  answer.writeUInt16BE(1, 2)
  answer.writeUInt16BE(1, 4)
  answer.writeUInt32BE(60, 6)
  answer.writeUInt16BE(4, 10)
  Buffer.from(address).copy(answer, 12)
  query.writeUInt16BE(0x8180, 2)
  query.writeUInt16BE(1, 6)
  return Buffer.concat([query, answer])
}

function tlsClientHello(host) {
  const sniName = Buffer.from(host)
  const sniBody = Buffer.alloc(5 + sniName.length)
  sniBody.writeUInt16BE(3 + sniName.length, 0)
  sniBody[2] = 0
  sniBody.writeUInt16BE(sniName.length, 3)
  sniName.copy(sniBody, 5)
  const sni = Buffer.concat([Buffer.from([0, 0, sniBody.length >> 8, sniBody.length & 255]), sniBody])

  const alpnBody = Buffer.from([0, 3, 2, 0x68, 0x32])
  const alpn = Buffer.concat([Buffer.from([0, 16, 0, alpnBody.length]), alpnBody])
  const versionsBody = Buffer.from([2, 3, 4])
  const versions = Buffer.concat([Buffer.from([0, 43, 0, versionsBody.length]), versionsBody])
  const extensions = Buffer.concat([sni, alpn, versions])

  const hello = Buffer.alloc(34 + 1 + 2 + 2 + 1 + 1 + 2)
  hello.writeUInt16BE(0x0303, 0)
  let cursor = 34
  hello[cursor++] = 0
  hello.writeUInt16BE(2, cursor); cursor += 2
  hello.writeUInt16BE(0x1301, cursor); cursor += 2
  hello[cursor++] = 1
  hello[cursor++] = 0
  hello.writeUInt16BE(extensions.length, cursor)
  const body = Buffer.concat([hello, extensions])
  const handshake = Buffer.alloc(4)
  handshake[0] = 1
  handshake[1] = (body.length >> 16) & 255
  handshake[2] = (body.length >> 8) & 255
  handshake[3] = body.length & 255
  const recordPayload = Buffer.concat([handshake, body])
  const record = Buffer.alloc(5)
  record[0] = 22
  record.writeUInt16BE(0x0301, 1)
  record.writeUInt16BE(recordPayload.length, 3)
  return Buffer.concat([record, recordPayload])
}

const dnsFrame = (opts = {}) => {
  const u = udp(53000, 53, dnsQuery(opts.host || "exemplo.com"))
  return cat(eth(0x0800, opts.vlan ?? null), ipv4(17, [192, 168, 1, 20], [1, 1, 1, 1], u.length, opts.ihl || 5), u)
}

/* ---------- construtores de arquivo ---------- */

const MAGICS = {
  "le-micro": { value: 0xa1b2c3d4, little: true, nano: false },
  "be-micro": { value: 0xa1b2c3d4, little: false, nano: false },
  "le-nano": { value: 0xa1b23c4d, little: true, nano: true },
  "be-nano": { value: 0xa1b23c4d, little: false, nano: true },
}

function pcapFile(frames, { magic = "le-micro", linkType = 1, capLenOverride = null, truncateTail = 0 } = {}) {
  const m = MAGICS[magic]
  const head = Buffer.alloc(24)
  if (m.little) head.writeUInt32LE(m.value, 0); else head.writeUInt32BE(m.value, 0)
  const w16 = (v, o) => (m.little ? head.writeUInt16LE(v, o) : head.writeUInt16BE(v, o))
  const w32 = (v, o) => (m.little ? head.writeUInt32LE(v, o) : head.writeUInt32BE(v, o))
  w16(2, 4); w16(4, 6); w32(65535, 16); w32(linkType, 20)

  const parts = [head]
  frames.forEach((pkt, i) => {
    const captured = capLenOverride === null ? pkt.length : Math.min(capLenOverride, pkt.length)
    const rec = Buffer.alloc(16)
    const r32 = (v, o) => (m.little ? rec.writeUInt32LE(v, o) : rec.writeUInt32BE(v, o))
    r32(1700000000 + i, 0)
    r32(m.nano ? 125000000 : 125000, 4)
    r32(captured, 8)
    r32(pkt.length, 12)
    parts.push(rec, pkt.subarray(0, captured))
  })
  const out = Buffer.concat(parts)
  return truncateTail ? out.subarray(0, out.length - truncateTail) : out
}

function ngBlock(type, body, little = true) {
  const pad = (4 - (body.length % 4)) % 4
  const total = 12 + body.length + pad
  const out = Buffer.alloc(total)
  if (little) { out.writeUInt32LE(type, 0); out.writeUInt32LE(total, 4); out.writeUInt32LE(total, total - 4) }
  else { out.writeUInt32BE(type, 0); out.writeUInt32BE(total, 4); out.writeUInt32BE(total, total - 4) }
  Buffer.from(body).copy(out, 8)
  return out
}

function pcapNgFile(frames, { little = true, linkTypes = [1], withOptions = false, tsresol = null, simpleBlocks = false, gapTicks = 250000 } = {}) {
  const shb = Buffer.alloc(16)
  if (little) { shb.writeUInt32LE(0x1a2b3c4d, 0); shb.writeUInt16LE(1, 4); shb.writeUInt16LE(0, 6); shb.writeBigInt64LE(-1n, 8) }
  else { shb.writeUInt32BE(0x1a2b3c4d, 0); shb.writeUInt16BE(1, 4); shb.writeUInt16BE(0, 6); shb.writeBigInt64BE(-1n, 8) }
  const shbBody = withOptions
    ? Buffer.concat([shb, optBlock(3, Buffer.from("PacketLens QA"), little), endOpt(little)])
    : shb
  const blocks = [ngBlock(0x0a0d0d0a, shbBody, little)]

  for (const lt of linkTypes) {
    const idb = Buffer.alloc(8)
    if (little) { idb.writeUInt16LE(lt, 0); idb.writeUInt32LE(65535, 4) }
    else { idb.writeUInt16BE(lt, 0); idb.writeUInt32BE(65535, 4) }
    const body = tsresol === null ? idb : Buffer.concat([idb, optBlock(9, Buffer.from([tsresol]), little), endOpt(little)])
    blocks.push(ngBlock(1, body, little))
  }

  frames.forEach((pkt, i) => {
    if (simpleBlocks) {
      const spb = Buffer.alloc(4 + pkt.length)
      if (little) spb.writeUInt32LE(pkt.length, 0); else spb.writeUInt32BE(pkt.length, 0)
      Buffer.from(pkt).copy(spb, 4)
      blocks.push(ngBlock(3, spb, little))
      return
    }
    const unit = tsresol === 9 ? 1000000000n : 1000000n
    const ts = BigInt(1700000000) * unit + BigInt(i) * BigInt(gapTicks)
    const epb = Buffer.alloc(20 + pkt.length)
    const iface = i % linkTypes.length
    if (little) {
      epb.writeUInt32LE(iface, 0)
      epb.writeUInt32LE(Number(ts >> 32n), 4)
      epb.writeUInt32LE(Number(ts & 0xffffffffn), 8)
      epb.writeUInt32LE(pkt.length, 12); epb.writeUInt32LE(pkt.length, 16)
    } else {
      epb.writeUInt32BE(iface, 0)
      epb.writeUInt32BE(Number(ts >> 32n), 4)
      epb.writeUInt32BE(Number(ts & 0xffffffffn), 8)
      epb.writeUInt32BE(pkt.length, 12); epb.writeUInt32BE(pkt.length, 16)
    }
    Buffer.from(pkt).copy(epb, 20)
    blocks.push(ngBlock(6, epb, little))
  })
  return Buffer.concat(blocks)
}

function optBlock(code, value, little) {
  const pad = (4 - (value.length % 4)) % 4
  const b = Buffer.alloc(4 + value.length + pad)
  if (little) { b.writeUInt16LE(code, 0); b.writeUInt16LE(value.length, 2) }
  else { b.writeUInt16BE(code, 0); b.writeUInt16BE(value.length, 2) }
  value.copy(b, 4)
  return b
}
const endOpt = (little) => optBlock(0, Buffer.alloc(0), little)

/* ---------- casos ---------- */

const cases = []
const add = (name, buf, fileName, check) => cases.push({ name, buf, fileName, check })

// 1-4: as quatro ordens de byte / resoluções de timestamp
for (const magic of Object.keys(MAGICS)) {
  add(`pcap magic ${magic}`, pcapFile([dnsFrame()], { magic }), "m.pcap", (r) => {
    if (r.done?.packetCount !== 1) return `packetCount=${r.done?.packetCount}`
    if (r.done.packets[0].protocol !== "DNS") return `protocol=${r.done.packets[0].protocol}`
    if (r.done.dns[0]?.domain !== "exemplo.com") return `domain=${r.done.dns[0]?.domain}`
    return null
  })
}

// 5: quadro com tag VLAN 802.1Q
add("quadro com VLAN 802.1Q", pcapFile([dnsFrame({ vlan: 0x0064 })]), "vlan.pcap", (r) =>
  r.done?.packets[0]?.protocol === "DNS" ? null : `protocol=${r.done?.packets[0]?.protocol}`)

// 6: cabeçalho IPv4 com opções (IHL=6)
add("IPv4 com opções (IHL=6)", pcapFile([dnsFrame({ ihl: 6 })]), "ihl.pcap", (r) =>
  r.done?.packets[0]?.protocol === "DNS" ? null : `protocol=${r.done?.packets[0]?.protocol}`)

// 7: TCP com opções (data offset 8)
const tcpOpt = (() => { const t = tcp(50000, 443, 0x18, Buffer.from([0x17, 3, 3, 0, 32]), 8); return cat(eth(0x0800), ipv4(6, [10, 0, 0, 5], [142, 250, 0, 1], t.length), t) })()
add("TCP com opções (offset 8)", pcapFile([tcpOpt]), "tcpopt.pcap", (r) =>
  r.done?.packets[0]?.protocol === "TCP" && r.done?.packets[0]?.serviceHint === "HTTPS provável" ? null : `protocol=${r.done?.packets[0]?.protocol} serviço=${r.done?.packets[0]?.serviceHint}`)

// 8: snaplen truncado (caplen < origlen) — muito comum em campo
add("snaplen truncado (caplen 40 < origlen)", pcapFile([dnsFrame()], { capLenOverride: 40 }), "snap.pcap", (r) => {
  if (r.error) return `erro: ${r.error}`
  if (r.done?.packetCount !== 1) return `packetCount=${r.done?.packetCount}`
  if (r.done.totalBytes !== dnsFrame().length) return `totalBytes=${r.done.totalBytes} (esperado tamanho original)`
  return null
})

// 9: snaplen agressivo, corta dentro do cabeçalho IP
add("snaplen corta dentro do IP (caplen 20)", pcapFile([dnsFrame()], { capLenOverride: 20 }), "snap2.pcap", (r) =>
  r.error ? `erro: ${r.error}` : (r.done?.packetCount === 1 ? null : `packetCount=${r.done?.packetCount}`))

// 10: último registro truncado
add("último registro truncado", pcapFile([dnsFrame(), dnsFrame()], { truncateTail: 20 }), "trunc.pcap", (r) =>
  r.error && /truncado|corrompido/i.test(r.error) ? null : `esperava erro amigável, veio: ${r.error || "sucesso"}`)

// 11: linktype 101 (IP cru, sem Ethernet)
const rawIp = (() => { const u = udp(53000, 53, dnsQuery("cru.exemplo.net")); return cat(ipv4(17, [172, 16, 0, 9], [8, 8, 8, 8], u.length), u) })()
add("linktype 101 (IP cru)", pcapFile([rawIp], { linkType: 101 }), "raw.pcap", (r) =>
  r.done?.packets[0]?.protocol === "DNS" ? null : `protocol=${r.done?.packets[0]?.protocol}`)

// 12: pcapng big-endian
add("pcapng big-endian", pcapNgFile([dnsFrame()], { little: false }), "be.pcapng", (r) =>
  r.done?.packetCount === 1 && r.done.packets[0].protocol === "DNS" ? null : `packetCount=${r.done?.packetCount} protocol=${r.done?.packets[0]?.protocol}`)

// 13: pcapng com opções no SHB
add("pcapng com opções no SHB", pcapNgFile([dnsFrame()], { withOptions: true }), "opt.pcapng", (r) =>
  r.done?.packetCount === 1 ? null : `packetCount=${r.done?.packetCount} erro=${r.error}`)

// 14: pcapng com múltiplas interfaces
add("pcapng com 2 interfaces", pcapNgFile([dnsFrame(), rawIp], { linkTypes: [1, 101] }), "multi.pcapng", (r) =>
  r.done?.packetCount === 2 && r.done.packets.every((p) => p.protocol === "DNS") ? null
    : `packetCount=${r.done?.packetCount} protocolos=${r.done?.packets.map((p) => p.protocol).join(",")}`)

// 15: pcapng com if_tsresol = 9 (nanossegundos) — duração tem de bater com microssegundos
add("pcapng if_tsresol=9 (nanossegundos)", pcapNgFile([dnsFrame(), dnsFrame()], { tsresol: 9, gapTicks: 250000000 }), "ns.pcapng", (r) => {
  if (!r.done) return `erro: ${r.error}`
  return Math.abs(r.done.duration - 0.25) < 1e-6 ? null : `duração=${r.done.duration}s (esperado 0,25s)`
})

// 15b: if_tsresol na forma potência de 2 (0x80 | 20 => 2^20 ~ 1 MHz)
add("pcapng if_tsresol=2^20", pcapNgFile([dnsFrame(), dnsFrame()], { tsresol: 0x80 | 20, gapTicks: 1 << 18 }), "p2.pcapng", (r) => {
  if (!r.done) return `erro: ${r.error}`
  return Math.abs(r.done.duration - 0.25) < 1e-6 ? null : `duração=${r.done.duration}s (esperado 0,25s)`
})

// 15c: sem a opção, o padrão continua microssegundos
add("pcapng sem if_tsresol (padrão us)", pcapNgFile([dnsFrame(), dnsFrame()], { gapTicks: 250000 }), "def.pcapng", (r) => {
  if (!r.done) return `erro: ${r.error}`
  return Math.abs(r.done.duration - 0.25) < 1e-6 ? null : `duração=${r.done.duration}s (esperado 0,25s)`
})

// 16: pcapng com Simple Packet Blocks
add("pcapng com Simple Packet Block", pcapNgFile([dnsFrame()], { simpleBlocks: true }), "spb.pcapng", (r) =>
  r.done?.packetCount === 1 && r.done.firstEpoch === undefined && r.done.packets[0].epoch === undefined && r.done.timeline.length === 0 && r.done.packets[0].timestamp === "—" ? null : `horário indevido=${r.done?.firstEpoch} epoch=${r.done?.packets[0]?.epoch} erro=${r.error}`)

// 17: arquivo só com cabeçalho, zero pacotes
add("pcap sem pacotes", pcapFile([]), "vazio-valido.pcap", (r) =>
  r.error ? null : `esperava erro, veio packetCount=${r.done?.packetCount}`)

// 18: quadro Ethernet curto demais
add("quadro Ethernet de 8 bytes", pcapFile([Buffer.alloc(8)]), "curto.pcap", (r) =>
  r.error ? `erro: ${r.error}` : (r.done?.packetCount === 1 ? null : `packetCount=${r.done?.packetCount}`))

// 19: etherType desconhecido (ARP)
add("etherType ARP (0x0806)", pcapFile([cat(eth(0x0806), Buffer.alloc(28))]), "arp.pcap", (r) =>
  r.error ? `erro: ${r.error}` : (r.done?.packetCount === 1 ? null : `packetCount=${r.done?.packetCount}`))

// 20: DNS com ponteiro de compressão no QNAME
const dnsCompressed = (() => {
  const d = Buffer.alloc(12 + 2 + 4)
  d.writeUInt16BE(0x1234, 0); d.writeUInt16BE(0x8180, 2); d.writeUInt16BE(1, 4)
  d[12] = 0xc0; d[13] = 0x0c
  const u = udp(53, 53000, d)
  return cat(eth(0x0800), ipv4(17, [1, 1, 1, 1], [192, 168, 1, 20], u.length), u)
})()
add("DNS com ponteiro de compressão", pcapFile([dnsCompressed]), "comp.pcap", (r) =>
  r.error ? `erro: ${r.error}` : (r.done?.packetCount === 1 ? null : `packetCount=${r.done?.packetCount}`))

/* ---------- execução ---------- */

// Application-layer extraction: HTTP request metadata.
const httpPayload = Buffer.from("GET /health?full=1 HTTP/1.1\r\nHost: api.exemplo.test\r\nUser-Agent: PacketLens-QA\r\nAccept: */*\r\n\r\n")
const httpFrame = (() => { const t = tcp(51000, 80, 0x18, httpPayload); return cat(eth(0x0800), ipv4(6, [192, 168, 1, 40], [203, 0, 113, 20], t.length), t) })()
add("HTTP extracts method, host, path and user-agent", pcapFile([httpFrame]), "http.pcap", (r) => {
  const row = r.done?.http?.[0]
  if (!row) return `HTTP not extracted; protocol=${r.done?.packets?.[0]?.protocol}`
  if (row.method !== "GET" || row.host !== "api.exemplo.test" || row.path !== "/health?full=1" || row.userAgent !== "PacketLens-QA") return `fields=${JSON.stringify(row)}`
  return null
})

// TLS ClientHello metadata: SNI, ALPN and supported version.
const tlsFrame = (() => { const t = tcp(52000, 443, 0x18, tlsClientHello("secure.exemplo.test")); return cat(eth(0x0800), ipv4(6, [192, 168, 1, 41], [203, 0, 113, 21], t.length), t) })()
add("TLS ClientHello extracts SNI, ALPN and version", pcapFile([tlsFrame]), "tls.pcap", (r) => {
  const row = r.done?.tls?.[0]
  if (!row) return `TLS not extracted; protocol=${r.done?.packets?.[0]?.protocol}`
  if (row.serverName !== "secure.exemplo.test" || !row.alpn?.includes("h2") || row.version !== "TLS 1.3") return `fields=${JSON.stringify(row)}`
  return null
})

// DNS request/response correlation, including A answer and latency.
const dnsPair = (() => {
  const q = udp(53000, 53, dnsQuery("correlacao.exemplo"))
  const a = udp(53, 53000, dnsResponse("correlacao.exemplo"))
  return [
    cat(eth(0x0800), ipv4(17, [192, 168, 1, 42], [1, 1, 1, 1], q.length), q),
    cat(eth(0x0800), ipv4(17, [1, 1, 1, 1], [192, 168, 1, 42], a.length), a),
  ]
})()
add("DNS correlates query, response, A answer and latency", pcapFile(dnsPair), "dns-pair.pcap", (r) => {
  const row = r.done?.dns?.find((item) => item.domain === "correlacao.exemplo")
  if (!row) return "DNS row missing"
  if (row.queries !== 1 || row.responses !== 1 || row.answer !== "203.0.113.10" || row.responseTime !== 1000) return `fields=${JSON.stringify(row)}`
  return null
})

// Mesmos ID, domínio e hosts, mas portas clientes diferentes: cada resposta
// deve encontrar sua própria consulta mesmo quando chegam em ordem inversa.
const overlappingDns = [
  cat(eth(0x0800), ipv4(17, [192, 168, 1, 42], [1, 1, 1, 1], udp(53000, 53, dnsQuery("mesmo.exemplo")).length), udp(53000, 53, dnsQuery("mesmo.exemplo"))),
  cat(eth(0x0800), ipv4(17, [192, 168, 1, 42], [1, 1, 1, 1], udp(53001, 53, dnsQuery("mesmo.exemplo")).length), udp(53001, 53, dnsQuery("mesmo.exemplo"))),
  cat(eth(0x0800), ipv4(17, [1, 1, 1, 1], [192, 168, 1, 42], udp(53, 53001, dnsResponse("mesmo.exemplo")).length), udp(53, 53001, dnsResponse("mesmo.exemplo"))),
  cat(eth(0x0800), ipv4(17, [1, 1, 1, 1], [192, 168, 1, 42], udp(53, 53000, dnsResponse("mesmo.exemplo")).length), udp(53, 53000, dnsResponse("mesmo.exemplo"))),
]
add("DNS diferencia consultas simultâneas por porta", pcapFile(overlappingDns), "dns-portas.pcap", (r) => {
  const row = r.done?.dns?.find((item) => item.domain === "mesmo.exemplo")
  return row?.responses === 2 && row.responseTime === 2000 ? null : `latência=${row?.responseTime}ms respostas=${row?.responses}`
})

const httpDeepPayload = Buffer.from(`GET /deep HTTP/1.1\r\nX-Pad: ${"a".repeat(8300)}\r\nHost: deep.exemplo\r\n\r\n`)
const httpDeepTcp = tcp(51000, 80, 0x18, httpDeepPayload)
const httpDeepFrame = cat(eth(0x0800), ipv4(6, [192, 168, 1, 40], [203, 0, 113, 20], httpDeepTcp.length), httpDeepTcp)
const deepResults = await Promise.all([
  analyze(pcapFile([httpDeepFrame]), "standard.pcap", { analysisMode: "standard" }),
  analyze(pcapFile([httpDeepFrame]), "deep.pcap", { analysisMode: "deep" }),
])
assert.equal(deepResults[0].done?.packets[0]?.protocol, "TCP")
assert.equal(deepResults[1].done?.packets[0]?.protocol, "HTTP")
assert.equal(deepResults[1].done?.metadata?.analysisMode, "deep")

const httpSplit = Buffer.from("GET /reassembled HTTP/1.1\r\nHost: split.exemplo\r\n\r\n")
const splitAt = 18
const firstSplitTcp = tcp(51010, 80, 0x18, httpSplit.subarray(0, splitAt), 5, 5000)
const secondSplitTcp = tcp(51010, 80, 0x18, httpSplit.subarray(splitAt), 5, 5000 + splitAt)
const splitFrames = [firstSplitTcp, secondSplitTcp].map((segment) => cat(eth(0x0800), ipv4(6, [192, 168, 1, 50], [203, 0, 113, 50], segment.length), segment))
const reassembled = await analyze(pcapFile(splitFrames), "reassembled.pcap", { analysisMode: "deep" })
assert.equal(reassembled.done?.http?.[0]?.host, "split.exemplo")
assert.equal(reassembled.done?.packets.at(-1)?.protocol, "HTTP")
assert.equal(reassembled.done?.metadata?.reassembledStreams, 1)

const outOfOrderFrames = [secondSplitTcp, firstSplitTcp].map((segment) => cat(eth(0x0800), ipv4(6, [192, 168, 1, 50], [203, 0, 113, 50], segment.length), segment))
const outOfOrder = await analyze(pcapFile(outOfOrderFrames), "out-of-order.pcap", { analysisMode: "deep" })
assert.equal(outOfOrder.done?.http?.[0]?.host, "split.exemplo")
assert.equal(outOfOrder.done?.packets.at(-1)?.protocol, "HTTP")

const fragmentedUdp = udp(53100, 53, dnsQuery("fragmentado.exemplo"))
const fragmentSplit = 16
const ipv4FragmentFrames = [
  cat(eth(0x0800), ipv4Fragment(17, [192, 168, 1, 70], [1, 1, 1, 1], fragmentedUdp.subarray(fragmentSplit), 0x4242, fragmentSplit, false)),
  cat(eth(0x0800), ipv4Fragment(17, [192, 168, 1, 70], [1, 1, 1, 1], fragmentedUdp.subarray(0, fragmentSplit), 0x4242, 0, true)),
]
const fragmented = await analyze(pcapFile(ipv4FragmentFrames), "fragmented-ipv4.pcap", { analysisMode: "deep" })
assert.equal(fragmented.done?.dns?.[0]?.domain, "fragmentado.exemplo")
assert.equal(fragmented.done?.packets.at(-1)?.protocol, "DNS")
assert.equal(fragmented.done?.packets.at(-1)?.reassembled, true)
assert.equal(fragmented.done?.metadata?.reassembledDatagrams, 1)

const http2Preface = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
const http2Tcp = tcp(51020, 80, 0x18, http2Preface)
const http2 = await analyze(pcapFile([cat(eth(0x0800), ipv4(6, [192, 168, 1, 51], [203, 0, 113, 51], http2Tcp.length), http2Tcp)]), "http2.pcap")
assert.equal(http2.done?.packets[0]?.protocol, "HTTP/2")
assert.equal(http2.done?.http?.[0]?.version, "HTTP/2")

const quicPayload = Buffer.from("c00000000108112233445566778808aabbccddeeff001100000000", "hex")
const quicUdp = udp(52020, 443, quicPayload)
const quic = await analyze(pcapFile([cat(eth(0x0800), ipv4(17, [192, 168, 1, 52], [203, 0, 113, 52], quicUdp.length), quicUdp)]), "quic.pcap")
assert.equal(quic.done?.packets[0]?.protocol, "QUIC")
assert.equal(quic.done?.quic?.[0]?.packetType, "Initial")
assert.equal(quic.done?.quic?.[0]?.destinationConnectionId, "1122334455667788")

const tlsFingerprint = await analyze(pcapFile([tlsFrame]), "ja3.pcap")
assert.match(tlsFingerprint.done?.tls?.[0]?.ja3 || "", /^[a-f0-9]{32}$/)
assert.deepEqual(Array.from(tlsFingerprint.done?.tls?.[0]?.cipherSuiteIds || []), [0x1301])
assert.ok(tlsFingerprint.done?.baseline)
assert.equal(tlsFingerprint.done?.metadata?.engine, "browser")
assert.ok(tlsFingerprint.done?.metadata?.analysisMs >= 1)
assert.ok(tlsFingerprint.done?.alerts?.[0]?.riskScore > 0)

const scanFrames = Array.from({ length: 8 }, (_, index) => {
  const segment = tcp(53000, 2000 + index, 0x02, Buffer.alloc(0), 5, 9000 + index)
  return cat(eth(0x0800), ipv4(6, [192, 168, 1, 60], [203, 0, 113, 60], segment.length), segment)
})
const scan = await analyze(pcapFile(scanFrames), "scan.pcap", { ruleOptions: { portScanPorts: 5 } })
const scanAlert = scan.done?.alerts.find((alert) => alert.ruleId === "port-scan")
assert.equal(scanAlert?.mitre?.id, "T1046")
assert.ok(scanAlert?.riskScore >= 60)
assert.match(scanAlert?.baseline || "", /Mediana por host/)
const suppressedScan = await analyze(pcapFile(scanFrames), "scan-suppressed.pcap", { ruleOptions: { portScanPorts: 5 }, suppressedRuleIds: ["port-scan"] })
assert.equal(suppressedScan.done?.alerts.some((alert) => alert.ruleId === "port-scan"), false)

const many = await analyze(pcapFile(Array.from({ length: 1200 }, () => dnsFrame())), "distributed.pcap", { packetLimit: 1000, memoryBudgetMb: 64 })
assert.equal(many.done?.packets.length, 1000)
assert.equal(many.done?.packets.at(-1).no, 1200)
assert.equal(new Set(many.done?.packets.map((packet) => packet.no)).size, 1000)
assert.equal(many.done?.metadata?.sampleStrategy, "distributed")
assert.ok(many.done?.metadata?.estimatedMemoryBytes <= 64 * 1024 * 1024)

const fails = []
for (const c of cases) {
  let verdict
  try {
    verdict = c.check(await analyze(c.buf, c.fileName))
  } catch (e) {
    verdict = `exceção: ${e.message}`
  }
  if (verdict !== null) fails.push(` - ${c.name}: ${verdict}`)
}
assert.equal(fails.length, 0, "Casos de robustez do parser falharam:" + fails.join(""))
console.log(`Robustez do parser: ${cases.length} casos concluídos com sucesso.`)
