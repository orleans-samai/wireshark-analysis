import assert from "node:assert/strict"
import { File } from "node:buffer"
import { readFile } from "node:fs/promises"
import vm from "node:vm"

const workerCode = await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8")
const codecsCode = await readFile(new URL("../public/pcap-codecs.js", import.meta.url), "utf8")

function dnsPacket() {
  const labels = ["example", "com"]
  const qname = Buffer.concat(labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])))
  const dns = Buffer.alloc(12 + qname.length + 5)
  dns.writeUInt16BE(0x1234, 0); dns.writeUInt16BE(0x0100, 2); dns.writeUInt16BE(1, 4)
  qname.copy(dns, 12); dns[12 + qname.length] = 0; dns.writeUInt16BE(1, 13 + qname.length); dns.writeUInt16BE(1, 15 + qname.length)
  const udp = Buffer.alloc(8); udp.writeUInt16BE(53000, 0); udp.writeUInt16BE(53, 2); udp.writeUInt16BE(udp.length + dns.length, 4)
  const ip = Buffer.alloc(20); ip[0] = 0x45; ip.writeUInt16BE(20 + udp.length + dns.length, 2); ip[8] = 64; ip[9] = 17; Buffer.from([192, 168, 1, 20]).copy(ip, 12); Buffer.from([1, 1, 1, 1]).copy(ip, 16)
  const ethernet = Buffer.from("04d4c4882e013c52824fa1200800", "hex")
  return Buffer.concat([ethernet, ip, udp, dns])
}

function pcapFile(packet) {
  const global = Buffer.alloc(24); global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20)
  const record = Buffer.alloc(16); record.writeUInt32LE(1_700_000_000, 0); record.writeUInt32LE(125_000, 4); record.writeUInt32LE(packet.length, 8); record.writeUInt32LE(packet.length, 12)
  return Buffer.concat([global, record, packet])
}

function pcapWithPackets(packets) {
  const global = pcapFile(packets[0]).subarray(0, 24)
  const records = packets.map((packet, index) => {
    const record = Buffer.alloc(16)
    record.writeUInt32LE(1_700_000_000 + index, 0)
    record.writeUInt32LE(packet.length, 8)
    record.writeUInt32LE(packet.length, 12)
    return Buffer.concat([record, packet])
  })
  return Buffer.concat([global, ...records])
}

function block(type, body) {
  const paddedLength = Math.ceil(body.length / 4) * 4
  const total = 12 + paddedLength
  const output = Buffer.alloc(total); output.writeUInt32LE(type, 0); output.writeUInt32LE(total, 4); body.copy(output, 8); output.writeUInt32LE(total, total - 4)
  return output
}

function pcapNgFile(packet) {
  const shb = Buffer.alloc(16); shb.writeUInt32LE(0x1a2b3c4d, 0); shb.writeUInt16LE(1, 4); shb.writeUInt16LE(0, 6); shb.writeBigInt64LE(-1n, 8)
  const idb = Buffer.alloc(8); idb.writeUInt16LE(1, 0); idb.writeUInt32LE(65535, 4)
  const epb = Buffer.alloc(20 + packet.length); epb.writeUInt32LE(0, 0); epb.writeUInt32LE(395_812, 4); epb.writeUInt32LE(1_221_000_000, 8); epb.writeUInt32LE(packet.length, 12); epb.writeUInt32LE(packet.length, 16); packet.copy(epb, 20)
  return Buffer.concat([block(0x0a0d0d0a, shb), block(1, idb), block(6, epb)])
}

async function analyze(buffer, name, options) {
  const messages = []
  const context = { self: {}, postMessage: (message) => messages.push(message), console, DataView, Uint8Array, ArrayBuffer, Date, Map, Set, Math, Intl, Number, String, Error, RegExp }
  vm.createContext(context); vm.runInContext(codecsCode, context); vm.runInContext(workerCode, context)
  await context.self.onmessage({ data: { type: "analyze", file: new File([buffer], name), options } })
  return messages
}

for (const [name, contents] of [["sample.pcap", pcapFile(dnsPacket())], ["sample.pcapng", pcapNgFile(dnsPacket())]]) {
  const messages = await analyze(contents, name)
  const done = messages.find((message) => message.type === "done")
  assert.ok(done, `${name} deve concluir a análise`)
  assert.equal(done.result.packetCount, 1)
  assert.equal(done.result.packets[0].protocol, "DNS")
  assert.equal(done.result.dns[0].domain, "example.com")
  assert.equal(done.result.hosts.length, 2)
  assert.ok(done.result.hosts.every((host) => host.connections === 1), "um único pacote já deve contar uma conversação para ambos os hosts")
}

const dnsResponses = Array.from({ length: 20 }, (_, index) => {
  const packet = dnsPacket()
  // 19 respostas NXDOMAIN seguidas por NOERROR para o mesmo domínio.
  // O status final não pode apagar o histórico das respostas anteriores.
  packet.writeUInt16BE(index === 19 ? 0x8180 : 0x8183, 14 + 20 + 8 + 2)
  return packet
})
const mixedDns = (await analyze(pcapWithPackets(dnsResponses), "dns-mixed.pcap")).find((message) => message.type === "done")?.result
assert.ok(mixedDns, "captura com respostas DNS deve concluir")
assert.equal(mixedDns.dns[0].responses, 20)
assert.equal(mixedDns.dns[0].nxDomainResponses, 19)
assert.equal(mixedDns.dns[0].status, "NOERROR")
assert.match(mixedDns.alerts.find((alert) => alert.ruleId === "dns-nxdomain")?.evidence || "", /19 de 20 respostas/)

const suppressedDns = (await analyze(pcapWithPackets(dnsResponses), "dns-mixed.pcap", { suppressedRuleIds: ["dns-nxdomain"] })).find((message) => message.type === "done")?.result
assert.ok(suppressedDns)
assert.equal(suppressedDns.alerts.some((alert) => alert.ruleId === "dns-nxdomain"), false)
assert.match(suppressedDns.alerts[0]?.description || "", /suprimidos/)

// Orçamento pequeno apenas nesta chamada interna: a normalização da opção
// de usuário mantém o mínimo de 64 MB, que seria caro de estourar num teste.
const budgetContext = { self: {}, postMessage: () => {}, console, DataView, Uint8Array, ArrayBuffer, Date, Map, Set, Math, Intl, Number, String, Error, RegExp }
vm.createContext(budgetContext)
vm.runInContext(codecsCode, budgetContext)
vm.runInContext(workerCode, budgetContext)
const budget = vm.runInContext('createAccumulator("tiny", 1, { packetLimit: 1000, memoryBudgetMb: 0.0001, analysisMode: "standard" })', budgetContext)
budgetContext.budget = budget
vm.runInContext('budget.decodedPackets++; retainPacket(budget, { no: 1, info: "payload", layers: [] })', budgetContext)
assert.equal(budget.memoryLimited, true)
assert.equal(budget.latestPacket, null)

const entityBudget = vm.runInContext('createAccumulator("tiny-entities", 1, { packetLimit: 1000, memoryBudgetMb: 0.001, analysisMode: "standard" })', budgetContext)
budgetContext.entityBudget = entityBudget
vm.runInContext('addHost(entityBudget, "192.0.2.10", true, 100, undefined)', budgetContext)
assert.equal(entityBudget.hosts.size, 0)
assert.equal(entityBudget.droppedEntities.hosts, 1)
assert.equal(entityBudget.memoryLimited, true)

const invalid = await analyze(Buffer.alloc(30), "broken.pcap")
assert.match(invalid.find((message) => message.type === "error").message, /Formato não reconhecido/)
console.log("PCAP, PCAPNG e arquivo inválido: testes concluídos com sucesso.")
