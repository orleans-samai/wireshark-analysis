import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import vm from "node:vm"
import ts from "typescript"

const source = await readFile(new URL("../lib/historical-baseline.ts", import.meta.url), "utf8")
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
const exports = {}
vm.runInNewContext(outputText, {
  exports,
  require: (id) => id.endsWith("local-db") ? { readLocalRecord: async () => [], writeLocalRecord: async () => undefined } : {},
  Date, Map, Math, Object, Array, Number, String,
})

const snapshots = [90, 100, 120].map((connections, index) => ({
  id: `old-${index}`,
  analyzedAt: new Date(2026, 0, index + 1).toISOString(),
  hosts: [{ ip: "192.168.1.20", sentBytes: 1_000_000, receivedBytes: 500_000, connections }],
}))

const analysis = {
  id: "current",
  fileName: "current.pcap",
  fileSize: 1,
  analyzedAt: "agora",
  packetCount: 1,
  totalBytes: 1,
  duration: 1,
  hosts: [{ ip: "192.168.1.20", sentPackets: 1, receivedPackets: 1, sentBytes: 1_100_000, receivedBytes: 500_000, connections: 110 }],
  conversations: [], dns: [], ports: [], packets: [], protocols: [], timeline: [],
  alerts: [{ id: "many", ruleId: "many-connections", severity: "Média", confidence: "Alta", title: "Muitas conexões", description: "", source: "192.168.1.20", time: "", evidence: "", reason: "Compare", riskScore: 75 }],
  metadata: { parserVersion: "test", streamed: true, linkTypes: [1], interfaces: 1, retainedPackets: 0, packetLimit: 1, unsupportedPackets: 0, malformedPackets: 0, warnings: [] },
}

const normal = exports.applyHistoricalContext(analysis, snapshots)
assert.equal(normal.alerts[0].riskScore, 55)
assert.equal(normal.alerts[0].confidence, "Média")
assert.match(normal.alerts[0].baseline, /Histórico local \(3 capturas\)/)
assert.equal(normal.metadata.historySamples, 3)

const outlier = exports.applyHistoricalContext({
  ...analysis,
  hosts: [{ ...analysis.hosts[0], connections: 500 }],
}, snapshots)
assert.equal(outlier.alerts[0].riskScore, 80)
assert.equal(outlier.alerts[0].confidence, "Alta")
console.log("Linha de base histórica: redução e elevação de prioridade validadas.")
