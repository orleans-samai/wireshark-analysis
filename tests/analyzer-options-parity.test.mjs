// Garante que os padrões do worker espelhem lib/analyzer-options.ts.
// O worker é JS puro em public/ e não pode importar o módulo TS, então a
// paridade é verificada por texto: se este teste quebrar, atualize os dois
// lados (ou extraia os padrões para um JSON compartilhado).
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"

const KEYS = [
  "packetLimit",
  "memoryBudgetMb",
  "portScanPorts",
  "dnsQueriesPerSecond",
  "highConnectionCount",
  "unknownPortConnections",
  "nxDomainRatio",
  "retransmissionRatio",
  "outboundRatio",
  "outboundMinimumBytes",
]

function extract(source, file) {
  const values = {}
  for (const key of KEYS) {
    const match = source.match(new RegExp(`${key}:\\s*([0-9][0-9_]*\\.?[0-9_]*)`))
    assert.ok(match, `${file} deve declarar ${key}`)
    values[key] = Number(match[1].replace(/_/g, ""))
  }
  return values
}

const lib = extract(await readFile(new URL("../lib/analyzer-options.ts", import.meta.url), "utf8"), "lib/analyzer-options.ts")
const worker = extract(await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8"), "public/pcap-worker.js")

assert.deepEqual(worker, lib, "DEFAULT_OPTIONS do worker divergiu de DEFAULT_ANALYZER_OPTIONS")
const libSource = await readFile(new URL("../lib/analyzer-options.ts", import.meta.url), "utf8")
const workerSource = await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8")
assert.equal(libSource.match(/analysisMode:\s*"([^"]+)"/)?.[1], workerSource.match(/analysisMode:\s*"([^"]+)"/)?.[1])
assert.match(libSource, /suppressedRuleIds:\s*\[\]/)
assert.match(workerSource, /suppressedRuleIds:\s*\[\]/)
console.log("Paridade das opções do analisador: padrões idênticos nos dois lados.")
