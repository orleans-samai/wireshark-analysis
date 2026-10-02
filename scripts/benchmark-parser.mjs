import { existsSync } from "node:fs"
import { resolve } from "node:path"
import { runWorkerAnalysis } from "./run-worker-analysis.mjs"

const input = process.argv[2]
if (!input) {
  console.error("Uso: npm run bench:capture -- caminho/arquivo.pcap [repetições]")
  process.exit(1)
}
const path = resolve(input)
if (!existsSync(path)) {
  console.error(`Arquivo não encontrado: ${path}`)
  process.exit(1)
}
const repeats = Math.min(10, Math.max(1, Number(process.argv[3]) || 3))
const numericFlag = (name) => {
  const index = process.argv.indexOf(name)
  return index >= 0 ? Number(process.argv[index + 1]) : undefined
}
const minimumThroughput = numericFlag("--min-mbps")
const maximumMemoryMb = numericFlag("--max-memory-mb")
const samples = []
for (let index = 0; index < repeats; index++) {
  const started = performance.now()
  const result = await runWorkerAnalysis(path, { analysisMode: "deep", packetLimit: 20_000, memoryBudgetMb: 256 })
  samples.push({ elapsed: performance.now() - started, result })
}
samples.sort((a, b) => a.elapsed - b.elapsed)
const median = samples[Math.floor(samples.length / 2)]
console.log(`Mediana de ${repeats} execução(ões): ${(median.elapsed / 1000).toFixed(2)} s`)
console.log(`${median.result.packetCount.toLocaleString("pt-BR")} pacotes · ${median.result.metadata.throughputMbps.toFixed(2)} Mb/s no worker · ${(median.result.metadata.estimatedMemoryBytes / 1024 / 1024).toFixed(1)} MB estimados`)
if (Number.isFinite(minimumThroughput) && median.result.metadata.throughputMbps < minimumThroughput) {
  console.error(`Regressão: vazão ${median.result.metadata.throughputMbps.toFixed(2)} Mb/s abaixo do mínimo de ${minimumThroughput} Mb/s.`)
  process.exitCode = 1
}
const measuredMemoryMb = median.result.metadata.estimatedMemoryBytes / 1024 / 1024
if (Number.isFinite(maximumMemoryMb) && measuredMemoryMb > maximumMemoryMb) {
  console.error(`Regressão: memória estimada ${measuredMemoryMb.toFixed(1)} MB acima do máximo de ${maximumMemoryMb} MB.`)
  process.exitCode = 1
}
