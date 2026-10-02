import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import vm from "node:vm"
import ts from "typescript"

const source = await readFile(new URL("../lib/investigation.ts", import.meta.url), "utf8")
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
const exports = {}
vm.runInNewContext(outputText, { exports })

const filter = { query: "dns", addresses: [], protocols: [], ports: [], domains: [] }
const packet = { no: 1, source: "192.0.2.1", destination: "198.51.100.1", protocol: "DNS", info: "example.com" }
assert.ok(exports.packetMatchesFilter(packet, filter, "example.com"), "busca global e refinamento local devem funcionar como critérios separados")
assert.equal(exports.packetMatchesFilter(packet, filter, "inexistente"), false)
assert.equal(exports.packetMatchesFilter(packet, { ...filter, query: "", from: 0 }, ""), false, "pacote sem horário não corresponde a filtro temporal")

const hosts = Array.from({ length: 110 }, (_, index) => ({ ip: `192.0.2.${index}`, connections: 110 - index }))
const dns = Array.from({ length: 110 }, (_, index) => ({ domain: index === 109 ? "raro.exemplo" : `dominio-${index}.exemplo`, source: "192.0.2.1", queries: 110 - index }))
const index = exports.buildSuggestionIndex({ hosts, dns, protocols: [], ports: [] })
assert.equal(exports.buildSuggestions(index, "192.0.2.109")[0]?.value, "192.0.2.109")
assert.equal(exports.buildSuggestions(index, "raro.exemplo")[0]?.value, "raro.exemplo")
assert.equal(exports.buildSuggestions(index, "").length, 8)
console.log("Filtros combinados e sugestões além do top 100: OK.")
