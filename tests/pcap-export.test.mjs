import assert from "node:assert/strict"
import { File } from "node:buffer"
import { readFile } from "node:fs/promises"
import vm from "node:vm"
import ts from "typescript"

const source = await readFile(new URL("../lib/pcap-export.ts", import.meta.url), "utf8")
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
const exports = {}
let downloaded
let batches = 0
class TrackingBlob extends Blob {
  constructor(parts, options) { super(parts, options); batches++ }
}
const context = {
  exports, Blob: TrackingBlob,
  URL: { createObjectURL: (blob) => { downloaded = blob; return "blob:teste" }, revokeObjectURL: () => {} },
  document: { body: { appendChild: () => {} }, createElement: () => ({ click: () => {}, remove: () => {} }) },
  window: { setTimeout: () => 0 },
}
vm.runInNewContext(outputText, context)

const frames = Array.from({ length: 600 }, (_, i) => Buffer.from([i % 256, 1, 2, 3]))
const file = new File(frames, "original.pcap")
const nativeSlice = file.slice.bind(file)
let slices = 0
file.slice = (...args) => {
  slices++
  const slice = nativeSlice(...args)
  slice.arrayBuffer = () => { throw new Error("exportação não deve materializar os quadros na memória") }
  return slice
}
const packets = frames.map((_, i) => ({ no: i + 1, captureOffset: i * 4, capturedLength: 4, linkType: 1, length: 4, epoch: 1_700_000_000 + i }))
assert.equal(await exports.exportPacketsAsPcap(file, packets), 600)
assert.equal(slices, 600)
assert.equal(batches, 3, "600 registros devem gerar dois lotes e o Blob final")
const result = Buffer.from(await downloaded.arrayBuffer())
assert.equal(result.length, 24 + 600 * 20)
assert.equal(result.readUInt32LE(20), 1)
assert.equal(result.readUInt32LE(24 + 8), 4)
assert.deepEqual(result.subarray(24 + 16, 24 + 20), frames[0])
assert.deepEqual(result.subarray(result.length - 4), frames.at(-1))

await assert.rejects(exports.exportPacketsAsPcap(file, [{ ...packets[0], capturedLength: file.size + 1 }]), /excede o tamanho/)
await assert.rejects(exports.exportPacketsAsPcap(file, [{ ...packets[0], epoch: undefined }]), /sem timestamp/)
console.log("Exportação PCAP: lotes limitados, bytes preservados, offsets validados.")
