import assert from "node:assert/strict"
import { File } from "node:buffer"
import { readFile } from "node:fs/promises"
import vm from "node:vm"

const workerCode = await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8")
const codecsCode = await readFile(new URL("../public/pcap-codecs.js", import.meta.url), "utf8")
const messages = []
const context = {
  self: {}, postMessage: (message) => messages.push(message), console,
  DataView, Uint8Array, ArrayBuffer, Date, Map, Set, Math, Intl, Number, String, Error, RegExp, TextDecoder,
}
vm.createContext(context)
vm.runInContext(codecsCode, context)
vm.runInContext(workerCode, context)

let state = 0x12345678
const randomByte = () => {
  state ^= state << 13
  state ^= state >>> 17
  state ^= state << 5
  return state & 255
}

for (let index = 0; index < 80; index++) {
  const length = 12 + (randomByte() % 244)
  const bytes = Buffer.alloc(length)
  for (let cursor = 0; cursor < length; cursor++) bytes[cursor] = randomByte()
  if (index % 3 === 0) Buffer.from("d4c3b2a1", "hex").copy(bytes, 0)
  if (index % 7 === 0) Buffer.from("0a0d0d0a", "hex").copy(bytes, 0)
  messages.length = 0
  let thrown = null
  try {
    await context.self.onmessage({ data: { type: "analyze", file: new File([bytes], `fuzz-${index}.pcap`) } })
  } catch (error) {
    thrown = error
  }
  assert.equal(thrown, null, `entrada fuzz ${index} escapou do tratamento do worker`)
  assert.ok(messages.some((message) => message.type === "done" || message.type === "error"), `entrada fuzz ${index} não produziu resultado terminal`)
}

console.log("Fuzz determinístico: 80 entradas malformadas tratadas sem exceção não capturada.")
