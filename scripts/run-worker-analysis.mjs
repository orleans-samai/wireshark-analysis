import { File } from "node:buffer"
import { readFile } from "node:fs/promises"
import { basename } from "node:path"
import vm from "node:vm"

const workerCode = await readFile(new URL("../public/pcap-worker.js", import.meta.url), "utf8")
const codecsCode = await readFile(new URL("../public/pcap-codecs.js", import.meta.url), "utf8")

export async function runWorkerAnalysis(path, options = { analysisMode: "deep" }) {
  const bytes = await readFile(path)
  const messages = []
  const context = {
    self: {}, postMessage: (message) => messages.push(message), console,
    DataView, Uint8Array, ArrayBuffer, Date, Map, Set, Math, Intl, Number, String, Error, RegExp, TextDecoder,
  }
  vm.createContext(context)
  vm.runInContext(codecsCode, context)
  vm.runInContext(workerCode, context)
  await context.self.onmessage({ data: { type: "analyze", file: new File([bytes], basename(path)), options } })
  const error = messages.find((message) => message.type === "error")
  if (error) throw new Error(error.message)
  const done = messages.find((message) => message.type === "done")
  if (!done) throw new Error("O worker não produziu um resultado terminal.")
  return done.result
}
