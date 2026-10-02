import { readdir } from "node:fs/promises"
import { resolve } from "node:path"
import { verifyCapture } from "./verify-capture.mjs"

async function captures(directory) {
  const found = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name)
    if (entry.isDirectory()) found.push(...await captures(path))
    else if (/\.pcap(?:ng)?$/i.test(entry.name)) found.push(path)
  }
  return found
}

const directory = resolve(process.argv[2] || "tests/fixtures/captures")
let files
try { files = await captures(directory) } catch { files = [] }
if (!files.length) {
  console.error(`Nenhuma captura encontrada em ${directory}. Consulte tests/fixtures/README.md.`)
  process.exit(1)
}

const failures = []
for (const file of files) {
  try {
    const { valid, report } = await verifyCapture(file, { strict: true })
    console.log(`${valid ? "OK" : "REVISAR"} · ${file} · ${report.packetCount.packetlens} pacotes`)
  } catch (error) {
    failures.push(`${file}: ${error instanceof Error ? error.message : String(error)}`)
  }
}
if (failures.length) {
  console.error(failures.join("\n"))
  process.exit(1)
}
