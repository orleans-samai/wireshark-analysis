import type { PacketRecord } from "./capture-types"

const RECORDS_PER_BATCH = 512

export async function exportPacketsAsPcap(source: File, packets: PacketRecord[], fileName = "packetlens-filtered.pcap") {
  const exportable = packets.filter((packet) => packet.captureOffset !== undefined && packet.capturedLength !== undefined && packet.capturedLength > 0 && packet.linkType !== undefined)
  if (!exportable.length) throw new Error("Os pacotes selecionados não possuem offsets de captura para exportação.")
  if (exportable.some((packet) => packet.epoch === undefined)) throw new Error("A seleção contém pacotes sem timestamp. O formato PCAP exige um horário para cada pacote; use CSV/JSON ou filtre pacotes com horário conhecido.")
  const linkType = exportable[0].linkType || 1
  if (exportable.some((packet) => packet.linkType !== linkType)) {
    throw new Error("A seleção contém interfaces com tipos de enlace diferentes. Exporte uma interface por vez.")
  }

  const header = new ArrayBuffer(24)
  const global = new DataView(header)
  global.setUint32(0, 0xa1b2c3d4, true)
  global.setUint16(4, 2, true)
  global.setUint16(6, 4, true)
  global.setUint32(16, 65_535, true)
  global.setUint32(20, linkType, true)

  const parts: BlobPart[] = [header]
  let batch: BlobPart[] = []
  for (const packet of exportable) {
    const offset = packet.captureOffset!
    const captured = packet.capturedLength!
    if (offset < 0 || offset + captured > source.size) throw new Error(`O pacote ${packet.no} excede o tamanho da captura original.`)
    // File.slice retorna um Blob sem ler seus bytes. Mesmo para uma seleção
    // grande, somente os cabeçalhos e as referências aos quadros são retidos.
    const frame = source.slice(offset, offset + captured)
    const record = new ArrayBuffer(16)
    const view = new DataView(record)
    const epoch = packet.epoch ?? 0
    let seconds = Math.floor(epoch)
    let micros = Math.round((epoch - seconds) * 1_000_000)
    if (micros === 1_000_000) { seconds++; micros = 0 }
    view.setUint32(0, seconds, true)
    view.setUint32(4, micros, true)
    view.setUint32(8, captured, true)
    view.setUint32(12, packet.length || captured, true)
    batch.push(record, frame)
    if (batch.length === RECORDS_PER_BATCH * 2) {
      parts.push(new Blob(batch))
      batch = []
    }
  }
  if (batch.length) parts.push(new Blob(batch))

  downloadBlob(new Blob(parts, { type: "application/vnd.tcpdump.pcap" }), fileName)
  return exportable.length
}

export function downloadSourceCapture(source: File) {
  downloadBlob(source, source.name)
}

export function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = fileName
  // O Firefox exige o link no DOM para disparar o download.
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
}
