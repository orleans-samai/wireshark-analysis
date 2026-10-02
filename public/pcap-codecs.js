/* Decodificadores de aplicação sem estado usados pelo Web Worker. */
(() => {
  function parseHttp2(packet, offset) {
    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if (offset + preface.length > packet.length) return null
    for (let index = 0; index < preface.length; index++) if (packet[offset + index] !== preface.charCodeAt(index)) return null
    return { kind: "request", method: "PRI", path: "*", version: "HTTP/2" }
  }

  function parseQuic(packet, offset) {
    if (offset >= packet.length || (packet[offset] & 0x40) === 0) return null
    const first = packet[offset]
    const longHeader = Boolean(first & 0x80)
    const packetNumberLength = (first & 3) + 1
    if (!longHeader) return { version: "1-RTT", longHeader: false, packetType: "1-RTT", packetNumberLength }
    if (offset + 7 > packet.length) return null
    const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
    const versionNumber = view.getUint32(offset + 1, false)
    let cursor = offset + 5
    const dcidLength = packet[cursor++]
    if (dcidLength > 20 || cursor + dcidLength + 1 > packet.length) return null
    const destinationConnectionId = toHex(packet, cursor, cursor + dcidLength)
    cursor += dcidLength
    const scidLength = packet[cursor++]
    if (scidLength > 20 || cursor + scidLength > packet.length) return null
    const sourceConnectionId = toHex(packet, cursor, cursor + scidLength)
    const type = (first >> 4) & 3
    const packetType = versionNumber === 0 ? "Version negotiation" : ["Initial", "0-RTT", "Handshake", "Retry"][type]
    const knownVersion = versionNumber === 1 ? "QUIC v1" : versionNumber === 0x6b3343cf ? "QUIC v2" : null
    return {
      version: versionNumber === 0 ? "Negociação" : knownVersion || `0x${versionNumber.toString(16).padStart(8, "0")}`,
      versionNumber,
      longHeader,
      packetType,
      packetNumberLength,
      destinationConnectionId,
      sourceConnectionId,
    }
  }

  function parseHttp(packet, offset, maxBytes = 8192) {
    if (offset >= packet.length) return null
    const limit = Math.min(packet.length, offset + maxBytes)
    let raw = ""
    for (let index = offset; index < limit; index++) raw += String.fromCharCode(packet[index])
    const headerEnd = raw.indexOf("\r\n\r\n")
    if (headerEnd < 0 && raw.indexOf("\n\n") < 0) return null
    const lines = raw.split(/\r?\n/)
    const first = lines[0]
    const request = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+(HTTP\/\d\.\d)$/i.exec(first)
    const response = /^(HTTP\/\d\.\d)\s+(\d{3})\b/.exec(first)
    if (!request && !response) return null
    const headers = {}
    for (const line of lines.slice(1)) {
      const colon = line.indexOf(":")
      if (colon > 0) headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim()
    }
    if (request) return { kind: "request", method: request[1].toUpperCase(), path: request[2], version: request[3], host: headers.host, userAgent: headers["user-agent"], contentType: headers["content-type"] }
    return { kind: "response", version: response[1], status: Number(response[2]), contentType: headers["content-type"] }
  }

  function toHex(bytes, start, end) {
    return [...bytes.subarray(start, end)].map((value) => value.toString(16).padStart(2, "0")).join("")
  }

  self.PacketLensCodecs = Object.freeze({ parseHttp2, parseQuic, parseHttp })
})()
