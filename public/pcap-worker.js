/* PacketLens local capture worker — parses common Ethernet PCAP/PCAPNG records. */
const COLORS = { TCP: "#42d3ff", UDP: "#8b7cff", DNS: "#f5b849", TLS: "#4ade80", HTTP: "#fb7185", ICMP: "#94a3b8", IPv4: "#64748b", IPv6: "#a78bfa", Other: "#475569" };
const SERVICES = { 20: "FTP data", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP", 5353: "mDNS" };

self.onmessage = async ({ data }) => {
  if (data.type !== "analyze") return;
  try {
    const file = data.file;
    postMessage({ type: "progress", percent: 3, processed: 0, stage: "Lendo captura" });
    const buffer = await file.arrayBuffer();
    const result = analyze(buffer, file.name, file.size);
    postMessage({ type: "done", result });
  } catch (error) {
    postMessage({ type: "error", message: error instanceof Error ? error.message : "Falha desconhecida ao analisar a captura." });
  }
};

function analyze(buffer, fileName, fileSize) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  if (buffer.byteLength < 24) throw new Error("O arquivo está vazio ou não possui um cabeçalho de captura válido.");

  const acc = createAccumulator(fileName, fileSize);
  const magic = [bytes[0], bytes[1], bytes[2], bytes[3]].map((n) => n.toString(16).padStart(2, "0")).join("");
  if (["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"].includes(magic)) {
    parsePcap(view, bytes, magic, acc);
  } else if (magic === "0a0d0d0a") {
    parsePcapNg(view, bytes, acc);
  } else {
    throw new Error("Formato não reconhecido. Selecione um arquivo PCAP ou PCAPNG válido.");
  }
  if (!acc.packetCount) throw new Error("A captura é válida, mas não contém pacotes analisáveis.");
  return finalize(acc);
}

function createAccumulator(fileName, fileSize) {
  return { fileName, fileSize, analyzedAt: new Date().toLocaleString("pt-BR"), packetCount: 0, totalBytes: 0, firstTime: Infinity, lastTime: 0, hosts: new Map(), conversations: new Map(), dns: new Map(), ports: new Map(), protocols: new Map(), timeline: new Map(), packets: [], packetLimit: 10000, alerts: [] };
}

function parsePcap(view, bytes, magic, acc) {
  const little = magic === "d4c3b2a1" || magic === "4d3cb2a1";
  const nano = magic === "4d3cb2a1" || magic === "a1b23c4d";
  const linkType = view.getUint32(20, little);
  let offset = 24;
  while (offset + 16 <= view.byteLength) {
    const sec = view.getUint32(offset, little);
    const fraction = view.getUint32(offset + 4, little);
    const captured = view.getUint32(offset + 8, little);
    const original = view.getUint32(offset + 12, little);
    if (captured > view.byteLength - offset - 16) throw new Error(`Pacote ${acc.packetCount + 1} está truncado ou corrompido.`);
    const timestamp = sec + fraction / (nano ? 1e9 : 1e6);
    consumePacket(bytes.subarray(offset + 16, offset + 16 + captured), original || captured, timestamp, linkType, acc);
    offset += 16 + captured;
    maybeProgress(offset, view.byteLength, acc.packetCount);
  }
}

function parsePcapNg(view, bytes, acc) {
  let offset = 0;
  let little = true;
  const interfaces = [];
  while (offset + 12 <= view.byteLength) {
    const rawType = view.getUint32(offset, true);
    if (rawType === 0x0a0d0d0a) {
      if (offset + 16 > view.byteLength) throw new Error("Cabeçalho PCAPNG incompleto.");
      const bomLittle = view.getUint32(offset + 8, true);
      little = bomLittle === 0x1a2b3c4d;
    }
    const blockType = view.getUint32(offset, little);
    const blockLength = view.getUint32(offset + 4, little);
    if (blockLength < 12 || offset + blockLength > view.byteLength) throw new Error("A captura PCAPNG possui um bloco inválido ou corrompido.");
    if (blockType === 1 && blockLength >= 20) {
      interfaces.push({ linkType: view.getUint16(offset + 8, little), resolution: 1e6 });
    } else if (blockType === 6 && blockLength >= 32) {
      const interfaceId = view.getUint32(offset + 8, little);
      const high = view.getUint32(offset + 12, little);
      const low = view.getUint32(offset + 16, little);
      const captured = view.getUint32(offset + 20, little);
      const original = view.getUint32(offset + 24, little);
      const iface = interfaces[interfaceId] || { linkType: 1, resolution: 1e6 };
      const timestamp = (high * 4294967296 + low) / iface.resolution;
      if (offset + 28 + captured <= view.byteLength) consumePacket(bytes.subarray(offset + 28, offset + 28 + captured), original || captured, timestamp, iface.linkType, acc);
    } else if (blockType === 3 && blockLength >= 16) {
      const original = view.getUint32(offset + 8, little);
      const captured = Math.min(original, blockLength - 16);
      consumePacket(bytes.subarray(offset + 12, offset + 12 + captured), original, acc.lastTime || Date.now() / 1000, interfaces[0]?.linkType || 1, acc);
    }
    offset += blockLength;
    maybeProgress(offset, view.byteLength, acc.packetCount);
  }
}

function maybeProgress(offset, total, processed) {
  if (processed % 2000 !== 0) return;
  const ratio = offset / total;
  const stages = ["Lendo captura", "Identificando protocolos", "Construindo conversações", "Analisando DNS", "Calculando estatísticas", "Procurando comportamentos incomuns", "Preparando dashboard"];
  postMessage({ type: "progress", percent: Math.min(96, Math.max(5, Math.round(ratio * 94))), processed, stage: stages[Math.min(stages.length - 1, Math.floor(ratio * stages.length))] });
}

function consumePacket(packet, originalLength, timestamp, linkType, acc) {
  const parsed = decodePacket(packet, linkType);
  acc.packetCount++;
  acc.totalBytes += originalLength;
  acc.firstTime = Math.min(acc.firstTime, timestamp);
  acc.lastTime = Math.max(acc.lastTime, timestamp);
  if (!parsed) return;
  const { source, destination, sourcePort = 0, destinationPort = 0, transport, protocol, info, layers } = parsed;
  addProtocol(acc, protocol, originalLength);
  addHost(acc, source, true, originalLength);
  addHost(acc, destination, false, originalLength);
  addConversation(acc, source, destination, sourcePort, destinationPort, transport, originalLength, timestamp);
  if (destinationPort) addPort(acc, destinationPort, transport, destination, originalLength);
  const second = Math.floor(timestamp);
  const bin = acc.timeline.get(second) || { time: new Date(second * 1000).toLocaleTimeString("pt-BR", { hour12: false }), packets: 0, bytes: 0, connections: 0 };
  bin.packets++; bin.bytes += originalLength; bin.connections += transport === "TCP" ? 1 : 0; acc.timeline.set(second, bin);
  if (parsed.dns) addDns(acc, parsed.dns, source);
  if (acc.packets.length < acc.packetLimit) {
    acc.packets.push({ no: acc.packetCount, timestamp: formatTimestamp(timestamp), source, destination, sourcePort, destinationPort, protocol, length: originalLength, info, layers });
  }
}

function decodePacket(packet, linkType) {
  const v = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  let offset = 0;
  let etherType;
  const layers = [];
  if (linkType === 1) {
    if (packet.length < 14) return null;
    const dstMac = mac(packet, 0), srcMac = mac(packet, 6);
    etherType = v.getUint16(12, false); offset = 14;
    if (etherType === 0x8100 && packet.length >= 18) { etherType = v.getUint16(16, false); offset = 18; }
    layers.push({ name: "Ethernet II", fields: [["Origem", srcMac], ["Destino", dstMac], ["Tipo", `0x${etherType.toString(16).padStart(4, "0")}`]] });
  } else if (linkType === 101) {
    etherType = (packet[0] >> 4) === 6 ? 0x86dd : 0x0800;
  } else return null;

  let source, destination, ipProtocol, transportOffset;
  if (etherType === 0x0800) {
    if (packet.length < offset + 20) return null;
    const headerLength = (packet[offset] & 15) * 4;
    ipProtocol = packet[offset + 9];
    source = ipv4(packet, offset + 12); destination = ipv4(packet, offset + 16); transportOffset = offset + headerLength;
    layers.push({ name: "Internet Protocol Version 4", fields: [["Source", source], ["Destination", destination], ["TTL", String(packet[offset + 8])], ["Header length", `${headerLength} bytes`]] });
  } else if (etherType === 0x86dd) {
    if (packet.length < offset + 40) return null;
    ipProtocol = packet[offset + 6];
    source = ipv6(packet, offset + 8); destination = ipv6(packet, offset + 24); transportOffset = offset + 40;
    layers.push({ name: "Internet Protocol Version 6", fields: [["Source", source], ["Destination", destination], ["Hop limit", String(packet[offset + 7])]] });
  } else return null;

  let sourcePort = 0, destinationPort = 0, transport = "IP", protocol = ipProtocol === 1 || ipProtocol === 58 ? "ICMP" : etherType === 0x86dd ? "IPv6" : "IPv4", info = protocol, payloadOffset = transportOffset;
  if ((ipProtocol === 6 || ipProtocol === 17) && packet.length >= transportOffset + 8) {
    transport = ipProtocol === 6 ? "TCP" : "UDP";
    sourcePort = v.getUint16(transportOffset, false); destinationPort = v.getUint16(transportOffset + 2, false);
    if (ipProtocol === 6) {
      const headerLength = ((packet[transportOffset + 12] >> 4) & 15) * 4;
      payloadOffset = transportOffset + headerLength;
      const flags = packet[transportOffset + 13];
      const flagText = [[2, "SYN"], [16, "ACK"], [1, "FIN"], [4, "RST"], [8, "PSH"]].filter(([bit]) => flags & bit).map(([, name]) => name).join(", ");
      info = `${sourcePort} → ${destinationPort}${flagText ? ` [${flagText}]` : ""}`;
    } else { payloadOffset = transportOffset + 8; info = `${sourcePort} → ${destinationPort} Len=${Math.max(0, packet.length - payloadOffset)}`; }
    layers.push({ name: transport === "TCP" ? "Transmission Control Protocol" : "User Datagram Protocol", fields: [["Source port", String(sourcePort)], ["Destination port", String(destinationPort)], ["Payload", `${Math.max(0, packet.length - payloadOffset)} bytes`]] });
    if (sourcePort === 53 || destinationPort === 53) {
      protocol = "DNS";
      const dns = parseDns(packet, payloadOffset, source, destination);
      if (dns?.domain) info = `${dns.response ? "Resposta" : "Consulta"} ${dns.domain}`;
      layers.push({ name: "Domain Name System", fields: [["Tipo", dns?.response ? "Resposta" : "Consulta"], ["Domínio", dns?.domain || "Não decodificado"], ["Status", dns?.status || "—"]] });
      return { source, destination, sourcePort, destinationPort, transport, protocol, info, layers, dns };
    }
    if (sourcePort === 80 || destinationPort === 80 || sourcePort === 8080 || destinationPort === 8080) {
      protocol = "HTTP"; const firstLine = ascii(packet, payloadOffset, Math.min(packet.length, payloadOffset + 120)).split("\r\n")[0]; if (firstLine) info = firstLine;
    } else if (sourcePort === 443 || destinationPort === 443) { protocol = "TLS"; info = `${info} · conteúdo criptografado`; }
    else protocol = transport;
  }
  layers.push({ name: protocol, fields: [["Resumo", info], ["Tamanho", `${packet.length} bytes`]] });
  return { source, destination, sourcePort, destinationPort, transport, protocol, info, layers };
}

function parseDns(packet, offset) {
  if (offset + 12 > packet.length) return null;
  const v = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const flags = v.getUint16(offset + 2, false), response = !!(flags & 0x8000), rcode = flags & 15;
  let cursor = offset + 12, domain = "", guard = 0;
  while (cursor < packet.length && packet[cursor] && guard++ < 64) {
    const len = packet[cursor++];
    if ((len & 0xc0) === 0xc0 || cursor + len > packet.length) break;
    domain += (domain ? "." : "") + ascii(packet, cursor, cursor + len); cursor += len;
  }
  return { domain, response, status: rcode === 0 ? "NOERROR" : rcode === 3 ? "NXDOMAIN" : `RCODE ${rcode}`, answer: "—" };
}

function addProtocol(acc, name, bytes) { const p = acc.protocols.get(name) || { name, packets: 0, bytes: 0, color: COLORS[name] || COLORS.Other }; p.packets++; p.bytes += bytes; acc.protocols.set(name, p); }
function addHost(acc, ip, sent, bytes) { const h = acc.hosts.get(ip) || { ip, sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, connections: new Set() }; if (sent) { h.sentPackets++; h.sentBytes += bytes; } else { h.receivedPackets++; h.receivedBytes += bytes; } acc.hosts.set(ip, h); }
function addConversation(acc, source, destination, sourcePort, destinationPort, protocol, bytes, time) {
  const left = `${source}:${sourcePort}`, right = `${destination}:${destinationPort}`, key = left < right ? `${left}|${right}|${protocol}` : `${right}|${left}|${protocol}`;
  const c = acc.conversations.get(key) || { id: `conv-${acc.conversations.size + 1}`, source, destination, sourcePort, destinationPort, protocol, packets: 0, bytes: 0, first: time, last: time };
  c.packets++; c.bytes += bytes; c.first = Math.min(c.first, time); c.last = Math.max(c.last, time); acc.conversations.set(key, c);
  acc.hosts.get(source)?.connections.add(key); acc.hosts.get(destination)?.connections.add(key);
}
function addPort(acc, port, protocol, host, bytes) { const key = `${port}/${protocol}`; const p = acc.ports.get(key) || { port, protocol, service: SERVICES[port] || "Desconhecido", connections: 0, hosts: new Set(), bytes: 0 }; p.connections++; p.hosts.add(host); p.bytes += bytes; acc.ports.set(key, p); }
function addDns(acc, dns, source) { if (!dns.domain) return; const key = `${dns.domain}|${source}`; const d = acc.dns.get(key) || { domain: dns.domain, source, answer: dns.answer || "—", queries: 0, status: dns.status || "—", responseTime: 0 }; if (!dns.response) d.queries++; acc.dns.set(key, d); }

function finalize(acc) {
  postMessage({ type: "progress", percent: 98, processed: acc.packetCount, stage: "Preparando dashboard" });
  const conversations = [...acc.conversations.values()].map((c) => ({ ...c, start: formatTimestamp(c.first).slice(0, 8), duration: Math.max(0, c.last - c.first) })).sort((a, b) => b.bytes - a.bytes);
  const hosts = [...acc.hosts.values()].map((h) => ({ ...h, connections: h.connections.size })).sort((a, b) => (b.sentBytes + b.receivedBytes) - (a.sentBytes + a.receivedBytes));
  const dns = [...acc.dns.values()].sort((a, b) => b.queries - a.queries);
  const ports = [...acc.ports.values()].map((p) => ({ ...p, hosts: p.hosts.size })).sort((a, b) => b.connections - a.connections);
  const protocols = [...acc.protocols.values()].sort((a, b) => b.packets - a.packets);
  const timeline = [...acc.timeline.values()].sort((a, b) => a.time.localeCompare(b.time));
  const alerts = buildAlerts(hosts, dns, ports, conversations);
  return { fileName: acc.fileName, fileSize: acc.fileSize, analyzedAt: acc.analyzedAt, packetCount: acc.packetCount, totalBytes: acc.totalBytes, duration: Math.max(0, acc.lastTime - acc.firstTime), hosts, conversations, dns, ports, protocols, timeline: compressTimeline(timeline, 120), packets: acc.packets, alerts, truncatedPackets: acc.packetCount > acc.packetLimit };
}

function buildAlerts(hosts, dns, ports, conversations) {
  const alerts = [];
  const scanGroups = new Map();
  for (const item of conversations) {
    const key = `${item.source}|${item.destination}`;
    const group = scanGroups.get(key) || { source: item.source, destination: item.destination, ports: new Set(), packets: 0 };
    if (item.destinationPort) group.ports.add(item.destinationPort); group.packets += item.packets; scanGroups.set(key, group);
  }
  const scan = [...scanGroups.values()].find((item) => item.ports.size >= 20);
  if (scan) alerts.push({ id: "port-scan", severity: scan.ports.size > 80 ? "Alta" : "Média", title: "Muitas portas em pouco tempo", description: `${scan.source} acessou ${scan.ports.size} portas distintas de ${scan.destination}.`, source: scan.source, destination: scan.destination, time: "Durante a captura", evidence: `${scan.packets} pacotes · ${scan.ports.size} portas`, reason: "Possível atividade de varredura de portas. O padrão merece investigação e não confirma um ataque." });
  const noisyDns = dns.find((d) => d.queries >= 100);
  if (noisyDns) alerts.push({ id: "dns-volume", severity: noisyDns.queries > 500 ? "Média" : "Baixa", title: "Frequência DNS elevada", description: `${noisyDns.queries.toLocaleString("pt-BR")} consultas para ${noisyDns.domain}.`, source: noisyDns.source, destination: "Servidor DNS", time: "Durante a captura", evidence: `${noisyDns.queries} consultas`, reason: "O volume merece comparação com o comportamento habitual. Não confirma atividade maliciosa." });
  const busy = hosts.find((h) => h.connections > 250);
  if (busy) alerts.push({ id: "many-connections", severity: "Média", title: "Grande quantidade de conexões", description: `${busy.ip} participou de ${busy.connections} conversações.`, source: busy.ip, time: "Durante a captura", evidence: `${busy.connections} conversações`, reason: "Pode ser causado por navegação, automação, atualização ou um padrão que merece investigação." });
  const unknown = ports.find((p) => p.service === "Desconhecido" && p.connections > 40);
  if (unknown) alerts.push({ id: "unusual-port", severity: "Baixa", title: "Uso recorrente de porta não classificada", description: `A porta ${unknown.port}/${unknown.protocol} apareceu em ${unknown.connections} conexões.`, source: "Múltiplos hosts", time: "Durante a captura", evidence: `${unknown.connections} conexões`, reason: "A classificação por porta é apenas indicativa. Verifique os endpoints e os pacotes relacionados." });
  if (!alerts.length) alerts.push({ id: "baseline", severity: "Informativo", title: "Nenhuma regra prioritária acionada", description: "Os indicadores básicos não encontraram um padrão de alta prioridade nesta captura.", source: "Captura", time: "Análise concluída", evidence: `${conversations.length} conversações`, reason: "A ausência de alerta não substitui a revisão contextual dos dados." });
  return alerts;
}

function compressTimeline(points, limit) { if (points.length <= limit) return points; const size = Math.ceil(points.length / limit), out = []; for (let i = 0; i < points.length; i += size) { const slice = points.slice(i, i + size); out.push({ time: slice[0].time, packets: slice.reduce((s, p) => s + p.packets, 0), bytes: slice.reduce((s, p) => s + p.bytes, 0), connections: slice.reduce((s, p) => s + p.connections, 0) }); } return out; }
function ascii(bytes, start, end) { let out = ""; for (let i = start; i < end && i < bytes.length; i++) out += bytes[i] >= 32 && bytes[i] < 127 ? String.fromCharCode(bytes[i]) : "."; return out; }
function mac(bytes, start) { return [...bytes.subarray(start, start + 6)].map((n) => n.toString(16).padStart(2, "0")).join(":"); }
function ipv4(bytes, start) { return `${bytes[start]}.${bytes[start + 1]}.${bytes[start + 2]}.${bytes[start + 3]}`; }
function ipv6(bytes, start) { const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), parts = []; for (let i = 0; i < 16; i += 2) parts.push(v.getUint16(start + i, false).toString(16)); return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::"); }
function formatTimestamp(value) { if (!Number.isFinite(value)) return "—"; const date = new Date(value * 1000); return `${date.toLocaleTimeString("pt-BR", { hour12: false })}.${String(date.getMilliseconds()).padStart(3, "0")}`; }
