/** Identificadores das visões do Workspace.
 *
 *  O código usa estes ids em inglês; os rótulos em pt-BR exibidos no
 *  cabeçalho ficam em `viewCopy` (workspace.tsx). Centralizar o union aqui
 *  evita typos silenciosos entre navegação, busca e renderização.
 */
export type ViewId =
  | "Dashboard"
  | "Traffic"
  | "Hosts"
  | "Conversations"
  | "Network Flows"
  | "Protocols"
  | "DNS"
  | "HTTP"
  | "TLS"
  | "Ports"
  | "Packet Explorer"
  | "Network Map"
  | "Security Insights"
  | "Timeline"
  | "Compare"
  | "Reports"
  | "Settings"
