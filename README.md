<div align="center">

# 🔬 PacketLens

**Analisador de capturas de rede (`.pcap` / `.pcapng`) que roda 100% no navegador.**

Nenhum pacote sai da sua máquina: o arquivo é lido em blocos dentro de um Web Worker e toda a análise acontece no cliente.

<br />

[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Playwright](https://img.shields.io/badge/Testes-Playwright-2EAD33?style=for-the-badge&logo=playwright&logoColor=white)](https://playwright.dev/)
[![Licença MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-yellow?style=for-the-badge)](LICENSE)

[Sobre](#-sobre) •
[Funcionalidades](#-funcionalidades) •
[Tecnologias](#-tecnologias) •
[Como executar](#-como-executar) •
[Scripts](#-scripts-disponíveis) •
[Estrutura](#-estrutura-do-projeto) •
[Licença](#-licença)

</div>

---

## 📌 Sobre

O **PacketLens** é uma ferramenta de análise e investigação de tráfego de rede no estilo Wireshark, feita para a web. Você arrasta uma captura `.pcap` ou `.pcapng` e recebe painéis de hosts, conversações, DNS, portas, protocolos, sinais de segurança e uma linha do tempo do tráfego, tudo sem enviar dados a nenhum servidor.

Ele também funciona como uma bancada de investigação: dá para abrir **casos**, anexar pacotes e sinais como evidência, comparar duas capturas e exportar relatórios.

> 💡 Sem uma captura à mão? Na tela inicial, clique em **"Abrir uma análise de exemplo"**.

---

## ✨ Funcionalidades

| | Recurso | Detalhes |
|---|---|---|
| 📥 | **Leitura streaming** | PCAP e PCAPNG lidos em blocos dentro de um Web Worker, com barra de progresso |
| 🌐 | **Visões de análise** | Hosts, conversações, DNS, portas, protocolos e explorador de pacotes |
| 🧬 | **Decodificação** | HTTP, HTTP/2, metadados QUIC, ClientHello TLS (SNI) e cálculo de **JA3** local |
| 🧵 | **Modo profundo** | Reagrupamento TCP limitado (64 KB por direção) para reconhecer protocolos divididos entre segmentos |
| 🚨 | **Sinais de segurança** | Risco de 0 a 100, linha de base da própria captura, histórico por ativo e mapeamento **MITRE ATT&CK** |
| 🕒 | **Linha do tempo** | Clique em um ponto do gráfico de tráfego para abrir aquele intervalo no explorador |
| 🗂️ | **Casos de investigação** | Responsável, estado, tags e evidências, com importação e exportação do caderno em JSON |
| ⚖️ | **Comparação** | Diferenças entre duas capturas lado a lado |
| 📤 | **Exportação** | Recorte de pacotes em PCAP e relatórios da análise |
| 🔒 | **Privacidade** | Content Security Policy restritiva, sem serviços externos e sem armazenar o conteúdo bruto da captura |

### ⌨️ Atalhos

| Tecla | Ação |
|---|---|
| `/` | Foca a busca |
| `Alt + 1` | Abre o painel |
| `Alt + 2` | Abre o explorador de pacotes |

---

## 🧰 Tecnologias

| Camada | Tecnologia |
|---|---|
| Interface | Next.js 16 (via Vinext/Vite), React 19, Tailwind CSS 4, componentes shadcn/Radix, Recharts |
| Motor de análise | Web Worker em JavaScript (`public/pcap-worker.js`) e decodificadores isolados (`public/pcap-codecs.js`) |
| Persistência local | IndexedDB, com migração e fallback para `localStorage` |
| Deploy | Cloudflare Workers via Wrangler |
| Qualidade | Testes com `node:vm` sobre o worker real, fuzzing do parser, Playwright (E2E), ESLint e `tsc` |
| CI | GitHub Actions: testes, checagem de tipos, lint, build e E2E a cada push |

---

## 🚀 Como executar

### Pré-requisitos

- Node.js **22.13.0** ou superior

### Instalação

```bash
git clone https://github.com/orleans-samai/wireshark-analysis.git
cd wireshark-analysis
npm run install:ci
npm run dev
```

Para os testes ponta a ponta, instale o Chromium do Playwright uma única vez:

```bash
npx playwright install chromium
```

---

## 📜 Scripts disponíveis

| Comando | O que faz |
|---|---|
| `npm run dev` | Servidor de desenvolvimento com HMR |
| `npm run build` | Gera o build para o Cloudflare Workers |
| `npm start` | Prévia local do Worker já construído |
| `npm test` | Parser PCAP/PCAPNG, robustez, fuzzing, paridade de opções, investigação e exportação |
| `npm run test:e2e` | Fluxo real no Chromium com Playwright |
| `npm run check` | `tsc --noEmit` + `eslint .` |
| `npm run verify:capture -- arquivo.pcap --strict` | Compara contagem, hosts, DNS, SNI e protocolos com o TShark local |
| `npm run verify:corpus -- pasta` | Valida em lote um corpus de capturas autorizado e anonimizado |
| `npm run bench:capture -- arquivo.pcap 3 --min-mbps 100 --max-memory-mb 256` | Mede desempenho e pode bloquear regressões |
---

## 🔧 Opções do analisador

| Opção | Faixa | Padrão | Função |
|---|---|---|---|
| `packetLimit` | 1.000 a 100.000 | 20.000 | Tamanho da **amostra distribuída** de pacotes retidos para o explorador e a exportação |
| `memoryBudgetMb` | 64 a 2.048 MB | 256 MB | Orçamento dividido entre detalhes, agregações, fluxos TCP e fragmentos IPv4 |

Quando alguma coleção precisa ser limitada, o resultado informa quais foram reduzidas. Limiares e preferências ficam em [`lib/analyzer-options.ts`](lib/analyzer-options.ts).

> ⚠️ Filtros e exportações de pacotes usam apenas a amostra retida, então a evidência de um alerta pode não estar entre os pacotes guardados. O serviço inferido pela porta aparece como *provável*, separado do protocolo efetivamente decodificado.

---

## 📁 Estrutura do projeto

```
wireshark-analysis/
├── app/                          # Shell Next (page.tsx renderiza o PacketLensApp)
├── components/
│   ├── packetlens-app.tsx        # Importação do arquivo, progresso, worker e tema
│   ├── workspace.tsx             # Navegação entre visões, filtros globais e casos
│   ├── analysis-views.tsx        # Tabelas: hosts, conversações, DNS, portas, pacotes
│   ├── investigation-views.tsx   # Segurança, timeline, mapa, relatórios e ajustes
│   └── compare-view.tsx          # Comparação entre duas capturas
├── lib/                          # Tipos, filtros, casos, opções, exportações e formatação
├── public/
│   ├── pcap-worker.js            # Leitura streaming, agregações, reagrupamento e heurísticas
│   └── pcap-codecs.js            # Decodificadores de HTTP, HTTP/2 e QUIC
├── scripts/                      # Verificação com TShark, benchmark e utilitários de build
├── tests/                        # Testes do worker, fuzzing e E2E (Playwright)
└── .github/workflows/ci.yml      # Pipeline de qualidade
```

---

## 🔒 Privacidade

Todo o processamento é local. Casos, referências de evidência, triagens e resumos históricos por ativo ficam no IndexedDB do navegador; o conteúdo bruto da captura **nunca** é armazenado. A aplicação envia uma Content Security Policy restritiva e não carrega serviços externos.

---

## 📄 Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).

---

## 👤 Autor

**Orleans Samai**

[![GitHub](https://img.shields.io/badge/GitHub-orleans--samai-181717?style=flat-square&logo=github)](https://github.com/orleans-samai)

<div align="center">

<sub>Feito com 💙 por Orleans Samai</sub>

</div>
