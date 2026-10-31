# PacketLens

Analisador local de capturas de rede (`.pcap` / `.pcapng`) no navegador. Nenhum pacote é enviado a servidores: o arquivo é lido em blocos dentro de um Web Worker (`public/pcap-worker.js`) e a análise acontece 100% no cliente.

## Requisitos

- Node.js `>=22.13.0`
- Dependências instaladas (`npm run install:ci`)

## Uso

- `npm run dev` — servidor de desenvolvimento (Vinext/Vite, HMR)
- `npm run build` — build do artefato Sites
- `npm start` — prévia local do Worker construído
- `npm test` — parser PCAP/PCAPNG, bateria de robustez e paridade das opções do analisador
- `npm run test:e2e` — fluxo real no Chromium (execute `npx playwright install chromium` uma vez se o navegador não estiver instalado)
- `npm run verify:capture -- arquivo.pcap --strict` — compara contagem, hosts, DNS, SNI e protocolos com o TShark local
- `npm run verify:corpus -- pasta` — valida em lote um corpus autorizado e anonimizado
- `npm run bench:capture -- arquivo.pcap 3 --min-mbps 100 --max-memory-mb 256` — mede desempenho e pode bloquear regressões
- `npm run check` — `tsc --noEmit` + `eslint .`

Sem uma captura à mão, abra **"Abrir uma análise de exemplo"** na tela inicial.

## Estrutura

- `app/` — shell Next (`page.tsx` renderiza `PacketLensApp`)
- `components/packetlens-app.tsx` — importação do arquivo, progresso, worker, tema
- `components/workspace.tsx` — navegação por `ViewId`, filtros globais e casos de investigação
- `components/analysis-views.tsx` — tabelas por visão (hosts, conversações, DNS, portas, pacotes)
- `components/investigation-views.tsx` — segurança, timeline, mapa, relatórios, ajustes
- `components/compare-view.tsx` — comparação entre duas capturas
- `lib/` — tipos (`capture-types.ts`), filtros e casos (`investigation.ts`, `casebook.ts`), opções (`analyzer-options.ts`), exportações (`pcap-export.ts`, `report.ts`), formatação (`format.ts`)
- `public/pcap-worker.js` — leitura streaming PCAP/PCAPNG, agregações, reagrupamento e heurísticas
- `public/pcap-codecs.js` — decodificadores isolados de HTTP, HTTP/2 e QUIC
- `tests/` — harness `node:vm` que executa o worker real

## Opções do analisador

`packetLimit` (1.000–100.000, padrão 20.000) limita a **amostra distribuída** de pacotes retidos para o explorador/exportação. O pacote mais recente é preservado; filtros e exportações dos pacotes usam apenas a amostra, podendo faltar a evidência de um alerta. O orçamento `memoryBudgetMb` (64–2.048 MB, padrão 256 MB) é dividido entre detalhes, agregações, fluxos TCP e fragmentos IPv4. Quando uma cardinalidade precisa ser limitada, o resultado informa quais coleções foram reduzidas.

Em **Configurações**, o modo profundo mantém um reagrupamento TCP limitado a 64 KB por direção, com quantidade de fluxos limitada pelo orçamento de memória. Isso permite reconhecer HTTP, o preâmbulo HTTP/2 e ClientHello TLS divididos entre segmentos. O parser também identifica metadados QUIC e calcula JA3 localmente. O modo padrão prioriza velocidade e examina somente cada segmento.

Os sinais exibem risco de 0 a 100, linha de base calculada na própria captura, histórico local por ativo e mapeamento MITRE ATT&CK quando aplicável. Regras podem ser silenciadas para a próxima análise; limiares e preferências ficam em `lib/analyzer-options.ts`.

## Fluxo de investigação

- Clique em um ponto do gráfico de tráfego para abrir aquele intervalo no explorador.
- Use `/` para focar a busca, `Alt+1` para o painel e `Alt+2` para o explorador.
- Crie um caso em **Casos**, defina responsável, estado e tags e anexe pacotes ou sinais como evidência.
- Exporte ou importe o caderno em JSON para continuar a análise localmente.

Blocos PCAPNG sem timestamp permanecem sem horário; eles não entram nas métricas temporais e não podem ser exportados como PCAP. O serviço inferido por porta é mostrado como *provável*, distinto do protocolo efetivamente decodificado.

## Privacidade

Todo o processamento é local. Casos, referências de evidência, triagens e resumos históricos por ativo são persistidos em IndexedDB, com migração e fallback para `localStorage`; o conteúdo bruto da captura nunca é armazenado. A aplicação envia uma Content Security Policy restritiva e não carrega serviços externos.

## Deploy (Sites/Cloudflare)

Segue o ciclo de vida do starter Vinext: `npm run build` gera `dist/server/wrangler.json`; `npm start` serve localmente via Wrangler. D1/R2 em `.openai/hosting.json` são opcionais e não são usados pelo PacketLens hoje.
