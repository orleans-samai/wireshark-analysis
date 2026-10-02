"use client"

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { AlertTriangle, FileUp, LockKeyhole, Moon, Sun, XCircle } from "lucide-react"
import { Brand } from "@/components/brand"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { demoAnalysis } from "@/lib/demo-data"
import { formatNumber } from "@/lib/format"
import type { AnalyzerOptions, CaptureAnalysis } from "@/lib/capture-types"
import { DEFAULT_ANALYZER_OPTIONS, loadAnalyzerOptions, normalizeAnalyzerOptions, saveAnalyzerOptions } from "@/lib/analyzer-options"
import { contextualizeAnalysis } from "@/lib/historical-baseline"

const Workspace = lazy(() => import("@/components/workspace").then((module) => ({ default: module.Workspace })))

const THEME_KEY = "packetlens:theme:v1"

function readStoredTheme() {
  if (typeof window === "undefined") return false
  try {
    const stored = window.localStorage.getItem(THEME_KEY)
    if (stored === "light" || stored === "dark") return stored === "light"
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ?? false
  } catch {
    return false
  }
}

export type AnalysisState = { percent: number; processed: number; stage: string; target: "primary" | "comparison" }

export function PacketLensApp() {
  const fileInput = useRef<HTMLInputElement>(null)
  const workerRef = useRef<Worker | null>(null)
  const analysisRunRef = useRef(0)
  const [analysis, setAnalysis] = useState<CaptureAnalysis | null>(null)
  const [sourceFile, setSourceFile] = useState<File | null>(null)
  const [comparison, setComparison] = useState<CaptureAnalysis | null>(null)
  const [comparisonFile, setComparisonFile] = useState<File | null>(null)
  const [progress, setProgress] = useState<AnalysisState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [light, setLight] = useState(false)
  const [themeReady, setThemeReady] = useState(false)
  const [options, setOptionsState] = useState<AnalyzerOptions>(DEFAULT_ANALYZER_OPTIONS)

  useEffect(() => {
    const timer = window.setTimeout(() => setOptionsState(loadAnalyzerOptions()), 0)
    return () => window.clearTimeout(timer)
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLight(readStoredTheme())
      setThemeReady(true)
    }, 0)
    return () => window.clearTimeout(timer)
  }, [])

  useEffect(() => {
    if (!themeReady) return
    document.documentElement.classList.toggle("dark", !light)
    document.documentElement.classList.toggle("light", light)
    try {
      window.localStorage.setItem(THEME_KEY, light ? "light" : "dark")
    } catch {
      // Storage indisponível: o tema segue valendo na sessão.
    }
  }, [light, themeReady])

  useEffect(() => {
    const swallow = (event: DragEvent) => event.preventDefault()
    window.addEventListener("dragover", swallow)
    window.addEventListener("drop", swallow)
    return () => {
      window.removeEventListener("dragover", swallow)
      window.removeEventListener("drop", swallow)
      workerRef.current?.terminate()
    }
  }, [])

  const updateOptions = useCallback((next: AnalyzerOptions) => {
    const normalized = normalizeAnalyzerOptions(next)
    setOptionsState(normalized)
    saveAnalyzerOptions(normalized)
  }, [])

  const analyzeFile = useCallback((file: File, target: "primary" | "comparison" = "primary") => {
    const runId = ++analysisRunRef.current
    setError(null)
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setError("Formato não suportado. Selecione um arquivo .pcap ou .pcapng.")
      return
    }
    workerRef.current?.terminate()
    setProgress({ percent: 2, processed: 0, stage: "Lendo captura", target })
    // Caminho relativo ao documento: respeita um eventual basePath e evita
    // depender da raiz do domínio (o app é página única, sem rotas aninhadas).
    const worker = new Worker(new URL("pcap-worker.js", window.location.href).toString())
    workerRef.current = worker
    worker.onmessage = ({ data }) => {
      if (data.type === "progress") setProgress({ ...data, target })
      if (data.type === "done") {
        worker.terminate()
        if (workerRef.current === worker) workerRef.current = null
        const finish = (result: CaptureAnalysis) => {
          if (analysisRunRef.current !== runId) return
          if (target === "primary") {
            setAnalysis(result)
            setSourceFile(file)
            setComparison(null)
            setComparisonFile(null)
          } else {
            setComparison(result)
            setComparisonFile(file)
          }
          setProgress(null)
        }
        void contextualizeAnalysis(data.result, target === "primary").then(finish).catch(() => finish(data.result))
      }
      if (data.type === "cancelled") {
        setProgress(null)
        worker.terminate()
        if (workerRef.current === worker) workerRef.current = null
      }
      if (data.type === "error") {
        setError(data.message)
        setProgress(null)
        worker.terminate()
        if (workerRef.current === worker) workerRef.current = null
      }
    }
    worker.onerror = () => {
      setError("Não foi possível iniciar o analisador local. Tente novamente.")
      setProgress(null)
      worker.terminate()
      if (workerRef.current === worker) workerRef.current = null
    }
    worker.postMessage({ type: "analyze", file, options })
  }, [options])

  const cancelAnalysis = useCallback(() => {
    const worker = workerRef.current
    if (!worker) return
    analysisRunRef.current++
    worker.postMessage({ type: "cancel" })
    window.setTimeout(() => {
      if (workerRef.current === worker) {
        worker.terminate()
        workerRef.current = null
        setProgress(null)
      }
    }, 500)
  }, [])

  const reset = useCallback(() => {
    analysisRunRef.current++
    workerRef.current?.terminate()
    workerRef.current = null
    setAnalysis(null)
    setSourceFile(null)
    setComparison(null)
    setComparisonFile(null)
    setProgress(null)
    setError(null)
  }, [])

  const captureSpec = useMemo(() => [
    ["Formatos aceitos", ".pcap, .pcapng"],
    ["Encapsulamentos", "Ethernet e IP cru; múltiplas interfaces PCAPNG"],
    ["Decodificação", "IPv4/IPv6, VLAN, ARP, TCP, UDP, ICMP, DNS, HTTP, HTTP/2, TLS/JA3 e QUIC"],
    ["Pacotes retidos", `Até ${formatNumber(options.packetLimit)} distribuídos; totais cobrem o arquivo e limites de cardinalidade são sinalizados`],
    ["Modo", options.analysisMode === "deep" ? `Profundo · reagrupamento TCP limitado · ${options.memoryBudgetMb} MB` : `Padrão · ${options.memoryBudgetMb} MB`],
    ["Execução", "Leitura incremental em Web Worker, sem upload"],
  ] as const, [options.analysisMode, options.memoryBudgetMb, options.packetLimit])

  if (analysis) {
    return (
      <Suspense fallback={<div className="shell grid min-h-screen place-items-center text-sm text-[var(--text-muted)]">Abrindo espaço de investigação…</div>}>
        <Workspace
          analysis={analysis}
          sourceFile={sourceFile}
          comparison={comparison}
          comparisonFile={comparisonFile}
          comparisonProgress={progress?.target === "comparison" ? progress : null}
          comparisonError={error}
          onCompareCapture={(file) => analyzeFile(file, "comparison")}
          onCancelComparison={cancelAnalysis}
          onNewCapture={reset}
          light={light}
          onTheme={() => setLight((value) => !value)}
          options={options}
          onOptionsChange={updateOptions}
        />
      </Suspense>
    )
  }

  const busy = progress !== null
  return (
    <div className="shell flex min-h-screen flex-col">
      <header className="topbar">
        <Brand />
        <span className="hidden text-[13px] text-[var(--text-muted)] sm:inline" aria-hidden="true">Analisador de capturas de rede</span>
        <div className="ml-auto flex items-center gap-2">
          <span className="hidden items-center gap-1.5 text-[13px] text-[var(--text-muted)] sm:flex">
            <LockKeyhole className="size-3.5 text-[var(--ok)]" aria-hidden="true" />
            Processamento local
          </span>
          <button className="icon-button" onClick={() => setLight((value) => !value)} aria-label={light ? "Usar tema escuro" : "Usar tema claro"}>
            {light ? <Moon className="size-4" /> : <Sun className="size-4" />}
          </button>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[720px] flex-1 px-4 py-8 sm:px-6 sm:py-12">
        <h1 className="text-[1.375rem] font-semibold tracking-[-0.02em] text-[var(--text)]">Importar captura</h1>
        <p className="mt-1.5 max-w-[60ch] text-base leading-relaxed text-[var(--text-muted)]">
          O arquivo é lido em blocos dentro deste navegador. Nenhum pacote é enviado a um servidor.
        </p>

        <section className="panel mt-6" aria-labelledby="import-heading">
          <h2 id="import-heading" className="sr-only">Origem da captura</h2>
          <div className="p-4">
            {busy ? (
              <div className="dropzone is-busy" aria-live="polite" aria-busy="true">
                <div className="w-full max-w-sm text-left">
                  <p className="text-[15px] font-semibold text-[var(--text)]">Analisando captura</p>
                  <p className="mt-0.5 text-[13px] text-[var(--text-muted)]">{progress.stage}</p>
                  <Progress value={progress.percent} aria-label="Progresso da análise" className="mt-4 h-1 rounded-sm bg-[var(--surface-sunken)] [&_[data-slot=progress-indicator]]:bg-[var(--accent)]" />
                  <div className="num mono mt-2 flex justify-between text-xs text-[var(--text-muted)]">
                    <span>{formatNumber(progress.processed)} pacotes lidos</span>
                    <span>{progress.percent}%</span>
                  </div>
                  <Button variant="outline" size="sm" className="mt-4" onClick={cancelAnalysis}>
                    <XCircle className="size-4" aria-hidden="true" /> Cancelar
                  </Button>
                </div>
              </div>
            ) : (
              <div
                className={`dropzone ${dragging ? "is-dragging" : ""}`}
                onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
                onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false) }}
                onDrop={(event) => {
                  event.preventDefault()
                  setDragging(false)
                  const file = event.dataTransfer.files[0]
                  if (file) analyzeFile(file)
                }}
              >
                <FileUp className="dropzone-icon size-6" strokeWidth={1.6} aria-hidden="true" />
                <p className="text-[15px] font-medium text-[var(--text)]">{dragging ? "Solte o arquivo para analisar" : "Arraste um arquivo .pcap ou .pcapng"}</p>
                <p className="-mt-1 text-[13px] text-[var(--text-muted)]">ou</p>
                <input
                  ref={fileInput}
                  type="file"
                  className="sr-only"
                  tabIndex={-1}
                  aria-hidden="true"
                  accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
                  onChange={(event) => {
                    const file = event.target.files?.[0]
                    event.target.value = ""
                    if (file) analyzeFile(file)
                  }}
                />
                <Button size="sm" className="mt-1" onClick={() => fileInput.current?.click()}>Selecionar arquivo</Button>
              </div>
            )}

            {error && <p className="inline-error mt-3" role="alert"><AlertTriangle aria-hidden="true" />{error}</p>}
          </div>

          <dl className="spec-list mx-4 mb-4">
            {captureSpec.map(([term, value]) => <div className="spec-row" key={term}><dt>{term}</dt><dd>{value}</dd></div>)}
          </dl>
        </section>

        <p className="mt-4 text-[13px] text-[var(--text-muted)]">
          Sem uma captura à mão?{" "}<button className="link-button" onClick={() => setAnalysis(demoAnalysis)}>Abrir uma análise de exemplo</button>
        </p>
      </main>
    </div>
  )
}
