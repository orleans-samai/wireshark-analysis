"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { AlertTriangle, FileUp, LockKeyhole, Moon, Sun } from "lucide-react"
import { Brand } from "@/components/brand"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { demoAnalysis } from "@/lib/demo-data"
import { formatNumber } from "@/lib/format"
import type { CaptureAnalysis } from "@/lib/capture-types"
import { Workspace } from "@/components/workspace"

type AnalysisState = { percent: number; processed: number; stage: string }

const captureSpec = [
  ["Formatos aceitos", ".pcap, .pcapng"],
  ["Encapsulamento", "Ethernet (Linktype 1)"],
  ["Decodificação", "IPv4, IPv6, TCP, UDP, ICMP, DNS; HTTP e TLS por metadados"],
  ["Pacotes retidos para inspeção", "10.000 (as estatísticas cobrem a captura inteira)"],
  ["Execução", "Web Worker no navegador"],
] as const

export function PacketLensApp() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [analysis, setAnalysis] = useState<CaptureAnalysis | null>(null)
  const [progress, setProgress] = useState<AnalysisState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [light, setLight] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle("dark", !light)
    document.documentElement.classList.toggle("light", light)
  }, [light])

  // A file dropped outside the target would otherwise be opened by the browser
  // and discard the session.
  useEffect(() => {
    const swallow = (event: DragEvent) => event.preventDefault()
    window.addEventListener("dragover", swallow)
    window.addEventListener("drop", swallow)
    return () => {
      window.removeEventListener("dragover", swallow)
      window.removeEventListener("drop", swallow)
    }
  }, [])

  const analyzeFile = useCallback((file: File) => {
    setError(null)
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setError("Formato não suportado. Selecione um arquivo .pcap ou .pcapng.")
      return
    }
    setProgress({ percent: 2, processed: 0, stage: "Lendo captura" })
    const worker = new Worker("/pcap-worker.js")
    worker.onmessage = ({ data }) => {
      if (data.type === "progress") setProgress(data)
      if (data.type === "done") { setAnalysis(data.result); setProgress(null); worker.terminate() }
      if (data.type === "error") { setError(data.message); setProgress(null); worker.terminate() }
    }
    worker.onerror = () => { setError("Não foi possível iniciar o analisador local. Tente novamente."); setProgress(null); worker.terminate() }
    worker.postMessage({ type: "analyze", file })
  }, [])

  if (analysis) {
    return <Workspace analysis={analysis} onNewCapture={() => setAnalysis(null)} light={light} onTheme={() => setLight((value) => !value)} />
  }

  const busy = progress !== null

  return (
    <div className="shell flex min-h-screen flex-col">
      <header className="topbar">
        <Brand />
        <span className="hidden text-[13px] text-[var(--text-muted)] sm:inline" aria-hidden="true">
          Analisador de capturas de rede
        </span>
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
        <p className="mt-1.5 max-w-[56ch] text-base leading-relaxed text-[var(--text-muted)]">
          O arquivo é lido e decodificado dentro deste navegador. Nenhum pacote é enviado a um servidor.
        </p>

        <section className="panel mt-6" aria-labelledby="import-heading">
          <h2 id="import-heading" className="sr-only">Origem da captura</h2>
          <div className="p-4">
            {busy ? (
              <div className="dropzone is-busy" aria-live="polite" aria-busy="true">
                <div className="w-full max-w-sm text-left">
                  <p className="text-[15px] font-semibold text-[var(--text)]">Analisando captura</p>
                  <p className="mt-0.5 text-[13px] text-[var(--text-muted)]">{progress.stage}</p>
                  <Progress
                    value={progress.percent}
                    aria-label="Progresso da análise"
                    className="mt-4 h-1 rounded-sm bg-[var(--surface-sunken)] [&_[data-slot=progress-indicator]]:bg-[var(--accent)]"
                  />
                  <div className="num mono mt-2 flex justify-between text-xs text-[var(--text-muted)]">
                    <span>{formatNumber(progress.processed)} pacotes lidos</span>
                    <span>{progress.percent}%</span>
                  </div>
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
                <p className="text-[15px] font-medium text-[var(--text)]">
                  {dragging ? "Solte o arquivo para analisar" : "Arraste um arquivo .pcap ou .pcapng"}
                </p>
                <p className="-mt-1 text-[13px] text-[var(--text-muted)]">ou</p>
                <input
                  ref={fileInput}
                  type="file"
                  className="sr-only"
                  accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
                  onChange={(event) => {
                    const file = event.target.files?.[0]
                    // Clear the control so picking the same file again still
                    // fires a change event after a rejected attempt.
                    event.target.value = ""
                    if (file) analyzeFile(file)
                  }}
                />
                <Button size="sm" className="mt-1" onClick={() => fileInput.current?.click()}>
                  Selecionar arquivo
                </Button>
              </div>
            )}

            {error && (
              <p className="inline-error mt-3" role="alert">
                <AlertTriangle aria-hidden="true" />
                {error}
              </p>
            )}
          </div>

          <dl className="spec-list mx-4 mb-4">
            {captureSpec.map(([term, value]) => (
              <div className="spec-row" key={term}>
                <dt>{term}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        <p className="mt-4 text-[13px] text-[var(--text-muted)]">
          Sem uma captura à mão?{" "}
          <button className="link-button" onClick={() => setAnalysis(demoAnalysis)}>
            Abrir uma análise de exemplo
          </button>
        </p>
      </main>
    </div>
  )
}
