"use client"

import { useEffect, useRef, useState } from "react"
import { Bookmark, Download, FileText, FileUp, FolderOpen, Save, Trash2 } from "lucide-react"
import type { CaptureAnalysis } from "@/lib/capture-types"
import type { InvestigationFilter, SavedInvestigation } from "@/lib/investigation"
import { describeFilter, investigationStorageKey } from "@/lib/investigation"
import { createCaseBundle, normalizeCaseList, normalizeInvestigationCase, parseCaseBundle } from "@/lib/casebook"
import { readLocalRecord, writeLocalRecord } from "@/lib/local-db"
import { downloadBlob } from "@/lib/pcap-export"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"

export function useSavedInvestigations(analysis: CaptureAnalysis) {
  const [saved, setSaved] = useState<SavedInvestigation[]>([])
  const key = investigationStorageKey(analysis)
  const loadedKey = useRef("")
  useEffect(() => {
    let cancelled = false
    loadedKey.current = ""
    const load = async () => {
      let next: SavedInvestigation[] = []
      try {
        const stored = await readLocalRecord<SavedInvestigation[]>(key)
        if (stored) next = normalizeCaseList(stored)
        else {
          const legacy = normalizeCaseList(JSON.parse(window.localStorage.getItem(key) || "[]"))
          next = legacy
          if (legacy.length) void writeLocalRecord(key, legacy).catch(() => undefined)
        }
      } catch {
        try { next = normalizeCaseList(JSON.parse(window.localStorage.getItem(key) || "[]")) } catch { /* Mantém a lista vazia se o conteúdo local estiver inválido. */ }
      }
      if (cancelled) return
      loadedKey.current = key
      setSaved(next)
    }
    void load()
    return () => { cancelled = true }
  }, [key])
  useEffect(() => {
    if (loadedKey.current !== key) return
    const normalized = normalizeCaseList(saved)
    void writeLocalRecord(key, normalized).catch(() => {
      try { window.localStorage.setItem(key, JSON.stringify(normalized)) } catch { /* Os casos seguem valendo na sessão. */ }
    })
  }, [key, saved])
  return [saved, setSaved] as const
}

export function InvestigationDrawer({ open, onOpenChange, analysis, filter, saved, setSaved, activeCaseId, onActiveCase, onLoad }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  analysis: CaptureAnalysis
  filter: InvestigationFilter
  saved: SavedInvestigation[]
  setSaved: React.Dispatch<React.SetStateAction<SavedInvestigation[]>>
  activeCaseId: string | null
  onActiveCase: (id: string | null) => void
  onLoad: (filter: InvestigationFilter) => void
}) {
  const [name, setName] = useState("")
  const [notes, setNotes] = useState("")
  const [owner, setOwner] = useState("")
  const [tags, setTags] = useState("")
  const [status, setStatus] = useState<"open" | "monitoring" | "closed">("open")
  const [message, setMessage] = useState<string | null>(null)
  const importInput = useRef<HTMLInputElement | null>(null)

  const save = () => {
    const now = new Date().toISOString()
    const item = normalizeInvestigationCase({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      name: name.trim() || `Caso ${saved.length + 1}`,
      notes,
      owner,
      tags: tags.split(","),
      status,
      createdAt: now,
      updatedAt: now,
      filter,
    })
    setSaved((items) => [item, ...items])
    onActiveCase(item.id)
    setName("")
    setNotes("")
    setOwner("")
    setTags("")
    setStatus("open")
    setMessage("Caso criado e definido como ativo.")
  }

  const exportCases = () => {
    const bundle = createCaseBundle(analysis, saved)
    downloadBlob(new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }), "packetlens-casos.json")
  }

  const importCases = async (file?: File) => {
    if (!file) return
    try {
      const imported = parseCaseBundle(await file.text())
      setSaved((items) => normalizeCaseList([...imported, ...items]))
      if (imported[0]) onActiveCase(imported[0].id)
      setMessage(`${imported.length} caso(s) importado(s).`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Não foi possível importar os casos.")
    } finally {
      if (importInput.current) importInput.current.value = ""
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-0 overflow-y-auto p-0 sm:max-w-xl">
        <SheetHeader className="border-b border-[var(--line)] p-4">
          <SheetTitle className="flex items-center gap-2 text-[15px]"><Bookmark className="size-4" /> Casos de investigação</SheetTitle>
          <SheetDescription>Organize escopo, responsável, estado, evidências e notas. Apenas metadados escolhidos ficam no navegador.</SheetDescription>
        </SheetHeader>
        <div className="space-y-5 p-4">
          <section aria-labelledby="save-investigation">
            <h3 id="save-investigation" className="text-sm font-semibold text-[var(--text)]">Criar caso com o escopo atual</h3>
            <p className="mt-1 text-xs text-[var(--text-muted)]">{describeFilter(filter)}</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Nome do caso" aria-label="Nome do caso" />
              <Input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Responsável" aria-label="Responsável pelo caso" />
              <Input className="sm:col-span-2" value={tags} onChange={(event) => setTags(event.target.value)} placeholder="Tags separadas por vírgula" aria-label="Tags do caso" />
              <Select value={status} onValueChange={(value) => setStatus(value as typeof status)}><SelectTrigger aria-label="Estado do caso"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="open">Aberto</SelectItem><SelectItem value="monitoring">Em monitoramento</SelectItem><SelectItem value="closed">Encerrado</SelectItem></SelectContent></Select>
              <Button size="sm" onClick={save}><Save className="size-4" /> Criar e ativar</Button>
              <Textarea className="sm:col-span-2" value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Hipóteses, decisões e próximos passos" aria-label="Notas do caso" rows={4} />
            </div>
          </section>

          <section aria-labelledby="saved-investigations">
            <div className="flex flex-wrap items-center justify-between gap-2"><h3 id="saved-investigations" className="text-sm font-semibold text-[var(--text)]">Casos salvos</h3><div className="flex gap-1"><input ref={importInput} type="file" accept="application/json,.json" className="sr-only" onChange={(event) => void importCases(event.target.files?.[0])} /><Button variant="outline" size="sm" onClick={() => importInput.current?.click()}><FileUp className="size-4" /> Importar</Button><Button variant="outline" size="sm" disabled={!saved.length} onClick={exportCases}><Download className="size-4" /> Exportar</Button></div></div>
            {message && <p className="mt-2 text-xs text-[var(--text-muted)]" role="status">{message}</p>}
            {saved.length === 0 ? (
              <div className="empty-state mt-3"><FileText aria-hidden="true" /><strong>Nenhum caso salvo</strong><span>Monte um filtro, registre uma hipótese e crie o primeiro caso.</span></div>
            ) : (
              <ul className="mt-3 space-y-2">
                {saved.map((item) => (
                  <li className={`saved-investigation${activeCaseId === item.id ? " is-active" : ""}`} key={item.id}>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2"><strong>{item.name}</strong><span className="tag">{item.status === "closed" ? "Encerrado" : item.status === "monitoring" ? "Monitorando" : "Aberto"}</span>{activeCaseId === item.id && <span className="confidence">Caso ativo</span>}</div>
                      <p>{describeFilter(item.filter)}</p>
                      {item.notes && <blockquote>{item.notes}</blockquote>}
                      <small>{item.owner ? `${item.owner} · ` : ""}{item.evidence?.length || 0} evidência(s) · atualizado {new Date(item.updatedAt).toLocaleString("pt-BR")}</small>
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-1">
                      <Button variant="outline" size="sm" onClick={() => { onActiveCase(item.id); onLoad(item.filter); onOpenChange(false) }}><FolderOpen className="size-4" /> Abrir</Button>
                      <Button variant="ghost" size="sm" onClick={() => { setSaved((items) => items.filter((entry) => entry.id !== item.id)); if (activeCaseId === item.id) onActiveCase(null) }} aria-label={`Excluir ${item.name}`}><Trash2 className="size-4" /></Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <p className="text-xs leading-relaxed text-[var(--text-muted)]">Captura: <span className="mono">{analysis.fileName}</span>. Os casos são vinculados à assinatura local deste arquivo.</p>
        </div>
      </SheetContent>
    </Sheet>
  )
}
