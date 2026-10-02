"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import { Clock3, Filter, RotateCcw, Search, Undo2, X } from "lucide-react"
import type { CaptureAnalysis } from "@/lib/capture-types"
import type { FilterKind, InvestigationFilter, InvestigationTarget, SearchSuggestion } from "@/lib/investigation"
import { buildSuggestionIndex, buildSuggestions, hasActiveFilters } from "@/lib/investigation"
import { formatDuration } from "@/lib/format"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

export function InvestigationSearch({ analysis, filter, onQuery, onSelect }: { analysis: CaptureAnalysis; filter: InvestigationFilter; onQuery: (value: string) => void; onSelect: (item: SearchSuggestion) => void }) {
  const [focused, setFocused] = useState(false)
  // Rascunho local com commit debounced: cada tecla redesenha as tabelas
  // (filtro O(n) sobre até 100k pacotes), então o filtro global só é
  // atualizado 200ms após a pausa na digitação.
  const [draft, setDraft] = useState(filter.query)
  const committed = useRef(filter.query)
  const timer = useRef<number | null>(null)
  useEffect(() => {
    // Mudança vinda de outra via (chip, alerta, sugestão): reflete no campo.
    if (filter.query !== committed.current) {
      committed.current = filter.query
      setDraft(filter.query)
    }
  }, [filter.query])
  useEffect(() => () => { if (timer.current !== null) window.clearTimeout(timer.current) }, [])
  const commit = (value: string) => {
    if (timer.current !== null) window.clearTimeout(timer.current)
    committed.current = value
    onQuery(value)
  }
  const suggestionIndex = useMemo(() => buildSuggestionIndex(analysis), [analysis])
  const suggestions = useMemo(() => buildSuggestions(suggestionIndex, draft), [suggestionIndex, draft])

  return (
    <div className="investigation-search">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-[var(--text-faint)]" aria-hidden="true" />
      <Input
        id="investigation-search"
        type="search"
        value={draft}
        onChange={(event) => {
          const value = event.target.value
          setDraft(value)
          if (timer.current !== null) window.clearTimeout(timer.current)
          timer.current = window.setTimeout(() => commit(value), 200)
        }}
        onFocus={() => setFocused(true)}
        onBlur={() => window.setTimeout(() => setFocused(false), 120)}
        onKeyDown={(event) => {
          if (event.key === "Escape") { setDraft(committed.current); setFocused(false) }
          if (event.key === "Enter" && suggestions[0]) {
            event.preventDefault()
            commit(draft)
            onSelect(suggestions[0])
            setFocused(false)
          }
        }}
        aria-label="Pesquisar e filtrar por host, domínio, porta ou protocolo"
        aria-expanded={focused && suggestions.length > 0}
        aria-controls="investigation-suggestions"
        placeholder="Pesquisar host, domínio, porta, protocolo"
        className="h-8 bg-[var(--surface-raised)] pl-8 text-sm"
      />
      {focused && suggestions.length > 0 && (
        <ul id="investigation-suggestions" className="suggestion-list" role="listbox">
          {suggestions.map((item) => (
            <li key={item.id}>
              <button type="button" role="option" aria-selected="false" onMouseDown={(event) => event.preventDefault()} onClick={() => { onSelect(item); setFocused(false) }}>
                <span className="suggestion-kind">{kindLabel(item.kind)}</span>
                <span className="min-w-0 flex-1"><b>{item.label}</b><small>{item.detail}</small></span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function FilterToolbar({ analysis, filter, onTarget, onRemove, onSetProtocols, onSetTime, onClear, onUndo, canUndo }: {
  analysis: CaptureAnalysis
  filter: InvestigationFilter
  onTarget: (target: InvestigationTarget) => void
  onRemove: (kind: FilterKind, value?: string | number) => void
  onSetProtocols: (protocols: string[]) => void
  onSetTime: (from?: number, to?: number) => void
  onClear: () => void
  onUndo: () => void
  canUndo: boolean
}) {
  const active = hasActiveFilters(filter)
  const max = Math.max(1, Math.ceil(analysis.duration))

  return (
    <section className="filter-toolbar" aria-label="Filtros da investigação">
      <div className="filter-toolbar-main">
        <span className="filter-toolbar-label"><Filter aria-hidden="true" /> Escopo</span>
        {!active && <span className="text-[13px] text-[var(--text-muted)]">Captura completa</span>}
        {filter.query && <FilterChip label={`texto: ${filter.query}`} onRemove={() => onRemove("query")} />}
        {filter.addresses.map((value) => <FilterChip key={`address-${value}`} label={`host: ${value}`} mono onRemove={() => onRemove("address", value)} />)}
        {filter.protocols.map((value) => <FilterChip key={`protocol-${value}`} label={value} onRemove={() => onRemove("protocol", value)} />)}
        {filter.ports.map((value) => <FilterChip key={`port-${value}`} label={`porta ${value}`} onRemove={() => onRemove("port", value)} />)}
        {filter.domains.map((value) => <FilterChip key={`domain-${value}`} label={value} mono onRemove={() => onRemove("domain", value)} />)}
        {(filter.from !== undefined || filter.to !== undefined) && <FilterChip label={`${formatDuration(filter.from || 0)}–${formatDuration(filter.to ?? max)}`} onRemove={() => onRemove("time")} />}
      </div>
      <div className="filter-toolbar-actions">
        <Select
          value={filter.protocols.length === 1 ? filter.protocols[0] : "Todos"}
          onValueChange={(value) => value === "Todos" ? onSetProtocols([]) : onTarget({ kind: "protocol", value, replace: true })}
        >
          <SelectTrigger className="h-8 w-36 bg-[var(--surface-raised)]" aria-label="Filtrar por protocolo"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="Todos">Todos</SelectItem>
            {analysis.protocols.map((item) => <SelectItem key={item.name} value={item.name}>{item.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <details className="time-filter">
          <summary><Clock3 aria-hidden="true" /> Tempo</summary>
          <div className="time-filter-popover">
            <p>Intervalo relativo ao início da captura</p>
            <label>De <input type="number" min={0} max={max} value={Math.round(filter.from || 0)} onChange={(event) => onSetTime(Number(event.target.value), filter.to ?? max)} /> s</label>
            <label>Até <input type="number" min={0} max={max} value={Math.round(filter.to ?? max)} onChange={(event) => onSetTime(filter.from || 0, Number(event.target.value))} /> s</label>
            <small>Janela total: {formatDuration(analysis.duration)}</small>
          </div>
        </details>
        <Button variant="ghost" size="sm" disabled={!canUndo} onClick={onUndo} aria-label="Desfazer último filtro"><Undo2 className="size-4" /></Button>
        {active && <Button variant="ghost" size="sm" onClick={onClear}><RotateCcw className="size-4" /> Limpar</Button>}
      </div>
    </section>
  )
}

function FilterChip({ label, mono = false, onRemove }: { label: string; mono?: boolean; onRemove: () => void }) {
  return <span className={`filter-chip${mono ? " mono" : ""}`}>{label}<button onClick={onRemove} aria-label={`Remover filtro ${label}`}><X aria-hidden="true" /></button></span>
}

function kindLabel(kind: InvestigationTarget["kind"]) {
  return kind === "address" ? "Host" : kind === "protocol" ? "Protocolo" : kind === "port" ? "Porta" : kind === "domain" ? "Domínio" : "Busca"
}
