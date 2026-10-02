"use client"

import { useState, type ReactNode } from "react"
import { AlertCircle, AlertTriangle, Info, SearchX, ShieldAlert } from "lucide-react"
import type { AlertRecord } from "@/lib/capture-types"
import { formatNumber } from "@/lib/format"
import { Button } from "@/components/ui/button"

/** Severity presentation. Each level differs by colour, icon and wording so
 *  the signal survives without colour perception. */
export const severityMeta: Record<
  AlertRecord["severity"],
  { className: string; rail: string; Icon: typeof ShieldAlert }
> = {
  Alta: { className: "sev-high", rail: "var(--danger)", Icon: ShieldAlert },
  Média: { className: "sev-medium", rail: "var(--warn)", Icon: AlertTriangle },
  Baixa: { className: "sev-low", rail: "var(--caution)", Icon: AlertCircle },
  Informativo: { className: "sev-info", rail: "var(--info)", Icon: Info },
}

export function SeverityBadge({ severity }: { severity: AlertRecord["severity"] }) {
  const { className, Icon } = severityMeta[severity]
  return (
    <span className={`severity ${className}`}>
      <Icon aria-hidden="true" />
      {severity}
    </span>
  )
}

export function ProtocolChip({ value }: { value: string }) {
  return <span className="proto">{value}</span>
}

/** An IP with its port underneath. The port line is metadata, not a heading. */
export function Address({ ip, port }: { ip: string; port?: number }) {
  return (
    <span className="block min-w-0">
      <span className="cell-primary truncate" title={ip}>{ip}</span>
      {port ? <span className="cell-secondary mono">:{port}</span> : null}
    </span>
  )
}

export function EmptyState({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="empty-state">
      <SearchX aria-hidden="true" />
      <strong>{title}</strong>
      <span>{hint}</span>
    </div>
  )
}

export function headingId(title: string) {
  return `panel-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`
}

export const PAGE_SIZE = 100

export type Paging = {
  page: number
  pages: number
  start: number
  shown: number
  total: number
  setPage: (page: number) => void
}

/** Caps how much of a result set reaches the DOM. A capture can hold tens of
 *  thousands of conversations, and rendering them all locks the main thread. */
export function usePage<T>(rows: T[]): { visible: T[]; paging: Paging } {
  const [page, setPage] = useState(1)
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  // Clamp rather than reset: narrowing the filter must never leave the view
  // parked on a page that no longer exists.
  const current = Math.min(page, pages)
  const start = (current - 1) * PAGE_SIZE
  const visible = rows.slice(start, start + PAGE_SIZE)
  return {
    visible,
    paging: { page: current, pages, start, shown: visible.length, total: rows.length, setPage },
  }
}

/** Stepping one page at a time is unusable at 100+ pages, so the page number
 *  is an input. It commits on Enter or blur and remounts (via `key`) whenever
 *  the page changes from elsewhere. */
function PageJump({ page, pages, setPage }: { page: number; pages: number; setPage: (page: number) => void }) {
  const commit = (raw: string) => {
    const next = Number.parseInt(raw, 10)
    if (Number.isNaN(next)) return
    setPage(Math.min(pages, Math.max(1, next)))
  }
  return (
    <span className="page-jump">
      <span aria-hidden="true">Página</span>
      <input
        key={page}
        type="number"
        inputMode="numeric"
        defaultValue={page}
        min={1}
        max={pages}
        aria-label={`Página atual, de 1 a ${pages}`}
        onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); commit(event.currentTarget.value) } }}
        onBlur={(event) => commit(event.target.value)}
      />
      <span aria-hidden="true">de {formatNumber(pages)}</span>
    </span>
  )
}

export function Pager({ paging, label }: { paging: Paging; label: string }) {
  const { page, pages, start, shown, total, setPage } = paging
  if (pages <= 1) {
    return <span>{formatNumber(total)} {total === 1 ? label.replace(/s$/, "") : label}</span>
  }
  return (
    <>
      <span>
        {formatNumber(start + 1)}–{formatNumber(start + shown)} de {formatNumber(total)} {label}
      </span>
      <span className="flex flex-wrap items-center gap-2">
        <PageJump page={page} pages={pages} setPage={setPage} />
        <Button variant="outline" size="sm" disabled={page === 1} onClick={() => setPage(page - 1)}>Anterior</Button>
        <Button variant="outline" size="sm" disabled={page === pages} onClick={() => setPage(page + 1)}>Próxima</Button>
      </span>
    </>
  )
}

/** Shared shell for every tabular view. The view title and description live in
 *  the page header, so the panel carries only the data: an optional advisory,
 *  the table itself, the record count or pager, and an empty state. */
export function TablePanel({
  title,
  paging,
  advisory,
  emptyTitle = "Nenhum registro corresponde ao filtro",
  emptyHint = "Ajuste a pesquisa ou limpe o filtro para ver todos os registros.",
  children,
}: {
  title: string
  paging: Paging
  advisory?: ReactNode
  emptyTitle?: string
  emptyHint?: string
  children: ReactNode
}) {
  const id = headingId(title)
  return (
    <section className="panel overflow-hidden" aria-labelledby={id}>
      <h2 id={id} className="sr-only">{title}</h2>
      {advisory}
      {paging.total === 0 ? (
        <EmptyState title={emptyTitle} hint={emptyHint} />
      ) : (
        <>
          <div className="table-scroll">{children}</div>
          <p className="table-foot">
            <Pager paging={paging} label="registros" />
          </p>
        </>
      )}
    </section>
  )
}
