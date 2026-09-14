import { FileCheck2, FileText, PackageSearch, Search, ShieldAlert, X, type LucideIcon } from 'lucide-react'
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../data/DemoProvider'
import type { WorkspaceSearchResult } from '../data/adapter'
import { featureUsed } from '../data/analytics'

type SearchRecord = WorkspaceSearchResult & { icon: LucideIcon }

const icons: Record<WorkspaceSearchResult['type'], LucideIcon> = {
  Product: PackageSearch,
  Release: FileCheck2,
  Finding: ShieldAlert,
  Compliance: FileCheck2,
  Document: FileText,
}

export function HeaderSearch() {
  const { products, releases, findings, documents, actions } = useDemo()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [remoteResults, setRemoteResults] = useState<SearchRecord[]>([])
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const records = useMemo<SearchRecord[]>(() => [
    ...products.map((product) => ({
      id: product.id,
      type: 'Product' as const,
      title: product.name,
      detail: `${product.identifier} · ${product.readiness.replaceAll('_', ' ')}`,
      to: `/products/${product.id}`,
      icon: PackageSearch,
    })),
    ...releases.map((release) => ({
      id: release.id,
      type: 'Release' as const,
      title: `${products.find((item) => item.id === release.productId)?.name ?? 'Product'} v${release.version}`,
      detail: `${release.channel} · monitoring ${release.monitoringHealth}`,
      to: `/products/${release.productId}/releases/${release.id}`,
      icon: FileCheck2,
    })),
    ...findings.map((finding) => ({
      id: finding.id,
      type: 'Finding' as const,
      title: finding.reference,
      detail: `${finding.title} · ${finding.priority}`,
      to: `/findings/${finding.id}`,
      icon: ShieldAlert,
    })),
    ...documents.map((document) => ({
      id: document.id,
      type: 'Document' as const,
      title: document.name,
      detail: `${document.format} · ${document.status.replaceAll('_', ' ')}`,
      to: `/documents/${document.id}`,
      icon: FileText,
    })),
  ], [documents, findings, products, releases])
  const normalized = query.trim().toLowerCase()
  const localMatches = records.filter((record) => `${record.type} ${record.title} ${record.detail}`.toLowerCase().includes(normalized))
  const results = (normalized.length >= 2
    ? remoteResults
    : normalized
      ? localMatches
      : ['Product', 'Release', 'Finding', 'Document'].flatMap((type) => records.filter((record) => record.type === type).slice(0, 1))
  ).slice(0, 8)

  useEffect(() => {
    if (normalized.length < 2) {
      setRemoteResults([])
      setSearching(false)
      setSearchError(false)
      return
    }
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      setSearching(true)
      setSearchError(false)
      void actions.search(normalized, { signal: controller.signal })
        .then((items) => {
          setRemoteResults(items.map((item) => ({ ...item, icon: icons[item.type] })))
          void Promise.resolve(actions.trackAnalytics(featureUsed('search'))).catch(() => undefined)
        })
        .catch((error: unknown) => {
          if (!(error instanceof DOMException && error.name === 'AbortError')) {
            setRemoteResults([])
            setSearchError(true)
          }
        })
        .finally(() => {
          if (!controller.signal.aborted) setSearching(false)
        })
    }, 180)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [actions, normalized])

  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('pointerdown', close)
    return () => window.removeEventListener('pointerdown', close)
  }, [])

  useEffect(() => {
    const focusSearch = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) {
        event.preventDefault()
        input.current?.focus()
      }
    }
    window.addEventListener('keydown', focusSearch)
    return () => window.removeEventListener('keydown', focusSearch)
  }, [])

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      setOpen(false)
      event.currentTarget.blur()
    }
  }

  return (
    <div className="global-search" ref={root}>
      <Search className="global-search__icon" size={18} aria-hidden="true" />
      <label className="sr-only" htmlFor="global-search">Search Actis</label>
      <input
        id="global-search"
        ref={input}
        type="search"
        value={query}
        placeholder="Search products, releases, findings…"
        autoComplete="off"
        onFocus={() => setOpen(true)}
        onChange={(event) => { setQuery(event.target.value); setOpen(true) }}
        onKeyDown={handleKeyDown}
        aria-label="Search products, releases, findings, and documents"
        aria-expanded={open}
        aria-controls="global-search-results"
        aria-busy={searching}
      />
      {query && <button className="global-search__clear" onClick={() => setQuery('')} aria-label="Clear search"><X size={16} /></button>}
      {open && (
        <div id="global-search-results" className="search-menu">
          <div className="search-menu__head">
            <span>{query ? (searching ? 'Searching workspace…' : 'Matching workspace records') : 'Suggested'}</span>
            <kbd>/</kbd>
          </div>
          {searchError ? (
            <div className="search-menu__empty" role="status"><Search size={20} /><span>Search is temporarily unavailable. Try again.</span></div>
          ) : results.length ? results.map(({ id, type, title, detail, to, icon: Icon }) => (
            <Link key={`${type}-${id}`} to={to} className="search-result" onClick={() => setOpen(false)}>
              <span className="search-result__icon"><Icon size={18} /></span>
              <span><strong>{title}</strong><small>{detail}</small></span>
              <em>{type}</em>
            </Link>
          )) : !searching ? (
            <div className="search-menu__empty"><Search size={20} /><span>No records match “{query}”</span></div>
          ) : null}
        </div>
      )}
    </div>
  )
}
