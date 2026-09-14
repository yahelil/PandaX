import { FileCheck2, FileText, PackageSearch, Search, ShieldAlert, X } from 'lucide-react'
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../data/DemoProvider'

export function HeaderSearch() {
  const { products, releases, findings, documents } = useDemo()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const records = useMemo(() => [
    ...products.map((product) => ({
      type: 'Product',
      title: product.name,
      detail: `${product.identifier} · ${product.readiness.replaceAll('_', ' ')}`,
      to: `/products/${product.id}`,
      icon: PackageSearch,
    })),
    ...releases.map((release) => ({
      type: 'Release',
      title: `${products.find((item) => item.id === release.productId)?.name ?? 'Product'} v${release.version}`,
      detail: `${release.channel} · monitoring ${release.monitoringHealth}`,
      to: `/products/${release.productId}/releases/${release.id}`,
      icon: FileCheck2,
    })),
    ...findings.map((finding) => ({
      type: 'Finding',
      title: finding.reference,
      detail: `${finding.title} · ${finding.priority}`,
      to: `/findings/${finding.id}`,
      icon: ShieldAlert,
    })),
    ...documents.map((document) => ({
      type: 'Document',
      title: document.name,
      detail: `${document.format} · ${document.status.replaceAll('_', ' ')}`,
      to: `/documents/${document.id}`,
      icon: FileText,
    })),
  ], [documents, findings, products, releases])
  const normalized = query.trim().toLowerCase()
  const matches = records.filter((record) => `${record.type} ${record.title} ${record.detail}`.toLowerCase().includes(normalized))
  const results = (normalized
    ? matches
    : ['Product', 'Release', 'Finding', 'Document'].flatMap((type) => records.filter((record) => record.type === type).slice(0, 1))
  ).slice(0, 8)

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
        aria-expanded={open}
        aria-controls="global-search-results"
      />
      {query && <button className="global-search__clear" onClick={() => setQuery('')} aria-label="Clear search"><X size={16} /></button>}
      {open && (
        <div id="global-search-results" className="search-menu">
          <div className="search-menu__head">
            <span>{query ? 'Matching workspace records' : 'Suggested'}</span>
            <kbd>/</kbd>
          </div>
          {results.length ? results.map(({ type, title, detail, to, icon: Icon }) => (
            <Link key={`${type}-${title}`} to={to} className="search-result" onClick={() => setOpen(false)}>
              <span className="search-result__icon"><Icon size={18} /></span>
              <span><strong>{title}</strong><small>{detail}</small></span>
              <em>{type}</em>
            </Link>
          )) : (
            <div className="search-menu__empty"><Search size={20} /><span>No records match “{query}”</span></div>
          )}
        </div>
      )}
    </div>
  )
}
