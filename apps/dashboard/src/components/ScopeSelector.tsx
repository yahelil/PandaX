import { Check, ChevronDown, Layers3 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useDemo } from '../data/DemoProvider'

export function ScopeSelector() {
  const { products, releases } = useDemo()
  const [params, setParams] = useSearchParams()
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const productId = params.get('product')
  const releaseId = params.get('release')
  const product = products.find((item) => item.id === productId)
  const release = releases.find((item) => item.id === releaseId && item.productId === productId)

  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('pointerdown', close)
    return () => window.removeEventListener('pointerdown', close)
  }, [])

  const select = (nextProduct?: string, nextRelease?: string) => {
    const next = new URLSearchParams(params)
    if (nextProduct) next.set('product', nextProduct)
    else next.delete('product')
    if (nextRelease) next.set('release', nextRelease)
    else next.delete('release')
    setParams(next, { replace: true })
    setOpen(false)
  }

  return (
    <div className="scope-picker" ref={root}>
      <button className="scope-picker__trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-haspopup="dialog">
        <Layers3 size={17} aria-hidden="true" />
        <span className="scope-picker__copy">
          <small>Viewing</small>
          <strong>{product ? `${product.name}${release ? ` · v${release.version}` : ''}` : 'All products'}</strong>
        </span>
        <ChevronDown size={16} aria-hidden="true" />
      </button>
      {open && (
        <div className="scope-menu" role="dialog" aria-label="Choose product and release scope">
          <div className="scope-menu__head">
            <strong>Product / release scope</strong>
            <span>Applies across workspace</span>
          </div>
          <button className="scope-option" onClick={() => select()}>
            <span><strong>All products</strong><small>Organization-wide view</small></span>
            {!product && <Check size={17} />}
          </button>
          {products.map((item) => (
            <div className="scope-menu__product" key={item.id}>
              <button className="scope-option" onClick={() => select(item.id)}>
                <span><strong>{item.name}</strong><small>All releases</small></span>
                {productId === item.id && !releaseId && <Check size={17} />}
              </button>
              {productId === item.id && releases.filter((itemRelease) => itemRelease.productId === item.id).map((itemRelease) => (
                <button className="scope-option scope-option--release" key={itemRelease.id} onClick={() => select(item.id, itemRelease.id)}>
                  <span><strong>v{itemRelease.version}</strong><small>{itemRelease.channel} · {itemRelease.status.replaceAll('_', ' ')}</small></span>
                  {releaseId === itemRelease.id && <Check size={17} />}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
