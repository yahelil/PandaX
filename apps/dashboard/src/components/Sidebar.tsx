import { FileWarning, Home, PackageSearch, Scale, Settings, X } from 'lucide-react'
import { NavLink, useLocation, useSearchParams } from 'react-router-dom'
import { Brand } from './Brand'
import { useDemo } from '../data/DemoProvider'

const primaryItems = [
  { to: '/', label: 'Home', icon: Home, end: true },
  { to: '/products', label: 'Products', icon: PackageSearch },
  { to: '/findings', label: 'Findings', icon: FileWarning },
  { to: '/compliance', label: 'Compliance', icon: Scale },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { findings, complianceItems } = useDemo()
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const isClientDemo = location.pathname.includes('/client-demo')
  const scopeParams = new URLSearchParams()
  const scopedProduct = searchParams.get('product')
  const scopedRelease = searchParams.get('release')
  if (scopedProduct) scopeParams.set('product', scopedProduct)
  if (scopedRelease) scopeParams.set('release', scopedRelease)
  const scopeSearch = scopeParams.toString()
  const badges: Record<string, number> = {
    '/findings': findings.filter((item) => item.status === 'needs_review' || item.status === 'action_required').length,
    '/compliance': complianceItems.filter((item) => (item.lifecycleStatus ? item.lifecycleStatus !== 'resolved' : item.status !== 'complete') && (item.priority === 'urgent' || item.priority === 'high')).length,
  }
  return (
    <aside className={`sidebar${open ? ' sidebar--open' : ''}`} aria-label="Primary navigation">
      <div className="sidebar__brand-row">
        <Brand />
        <button className="icon-button sidebar__close" onClick={onClose} aria-label="Close navigation">
          <X size={20} />
        </button>
      </div>

      <nav className="sidebar__nav">
        <p className="sidebar__label">Workspace</p>
        {primaryItems.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={{ pathname: to, search: scopeSearch }}
            end={end}
            className={({ isActive }) => `nav-item${isActive ? ' nav-item--active' : ''}`}
          >
            <Icon size={19} strokeWidth={1.9} aria-hidden="true" />
            <span>{label}</span>
            {badges[to] > 0 && <span className="nav-item__badge" aria-label={`${badges[to]} items need attention`}>{badges[to]}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar__footer">
        <NavLink
          to="/settings/organization"
          className={({ isActive }) => `nav-item${isActive ? ' nav-item--active' : ''}`}
        >
          <Settings size={19} strokeWidth={1.9} aria-hidden="true" />
          <span>Settings</span>
        </NavLink>
        {!isClientDemo && <div className="demo-marker" title="This workspace uses demonstration data">
          <span className="demo-marker__dot" />
          Demo workspace
        </div>}
      </div>
    </aside>
  )
}
