import { Suspense, useEffect, useRef, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { analyticsAreaForPath, pageViewed } from '../data/analytics'
import { useDemo } from '../data/DemoProvider'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()
  const { adapterStatus, actions } = useDemo()
  const awaitingFirstLoad = adapterStatus.mode === 'production' && !adapterStatus.lastSyncedAt
  const lastTrackedPath = useRef('')
  const [bannerDismissed, setBannerDismissed] = useState(false)
  const mountedPath = useRef(false)

  useEffect(() => {
    if (!mountedPath.current) {
      mountedPath.current = true
      return
    }
    setSidebarOpen(false)
    requestAnimationFrame(() => {
      window.scrollTo({ top: 0, left: 0 })
      document.getElementById('main-content')?.focus({ preventScroll: true })
      requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0 }))
    })
  }, [location.pathname])

  useEffect(() => {
    if (adapterStatus.phase !== 'ready' || lastTrackedPath.current === location.pathname) return
    const area = analyticsAreaForPath(location.pathname)
    if (!area) return
    lastTrackedPath.current = location.pathname
    void Promise.resolve(actions.trackAnalytics(pageViewed(area))).catch(() => undefined)
  }, [actions, adapterStatus.phase, location.pathname])

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <div className="app-shell__body">
        <Topbar onOpenSidebar={() => setSidebarOpen(true)} />
        <div id="main-content" className="main-content" tabIndex={-1}>
          {adapterStatus.failure ? (
            <div className="adapter-status adapter-status--error" role="alert">
              <span>{adapterStatus.failure.message}</span>
              <button type="button" onClick={() => { void actions.refresh().catch(() => undefined) }}>Retry</button>
            </div>
          ) : null}
          {adapterStatus.mode === 'fixture' && !bannerDismissed ? (
            <div className="adapter-status" role="status">
              <span>Local demo: changes stay in this browser. Only uploaded JSON SBOMs are analyzed, using OSV.</span>
              <button type="button" className="text-button" onClick={() => setBannerDismissed(true)} aria-label="Dismiss demo notice" style={{ marginLeft: 'auto', padding: '0 4px' }}>✕</button>
            </div>
          ) : null}
          {awaitingFirstLoad && adapterStatus.phase === 'loading' ? (
            <DashboardSkeleton />
          ) : awaitingFirstLoad && adapterStatus.phase === 'error' ? null : (
            <Suspense fallback={<DashboardSkeleton />}>
              <Outlet />
            </Suspense>
          )}
        </div>
      </div>
    </div>
  )
}

function DashboardSkeleton() {
  return (
    <div className="dashboard-skeleton" role="status">
      <span className="sr-only">Loading your workspace</span>
      <div aria-hidden="true">
        <div className="dashboard-skeleton__heading">
          <span className="skeleton-block dashboard-skeleton__title" />
          <span className="skeleton-block dashboard-skeleton__description" />
        </div>
        <div className="dashboard-skeleton__metrics">
          {Array.from({ length: 3 }, (_, index) => (
            <div className="dashboard-skeleton__card" key={index}>
              <span className="skeleton-block dashboard-skeleton__label" />
              <span className="skeleton-block dashboard-skeleton__number" />
              <span className="skeleton-block dashboard-skeleton__detail" />
            </div>
          ))}
        </div>
        <div className="dashboard-skeleton__panels">
          {[3, 2].map((rows, index) => (
            <div className="dashboard-skeleton__panel" key={index}>
              <div className="dashboard-skeleton__panel-heading">
                <span className="skeleton-block dashboard-skeleton__panel-title" />
                <span className="skeleton-block dashboard-skeleton__panel-description" />
              </div>
              {Array.from({ length: rows }, (_, row) => (
                <div className="dashboard-skeleton__row" key={row}>
                  <span className="skeleton-block dashboard-skeleton__row-title" />
                  <span className="skeleton-block dashboard-skeleton__row-detail" />
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
