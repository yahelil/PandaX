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
  const lastTrackedPath = useRef('')
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
          {adapterStatus.mode === 'production' && adapterStatus.phase === 'loading' ? (
            <div className="adapter-status" role="status">Syncing production data…</div>
          ) : null}
          {adapterStatus.failure ? (
            <div className="adapter-status adapter-status--error" role="alert">
              <span>{adapterStatus.failure.message}</span>
              <button type="button" onClick={() => { void actions.refresh().catch(() => undefined) }}>Retry</button>
            </div>
          ) : null}
          <Suspense fallback={<div className="adapter-status" role="status" aria-live="polite">Loading workspace…</div>}>
            <Outlet />
          </Suspense>
        </div>
      </div>
    </div>
  )
}
