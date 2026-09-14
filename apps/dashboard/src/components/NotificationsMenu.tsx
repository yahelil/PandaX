import { Activity, Bell, Check, ChevronRight, FileText, Info, RadioTower, ShieldAlert, TimerReset, type LucideIcon } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../data/DemoProvider'

import type { Notification } from '../data/types'

const alertIcons: Record<Notification['type'], LucideIcon> = {
  finding: ShieldAlert,
  deadline: TimerReset,
  monitoring: RadioTower,
  approval: Check,
  document: FileText,
  analysis: Activity,
  system: Info,
}

function relativeTime(value: string) {
  const minutes = Math.max(1, Math.round((Date.now() - new Date(value).getTime()) / 60_000))
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`
}

export function NotificationsMenu() {
  const { notifications, actions } = useDemo()
  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const root = useRef<HTMLDivElement>(null)
  const unread = notifications.filter((notification) => !notification.readAt)
  const markRead = async (id: string) => {
    setError('')
    try {
      await actions.markNotificationRead(id)
    } catch {
      setError('Could not update notification. Try again.')
    }
  }
  const markAllRead = async () => {
    setPending(true)
    setError('')
    try {
      await Promise.all(unread.map((item) => actions.markNotificationRead(item.id)))
    } catch {
      setError('Some notifications could not be updated. Try again.')
    } finally {
      setPending(false)
    }
  }

  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('pointerdown', close)
    return () => window.removeEventListener('pointerdown', close)
  }, [])

  return (
    <div className="popover-anchor" ref={root}>
      <button className="icon-button notification-trigger" onClick={() => setOpen((value) => !value)} aria-label="Action-required notifications" aria-expanded={open}>
        <Bell size={19} />
        {unread.length > 0 && <span className="notification-dot" />}
      </button>
      {open && (
        <div className="popover notification-menu">
          <div className="popover__head">
            <span><strong>Needs your attention</strong><small>{unread.length ? `${unread.length} unread alert${unread.length === 1 ? '' : 's'}` : 'No unread alerts'}</small></span>
            {unread.length > 0 && <button className="text-button" disabled={pending} onClick={() => { void markAllRead() }}><Check size={14} /> {pending ? 'Updating…' : 'Mark read'}</button>}
          </div>
          {error ? <p className="notification-menu__error" role="alert">{error}</p> : null}
          <div className={unread.length ? 'notification-list' : 'notification-list notification-list--read'}>
            {notifications.slice(0, 5).map((notification) => {
              const Icon = alertIcons[notification.type]
              return (
              <Link className="notification-item" to={notification.targetUrl} key={notification.id} onClick={() => { void markRead(notification.id); setOpen(false) }}>
                <span className="notification-item__icon"><Icon size={17} /></span>
                <span><strong>{notification.title}</strong><small>{notification.body} · {relativeTime(notification.createdAt)}</small></span>
                <ChevronRight size={16} />
              </Link>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
