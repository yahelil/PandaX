import { Check, ChevronDown, HelpCircle, LogOut, RotateCcw, UserRound } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../data/DemoProvider'

const roleLabels = {
  org_admin: 'Org Admin',
  compliance_operator: 'Compliance Operator',
  authorized_approver: 'Authorized Approver',
  read_only_auditor: 'Read-only Auditor',
} as const

export function UserMenu() {
  const { currentUser, state, actions } = useDemo()
  const [open, setOpen] = useState(false)
  const [resetDone, setResetDone] = useState(false)
  const root = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('pointerdown', close)
    return () => window.removeEventListener('pointerdown', close)
  }, [])

  const resetDemo = () => {
    actions.reset()
    setResetDone(true)
    window.setTimeout(() => setResetDone(false), 2200)
  }

  return (
    <div className="popover-anchor" ref={root}>
      <button className="user-trigger" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-label="Open account menu">
        <span className="avatar">{currentUser.initials}</span>
        <span className="user-trigger__copy"><strong>{currentUser.name}</strong><small>{state.organization.name}</small></span>
        <ChevronDown size={15} />
      </button>
      {open && (
        <div className="popover user-menu">
          <div className="user-menu__identity">
            <span className="avatar avatar--large">{currentUser.initials}</span>
            <span><strong>{currentUser.name}</strong><small>{currentUser.title}</small></span>
          </div>
          <div className="user-menu__roles"><Check size={14} /> {currentUser.roles.map((role) => roleLabels[role]).join(' · ')}</div>
          <Link to="/settings/team" className="menu-row" onClick={() => setOpen(false)}><UserRound size={17} /> Profile &amp; access</Link>
          <button className="menu-row" onClick={resetDemo}><RotateCcw size={17} /> {resetDone ? 'Demo data restored' : 'Reset demo data'}</button>
          <a href="mailto:support@pandax.online" className="menu-row"><HelpCircle size={17} /> Help &amp; support</a>
          <button className="menu-row menu-row--muted" disabled><LogOut size={17} /> Sign out unavailable in demo</button>
        </div>
      )}
    </div>
  )
}
