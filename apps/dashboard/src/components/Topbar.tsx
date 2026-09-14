import { Menu } from 'lucide-react'
import { HeaderSearch } from './HeaderSearch'
import { ScopeSelector } from './ScopeSelector'
import { ThemeToggle } from './ThemeToggle'
import { NotificationsMenu } from './NotificationsMenu'
import { UserMenu } from './UserMenu'

export function Topbar({ onOpenSidebar }: { onOpenSidebar: () => void }) {
  return (
    <header className="topbar">
      <button className="icon-button topbar__menu" onClick={onOpenSidebar} aria-label="Open navigation">
        <Menu size={21} />
      </button>
      <HeaderSearch />
      <div className="topbar__scope"><ScopeSelector /></div>
      <div className="topbar__actions">
        <ThemeToggle />
        <NotificationsMenu />
        <UserMenu />
      </div>
    </header>
  )
}
