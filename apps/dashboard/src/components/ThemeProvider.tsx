import { createContext, type ReactNode, useContext, useEffect, useMemo } from 'react'
import { useDemo } from '../data/DemoProvider'

export type Theme = 'light' | 'dark'

type ThemeContextValue = {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { state, actions } = useDemo()
  const setting = state.settings.appearance.theme
  const density = state.settings.appearance.density
  const theme: Theme = setting === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : setting
  const setTheme = (next: Theme) => {
    void Promise.resolve(actions.updateSettings('appearance', { theme: next })).catch(() => undefined)
  }

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.dataset.density = density
    document.documentElement.style.colorScheme = theme
    document.querySelector('meta[name="theme-color"]')?.setAttribute(
      'content',
      theme === 'dark' ? '#0b1220' : '#f5f7fb',
    )
  }, [density, theme])

  const value = useMemo(
    () => ({ theme, setTheme, toggleTheme: () => setTheme(theme === 'dark' ? 'light' : 'dark') }),
    [theme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const value = useContext(ThemeContext)
  if (!value) throw new Error('useTheme must be used inside ThemeProvider')
  return value
}
