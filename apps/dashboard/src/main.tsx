import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { DemoProvider } from './data/DemoProvider'
import { ThemeProvider } from './components/ThemeProvider'
import './styles/global.css'

if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <DemoProvider>
        <ThemeProvider>
          <App />
        </ThemeProvider>
      </DemoProvider>
    </BrowserRouter>
  </StrictMode>,
)
