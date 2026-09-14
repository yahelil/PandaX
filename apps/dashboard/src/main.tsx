import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { DemoProvider } from './data/DemoProvider'
import { createRuntimeDataAdapter } from './data/productionAdapter'
import { ThemeProvider } from './components/ThemeProvider'
import './styles/global.css'

if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual'

const dataAdapter = createRuntimeDataAdapter({
  apiUrl: import.meta.env.VITE_ACTIS_API_URL,
  organizationId: import.meta.env.VITE_ACTIS_ORGANIZATION_ID,
  getBearerToken: window.__ACTIS_GET_BEARER_TOKEN__,
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <DemoProvider adapter={dataAdapter}>
        <ThemeProvider>
          <App />
        </ThemeProvider>
      </DemoProvider>
    </BrowserRouter>
  </StrictMode>,
)
