import { lazy, StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { AuthProvider, AuthenticationGate, BrowserOidcClient, authenticatedTeamMember, readRuntimeConfig, useAuth, type AuthClient, type RuntimeConfig } from './auth'
import type { DataAdapter } from './data/adapter'
import { DemoProvider } from './data/DemoProvider'
import { createRuntimeDataAdapter } from './data/productionAdapter'
import { ThemeProvider } from './components/ThemeProvider'
import './styles/global.css'

const SupabaseAuthorizationPage = lazy(async () => {
  const module = await import('./auth/SupabaseAuthorizationPage')
  return { default: module.SupabaseAuthorizationPage }
})

if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual'

const root = createRoot(document.getElementById('root')!)

try {
  const config = readRuntimeConfig(import.meta.env)
  const isProd = config.mode === 'production'
  const authClient = isProd ? new BrowserOidcClient({
    ...config.oidc,
    apiUrl: config.apiUrl,
    organizationId: config.organizationId,
  }) : undefined
  const dataAdapter = createRuntimeDataAdapter(config.mode === 'demo' ? { mode: 'demo' } : {
    mode: 'production',
    apiUrl: config.apiUrl,
    organizationId: config.organizationId,
    getBearerToken: () => isProd ? authClient!.getAccessToken() : Promise.resolve('dev-token'),
  })
  root.render(<RuntimeRoot config={config} authClient={authClient} dataAdapter={dataAdapter} />)
} catch (error) {
  root.render(<ConfigurationError message={error instanceof Error ? error.message : 'Actis configuration is invalid.'} />)
}

function RuntimeRoot({ config, authClient, dataAdapter }: { config: RuntimeConfig; authClient?: AuthClient; dataAdapter: DataAdapter }) {
  if (config.mode === 'production' && window.location.pathname === '/oauth/consent') {
    return <StrictMode><Suspense fallback={<main className="auth-screen"><section className="auth-card"><h1>Preparing secure sign-in</h1><div className="auth-progress" /></section></main>}><SupabaseAuthorizationPage {...config.supabase} /></Suspense></StrictMode>
  }
  return <StrictMode>
    <BrowserRouter>
      <AuthProvider mode={config.mode} client={authClient}>
        <AuthenticatedApplication adapter={dataAdapter} />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
}

function AuthenticatedApplication({ adapter }: { adapter: DataAdapter }) {
  const auth = useAuth()
  return <AuthenticationGate>
    <DemoProvider adapter={adapter} currentUserOverride={authenticatedTeamMember(auth.user)}>
      <ThemeProvider><App /></ThemeProvider>
    </DemoProvider>
  </AuthenticationGate>
}

function ConfigurationError({ message }: { message: string }) {
  return <main className="auth-screen"><section className="auth-card"><h1>Actis is not configured</h1><p role="alert">{message}</p></section></main>
}
