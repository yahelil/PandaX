import { lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { HomePage } from './pages/HomePage'

const AnalysisPage = lazy(() => import('./pages/AnalysisPage').then(({ AnalysisPage }) => ({ default: AnalysisPage })))
const AnalysisResultPage = lazy(() => import('./pages/AnalysisResultPage').then(({ AnalysisResultPage }) => ({ default: AnalysisResultPage })))
const CompliancePage = lazy(() => import('./pages/CompliancePage').then(({ CompliancePage }) => ({ default: CompliancePage })))
const DocumentDetailPage = lazy(() => import('./pages/DocumentDetailPage').then(({ DocumentDetailPage }) => ({ default: DocumentDetailPage })))
const FindingDetailPage = lazy(() => import('./pages/FindingDetailPage').then(({ FindingDetailPage }) => ({ default: FindingDetailPage })))
const FindingsPage = lazy(() => import('./pages/FindingsPage').then(({ FindingsPage }) => ({ default: FindingsPage })))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then(({ NotFoundPage }) => ({ default: NotFoundPage })))
const ProductsPage = lazy(() => import('./pages/ProductsPage').then(({ ProductsPage }) => ({ default: ProductsPage })))
const ProductWorkspacePage = lazy(() => import('./pages/ProductWorkspacePage').then(({ ProductWorkspacePage }) => ({ default: ProductWorkspacePage })))
const ReleaseWorkspacePage = lazy(() => import('./pages/ReleaseWorkspacePage').then(({ ReleaseWorkspacePage }) => ({ default: ReleaseWorkspacePage })))
const SettingsPage = lazy(() => import('./pages/SettingsPage').then(({ SettingsPage }) => ({ default: SettingsPage })))

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<HomePage />} />
        <Route path="products" element={<ProductsPage />} />
        <Route path="products/:productId" element={<ProductWorkspacePage />} />
        <Route path="products/:productId/releases/:releaseId" element={<ReleaseWorkspacePage />} />
        <Route path="products/:productId/releases/:releaseId/analyze" element={<AnalysisPage />} />
        <Route path="analyses/:analysisId" element={<AnalysisResultPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:findingId" element={<FindingDetailPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="documents/:documentId" element={<DocumentDetailPage />} />
        <Route path="settings" element={<Navigate replace to="/settings/organization" />} />
        <Route path="settings/:section" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
