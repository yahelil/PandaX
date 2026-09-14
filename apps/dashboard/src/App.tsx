import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import {
  AnalysisPage,
  AnalysisResultPage,
  CompliancePage,
  DocumentDetailPage,
  FindingDetailPage,
  FindingsPage,
  HomePage,
  NotFoundPage,
  ProductsPage,
  ProductWorkspacePage,
  ReleaseWorkspacePage,
  SettingsPage,
} from './pages'

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
